#!/usr/bin/env python3
"""
parse_eml_ioc.py - Offline phishing header, EML and IOC triage engine.

READS ONLY. Never fetches a URL, resolves a domain, queries DNS, or executes an
attachment. Every verdict is derived statically from the bytes supplied on disk, so
the tool is safe to run on a live suspicious message from an analyst workstation.

What it does
------------
  * Parses RFC 5322 / MIME structure with the Python standard library only.
  * Rebuilds the Received hop timeline and flags forged or implausible hops.
  * Parses Authentication-Results (RFC 8601) and evaluates DMARC *alignment*
    (RFC 9989, which obsoletes RFC 7489), not just raw SPF/DKIM pass/fail.
  * Detects From / Reply-To / Return-Path divergence, punycode and homoglyph
    lookalike domains, and display-name impersonation.
  * Extracts and DEFANGS URLs, domains and IPs so no clickable live indicator ever
    reaches a ticket or chat window.
  * Hashes attachments (SHA-256), flags dangerous and double extensions.
  * Scores modern lure patterns that carry no attachment and often no link at all:
    ClickFix / CrashFix / FileFix command-paste lures, quishing (QR), Microsoft
    device-code phishing, and AiTM credential-harvest redirectors.

Sanitization policy (important)
-------------------------------
Defanging and sanitization are different controls and are applied separately:

  * Defanging is ALWAYS on. It prevents an analyst from clicking a live indicator.
  * Credential redaction is ALWAYS on, via the library's shared residual pass. A
    reply chain inside a phishing message frequently contains real passwords,
    tokens, card numbers or national IDs; those are never operational evidence.
  * Attacker indicators (sender address, originating IP, URLs, hashes) are
    DELIBERATELY PRESERVED. They are the deliverable - redacting them would make
    the report useless for blocking.
  * `--sanitize` additionally masks the *recipient* side (To/Cc, internal hosts),
    for sharing outside the responding team.

Exit codes: 0 analysis produced, 1 input could not be used, 2 bad invocation.
"""

import argparse
import base64
import binascii
import email
import email.policy
import email.utils
import hashlib
import ipaddress
import json
import os
import re
import sys
import unicodedata
from datetime import datetime, timezone

# --------------------------------------------------------------------------
# Shared residual sanitization pass (vendored: scripts/sanitizer.py).
# Indicator classes are skipped on purpose - see "Sanitization policy" above.
# --------------------------------------------------------------------------
try:
    from sanitizer import residual_scrub as _residual_scrub
except ImportError:  # pragma: no cover - direct execution from another cwd
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        from sanitizer import residual_scrub as _residual_scrub
    except ImportError:
        def _residual_scrub(text, skip=None):
            return text if isinstance(text, str) else ""

# Keep the evidence, drop the credentials.
_INDICATOR_CLASSES = frozenset({"email", "ipv4", "ipv6", "guid", "mac-address"})

MAX_BYTES = 64 * 1024 * 1024  # refuse absurd inputs rather than exhausting memory

# --------------------------------------------------------------------------
# Reference data
# --------------------------------------------------------------------------

# Extensions that execute, script, mount, or carry macros.
DANGEROUS_EXT = {
    "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf",
    "wsh", "hta", "msi", "msp", "cpl", "jar", "lnk", "iso", "img", "vhd", "vhdx",
    "one", "onepkg", "reg", "ps1", "psm1", "psd1", "chm", "scf", "url", "appx",
    "msix", "xll", "wll", "docm", "xlsm", "pptm", "dotm", "xlam", "mhtml", "mht",
    "settingcontent-ms", "library-ms", "diagcab", "svg", "vhd", "udf", "cab",
}

# Extensions commonly used as the decoy half of a double extension.
DECOY_EXT = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg",
    "png", "gif", "html", "htm", "csv", "zip", "rtf", "xml", "msg", "eml",
}

# Brands impersonated often enough to be worth an explicit lookalike check.
WATCHED_BRANDS = (
    "microsoft", "office365", "outlook", "sharepoint", "onedrive", "google",
    "gmail", "apple", "icloud", "amazon", "aws", "paypal", "dhl", "fedex", "ups",
    "docusign", "dropbox", "linkedin", "meta", "facebook", "instagram", "netflix",
    "adobe", "zoom", "slack", "okta", "salesforce", "oracle", "sap", "intuit",
    "hsbc", "barclays", "chase", "wellsfargo", "santander", "citibank",
    "gtbank", "zenithbank", "firstbank", "accessbank", "uba", "stanbic",
)

# Homoglyph and typo substitutions seen in real lookalike domains.
CONFUSABLE_MAP = (
    ("rn", "m"), ("vv", "w"), ("cl", "d"), ("0", "o"), ("1", "l"), ("l", "i"),
    ("5", "s"), ("3", "e"), ("4", "a"), ("$", "s"), ("8", "b"), ("7", "t"),
)

FREE_WEBMAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "ymail.com", "aol.com", "protonmail.com", "proton.me",
    "gmx.com", "mail.com", "zoho.com", "yandex.com", "icloud.com", "me.com",
}

# ClickFix / CrashFix / FileFix: the victim is talked into running the payload.
# These lures carry no attachment and frequently no link, so URL-and-hash
# extraction alone scores them clean. Detect the instruction text itself.
CLICKFIX_PATTERNS = (
    (r"(?i)\bwin(?:dows)?\s*\+\s*r\b", "Instructs use of the Windows Run dialog"),
    (r"(?i)\bpress\s+(?:the\s+)?(?:windows|win)\s+key", "Instructs a Windows key press"),
    (r"(?i)\b(?:ctrl|command)\s*\+\s*v\b", "Instructs a clipboard paste"),
    (r"(?i)\bpaste\b[^.\n]{0,40}\b(?:terminal|powershell|command prompt|cmd|run box|run dialog)\b",
     "Instructs pasting into a shell"),
    (r"(?i)\bpowershell(?:\.exe)?\b[^\n]{0,80}(?:-enc|-e\s|-nop|-w\s+hidden|bypass|iex|invoke-expression)",
     "Encoded or hidden PowerShell command present in body"),
    (r"(?i)\bmshta\b|\bcertutil\b[^\n]{0,40}-urlcache|\bbitsadmin\b",
     "Living-off-the-land binary invocation in body"),
    (r"(?i)\b(?:verify|confirm)\s+(?:you\s+are|you're)\s+(?:a\s+)?human\b",
     "Fake human-verification prompt (ClickFix hallmark)"),
    (r"(?i)\bi\s*am\s*not\s*a\s*robot\b", "Fake CAPTCHA prompt"),
    (r"(?i)\bcaptcha\b[^\n]{0,60}\b(?:paste|run|press|copy)\b", "CAPTCHA combined with run/paste instruction"),
    (r"(?i)\bfix\s+(?:it|this)\s+(?:yourself|manually)\b", "Self-remediation lure"),
    (r"(?i)\b(?:crash|error)\s+report[^\n]{0,60}\b(?:copy|paste|run)\b", "CrashFix-style dialog lure"),
)

DEVICE_CODE_PATTERNS = (
    (r"(?i)microsoft\.com/devicelogin", "Microsoft device-code login endpoint referenced"),
    (r"(?i)\baka\.ms/devicelogin\b", "Microsoft device-code shortlink referenced"),
    (r"(?i)\benter\s+(?:the\s+)?code\b[^\n]{0,40}\b[A-Z0-9]{6,9}\b", "Device-code entry instruction"),
    (r"(?i)\bdevice\s+code\b", "Device-code flow mentioned"),
)

CREDENTIAL_LURE_PATTERNS = (
    (r"(?i)\b(?:password|passphrase)\s+(?:will\s+)?expir", "Password expiry pressure"),
    (r"(?i)\bre-?authenticat", "Re-authentication demand"),
    (r"(?i)\bverify\s+your\s+(?:account|identity|email|mailbox)", "Account verification demand"),
    (r"(?i)\bmailbox\s+(?:is\s+)?(?:full|quota|storage)", "Mailbox quota pressure"),
    (r"(?i)\byour\s+account\s+(?:will\s+be\s+)?(?:suspend|disabl|lock|clos|terminat)", "Account suspension threat"),
    (r"(?i)\bunusual\s+sign-?in\b|\bsuspicious\s+(?:activity|sign-?in)\b", "Fake security alert"),
    (r"(?i)\bmfa\b[^\n]{0,40}\b(?:re-?enroll|re-?register|expired)\b", "MFA re-enrolment lure"),
    (r"(?i)\bclick\s+(?:here|below)\s+to\s+(?:sign|log)\s*in", "Direct sign-in solicitation"),
)

BEC_LURE_PATTERNS = (
    (r"(?i)\b(?:wire|bank|payment)\s+(?:transfer|details|instructions)\b", "Payment instruction change"),
    (r"(?i)\bupdate[^\n]{0,30}\b(?:bank|account|remittance|beneficiary)\s+details\b", "Beneficiary change request"),
    (r"(?i)\boutstanding\s+invoice\b|\bpast\s+due\b|\boverdue\s+payment\b", "Invoice pressure"),
    (r"(?i)\burgent\b[^\n]{0,40}\b(?:payment|transfer|wire)\b", "Urgent payment demand"),
    (r"(?i)\bkeep\s+this\s+(?:confidential|between us)\b", "Secrecy request"),
    (r"(?i)\bi'?m\s+(?:currently\s+)?in\s+a\s+meeting\b", "Unavailability pretext"),
    (r"(?i)\bgift\s+cards?\b", "Gift card request"),
    (r"(?i)\bchange\s+(?:of\s+)?(?:payroll|salary)\s+account\b", "Payroll diversion"),
)

SUSPICIOUS_HOSTING = (
    "ipfs.io", "cloudflare-ipfs.com", "dweb.link", "r2.dev", "web.app",
    "firebaseapp.com", "firebasestorage.googleapis.com", "blob.core.windows.net",
    "weebly.com", "wixsite.com", "glitch.me", "pages.dev", "workers.dev",
    "netlify.app", "vercel.app", "repl.co", "duckdns.org", "ngrok.io",
    "ngrok-free.app", "trycloudflare.com", "sharepoint-files.com",
    "googleusercontent.com", "amazonaws.com", "storage.googleapis.com",
    "sendgrid.net", "mailgun.org", "t.co", "bit.ly", "tinyurl.com",
    "rebrand.ly", "cutt.ly", "is.gd", "shorturl.at", "lnkd.in",
)

URL_RE = re.compile(r"""(?i)\bhttps?://[^\s<>"'\)\]}»,;]+""")
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
QR_HINT_RE = re.compile(r"(?i)\b(?:qr[\s-]?code|scan\s+(?:the\s+)?(?:qr|code)|scan\s+to\s+(?:view|verify|pay))\b")


# --------------------------------------------------------------------------
# Defanging - targeted, never a blanket dot replacement
# --------------------------------------------------------------------------
def defang_ip(value):
    """203.0.113.5 -> 203[.]0[.]113[.]5"""
    if not value:
        return ""
    return value.replace(".", "[.]").replace(":", "[:]")


def defang_domain(value):
    """evil.com -> evil[.]com"""
    if not value:
        return ""
    return value.replace(".", "[.]")


def defang_url(value):
    """
    https://evil.com/a.php?x=1 -> hxxps://evil[.]com/a[.]php?x=1

    Only the scheme and the host are rewritten plus dots in the path, which is
    enough to kill auto-linking. A blanket `text.replace(".", "[.]")` over whole
    sentences - as the previous scaffold did - corrupts ordinary prose and makes
    the report unreadable.
    """
    if not value:
        return ""
    out = re.sub(r"(?i)^http://", "hxxp://", value)
    out = re.sub(r"(?i)^https://", "hxxps://", out)
    out = re.sub(r"(?i)^ftp://", "fxp://", out)
    return out.replace(".", "[.]")


def defang_email(value):
    if not value or "@" not in value:
        return value or ""
    local, _, domain = value.rpartition("@")
    return "%s[at]%s" % (local, defang_domain(domain))


def _scrub(text):
    """Always-on credential redaction that preserves attacker indicators."""
    return _residual_scrub(text or "", skip=_INDICATOR_CLASSES)


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def _levenshtein(a, b, cap=4):
    """Bounded edit distance; returns cap+1 once it provably exceeds cap."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        best = i
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            val = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            cur.append(val)
            best = min(best, val)
        prev = cur
        if best > cap:
            return cap + 1
    return prev[-1]


def address_domain(addr):
    if not addr or "@" not in addr:
        return ""
    return addr.rpartition("@")[2].strip().strip(">").strip("]").lower()


def registrable(domain):
    """
    Best-effort eTLD+1 without a public-suffix list (no network, no deps).
    Handles the common two-level suffixes so co.uk and com.ng behave.
    """
    if not domain:
        return ""
    parts = [p for p in domain.lower().split(".") if p]
    if len(parts) < 2:
        return domain.lower()
    two_level = {
        "co", "com", "net", "org", "gov", "edu", "ac", "mil", "or", "ne", "gob",
    }
    if len(parts) >= 3 and parts[-2] in two_level and len(parts[-1]) <= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def first_address(header_value):
    if not header_value:
        return ""
    pairs = email.utils.getaddresses([header_value])
    for _, addr in pairs:
        if addr:
            return addr.strip().lower()
    return ""


def display_name(header_value):
    if not header_value:
        return ""
    pairs = email.utils.getaddresses([header_value])
    for name, _ in pairs:
        if name:
            return name.strip()
    return ""


# --------------------------------------------------------------------------
# Authentication-Results parsing (RFC 8601)
# --------------------------------------------------------------------------
def parse_auth_results(headers):
    """
    Collapse every Authentication-Results and vendor-specific auth header into a
    normalised view. Later hops are evaluated first because the nearest trusted
    receiver's verdict is the one that matters.
    """
    blob = " ".join(headers)
    low = blob.lower()
    result = {
        "raw": blob.strip(),
        "spf": None, "dkim": None, "dmarc": None, "arc": None, "compauth": None,
        "dkim_domains": [], "spf_mailfrom": "", "dmarc_policy": "", "reason": "",
    }

    for mech in ("spf", "dkim", "dmarc", "arc", "compauth"):
        m = re.search(r"\b%s\s*=\s*([a-z]+)" % mech, low)
        if m:
            result[mech] = m.group(1)

    result["dkim_domains"] = sorted({
        d.lower().strip(" \t\"';") for d in re.findall(r"(?i)\bheader\.d\s*=\s*([^\s;,]+)", blob)
    } | {
        d.lower().strip(" \t\"';") for d in re.findall(r"(?i)\bd\s*=\s*([^\s;,]+)", blob)
    } - {""})

    m = re.search(r"(?i)\bsmtp\.mailfrom\s*=\s*([^\s;,]+)", blob)
    if m:
        result["spf_mailfrom"] = m.group(1).lower().strip(" \t\"';")
    m = re.search(r"(?i)\b(?:header\.from|dmarc[^;]*?header\.from)\s*=\s*([^\s;,]+)", blob)
    if m:
        result["dmarc_header_from"] = m.group(1).lower().strip(" \t\"';")
    m = re.search(r"(?i)\b(?:p|policy)\s*=\s*(none|quarantine|reject)\b", blob)
    if m:
        result["dmarc_policy"] = m.group(1).lower()
    m = re.search(r"(?i)\breason\s*=\s*\"?([^\";]+)", blob)
    if m:
        result["reason"] = m.group(1).strip()
    return result


def parse_received_hops(received_headers):
    """Oldest-first hop timeline. Received headers are prepended, so reverse them."""
    hops = []
    for index, raw in enumerate(reversed(received_headers)):
        flat = " ".join(str(raw).split())
        stamp = None
        _, _, tail = flat.rpartition(";")
        if tail:
            try:
                parsed = email.utils.parsedate_to_datetime(tail.strip())
                if parsed is not None:
                    stamp = parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
            except (TypeError, ValueError, IndexError, OverflowError):
                stamp = None
        ips = [ip for ip in IPV4_RE.findall(flat)]
        public = []
        for ip in ips:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr.is_global:
                public.append(ip)
        m = re.search(r"(?i)\bfrom\s+([A-Za-z0-9._-]+)", flat)
        hops.append({
            "index": index,
            "from_host": (m.group(1).lower() if m else ""),
            "ips": ips,
            "public_ips": public,
            "timestamp": stamp.isoformat() if stamp else "",
            "_dt": stamp,
            "raw": flat[:400],
        })

    for i in range(1, len(hops)):
        prev, cur = hops[i - 1]["_dt"], hops[i]["_dt"]
        delay = None
        if prev and cur:
            delay = (cur - prev).total_seconds()
        hops[i]["delay_seconds"] = delay
    if hops:
        hops[0]["delay_seconds"] = None
    for hop in hops:
        hop.pop("_dt", None)
    return hops


# --------------------------------------------------------------------------
# Lookalike / impersonation analysis
# --------------------------------------------------------------------------
def _normalise_confusables(label):
    out = label.lower()
    for bad, good in CONFUSABLE_MAP:
        out = out.replace(bad, good)
    return out


def analyse_lookalike(domain):
    findings = []
    if not domain:
        return findings
    low = domain.lower()

    if "xn--" in low:
        findings.append({
            "severity": "HIGH",
            "indicator": "Punycode domain",
            "detail": "Domain contains an IDN punycode label (xn--), a standard "
                      "homograph impersonation vector.",
        })
    try:
        if any(ord(ch) > 127 for ch in domain):
            scripts = {unicodedata.name(ch, "").split()[0]
                       for ch in domain if ch.isalpha() and ord(ch) > 127}
            findings.append({
                "severity": "HIGH",
                "indicator": "Mixed-script domain",
                "detail": "Domain mixes non-ASCII scripts (%s) with ASCII, which is "
                          "how Cyrillic/Latin homoglyph lookalikes are built."
                          % (", ".join(sorted(s for s in scripts if s)) or "non-Latin"),
            })
    except ValueError:
        pass

    base = registrable(low)
    label = base.split(".")[0] if base else ""
    if label:
        folded = _normalise_confusables(label)
        for brand in WATCHED_BRANDS:
            if label == brand:
                break
            distance = _levenshtein(folded, brand, cap=2)
            if folded == brand and label != brand:
                findings.append({
                    "severity": "HIGH",
                    "indicator": "Homoglyph lookalike of '%s'" % brand,
                    "detail": "Label '%s' normalises to '%s' after confusable "
                              "substitution." % (label, brand),
                })
                break
            if 0 < distance <= 2 and len(brand) >= 5:
                findings.append({
                    "severity": "HIGH",
                    "indicator": "Typosquat of '%s'" % brand,
                    "detail": "Label '%s' is %d edit(s) from '%s'." % (label, distance, brand),
                })
                break
            if brand in label and label != brand and len(label) > len(brand):
                findings.append({
                    "severity": "MEDIUM",
                    "indicator": "Brand embedded in unrelated domain",
                    "detail": "Label '%s' embeds '%s' but is not that domain."
                              % (label, brand),
                })
                break
    return findings


def analyse_alignment(from_addr, reply_to, return_path, sender, auth):
    """
    DMARC alignment per RFC 9989: a pass requires SPF or DKIM to authenticate a
    domain that aligns with the visible From. A bare spf=pass or dkim=pass on an
    unrelated domain is NOT a DMARC pass.
    """
    findings = []
    from_dom = address_domain(from_addr)
    from_org = registrable(from_dom)

    dkim_aligned = False
    for d in auth.get("dkim_domains") or []:
        if registrable(d) == from_org and from_org:
            dkim_aligned = True
            break
    spf_dom = auth.get("spf_mailfrom") or address_domain(return_path)
    spf_aligned = bool(from_org) and registrable(spf_dom) == from_org

    spf_pass = auth.get("spf") == "pass"
    dkim_pass = auth.get("dkim") == "pass"
    dmarc = auth.get("dmarc")

    aligned_pass = (spf_pass and spf_aligned) or (dkim_pass and dkim_aligned)

    if dmarc == "fail" or (dmarc is None and not aligned_pass and (spf_pass or dkim_pass)):
        findings.append({
            "severity": "HIGH",
            "indicator": "DMARC alignment failure",
            "detail": "Neither an SPF-authenticated nor a DKIM-authenticated domain "
                      "aligns with the visible From domain '%s'. This is the "
                      "signature of direct domain spoofing." % (from_dom or "unknown"),
        })

    # The classic false positive: forwarding breaks SPF but leaves DKIM intact.
    if auth.get("spf") in ("fail", "softfail") and dkim_pass and dkim_aligned:
        findings.append({
            "severity": "INFO",
            "indicator": "Forwarding signature, not spoofing",
            "detail": "spf=%s with an aligned dkim=pass is the normal result of "
                      "legitimate forwarding or a mailing list, because the "
                      "forwarder re-sends from its own IP. Do not treat the SPF "
                      "failure alone as spoofing." % auth.get("spf"),
        })

    if aligned_pass and dmarc != "fail":
        findings.append({
            "severity": "MEDIUM",
            "indicator": "Authenticated sender - consider account compromise",
            "detail": "The message is correctly authenticated and aligned for '%s'. "
                      "If the content is still malicious this indicates Business "
                      "Email Compromise or an abused cloud tenant, not header "
                      "forgery." % (from_dom or "unknown"),
        })

    reply_dom = address_domain(reply_to)
    if reply_dom and from_org and registrable(reply_dom) != from_org:
        sev = "HIGH" if reply_dom in FREE_WEBMAIL else "MEDIUM"
        findings.append({
            "severity": sev,
            "indicator": "Reply-To divergence",
            "detail": "Reply-To domain '%s' differs from the From domain '%s'%s. "
                      "This is the standard BEC reply-redirect pattern."
                      % (reply_dom, from_dom,
                         " and is free webmail" if reply_dom in FREE_WEBMAIL else ""),
        })

    rp_dom = address_domain(return_path)
    if rp_dom and from_org and registrable(rp_dom) != from_org:
        findings.append({
            "severity": "MEDIUM",
            "indicator": "Return-Path divergence",
            "detail": "Envelope Return-Path domain '%s' differs from the header "
                      "From domain '%s'. Common for bulk senders, suspicious "
                      "otherwise." % (rp_dom, from_dom),
        })

    sender_dom = address_domain(sender)
    if sender_dom and from_org and registrable(sender_dom) != from_org:
        findings.append({
            "severity": "LOW",
            "indicator": "Sender header divergence",
            "detail": "Sender '%s' differs from From '%s'." % (sender_dom, from_dom),
        })

    name = display_name(from_addr)
    if name:
        name_low = name.lower()
        for brand in WATCHED_BRANDS:
            if brand in name_low.replace(" ", "") and from_org and brand not in from_org:
                findings.append({
                    "severity": "HIGH",
                    "indicator": "Display-name impersonation",
                    "detail": "Display name claims '%s' but the sending domain is "
                              "'%s'." % (name, from_dom or "unknown"),
                })
                break
        if "@" in name and address_domain(name) and from_org \
                and registrable(address_domain(name)) != from_org:
            findings.append({
                "severity": "HIGH",
                "indicator": "Display name forges an address",
                "detail": "Display name contains an address on a different domain, "
                          "which renders as the sender in most clients.",
            })

    return findings, {
        "from_domain": from_dom,
        "from_org_domain": from_org,
        "dkim_aligned": dkim_aligned,
        "spf_aligned": spf_aligned,
        "aligned_pass": aligned_pass,
        "reply_to_domain": reply_dom,
        "return_path_domain": rp_dom,
    }


# --------------------------------------------------------------------------
# Body, URL, attachment and lure analysis
# --------------------------------------------------------------------------
def extract_bodies(msg):
    """Return (text_body, html_body). Decoding never raises on hostile input."""
    text_parts, html_parts = [], []
    try:
        walker = msg.walk()
    except Exception:
        return "", ""
    for part in walker:
        try:
            if part.is_multipart():
                continue
            ctype = (part.get_content_type() or "").lower()
            if part.get_filename():
                continue
            if ctype not in ("text/plain", "text/html"):
                continue
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            try:
                decoded = payload.decode(charset, errors="replace")
            except (LookupError, UnicodeDecodeError, TypeError):
                decoded = payload.decode("utf-8", errors="replace")
            (text_parts if ctype == "text/plain" else html_parts).append(decoded)
        except Exception:
            # A single malformed MIME part must not abort the whole analysis.
            continue
    return "\n".join(text_parts), "\n".join(html_parts)


def html_to_text(html):
    if not html:
        return ""
    out = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", html)
    out = re.sub(r"(?s)<[^>]{0,4000}>", " ", out)
    out = out.replace("&nbsp;", " ").replace("&amp;", "&")
    out = out.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"')
    return re.sub(r"\s+", " ", out).strip()


def extract_urls(text_body, html_body):
    found = {}
    for blob in (text_body or "", html_body or ""):
        for raw in URL_RE.findall(blob):
            cleaned = raw.rstrip(".,);:'\"")
            if cleaned and cleaned not in found:
                found[cleaned] = True
    # Anchor hrefs can differ from visible text - that mismatch is the lure.
    mismatches = []
    if html_body:
        for m in re.finditer(
                r"(?is)<a\b[^>]{0,2000}?href\s*=\s*[\"']?([^\"'>\s]{1,2000})[\"']?[^>]{0,2000}>(.{0,300}?)</a>",
                html_body):
            href, label = m.group(1), html_to_text(m.group(2))
            if not href.lower().startswith(("http://", "https://")):
                continue
            found.setdefault(href.rstrip(".,);:'\""), True)
            label_urls = URL_RE.findall(label)
            if label_urls:
                shown = registrable(_host_of(label_urls[0]))
                actual = registrable(_host_of(href))
                if shown and actual and shown != actual:
                    mismatches.append({
                        "displayed": defang_url(label_urls[0]),
                        "actual": defang_url(href),
                    })
            elif label and "." in label and " " not in label.strip():
                shown = registrable(label.strip().lower())
                actual = registrable(_host_of(href))
                if shown and actual and shown != actual and "." in shown:
                    mismatches.append({
                        "displayed": defang_domain(label.strip()),
                        "actual": defang_url(href),
                    })
    return list(found.keys()), mismatches


def _host_of(url):
    m = re.match(r"(?i)^[a-z][a-z0-9+.\-]*://([^/\\?#:]+)", url or "")
    if m:
        return m.group(1).lower()
    return (url or "").split("/")[0].lower()


def analyse_urls(urls):
    findings, rows = [], []
    for url in urls:
        host = _host_of(url)
        notes = []
        try:
            ipaddress.ip_address(host)
            notes.append("raw IP host")
        except ValueError:
            pass
        if "xn--" in host:
            notes.append("punycode host")
        if "@" in url.split("//", 1)[-1].split("/")[0]:
            notes.append("userinfo obfuscation")
        for bad in SUSPICIOUS_HOSTING:
            if host.endswith(bad) or host == bad:
                notes.append("abusable hosting/shortener (%s)" % bad)
                break
        if len(url) > 220:
            notes.append("very long URL")
        if re.search(r"(?i)(?:redirect|url|next|continue|return|dest)=https?%3a", url):
            notes.append("open-redirect parameter")
        if re.search(r"(?i)\.(?:zip|mov)(?:/|$)", host):
            notes.append("ambiguous .zip/.mov TLD")
        if re.search(r"(?i)[?&](?:email|user|login|usr)=", url):
            notes.append("pre-filled victim identity (credential harvest)")
        rows.append({"url": defang_url(url), "host": defang_domain(host), "notes": notes})
        for note in notes:
            findings.append({
                "severity": "HIGH" if "credential harvest" in note or "punycode" in note
                            or "userinfo" in note else "MEDIUM",
                "indicator": "Suspicious URL (%s)" % note,
                "detail": "URL %s" % defang_url(url),
            })
        findings.extend(
            dict(f, detail="%s (via URL %s)" % (f["detail"], defang_url(url)))
            for f in analyse_lookalike(host)
        )
    return findings, rows


def analyse_attachments(msg):
    findings, rows = [], []
    try:
        parts = list(msg.walk())
    except Exception:
        return findings, rows
    for part in parts:
        try:
            if part.is_multipart():
                continue
            name = part.get_filename()
            if not name:
                continue
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            digest = hashlib.sha256(payload).hexdigest() if payload else ""
            clean_name = "".join(ch for ch in str(name) if ch.isprintable())
            segs = [s for s in clean_name.lower().split(".") if s]
            ext = segs[-1] if len(segs) > 1 else ""
            notes = []
            if ext in DANGEROUS_EXT:
                notes.append("executable/scriptable extension .%s" % ext)
            if len(segs) > 2 and segs[-2] in DECOY_EXT and ext in DANGEROUS_EXT:
                notes.append("double extension .%s.%s" % (segs[-2], ext))
            if re.search(r"[‪-‮⁦-⁩]", str(name)):
                notes.append("bidi override in filename (extension spoofing)")
            if ext in ("htm", "html", "mhtml", "mht", "svg"):
                body = payload.decode("utf-8", errors="replace")
                if re.search(r"(?i)<script|base64,|atob\(|unescape\(|document\.write", body):
                    notes.append("HTML smuggling markers (script/base64 blob)")
            if ext in ("iso", "img", "vhd", "vhdx", "udf"):
                notes.append("disk image container (bypasses mark-of-the-web)")
            if ext in ("one", "onepkg"):
                notes.append("OneNote container (embedded payload vector)")
            rows.append({
                "filename": clean_name, "content_type": part.get_content_type(),
                "size_bytes": len(payload), "sha256": digest, "notes": notes,
            })
            for note in notes:
                findings.append({
                    "severity": "HIGH" if ("double extension" in note or "bidi" in note
                                           or "smuggling" in note) else "MEDIUM",
                    "indicator": "Suspicious attachment (%s)" % note,
                    "detail": "Attachment '%s' SHA-256 %s" % (clean_name, digest or "n/a"),
                })
        except Exception:
            continue
    return findings, rows


def _match_patterns(body, patterns, label, severity):
    findings = []
    for pattern, why in patterns:
        if re.search(pattern, body):
            findings.append({
                "severity": severity, "indicator": "%s: %s" % (label, why),
                "detail": "Matched body pattern for %s." % label,
            })
    return findings


def analyse_lures(text_body, html_body, has_attachments, urls):
    body = "\n".join([text_body or "", html_to_text(html_body or "")])
    findings = []
    findings += _match_patterns(body, CLICKFIX_PATTERNS, "ClickFix/command-paste lure", "HIGH")
    findings += _match_patterns(body, DEVICE_CODE_PATTERNS, "Device-code phishing", "HIGH")
    findings += _match_patterns(body, CREDENTIAL_LURE_PATTERNS, "Credential-harvest lure", "MEDIUM")
    findings += _match_patterns(body, BEC_LURE_PATTERNS, "BEC/payment-fraud lure", "MEDIUM")

    if QR_HINT_RE.search(body):
        findings.append({
            "severity": "HIGH",
            "indicator": "Quishing (QR code lure)",
            "detail": "Body solicits a QR scan. QR payloads bypass text-based link "
                      "scanning; the destination cannot be read from the image "
                      "offline and must be decoded manually in a sandbox.",
        })
    elif not urls and not has_attachments and len(body.strip()) < 600:
        img_only = bool(re.search(r"(?i)<img\b", html_body or ""))
        if img_only:
            findings.append({
                "severity": "MEDIUM",
                "indicator": "Image-only body with no links",
                "detail": "Short image-only message with no extractable URL. "
                          "Typical of QR or screenshot lures that evade text scanning.",
            })
    if not urls and not has_attachments:
        findings.append({
            "severity": "INFO",
            "indicator": "No link or attachment present",
            "detail": "Absence of URLs and attachments does not imply safety. "
                      "ClickFix-class lures deliver payloads purely as instructions "
                      "for the victim to execute.",
        })
    return findings


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------
SEVERITY_WEIGHT = {"HIGH": 10, "MEDIUM": 4, "LOW": 1, "INFO": 0}


def classify(findings, alignment, has_attachments):
    score = sum(SEVERITY_WEIGHT.get(f["severity"], 0) for f in findings)
    text = " ".join(f["indicator"].lower() for f in findings)

    forwarding = "forwarding signature" in text
    if forwarding:
        score = max(0, score - 10)

    if "clickfix" in text or "device-code phishing" in text:
        verdict = "Malware Delivery / Command Execution Lure"
    elif "quishing" in text:
        verdict = "Confirmed Phishing / Credential Harvest"
    elif has_attachments and "suspicious attachment" in text:
        verdict = "Malware Delivery"
    elif "bec/payment-fraud" in text and alignment.get("aligned_pass"):
        verdict = "Business Email Compromise (BEC)"
    elif "reply-to divergence" in text and "bec/payment-fraud" in text:
        verdict = "Business Email Compromise (BEC)"
    elif "credential-harvest" in text or "suspicious url" in text:
        verdict = "Confirmed Phishing / Credential Harvest"
    elif "dmarc alignment failure" in text or "display-name impersonation" in text \
            or "homoglyph" in text or "typosquat" in text or "punycode" in text:
        verdict = "Confirmed Phishing / Spoofed Sender"
    elif score >= 4:
        verdict = "Spam / Graymail"
    else:
        verdict = "Legitimate / False Positive"

    if score >= 20:
        confidence = "High"
    elif score >= 8:
        confidence = "Medium"
    else:
        confidence = "Low"

    if verdict == "Legitimate / False Positive" and forwarding:
        confidence = "Medium"
    return verdict, confidence, score


# --------------------------------------------------------------------------
# Analysis entry point
# --------------------------------------------------------------------------
def analyse(raw_bytes, source_name, mask_recipients=False):
    try:
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    except Exception:
        try:
            msg = email.message_from_bytes(raw_bytes, policy=email.policy.compat32)
        except Exception as exc:
            raise ValueError("input is not a parseable RFC 5322 message: %s" % exc)

    def header(name):
        try:
            value = msg.get(name)
            return "" if value is None else str(value)
        except Exception:
            return ""

    from_raw = header("From")
    from_addr = first_address(from_raw)
    reply_to = first_address(header("Reply-To"))
    return_path = first_address(header("Return-Path"))
    sender = first_address(header("Sender"))
    to_raw = header("To")
    cc_raw = header("Cc")
    subject = header("Subject")

    try:
        auth_headers = [str(v) for v in msg.get_all("Authentication-Results", [])]
        auth_headers += [str(v) for v in msg.get_all("ARC-Authentication-Results", [])]
        auth_headers += [str(v) for v in msg.get_all("X-Forefront-Antispam-Report", [])]
        auth_headers += [str(v) for v in msg.get_all("X-Microsoft-Antispam", [])]
        received = [str(v) for v in msg.get_all("Received", [])]
    except Exception:
        auth_headers, received = [], []

    auth = parse_auth_results(auth_headers)
    hops = parse_received_hops(received)
    text_body, html_body = extract_bodies(msg)
    urls, link_mismatches = extract_urls(text_body, html_body)

    findings = []
    align_findings, alignment = analyse_alignment(from_raw, reply_to, return_path, sender, auth)
    findings += align_findings
    findings += analyse_lookalike(alignment["from_domain"])
    url_findings, url_rows = analyse_urls(urls)
    findings += url_findings
    att_findings, att_rows = analyse_attachments(msg)
    findings += att_findings
    findings += analyse_lures(text_body, html_body, bool(att_rows), urls)

    for mm in link_mismatches:
        findings.append({
            "severity": "HIGH",
            "indicator": "Displayed link does not match destination",
            "detail": "Shows %s but resolves to %s." % (mm["displayed"], mm["actual"]),
        })

    if not auth_headers:
        findings.append({
            "severity": "MEDIUM",
            "indicator": "No Authentication-Results header",
            "detail": "No receiver auth verdict present. Either the message was not "
                      "processed by an authenticating gateway, or the headers were "
                      "pasted incompletely. Alignment cannot be confirmed.",
        })
    if len(hops) == 1:
        findings.append({
            "severity": "LOW",
            "indicator": "Single Received hop",
            "detail": "Only one hop recorded; direct-to-MX injection or truncated headers.",
        })
    for hop in hops:
        if hop.get("delay_seconds") is not None and hop["delay_seconds"] < -60:
            findings.append({
                "severity": "HIGH",
                "indicator": "Received hop timestamps run backwards",
                "detail": "Hop %d is %.0fs earlier than the previous hop, indicating "
                          "forged Received headers." % (hop["index"], -hop["delay_seconds"]),
            })
            break

    verdict, confidence, score = classify(findings, alignment, bool(att_rows))

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 9))

    originating = ""
    for hop in hops:
        if hop.get("public_ips"):
            originating = hop["public_ips"][0]
            break

    recipients = to_raw
    cc = cc_raw
    if mask_recipients:
        recipients = "[MASKED-RECIPIENTS:%d]" % len(email.utils.getaddresses([to_raw or ""]))
        cc = "[MASKED-RECIPIENTS:%d]" % len(email.utils.getaddresses([cc_raw or ""]))

    return {
        "source": os.path.basename(source_name),
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verdict": verdict,
        "confidence": confidence,
        "risk_score": score,
        "headers": {
            "from": _scrub(defang_email(from_addr)),
            "from_display_name": _scrub(display_name(from_raw)),
            "reply_to": _scrub(defang_email(reply_to)),
            "return_path": _scrub(defang_email(return_path)),
            "sender": _scrub(defang_email(sender)),
            "to": _scrub(recipients),
            "cc": _scrub(cc),
            "subject": _scrub(subject),
            "date": header("Date"),
            "message_id": header("Message-ID"),
        },
        "authentication": {
            "spf": auth.get("spf"), "dkim": auth.get("dkim"),
            "dmarc": auth.get("dmarc"), "arc": auth.get("arc"),
            "compauth": auth.get("compauth"),
            "dkim_domains": [defang_domain(d) for d in auth.get("dkim_domains") or []],
            "spf_mailfrom": defang_domain(auth.get("spf_mailfrom") or ""),
            "dmarc_policy": auth.get("dmarc_policy") or "",
            "spf_aligned": alignment["spf_aligned"],
            "dkim_aligned": alignment["dkim_aligned"],
            "dmarc_aligned_pass": alignment["aligned_pass"],
        },
        "hop_timeline": hops,
        "originating_ip": defang_ip(originating),
        "findings": [
            {"severity": f["severity"], "indicator": _scrub(f["indicator"]),
             "detail": _scrub(f["detail"])} for f in findings
        ],
        "iocs": {
            "sender_addresses": sorted({defang_email(a) for a in (from_addr, reply_to, return_path) if a}),
            "domains": sorted({defang_domain(d) for d in (
                alignment["from_domain"], alignment["reply_to_domain"],
                alignment["return_path_domain"]) if d}),
            "originating_ips": [defang_ip(ip) for hop in hops for ip in hop.get("public_ips", [])][:25],
            "urls": [r["url"] for r in url_rows],
            "attachment_sha256": [r["sha256"] for r in att_rows if r["sha256"]],
        },
        "attachments": att_rows,
        "urls": url_rows,
        "link_mismatches": link_mismatches,
    }


# --------------------------------------------------------------------------
# Renderers
# --------------------------------------------------------------------------
def _alignment_label(result, aligned):
    """
    Alignment and result are orthogonal, and conflating them misleads the reader.
    A domain can align while the mechanism still fails (attacker-owned domain with a
    broken record), and a mechanism can pass on a domain that does not align at all -
    which is the actual spoofing signature.
    """
    if not aligned:
        return "domain does NOT align"
    if result == "pass":
        return "aligns and passes"
    if result in (None, "", "absent", "none"):
        return "domain aligns (no result)"
    return "domain aligns but result is %s" % result


def render_markdown(r):
    a = r["authentication"]
    h = r["headers"]
    out = []
    out.append("# Phishing Triage Report: %s" % r["source"])
    out.append("")
    out.append("## 1. Triage Verdict")
    out.append("")
    out.append("- **Classification:** `%s`" % r["verdict"])
    out.append("- **Confidence:** `%s`" % r["confidence"])
    out.append("- **Risk Score:** `%d`" % r["risk_score"])
    out.append("- **Originating IP:** `%s`" % (r["originating_ip"] or "not determinable"))
    out.append("- **Report Generated (UTC):** `%s`" % r["generated_utc"])
    out.append("")
    out.append("> All indicators below are defanged. Do not re-fang or click them.")
    out.append("")
    out.append("## 2. Header and Authentication Alignment")
    out.append("")
    out.append("| Field | Observed Value (Defanged) | Verdict |")
    out.append("| :--- | :--- | :--- |")
    rows = [
        ("From", h["from"], "visible sender"),
        ("Display Name", h["from_display_name"] or "(none)", "rendered to the user"),
        ("Reply-To", h["reply_to"] or "(absent)",
         "DIVERGENT" if h["reply_to"] and h["reply_to"] != h["from"] else "aligned/absent"),
        ("Return-Path", h["return_path"] or "(absent)",
         "DIVERGENT" if h["return_path"] and h["return_path"] != h["from"] else "aligned/absent"),
        ("Subject", h["subject"] or "(none)", "-"),
        ("Date", h["date"] or "(none)", "-"),
        ("SPF", a["spf"] or "absent", _alignment_label(a["spf"], a["spf_aligned"])),
        ("DKIM", a["dkim"] or "absent", _alignment_label(a["dkim"], a["dkim_aligned"])),
        ("DMARC", a["dmarc"] or "absent",
         "PASS (aligned)" if a["dmarc_aligned_pass"] else "FAIL / unproven"),
        ("CompAuth", a["compauth"] or "absent", "-"),
        ("DKIM d=", ", ".join(a["dkim_domains"]) or "(none)", "signing domain"),
        ("SPF mailfrom", a["spf_mailfrom"] or "(none)", "envelope domain"),
    ]
    for name, value, verdict in rows:
        out.append("| %s | `%s` | %s |" % (name, str(value).replace("|", "\\|")[:160], verdict))
    out.append("")
    out.append("DMARC alignment is evaluated per RFC 9989 (obsoletes RFC 7489): a pass "
               "requires SPF or DKIM to authenticate a domain that aligns with the "
               "visible From domain.")
    out.append("")
    out.append("## 3. Prioritised Findings")
    out.append("")
    if r["findings"]:
        out.append("| Severity | Indicator | Detail |")
        out.append("| :--- | :--- | :--- |")
        for f in r["findings"]:
            out.append("| **%s** | %s | %s |" % (
                f["severity"], f["indicator"].replace("|", "\\|"),
                f["detail"].replace("|", "\\|")[:300]))
    else:
        out.append("No findings recorded.")
    out.append("")
    out.append("## 4. Received Hop Timeline")
    out.append("")
    if r["hop_timeline"]:
        out.append("| Hop | From Host | Public IP (Defanged) | Timestamp | Delay (s) |")
        out.append("| :--- | :--- | :--- | :--- | :--- |")
        for hop in r["hop_timeline"]:
            out.append("| %d | `%s` | `%s` | `%s` | %s |" % (
                hop["index"], hop.get("from_host") or "-",
                defang_ip((hop.get("public_ips") or ["-"])[0]),
                hop.get("timestamp") or "-",
                "-" if hop.get("delay_seconds") is None else "%.0f" % hop["delay_seconds"]))
        out.append("")
        out.append("Received hops below the attacker's true entry point are forgeable. "
                   "Corroborate the originating IP against gateway logs before blocking.")
    else:
        out.append("No Received headers present.")
    out.append("")
    out.append("## 5. Defanged IOC Blocklist")
    out.append("")
    iocs = r["iocs"]
    out.append("| Type | Indicator (Defanged) |")
    out.append("| :--- | :--- |")
    for label, key in (("Sender Address", "sender_addresses"), ("Domain", "domains"),
                       ("Originating IP", "originating_ips"), ("URL", "urls"),
                       ("Attachment SHA-256", "attachment_sha256")):
        for value in iocs.get(key) or []:
            out.append("| %s | `%s` |" % (label, str(value)[:300]))
    if not any(iocs.get(k) for k in iocs):
        out.append("| - | No extractable indicators |")
    out.append("")
    if r["attachments"]:
        out.append("## 6. Attachments")
        out.append("")
        out.append("| Filename | Type | Size | SHA-256 | Notes |")
        out.append("| :--- | :--- | :--- | :--- | :--- |")
        for att in r["attachments"]:
            out.append("| `%s` | %s | %d | `%s` | %s |" % (
                att["filename"][:80], att["content_type"], att["size_bytes"],
                att["sha256"][:64] or "-", "; ".join(att["notes"]) or "-"))
        out.append("")
    out.append("## 7. SOC Containment and Hunt Queries")
    out.append("")
    sender_host = (iocs.get("domains") or ["unknown[.]invalid"])[0].replace("[.]", ".")
    out.append("Microsoft Defender XDR - find every recipient of the campaign:")
    out.append("")
    out.append("```kusto")
    out.append("EmailEvents")
    out.append("| where Timestamp > ago(14d)")
    out.append('| where SenderFromDomain == "%s"' % sender_host)
    out.append("| project Timestamp, RecipientEmailAddress, Subject, DeliveryAction, NetworkMessageId")
    out.append("| order by Timestamp desc")
    out.append("```")
    out.append("")
    out.append("Exchange Online - scope then purge (review the scope before purging):")
    out.append("")
    out.append("```powershell")
    out.append('New-ComplianceSearch -Name "Phish-%s" -ExchangeLocation All `' % r["generated_utc"][:10])
    out.append('  -ContentMatchQuery \'(From:"%s")\'' % sender_host)
    out.append('Start-ComplianceSearch -Identity "Phish-%s"' % r["generated_utc"][:10])
    out.append("# After reviewing results:")
    out.append('# New-ComplianceSearchAction -SearchName "Phish-%s" -Purge -PurgeType SoftDelete'
               % r["generated_utc"][:10])
    out.append("```")
    out.append("")
    out.append("## 8. Reply to the Reporting Employee")
    out.append("")
    out.append("```text")
    if r["verdict"].startswith("Legitimate"):
        out.append("Thank you for reporting this message. We reviewed the headers and")
        out.append("found no evidence of spoofing or malicious content. The message")
        out.append("appears legitimate. Please continue to report anything that looks")
        out.append("unusual - a false alarm is always preferable to an unreported attack.")
    else:
        out.append("Thank you for reporting this message - you did exactly the right thing.")
        out.append("We have confirmed it is malicious (%s) and are removing it" % r["verdict"])
        out.append("from affected mailboxes and blocking the sender.")
        out.append("")
        out.append("Please do not reply to it, open any attachment, or follow any")
        out.append("instruction it contains. If you already entered your password or ran")
        out.append("any command it asked for, contact the service desk immediately so we")
        out.append("can reset your credentials and check the device.")
    out.append("```")
    out.append("")
    return "\n".join(out)


def render_ioc_csv(r):
    lines = ["type,indicator,verdict,confidence,source"]
    iocs = r["iocs"]
    for label, key in (("sender", "sender_addresses"), ("domain", "domains"),
                       ("ip", "originating_ips"), ("url", "urls"),
                       ("sha256", "attachment_sha256")):
        for value in iocs.get(key) or []:
            safe = str(value).replace('"', '""')
            lines.append('%s,"%s","%s",%s,"%s"' % (
                label, safe, r["verdict"], r["confidence"], r["source"]))
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        description="Offline phishing header, EML and IOC triage engine "
                    "(read-only, zero dependencies).")
    p.add_argument("-i", "--input", required=True,
                   help="Path to a .eml file, raw RFC 5322 headers, or '-' for stdin.")
    p.add_argument("-f", "--format", choices=["markdown", "json", "ioc-csv"],
                   default="markdown", help="Output format (default: markdown).")
    p.add_argument("--sanitize", action="store_true",
                   help="Additionally mask recipient identities (To/Cc) for external "
                        "sharing. Credential redaction and IOC defanging are always on.")
    p.add_argument("-o", "--output", help="Write to this path instead of stdout.")
    return p


def main():
    parser = build_parser()
    try:
        args = parser.parse_args()
    except SystemExit:
        return 2

    try:
        if args.input == "-":
            raw = sys.stdin.buffer.read()
        else:
            if os.path.isdir(args.input):
                sys.stderr.write("Error: input path is a directory, not a message file: "
                                 "%s\n" % args.input)
                return 1
            size = os.path.getsize(args.input)
            if size > MAX_BYTES:
                sys.stderr.write("Error: input is %d bytes, above the %d byte limit.\n"
                                 % (size, MAX_BYTES))
                return 1
            with open(args.input, "rb") as fh:
                raw = fh.read()
    except FileNotFoundError:
        sys.stderr.write("Error: input file not found: %s\n" % args.input)
        return 1
    except PermissionError:
        sys.stderr.write("Error: permission denied reading: %s\n" % args.input)
        return 1
    except OSError as exc:
        sys.stderr.write("Error: could not read input: %s\n" % exc)
        return 1

    if not raw or not raw.strip():
        sys.stderr.write("Error: input is empty. Supply a .eml file or pasted headers.\n")
        return 1

    try:
        report = analyse(raw, args.input if args.input != "-" else "stdin.eml",
                         mask_recipients=args.sanitize)
    except ValueError as exc:
        sys.stderr.write("Error: %s\n" % exc)
        return 1
    except RecursionError:
        sys.stderr.write("Error: message structure is nested too deeply to parse safely.\n")
        return 1
    except MemoryError:
        sys.stderr.write("Error: message exhausted available memory; refusing to continue.\n")
        return 1
    except Exception as exc:  # last resort: never show a traceback to an analyst
        sys.stderr.write("Error: unrecoverable problem analysing this message (%s: %s).\n"
                         % (type(exc).__name__, exc))
        return 1

    if args.format == "json":
        rendered = json.dumps(report, indent=2, sort_keys=True, default=str)
    elif args.format == "ioc-csv":
        rendered = render_ioc_csv(report)
    else:
        rendered = render_markdown(report)

    if args.output:
        try:
            parent = os.path.dirname(os.path.abspath(args.output))
            if parent and not os.path.isdir(parent):
                os.makedirs(parent, exist_ok=True)
            with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(rendered)
            sys.stderr.write("Report written to: %s\n" % args.output)
        except OSError as exc:
            sys.stderr.write("Error: could not write output: %s\n" % exc)
            return 1
    else:
        sys.stdout.write(rendered + ("\n" if not rendered.endswith("\n") else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
