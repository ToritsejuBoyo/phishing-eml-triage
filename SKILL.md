---
name: phishing-eml-triage
description: >-
  Analyzes raw .eml files and pasted RFC 5322 email headers offline to evaluate SPF, DKIM and DMARC
  alignment, detect Reply-To / Return-Path divergence and punycode or homoglyph lookalike domains,
  score modern lures that carry no link or attachment (ClickFix command-paste, quishing, Microsoft
  device-code phishing), and emit defanged IOC blocklists with SOC containment queries. Use when a
  user reports or forwards a suspicious email, pastes message headers, asks whether an urgent
  invoice or password-reset message is genuine, or when triaging a Report Phish submission.
license: MIT
version: 1.0.0
metadata:
  standard: agentskills.io
  dependencies: none (Python standard library only)
  access: read-only; never fetches a URL, resolves a domain, or executes an attachment
---

# Phishing Header, EML & IOC Triage Analyst (`phishing-eml-triage`)

## Purpose & Target Roles

Designed for **SOC Tier 1/Tier 2 Analysts, Incident Responders, Security Officers and IT Help Desk
Technicians** handling employee-reported phishing — "Report Phish" button submissions and
forward-as-attachment tickets. It replaces manual header reading with a deterministic verdict, a
defanged IOC blocklist, and ready-to-run hunt queries.

## Operating Rules & Safety Guardrails

1. **Mandatory IOC defanging.** NEVER output a clickable live URL, domain or IP. Every indicator is
   emitted defanged (`hxxps://`, `evil[.]com`, `203[.]0[.]113[.]5`) so no one can click it from a
   ticket or chat window. Do not re-fang an indicator to "check" it.
2. **Strictly static, offline analysis.** Never fetch a URL, resolve a domain, query DNS or
   WHOIS, submit a hash to a third party, or open an attachment. Every verdict comes from the bytes
   on disk. Sending a sample to an online sandbox is a decision for the operator, not this skill.
3. **Alignment is the verdict, not pass/fail.** A bare `spf=pass` or `dkim=pass` proves nothing on
   its own. DMARC (RFC 9989, which obsoletes RFC 7489) requires the SPF- or DKIM-authenticated
   domain to *align* with the visible `From` domain. Always state which domain actually aligned.
4. **`spf=fail` with an aligned `dkim=pass` is forwarding, not spoofing.** A forwarder re-sends
   from its own IP, so SPF breaks legitimately. Never call this spoofing on the SPF result alone.
5. **A full authenticated pass can still be an attack.** If SPF, DKIM and DMARC all pass and align
   for a real tenant, and the content is malicious, that indicates **Business Email Compromise or
   an abused cloud sender** — not header forgery. Say so explicitly, because the containment action
   is different: suspend the account, do not just block the domain.
6. **`Received` hops are forgeable.** An attacker controls every hop below their true entry point.
   Corroborate the originating IP against your own gateway logs before blocking it.
7. **Absence of a link or attachment is not safety.** ClickFix-class lures deliver the payload as
   instructions for the victim to run. Read the body text, not just the extracted indicators.
8. **Propose, do not apply.** Emit the purge and block commands for a human to review and run.

---

## Step 1: Run the Deterministic Triage Engine (Required First)

Always run the bundled engine before reasoning manually. It implements the full alignment, lookalike
and lure logic deterministically, so the verdict is reproducible rather than inferred:

```bash
# Markdown triage report (default)
python scripts/parse_eml_ioc.py -i ./reported-message.eml

# Structured JSON for automation or SIEM ingestion
python scripts/parse_eml_ioc.py -i ./reported-message.eml -f json

# IOC blocklist only, ready for a block rule import
python scripts/parse_eml_ioc.py -i ./reported-message.eml -f ioc-csv

# Mask recipient identities before sharing outside the responding team
python scripts/parse_eml_ioc.py -i ./reported-message.eml --sanitize -o ./report.md
```

Pass `-i -` to read a pasted message from stdin. If the user pasted only headers with no body, the
engine still works — say in the report that body-based lure detection was unavailable.

**Scope limit:** this skill parses `.eml` / RFC 5322 only. Outlook `.msg` is an OLE2 compound file
that cannot be read with the standard library alone, so it is deliberately out of scope. Ask the
operator to re-save the message as `.eml`, or to forward it as an attachment, rather than guessing.

---

## Step 2: Interpret the Authentication Verdict

Use [`references/email-auth-alignment.md`](references/email-auth-alignment.md) to read the result.
Work through, in order:

1. **Which domain authenticated?** Compare the DKIM `d=` domain and the SPF `smtp.mailfrom` domain
   against the organizational domain of the visible `From`.
2. **Did anything align?** If neither aligned, this is direct domain spoofing.
3. **Is this forwarding?** `spf=fail` plus an aligned `dkim=pass` is the forwarding signature.
4. **Is it authenticated but still hostile?** Aligned pass plus a malicious payload means BEC or a
   compromised tenant. Escalate as account compromise.
5. **Is `Authentication-Results` missing entirely?** Then alignment is unproven — say so rather
   than implying a pass.

## Step 3: Check Identity Divergence and Lookalikes

1. **`Reply-To` divergence** — the classic BEC redirect: `From` looks internal or executive while
   `Reply-To` points at free webmail or a lookalike. Treat free webmail as high severity.
2. **`Return-Path` divergence** — normal for bulk senders, suspicious otherwise.
3. **Display-name impersonation** — a display name claiming a brand the sending domain does not own.
4. **Punycode (`xn--`) and homoglyph domains** — `rnicrosoft.com` for `microsoft.com`, Cyrillic
   lookalikes, mixed-script labels.
5. **Displayed link vs destination** — an anchor showing one domain but resolving to another.

## Step 4: Inspect Payload, Lures and Attachments

Cross-reference [`references/phishing-ioc-matrix.md`](references/phishing-ioc-matrix.md):

- **ClickFix / CrashFix / FileFix** — instructions to press `Win+R`, paste from the clipboard, or
  run `powershell -enc`, usually behind a fake human-verification or crash-report prompt. These
  carry no attachment and often no link, so judge them on body text.
- **Quishing** — a QR lure. The destination is inside an image and cannot be read offline; it must
  be decoded in a sandbox before any verdict about the destination.
- **Device-code phishing** — references to `microsoft.com/devicelogin` or a short code to enter.
- **AiTM / MFA bypass** — reverse-proxy sign-in pages (Tycoon2FA, Sneaky2FA, Evilginx class).
  Defeats every MFA factor except FIDO2 and passkeys, so a successful login is not reassurance.
- **Dangerous and double extensions** — `.hta`, `.lnk`, `.iso`, `.one`, `.svg`, `.xll`,
  `invoice.pdf.exe`, plus bidi-override filenames that reverse the visible extension.
- **HTML smuggling** — script or base64 blobs inside an `.html` / `.svg` attachment.

## Step 5: Classify and Contain

Assign exactly one classification:

| Classification | Meaning | First containment action |
| :--- | :--- | :--- |
| `Confirmed Phishing / Credential Harvest` | Fake sign-in or data capture | Purge, block domain, reset any entered credential |
| `Confirmed Phishing / Spoofed Sender` | Failed alignment, lookalike or impersonation | Purge, block sender and lookalike domain |
| `Business Email Compromise (BEC)` | Authenticated sender, fraudulent request | Treat as account compromise; verify payment changes out of band |
| `Malware Delivery / Command Execution Lure` | Attachment payload or ClickFix-style instructions | Isolate any host where the command ran; purge |
| `Spam / Graymail` | Unwanted, not malicious | Filter; no incident |
| `Legitimate / False Positive` | Genuine mail | Reassure the reporter; do not discourage reporting |

---

## Step 6: Output Deliverable Structure

Populate [`assets/phishing-triage-report-template.md`](assets/phishing-triage-report-template.md):

1. **Triage verdict and risk score** — classification, confidence, decisive indicators.
2. **Header and authentication alignment table** — field, observed value (defanged), verdict.
3. **Prioritised findings** — severity-ordered, each citing the header or body evidence.
4. **Received hop timeline** — hops, public IPs, timestamps, delays, with the forgery caveat.
5. **Defanged IOC blocklist** — senders, domains, IPs, URLs, attachment SHA-256 hashes.
6. **SOC containment and hunt queries** — Defender XDR `EmailEvents` KQL, Exchange Online
   `New-ComplianceSearch`, and the user reply drawn from
   [`references/response-templates.md`](references/response-templates.md).

Always include the employee reply. Reporting users who receive no response stop reporting, and that
costs more detection coverage than any single blocked domain.

---

## Data Handling & Sanitization

Defanging and sanitization are separate controls and both apply:

- **Defanging is always on** — it stops an analyst clicking a live indicator.
- **Credential redaction is always on**, via the shared residual pass in
  [`scripts/sanitizer.py`](scripts/sanitizer.py). A reply chain inside a phishing message often
  contains real passwords, tokens, card numbers or national ID numbers; those are never operational
  evidence and are redacted before output.
- **Attacker indicators are deliberately preserved.** Sender addresses, originating IPs, URLs and
  hashes are the deliverable — redacting them would make the report useless for blocking. This is
  the one skill in the library that intentionally skips the indicator redaction classes.
- **`--sanitize` additionally masks the recipient side** (`To` / `Cc`) for sharing outside the
  responding team.

The contract is enforced by `tests/sanitizer_conformance_test.py` and
`tests/extreme_stress_matrix.py`.

## Bundled Resources

- **Triage Engine:** [`scripts/parse_eml_ioc.py`](scripts/parse_eml_ioc.py) — Read-only `.eml` and
  header parser, alignment evaluator, lookalike and lure scorer, IOC defanger. **Run this first.**
- **Shared Sanitizer:** [`scripts/sanitizer.py`](scripts/sanitizer.py) — Library-wide credential and
  PII redaction floor.
- **Authentication Reference:** [`references/email-auth-alignment.md`](references/email-auth-alignment.md)
  — SPF/DKIM/DMARC alignment rules per RFC 9989, forwarding and mailing-list behaviour, ARC caveats.
- **IOC & TTP Matrix:** [`references/phishing-ioc-matrix.md`](references/phishing-ioc-matrix.md) —
  Current lure taxonomy, dangerous extensions, abusable hosting, MITRE ATT&CK mapping.
- **Response Templates:** [`references/response-templates.md`](references/response-templates.md) —
  Reporter replies, escalation notes, and the all-staff notice for a confirmed campaign.
- **Report Template:** [`assets/phishing-triage-report-template.md`](assets/phishing-triage-report-template.md)
