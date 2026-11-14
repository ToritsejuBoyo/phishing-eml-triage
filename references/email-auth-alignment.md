# Email Authentication & DMARC Alignment Reference

Technical reference for interpreting SPF, DKIM, DMARC, ARC and CompAuth results during phishing
triage. Consult before issuing any verdict about whether a sender was spoofed.

## 1. Standards baseline

| Mechanism | Specification | Status |
| :--- | :--- | :--- |
| SPF | RFC 7208 | Proposed Standard |
| DKIM | RFC 6376 | Internet Standard |
| **DMARC** | **RFC 9989** | **Proposed Standard (May 2026) — obsoletes RFC 7489 and RFC 9091** |
| DMARC aggregate reporting | RFC 9990 | Companion to 9989 |
| DMARC failure reporting | RFC 9991 | Companion to 9989 |
| ARC | RFC 8617 | **Experimental** |
| `Authentication-Results` header | RFC 8601 | Proposed Standard |
| Message format | RFC 5322 | Internet Standard |

**What changed with RFC 9989 (DMARCbis):** the original RFC 7489 was an Informational document from
the Independent Submission Stream and never held Standards Track status. RFC 9989 replaces it on the
IETF Standards Track. The `v=DMARC1` version string is preserved, so existing published records keep
working. The `pct`, `rf` and `ri` tags were removed. Cite RFC 9989 in reports, not RFC 7489.

## 2. The only question that matters: alignment

A `pass` on its own is meaningless for anti-spoofing. An attacker can trivially publish SPF and DKIM
for a domain they control, send from it, and obtain `spf=pass dkim=pass`. What DMARC adds is
**alignment**: the authenticated domain must match the domain the user actually sees in `From`.

```
DMARC pass  =  ( SPF pass   AND  spf.mailfrom domain aligns with header From )
            OR ( DKIM pass  AND  DKIM d= domain     aligns with header From )
```

Alignment modes:

- **Relaxed (default)** — the organizational domains must match. `mail.corp.example.com` aligns with
  `corp.example.com`.
- **Strict** (`aspf=s` / `adkim=s`) — the domains must match exactly.

Always report **which** domain aligned. "DKIM passed" is not a finding; "DKIM passed for
`d=sendgrid.net`, which does not align with the `From` domain `corp.example.com`" is.

## 3. Result combinations and what they actually mean

| SPF | DKIM | Aligned? | Interpretation | Action |
| :--- | :--- | :--- | :--- | :--- |
| pass | pass | yes | Genuinely authenticated sender | If content is malicious, treat as **BEC / compromised account**, not forgery |
| fail | pass | DKIM aligned | **Forwarding or mailing list** — the forwarder re-sent from its own IP | Not spoofing. Do not block on this alone |
| pass | fail | SPF aligned | Content was modified in transit, or a list rewrote the body | Usually benign; check the list |
| pass | pass | neither aligns | Attacker-owned domain with its own valid records | **Spoofing / lookalike** |
| fail | fail | no | Unauthenticated | **Spoofing**, or badly misconfigured legitimate sender |
| fail | none | no | No signature at all | Suspicious; many legitimate small senders also look like this |
| absent | absent | unknown | No receiver verdict in the headers | **Alignment unproven** — say so, do not imply a pass |

### The forwarding trap

This is the single most common false positive in phishing triage. When a message is forwarded:

- SPF is evaluated against the **forwarder's** IP, which is not in the original domain's SPF record,
  so SPF fails legitimately.
- DKIM survives, because the signature covers the content and selected headers, not the path.

So `spf=fail` + aligned `dkim=pass` is the *expected* result for forwarded mail. Mailing lists are
harder: they often modify the subject or append a footer, which breaks DKIM too, producing a
double failure on entirely legitimate mail.

### The authenticated-attacker trap

A clean DMARC pass does **not** mean the message is safe. DMARC does not address:

- lookalike and typosquatted domains (the attacker owns and authenticates them properly),
- display-name spoofing,
- compromised legitimate accounts,
- malicious attachments or links from an authenticated sender,
- any lure that requires no link at all.

## 4. ARC (RFC 8617) — supporting evidence only

ARC preserves the authentication results seen by earlier handlers so a later receiver can take them
into account when forwarding broke SPF. Two cautions:

1. ARC does **not** change the DMARC result automatically. It informs a local policy decision.
2. The specification is **Experimental**, and the chain is only as trustworthy as the intermediaries
   that sealed it. An `arc=pass` from an unknown intermediary is not an endorsement.

Treat ARC as context that can explain a forwarding failure, never as a verdict.

## 5. Microsoft CompAuth

Microsoft 365 adds a composite verdict in `Authentication-Results` and
`X-Forefront-Antispam-Report`:

| `compauth` | Meaning |
| :--- | :--- |
| `pass` | Passed explicit or implicit authentication |
| `fail` | Failed; check the `reason` code |
| `softpass` | Partial implicit authentication signal |
| `none` | Message was not authenticated |

The `reason` code narrows it: `000`/`001` indicate explicit failure, the `1xx` range implicit
failure, `2xx` is spoof intelligence, `3xx` is a tenant allow/block override. A `compauth=fail
reason=001` alongside an aligned-pass claim is contradictory and worth noting in the report.

## 6. Received hop analysis

Hops are prepended, so the **last** `Received` header is the earliest hop. The engine reverses them
into oldest-first order.

What to look for:

- **The first hop with a public IP** is the best candidate for the true origin.
- **Forged hops.** An attacker fully controls any hop below their entry point and can fabricate
  plausible-looking ones. Never block an IP on header evidence alone — corroborate against your own
  gateway logs, which the attacker cannot write to.
- **Timestamps running backwards** between consecutive hops indicate fabrication.
- **Implausible delays.** Multi-hour gaps can mean a queued relay or a staged forgery.
- **A single hop** suggests direct-to-MX injection, or that the user pasted only part of the headers.

## 7. Reporting language

Write the verdict so a non-specialist can act on it:

- Good: "The visible sender shows `corp.example.com`, but the only domain that passed
  authentication was `sendgrid.net`. The two do not align, so the sender address was forged."
- Bad: "DMARC fail." (No one can act on this.)
- Good: "SPF failed because the message was forwarded, but DKIM passed for the original sending
  domain, so the sender is genuine."
- Bad: "SPF failed, likely spoofed." (This is the forwarding trap.)
