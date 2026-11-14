# Phishing Header, EML & IOC Triage Analyst (`phishing-eml-triage`)

[![tests](https://github.com/ToritsejuBoyo/phishing-eml-triage/actions/workflows/tests.yml/badge.svg)](https://github.com/ToritsejuBoyo/phishing-eml-triage/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)]()
[![Dependencies](https://img.shields.io/badge/dependencies-zero%20(stdlib%20only)-brightgreen.svg)](CONTRIBUTING.md)
[![Security](https://img.shields.io/badge/security-read--only%20%7C%20no%20egress-informational.svg)](SECURITY.md)
[![Standard](https://img.shields.io/badge/standard-agentskills.io-blueviolet.svg)](https://agentskills.io)

> Offline phishing triage for `.eml` files and pasted email headers. Evaluates SPF/DKIM/DMARC
> **alignment** (not just pass/fail), detects Reply-To and Return-Path divergence, punycode and
> homoglyph lookalikes, and scores modern lures that carry **no link and no attachment** — then
> emits a defanged IOC blocklist and ready-to-run containment queries.

---

## Who this is for

SOC Tier 1/Tier 2 analysts, incident responders, security officers and IT help desk technicians
handling employee-reported phishing: "Report Phish" submissions and forward-as-attachment tickets.

## Why it exists

Manual header triage is slow and error-prone in two specific directions, and this skill is built
around both:

1. **It calls legitimate mail malicious.** `spf=fail` is the *normal* result for a forwarded
   message, because the forwarder re-sends from its own IP. Treating that as spoofing generates
   false positives and erodes trust in the reporting process.
2. **It calls malicious mail clean.** The dominant 2026 technique, ClickFix, ships **no attachment
   and often no link** — the victim is talked into pasting a command into the Run dialog. Any triage
   that only extracts URLs and hashes scores these messages as harmless.

## What it does

| Capability | Detail |
| :--- | :--- |
| Authentication | Parses `Authentication-Results` (RFC 8601), evaluates DMARC **alignment** per **RFC 9989** (obsoletes RFC 7489), reports which domain actually aligned |
| Identity divergence | `From` vs `Reply-To` vs `Return-Path` vs `Sender`, free-webmail reply redirects, display-name impersonation |
| Lookalike domains | Punycode (`xn--`), mixed-script homoglyphs, confusable substitution (`rnicrosoft` → `microsoft`), bounded edit-distance typosquats, brand-embedded domains |
| Modern lures | ClickFix / CrashFix / FileFix command-paste, Microsoft device-code phishing, quishing solicitation, AiTM credential harvest, BEC payment fraud |
| Attachments | SHA-256, dangerous extensions, double extensions, bidi-override filename spoofing, HTML smuggling markers |
| URLs | Raw-IP hosts, userinfo obfuscation, open redirects, prefilled `?email=`, abusable hosting and shorteners, displayed-vs-actual link mismatch |
| Hop analysis | Oldest-first Received timeline with inter-hop delays and backwards-timestamp forgery detection |
| Output | Markdown report, JSON, or IOC CSV — every indicator defanged |

## Install

```bash
git clone https://github.com/ToritsejuBoyo/phishing-eml-triage.git
cd phishing-eml-triage
python tests/validate-skill.py     # verify: 31 checks against known-answer fixtures
```

No dependencies. Python 3.9+ and the standard library only.

### As an Agent Skill

- **Claude Code / Claude Desktop:** place or symlink into your skills directory
- **Google Antigravity:** `~/.gemini/skills/phishing-eml-triage/`
- **Cursor / Windsurf / VS Code:** `.cursor/skills/phishing-eml-triage/` or the workspace root
- **Web UI or Ollama:** paste `SKILL.md` as system instructions and upload the engine's JSON output

## Usage

```bash
# Markdown triage report (default)
python scripts/parse_eml_ioc.py -i ./reported-message.eml

# Structured JSON for automation or SIEM ingestion
python scripts/parse_eml_ioc.py -i ./reported-message.eml -f json

# IOC blocklist only, ready for a block-rule import
python scripts/parse_eml_ioc.py -i ./reported-message.eml -f ioc-csv

# Mask recipient identities before sharing outside the responding team
python scripts/parse_eml_ioc.py -i ./reported-message.eml --sanitize -o ./report.md

# Read pasted headers from stdin
cat headers.txt | python scripts/parse_eml_ioc.py -i -
```

## Example

Input is the bundled ClickFix fixture — no URL, no attachment, so a conventional extractor finds
nothing to flag:

```text
From: "Microsoft Account Team" <no-reply@rnicrosoft-verify.com>
Subject: Action required: verify you are human to restore mailbox access

To verify you are human, complete these steps:
  1. Press Windows + R
  2. Press Ctrl + V to paste the verification code
  3. Press Enter
```

Output:

```text
- Classification: `Malware Delivery / Command Execution Lure`
- Confidence:     `High`
- Risk Score:     `69`

| SPF  | fail | domain aligns but result is fail |
| DKIM | none | domain does NOT align           |
| DMARC| fail | FAIL / unproven                 |

| HIGH | DMARC alignment failure                  | ...no authenticated domain aligns with From |
| HIGH | Display-name impersonation               | claims 'Microsoft Account Team', domain is rnicrosoft-verify.com |
| HIGH | ClickFix: Instructs use of Run dialog    | ... |
| HIGH | ClickFix: Encoded PowerShell in body     | ... |
| HIGH | ClickFix: Fake human-verification prompt | ... |
```

## Safety posture

- **Read-only and offline.** Never fetches a URL, resolves a domain, queries DNS or WHOIS, submits a
  hash, or opens an attachment. Every verdict comes from bytes on disk.
- **All indicators defanged.** `hxxps://`, `evil[.]com`, `203[.]0[.]113[.]5` — nothing clickable
  reaches a ticket.
- **Credentials redacted, indicators preserved.** Reply chains often contain real passwords and
  tokens; those are stripped by the shared sanitizer. Attacker indicators are kept, because they are
  the deliverable. See [SECURITY.md](SECURITY.md).
- **Proposes, never applies.** Purge and block commands are emitted for a human to review.

## Limits

- **Outlook `.msg` is out of scope.** It is an OLE2 compound file and cannot be parsed with the
  standard library alone, so supporting it would break the zero-dependency guarantee. Re-save as
  `.eml` or forward as an attachment.
- **QR payloads are flagged, not decoded.** Decoding requires image processing in a sandbox. The
  report says so explicitly rather than implying the destination was checked.
- **`Received` hops are forgeable** below the attacker's entry point. Corroborate the originating IP
  against your own gateway logs before blocking.
- **A clean DMARC pass is not safety.** It does not address lookalike domains, display-name
  spoofing, compromised accounts, or authenticated phishing.
- **Verdicts are heuristic, not authoritative.** This is a triage accelerator for a human analyst,
  not an adjudicator.

## Test coverage

| Suite | Checks | Covers |
| :--- | :--- | :--- |
| `tests/validate-skill.py` | 31 | Known-answer verdicts for 3 fixtures, defanging rules, credential redaction, workspace rules |
| `tests/sanitizer_conformance_test.py` | 17 | Library-wide credential/PII redaction contract |
| `tests/extreme_stress_matrix.py` | 16 | ~47 hostile payloads: malformed MIME, encodings, ReDoS, injection, scale, determinism |

Status is published by CI on every push across Python 3.9–3.13 on Linux, macOS and Windows — see the
`tests` badge above rather than a count recorded here by hand.

## Repository structure

```text
phishing-eml-triage/
├── SKILL.md                                  # Agent-facing contract
├── scripts/
│   ├── parse_eml_ioc.py                      # Triage engine (run this first)
│   └── sanitizer.py                          # Shared credential/PII redaction floor
├── references/
│   ├── email-auth-alignment.md               # SPF/DKIM/DMARC alignment, RFC 9989
│   ├── phishing-ioc-matrix.md                # Lure taxonomy, extensions, ATT&CK mapping
│   └── response-templates.md                 # Reporter, escalation, all-staff comms
├── assets/
│   └── phishing-triage-report-template.md    # Report structure
└── tests/
    ├── validate-skill.py
    ├── sanitizer_conformance_test.py
    ├── extreme_stress_matrix.py
    └── fixtures/                             # Synthetic .eml samples (no real data)
```

All fixtures are synthetic. No real reported message, recipient or customer data is included.

## License

MIT. See [LICENSE](LICENSE).
