# Changelog

All notable changes to `phishing-eml-triage` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-11-13

First release. Day 4 (OP-06) of the it-ops-skills roadmap.

### Added
- Offline `.eml` / RFC 5322 triage engine (`scripts/parse_eml_ioc.py`): Received hop
  timeline, `Authentication-Results` parsing, DMARC alignment evaluation, Reply-To and
  Return-Path divergence, punycode and homoglyph lookalike detection, display-name
  impersonation, URL and attachment analysis, SHA-256 hashing, defanged IOC output.
  Formats: markdown, json, ioc-csv.
- Detection for lures that carry no link and no attachment: ClickFix / CrashFix /
  FileFix command-paste, Microsoft device-code phishing, and quishing solicitation.
- Authentication reference written against **RFC 9989** (which obsoletes RFC 7489),
  including the forwarding false-positive and the authenticated-attacker case.
- Response templates for the reporter, internal escalation, and all-staff notice.
- Three synthetic fixtures with known-correct verdicts (BEC, ClickFix, forwarded-legit).
- Test suites: 31 validation, 17 sanitization conformance, 16 extreme stress matrix.
- Shared `scripts/sanitizer.py`, CI workflow, SECURITY/CONTRIBUTING policy.

### Security
- Strictly read-only and offline: never fetches a URL, resolves a domain, queries DNS,
  or executes an attachment.
- All indicators defanged on output. Credential redaction always on; attacker
  indicators deliberately preserved as the deliverable.

### Known limitations
- Outlook `.msg` (OLE2) is out of scope and documented as such, because it cannot be
  parsed with the Python standard library alone.
- QR payloads are flagged but not decoded; decoding requires a sandbox.

[Unreleased]: https://github.com/ToritsejuBoyo/phishing-eml-triage/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/ToritsejuBoyo/phishing-eml-triage/releases/tag/v1.0.0
