# Phishing IOC, Lure & TTP Matrix

Detection reference for the payload and social-engineering layer, after authentication has been
assessed. Consult when classifying a message and when explaining the decisive indicator.

## 1. Lure taxonomy (current)

### ClickFix / CrashFix / FileFix — command-paste lures

**The most important gap in conventional triage.** The victim is talked into executing the payload
themselves, so the message frequently contains **no attachment and no link**. A parser that only
extracts URLs and hashes scores these messages clean.

Pattern: a fake human-verification, CAPTCHA, crash-report or "fix it yourself" prompt, followed by
step-by-step instructions to open a shell and paste a command.

| Indicator | Why it matters |
| :--- | :--- |
| `Win+R` / "press the Windows key" | Opens the Run dialog — no browser sandbox applies |
| `Ctrl+V` / "paste the verification code" | The "code" is a command already on the clipboard |
| "verify you are human", "I am not a robot" | Fake CAPTCHA framing to justify the steps |
| `powershell -enc`, `-nop`, `-w hidden`, `iex` | Encoded or hidden execution |
| `mshta`, `certutil -urlcache`, `bitsadmin` | Living-off-the-land download cradles |
| Crash/error dialog imagery plus copy instructions | CrashFix variant |

Reported to have become the dominant initial-access technique during 2026, with variants emerging
through the year. Treat any command-paste instruction as `Malware Delivery / Command Execution Lure`
regardless of how clean the headers are.

**Response note:** if the user already ran the command, this is a host compromise, not an email
incident. Isolate the endpoint; purging the mail is insufficient.

### Quishing — QR code lures

The destination lives inside an image, so text-based link scanning sees nothing. The engine flags
the solicitation text and image-only bodies, but **cannot read the QR payload offline** — say that
explicitly rather than implying the destination was checked. Decode in a sandbox before any verdict
about where it led.

### Device-code phishing

Abuses the OAuth device authorization flow: the victim is asked to visit a genuine Microsoft URL
(`microsoft.com/devicelogin`, `aka.ms/devicelogin`) and enter a short code, which authorizes the
attacker's device against the victim's account. Reported to have grown sharply through 2026.

Dangerous because the sign-in page is **legitimate** — no lookalike domain, nothing for a URL
reputation check to flag. Detect it from the instruction pattern, not the link.

### AiTM / MFA bypass

Reverse-proxy kits (Tycoon2FA, Sneaky2FA, Evilginx class) relay the real sign-in page in real time
and capture the session cookie after MFA completes. These defeat every MFA factor except **FIDO2
security keys and passkeys**, which are origin-bound.

Implication for the report: "the user completed MFA" is not reassurance. If credentials were entered
on an AiTM page, revoke sessions and refresh tokens, do not just reset the password.

### Credential harvest

Account-expiry, mailbox-quota, suspension-threat, unusual-sign-in and MFA-re-enrolment pretexts
driving the user to a fake sign-in page. Watch for URLs with a pre-filled `?email=` parameter — the
page personalises itself, which raises credibility and confirms targeting.

### BEC / payment fraud

Usually text-only, often from a genuinely authenticated account. Signals: beneficiary or payroll
change requests, invoice pressure, secrecy requests, unavailability pretexts ("I'm in a meeting"),
gift-card requests, and `Reply-To` pointing at free webmail.

## 2. Attachment indicators

### Directly dangerous extensions

Executable and scripting: `.exe .scr .com .pif .bat .cmd .js .jse .vbs .vbe .wsf .wsh .hta .msi
.msp .cpl .jar .ps1 .psm1 .reg .scf .chm`

Containers that bypass mark-of-the-web: `.iso .img .vhd .vhdx .udf .cab`

Office macro and add-in: `.docm .xlsm .pptm .dotm .xlam .xll .wll`

Other notable: `.lnk` (shortcut cradles), `.one`/`.onepkg` (OneNote embedded payloads), `.svg`
(scriptable vector — increasingly used to smuggle HTML), `.url`, `.settingcontent-ms`,
`.library-ms`, `.appx`/`.msix`, `.mhtml`/`.mht`, `.diagcab`

### Double extensions

`invoice.pdf.exe`, `statement.xlsx.lnk`, `scan.jpg.hta`. Flagged when a decoy document extension is
followed by a dangerous one — Windows hides the known extension by default, so the user sees only
the decoy.

### Bidi-override filename spoofing

A right-to-left override character (`U+202E`) inside a filename visually reverses the extension:
`report‮gpj.exe` renders as `reportexe.jpg`. Always inspect the raw bytes of the filename.

### HTML smuggling

An `.html`, `.htm`, `.svg` or `.mhtml` attachment carrying `<script>`, a `base64,` blob, `atob(`,
`unescape(` or `document.write`. The payload is assembled in the browser from local content, so no
file is downloaded and network inspection sees nothing.

## 3. URL indicators

| Indicator | Significance |
| :--- | :--- |
| Raw IP as host | Legitimate business mail effectively never does this |
| `xn--` punycode host | Homograph impersonation |
| Userinfo obfuscation (`https://trusted.com@evil.com`) | Browser navigates to `evil.com` |
| Open-redirect parameter (`?redirect=https%3A`) | Borrows a trusted domain's reputation |
| `?email=victim@corp.com` prefilled | Credential harvest, confirms targeting |
| URL shorteners | Hides the destination from inspection |
| `.zip` / `.mov` TLDs | Visually ambiguous with filenames |
| Very long URLs (>220 chars) | Often encode tracking or session state |

### Abusable hosting commonly seen

IPFS gateways (`ipfs.io`, `dweb.link`), Cloudflare R2 (`r2.dev`), Workers/Pages (`workers.dev`,
`pages.dev`), Firebase (`web.app`, `firebaseapp.com`), Azure Blob (`blob.core.windows.net`), AWS S3,
`googleusercontent.com`, Netlify, Vercel, Glitch, Replit, tunnels (`ngrok-free.app`,
`trycloudflare.com`), dynamic DNS (`duckdns.org`), and site builders (Weebly, Wix).

These carry **valid TLS and good domain reputation**, which is exactly why they are used. A green
padlock is not evidence of legitimacy — say so in the user reply.

## 4. Lookalike domain techniques

| Technique | Example |
| :--- | :--- |
| Homoglyph substitution | `rnicrosoft.com` (`rn` reads as `m`), `vvells.com` |
| Cyrillic/mixed script | `раypal.com` with a Cyrillic `а` |
| Punycode IDN | `xn--pypal-4ve.com` |
| Typosquat | `micorsoft.com`, `outlok.com` |
| Brand embedded in unrelated domain | `microsoft-verify-login.xyz` |
| Combosquat | `office365-secure-portal.com` |
| TLD swap | `paypal.co`, `microsoft.cc` |
| Subdomain deception | `microsoft.com.attacker.net` |

## 5. MITRE ATT&CK mapping

| Technique | ID |
| :--- | :--- |
| Phishing: Spearphishing Attachment | T1566.001 |
| Phishing: Spearphishing Link | T1566.002 |
| Phishing: Spearphishing via Service | T1566.003 |
| Phishing: Spearphishing Voice | T1566.004 |
| User Execution: Malicious Link | T1204.001 |
| User Execution: Malicious File | T1204.002 |
| Steal Web Session Cookie (AiTM) | T1539 |
| Multi-Factor Authentication Request Generation | T1621 |
| Forge Web Credentials: Web Cookies | T1606.001 |
| Masquerading: Double File Extension | T1036.007 |
| Masquerading: Right-to-Left Override | T1036.002 |
| Obfuscated Files or Information: HTML Smuggling | T1027.006 |
| Impersonation | T1656 |

## 6. Severity guidance

| Severity | Use for |
| :--- | :--- |
| **HIGH** | Alignment failure, homoglyph/punycode, display-name impersonation, ClickFix, device-code, quishing, double extension, bidi filename, HTML smuggling, link/destination mismatch |
| **MEDIUM** | Return-Path divergence, credential-harvest or BEC lure text, abusable hosting, dangerous single extension, missing `Authentication-Results`, authenticated-but-suspicious sender |
| **LOW** | Sender header divergence, single Received hop |
| **INFO** | Forwarding signature, absence of links/attachments (explicitly not a safety signal) |
