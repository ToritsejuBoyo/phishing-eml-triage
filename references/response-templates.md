# Phishing Response Communication Templates

Copy-paste templates for closing the loop with the reporter, escalating internally, and notifying
staff. Fill the `{{PLACEHOLDERS}}`. Keep indicators defanged in every message that leaves the team.

## 1. Reporter reply - confirmed malicious

```text
Subject: Re: Your reported message - confirmed malicious, no further action needed

Thank you for reporting this message. You did exactly the right thing.

We have confirmed it is malicious ({{CLASSIFICATION}}). We are removing it from
affected mailboxes and blocking the sender.

Please do not reply to it, open any attachment, or follow any instruction it
contains - including any step asking you to copy and paste a command or scan a
QR code.

If you have already entered your password, approved a sign-in prompt, or run any
command it asked for, contact the service desk immediately on {{SERVICE_DESK}}.
That is not a problem you will be blamed for, but we do need to know quickly so
we can protect your account and device.

Thanks again for reporting it.
{{ANALYST_NAME}}, {{TEAM_NAME}}
```

## 2. Reporter reply - legitimate message (false positive)

```text
Subject: Re: Your reported message - this one is genuine

Thank you for reporting this message.

We reviewed the message headers and content and found no evidence of spoofing or
anything malicious. It appears to be genuine{{LEGIT_CONTEXT}}.

Please keep reporting anything that looks unusual. A false alarm costs us a few
minutes; an unreported attack can cost far more. You will never be criticised
for reporting something that turns out to be fine.

{{ANALYST_NAME}}, {{TEAM_NAME}}
```

## 3. Reporter reply - credentials may have been entered

```text
Subject: URGENT - action required on your account

Thank you for reporting this. The message was malicious, and based on what you
have told us there is a chance your credentials were captured.

We have taken these steps already:
  - Reset your password
  - Revoked your active sessions and refresh tokens
  - Required re-registration of your MFA methods

What we need from you now:
  1. Sign in again using {{SIGN_IN_METHOD}} and set a new password.
  2. Tell us whether you approved any MFA prompt you did not initiate.
  3. Tell us whether you ran any command, opened any attachment, or scanned any
     QR code from the message.

Note that completing MFA does not mean you are safe in this case: the attack
technique used here can relay a genuine MFA prompt. That is why we revoked the
sessions rather than only changing the password.

{{ANALYST_NAME}}, {{TEAM_NAME}} - {{SERVICE_DESK}}
```

## 4. Internal escalation note (L2/L3 or IR lead)

```text
PHISHING ESCALATION - {{TICKET_ID}}

Classification : {{CLASSIFICATION}}
Confidence     : {{CONFIDENCE}}
Risk score     : {{RISK_SCORE}}
Reported by    : {{REPORTER}} at {{REPORT_TIME}}

AUTHENTICATION
  SPF        : {{SPF}} (aligned: {{SPF_ALIGNED}})
  DKIM       : {{DKIM}} (aligned: {{DKIM_ALIGNED}}, d={{DKIM_DOMAIN}})
  DMARC      : {{DMARC}} -> aligned pass: {{DMARC_ALIGNED_PASS}}
  Interpretation: {{AUTH_INTERPRETATION}}

DECISIVE INDICATORS
{{TOP_FINDINGS}}

IOCs (DEFANGED - do not re-fang)
  Senders    : {{SENDERS}}
  Domains    : {{DOMAINS}}
  Origin IP  : {{ORIGIN_IP}}  (header-derived; corroborate against gateway logs)
  URLs       : {{URLS}}
  Hashes     : {{HASHES}}

BLAST RADIUS
  Recipients identified : {{RECIPIENT_COUNT}}
  Clicked / submitted   : {{CLICK_COUNT}}
  Commands executed     : {{EXECUTION_COUNT}}

ACTIONS TAKEN
{{ACTIONS_TAKEN}}

ACTIONS REQUESTED
{{ACTIONS_REQUESTED}}
```

## 5. All-staff notice (confirmed campaign only)

Send only for a campaign with meaningful reach. Over-notifying trains staff to ignore notices.

```text
Subject: Security notice - phishing campaign currently targeting {{ORG_NAME}}

We are seeing a phishing campaign sent to staff today.

What it looks like:
  - Subject lines similar to: "{{SUBJECT_EXAMPLE}}"
  - Appears to come from: {{IMPERSONATED_PARTY}}
  - Asks you to: {{REQUESTED_ACTION}}

What to do:
  - Do not interact with it. Report it using {{REPORT_METHOD}} and delete it.
  - If you already did what it asked, contact {{SERVICE_DESK}} now.

What to remember:
  - A padlock or a legitimate-looking domain in the address bar does not mean a
    page is genuine. Attackers host pages on reputable cloud services.
  - We will never ask you to paste a command into a terminal or Run box to fix a
    problem, or to scan a QR code to keep your account active.
  - Reporting early is always the right call, even if you are not sure.

{{TEAM_NAME}}
```

## 6. Writing guidance

- **Never blame the reporter.** A user who feels blamed stops reporting, and reporting is the
  detection control with the best coverage per pound spent.
- **State the action, not the mechanism.** "Reset your password and tell us if you approved a
  prompt" beats an explanation of OAuth token replay.
- **Keep indicators defanged** in anything that leaves the responding team.
- **Say what you did not check.** If a QR payload was not decoded, or `Authentication-Results` was
  missing, say so rather than implying full coverage.
