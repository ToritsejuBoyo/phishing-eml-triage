# Phishing Triage Report: {{SOURCE_FILENAME}}

**Ticket:** `{{TICKET_ID}}` | **Analyst:** `{{ANALYST_NAME}}` | **Generated (UTC):** `{{GENERATED_UTC}}`

> Every indicator in this report is DEFANGED. Do not re-fang or click any of them.

## 1. Triage Verdict

- **Classification:** `{{CLASSIFICATION}}`
- **Confidence:** `{{CONFIDENCE}}`
- **Risk Score:** `{{RISK_SCORE}}`
- **Originating IP:** `{{ORIGINATING_IP}}` (header-derived; corroborate against gateway logs)
- **Decisive Indicator:** {{DECISIVE_INDICATOR}}

**Plain-English summary for non-technical stakeholders:**
{{PLAIN_ENGLISH_SUMMARY}}

## 2. Header & Authentication Alignment

| Field | Observed Value (Defanged) | Verdict |
| :--- | :--- | :--- |
| From | `{{FROM}}` | visible sender |
| Display Name | `{{DISPLAY_NAME}}` | rendered to the user |
| Reply-To | `{{REPLY_TO}}` | {{REPLY_TO_VERDICT}} |
| Return-Path | `{{RETURN_PATH}}` | {{RETURN_PATH_VERDICT}} |
| Subject | `{{SUBJECT}}` | - |
| Date | `{{DATE}}` | - |
| SPF | `{{SPF}}` | {{SPF_ALIGNMENT}} |
| DKIM | `{{DKIM}}` | {{DKIM_ALIGNMENT}} |
| DMARC | `{{DMARC}}` | {{DMARC_VERDICT}} |
| CompAuth | `{{COMPAUTH}}` | - |
| DKIM `d=` | `{{DKIM_DOMAIN}}` | signing domain |
| SPF `mailfrom` | `{{SPF_MAILFROM}}` | envelope domain |

Alignment is evaluated per **RFC 9989** (obsoletes RFC 7489): a DMARC pass requires SPF or DKIM to
authenticate a domain that aligns with the visible `From` domain.

**Authentication interpretation:** {{AUTH_INTERPRETATION}}

## 3. Prioritised Findings

| Severity | Indicator | Evidence |
| :--- | :--- | :--- |
| {{SEVERITY}} | {{INDICATOR}} | {{EVIDENCE}} |

## 4. Received Hop Timeline

| Hop | From Host | Public IP (Defanged) | Timestamp | Delay (s) |
| :--- | :--- | :--- | :--- | :--- |
| {{HOP_INDEX}} | `{{HOP_HOST}}` | `{{HOP_IP}}` | `{{HOP_TIME}}` | {{HOP_DELAY}} |

Hops below the attacker's true entry point are forgeable. Do not block an IP on header evidence
alone.

## 5. Defanged IOC Blocklist

| Type | Indicator (Defanged) |
| :--- | :--- |
| Sender Address | `{{IOC_SENDER}}` |
| Domain | `{{IOC_DOMAIN}}` |
| Originating IP | `{{IOC_IP}}` |
| URL | `{{IOC_URL}}` |
| Attachment SHA-256 | `{{IOC_HASH}}` |

## 6. Attachments

| Filename | Type | Size | SHA-256 | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `{{ATT_NAME}}` | {{ATT_TYPE}} | {{ATT_SIZE}} | `{{ATT_HASH}}` | {{ATT_NOTES}} |

## 7. Not Checked / Limitations

State explicitly what this analysis did not cover, so no one assumes coverage that was not provided:

- [ ] QR payload not decoded (requires sandbox) - {{QR_STATUS}}
- [ ] URLs not visited or detonated (by design) - {{URL_STATUS}}
- [ ] Attachment not executed or sandboxed - {{ATT_STATUS}}
- [ ] `Authentication-Results` absent, alignment unproven - {{AUTH_STATUS}}
- [ ] Headers may have been pasted incompletely - {{HEADER_STATUS}}

## 8. Containment Actions

| # | Action | Target | Status | Owner |
| :--- | :--- | :--- | :--- | :--- |
| 1 | Purge from affected mailboxes | {{PURGE_SCOPE}} | {{STATUS}} | {{OWNER}} |
| 2 | Block sender domain | `{{BLOCK_DOMAIN}}` | {{STATUS}} | {{OWNER}} |
| 3 | Reset credentials / revoke sessions | {{AFFECTED_USERS}} | {{STATUS}} | {{OWNER}} |
| 4 | Isolate hosts where commands ran | {{AFFECTED_HOSTS}} | {{STATUS}} | {{OWNER}} |

## 9. Hunt Queries

```kusto
EmailEvents
| where Timestamp > ago(14d)
| where SenderFromDomain == "{{SENDER_DOMAIN}}"
| project Timestamp, RecipientEmailAddress, Subject, DeliveryAction, NetworkMessageId
| order by Timestamp desc
```

```powershell
New-ComplianceSearch -Name "{{SEARCH_NAME}}" -ExchangeLocation All `
  -ContentMatchQuery '(From:"{{SENDER_DOMAIN}}")'
Start-ComplianceSearch -Identity "{{SEARCH_NAME}}"
# Review results before purging:
# New-ComplianceSearchAction -SearchName "{{SEARCH_NAME}}" -Purge -PurgeType SoftDelete
```

## 10. Reporter Reply

{{REPORTER_REPLY}}
