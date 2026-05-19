# Suspicious Parameter

**Severity:** 0/10
**Risk Level:** LOW

## Target
- URL: `https://www.gartner.com/reviews/market/application-security-testing/vendor/invicti?utm_source=invicti&utm_medium=referral&utm_campaign=widget&utm_content=MzI5Y2MxYjMtYjA1NC00NzlmLTllODUtZTQ1ZDFjZGM5ZWRj`
- Parameter: `utm_source`

## Description
- No direct exploit detected, but parameter is user-controlled and should be monitored.
- Low severity suggests informational or low-impact behavior.

## Proof of Concept (PoC)
```
https://www.gartner.com/reviews/market/application-security-testing/vendor/invicti?utm_source=invicti&utm_medium=referral&utm_campaign=widget&utm_content=MzI5Y2MxYjMtYjA1NC00NzlmLTllODUtZTQ1ZDFjZGM5ZWRj?utm_source=<payload>
```

## Impact
Potential data leakage, account takeover, or client-side attack.

## Remediation
Validate input, sanitize output, and use parameterized queries.

---
Generated on 2026-02-08 02:49:52.889093
