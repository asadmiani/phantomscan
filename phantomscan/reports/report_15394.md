# Suspicious Parameter

**Severity:** 0/10
**Risk Level:** LOW

## Target
- URL: `https://www.youtube.com/embed/IpIf5DTz33s?rel=0`
- Parameter: `rel`

## Description
- No direct exploit detected, but parameter is user-controlled and should be monitored.
- Low severity suggests informational or low-impact behavior.

## Proof of Concept (PoC)
```
https://www.youtube.com/embed/IpIf5DTz33s?rel=0?rel=<payload>
```

## Impact
Potential data leakage, account takeover, or client-side attack.

## Remediation
Validate input, sanitize output, and use parameterized queries.

---
Generated on 2026-02-08 02:50:19.289000
