# XSS

**Severity:** 2/10
**Risk Level:** LOW

## Target
- URL: `http://testphp.vulnweb.com:80/hpp/?pp=12`
- Parameter: `pp`

## Description
- Cross-Site Scripting detected on `pp`. Input is reflected or stored without proper sanitization.
- Low severity suggests informational or low-impact behavior.

## Proof of Concept (PoC)
```
http://testphp.vulnweb.com:80/hpp/?pp=12?pp=<payload>
```

## Impact
Potential data leakage, account takeover, or client-side attack.

## Remediation
Validate input, sanitize output, and use parameterized queries.

---
Generated on 2026-02-08 08:38:01.085095
