# SQL Injection

**Severity:** 4/10
**Risk Level:** MEDIUM

## Target
- URL: `http://testphp.vulnweb.com:80/listproducts.php?cat=2`
- Parameter: `cat`

## Description
- SQL Injection detected on parameter `cat`. The parameter influences backend database queries and responded abnormally to SQL payloads.
- Cross-Site Scripting detected on `cat`. Input is reflected or stored without proper sanitization.
- Medium severity may allow limited data exposure or client-side attacks.

## Proof of Concept (PoC)
```
http://testphp.vulnweb.com:80/listproducts.php?cat=2?cat=<payload>
```

## Impact
Potential data leakage, account takeover, or client-side attack.

## Remediation
Validate input, sanitize output, and use parameterized queries.

---
Generated on 2026-02-08 08:30:53.481881
