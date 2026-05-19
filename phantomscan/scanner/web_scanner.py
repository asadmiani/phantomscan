"""
Web Scanner Module
Autonomous Security Platform

- Detects basic XSS
- Detects basic SQLi
"""

import requests


class WebScanner:

    def __init__(self, timeout=5):
        self.timeout = timeout

    # ------------------------------------------
    # Scan URL
    # ------------------------------------------

    def scan(self, url):

        findings = []

        # XSS Test
        xss_payload = "<script>alert(1)</script>"
        try:
            response = requests.get(url, params={"q": xss_payload}, timeout=self.timeout)
            if xss_payload in response.text:
                findings.append({
                    "type": "XSS",
                    "url": url,
                    "severity": "High"
                })
        except:
            pass

        # SQLi Test
        sqli_payload = "' OR '1'='1"
        try:
            response = requests.get(url, params={"id": sqli_payload}, timeout=self.timeout)
            if "sql" in response.text.lower():
                findings.append({
                    "type": "SQL Injection",
                    "url": url,
                    "severity": "Critical"
                })
        except:
            pass

        return findings
