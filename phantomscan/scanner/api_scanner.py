"""
API Scanner Module
Autonomous Security Platform

- Detects open API endpoints
- Checks for debug exposure
"""

import requests


class APIScanner:

    def __init__(self, timeout=5):
        self.timeout = timeout

    # ------------------------------------------
    # Scan API Endpoint
    # ------------------------------------------

    def scan(self, base_url):

        findings = []

        common_endpoints = [
            "/api",
            "/api/v1",
            "/swagger",
            "/openapi.json",
            "/debug"
        ]

        for endpoint in common_endpoints:
            url = base_url.rstrip("/") + endpoint
            try:
                response = requests.get(url, timeout=self.timeout)

                if response.status_code == 200:
                    findings.append({
                        "type": "Exposed API Endpoint",
                        "url": url,
                        "severity": "Medium"
                    })

            except:
                continue

        return findings
