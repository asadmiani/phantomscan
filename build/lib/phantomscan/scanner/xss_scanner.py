"""
XSS Scanner
Autonomous Security Platform

- Performs reflected XSS detection
- Uses extracted parameters
- Returns structured findings
"""

import requests


class XSSScanner:

    def __init__(self, timeout=5):
        self.timeout = timeout

        self.payloads = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "'><img src=x onerror=alert(1)>"
        ]

    # ------------------------------------------
    # Scan URL
    # ------------------------------------------

    def scan(self, url, parameters):

        findings = []

        for param in parameters.get("get_params", []):

            for payload in self.payloads:

                try:
                    response = requests.get(
                        url,
                        params={param: payload},
                        timeout=self.timeout
                    )

                    if payload in response.text and "<script>" in payload:
                        findings.append({
                            "type": "Reflected XSS",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "severity": "High"
                        })
                        break

                except:
                    continue

        return findings
