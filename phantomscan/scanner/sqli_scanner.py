"""
SQL Injection Scanner
Autonomous Security Platform

- Performs basic error-based SQLi detection
- Uses extracted GET parameters
- Returns structured findings
"""

import requests


class SQLiScanner:

    def __init__(self, timeout=5):
        self.timeout = timeout

        self.payloads = [
            "' OR '1'='1",
            "' OR 1=1 --",
            "\" OR \"1\"=\"1",
            "'; DROP TABLE users; --"
        ]

        self.error_signatures = [
            "sql syntax",
            "mysql",
            "syntax error",
            "unclosed quotation",
            "postgresql",
            "odbc",
            "sqlite"
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

                    if self._detect_error(response.text):
                        findings.append({
                            "type": "SQL Injection",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "severity": "Critical"
                        })
                        break

                except:
                    continue

        return findings

    # ------------------------------------------
    # Detect SQL Error
    # ------------------------------------------

    def _detect_error(self, response_text):

        text = response_text.lower()

        for signature in self.error_signatures:
            if signature in text:
                return True

        return False
