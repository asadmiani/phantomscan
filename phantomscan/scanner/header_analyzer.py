"""
Header Analyzer Module
Autonomous Security Platform

- Analyzes HTTP security headers
- Detects missing or weak configurations
- Assigns severity levels
"""

import requests


class HeaderAnalyzer:

    def __init__(self, timeout=5):
        self.timeout = timeout

    # ------------------------------------------
    # Analyze Headers
    # ------------------------------------------

    def analyze(self, url):

        findings = []

        try:
            response = requests.get(url, timeout=self.timeout)
        except:
            return findings

        headers = response.headers

        # --- Content Security Policy ---
        if "Content-Security-Policy" not in headers:
            findings.append({
                "type": "Missing Content-Security-Policy",
                "url": url,
                "severity": "Medium"
            })

        # --- X-Frame-Options ---
        if "X-Frame-Options" not in headers:
            findings.append({
                "type": "Missing X-Frame-Options",
                "url": url,
                "severity": "Medium"
            })

        # --- HSTS ---
        if "Strict-Transport-Security" not in headers:
            findings.append({
                "type": "Missing HSTS",
                "url": url,
                "severity": "Medium"
            })

        # --- X-Content-Type-Options ---
        if "X-Content-Type-Options" not in headers:
            findings.append({
                "type": "Missing X-Content-Type-Options",
                "url": url,
                "severity": "Low"
            })

        # --- Server Disclosure ---
        if "Server" in headers:
            findings.append({
                "type": "Server Version Disclosure",
                "url": url,
                "severity": "Low"
            })

        return findings
