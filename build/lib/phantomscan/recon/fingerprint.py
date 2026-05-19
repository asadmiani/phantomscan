"""
Technology Fingerprinting Module
Autonomous Security Platform

This module:
- Identifies server technology
- Detects frameworks
- Extracts security headers
- Evaluates basic misconfigurations
"""

import requests
import re


class FingerprintEngine:

    def __init__(self, timeout=5):
        self.timeout = timeout

    # ------------------------------------------
    # Main Fingerprint Function
    # ------------------------------------------

    def analyze(self, target):

        try:
            response = requests.get(target, timeout=self.timeout)
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

        headers = response.headers
        content = response.text.lower()

        server_info = self._detect_server(headers)
        framework_info = self._detect_framework(headers, content)
        security_headers = self._check_security_headers(headers)

        return {
            "success": True,
            "server": server_info,
            "frameworks": framework_info,
            "security_headers": security_headers
        }

    # ------------------------------------------
    # Detect Server
    # ------------------------------------------

    def _detect_server(self, headers):

        server = headers.get("Server", "Unknown")
        powered = headers.get("X-Powered-By", "")

        return {
            "server": server,
            "powered_by": powered
        }

    # ------------------------------------------
    # Detect Framework
    # ------------------------------------------

    def _detect_framework(self, headers, content):

        detected = []

        if "django" in content:
            detected.append("Django")

        if "laravel" in content:
            detected.append("Laravel")

        if "wordpress" in content:
            detected.append("WordPress")

        if "react" in content:
            detected.append("React")

        if "angular" in content:
            detected.append("Angular")

        if re.search(r"\.aspx", content):
            detected.append("ASP.NET")

        if "node" in headers.get("X-Powered-By", "").lower():
            detected.append("Node.js")

        return detected

    # ------------------------------------------
    # Check Security Headers
    # ------------------------------------------

    def _check_security_headers(self, headers):

        required_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "X-Content-Type-Options"
        ]

        missing = []

        for header in required_headers:
            if header not in headers:
                missing.append(header)

        return {
            "missing": missing,
            "score": self._calculate_security_score(len(missing))
        }

    # ------------------------------------------
    # Security Score Calculation
    # ------------------------------------------

    def _calculate_security_score(self, missing_count):

        if missing_count == 0:
            return "Strong"

        if missing_count <= 2:
            return "Moderate"

        return "Weak"
