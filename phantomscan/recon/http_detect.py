"""
HTTP Detection Module
Autonomous Security Platform

This module:
- Detects live HTTP/HTTPS services
- Identifies allowed methods
- Checks redirect behavior
"""

import requests


class HTTPDetector:

    def __init__(self, timeout=5):
        self.timeout = timeout

    # ------------------------------------------
    # Detect HTTP/HTTPS
    # ------------------------------------------

    def detect(self, target):

        results = {
            "http": False,
            "https": False,
            "status_code": None,
            "allowed_methods": [],
            "redirect": False
        }

        # Try HTTPS first
        try:
            response = requests.get(
                target.replace("http://", "https://"),
                timeout=self.timeout,
                allow_redirects=True
            )
            results["https"] = True
            results["status_code"] = response.status_code
            results["redirect"] = len(response.history) > 0
            results["allowed_methods"] = self._detect_methods(target)
            return results
        except:
            pass

        # Try HTTP
        try:
            response = requests.get(
                target.replace("https://", "http://"),
                timeout=self.timeout,
                allow_redirects=True
            )
            results["http"] = True
            results["status_code"] = response.status_code
            results["redirect"] = len(response.history) > 0
            results["allowed_methods"] = self._detect_methods(target)
            return results
        except:
            return {"error": "No HTTP service detected"}

    # ------------------------------------------
    # Detect Allowed Methods
    # ------------------------------------------

    def _detect_methods(self, target):

        try:
            response = requests.options(target, timeout=self.timeout)
            allow = response.headers.get("Allow", "")
            if allow:
                return [m.strip() for m in allow.split(",")]
        except:
            pass

        return []
