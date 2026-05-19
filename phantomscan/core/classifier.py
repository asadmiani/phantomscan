"""
Service Classification Engine
Autonomous Security Platform

This module:
- Classifies target type (Web / API / Mixed)
- Detects technology stack indicators
- Suggests scan strategy profile
"""

import requests
import re


class ServiceClassifier:

    def __init__(self, timeout=5):
        self.timeout = timeout

    # ---------------------------------------
    # Main Classification Method
    # ---------------------------------------

    def classify(self, target):
        """
        Analyze target and determine:
        - service_type
        - detected_technologies
        - recommended_profile
        """

        try:
            response = requests.get(target, timeout=self.timeout)
        except Exception as e:
            return {
                "service_type": "Unknown",
                "technologies": [],
                "profile": "light_scan",
                "error": str(e)
            }

        headers = response.headers
        content = response.text.lower()

        technologies = self._detect_technologies(headers, content)
        service_type = self._detect_service_type(headers, content)
        profile = self._recommend_profile(service_type)

        return {
            "service_type": service_type,
            "technologies": technologies,
            "profile": profile
        }

    # ---------------------------------------
    # Detect Service Type
    # ---------------------------------------

    def _detect_service_type(self, headers, content):

        content_type = headers.get("Content-Type", "").lower()

        if "application/json" in content_type:
            return "API"

        if "text/html" in content_type:
            if "swagger" in content or "openapi" in content:
                return "API"
            return "Web"

        if "xml" in content_type:
            return "API"

        return "Mixed"

    # ---------------------------------------
    # Detect Technologies
    # ---------------------------------------

    def _detect_technologies(self, headers, content):

        tech_stack = []

        server = headers.get("Server", "").lower()
        powered = headers.get("X-Powered-By", "").lower()

        if "apache" in server:
            tech_stack.append("Apache")

        if "nginx" in server:
            tech_stack.append("Nginx")

        if "php" in powered or "php" in content:
            tech_stack.append("PHP")

        if "express" in powered or "node" in powered:
            tech_stack.append("Node.js")

        if "django" in content:
            tech_stack.append("Django")

        if re.search(r"\.aspx", content):
            tech_stack.append("ASP.NET")

        return tech_stack

    # ---------------------------------------
    # Recommend Scan Profile
    # ---------------------------------------

    def _recommend_profile(self, service_type):

        if service_type == "API":
            return "api_deep_scan"

        if service_type == "Web":
            return "web_full_scan"

        return "balanced_scan"
