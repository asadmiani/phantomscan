"""
Scope Validation Engine
Autonomous Security Platform

This module:
- Validates user input target
- Normalizes domain format
- Blocks unsafe/private IP scanning
- Ensures ethical scope compliance
"""

import re
import socket
from urllib.parse import urlparse


class ScopeValidator:

    def __init__(self, allowed_domains=None):
        """
        allowed_domains:
            Optional list of allowed domains.
            If provided, scanning is restricted to these.
        """
        self.allowed_domains = allowed_domains or []

    # ------------------------------------------
    # Normalize Target
    # ------------------------------------------

    def normalize(self, target):

        if not target.startswith("http"):
            target = "http://" + target

        return target.rstrip("/")

    # ------------------------------------------
    # Validate Scope
    # ------------------------------------------

    def validate(self, target):

        normalized = self.normalize(target)
        parsed = urlparse(normalized)
        domain = parsed.hostname

        if not domain:
            return self._reject("Invalid target format")

        # Resolve IP
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            return self._reject("Unable to resolve domain")

        # Block local/private networks
        if self._is_private_ip(ip):
            return self._reject("Target resolves to private/local IP")

        # Restrict to allowed domains if configured
        if self.allowed_domains:
            if not any(domain.endswith(d) for d in self.allowed_domains):
                return self._reject("Target outside allowed scope")

        return {
            "in_scope": True,
            "normalized_target": normalized,
            "resolved_ip": ip
        }

    # ------------------------------------------
    # Private IP Detection
    # ------------------------------------------

    def _is_private_ip(self, ip):

        private_patterns = [
            r"^10\.",
            r"^192\.168\.",
            r"^172\.(1[6-9]|2\d|3[0-1])\.",
            r"^127\.",
        ]

        for pattern in private_patterns:
            if re.match(pattern, ip):
                return True

        return False

    # ------------------------------------------
    # Reject Helper
    # ------------------------------------------

    def _reject(self, reason):
        return {
            "in_scope": False,
            "reason": reason
        }
