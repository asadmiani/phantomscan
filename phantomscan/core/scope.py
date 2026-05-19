"""
PhantomScan Advanced Scope Validator
Author: Asad Ullah
"""

import socket
from urllib.parse import urlparse


class ScopeValidator:

    def __init__(self):

        self.blocked = [
            "127.0.0.1",
            "localhost",
            "0.0.0.0"
        ]

    # =====================================
    # VALIDATE TARGET
    # =====================================

    def validate(self, target):

        try:

            # -----------------------------
            # ADD HTTP
            # -----------------------------

            if not target.startswith("http"):

                target = "http://" + target

            # -----------------------------
            # PARSE URL
            # -----------------------------

            parsed = urlparse(target)

            host = parsed.netloc

            if not host:

                return False

            # -----------------------------
            # BLOCK LOCALHOST
            # -----------------------------

            if host.lower() in self.blocked:

                return False

            # -----------------------------
            # DOMAIN FORMAT CHECK
            # -----------------------------

            if "." not in host:

                return False

            # -----------------------------
            # DNS RESOLUTION
            # -----------------------------

            ip = socket.gethostbyname(host)

            if not ip:

                return False

            return True

        except Exception:

            return False
