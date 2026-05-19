import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class RCEScanner:

    def __init__(self):

        self.payloads = [

            ";id",

            "&& id",

            "| id",

            "; whoami",

            "&& whoami",

            "| whoami",

            "; uname -a",

            "$(id)",

            "`id`",

            "; ping -c 5 127.0.0.1",

            "&& timeout 5",

            "| sleep 5"
        ]

        self.headers = {
            "User-Agent": "PhantomScan-RCE"
        }

    # ---------------------------------
    # Build modified URL
    # ---------------------------------

    def build_url(self, parsed, params):

        query = urlencode(params, doseq=True)

        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            query,
            parsed.fragment
        ))

    # ---------------------------------
    # Detect command execution
    # ---------------------------------

    def detect_rce(self, response_text):

        indicators = [

            "uid=",
            "gid=",
            "groups=",
            "root:x:",
            "linux",
            "daemon",
            "bin/bash",
            "www-data",
            "nt authority",
            "windows"
        ]

        text = response_text.lower()

        return any(i.lower() in text for i in indicators)

    # ---------------------------------
    # Main scan
    # ---------------------------------

    def scan(self, url):

        findings = []

        try:

            parsed = urlparse(url)

            params = parse_qs(parsed.query)

            if not params:
                return findings

            for param in params:

                for payload in self.payloads:

                    modified_params = params.copy()

                    original = modified_params[param][0]

                    modified_params[param] = [
                        original + payload
                    ]

                    modified_url = self.build_url(
                        parsed,
                        modified_params
                    )

                    try:

                        start = time.time()

                        response = requests.get(
                            modified_url,
                            headers=self.headers,
                            timeout=15,
                            verify=False
                        )

                        elapsed = time.time() - start

                        # ---------------------------------
                        # Response-based RCE
                        # ---------------------------------

                        if self.detect_rce(response.text):

                            findings.append({

                                "type": "Remote Code Execution",

                                "url": modified_url,

                                "parameter": param,

                                "payload": payload,

                                "severity": "Critical",

                                "confidence": "High",

                                "description":
                                    "Potential Remote Code Execution vulnerability detected.",

                                "impact":
                                    "Attackers may execute arbitrary commands on the server.",

                                "remediation":
                                    "Sanitize user input and avoid unsafe command execution.",

                                "evidence":
                                    "Command execution indicators detected in response."
                            })

                        # ---------------------------------
                        # Time-based blind RCE
                        # ---------------------------------

                        if "sleep 5" in payload or "ping -c 5" in payload:

                            if elapsed >= 5:

                                findings.append({

                                    "type": "Blind RCE",

                                    "url": modified_url,

                                    "parameter": param,

                                    "payload": payload,

                                    "severity": "Critical",

                                    "confidence": "Medium",

                                    "description":
                                        "Potential blind command injection vulnerability detected.",

                                    "impact":
                                        "Attackers may execute commands blindly on the server.",

                                    "remediation":
                                        "Avoid executing OS commands using user-controlled input.",

                                    "evidence":
                                        f"Delayed response detected ({elapsed:.2f}s)"
                                })

                    except Exception:
                        pass

        except Exception:
            pass

        return findings
