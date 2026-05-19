import requests
import re
import json
from difflib import SequenceMatcher
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class IDORScanner:

    def __init__(self):

        self.test_values = [
            "1", "2", "5", "10",
            "100", "999", "1337",
            "admin", "test"
        ]

        self.headers = {
            "User-Agent": "PhantomScan-IDOR"
        }

    # --------------------------------
    # Response similarity
    # --------------------------------
    def similarity(self, a, b):
        return SequenceMatcher(None, a, b).ratio()

    # --------------------------------
    # Detect numeric/object params
    # --------------------------------
    def extract_params(self, url):

        parsed = urlparse(url)

        params = parse_qs(parsed.query)

        return parsed, params

    # --------------------------------
    # Build modified URL
    # --------------------------------
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

    # --------------------------------
    # Main scan
    # --------------------------------
    def scan(self, url):

        findings = []

        try:

            parsed, params = self.extract_params(url)

            if not params:
                return findings

            # Original request
            original_response = requests.get(
                url,
                headers=self.headers,
                timeout=10,
                verify=False
            )

            original_text = original_response.text

            # Test each parameter
            for param in params:

                original_value = params[param][0]

                for test in self.test_values:

                    if test == original_value:
                        continue

                    modified_params = params.copy()

                    modified_params[param] = [test]

                    modified_url = self.build_url(
                        parsed,
                        modified_params
                    )

                    try:

                        response = requests.get(
                            modified_url,
                            headers=self.headers,
                            timeout=10,
                            verify=False
                        )

                        similarity_score = self.similarity(
                            original_text,
                            response.text
                        )

                        # Heuristic detection
                        if (
                            response.status_code == 200
                            and len(response.text) > 100
                            and similarity_score < 0.95
                        ):

                            findings.append({

                                "type": "IDOR",

                                "url": modified_url,

                                "parameter": param,

                                "payload": test,

                                "severity": "High",

                                "confidence": "Medium",

                                "description":
                                    "Potential IDOR vulnerability detected by parameter manipulation.",

                                "impact":
                                    "Unauthorized access to sensitive objects or user data may be possible.",

                                "remediation":
                                    "Enforce server-side authorization checks for every object request.",

                                "evidence":
                                    f"Similarity score changed to {similarity_score:.2f}"
                            })

                    except Exception:
                        pass

        except Exception:
            pass

        return findings
