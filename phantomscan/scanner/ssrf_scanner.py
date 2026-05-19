import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class SSRFScanner:

    def __init__(self):

        self.payloads = [

            "http://127.0.0.1",

            "http://localhost",

            "http://169.254.169.254",

            "http://0.0.0.0",

            "http://metadata.google.internal",

            "http://[::1]"
        ]

        self.headers = {
            "User-Agent": "PhantomScan-SSRF"
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
    # Scan
    # ---------------------------------

    def scan(self, url):

        findings = []

        try:

            parsed = urlparse(url)

            params = parse_qs(parsed.query)

            if not params:
                return findings

            for param in params:

                original_value = params[param][0]

                # SSRF-like parameters
                if not any(
                    keyword in param.lower()
                    for keyword in [
                        "url",
                        "uri",
                        "link",
                        "api",
                        "redirect",
                        "callback",
                        "image",
                        "file",
                        "path"
                    ]
                ):
                    continue

                for payload in self.payloads:

                    modified_params = params.copy()

                    modified_params[param] = [payload]

                    modified_url = self.build_url(
                        parsed,
                        modified_params
                    )

                    try:

                        response = requests.get(
                            modified_url,
                            headers=self.headers,
                            timeout=10,
                            verify=False,
                            allow_redirects=True
                        )

                        body = response.text.lower()

                        indicators = [

                            "localhost",
                            "127.0.0.1",
                            "meta-data",
                            "ami-id",
                            "internal server error"
                        ]

                        if (
                            response.status_code in [200, 500]
                            and any(
                                i in body
                                for i in indicators
                            )
                        ):

                            findings.append({

                                "type": "SSRF",

                                "url": modified_url,

                                "parameter": param,

                                "payload": payload,

                                "severity": "Critical",

                                "confidence": "Medium",

                                "description":
                                    "Potential Server-Side Request Forgery detected.",

                                "impact":
                                    "Attackers may access internal systems or cloud metadata services.",

                                "remediation":
                                    "Restrict outbound requests and validate user-supplied URLs.",

                                "evidence":
                                    f"Indicator detected using payload: {payload}"
                            })

                    except Exception:
                        pass

        except Exception:
            pass

        return findings
