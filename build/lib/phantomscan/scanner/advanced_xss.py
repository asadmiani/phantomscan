import requests
import urllib.parse
import re


class AdvancedXSSScanner:

    def __init__(self):
        self.timeout = 8

        # Multiple payload strategies
        self.payloads = [
            "<script>alert(1)</script>",
            "\" onmouseover=alert(1) x=\"",
            "<svg/onload=alert(1)>",
            "'><img src=x onerror=alert(1)>"
        ]

        # Dangerous DOM sinks
        self.dom_sinks = [
            "document.write",
            "innerHTML",
            "eval(",
            "location.hash",
            "document.URL"
        ]

    # -------------------------------------------------
    # Inject Payload
    # -------------------------------------------------
    def inject(self, url, param, payload):

        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)

        if param not in query:
            return url

        query[param] = payload
        new_query = urllib.parse.urlencode(query, doseq=True)

        return parsed._replace(query=new_query).geturl()

    # -------------------------------------------------
    # Reflected XSS Detection
    # -------------------------------------------------
    def reflected_test(self, url, param):

        findings = []

        for payload in self.payloads:

            injected_url = self.inject(url, param, payload)

            try:
                r = requests.get(injected_url, timeout=self.timeout)

                confidence = 0

                # Basic reflection
                if payload in r.text:
                    confidence += 40

                # Inside script tag
                if re.search(r"<script>.*" + re.escape(payload) + ".*</script>", r.text, re.IGNORECASE):
                    confidence += 30

                # Inside attribute context
                if re.search(r"=\s*[\"'].*" + re.escape(payload) + ".*[\"']", r.text, re.IGNORECASE):
                    confidence += 30

                if confidence > 0:

                    severity = "HIGH" if confidence >= 70 else "MEDIUM"

                    finding = {
                        "type": "Cross-Site Scripting (XSS)",
                        "url": url,
                        "parameter": param,
                        "payload": injected_url,
                        "confidence": confidence,
                        "severity": severity,
                        "description": f"Reflected XSS detected on parameter '{param}'.",
                        "impact": "Attacker can execute arbitrary JavaScript in victim's browser.",
                        "remediation": "Sanitize and encode user input before rendering in HTML."
                    }

                    findings.append(finding)

            except:
                pass

        return findings

    # -------------------------------------------------
    # DOM-Based XSS Detection
    # -------------------------------------------------
    def dom_based_test(self, url):

        findings = []

        try:
            r = requests.get(url, timeout=self.timeout)

            for sink in self.dom_sinks:
                if sink in r.text:

                    finding = {
                        "type": "DOM-Based XSS (Potential)",
                        "url": url,
                        "parameter": "N/A",
                        "payload": "DOM Sink Found",
                        "confidence": 40,
                        "severity": "LOW",
                        "description": f"Potential DOM-based XSS due to usage of '{sink}'.",
                        "impact": "Client-side JavaScript injection may be possible.",
                        "remediation": "Avoid unsafe DOM manipulation and validate sources."
                    }

                    findings.append(finding)

        except:
            pass

        return findings

    # -------------------------------------------------
    # Main Scan Function
    # -------------------------------------------------
    def scan(self, url, params):

        all_findings = []

        for param in params:
            reflected_findings = self.reflected_test(url, param)
            all_findings.extend(reflected_findings)

        dom_findings = self.dom_based_test(url)
        all_findings.extend(dom_findings)

        return all_findings
