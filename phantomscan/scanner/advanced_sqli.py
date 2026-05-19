import requests
import urllib.parse
import time
import re


class AdvancedSQLiScanner:

    def __init__(self):
        self.timeout = 10

    # -------------------------------------------------
    # Helper: Inject Payload Properly
    # -------------------------------------------------
    def inject(self, url, param, payload):

        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)

        if param not in query:
            return None

        query[param] = [payload]  # FIXED HERE

        new_query = urllib.parse.urlencode(query, doseq=True)
        return parsed._replace(query=new_query).geturl()

    # -------------------------------------------------
    # Error-Based SQLi
    # -------------------------------------------------
    def error_based_test(self, url, param):

        payload = "'"
        injected_url = self.inject(url, param, payload)
        if not injected_url:
            return False, None

        try:
            r = requests.get(injected_url, timeout=self.timeout)

            sql_errors = [
                "SQL syntax",
                "mysql_fetch",
                "ORA-",
                "PostgreSQL",
                "Unclosed quotation mark",
                "Warning: mysql",
                "You have an error in your SQL syntax"
            ]

            for error in sql_errors:
                if error.lower() in r.text.lower():
                    return True, injected_url

        except:
            pass

        return False, None

    # -------------------------------------------------
    # Boolean-Based SQLi
    # -------------------------------------------------
    def boolean_based_test(self, url, param):

        try:
            original = requests.get(url, timeout=self.timeout)

            true_payload = "1 AND 1=1"
            false_payload = "1 AND 1=2"

            true_url = self.inject(url, param, true_payload)
            false_url = self.inject(url, param, false_payload)

            if not true_url or not false_url:
                return False, None

            r_true = requests.get(true_url, timeout=self.timeout)
            r_false = requests.get(false_url, timeout=self.timeout)

            if (
                r_true.status_code == original.status_code and
                r_false.status_code == original.status_code and
                r_true.text != r_false.text
            ):
                return True, true_url

        except:
            pass

        return False, None

    # -------------------------------------------------
    # Time-Based Blind SQLi
    # -------------------------------------------------
    def time_based_test(self, url, param):

        payload = "1 AND SLEEP(5)"
        injected_url = self.inject(url, param, payload)

        if not injected_url:
            return False, None

        try:
            start = time.time()
            requests.get(injected_url, timeout=self.timeout)
            end = time.time()

            if (end - start) > 4:
                return True, injected_url

        except:
            pass

        return False, None

    # -------------------------------------------------
    # Main Scan
    # -------------------------------------------------
    def scan(self, url, params):

        findings = []

        for param in params:

            confidence = 0
            poc = None

            # Error-based
            result, injected = self.error_based_test(url, param)
            if result:
                confidence += 50
                poc = injected

            # Boolean-based
            result, injected = self.boolean_based_test(url, param)
            if result:
                confidence += 30
                poc = injected

            # Time-based
            result, injected = self.time_based_test(url, param)
            if result:
                confidence += 70
                poc = injected

            if confidence > 0:

                severity = "CRITICAL" if confidence >= 70 else "HIGH"

                finding = {
                    "type": "SQL Injection",
                    "url": url,
                    "parameter": param,
                    "payload": poc,
                    "confidence": confidence,
                    "severity": severity,
                    "description": f"SQL Injection detected in parameter '{param}'.",
                    "impact": "Attackers can extract or manipulate database data.",
                    "remediation": "Use prepared statements and parameterized queries."
                }

                findings.append(finding)

        return findings
