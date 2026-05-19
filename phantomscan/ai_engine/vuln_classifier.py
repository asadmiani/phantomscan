class VulnerabilityClassifier:

    def classify(self, finding_type):

        classification = {
            "category": "Other",
            "owasp": "N/A",
            "cwe": "N/A"
        }

        # -----------------------------------------
        # SQL Injection
        # -----------------------------------------
        if "SQL Injection" in finding_type:

            classification = {
                "category": "Injection",
                "owasp": "A03:2021 - Injection",
                "cwe": "CWE-89 - SQL Injection"
            }

        # -----------------------------------------
        # Cross-Site Scripting
        # -----------------------------------------
        elif "XSS" in finding_type:

            classification = {
                "category": "Injection",
                "owasp": "A03:2021 - Injection",
                "cwe": "CWE-79 - Cross-Site Scripting"
            }

        # -----------------------------------------
        # Security Headers Missing
        # -----------------------------------------
        elif "Header" in finding_type or "Security Header" in finding_type:

            classification = {
                "category": "Security Misconfiguration",
                "owasp": "A05:2021 - Security Misconfiguration",
                "cwe": "CWE-16 - Configuration"
            }

        # -----------------------------------------
        # Authentication Issues
        # -----------------------------------------
        elif "Authentication" in finding_type:

            classification = {
                "category": "Identification & Authentication Failures",
                "owasp": "A07:2021 - Identification and Authentication Failures",
                "cwe": "CWE-287 - Improper Authentication"
            }

        # -----------------------------------------
        # API Issues
        # -----------------------------------------
        elif "API" in finding_type:

            classification = {
                "category": "Broken Access Control",
                "owasp": "A01:2021 - Broken Access Control",
                "cwe": "CWE-284 - Improper Access Control"
            }

        return classification
