"""
AI Explanation Engine
Autonomous Security Platform

This module:
- Assigns intelligent risk scoring
- Generates human-readable explanations
- Suggests remediation steps
"""

from datetime import datetime


# ---------------------------
# Risk Scoring System
# ---------------------------

SEVERITY_WEIGHTS = {
    "SQLi": 9,
    "XSS": 7,
    "LFI": 8,
    "HPP": 6,
    "Unknown": 5
}


def calculate_risk(vuln_type, confidence=0.8):
    """
    Calculate dynamic risk score (0–10 scale)
    """
    base = SEVERITY_WEIGHTS.get(vuln_type, SEVERITY_WEIGHTS["Unknown"])
    score = round(base * confidence, 1)

    if score >= 8:
        level = "Critical"
    elif score >= 6:
        level = "High"
    elif score >= 4:
        level = "Medium"
    else:
        level = "Low"

    return {
        "score": score,
        "level": level
    }


# ---------------------------
# Vulnerability Explanation
# ---------------------------

def generate_explanation(finding):
    """
    Generate professional explanation for vulnerability
    """
    vuln_type = finding.get("type", "Unknown")
    url = finding.get("url", "")
    param = finding.get("param", "")
    method = finding.get("method", "GET")

    explanation_templates = {
        "SQLi": f"""
SQL Injection detected at {url}

The parameter '{param}' appears vulnerable via {method} request.
An attacker may manipulate SQL queries and gain unauthorized access
to database contents including user credentials and sensitive data.
""",

        "XSS": f"""
Cross-Site Scripting (XSS) detected at {url}

The parameter '{param}' reflects user input without proper sanitization.
An attacker may inject malicious JavaScript and hijack user sessions.
""",

        "LFI": f"""
Local File Inclusion (LFI) detected at {url}

The parameter '{param}' may allow attackers to access internal server files.
This could expose configuration files and system credentials.
""",

        "HPP": f"""
HTTP Parameter Pollution detected at {url}

Duplicate or manipulated parameters may allow logic bypass
or unexpected backend behavior.
""",

        "Unknown": f"""
Potential security issue detected at {url}
Further manual verification is recommended.
"""
    }

    return explanation_templates.get(vuln_type, explanation_templates["Unknown"])


# ---------------------------
# Remediation Suggestions
# ---------------------------

def generate_remediation(vuln_type):
    """
    Provide remediation steps
    """

    remediation_map = {
        "SQLi": """
- Use parameterized queries (Prepared Statements)
- Implement ORM frameworks
- Apply strict input validation
- Use least privilege database accounts
""",

        "XSS": """
- Encode output properly (HTML entity encoding)
- Use Content Security Policy (CSP)
- Sanitize user input
- Avoid directly rendering user-controlled content
""",

        "LFI": """
- Disable file inclusion using user input
- Use allow-list validation for file paths
- Restrict file permissions
- Disable remote file inclusion in PHP config
""",

        "HPP": """
- Normalize input parameters server-side
- Reject duplicate parameters
- Validate request structure
"""
    }

    return remediation_map.get(vuln_type, "Apply proper input validation and secure coding practices.")


# ---------------------------
# Full AI Analysis Pipeline
# ---------------------------

def analyze_finding(finding):
    """
    Full AI processing of vulnerability finding
    """

    vuln_type = finding.get("type", "Unknown")

    risk = calculate_risk(vuln_type)

    explanation = generate_explanation(finding)

    remediation = generate_remediation(vuln_type)

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "type": vuln_type,
        "url": finding.get("url"),
        "parameter": finding.get("param"),
        "method": finding.get("method"),
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "explanation": explanation.strip(),
        "remediation": remediation.strip()
    }
