"""
Feature Engineering Module
Autonomous Security Platform

This module:
- Converts raw vulnerability findings into structured numeric features
- Enables AI scoring & ML extension
- Standardizes data for analytics pipeline
"""

from urllib.parse import urlparse
import re


# ------------------------------
# Utility Functions
# ------------------------------

def count_special_chars(value):
    """Count SQL/XSS related special characters"""
    return len(re.findall(r"[\'\"=<>;()\-]", value))


def has_sql_keywords(payload):
    keywords = [
        "select", "union", "insert", "update",
        "delete", "drop", "or", "and", "--"
    ]
    payload_lower = payload.lower()
    return int(any(k in payload_lower for k in keywords))


def has_script_keywords(payload):
    keywords = ["<script>", "onerror", "alert(", "javascript:"]
    payload_lower = payload.lower()
    return int(any(k in payload_lower for k in keywords))


# ------------------------------
# Core Feature Extraction
# ------------------------------

def extract_features(finding):
    """
    Convert raw finding into structured AI features.
    Returns a dictionary of numerical & categorical features.
    """

    url = finding.get("url", "")
    param = finding.get("param", "")
    payload = finding.get("payload", "")
    vuln_type = finding.get("type", "Unknown")
    method = finding.get("method", "GET")

    parsed_url = urlparse(url)

    features = {}

    # --- URL Features ---
    features["url_length"] = len(url)
    features["path_length"] = len(parsed_url.path)
    features["num_subdirectories"] = parsed_url.path.count("/")

    # --- Parameter Features ---
    features["param_length"] = len(param)
    features["payload_length"] = len(payload)
    features["special_char_count"] = count_special_chars(payload)

    # --- Payload Behavior ---
    features["contains_sql_keywords"] = has_sql_keywords(payload)
    features["contains_script_keywords"] = has_script_keywords(payload)

    # --- HTTP Method ---
    features["is_post"] = 1 if method.upper() == "POST" else 0

    # --- Vulnerability Encoding ---
    vuln_encoding = {
        "SQLi": 1,
        "XSS": 2,
        "LFI": 3,
        "HPP": 4,
        "Unknown": 0
    }

    features["vuln_type_encoded"] = vuln_encoding.get(vuln_type, 0)

    # --- Risk Heuristics ---
    features["high_entropy_payload"] = 1 if len(set(payload)) > 10 else 0

    return features


# ------------------------------
# Batch Processing
# ------------------------------

def extract_features_batch(findings_list):
    """
    Process multiple findings for ML pipeline
    Returns list of feature dictionaries
    """
    feature_set = []

    for finding in findings_list:
        features = extract_features(finding)
        feature_set.append(features)

    return feature_set


# ------------------------------
# Feature Vector Conversion
# ------------------------------

def features_to_vector(features):
    """
    Convert feature dictionary to ordered numeric vector
    (Useful for ML models)
    """

    ordered_keys = sorted(features.keys())
    return [features[key] for key in ordered_keys]
