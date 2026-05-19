"""
AI Risk Model
Autonomous Security Platform

This module:
- Simulates ML-based vulnerability scoring
- Uses weighted feature scoring
- Outputs risk score + confidence
- Extendable to real ML models later
"""

import math


class AIRiskModel:

    def __init__(self):
        """
        Initialize feature weights.
        These simulate trained ML coefficients.
        """

        self.weights = {
            "url_length": 0.02,
            "path_length": 0.03,
            "num_subdirectories": 0.2,
            "param_length": 0.05,
            "payload_length": 0.08,
            "special_char_count": 0.5,
            "contains_sql_keywords": 1.5,
            "contains_script_keywords": 1.2,
            "is_post": 0.3,
            "vuln_type_encoded": 1.0,
            "high_entropy_payload": 0.6
        }

        self.bias = 1.0

    # --------------------------------
    # Core Prediction Function
    # --------------------------------

    def predict(self, features):
        """
        Predict risk score from feature dictionary.
        Returns:
            {
                "risk_score": float,
                "confidence": float,
                "severity": str
            }
        """

        score = self.bias

        # Weighted sum
        for feature, value in features.items():
            weight = self.weights.get(feature, 0)
            score += weight * value

        # Normalize score to 0–10 scale
        normalized_score = self._normalize(score)

        confidence = self._calculate_confidence(features)

        severity = self._severity_label(normalized_score)

        return {
            "risk_score": normalized_score,
            "confidence": confidence,
            "severity": severity
        }

    # --------------------------------
    # Helper Functions
    # --------------------------------

    def _normalize(self, score):
        """
        Convert raw score into 0–10 range using sigmoid scaling
        """
        sigmoid = 1 / (1 + math.exp(-score))
        return round(sigmoid * 10, 2)

    def _calculate_confidence(self, features):
        """
        Simple confidence estimation based on strong indicators
        """
        strong_indicators = (
            features.get("contains_sql_keywords", 0) +
            features.get("contains_script_keywords", 0) +
            features.get("special_char_count", 0) / 5
        )

        confidence = min(0.5 + strong_indicators * 0.1, 0.99)
        return round(confidence, 2)

    def _severity_label(self, score):
        """
        Convert numeric score to severity label
        """
        if score >= 8:
            return "Critical"
        elif score >= 6:
            return "High"
        elif score >= 4:
            return "Medium"
        else:
            return "Low"
