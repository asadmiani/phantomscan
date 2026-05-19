"""
Advanced Risk Aggregation Model
Autonomous Security Platform

This module:
- Aggregates AI prediction
- Applies contextual modifiers
- Adjusts based on learning history
- Produces final enterprise-grade risk score
"""

from datetime import datetime


class AdvancedRiskModel:

    def __init__(self):
        """
        Define contextual risk modifiers.
        These simulate real-world risk weighting logic.
        """

        self.context_weights = {
            "SQLi": 1.2,
            "XSS": 1.1,
            "LFI": 1.15,
            "HPP": 1.05,
            "Unknown": 1.0
        }

        self.method_modifier = {
            "GET": 1.0,
            "POST": 1.1
        }

    # ---------------------------------------
    # Main Risk Aggregation
    # ---------------------------------------

    def compute_final_risk(self, ai_result):
        """
        Combine:
        - AI model score
        - Confidence
        - Context weighting
        """

        base_score = ai_result.get("risk_score", 5)
        confidence = ai_result.get("confidence", 0.7)
        vuln_type = ai_result.get("type", "Unknown")
        method = ai_result.get("method", "GET")

        # Apply vulnerability weight
        type_weight = self.context_weights.get(vuln_type, 1.0)

        # Apply HTTP method modifier
        method_weight = self.method_modifier.get(method.upper(), 1.0)

        # Confidence influence
        confidence_boost = 1 + (confidence - 0.5)

        # Final score calculation
        final_score = base_score * type_weight * method_weight * confidence_boost

        final_score = min(round(final_score, 2), 10)

        severity = self._map_severity(final_score)

        return {
            "final_risk_score": final_score,
            "final_severity": severity,
            "computed_at": datetime.utcnow().isoformat()
        }

    # ---------------------------------------
    # Severity Mapping
    # ---------------------------------------

    def _map_severity(self, score):
        if score >= 9:
            return "Critical"
        elif score >= 7:
            return "High"
        elif score >= 4:
            return "Medium"
        else:
            return "Low"
