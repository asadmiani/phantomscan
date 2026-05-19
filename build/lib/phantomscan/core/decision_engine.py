"""
Decision Engine
Autonomous Security Platform

This module:
- Evaluates scan results
- Determines adaptive scanning strategy
- Controls scan intensity and behavior
"""

from collections import Counter


class DecisionEngine:

    def __init__(self):
        """
        Define adaptive thresholds.
        These simulate real-world SOC logic.
        """

        self.critical_threshold = 2
        self.high_threshold = 3
        self.medium_threshold = 5

    # ------------------------------------------
    # Main Strategy Decision
    # ------------------------------------------

    def decide(self, findings):

        """
        findings: list of processed findings
        (must contain final_severity)
        """

        if not findings:
            return {
                "action": "reduce_scan",
                "reason": "No vulnerabilities detected"
            }

        severity_counts = Counter(
            f.get("final_severity", "Low")
            for f in findings
        )

        critical = severity_counts.get("Critical", 0)
        high = severity_counts.get("High", 0)
        medium = severity_counts.get("Medium", 0)

        # --- Decision Logic ---

        if critical >= self.critical_threshold:
            return {
                "action": "aggressive_scan",
                "reason": "Multiple critical findings detected"
            }

        if high >= self.high_threshold:
            return {
                "action": "deep_scan",
                "reason": "High severity vulnerabilities increasing"
            }

        if medium >= self.medium_threshold:
            return {
                "action": "focused_scan",
                "reason": "Multiple medium risks detected"
            }

        return {
            "action": "maintain_strategy",
            "reason": "Risk level stable"
        }

    # ------------------------------------------
    # Scan Depth Adjustment
    # ------------------------------------------

    def adjust_scan_depth(self, current_depth, action):

        """
        Modify scanning depth dynamically
        """

        if action == "aggressive_scan":
            return min(current_depth + 2, 10)

        if action == "deep_scan":
            return min(current_depth + 1, 10)

        if action == "reduce_scan":
            return max(current_depth - 1, 1)

        return current_depth
