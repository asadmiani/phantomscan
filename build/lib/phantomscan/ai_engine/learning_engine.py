import sqlite3
"""
Learning Engine
Autonomous Security Platform

This module:
- Stores scan history
- Learns from repeated patterns
- Adjusts risk dynamically
- Simulates adaptive AI behavior
"""

import json
import os
from collections import defaultdict
from datetime import datetime


LEARNING_DB_PATH = "knowledge_learning.json"


class LearningEngine:

    def __init__(self, db_path=LEARNING_DB_PATH):
        self.db_path = db_path
        self.data = self._load_db()

    # ----------------------------
    # Database Handling
    # ----------------------------

    def _load_db(self):
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_db(self):
        with open(self.db_path, "w") as f:
            json.dump(self.data, f, indent=4)

    # ----------------------------
    # Learning From Findings
    # ----------------------------

    def learn_from_finding(self, analyzed_finding):
        """
        Store vulnerability occurrence and update statistics
        """

        vuln_type = analyzed_finding.get("type")
        url = analyzed_finding.get("url")
        risk_level = analyzed_finding.get("risk_level")

        key = f"{vuln_type}:{url}"

        if key not in self.data:
            self.data[key] = {
                "type": vuln_type,
                "url": url,
                "occurrences": 0,
                "last_seen": None,
                "risk_levels": []
            }

        self.data[key]["occurrences"] += 1
        self.data[key]["last_seen"] = datetime.utcnow().isoformat()
        self.data[key]["risk_levels"].append(risk_level)

        self._save_db()

    # ----------------------------
    # Adaptive Risk Adjustment
    # ----------------------------

    def adjust_risk(self, analyzed_finding):
        """
        Increase risk if vulnerability repeatedly detected
        """

        vuln_type = analyzed_finding.get("type")
        url = analyzed_finding.get("url")
        base_score = analyzed_finding.get("risk_score", 5)

        key = f"{vuln_type}:{url}"

        if key in self.data:
            occurrences = self.data[key]["occurrences"]

            # Increase score based on repetition
            bonus = min(occurrences * 0.3, 2.0)
            adjusted_score = round(min(base_score + bonus, 10), 1)

            if adjusted_score >= 8:
                level = "Critical"
            elif adjusted_score >= 6:
                level = "High"
            elif adjusted_score >= 4:
                level = "Medium"
            else:
                level = "Low"

            analyzed_finding["risk_score"] = adjusted_score
            analyzed_finding["risk_level"] = level

        return analyzed_finding

    # ----------------------------
    # Learning Summary
    # ----------------------------

    def get_statistics(self):
        """
        Return summary statistics
        """

        stats = defaultdict(int)

        for record in self.data.values():
            stats[record["type"]] += record["occurrences"]

        return dict(stats)

    # ----------------------------
    # Reset Learning (Optional)
    # ----------------------------

    def reset_learning(self):
        self.data = {}
        self._save_db()
