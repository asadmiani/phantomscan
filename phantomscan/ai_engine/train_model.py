"""
AI Training Engine
Autonomous Security Platform

This module:
- Uses accumulated learning data
- Simulates model retraining
- Updates feature weights dynamically
- Saves trained model parameters
"""

import json
import os
from statistics import mean

LEARNING_DB_PATH = "knowledge_learning.json"
MODEL_WEIGHTS_PATH = "trained_weights.json"


class AITrainer:

    def __init__(self,
                 learning_db=LEARNING_DB_PATH,
                 model_path=MODEL_WEIGHTS_PATH):
        self.learning_db = learning_db
        self.model_path = model_path

    # -----------------------------------------
    # Load Learning Data
    # -----------------------------------------

    def _load_learning_data(self):
        if os.path.exists(self.learning_db):
            with open(self.learning_db, "r") as f:
                return json.load(f)
        return {}

    # -----------------------------------------
    # Simulated Training Logic
    # -----------------------------------------

    def train(self):
        """
        Simulate retraining using historical occurrences.
        Adjust feature importance dynamically.
        """

        data = self._load_learning_data()

        if not data:
            return {
                "trained": False,
                "reason": "No learning data available"
            }

        # Aggregate vulnerability statistics
        vuln_counts = {}
        risk_history = []

        for record in data.values():
            vtype = record.get("type", "Unknown")
            occurrences = record.get("occurrences", 0)
            risks = record.get("risk_levels", [])

            vuln_counts[vtype] = vuln_counts.get(vtype, 0) + occurrences

            # Convert risk labels to numeric values
            for r in risks:
                risk_history.append(self._risk_to_numeric(r))

        avg_risk = mean(risk_history) if risk_history else 5

        # Generate adaptive weights
        trained_weights = self._generate_weights(vuln_counts, avg_risk)

        self._save_model(trained_weights)

        return {
            "trained": True,
            "average_risk": round(avg_risk, 2),
            "updated_weights": trained_weights
        }

    # -----------------------------------------
    # Convert Risk Label to Numeric
    # -----------------------------------------

    def _risk_to_numeric(self, risk_label):
        mapping = {
            "Critical": 9,
            "High": 7,
            "Medium": 5,
            "Low": 3
        }
        return mapping.get(risk_label, 5)

    # -----------------------------------------
    # Generate New Weights
    # -----------------------------------------

    def _generate_weights(self, vuln_counts, avg_risk):
        """
        Create simulated feature importance weights
        based on vulnerability frequency.
        """

        base_weight = avg_risk / 10

        weights = {
            "contains_sql_keywords": base_weight * vuln_counts.get("SQLi", 1),
            "contains_script_keywords": base_weight * vuln_counts.get("XSS", 1),
            "special_char_count": base_weight * 0.8,
            "payload_length": base_weight * 0.6,
            "high_entropy_payload": base_weight * 0.7
        }

        # Normalize weights
        normalized = {}
        total = sum(weights.values()) or 1

        for k, v in weights.items():
            normalized[k] = round(v / total * 5, 3)

        return normalized

    # -----------------------------------------
    # Save Trained Weights
    # -----------------------------------------

    def _save_model(self, weights):

        model_data = {
            "trained_at": self._current_time(),
            "weights": weights
        }

        with open(self.model_path, "w") as f:
            json.dump(model_data, f, indent=4)

    def _current_time(self):
        from datetime import datetime
        return datetime.utcnow().isoformat()
