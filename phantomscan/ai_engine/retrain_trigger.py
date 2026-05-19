"""
Retrain Trigger Engine
Autonomous Security Platform

This module:
- Monitors accumulated learning data
- Detects when model retraining should occur
- Simulates AI lifecycle management
"""

import json
import os
from datetime import datetime


LEARNING_DB_PATH = "knowledge_learning.json"
RETRAIN_LOG_PATH = "retrain_log.json"


class RetrainTrigger:

    def __init__(self,
                 learning_db=LEARNING_DB_PATH,
                 retrain_threshold=20,
                 drift_threshold=10):
        """
        retrain_threshold:
            Minimum total findings before retraining

        drift_threshold:
            If a vulnerability type increases sharply
        """

        self.learning_db = learning_db
        self.retrain_threshold = retrain_threshold
        self.drift_threshold = drift_threshold

    # --------------------------------------
    # Load Learning Data
    # --------------------------------------

    def _load_learning_data(self):
        if os.path.exists(self.learning_db):
            with open(self.learning_db, "r") as f:
                return json.load(f)
        return {}

    # --------------------------------------
    # Check Total Volume
    # --------------------------------------

    def _total_occurrences(self, data):
        total = 0
        for record in data.values():
            total += record.get("occurrences", 0)
        return total

    # --------------------------------------
    # Detect Data Drift
    # --------------------------------------

    def _detect_drift(self, data):
        """
        Detect abnormal growth of specific vulnerability type
        """

        vuln_counter = {}

        for record in data.values():
            vtype = record.get("type")
            vuln_counter[vtype] = vuln_counter.get(vtype, 0) + record.get("occurrences", 0)

        for vtype, count in vuln_counter.items():
            if count >= self.drift_threshold:
                return True, vtype

        return False, None

    # --------------------------------------
    # Retrain Decision Logic
    # --------------------------------------

    def should_retrain(self):
        """
        Determine whether retraining should occur.
        """

        data = self._load_learning_data()

        if not data:
            return False, "No learning data available"

        total = self._total_occurrences(data)

        if total >= self.retrain_threshold:
            return True, "Threshold exceeded"

        drift_detected, vuln_type = self._detect_drift(data)

        if drift_detected:
            return True, f"Drift detected in {vuln_type}"

        return False, "No retraining required"

    # --------------------------------------
    # Simulated Retraining
    # --------------------------------------

    def trigger_retraining(self):
        """
        Simulate retraining event.
        Logs retraining action.
        """

        decision, reason = self.should_retrain()

        if not decision:
            return {
                "retrained": False,
                "reason": reason
            }

        retrain_event = {
            "timestamp": datetime.utcnow().isoformat(),
            "reason": reason,
            "status": "Model retrained (simulated)"
        }

        self._log_retrain_event(retrain_event)

        return {
            "retrained": True,
            "reason": reason
        }

    # --------------------------------------
    # Logging
    # --------------------------------------

    def _log_retrain_event(self, event):

        log_data = []

        if os.path.exists(RETRAIN_LOG_PATH):
            with open(RETRAIN_LOG_PATH, "r") as f:
                try:
                    log_data = json.load(f)
                except Exception:
                    log_data = []

        log_data.append(event)

        with open(RETRAIN_LOG_PATH, "w") as f:
            json.dump(log_data, f, indent=4)
