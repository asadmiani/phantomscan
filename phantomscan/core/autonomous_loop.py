"""
Autonomous Execution Loop
Autonomous Security Platform

This module:
- Controls scan lifecycle
- Executes adaptive scanning loop
- Integrates AI analysis
- Triggers retraining
"""

import time
from datetime import datetime

from ai_engine.predict import AIPredictor
from ai_engine.risk_model import AdvancedRiskModel
from ai_engine.retrain_trigger import RetrainTrigger
from ai_engine.train_model import AITrainer


class AutonomousLoop:

    def __init__(self, scanner, max_iterations=5):
        """
        scanner:
            Object that has method: scan(target)
            and returns list of raw findings

        max_iterations:
            Maximum adaptive scan rounds
        """

        self.scanner = scanner
        self.max_iterations = max_iterations

        self.ai_predictor = AIPredictor()
        self.risk_model = AdvancedRiskModel()
        self.retrain_trigger = RetrainTrigger()
        self.trainer = AITrainer()

        self.all_results = []

    # ------------------------------------------
    # Main Autonomous Loop
    # ------------------------------------------

    def run(self, target):

        print(f"[+] Starting autonomous scan on {target}")
        print("=" * 60)

        for iteration in range(1, self.max_iterations + 1):

            print(f"\n[+] Iteration {iteration} started at {datetime.utcnow().isoformat()}")

            raw_findings = self.scanner.scan(target)

            if not raw_findings:
                print("[!] No findings detected in this iteration.")
                continue

            for finding in raw_findings:

                # Step 1: AI Analysis
                ai_result = self.ai_predictor.analyze(finding)

                # Step 2: Advanced Risk Aggregation
                final_risk = self.risk_model.compute_final_risk(ai_result)

                combined = {**ai_result, **final_risk}

                self.all_results.append(combined)

                print(f"[+] Processed {finding.get('type')} → "
                      f"{combined['final_severity']} "
                      f"(Score: {combined['final_risk_score']})")

            # Step 3: Check retraining condition
            retrain_decision = self.retrain_trigger.trigger_retraining()

            if retrain_decision.get("retrained"):
                print("[*] Retraining triggered:", retrain_decision.get("reason"))
                training_result = self.trainer.train()
                print("[*] Training status:", training_result.get("trained"))

            # Optional adaptive delay
            time.sleep(1)

        print("\n[+] Autonomous scanning complete.")
        return self.all_results

    # ------------------------------------------
    # Decision System (Optional AI Expansion)
    # ------------------------------------------

    def decide_next_action(self):

        """
        Simple adaptive strategy example:
        If many high-risk findings exist,
        increase scan depth.
        """

        high_risk_count = sum(
            1 for r in self.all_results
            if r.get("final_severity") in ["High", "Critical"]
        )

        if high_risk_count >= 3:
            return "Increase scan depth"
        elif high_risk_count == 0:
            return "Reduce scan intensity"
        else:
            return "Maintain current strategy"
