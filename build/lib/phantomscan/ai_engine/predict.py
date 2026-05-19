"""
AI Prediction Pipeline
Autonomous Security Platform

This module orchestrates:
- Feature extraction
- Risk model prediction
- Explanation generation
- Adaptive learning adjustment
"""

from ai_engine.feature_engineering import extract_features
from ai_engine.model import AIRiskModel
from ai_engine.explain import generate_explanation, generate_remediation
from ai_engine.learning_engine import LearningEngine


class AIPredictor:

    def __init__(self):
        self.model = AIRiskModel()
        self.learning_engine = LearningEngine()

    # -----------------------------------------
    # Full AI Processing Pipeline
    # -----------------------------------------

    def analyze(self, raw_finding):
        """
        Process raw scanner finding through full AI pipeline.
        Returns enriched vulnerability analysis.
        """

        # Step 1: Feature Extraction
        features = extract_features(raw_finding)

        # Step 2: Risk Model Prediction
        model_result = self.model.predict(features)

        # Step 3: Explanation Generation
        explanation = generate_explanation(raw_finding)
        remediation = generate_remediation(raw_finding.get("type", "Unknown"))

        # Step 4: Build AI Analysis Object
        analyzed = {
            "type": raw_finding.get("type"),
            "url": raw_finding.get("url"),
            "parameter": raw_finding.get("param"),
            "method": raw_finding.get("method"),
            "payload": raw_finding.get("payload"),

            "risk_score": model_result["risk_score"],
            "confidence": model_result["confidence"],
            "risk_level": model_result["severity"],

            "explanation": explanation.strip(),
            "remediation": remediation.strip(),

            "features": features
        }

        # Step 5: Adaptive Learning Adjustment
        analyzed = self.learning_engine.adjust_risk(analyzed)

        # Step 6: Learn From This Finding
        self.learning_engine.learn_from_finding(analyzed)

        return analyzed
