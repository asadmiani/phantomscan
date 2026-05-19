import math


class CVSSv3Calculator:

    # Metric numerical values
    METRICS = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
        "AC": {"L": 0.77, "H": 0.44},
        "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
        "UI": {"N": 0.85, "R": 0.62},
        "C": {"H": 0.56, "L": 0.22, "N": 0},
        "I": {"H": 0.56, "L": 0.22, "N": 0},
        "A": {"H": 0.56, "L": 0.22, "N": 0}
    }

    def round_up(self, score):
        return math.ceil(score * 10) / 10.0

    def calculate(self, metrics):

        AV = self.METRICS["AV"][metrics["AV"]]
        AC = self.METRICS["AC"][metrics["AC"]]
        PR = self.METRICS["PR"][metrics["PR"]]
        UI = self.METRICS["UI"][metrics["UI"]]

        C = self.METRICS["C"][metrics["C"]]
        I = self.METRICS["I"][metrics["I"]]
        A = self.METRICS["A"][metrics["A"]]

        # Exploitability
        exploitability = 8.22 * AV * AC * PR * UI

        # Impact
        impact = 1 - ((1 - C) * (1 - I) * (1 - A))

        if impact <= 0:
            return 0, "NONE"

        impact_score = 6.42 * impact

        base_score = self.round_up(min((impact_score + exploitability), 10))

        severity = self.get_severity(base_score)

        vector = (
            f"AV:{metrics['AV']}/AC:{metrics['AC']}/"
            f"PR:{metrics['PR']}/UI:{metrics['UI']}/"
            f"S:U/C:{metrics['C']}/I:{metrics['I']}/A:{metrics['A']}"
        )

        return base_score, severity, vector

    def get_severity(self, score):

        if score == 0:
            return "NONE"
        elif score <= 3.9:
            return "LOW"
        elif score <= 6.9:
            return "MEDIUM"
        elif score <= 8.9:
            return "HIGH"
        else:
            return "CRITICAL"
