import requests
import difflib


class FalsePositiveFilter:

    def __init__(self):
        self.timeout = 8
        self.similarity_threshold = 0.95  # 95% similarity = likely false positive

    # -----------------------------------------
    # Get Baseline Response
    # -----------------------------------------
    def get_baseline(self, url):
        try:
            r = requests.get(url, timeout=self.timeout)
            return r.text
        except:
            return ""

    # -----------------------------------------
    # Compare Similarity
    # -----------------------------------------
    def similarity(self, text1, text2):
        return difflib.SequenceMatcher(None, text1, text2).ratio()

    # -----------------------------------------
    # Filter Findings
    # -----------------------------------------
    def filter(self, findings):

        refined = []

        for f in findings:

            url = f.get("url")
            injected_url = f.get("payload")

            if not injected_url or injected_url == "DOM Sink Found":
                refined.append(f)
                continue

            baseline = self.get_baseline(url)

            try:
                injected_response = requests.get(injected_url, timeout=self.timeout).text
            except:
                refined.append(f)
                continue

            sim = self.similarity(baseline, injected_response)

            # -----------------------------------------
            # False Positive Logic
            # -----------------------------------------

            if sim > self.similarity_threshold:
                # Too similar → likely false positive
                f["confidence"] = max(f.get("confidence", 0) - 40, 10)
                f["false_positive_likelihood"] = "HIGH"
            else:
                f["false_positive_likelihood"] = "LOW"

            # Remove extremely weak findings
            if f.get("confidence", 0) >= 20:
                refined.append(f)

        return refined
