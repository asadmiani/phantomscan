import re
import hashlib
import copy
from core.response_analyzer import ResponseAnalyzer

class IDOREngine:
    def __init__(self, session):
        self.session = session

    def extract_ids_from_url(self, url):
        numeric_ids = re.findall(r'/(\d+)', url)
        uuid_ids = re.findall(
            r'/([0-9a-fA-F-]{36})', url
        )
        return numeric_ids + uuid_ids

    def modify_numeric_id(self, url, original_id):
        new_id = str(int(original_id) + 1)
        return url.replace(original_id, new_id)


    def test_idor(self, url):
        findings = []

        original_response = self.session.get(url)
        ids = self.extract_ids_from_url(url)

        for object_id in ids:
            modified_url = self.modify_numeric_id(url, object_id)
            modified_response = self.session.get(modified_url)

            comparison = ResponseAnalyzer.compare(
                original_response,
                modified_response
            )

            if (
                original_response.status_code == 200 and
                modified_response.status_code == 200 and
                comparison["hash_changed"]
            ):
                findings.append({
                    "type": "IDOR",
                    "original_url": url,
                    "modified_url": modified_url,
                    "confidence": self.calculate_confidence(comparison)
                })

        return findings
