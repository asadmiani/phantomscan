import hashlib

class ResponseAnalyzer:

    @staticmethod
    def hash_response(response_text):
        return hashlib.sha256(response_text.encode()).hexdigest()

    @staticmethod
    def compare(original, modified):
        result = {
            "status_changed": original.status_code != modified.status_code,
            "length_changed": len(original.text) != len(modified.text),
            "hash_changed": (
                ResponseAnalyzer.hash_response(original.text) !=
                ResponseAnalyzer.hash_response(modified.text)
            )
        }
        return result
