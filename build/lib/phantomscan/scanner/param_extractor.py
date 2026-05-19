"""
Parameter Extraction Module
Autonomous Security Platform

- Extracts GET parameters
- Extracts HTML form inputs
- Prepares injection points
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs


class ParamExtractor:

    def __init__(self, timeout=5):
        self.timeout = timeout

    # ------------------------------------------
    # Extract Parameters
    # ------------------------------------------

    def extract(self, url):

        parameters = {
            "get_params": [],
            "form_params": []
        }

        # --- Extract GET Parameters ---
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        for param in query_params:
            parameters["get_params"].append(param)

        # --- Extract Form Inputs ---
        try:
            response = requests.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, "html.parser")

            forms = soup.find_all("form")

            for form in forms:
                inputs = form.find_all("input")
                for inp in inputs:
                    name = inp.get("name")
                    if name:
                        parameters["form_params"].append(name)

        except:
            pass

        return parameters
