"""
PhantomScan Parameter Extractor
"""

from urllib.parse import (
    urlparse,
    parse_qs
)


class ParamExtractor:

    def extract(self, url):

        params = {}

        try:

            parsed = urlparse(url)

            query = parse_qs(parsed.query)

            for key in query:

                params[key] = "test"

            return params

        except:

            return {}
