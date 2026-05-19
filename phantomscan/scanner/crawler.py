# phantomscan/scanner/crawler.py

import requests
import urllib3

from bs4 import BeautifulSoup

from urllib.parse import (
    urljoin,
    urlparse
)

urllib3.disable_warnings()


class WebCrawler:

    def __init__(self):

        self.visited = set()

        self.urls = set()

        self.max_urls = 30

    # =====================================
    # START
    # =====================================

    def crawl(self, start_url):

        # FORCE HTTP
        if start_url.startswith("https://"):

            start_url = start_url.replace(
                "https://",
                "http://"
            )

        self.visited.clear()

        self.urls.clear()

        self._crawl(start_url)

        return list(self.urls)

    # =====================================
    # INTERNAL
    # =====================================

    def _crawl(self, url):

        if url in self.visited:
            return

        if len(self.urls) >= self.max_urls:
            return

        self.visited.add(url)

        print(f"[CRAWLER] Visiting: {url}")

        headers = {

            "User-Agent":
            "Mozilla/5.0 PhantomScan"
        }

        try:

            response = requests.get(

                url,

                headers=headers,

                timeout=5,

                verify=False,

                allow_redirects=True
            )

        except Exception as e:

            print(f"[CRAWLER ERROR] {url}: {e}")

            return

        self.urls.add(url)

        try:

            soup = BeautifulSoup(
                response.text,
                "html.parser"
            )

            for tag in soup.find_all("a", href=True):

                href = tag.get("href")

                full_url = urljoin(url, href)

                parsed = urlparse(full_url)

                clean_url = (

                    parsed.scheme
                    + "://"
                    + parsed.netloc
                    + parsed.path
                )

                # SAME DOMAIN ONLY
                if (
                    parsed.netloc
                    == urlparse(url).netloc
                ):

                    if clean_url not in self.visited:

                        self.urls.add(clean_url)

        except Exception as e:

            print(f"[CRAWLER PARSE ERROR] {e}")
