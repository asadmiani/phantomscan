"""
Web Crawler Module
Autonomous Security Platform

- Extracts internal links
- Prevents duplicate crawling
- Respects scan depth
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


class WebCrawler:

    def __init__(self, max_depth=2, timeout=5):
        self.max_depth = max_depth
        self.timeout = timeout
        self.visited = set()

    # ------------------------------------------
    # Start Crawling
    # ------------------------------------------

    def crawl(self, base_url):

        self.visited = set()
        urls = []
        self._crawl_recursive(base_url, base_url, 0, urls)
        return urls

    # ------------------------------------------
    # Recursive Crawl
    # ------------------------------------------

    def _crawl_recursive(self, base_url, current_url, depth, urls):

        if depth > self.max_depth:
            return

        if current_url in self.visited:
            return

        self.visited.add(current_url)

        try:
            response = requests.get(current_url, timeout=self.timeout)
        except:
            return

        urls.append(current_url)

        soup = BeautifulSoup(response.text, "html.parser")

        for link in soup.find_all("a", href=True):
            href = link["href"]
            full_url = urljoin(base_url, href)

            if self._is_internal(base_url, full_url):
                self._crawl_recursive(base_url, full_url, depth + 1, urls)

    # ------------------------------------------
    # Check Internal Links
    # ------------------------------------------

    def _is_internal(self, base, url):

        return urlparse(base).netloc == urlparse(url).netloc
