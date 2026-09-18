"""Remote scanning: crawl a site and feed what it serves to the normal pipeline.

Needs `requests` and `beautifulsoup4`, which are an optional extra — the local
scanner must work without network libraries installed:

    pip install 'clurichaun[web]'
"""

from __future__ import annotations

from .crawler import Fetched, WebConfig, WebCrawler, WebScanError
from .policy import AiPolicy, parse_ai_txt, parse_llms_txt, parse_rate_limit

__all__ = [
    "AiPolicy",
    "Fetched",
    "WebConfig",
    "WebCrawler",
    "WebScanError",
    "parse_ai_txt",
    "parse_llms_txt",
    "parse_rate_limit",
]
