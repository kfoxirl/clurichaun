"""Web crawler and fetcher for scanning remote content for secrets.

Discovers HTML, JS, CSS, source maps, JSON and config files from a starting URL,
then hands their *bytes* back to the caller so the normal ingestion and detection
pipeline can process them — a fetched URL is just another `Blob` source, so
archives, source maps and binary payloads work remotely exactly as they do on
disk.

Crawling someone else's site is an outward-facing act: `robots.txt` is honoured
by default, requests are rate-limited, and the crawl never leaves the starting
host.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Set, Tuple
from urllib import robotparser
from urllib.parse import urljoin, urldefrag, urlparse

import requests
from bs4 import BeautifulSoup

from ..models import ScanStats
from .policy import AiPolicy, parse_ai_txt, parse_llms_txt

USER_AGENT = "clurichaun/0.1.0 (+https://github.com/kfoxirl/clurichaun)"
DEFAULT_TIMEOUT = 10
MAX_DEPTH = 3
MAX_FILES = 1000
DEFAULT_DELAY = 0.2
MAX_BYTES = 32 * 1024 * 1024

# Extensions worth downloading even when the server's Content-Type is unhelpful.
INTERESTING_SUFFIXES: Tuple[str, ...] = (
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".map", ".json", ".yml",
    ".yaml", ".toml", ".ini", ".cfg", ".conf", ".config", ".properties",
    ".env", ".txt", ".log", ".bak", ".old", ".orig", ".sql", ".xml", ".css",
    ".pem", ".key", ".tf", ".tfstate", ".zip", ".tar", ".gz", ".jar", ".wasm",
)

_TEXTUAL_TYPES: Tuple[str, ...] = (
    "text/", "application/json", "javascript", "application/xml",
    "application/x-yaml", "application/octet-stream", "application/zip",
)


class WebScanError(Exception):
    pass


@dataclass
class WebConfig:
    url: str
    depth: int = MAX_DEPTH
    max_files: int = MAX_FILES
    timeout: int = DEFAULT_TIMEOUT
    respect_robots: bool = True
    follow_redirects: bool = True
    delay: float = DEFAULT_DELAY
    max_bytes: int = MAX_BYTES
    same_host_only: bool = True
    respect_ai_txt: bool = True
    use_llms_txt: bool = True
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class Fetched:
    """One downloaded resource, ready for `FileIngestor.blobs_from_bytes`."""

    url: str
    content: bytes
    content_type: str

    @property
    def logical_path(self) -> str:
        """A path-shaped name so scope rules and parsers key off the real file."""
        parsed = urlparse(self.url)
        path = parsed.path or "/"
        if path.endswith("/"):
            path += "index.html"
        return f"{parsed.netloc}{path}"


class WebCrawler:
    def __init__(self, config: WebConfig) -> None:
        self.config = config
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        self.session.headers.update(config.headers)
        self.seen_urls: Set[str] = set()
        self.queued: Set[str] = set()
        self.stats = ScanStats()
        self._robots: Optional[robotparser.RobotFileParser] = None
        self._robots_loaded = False
        self._last_request = 0.0
        self.ai_policy = AiPolicy()
        self._ai_loaded = False

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #

    def crawl(self) -> Iterator[str]:
        """Yield URLs worth scanning, breadth-first, deduplicated."""
        start = urldefrag(self.config.url).url
        self._load_ai_policy(start)
        if self.config.respect_ai_txt and self.ai_policy.scraping_denied:
            self.stats.errors.append(
                f"{urlparse(start).netloc}: ai.txt declares Scraping: deny "
                f"({self.ai_policy.source}); use --no-ai-txt if you are authorised"
            )
            return

        queue: List[Tuple[str, int]] = [(start, 0)]
        self.queued.add(start)
        emitted: Set[str] = set()

        # llms.txt is written for agents: prefer its index over blind walking.
        for seed in self._llms_seeds(start):
            if seed not in self.queued:
                self.queued.add(seed)
                queue.append((seed, 1))

        while queue and len(emitted) < self.config.max_files:
            url, depth = queue.pop(0)
            response = self._get(url)
            if response is None:
                continue

            content_type = response.headers.get("Content-Type", "").lower()
            is_html = "text/html" in content_type or "xhtml" in content_type

            # Always yield the starting URL as a scannable artefact, even if it's HTML with no interesting suffix.
            if url not in emitted:
                emitted.add(url)
                yield url

            if not is_html:
                continue

            # For HTML pages, extract assets and links for further crawling.
            for asset in self._assets(response.text, url):
                if asset in emitted or len(emitted) >= self.config.max_files:
                    continue
                emitted.add(asset)
                yield asset

            if depth + 1 < self.config.depth:
                for link in self._links(response.text, url):
                    if link in self.queued:
                        continue
                    self.queued.add(link)
                    queue.append((link, depth + 1))

    def _assets(self, html: str, base_url: str) -> Iterator[str]:
        """Scripts, stylesheets, source maps and linked config files."""
        soup = BeautifulSoup(html, "html.parser")

        for tag, attr in (("script", "src"), ("link", "href"), ("iframe", "src")):
            for node in soup.find_all(tag, attrs={attr: True}):
                target = urldefrag(urljoin(base_url, str(node[attr]))).url
                if not self._in_scope(target, base_url):
                    continue
                if tag == "link":
                    rel = " ".join(node.get("rel") or []).lower()
                    if "stylesheet" not in rel and not _is_interesting(target):
                        continue
                yield target
                # A bundle almost always ships a sibling source map.
                if target.endswith((".js", ".mjs", ".css")):
                    yield target + ".map"

        for anchor in soup.find_all("a", href=True):
            target = urldefrag(urljoin(base_url, str(anchor["href"]))).url
            if _is_interesting(target) and self._in_scope(target, base_url):
                yield target

    def _links(self, html: str, base_url: str) -> List[str]:
        soup = BeautifulSoup(html, "html.parser")
        out: List[str] = []
        for anchor in soup.find_all("a", href=True):
            target = urldefrag(urljoin(base_url, str(anchor["href"]))).url
            if self._in_scope(target, base_url) and not _is_interesting(target):
                out.append(target)
        return out

    # ------------------------------------------------------------------ #
    # Fetching
    # ------------------------------------------------------------------ #

    def fetch(self, url: str) -> Optional[Fetched]:
        """Download one URL's bytes, or None if it is unusable."""
        response = self._get(url, stream=True)
        if response is None:
            return None

        content_type = response.headers.get("Content-Type", "").lower()
        declared = response.headers.get("Content-Length")
        if declared and declared.isdigit() and int(declared) > self.config.max_bytes:
            self.stats.errors.append(f"{url}: skipped, {declared} bytes over max-bytes")
            return None

        chunks: List[bytes] = []
        total = 0
        try:
            for chunk in response.iter_content(65536):
                chunks.append(chunk)
                total += len(chunk)
                if total > self.config.max_bytes:
                    self.stats.errors.append(f"{url}: truncated at max-bytes")
                    break
        except requests.RequestException as exc:
            self.stats.errors.append(f"{url}: read failed: {exc}")
            return None
        finally:
            response.close()

        content = b"".join(chunks)
        if not content:
            return None
        self.stats.bytes_scanned += len(content)
        return Fetched(url=url, content=content, content_type=content_type)

    def crawl_and_fetch(self) -> Iterator[Fetched]:
        """Discovery and download in one pass."""
        for url in self.crawl():
            fetched = self.fetch(url)
            if fetched is not None:
                self.stats.files_scanned += 1
                yield fetched

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _get(self, url: str, stream: bool = False) -> Optional[requests.Response]:
        if url in self.seen_urls:
            return None
        self.seen_urls.add(url)
        self.stats.files_seen += 1

        if not self._allowed(url):
            self.stats.files_skipped += 1
            self.stats.errors.append(f"{url}: disallowed by robots.txt")
            return None

        self._load_ai_policy(url)
        if not self._ai_allowed(url):
            self.stats.files_skipped += 1
            self.stats.errors.append(f"{url}: disallowed by ai.txt")
            return None

        self._throttle()
        try:
            response = self.session.get(
                url,
                timeout=self.config.timeout,
                allow_redirects=self.config.follow_redirects,
                stream=stream,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            self.stats.errors.append(f"{url}: fetch failed: {exc}")
            self.stats.files_skipped += 1
            return None

        content_type = response.headers.get("Content-Type", "").lower()
        if content_type and not any(kind in content_type for kind in _TEXTUAL_TYPES):
            if not _is_interesting(url):
                response.close()
                self.stats.files_skipped += 1
                return None
        return response

    def _throttle(self) -> None:
        # A site-declared Rate-Limit is an instruction, so the stricter of it
        # and --delay wins.
        delay = self.config.delay
        if self.config.respect_ai_txt:
            delay = max(delay, self.ai_policy.delay_seconds)
        if delay <= 0:
            return
        elapsed = time.monotonic() - self._last_request
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._last_request = time.monotonic()

    def _allowed(self, url: str) -> bool:
        """Honour robots.txt. A fetch failure means 'no rules', not 'deny all'."""
        if not self.config.respect_robots:
            return True
        if not self._robots_loaded:
            self._robots_loaded = True
            parsed = urlparse(url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            parser = robotparser.RobotFileParser()
            try:
                response = self.session.get(robots_url, timeout=self.config.timeout)
                if response.status_code == 200:
                    parser.parse(response.text.splitlines())
                    self._robots = parser
            except requests.RequestException:
                self._robots = None
        if self._robots is None:
            return True
        return self._robots.can_fetch(USER_AGENT, url)

    def _ai_allowed(self, url: str) -> bool:
        if not self.config.respect_ai_txt or not self.ai_policy.declared:
            return True
        if self.ai_policy.scraping_denied:
            return False
        return self.ai_policy.path_allowed(url)

    def _load_ai_policy(self, url: str) -> None:
        """Try the IETF well-known location, then Spawning's root file."""
        if self._ai_loaded:
            return
        self._ai_loaded = True
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        for location in ("/.well-known/ai.txt", "/ai.txt"):
            try:
                response = self.session.get(
                    origin + location, timeout=self.config.timeout
                )
            except requests.RequestException:
                continue
            if response.status_code != 200 or not response.text.strip():
                continue
            content_type = response.headers.get("Content-Type", "").lower()
            if "html" in content_type:
                continue  # a catch-all 200 page, not a policy file
            self.ai_policy = parse_ai_txt(response.text, USER_AGENT, origin + location)
            return

    def _llms_seeds(self, url: str) -> List[str]:
        if not self.config.use_llms_txt:
            return []
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        try:
            response = self.session.get(origin + "/llms.txt", timeout=self.config.timeout)
        except requests.RequestException:
            return []
        if response.status_code != 200 or "html" in response.headers.get(
            "Content-Type", ""
        ).lower():
            return []
        seeds = parse_llms_txt(
            response.text, origin + "/", same_host=self.config.same_host_only
        )
        if seeds:
            self.stats.errors.append(
                f"{parsed.netloc}: llms.txt offered {len(seeds)} URLs, used as seeds"
            )
        return seeds[: self.config.max_files]

    def _in_scope(self, url: str, base_url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if self.config.same_host_only:
            return parsed.netloc == urlparse(base_url).netloc
        return True


def _is_interesting(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith(INTERESTING_SUFFIXES) or "/.env" in path or "/.git/" in path
