"""SCM sources: GitHub repositories, their issue and PR comment bodies.

Issue and pull-request comments are a very common leak surface that a repo clone
never sees — someone pastes a token into a bug report or a review thread. This
walks the GitHub REST API for a repo (or every repo in an org) and yields the
bodies of issues, PRs, and their comments as scannable blobs, through the same
pipeline as everything else.

`requests` is the only dependency (the `[web]` extra); the session is injected so
tests exercise paging and extraction against a fake API with no network or token.
Read-only: only GET, and a token is used solely for auth and rate limits.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, List, Optional, Tuple

from .models import ScanStats

API = "https://api.github.com"
PER_PAGE = 100
MAX_PAGES = 50  # safety cap per endpoint


@dataclass
class GitHubSource:
    owner: str
    repo: Optional[str] = None  # None => every repo in the org/user
    token: Optional[str] = None
    session: object = None  # injectable for tests
    base_url: str = API

    def blobs(self, stats: ScanStats) -> Iterator[Tuple[str, bytes]]:
        session = self.session or _make_session(self.token)
        repos = [self.repo] if self.repo else self._list_repos(session, stats)
        for repo in repos:
            yield from self._repo_text(session, repo, stats)

    # ------------------------------------------------------------------ #

    def _list_repos(self, session, stats: ScanStats) -> List[str]:  # type: ignore[no-untyped-def]
        names: List[str] = []
        for kind in ("orgs", "users"):
            data = self._paged(session, f"/{kind}/{self.owner}/repos", stats)
            if data:
                names = [r["name"] for r in data if isinstance(r, dict) and "name" in r]
                break
        return names

    def _repo_text(self, session, repo: str, stats: ScanStats) -> Iterator[Tuple[str, bytes]]:  # type: ignore[no-untyped-def]
        base = f"/repos/{self.owner}/{repo}"
        # Issues (includes PRs) with their bodies, then all issue/PR comments,
        # then PR review comments — every free-text field a secret can hide in.
        for path, label in (
            (f"{base}/issues?state=all", "issue"),
            (f"{base}/issues/comments", "issue-comment"),
            (f"{base}/pulls/comments", "review-comment"),
        ):
            for item in self._paged(session, path, stats):
                if not isinstance(item, dict):
                    continue
                body = item.get("body")
                if not body:
                    continue
                number = item.get("number") or item.get("id") or "?"
                logical = f"github://{self.owner}/{repo}/{label}/{number}"
                yield logical, body.encode("utf-8", "replace")

    def _paged(self, session, path: str, stats: ScanStats) -> List[dict]:  # type: ignore[no-untyped-def]
        out: List[dict] = []
        sep = "&" if "?" in path else "?"
        for page in range(1, MAX_PAGES + 1):
            url = f"{self.base_url}{path}{sep}per_page={PER_PAGE}&page={page}"
            try:
                resp = session.get(url)
            except Exception as exc:  # noqa: BLE001
                stats.errors.append(f"{path}: {type(exc).__name__}")
                break
            if getattr(resp, "status_code", 200) != 200:
                if resp.status_code not in (404,):
                    stats.errors.append(f"{path}: http {resp.status_code}")
                break
            try:
                batch = resp.json()
            except Exception:  # noqa: BLE001
                break
            if not isinstance(batch, list) or not batch:
                break
            out.extend(batch)
            if len(batch) < PER_PAGE:
                break
        return out


def _make_session(token: Optional[str]):  # type: ignore[no-untyped-def]
    import requests

    session = requests.Session()
    session.headers["Accept"] = "application/vnd.github+json"
    session.headers["User-Agent"] = "clurichaun"
    if token:
        session.headers["Authorization"] = f"Bearer {token}"

    class _Wrapped:
        def get(self, url):  # type: ignore[no-untyped-def]
            return session.get(url, timeout=20)

    return _Wrapped()
