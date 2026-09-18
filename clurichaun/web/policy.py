"""Site-declared agent policy: ``robots.txt``, ``ai.txt`` and ``llms.txt``.

Three conventions, three different jobs:

* ``robots.txt`` — per-path crawl permission. Long settled.
* ``ai.txt`` — AI-specific usage policy. Two forms exist in the wild:

  - the IETF draft (`draft-car-ai-txt-wellknown`) at ``/.well-known/ai.txt``:
    a block key-value format with ``Scraping:``, ``Training:``, ``Indexing:``,
    ``Caching:`` (each ``allow``/``deny``/``conditional``), ``Rate-Limit:
    N/window``, ``Contact:``, ``Policy-URL:``, and per-``Agent:`` overrides;
  - Spawning's earlier robots-shaped file at ``/ai.txt``, using
    ``User-Agent:``/``Disallow:``.

  Both are parsed. For a *scanner* the operative field is ``Scraping`` — we
  fetch and analyse, we do not train — and ``Rate-Limit``, which is a concrete
  instruction we can obey. ``Training``/``Attribution`` are recorded and
  reported but do not govern scanning.

* ``llms.txt`` — a Markdown index of a site's own content, written *for* agents.
  It is not a permission file at all; it is a gift to a crawler, so we read it
  as a seed list and skip blind link-walking where it exists.

All three are advisory. Clurichaun honours them by default because pointing a
secret scanner at someone else's host is an outward-facing act; `--no-robots`
and `--no-ai-txt` exist for hosts you are authorised to test.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.parse import urljoin, urldefrag, urlparse

POLICY_ALLOW = "allow"
POLICY_DENY = "deny"
POLICY_CONDITIONAL = "conditional"

_WINDOW_SECONDS = {
    "second": 1.0,
    "sec": 1.0,
    "s": 1.0,
    "minute": 60.0,
    "min": 60.0,
    "m": 60.0,
    "hour": 3600.0,
    "h": 3600.0,
    "day": 86400.0,
    "d": 86400.0,
}

_RATE = re.compile(r"(\d+(?:\.\d+)?)\s*/\s*([a-z]+)", re.IGNORECASE)
_MD_LINK = re.compile(r"\[[^\]]*\]\(\s*(<?)([^)\s>]+)\1[^)]*\)")


@dataclass(slots=True)
class AiPolicy:
    """What a site's ai.txt declares, reduced to what a scanner can act on."""

    source: str = ""
    site_name: str = ""
    contact: str = ""
    policy_url: str = ""
    scraping: str = POLICY_ALLOW
    training: str = ""
    indexing: str = ""
    caching: str = ""
    attribution: str = ""
    delay_seconds: float = 0.0
    disallow: Tuple[str, ...] = ()
    allow: Tuple[str, ...] = ()
    fields: Dict[str, str] = field(default_factory=dict)

    @property
    def declared(self) -> bool:
        return bool(self.source)

    @property
    def scraping_denied(self) -> bool:
        return self.scraping == POLICY_DENY

    def path_allowed(self, url: str) -> bool:
        """Spawning-style Disallow/Allow globs, longest match wins."""
        path = urlparse(url).path or "/"
        verdict = True
        best = -1
        for pattern in self.allow:
            if _glob_match(pattern, path) and len(pattern) > best:
                verdict, best = True, len(pattern)
        for pattern in self.disallow:
            if _glob_match(pattern, path) and len(pattern) > best:
                verdict, best = False, len(pattern)
        return verdict

    def summary(self) -> str:
        bits = [f"ai.txt at {self.source}"]
        if self.site_name:
            bits.append(self.site_name)
        bits.append(f"scraping={self.scraping}")
        if self.training:
            bits.append(f"training={self.training}")
        if self.delay_seconds:
            bits.append(f"rate-limit={self.delay_seconds:g}s/request")
        if self.contact:
            bits.append(f"contact={self.contact}")
        return " | ".join(bits)


def parse_ai_txt(text: str, agent: str, source: str = "") -> AiPolicy:
    """Parse either ai.txt dialect. Unknown keys are kept in ``fields``."""
    if _looks_robots_shaped(text):
        return _parse_robots_shaped(text, agent, source)
    return _parse_ietf(text, agent, source)


def _looks_robots_shaped(text: str) -> bool:
    lowered = text.lower()
    has_ua = re.search(r"(?m)^\s*user-agent\s*:", lowered) is not None
    has_site = re.search(r"(?m)^\s*(?:site-name|site-url|training|scraping)\s*:", lowered)
    return has_ua and has_site is None


def _parse_ietf(text: str, agent: str, source: str) -> AiPolicy:
    site: Dict[str, str] = {}
    blocks: Dict[str, Dict[str, str]] = {}
    current: Optional[str] = None

    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indented = line[:1].isspace()
        key, _, value = line.strip().partition(":")
        if not _:
            continue
        key = key.strip().lower()
        value = value.strip()

        if key == "agent":
            current = value.lower()
            blocks.setdefault(current, {})
            continue
        if indented and current is not None:
            blocks[current][key] = value
        else:
            current = None
            site[key] = value

    merged = dict(site)
    for name in ("*", agent.split("/", 1)[0].lower(), agent.lower()):
        merged.update(blocks.get(name, {}))

    policy = AiPolicy(
        source=source,
        site_name=merged.get("site-name", ""),
        contact=merged.get("contact", ""),
        policy_url=merged.get("policy-url", ""),
        scraping=_verdict(merged.get("scraping"), POLICY_ALLOW),
        training=_verdict(merged.get("training"), ""),
        indexing=_verdict(merged.get("indexing"), ""),
        caching=_verdict(merged.get("caching"), ""),
        attribution=merged.get("attribution", ""),
        delay_seconds=parse_rate_limit(merged.get("rate-limit")),
        fields=merged,
    )
    # `conditional` scraping carries its own path globs in the same shape as
    # Training-Allow/Deny, so reuse them when present.
    policy.allow = tuple(_globs(merged, ("scraping-allow", "training-allow")))
    policy.disallow = tuple(_globs(merged, ("scraping-deny", "training-deny")))
    return policy


def _parse_robots_shaped(text: str, agent: str, source: str) -> AiPolicy:
    """Spawning-style ai.txt: User-Agent / Disallow / Allow."""
    applies = False
    disallow: List[str] = []
    allow: List[str] = []
    delay = 0.0
    agent_token = agent.split("/", 1)[0].lower()

    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        key, _, value = line.partition(":")
        if not _:
            continue
        key = key.strip().lower()
        value = value.strip()
        if key == "user-agent":
            applies = value == "*" or value.lower() in (agent_token, agent.lower())
        elif applies and key == "disallow" and value:
            disallow.append(value)
        elif applies and key == "allow" and value:
            allow.append(value)
        elif applies and key == "crawl-delay":
            try:
                delay = float(value)
            except ValueError:
                pass

    scraping = POLICY_DENY if "/" in disallow else POLICY_ALLOW
    return AiPolicy(
        source=source,
        scraping=scraping,
        delay_seconds=delay,
        disallow=tuple(disallow),
        allow=tuple(allow),
    )


def parse_rate_limit(value: Optional[str]) -> float:
    """``120/minute`` -> 0.5 seconds between requests. 0 means unspecified."""
    if not value:
        return 0.0
    match = _RATE.search(value)
    if match is None:
        return 0.0
    try:
        count = float(match.group(1))
    except ValueError:
        return 0.0
    if count <= 0:
        return 0.0
    window = _WINDOW_SECONDS.get(match.group(2).lower())
    if window is None:
        return 0.0
    return window / count


def parse_llms_txt(text: str, base_url: str, same_host: bool = True) -> List[str]:
    """Extract the URLs an ``llms.txt`` offers, in document order.

    The `Optional` H2 section is explicitly skippable per the spec; it is kept
    here because a scanner wants the whole surface, not a short context.
    """
    seeds: List[str] = []
    seen: set[str] = set()
    host = urlparse(base_url).netloc

    for match in _MD_LINK.finditer(text):
        target = urldefrag(urljoin(base_url, match.group(2))).url
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https"):
            continue
        if same_host and parsed.netloc != host:
            continue
        if target in seen:
            continue
        seen.add(target)
        seeds.append(target)
    return seeds


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _verdict(value: Optional[str], default: str) -> str:
    if not value:
        return default
    lowered = value.strip().lower()
    if lowered in (POLICY_ALLOW, POLICY_DENY, POLICY_CONDITIONAL):
        return lowered
    if lowered in ("yes", "true", "permitted"):
        return POLICY_ALLOW
    if lowered in ("no", "false", "prohibited"):
        return POLICY_DENY
    return default


def _globs(fields: Dict[str, str], keys: Sequence[str]) -> List[str]:
    out: List[str] = []
    for key in keys:
        value = fields.get(key)
        if value:
            out.extend(part.strip() for part in value.split(",") if part.strip())
    return out


def _glob_match(pattern: str, path: str) -> bool:
    """robots-style prefix match with `*` wildcards and optional `$` anchor."""
    if not pattern:
        return False
    anchored = pattern.endswith("$")
    body = pattern[:-1] if anchored else pattern
    regex = "".join(".*" if part == "*" else re.escape(part) for part in re.split(r"(\*)", body))
    return re.match(regex + ("$" if anchored else ""), path) is not None
