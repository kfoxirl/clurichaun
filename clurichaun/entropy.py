"""Shannon-entropy candidate scoring with structural false-positive filters."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Iterator, Optional

B64_CHARSET = re.compile(r"^[A-Za-z0-9+/=_\-]+$")
HEX_CHARSET = re.compile(r"^[A-Fa-f0-9]+$")

# Candidate tokenisers: long unbroken runs that could carry a secret.
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{20,120}")
_HEX_TOKEN = re.compile(r"\b[A-Fa-f0-9]{32,128}\b")

_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")
_ALL_DIGITS = re.compile(r"^[0-9._\-]+$")
_DATEISH = re.compile(r"^\d{4}[-_]?\d{2}[-_]?\d{2}")
_SNAKE_WORDS = re.compile(r"^[a-z0-9]{1,32}(?:[_\-][a-z0-9]{1,32}){2,8}$")
_PATHISH = re.compile(r"[/\\]{1}[A-Za-z0-9_.\-]+[/\\]")
_MIME_OR_CSS = re.compile(r"(?i)^(?:data:|#[0-9a-f]{3,8}$|rgba?\()")

# Lines whose surrounding context makes a high-entropy blob boring.
_SAFE_CONTEXT = re.compile(
    r"(?i)(?:integrity\s*[=:]|sha(?:1|256|384|512)[-:]|md5|checksum|etag|"
    r"\bdigest\b|content-hash|resolved\s*[\"']?https|\"version\"|sourcemappingurl|"
    r"\bcommit\b|\brevision\b|\bhash\b|\bfingerprint\b|base64,|font-face|"
    r"cache[-_]?key|bundle[-_]?id|build[-_]?id)"
)

_SECRETISH_KEY = re.compile(
    r"(?i)(?:secret|token|key|passwd|password|passphrase|credential|auth|"
    r"signature|sig|private|session|cookie|salt|seed|dsn)"
)

# Minified JS / lockfiles are entropy minefields; require more evidence there.
_NOISY_SUFFIXES = (
    ".min.js",
    ".bundle.js",
    ".map",
    ".lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "composer.lock",
    "cargo.lock",
    "go.sum",
)


@dataclass(slots=True)
class EntropyCandidate:
    value: str
    start: int
    end: int
    entropy: float
    charset: str
    confidence: float


def shannon(data: str) -> float:
    """Bits of entropy per character."""
    if not data:
        return 0.0
    length = len(data)
    counts: dict[str, int] = {}
    for char in data:
        counts[char] = counts.get(char, 0) + 1
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _charset_of(token: str) -> Optional[str]:
    if HEX_CHARSET.match(token):
        return "hex"
    if B64_CHARSET.match(token):
        return "base64"
    return None


def looks_like_words(token: str) -> bool:
    """``getUserProfileData`` / ``connectionstring`` -> True; a key blob -> False.

    Written procedurally on purpose: the obvious regex for this
    (``^(?:[A-Z]?[a-z]{3,}){2,}$``) backtracks catastrophically on the long
    lowercase runs that binaries are full of.
    """
    if not token.isalpha():
        return False
    segments: list[str] = []
    current = token[0]
    for char in token[1:]:
        if char.isupper():
            segments.append(current)
            current = char
        else:
            current += char
    segments.append(current)
    if len(segments) >= 2 and all(len(part) >= 3 for part in segments):
        return True
    # A single all-lowercase alphabetic run carries no secret either.
    return len(segments) == 1 and token.islower()


def is_structural_noise(token: str) -> bool:
    """True when the token's *shape* explains its entropy."""
    if _UUID.match(token) or _GIT_SHA.match(token):
        return True
    if _ALL_DIGITS.match(token) or _DATEISH.match(token):
        return True
    if looks_like_words(token) or _SNAKE_WORDS.match(token):
        return True
    if _PATHISH.search(token) or _MIME_OR_CSS.match(token):
        return True
    # A single repeated or near-repeated character class carries no secret.
    if len(set(token)) <= max(4, len(token) // 8):
        return True
    return False


def _threshold(charset: str, noisy: bool) -> float:
    if charset == "hex":
        return 3.6 if noisy else 3.2
    return 4.8 if noisy else 4.3


def iter_candidates(
    text: str,
    logical_path: str = "",
    min_confidence: float = 0.0,
) -> Iterator[EntropyCandidate]:
    """Yield high-entropy tokens that survive the structural filters."""
    lowered = logical_path.lower()
    noisy = lowered.endswith(_NOISY_SUFFIXES) or "/node_modules/" in lowered

    for tokenizer in (_B64_TOKEN, _HEX_TOKEN):
        for match in tokenizer.finditer(text):
            token = match.group(0).strip("=-_")
            if len(token) < 20:
                continue
            charset = _charset_of(token)
            if charset is None or is_structural_noise(token):
                continue

            score = shannon(token)
            if score < _threshold(charset, noisy):
                continue

            line = _line_around(text, match.start())
            if _SAFE_CONTEXT.search(line):
                continue

            confidence = _confidence(score, charset, token, line, noisy)
            if confidence < min_confidence:
                continue

            yield EntropyCandidate(
                value=token,
                start=match.start(),
                end=match.end(),
                entropy=round(score, 3),
                charset=charset,
                confidence=round(confidence, 3),
            )


def _confidence(
    score: float, charset: str, token: str, line: str, noisy: bool
) -> float:
    base = 0.45 if charset == "base64" else 0.35
    base += min(0.25, max(0.0, (score - _threshold(charset, noisy)) * 0.25))
    if _SECRETISH_KEY.search(line):
        base += 0.25
    if len(token) >= 40:
        base += 0.05
    if noisy:
        base -= 0.15
    return max(0.05, min(0.95, base))


def _line_around(text: str, index: int, window: int = 160) -> str:
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    if end == -1:
        end = len(text)
    line = text[start:end]
    if len(line) <= window * 2:
        return line
    local = index - start
    return line[max(0, local - window) : local + window]
