"""Decoder layer: re-present content with encoded substrings decoded in place.

A secret that survives one layer of encoding is invisible to every regex:
``QUtJQVE3SlozTVBMWEsyTlJUVlc=`` is an AWS key, and ``\\u0041\\u004b\\u0049\\u0041…``
is the same key again. The fix is to build derived copies of the text with those
runs replaced by their plaintext, then run the normal detection passes over each
copy.

Substituting *in place* rather than scanning the decoded fragment alone matters:
rules that need a nearby keyword (``aws_secret_access_key = …``) still see their
context, and byte positions stay roughly aligned with the original.

The technique is one Clurichaun adopts from TruffleHog's ``pkg/decoders``; the
implementation here is our own (TruffleHog is AGPL-3.0, this project is MIT).
"""

from __future__ import annotations

import base64
import binascii
import html
import re
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

DEFAULT_MAX_INPUT = 4 * 1024 * 1024
MIN_B64_RUN = 20
MAX_B64_RUN = 8192

# `=` is padding: it may only trail, never sit inside a run (otherwise
# `KEY_ID=AKIA…` reads as one base64 token and "decodes" to noise).
_B64_RUN = re.compile(rb"[A-Za-z0-9+/_\-]{%d,%d}={0,2}" % (MIN_B64_RUN, MAX_B64_RUN))
_STD_ALPHABET = re.compile(rb"^[A-Za-z0-9+/]+$")
_URL_ALPHABET = re.compile(rb"^[A-Za-z0-9_\-]+$")
_UNICODE_ESCAPE = re.compile(r"\\[uU]00[0-9a-fA-F]{2}")
_HEX_ESCAPE = re.compile(r"\\x[0-9a-fA-F]{2}")
_PERCENT = re.compile(r"%[0-9a-fA-F]{2}")
_ENTITY = re.compile(r"&(?:#x?[0-9a-fA-F]{2,6}|[A-Za-z][A-Za-z0-9]{1,31});")


@dataclass(slots=True)
class Decoded:
    """One derived view of a blob's text."""

    label: str
    text: str


def derive(text: str, max_input: int = DEFAULT_MAX_INPUT) -> List[Decoded]:
    """Return every decoded view that actually differs from the input.

    Order is stable so findings dedupe predictably. Empty list means the text
    carried no recognisable encoding.
    """
    if not text or len(text) > max_input:
        return []

    out: List[Decoded] = []
    for label, decoder in _DECODERS:
        try:
            decoded = decoder(text)
        except (ValueError, UnicodeError, binascii.Error, MemoryError):
            continue
        if decoded and decoded != text:
            out.append(Decoded(label=label, text=decoded))
    return out


# --------------------------------------------------------------------------- #
# Individual decoders
# --------------------------------------------------------------------------- #


def decode_base64(text: str) -> Optional[str]:
    """Replace base64/base64url runs whose plaintext looks like text."""
    if "=" not in text and not _has_long_run(text):
        return None

    raw = text.encode("utf-8", "surrogateescape")
    pieces: List[bytes] = []
    cursor = 0
    substitutions = 0

    for match in _B64_RUN.finditer(raw):
        candidate = match.group(0)
        plain = _try_b64(candidate)
        if plain is None:
            continue
        pieces.append(raw[cursor : match.start()])
        pieces.append(plain)
        cursor = match.end()
        substitutions += 1
        if substitutions > 2000:
            break

    if not substitutions:
        return None
    pieces.append(raw[cursor:])
    return b"".join(pieces).decode("utf-8", "replace")


def _try_b64(candidate: bytes) -> Optional[bytes]:
    """Decode a run only under an alphabet it fully matches, strictly."""
    stripped = candidate.rstrip(b"=")
    if len(stripped) < MIN_B64_RUN:
        return None

    if _STD_ALPHABET.match(stripped):
        token = stripped
    elif _URL_ALPHABET.match(stripped):
        token = stripped.replace(b"-", b"+").replace(b"_", b"/")
    else:
        return None  # mixed alphabets are not base64

    padded = token + b"=" * (-len(token) % 4)
    try:
        plain = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(plain) >= 8 and _mostly_printable(plain):
        return plain
    return None


def decode_unicode_escapes(text: str) -> Optional[str]:
    r"""``A`` / ``\x41`` -> ``A`` (JSON, JS bundles, Java properties)."""
    if "\\u" not in text and "\\U" not in text and "\\x" not in text:
        return None

    def sub(match: re.Match[str]) -> str:
        token = match.group(0)
        try:
            return chr(int(token[-2:], 16))
        except ValueError:  # pragma: no cover - the regex guarantees hex
            return token

    result = _UNICODE_ESCAPE.sub(sub, text)
    result = _HEX_ESCAPE.sub(sub, result)
    return result if result != text else None


def decode_percent(text: str) -> Optional[str]:
    """``%2F`` -> ``/`` (URLs, query strings, Docker labels)."""
    if "%" not in text:
        return None

    def sub(match: re.Match[str]) -> str:
        try:
            return bytes([int(match.group(0)[1:], 16)]).decode("latin-1")
        except ValueError:  # pragma: no cover
            return match.group(0)

    result = _PERCENT.sub(sub, text)
    return result if result != text else None


def decode_entities(text: str) -> Optional[str]:
    """``&amp;`` / ``&#x27;`` -> ``&`` / ``'`` (HTML, XML config, JSP)."""
    if "&" not in text or not _ENTITY.search(text):
        return None
    result = html.unescape(text)
    return result if result != text else None


_DECODERS: Tuple[Tuple[str, Callable[[str], Optional[str]]], ...] = (
    ("base64", decode_base64),
    ("unicode-escape", decode_unicode_escapes),
    ("percent", decode_percent),
    ("html-entity", decode_entities),
)

LABELS: Tuple[str, ...] = tuple(label for label, _ in _DECODERS)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _mostly_printable(payload: bytes, threshold: float = 0.9) -> bool:
    """Decoded bytes are only interesting if they read as text."""
    if not payload:
        return False
    printable = sum(
        1 for byte in payload if 32 <= byte <= 126 or byte in (9, 10, 13)
    )
    return printable / len(payload) >= threshold


def _has_long_run(text: str) -> bool:
    run = 0
    for char in text:
        if char.isalnum() or char in "+/-_":
            run += 1
            if run >= MIN_B64_RUN:
                return True
        else:
            run = 0
    return False
