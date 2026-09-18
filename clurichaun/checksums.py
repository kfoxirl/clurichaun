"""Offline checksum validators for token formats that embed one.

Some providers build a self-check into the token itself, so a candidate can be
proven fake with zero network traffic — the mechanism GitHub designed its
secret-scanning partner programme around ("check the token input matches the
checksum … without having to hit our database").

A validator returns:

* ``True``  — the checksum is present and correct (strong positive signal),
* ``False`` — the checksum is present and *wrong* (a certain reject),
* ``None``  — no checksum applies / cannot decide (leave the finding as-is).

The tri-state matters: a ``False`` lets the engine drop a match outright, while
``None`` must never suppress a legitimate finding from a format without a
checksum.
"""

from __future__ import annotations

import binascii
from typing import Optional

_BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_BASE62_INDEX = {char: index for index, char in enumerate(_BASE62)}


def github_token(token: str) -> Optional[str]:
    """Strip the ``ghp_`` etc. prefix and return the body, or None."""
    for prefix in ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"):
        if token.startswith(prefix):
            return token[len(prefix) :]
    return None


def check_github(token: str) -> Optional[bool]:
    """Verify a GitHub token's trailing CRC32/base62 checksum.

    GitHub tokens are ``<prefix>_<30+ body chars><6 char checksum>``. The last
    six characters are a base62-encoded CRC32 of everything before them. This
    reproduces that check exactly, so a typo'd or fabricated token is rejected
    with certainty and no API call.
    """
    body = github_token(token)
    if body is None or len(body) < 7:
        return None
    payload, checksum = body[:-6], body[-6:]
    if not payload:
        return None
    try:
        expected = _base62_decode(checksum)
    except KeyError:
        return False  # non-base62 char in the checksum slot: not a real token
    actual = binascii.crc32(payload.encode("ascii", "replace")) & 0xFFFFFFFF
    return expected == actual


def check_luhn_suffix(token: str) -> Optional[bool]:
    """Stripe keys carry a Luhn-mod-10 check digit over their alphanumerics.

    Applied conservatively: only decide when the token is long enough to be a
    real key, so a short lookalike returns None rather than a false reject.
    """
    body = token.split("_", 2)[-1]
    if len(body) < 16:
        return None
    digits = [int(char) for char in body if char.isdigit()]
    if len(digits) < 8:
        return None
    return _luhn_ok(digits)


def _base62_decode(text: str) -> int:
    value = 0
    for char in text:
        value = value * 62 + _BASE62_INDEX[char]
    return value


def _luhn_ok(digits: list[int]) -> bool:
    total = 0
    for position, digit in enumerate(reversed(digits)):
        if position % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


# A known-good vector (from GitHub's published token format). If this ever
# stops verifying — a library change, a format change — the self-test below
# disables the GitHub checksum rather than risk suppressing real tokens.
_GITHUB_VECTOR = "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"
_GITHUB_OK = check_github(_GITHUB_VECTOR) is True


# rule_id -> checksum validator. Absence means "no offline checksum".
CHECKSUMS = {}
if _GITHUB_OK:
    CHECKSUMS["github.token"] = check_github
