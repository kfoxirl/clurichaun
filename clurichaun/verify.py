"""Live credential verification.

A pattern match says "this looks like a secret." A verification says "and it
still works." That is the difference between a 1,500-line report and the handful
of findings that are an actual breach, and it is the axis the whole field
competes on.

Each verifier makes a **read-only** request to the provider — never a mutation —
and returns a :class:`~clurichaun.models.Verified` verdict. Verdicts are cached
by ``sha256(secret)`` so a re-scan or a repeated secret costs one request, not N.

This is the one feature that puts credentials on the wire, so it is strictly
opt-in and gated by the caller (see ``cli.scan``'s ``--verify``): off by
default, never run on ``scan-web`` targets, and it announces which providers it
will contact before the first request.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence

from .models import Finding, Verified

DEFAULT_TIMEOUT = 8.0
USER_AGENT = "clurichaun/0.1.0 verifier"

# rule_id -> provider label (a single verifier can serve several rules).
PROVIDERS: Dict[str, str] = {
    "github.token": "github",
    "slack.token": "slack",
    "stripe.secret-key": "stripe",
    "openai.api-key": "openai",
    "gcp.api-key": "gcp",
    "aws.access-key-id": "aws",
}


@dataclass(slots=True)
class VerifyConfig:
    enabled: bool = False
    timeout: float = DEFAULT_TIMEOUT
    min_confidence: float = 0.5
    only: Optional[frozenset] = None  # provider labels to restrict to
    max_requests: int = 2000


@dataclass(slots=True)
class _Result:
    verdict: Verified
    note: str = ""
    access: Optional[Dict[str, object]] = None  # blast radius on ACTIVE


VerifierFn = Callable[[str, "Session", float], _Result]


class Session:
    """Thin wrapper over ``requests`` so tests can inject a fake transport."""

    def __init__(self, timeout: float) -> None:
        import requests  # lazy: only when verification actually runs

        self._session = requests.Session()
        self._session.headers["User-Agent"] = USER_AGENT
        self.timeout = timeout

    def get(self, url: str, **kwargs: object):  # type: ignore[no-untyped-def]
        return self._session.get(url, timeout=self.timeout, **kwargs)

    def post(self, url: str, **kwargs: object):  # type: ignore[no-untyped-def]
        return self._session.post(url, timeout=self.timeout, **kwargs)


# --------------------------------------------------------------------------- #
# Per-provider verifiers (read-only probes)
# --------------------------------------------------------------------------- #


def _active_if(ok: bool, active_note: str, dead_note: str = "provider rejected") -> _Result:
    return _Result(Verified.ACTIVE, active_note) if ok else _Result(Verified.INACTIVE, dead_note)


def verify_github(secret: str, session: Session, timeout: float) -> _Result:
    try:
        resp = session.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {secret}"},
        )
    except Exception as exc:  # noqa: BLE001 - network errors are ERROR, not INACTIVE
        return _Result(Verified.ERROR, f"github: {type(exc).__name__}")
    if resp.status_code == 200:
        login = ""
        try:
            login = resp.json().get("login", "")
        except Exception:  # noqa: BLE001
            pass
        # Blast radius comes free in the response headers — no extra call.
        scopes = _header(resp, "X-OAuth-Scopes")
        access = {
            "identity": login,
            "scopes": [s.strip() for s in scopes.split(",") if s.strip()] if scopes else [],
        }
        rate = _header(resp, "X-RateLimit-Limit")
        if rate:
            access["rate_limit"] = rate
        note = f"github user {login}".strip()
        if access["scopes"]:
            note += f" — scopes: {', '.join(access['scopes'])}"
        return _Result(Verified.ACTIVE, note, access=access)
    if resp.status_code in (401, 403):
        return _Result(Verified.INACTIVE, "github rejected")
    return _Result(Verified.ERROR, f"github http {resp.status_code}")


def _header(resp: object, name: str) -> str:
    headers = getattr(resp, "headers", None)
    if headers is None:
        return ""
    try:
        return headers.get(name, "") or ""
    except Exception:  # noqa: BLE001
        return ""


def verify_slack(secret: str, session: Session, timeout: float) -> _Result:
    try:
        resp = session.post(
            "https://slack.com/api/auth.test",
            headers={"Authorization": f"Bearer {secret}"},
        )
        body = resp.json()
        ok = bool(body.get("ok"))
    except Exception as exc:  # noqa: BLE001
        return _Result(Verified.ERROR, f"slack: {type(exc).__name__}")
    if not ok:
        return _Result(Verified.INACTIVE, "slack rejected")
    access = {
        "identity": body.get("user", ""),
        "team": body.get("team", ""),
        "scopes": [s.strip() for s in _header(resp, "X-OAuth-Scopes").split(",") if s.strip()],
    }
    note = f"slack {access['identity']}@{access['team']}".strip("@")
    return _Result(Verified.ACTIVE, note, access=access)


def verify_stripe(secret: str, session: Session, timeout: float) -> _Result:
    try:
        resp = session.get("https://api.stripe.com/v1/account", auth=(secret, ""))
    except Exception as exc:  # noqa: BLE001
        return _Result(Verified.ERROR, f"stripe: {type(exc).__name__}")
    if resp.status_code == 200:
        return _Result(Verified.ACTIVE, "stripe account reachable")
    if resp.status_code in (401, 403):
        return _Result(Verified.INACTIVE, "stripe rejected")
    return _Result(Verified.ERROR, f"stripe http {resp.status_code}")


def verify_openai(secret: str, session: Session, timeout: float) -> _Result:
    try:
        resp = session.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {secret}"},
        )
    except Exception as exc:  # noqa: BLE001
        return _Result(Verified.ERROR, f"openai: {type(exc).__name__}")
    if resp.status_code == 200:
        return _Result(Verified.ACTIVE, "openai models reachable")
    if resp.status_code in (401, 403):
        return _Result(Verified.INACTIVE, "openai rejected")
    return _Result(Verified.ERROR, f"openai http {resp.status_code}")


def verify_aws(secret: str, session: Session, timeout: float) -> _Result:
    """sts:GetCallerIdentity, SigV4-signed. ``secret`` is ``AKIA…:secretkey``.

    A 200 returns the caller's ARN and account — the identity *is* the blast
    radius, so it doubles as access mapping. An ``InvalidClientTokenId`` /
    ``SignatureDoesNotMatch`` 403 means the key does not work.
    """
    from . import awssig

    pair = awssig.split_pair(secret)
    if pair is None:
        return _Result(Verified.UNSUPPORTED, "aws: no id:secret pair (needs both keys)")
    access_key, secret_key = pair
    signed = awssig.sign(
        access_key=access_key,
        secret_key=secret_key,
        region="us-east-1",
        service="sts",
        body=awssig.caller_identity_body(),
        host="sts.amazonaws.com",
    )
    try:
        resp = session.post(signed.url, data=signed.body, headers=signed.headers)
    except Exception as exc:  # noqa: BLE001
        return _Result(Verified.ERROR, f"aws: {type(exc).__name__}")
    text = getattr(resp, "text", "") or ""
    if resp.status_code == 200:
        arn = _between(text, "<Arn>", "</Arn>")
        account = _between(text, "<Account>", "</Account>")
        access = {"identity": arn, "account": account, "scopes": []}
        return _Result(Verified.ACTIVE, f"aws {arn}".strip(), access=access)
    if resp.status_code in (401, 403):
        return _Result(Verified.INACTIVE, "aws rejected the key")
    return _Result(Verified.ERROR, f"aws http {resp.status_code}")


def _between(text: str, start: str, end: str) -> str:
    i = text.find(start)
    if i == -1:
        return ""
    j = text.find(end, i + len(start))
    return text[i + len(start) : j] if j != -1 else ""


VERIFIERS: Dict[str, VerifierFn] = {
    "github": verify_github,
    "slack": verify_slack,
    "stripe": verify_stripe,
    "openai": verify_openai,
    "aws": verify_aws,
}


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


class Verifier:
    def __init__(
        self,
        config: VerifyConfig,
        session: Optional[Session] = None,
        verifiers: Optional[Dict[str, VerifierFn]] = None,
    ) -> None:
        self.config = config
        self._verifiers = verifiers if verifiers is not None else VERIFIERS
        self._session = session
        self._cache: Dict[str, _Result] = {}
        self._requests = 0

    def providers_for(self, findings: Sequence[Finding]) -> List[str]:
        """Distinct provider labels that would actually be contacted."""
        wanted: set[str] = set()
        for finding in findings:
            provider = PROVIDERS.get(finding.rule_id)
            if provider and provider in self._verifiers and self._eligible(finding):
                if self.config.only is None or provider in self.config.only:
                    wanted.add(provider)
        return sorted(wanted)

    def run(self, findings: Sequence[Finding]) -> None:
        """Verify eligible findings in place, setting ``verified`` + note."""
        if not self.config.enabled:
            return
        session = self._session or Session(self.config.timeout)
        for finding in findings:
            provider = PROVIDERS.get(finding.rule_id)
            if provider is None:
                continue
            if not self._eligible(finding):
                continue
            if self.config.only is not None and provider not in self.config.only:
                continue
            verifier = self._verifiers.get(provider)
            if verifier is None:
                finding.verified = Verified.UNSUPPORTED
                continue
            secret = finding.secret_v2 or finding.secret
            result = self._verify_cached(provider, secret, session, verifier)
            finding.verified = result.verdict
            finding.verification_note = result.note or None
            if result.access:
                finding.access = dict(result.access)

    def _eligible(self, finding: Finding) -> bool:
        return finding.confidence >= self.config.min_confidence

    def _verify_cached(
        self, provider: str, secret: str, session: Session, verifier: VerifierFn
    ) -> _Result:
        key = hashlib.sha256(f"{provider}\0{secret}".encode()).hexdigest()
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        if self._requests >= self.config.max_requests:
            return _Result(Verified.ERROR, "request budget exhausted")
        self._requests += 1
        result = verifier(secret, session, self.config.timeout)
        self._cache[key] = result
        return result
