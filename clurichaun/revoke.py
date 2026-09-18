"""Defender-led credential revocation.

Detection and verification tell you a leak is real; revocation lets you *contain*
it from the CLI, the way Kingfisher's ``revoke`` does. This is the only part of
Clurichaun that **mutates** anything at a provider, so it is fenced hard:

* **Dry-run by default.** ``plan()`` shows exactly what would be revoked and how;
  nothing happens until ``execute()`` is called with explicit confirmation.
* **Verified-ACTIVE only.** A credential is never revoked on a pattern match
  alone — only when live verification confirmed it works. Revoking on a guess
  could disable an innocent third party's key.
* **Per-provider honesty.** Where a provider offers no self-service revocation
  API, the plan says so and points at the console, rather than pretending.

Only providers with a *token-self-revoke* endpoint are automated. Slack tokens
can revoke themselves (``auth.revoke``); GitHub/AWS/Stripe require the owning
app, IAM, or dashboard, so they are reported as manual with the right URL.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from .models import Finding, Verified

# Providers with a working token-self-revoke API. Everything else is manual.
_MANUAL: Dict[str, str] = {
    "github": "Delete the token at https://github.com/settings/tokens",
    "stripe": "Roll the key at https://dashboard.stripe.com/apikeys",
    "openai": "Revoke at https://platform.openai.com/api-keys",
    "gcp": "Disable at https://console.cloud.google.com/apis/credentials",
}


@dataclass(slots=True)
class RevokePlan:
    finding: Finding
    provider: str
    automated: bool
    detail: str  # what will happen, or the manual instruction


@dataclass(slots=True)
class RevokeResult:
    finding: Finding
    provider: str
    ok: bool
    detail: str


class Revoker:
    def __init__(
        self,
        session=None,  # type: ignore[no-untyped-def]
        revokers: Optional[Dict[str, Callable]] = None,  # type: ignore[type-arg]
    ) -> None:
        self._session = session
        self._revokers = revokers if revokers is not None else _REVOKERS

    def plan(self, findings: List[Finding]) -> List[RevokePlan]:
        """What revocation would do — the dry-run. Verified-ACTIVE only."""
        plans: List[RevokePlan] = []
        for finding in findings:
            if finding.verified is not Verified.ACTIVE:
                continue
            from .verify import PROVIDERS

            provider = PROVIDERS.get(finding.rule_id)
            if provider is None:
                continue
            if provider in self._revokers:
                plans.append(
                    RevokePlan(finding, provider, True,
                               f"revoke via {provider} self-revoke API")
                )
            else:
                plans.append(
                    RevokePlan(finding, provider, False,
                               _MANUAL.get(provider, "manual revocation required"))
                )
        return plans

    def execute(self, plans: List[RevokePlan]) -> List[RevokeResult]:
        """Actually revoke the automated plans. Call only after confirmation."""
        session = self._session or _make_session()
        results: List[RevokeResult] = []
        for plan in plans:
            if not plan.automated:
                results.append(RevokeResult(plan.finding, plan.provider, False, plan.detail))
                continue
            revoker = self._revokers[plan.provider]
            secret = plan.finding.secret_v2 or plan.finding.secret
            try:
                ok, detail = revoker(secret, session)
            except Exception as exc:  # noqa: BLE001 - never crash on a provider error
                ok, detail = False, f"{type(exc).__name__}: {exc}"
            results.append(RevokeResult(plan.finding, plan.provider, ok, detail))
        return results


# --------------------------------------------------------------------------- #
# Per-provider revokers (only self-revoke endpoints)
# --------------------------------------------------------------------------- #


def revoke_slack(secret: str, session) -> tuple[bool, str]:  # type: ignore[no-untyped-def]
    resp = session.post(
        "https://slack.com/api/auth.revoke",
        headers={"Authorization": f"Bearer {secret}"},
    )
    ok = bool(resp.json().get("revoked"))
    return ok, "slack token revoked" if ok else "slack revoke failed"


def revoke_aws(secret: str, session) -> tuple[bool, str]:  # type: ignore[no-untyped-def]
    """iam:UpdateAccessKey Status=Inactive, SigV4-signed. Needs id:secret.

    Often the key lacks ``iam:UpdateAccessKey`` on itself, so AccessDenied is a
    common and honest outcome — reported, not hidden.
    """
    from . import awssig

    pair = awssig.split_pair(secret)
    if pair is None:
        return False, "aws: no id:secret pair to revoke"
    access_key, secret_key = pair
    signed = awssig.sign(
        access_key=access_key,
        secret_key=secret_key,
        region="us-east-1",
        service="iam",
        body=awssig.update_access_key_body(access_key, "Inactive"),
        host="iam.amazonaws.com",
    )
    resp = session.post(signed.url, data=signed.body, headers=signed.headers)
    if resp.status_code == 200:
        return True, "aws access key set Inactive"
    text = getattr(resp, "text", "") or ""
    reason = "AccessDenied" if "AccessDenied" in text else f"http {resp.status_code}"
    return False, f"aws revoke failed: {reason}"


_REVOKERS: Dict[str, Callable] = {  # type: ignore[type-arg]
    "slack": revoke_slack,
    "aws": revoke_aws,
}


def _make_session():  # type: ignore[no-untyped-def]
    from .verify import Session

    return Session(timeout=10.0)
