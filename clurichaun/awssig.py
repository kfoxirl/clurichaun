"""AWS Signature Version 4 signing — pure stdlib, no boto3.

Just enough SigV4 to make two read-mostly calls with a discovered access key:
``sts:GetCallerIdentity`` (verify — who is this key) and ``iam:UpdateAccessKey``
(revoke — deactivate it). Implemented from AWS's published algorithm and checked
against AWS's own documented test vector (see the test suite), so a signing bug
cannot silently make every key look invalid.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from urllib.parse import quote

ALGORITHM = "AWS4-HMAC-SHA256"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def signing_key(secret_key: str, date: str, region: str, service: str) -> bytes:
    """Derive the SigV4 signing key (the ``kSigning`` of the AWS docs)."""
    k_date = _hmac(("AWS4" + secret_key).encode("utf-8"), date)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    return _hmac(k_service, "aws4_request")


@dataclass(slots=True)
class SignedRequest:
    url: str
    headers: Dict[str, str]
    body: str


def sign(
    access_key: str,
    secret_key: str,
    region: str,
    service: str,
    body: str,
    host: str,
    session_token: Optional[str] = None,
    method: str = "POST",
    path: str = "/",
    content_type: str = "application/x-www-form-urlencoded; charset=utf-8",
    now: Optional[datetime.datetime] = None,
) -> SignedRequest:
    """Sign a request and return the URL, headers and body ready to send."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    payload_hash = _sha256(body.encode("utf-8"))
    headers: Dict[str, str] = {
        "content-type": content_type,
        "host": host,
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
    }
    if session_token:
        headers["x-amz-security-token"] = session_token

    signed_headers, canonical_headers = _canonical_headers(headers)
    canonical_request = "\n".join(
        [method, path, "", canonical_headers, signed_headers, payload_hash]
    )

    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [ALGORITHM, amz_date, scope, _sha256(canonical_request.encode("utf-8"))]
    )
    signature = hmac.new(
        signing_key(secret_key, date_stamp, region, service),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    authorization = (
        f"{ALGORITHM} Credential={access_key}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    out_headers = dict(headers)
    out_headers["Authorization"] = authorization
    return SignedRequest(url=f"https://{host}{path}", headers=out_headers, body=body)


def _canonical_headers(headers: Dict[str, str]) -> Tuple[str, str]:
    items = sorted((k.lower(), v.strip()) for k, v in headers.items())
    signed = ";".join(k for k, _ in items)
    canonical = "".join(f"{k}:{v}\n" for k, v in items)
    return signed, canonical


def caller_identity_body() -> str:
    return "Action=GetCallerIdentity&Version=2011-06-15"


def update_access_key_body(access_key_id: str, status: str = "Inactive") -> str:
    return (
        "Action=UpdateAccessKey&Version=2010-05-08"
        f"&AccessKeyId={quote(access_key_id)}&Status={quote(status)}"
    )


def split_pair(value: str) -> Optional[Tuple[str, str]]:
    """Split a multi-part ``id:secret`` value into (access_key_id, secret_key)."""
    if ":" not in value:
        return None
    key_id, _, secret = value.partition(":")
    if key_id.startswith(("AKIA", "ASIA", "AGPA", "AIDA", "AROA")) and secret:
        return key_id, secret
    return None
