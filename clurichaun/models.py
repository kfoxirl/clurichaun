"""Core data types shared by every stage of the pipeline."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: Dict["Severity", int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class Detector(str, Enum):
    REGEX = "regex"
    ENTROPY = "entropy"
    KEYNAME = "keyname"


@dataclass(slots=True)
class Blob:
    """A decoded (or raw) unit of content handed to the detector.

    ``logical_path`` is the display path: for content nested inside archives it
    carries the container chain, e.g. ``dist/app.zip!/config/prod.env``.
    """

    logical_path: str
    source_path: str
    text: str
    is_binary: bool = False
    media_type: str = "text/plain"
    line_offset: int = 0
    byte_offset: int = 0
    container_depth: int = 0
    # Findings on lines below this (1-based, within this blob's text) belong to
    # the previous streamed chunk's overlap and must be dropped, so a secret in
    # the overlap window is reported exactly once. 0 means "own every line".
    commit_line: int = 0

    @property
    def size(self) -> int:
        return len(self.text)


_ACTIONABILITY_RANK: Dict[str, int] = {
    "verified-active": 4,
    "checksum-valid": 3,
    "high-confidence": 2,
    "candidate": 1,
    "verified-inactive": 0,
}


class Verified(str, Enum):
    """Live-verification verdict for a finding (see clurichaun.verify)."""

    UNKNOWN = "unknown"      # not checked
    ACTIVE = "active"        # the credential works right now
    INACTIVE = "inactive"    # the provider rejected it
    ERROR = "error"          # the check itself failed (timeout, no network)
    UNSUPPORTED = "unsupported"  # no verifier for this rule


@dataclass(slots=True)
class GitContext:
    """Provenance for a finding recovered from git history."""

    commit: str = ""
    author: str = ""
    email: str = ""
    date: str = ""
    message: str = ""


@dataclass(slots=True)
class Finding:
    rule_id: str
    title: str
    detector: Detector
    severity: Severity
    logical_path: str
    source_path: str
    line: int
    column: int
    secret: str
    match_context: str
    confidence: float = 0.5
    entropy: Optional[float] = None
    key_name: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    media_type: str = "text/plain"
    # For multi-part credentials (AWS id+secret, basic-auth user:pass) this is
    # the combined identifier used for identity — see gitleaks/TruffleHog RawV2.
    # When unset the fingerprint keys on ``secret`` alone.
    secret_v2: Optional[str] = None
    verified: Verified = Verified.UNKNOWN
    verification_note: Optional[str] = None
    git: Optional[GitContext] = None
    # Blast radius of a verified credential: identity + scopes it grants. Set by
    # the verifier on an ACTIVE verdict — "live" vs "live and can assume admin".
    access: Optional[Dict[str, Any]] = None
    # When a finding is reconstructed from the datastore (carried forward from a
    # prior scan of an unchanged file), its original fingerprint is preserved
    # here — the stored `secret` is redacted, so the computed one would differ.
    stored_fingerprint: Optional[str] = None
    carried: bool = False  # loaded from the datastore, not scanned this run

    @property
    def identity_value(self) -> str:
        """What the fingerprint keys on: the multi-part value, else the secret."""
        return self.secret_v2 if self.secret_v2 else self.secret

    @property
    def actionability(self) -> str:
        """A single triage axis folding in verification and checksum evidence.

        ``verified-active`` (act now) > ``checksum-valid`` (well-formed real
        token) > ``high-confidence`` > ``candidate``. ``verified-inactive`` is
        demoted below candidate: the credential provably does not work.
        """
        if self.verified is Verified.ACTIVE:
            return "verified-active"
        if self.verified is Verified.INACTIVE:
            return "verified-inactive"
        if any("checksum verified" in note for note in self.notes):
            return "checksum-valid"
        if self.confidence >= 0.85:
            return "high-confidence"
        return "candidate"

    @property
    def actionability_rank(self) -> int:
        return _ACTIONABILITY_RANK.get(self.actionability, 0)

    @property
    def fingerprint(self) -> str:
        """Stable identity for dedup and baseline suppression.

        Keyed on the *content* identity (rule + logical path + the multi-part
        value where one exists), never on line number, so a finding survives
        code moving around it. For a multi-part credential the value carries
        both the id and the secret, so rotating the secret under a reused id
        produces a distinct fingerprint — the rotation is not silently deduped.
        """
        if self.stored_fingerprint:
            return self.stored_fingerprint
        raw = f"{self.rule_id}\0{self.logical_path}\0{self.identity_value}"
        return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:32]

    def redacted(self) -> str:
        return redact(self.secret)

    @classmethod
    def from_stored(cls, data: Dict[str, Any]) -> "Finding":
        """Rebuild a (display-only, already-redacted) finding from stored JSON.

        Used to carry a finding forward from the datastore when its file was
        unchanged since the last scan. The secret is already redacted, so the
        original fingerprint is preserved via ``stored_fingerprint``.
        """
        git = None
        if data.get("git"):
            g = data["git"]
            git = GitContext(
                commit=g.get("commit", ""), author=g.get("author", ""),
                email=g.get("email", ""), date=g.get("date", ""),
                message=g.get("message", ""),
            )
        try:
            verified = Verified(data.get("verified", "unknown"))
        except ValueError:
            verified = Verified.UNKNOWN
        return cls(
            rule_id=data.get("rule_id", ""),
            title=data.get("title", ""),
            detector=Detector(data.get("detector", "regex")),
            severity=Severity(data.get("severity", "info")),
            logical_path=data.get("logical_path", ""),
            source_path=data.get("source_path", ""),
            line=int(data.get("line", 0)),
            column=int(data.get("column", 1)),
            secret=data.get("secret", ""),
            match_context=data.get("match_context", ""),
            confidence=float(data.get("confidence", 0.5)),
            entropy=data.get("entropy"),
            key_name=data.get("key_name"),
            notes=list(data.get("notes", [])),
            media_type=data.get("media_type", "text/plain"),
            secret_v2=data.get("secret_v2"),
            verified=verified,
            verification_note=data.get("verification_note"),
            git=git,
            access=data.get("access"),
            stored_fingerprint=data.get("fingerprint"),
            carried=True,
        )

    def to_dict(self, unredact: bool = False) -> Dict[str, Any]:
        data = asdict(self)
        data["detector"] = self.detector.value
        data["severity"] = self.severity.value
        data["verified"] = self.verified.value
        data["actionability"] = self.actionability
        data["fingerprint"] = self.fingerprint
        data["secret"] = self.secret if unredact else self.redacted()
        if self.secret_v2 and not unredact:
            data["secret_v2"] = scrub(self.secret_v2, [self.secret, self.secret_v2])
        if not unredact:
            secrets = [self.secret]
            if self.secret_v2:
                secrets.append(self.secret_v2)
            data["match_context"] = scrub(self.match_context, secrets)
        return data


def redact(secret: str, keep: int = 4) -> str:
    """``AKIAIOSFODNN7EXAMPLE`` -> ``AKIA...MPLE``."""
    stripped = secret.strip()
    if len(stripped) <= keep * 2 + 3:
        return "*" * len(stripped)
    return f"{stripped[:keep]}...{stripped[-keep:]}"


def _redact_within(context: str, secret: str) -> str:
    return scrub(context, [secret])


def scrub(text: str, secrets: Iterable[str]) -> str:
    """Replace every known secret value inside ``text`` with its redaction.

    Applied across the whole finding set, not just a finding's own secret: two
    secrets on one line would otherwise leak through each other's context.
    """
    for secret in sorted({s.strip() for s in secrets if s and s.strip()}, key=len, reverse=True):
        if len(secret) < 8:
            continue
        if secret in text:
            text = text.replace(secret, redact(secret))
    return text


@dataclass(slots=True)
class ScanStats:
    files_seen: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    archives_opened: int = 0
    bytes_scanned: int = 0
    errors: List[str] = field(default_factory=list)

    def merge(self, other: "ScanStats") -> None:
        self.files_seen += other.files_seen
        self.files_scanned += other.files_scanned
        self.files_skipped += other.files_skipped
        self.archives_opened += other.archives_opened
        self.bytes_scanned += other.bytes_scanned
        self.errors.extend(other.errors)


@dataclass(slots=True)
class FileResult:
    """What one worker returns for one filesystem path."""

    path: str
    findings: List[Finding] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    blob_hash: Optional[str] = None   # content hash, for incremental scanning
    mtime: float = 0.0
    size: int = 0
    unchanged: bool = False           # hash matched the previous scan -> skipped


def dedupe(findings: Iterable[Finding]) -> List[Finding]:
    seen: set[str] = set()
    out: List[Finding] = []
    for finding in findings:
        fp = finding.fingerprint
        if fp in seen:
            continue
        seen.add(fp)
        out.append(finding)
    return out
