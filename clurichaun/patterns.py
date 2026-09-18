"""High-confidence credential patterns.

Each rule owns a compiled regex, a severity, a base confidence and an optional
validator that inspects the captured candidate (and its surrounding line) to
kill structural false positives before the finding ever reaches the report.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Pattern, Tuple

from .checksums import CHECKSUMS
from .models import Severity
from .stopwords import contains_stopword

Validator = Callable[[str, str], bool]
"""(candidate, containing_line) -> keep?"""


@dataclass(slots=True)
class Rule:
    rule_id: str
    title: str
    regex: Pattern[str]
    severity: Severity
    confidence: float = 0.9
    group: int = 0
    validator: Optional[Validator] = None
    tags: List[str] = field(default_factory=list)
    min_entropy: float = 0.0
    """Minimum Shannon entropy of the captured value, per gitleaks' `entropy` key."""
    allow_regexes: Tuple[Pattern[str], ...] = ()
    """If any matches the captured value, the finding is dropped."""
    use_stopwords: bool = False
    """Drop the finding when the value contains a known stopword."""
    prefilter: Tuple[str, ...] = ()
    """Lowercase literals; the regex only runs if one appears in the text.

    This is the difference between 40 full regex passes over a 30MB carved
    binary and two. Empty means "always run" (used by the IP/URL rules, whose
    patterns have no literal anchor).
    """

    path_regex: Optional[Pattern[str]] = None
    """When set, the rule only applies to logical paths this matches."""
    deny_paths: Tuple[Pattern[str], ...] = ()
    """Logical paths on which this rule is suppressed."""
    checksum: Optional[Callable[[str], Optional[bool]]] = None
    """Offline self-check on the whole token. A ``False`` verdict drops the
    match with certainty; ``None`` decides nothing. See clurichaun.checksums."""

    def candidate(self, match: re.Match[str]) -> str:
        return self.pick(match)[0]

    def pick(self, match: re.Match[str]) -> Tuple[str, int]:
        """Return (secret, start offset) for a match.

        ``group`` semantics follow gitleaks' ``secretGroup``: a positive value
        names the group; ``-1`` means "the first non-empty capture group",
        which is what its rules rely on when they omit ``secretGroup``; ``0``
        means the whole match.
        """
        if self.group > 0:
            try:
                value = match.group(self.group)
            except (IndexError, re.error):  # pragma: no cover - defensive
                value = None
            if value:
                return value, match.start(self.group)
        elif self.group < 0:
            for index in range(1, (match.re.groups or 0) + 1):
                value = match.group(index)
                if value:
                    return value, match.start(index)
        return match.group(0), match.start()

    def applies_to(self, logical_path: str) -> bool:
        if self.path_regex is not None and not self.path_regex.search(logical_path):
            return False
        return not any(denied.search(logical_path) for denied in self.deny_paths)


def _r(pattern: str, flags: int = 0) -> Pattern[str]:
    return re.compile(pattern, flags)


def assignment(keywords: str, capture: str) -> str:
    """Build an assignment-proximity pattern: `<key> <op> <value>`.

    Ported from the shape gitleaks uses for its keyword-anchored rules
    (MIT, Copyright (c) 2019 Zachary Rice — see NOTICE.md). It tolerates every
    assignment operator in common use (`=`, `:`, `=>`, `:=`, `||`, `?=`, `,`),
    optional quoting on either side, and a bounded amount of prefix noise, which
    is what makes one pattern work across YAML, JSON, INI, shell, Java
    properties, JS and Go source.
    """
    return (
        r"(?i)[\w.-]{0,50}?(?:" + keywords + r")(?:[ \t\w.-]{0,20})[\s'\"]{0,3}"
        r"(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}"
        r"(" + capture + r")(?:[\x60'\"\s;]|\\[nr]|$)"
    )


# --------------------------------------------------------------------------- #
# Validators
# --------------------------------------------------------------------------- #

_PLACEHOLDER_RE = _r(
    r"(?:example|sample|dummy|placeholder|changeme|change_me|your[-_ ]?(?:key|token|secret)"
    r"|xxx+|fake|redact|test[-_]?key|insert[-_]?here|<[^>]+>|\$\{[^}]+\}|%\([^)]+\)s)",
    re.IGNORECASE,
)


def not_placeholder(candidate: str, line: str) -> bool:
    return not _PLACEHOLDER_RE.search(candidate)


def valid_jwt(candidate: str, line: str) -> bool:
    parts = candidate.split(".")
    if len(parts) != 3:
        return False
    header = _b64url(parts[0])
    if header is None:
        return False
    try:
        decoded = json.loads(header)
    except (ValueError, UnicodeDecodeError):
        return False
    return isinstance(decoded, dict) and "alg" in decoded


def valid_b64(candidate: str, line: str) -> bool:
    return _b64(candidate) is not None


def _b64url(chunk: str) -> Optional[str]:
    pad = "=" * (-len(chunk) % 4)
    try:
        return base64.urlsafe_b64decode(chunk + pad).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


def _b64(chunk: str) -> Optional[bytes]:
    pad = "=" * (-len(chunk) % 4)
    try:
        return base64.b64decode(chunk + pad, validate=True)
    except (binascii.Error, ValueError):
        return None


_URI_CREDS = _r(r"://([^:/\s]*):([^@\s]*)@")


def no_local_host(candidate: str, line: str) -> bool:
    """Keep only URIs that carry a real-looking password.

    The placeholder check applies to the credential pair alone — hostnames like
    ``db.prod.example.com`` must not disqualify a live password.
    """
    match = _URI_CREDS.search(candidate)
    if match is None:
        return False
    user, password = match.group(1), match.group(2)
    if not password:
        return False
    return not (_PLACEHOLDER_RE.search(password) or _PLACEHOLDER_RE.fullmatch(user))


def private_ipv4(candidate: str, line: str) -> bool:
    octets = candidate.split(".")
    if len(octets) != 4:
        return False
    try:
        nums = [int(part) for part in octets]
    except ValueError:
        return False
    if any(num > 255 for num in nums):
        return False
    if nums[0] == 10:
        return True
    if nums[0] == 172 and 16 <= nums[1] <= 31:
        return True
    if nums[0] == 192 and nums[1] == 168:
        return True
    return False


def public_ipv4(candidate: str, line: str) -> bool:
    octets = candidate.split(".")
    if len(octets) != 4:
        return False
    try:
        nums = [int(part) for part in octets]
    except ValueError:
        return False
    if any(num > 255 for num in nums):
        return False
    if nums[0] in (0, 10, 127) or nums == [255, 255, 255, 255]:
        return False
    if nums[0] == 172 and 16 <= nums[1] <= 31:
        return False
    if nums[0] == 192 and nums[1] == 168:
        return False
    if nums[0] == 169 and nums[1] == 254:
        return False
    if nums[0] >= 224:
        return False
    return True


# Key names that look like secrets but never are: `api_version`, `primary_key`,
# `csrf_token`, `monkey`, `turkey`. Ported from the `generic-api-key` rule's
# allowlist in gitleaks' default config (MIT, (c) 2019 Zachary Rice, NOTICE.md).
GENERIC_KEY_ALLOWLIST = r"""(?i)(?:access(?:ibility|or)|access[_.-]?id|random[_.-]?access|api[_.-]?(?:id|name|version)|rapid|capital|[a-z0-9-]*?api[a-z0-9-]*?:jar:|author|X-MS-Exchange-Organization-Auth|Authentication-Results|(?:credentials?[_.-]?id|withCredentials)|(?:bucket|foreign|hot|idx|natural|primary|pub(?:lic)?|schema|sequence)[_.-]?key|(?:turkey)|key[_.-]?(?:alias|board|code|frame|id|length|mesh|name|pair|press(?:ed)?|ring|selector|signature|size|stone|storetype|word|up|down|left|right)|key[_.-]?vault[_.-]?(?:id|name)|keyVaultToStoreSecrets|key(?:store|tab)[_.-]?(?:file|path)|issuerkeyhash|(?-i:[DdMm]onkey|[DM]ONKEY)|keying|(?:secret)[_.-]?(?:length|name|size)|UserSecretsId|(?:csrf)[_.-]?token|(?:io\.jsonwebtoken[ \t]?:[ \t]?[\w-]+)|(?:api|credentials|token)[_.-]?(?:endpoint|ur[il])|public[_.-]?token|(?:key|token)[_.-]?file|(?-i:(?:[A-Z_]+=\n[A-Z_]+=|[a-z_]+=\n[a-z_]+=)(?:\n|\z))|(?-i:(?:[A-Z.]+=\n[A-Z.]+=|[a-z.]+=\n[a-z.]+=)(?:\n|\z)))"""


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

_AWS: List[Rule] = [
    Rule(
        "aws.access-key-id",
        "AWS access key ID",
        _r(r"\b((?:A3T[A-Z0-9]|AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b"),
        Severity.CRITICAL,
        0.95,
        group=1,
        validator=not_placeholder,
        tags=["aws"],
    ),
    Rule(
        "aws.secret-access-key",
        "AWS secret access key",
        _r(
            r"(?i)aws[_\- ]?(?:secret|sec)[_\- ]?(?:access)?[_\- ]?key\w*"
            r"\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?"
        ),
        Severity.CRITICAL,
        0.92,
        group=1,
        validator=not_placeholder,
        tags=["aws"],
    ),
    Rule(
        "aws.session-token",
        "AWS session token",
        _r(
            r"(?i)aws[_\- ]?session[_\- ]?token\s*[:=]\s*[\"']?"
            r"([A-Za-z0-9/+=]{100,})[\"']?"
        ),
        Severity.HIGH,
        0.9,
        group=1,
        tags=["aws"],
    ),
]

_AZURE: List[Rule] = [
    Rule(
        "azure.storage-connection-string",
        "Azure storage connection string",
        _r(
            r"DefaultEndpointsProtocol=https?;AccountName=[A-Za-z0-9]+;"
            r"AccountKey=([A-Za-z0-9+/=]{60,120})"
        ),
        Severity.CRITICAL,
        0.95,
        group=1,
        tags=["azure"],
    ),
    Rule(
        "azure.servicebus-sas",
        "Azure Service Bus / Event Hub SAS key",
        _r(
            r"Endpoint=sb://[^;]+;SharedAccessKeyName=[^;]+;SharedAccessKey="
            r"([A-Za-z0-9+/=]{40,})"
        ),
        Severity.CRITICAL,
        0.95,
        group=1,
        tags=["azure"],
    ),
    Rule(
        "azure.client-secret",
        "Azure AD client secret",
        _r(
            r"(?i)(?:client[_\-]?secret|azure[_\-]?secret)\w*\s*[:=]\s*[\"']?"
            r"([A-Za-z0-9~._\-]{32,48})[\"']?"
        ),
        Severity.CRITICAL,
        0.8,
        group=1,
        validator=not_placeholder,
        tags=["azure"],
    ),
    Rule(
        "azure.sas-token",
        "Azure shared access signature",
        _r(r"(?:\?|&)(?:sv=\d{4}-\d{2}-\d{2}[^\s\"']*?sig=([A-Za-z0-9%+/=]{40,}))"),
        Severity.HIGH,
        0.88,
        group=1,
        tags=["azure"],
    ),
    Rule(
        "azure.management-certificate",
        "Azure management certificate (PFX blob)",
        _r(r"(?i)<ManagementCertificate>([A-Za-z0-9+/=]{200,})</ManagementCertificate>"),
        Severity.CRITICAL,
        0.9,
        group=1,
        tags=["azure"],
    ),
]

_GCP: List[Rule] = [
    Rule(
        "gcp.api-key",
        "Google API key",
        _r(r"\b(AIza[0-9A-Za-z_\-]{35})\b"),
        Severity.HIGH,
        0.93,
        group=1,
        validator=not_placeholder,
        tags=["gcp"],
    ),
    Rule(
        "gcp.service-account-key",
        "GCP service account private key",
        _r(
            r"\"type\"\s*:\s*\"service_account\"[\s\S]{0,400}?"
            r"\"private_key\"\s*:\s*\"(-----BEGIN[^\"]+)\""
        ),
        Severity.CRITICAL,
        0.97,
        group=1,
        tags=["gcp"],
    ),
    Rule(
        "gcp.oauth-client-secret",
        "Google OAuth client secret",
        _r(r"\b(GOCSPX-[A-Za-z0-9_\-]{28})\b"),
        Severity.HIGH,
        0.93,
        group=1,
        tags=["gcp"],
    ),
    Rule(
        "gcp.oauth-refresh-token",
        "Google OAuth refresh token",
        _r(r"\b(1//[0-9A-Za-z_\-]{30,})"),
        Severity.HIGH,
        0.85,
        group=1,
        tags=["gcp"],
    ),
]

_DEVOPS: List[Rule] = [
    Rule(
        "github.token",
        "GitHub token",
        _r(r"\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{22,255})\b"),
        Severity.CRITICAL,
        0.96,
        group=1,
        tags=["github"],
    ),
    Rule(
        "gitlab.token",
        "GitLab token",
        _r(r"\b(glpat-[A-Za-z0-9_\-]{20,}|gl(?:rt|ft|soat|cbt)-[A-Za-z0-9_\-]{20,})\b"),
        Severity.CRITICAL,
        0.95,
        group=1,
        tags=["gitlab"],
    ),
    Rule(
        "slack.token",
        "Slack token",
        _r(r"\b(xox[abposr]-[A-Za-z0-9\-]{10,})\b"),
        Severity.HIGH,
        0.94,
        group=1,
        tags=["slack"],
    ),
    Rule(
        "slack.webhook",
        "Slack incoming webhook",
        _r(r"(https://hooks\.slack\.com/(?:services|workflows)/[A-Za-z0-9/_+-]{20,})"),
        Severity.HIGH,
        0.95,
        group=1,
        tags=["slack"],
    ),
    Rule(
        "stripe.secret-key",
        "Stripe secret / restricted key",
        _r(r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,})\b"),
        Severity.CRITICAL,
        0.96,
        group=1,
        tags=["stripe"],
    ),
    Rule(
        "npm.token",
        "npm access token",
        _r(r"\b(npm_[A-Za-z0-9]{36})\b"),
        Severity.HIGH,
        0.95,
        group=1,
        tags=["npm"],
    ),
    Rule(
        "pypi.token",
        "PyPI upload token",
        _r(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})\b"),
        Severity.HIGH,
        0.96,
        group=1,
        tags=["pypi"],
    ),
    Rule(
        "openai.api-key",
        "OpenAI API key",
        _r(r"\b(sk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,})\b"),
        Severity.HIGH,
        0.9,
        group=1,
        tags=["saas"],
    ),
    Rule(
        "anthropic.api-key",
        "Anthropic API key",
        _r(r"\b(sk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_\-]{80,})\b"),
        Severity.HIGH,
        0.95,
        group=1,
        tags=["saas"],
    ),
    Rule(
        "sendgrid.api-key",
        "SendGrid API key",
        _r(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"),
        Severity.HIGH,
        0.95,
        group=1,
        tags=["saas"],
    ),
    Rule(
        "twilio.api-key",
        "Twilio account/API SID",
        _r(r"\b((?:AC|SK)[0-9a-fA-F]{32})\b"),
        Severity.MEDIUM,
        0.8,
        group=1,
        tags=["saas"],
    ),
    Rule(
        "telegram.bot-token",
        "Telegram bot token",
        _r(r"\b([0-9]{8,10}:AA[A-Za-z0-9_\-]{33})\b"),
        Severity.HIGH,
        0.94,
        group=1,
        tags=["saas"],
    ),
    Rule(
        "jwt",
        "JSON Web Token",
        _r(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})"),
        Severity.MEDIUM,
        0.85,
        group=1,
        validator=valid_jwt,
        tags=["jwt"],
    ),
    Rule(
        "crypto.private-key",
        "Private key block",
        _r(
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
        ),
        Severity.CRITICAL,
        0.98,
        tags=["pki"],
    ),
    Rule(
        "crypto.putty-private-key",
        "PuTTY private key",
        _r(r"PuTTY-User-Key-File-\d+:"),
        Severity.CRITICAL,
        0.95,
        tags=["pki"],
    ),
]

_UNIVERSAL: List[Rule] = [
    Rule(
        "generic.database-uri",
        "Database connection URI with credentials",
        _r(
            r"\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqps?"
            r"|mssql|jdbc:[a-z]+|clickhouse|cassandra)://"
            r"[^:/\s\"']+:[^@\s\"']+@[^\s\"'<>\\]+)"
        ),
        Severity.CRITICAL,
        0.9,
        group=1,
        validator=no_local_host,
        tags=["db"],
    ),
    Rule(
        "generic.basic-auth-url",
        "URL with embedded basic-auth credentials",
        _r(r"\b(https?://[^:/\s\"']+:[^@\s\"']{3,}@[^\s\"'<>\\]+)"),
        Severity.HIGH,
        0.88,
        group=1,
        validator=no_local_host,
        tags=["url"],
    ),
    Rule(
        "generic.internal-url",
        "Internal / RFC1918 endpoint",
        _r(
            r"\b((?:https?|ssh|ftp|smb|ldaps?|rdp)://(?:[A-Za-z0-9._\-]+\."
            r"(?:local|lan|internal|intranet|corp|home\.arpa)|10\.\d+\.\d+\.\d+"
            r"|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+"
            r"|localhost)(?::\d+)?[^\s\"'<>\\]*)"
        ),
        Severity.LOW,
        0.7,
        group=1,
        tags=["endpoint"],
    ),
    Rule(
        "generic.external-url",
        "External endpoint",
        _r(r"\b(https?://(?!localhost)[A-Za-z0-9._\-]+\.[A-Za-z]{2,24}(?::\d+)?[^\s\"'<>\\]*)"),
        Severity.INFO,
        0.5,
        group=1,
        tags=["endpoint"],
    ),
    Rule(
        "generic.ipv4-private",
        "Private IPv4 address",
        _r(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"),
        Severity.INFO,
        0.6,
        group=1,
        validator=private_ipv4,
        tags=["network"],
    ),
    Rule(
        "generic.ipv4-public",
        "Public IPv4 address",
        _r(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"),
        Severity.INFO,
        0.5,
        group=1,
        validator=public_ipv4,
        tags=["network"],
    ),
    Rule(
        "generic.ipv6",
        "IPv6 address",
        # Require the full 8-group form or a `::` compression, so a timestamp
        # like `19:53:57` (only two colons, no ``::``) is not mistaken for IPv6.
        _r(
            r"(?<![:.\w])("
            r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
            r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{0,4}"
            r")(?![:.\w])"
        ),
        Severity.INFO,
        0.4,
        group=1,
        tags=["network"],
    ),
    Rule(
        "generic.api-key-assignment",
        "Generic secret assignment",
        _r(
            assignment(
                r"access|auth|(?-i:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|secret|token",
                r"[\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3}",
            )
        ),
        Severity.MEDIUM,
        0.6,
        group=1,
        validator=not_placeholder,
        min_entropy=3.5,
        allow_regexes=(_r(r"^[a-zA-Z_.-]+$"), _r(GENERIC_KEY_ALLOWLIST)),
        use_stopwords=True,
        tags=["generic"],
    ),
    Rule(
        "generic.authorization-header",
        "Hardcoded Authorization header",
        _r(r"(?i)authorization\s*[:=]\s*[\"']?(?:bearer|basic|token)\s+([A-Za-z0-9._\-+/=]{12,})"),
        Severity.HIGH,
        0.85,
        group=1,
        validator=not_placeholder,
        tags=["generic"],
    ),
]

RULES: List[Rule] = _AWS + _AZURE + _GCP + _DEVOPS + _UNIVERSAL

# Literal anchors used to skip a rule before its regex ever runs.
PREFILTERS: Dict[str, Tuple[str, ...]] = {
    "aws.access-key-id": ("akia", "asia", "abia", "acca", "a3t"),
    "aws.secret-access-key": ("aws",),
    "aws.session-token": ("session",),
    "azure.storage-connection-string": ("defaultendpointsprotocol",),
    "azure.servicebus-sas": ("sharedaccesskey",),
    "azure.client-secret": ("client_secret", "client-secret", "clientsecret", "azure"),
    "azure.sas-token": ("sig=",),
    "azure.management-certificate": ("managementcertificate",),
    "gcp.api-key": ("aiza",),
    "gcp.service-account-key": ("service_account",),
    "gcp.oauth-client-secret": ("gocspx-",),
    "gcp.oauth-refresh-token": ("1//",),
    "github.token": ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
    "gitlab.token": ("glpat-", "glrt-", "glft-", "glsoat-", "glcbt-"),
    "slack.token": ("xox",),
    "slack.webhook": ("hooks.slack.com",),
    "stripe.secret-key": ("sk_live_", "sk_test_", "rk_live_", "rk_test_"),
    "npm.token": ("npm_",),
    "pypi.token": ("pypi-",),
    "openai.api-key": ("sk-",),
    "anthropic.api-key": ("sk-ant-",),
    "sendgrid.api-key": ("sg.",),
    "twilio.api-key": ("ac", "sk"),
    "telegram.bot-token": (":aa",),
    "jwt": ("eyj",),
    "crypto.private-key": ("-----begin",),
    "crypto.putty-private-key": ("putty-user-key-file",),
    "generic.database-uri": ("://",),
    "generic.basic-auth-url": ("http",),
    "generic.internal-url": ("://",),
    "generic.external-url": ("http",),
    "generic.api-key-assignment": (
        "key", "secret", "token", "pass", "auth", "credential",
    ),
    "generic.authorization-header": ("authorization",),
}

for _rule in RULES:
    _rule.prefilter = PREFILTERS.get(_rule.rule_id, ())
    _rule.checksum = CHECKSUMS.get(_rule.rule_id)

RULES_BY_ID = {rule.rule_id: rule for rule in RULES}

ALL_TAGS = sorted({tag for rule in RULES for tag in rule.tags})


def select_rules(
    include: Optional[List[str]] = None,
    exclude: Optional[List[str]] = None,
) -> List[Rule]:
    """Filter the ruleset by rule id prefix or tag."""
    rules = RULES
    if include:
        rules = [r for r in rules if _matches(r, include)]
    if exclude:
        rules = [r for r in rules if not _matches(r, exclude)]
    return rules


def _matches(rule: Rule, selectors: List[str]) -> bool:
    for selector in selectors:
        sel = selector.strip().lower()
        if not sel:
            continue
        if sel in rule.tags or rule.rule_id == sel or rule.rule_id.startswith(sel):
            return True
    return False
