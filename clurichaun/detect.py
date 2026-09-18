"""SecretDetector: the regex + entropy + key-name evaluation engine."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Set, Tuple

from . import decode as decode_mod
from . import entropy as entropy_mod
from . import keywords as keywords_mod
from . import parsers, scope
from .stopwords import contains_stopword
from .models import Blob, Detector, Finding, Severity
from .patterns import Rule, select_rules

CONTEXT_WINDOW = 96

# Values published in vendor documentation; never real.
KNOWN_FAKE: Set[str] = {
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe",
    "sk_test_4eC39HqLyjWDarjtT1zdp7dc",
    "xoxb-000000000000-000000000000-abcdefghijklmnopqrstuvwx",
}

INLINE_IGNORE = re.compile(
    r"(?i)(?:clurichaun\s*[:\-]\s*ignore|pragma\s*:\s*allowlist\s+secret|"
    r"nosecret|trufflehog\s*:\s*ignore|gitleaks\s*:\s*allow|noqa\s*:\s*secret)"
)

_MINIFIED_HINT = re.compile(r"^\s*[\w$]{1,3}\s*=\s*function|;\s*function\s*\(", re.M)


@dataclass(slots=True)
class DetectorConfig:
    include_rules: Optional[List[str]] = None
    exclude_rules: Optional[List[str]] = None
    min_confidence: float = 0.4
    # Default excludes INFO: bare endpoint URLs and IP addresses are context,
    # not secrets, and dominate false positives (measured on CredData). Pass
    # `--min-severity info` to include them for reconnaissance.
    min_severity: Severity = Severity.LOW
    entropy_enabled: bool = True
    keyname_enabled: bool = True
    regex_enabled: bool = True
    respect_inline_ignore: bool = True
    baseline: Set[str] = field(default_factory=set)
    max_findings_per_blob: int = 2000
    decoders_enabled: bool = True
    max_decode_input: int = decode_mod.DEFAULT_MAX_INPUT
    rule_packs: Tuple[str, ...] = ()
    """Bundled pack names or TOML paths, loaded on top of the built-in rules."""


class SecretDetector:
    """Stateless per-blob evaluator. Safe to construct once per worker process."""

    def __init__(self, config: Optional[DetectorConfig] = None) -> None:
        self.config = config or DetectorConfig()
        rules: List[Rule] = list(
            select_rules(self.config.include_rules, self.config.exclude_rules)
        )
        for pack in self.config.rule_packs:
            # Imported here so the loader (and tomllib) stay off the hot path
            # for callers that never use packs.
            from .rules_toml import load_any, resolve_pack

            extra, _report = load_any(resolve_pack(pack))
            known = {rule.rule_id for rule in rules}
            rules.extend(rule for rule in extra if rule.rule_id not in known)
        self.rules: Sequence[Rule] = rules
        self._rules_by_id = {rule.rule_id: rule for rule in rules}
        # Above ~80 rules a single Aho-Corasick pass beats the per-rule
        # substring loop; below it the loop's zero setup cost wins.
        self._keyword_index = (
            keywords_mod.KeywordIndex.build(rules)
            if len(rules) >= keywords_mod.ACTIVATION_THRESHOLD
            else None
        )

    # ------------------------------------------------------------------ #

    def scan(self, blob: Blob) -> List[Finding]:
        if not blob.text:
            return []

        findings = self._passes(blob)

        if blob.commit_line > 0:
            # Drop findings in the previous streamed chunk's overlap window;
            # they were already owned there. Lines are absolute (line_offset
            # folded in), so the window floor is line_offset + commit_line.
            floor = blob.line_offset + blob.commit_line
            findings = [f for f in findings if f.line >= floor]

        if self.config.decoders_enabled:
            # A secret behind one layer of encoding is invisible to every regex,
            # so re-run the passes over each decoded view of the same text.
            plain = {(f.rule_id, f.secret) for f in findings}
            for decoded in decode_mod.derive(blob.text, self.config.max_decode_input):
                view = Blob(
                    logical_path=f"{blob.logical_path}#{decoded.label}",
                    source_path=blob.source_path,
                    text=decoded.text,
                    is_binary=blob.is_binary,
                    media_type=blob.media_type,
                    line_offset=blob.line_offset,
                    byte_offset=blob.byte_offset,
                    container_depth=blob.container_depth,
                )
                for finding in self._passes(view):
                    key = (finding.rule_id, finding.secret)
                    if key in plain:
                        continue  # the plaintext hit already reported it
                    plain.add(key)
                    finding.notes.append(f"recovered after {decoded.label} decoding")
                    finding.confidence = round(max(0.05, finding.confidence - 0.05), 3)
                    findings.append(finding)

        return self._finalize(findings)

    def _passes(self, blob: Blob) -> List[Finding]:
        findings: List[Finding] = []
        offsets = _line_offsets(blob.text)
        boost = scope.interest_boost(blob.logical_path)

        if self.config.regex_enabled:
            findings.extend(self._regex_pass(blob, offsets, boost))
        if self.config.entropy_enabled:
            findings.extend(self._entropy_pass(blob, offsets, boost))
        if self.config.keyname_enabled and not blob.is_binary:
            findings.extend(self._keyname_pass(blob, boost))
        _link_multipart(findings)
        return findings

    # ------------------------------------------------------------------ #

    def _regex_pass(
        self, blob: Blob, offsets: List[int], boost: float
    ) -> Iterable[Finding]:
        text = blob.text
        lowered = text.lower()
        if self._keyword_index is not None:
            candidate_ids = self._keyword_index.candidate_rules(text)
            candidates = [self._rules_by_id[rid] for rid in candidate_ids]
        else:
            candidates = [
                rule
                for rule in self.rules
                if not rule.prefilter
                or any(anchor in lowered for anchor in rule.prefilter)
            ]
        for rule in candidates:
            if not rule.applies_to(blob.logical_path):
                continue
            for match in rule.regex.finditer(text):
                raw, start = rule.pick(match)
                if not raw:
                    continue
                candidate = raw.strip().strip("\"'")
                if not candidate or candidate in KNOWN_FAKE:
                    continue
                line_text = _line_text(text, offsets, start)
                if rule.validator is not None and not rule.validator(candidate, line_text):
                    continue
                if any(allowed.search(candidate) for allowed in rule.allow_regexes):
                    continue
                if rule.min_entropy and entropy_mod.shannon(candidate) < rule.min_entropy:
                    continue
                stopword = contains_stopword(candidate) if rule.use_stopwords else None
                if stopword is not None:
                    continue
                if self.config.respect_inline_ignore and INLINE_IGNORE.search(line_text):
                    continue

                confidence = rule.confidence + boost - scope.context_penalty(
                    blob.logical_path, line_text
                )
                notes: List[str] = []

                # An embedded checksum is a certain signal in both directions.
                if rule.checksum is not None:
                    verdict = rule.checksum(candidate)
                    if verdict is False:
                        continue  # provably fabricated; drop with certainty
                    if verdict is True:
                        confidence = 0.99
                        notes.append("checksum verified")

                if blob.is_binary:
                    confidence -= 0.05
                    notes.append("recovered from binary strings")
                if parsers.is_benign_value(candidate) and "generic" in rule.tags:
                    continue

                line, column = _position(offsets, start)
                yield Finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    detector=Detector.REGEX,
                    severity=rule.severity,
                    logical_path=blob.logical_path,
                    source_path=blob.source_path,
                    line=line + blob.line_offset,
                    column=column,
                    secret=candidate,
                    match_context=_context(text, start, len(candidate)),
                    confidence=round(min(0.99, confidence), 3),
                    key_name=_key_near(line_text),
                    notes=notes,
                    media_type=blob.media_type,
                )

    def _entropy_pass(
        self, blob: Blob, offsets: List[int], boost: float
    ) -> Iterable[Finding]:
        text = blob.text
        minified = blob.logical_path.lower().endswith(
            (".min.js", ".bundle.js")
        ) or bool(_MINIFIED_HINT.search(text[:4096]))
        for candidate in entropy_mod.iter_candidates(text, blob.logical_path):
            line_text = _line_text(text, offsets, candidate.start)
            if self.config.respect_inline_ignore and INLINE_IGNORE.search(line_text):
                continue
            if candidate.value in KNOWN_FAKE:
                continue
            # A genuinely high-entropy secret is random; a token that contains a
            # dictionary word (`benchmarks`, `config-test`) is a name, not a key.
            # Applied as a penalty, not a hard skip, so a real secret that
            # happens to contain a common substring still surfaces (lower ranked).
            stopword_penalty = 0.2 if contains_stopword(candidate.value) else 0.0

            confidence = candidate.confidence + boost - stopword_penalty - scope.context_penalty(
                blob.logical_path, line_text
            )
            if minified:
                confidence -= 0.1
            if blob.is_binary:
                confidence -= 0.1

            line, column = _position(offsets, candidate.start)
            yield Finding(
                rule_id=f"entropy.{candidate.charset}",
                title=f"High-entropy {candidate.charset} string",
                detector=Detector.ENTROPY,
                severity=Severity.MEDIUM if candidate.confidence > 0.6 else Severity.LOW,
                logical_path=blob.logical_path,
                source_path=blob.source_path,
                line=line + blob.line_offset,
                column=column,
                secret=candidate.value,
                match_context=_context(text, candidate.start, len(candidate.value)),
                confidence=round(max(0.05, min(0.95, confidence)), 3),
                entropy=candidate.entropy,
                key_name=_key_near(line_text),
                media_type=blob.media_type,
            )

    def _keyname_pass(self, blob: Blob, boost: float) -> Iterable[Finding]:
        pairs = parsers.parse(blob.text, blob.logical_path)
        if not pairs:
            return
        for pair in pairs:
            if not parsers.is_suspicious_key(pair.key_path):
                continue
            if parsers.is_benign_value(pair.value):
                continue
            value = pair.value.strip()
            if value in KNOWN_FAKE or len(value) > 512:
                continue
            # A sensitive key whose *value* is prose, a flag description, or a
            # bare identifier is almost always a false positive: passwords are
            # not sentences, and `passwd, "", "the SASL password"` is doc text.
            if _looks_like_prose(value) or _looks_like_identifier(value):
                continue

            confidence = 0.6 + boost
            score = entropy_mod.shannon(value)
            if score > 3.5:
                confidence += 0.1
            if entropy_mod.is_structural_noise(value):
                confidence -= 0.2
            if contains_stopword(value):
                confidence -= 0.2

            yield Finding(
                rule_id="keyname.sensitive-assignment",
                title=f"Sensitive key '{pair.key}' with a literal value",
                detector=Detector.KEYNAME,
                severity=Severity.HIGH if confidence >= 0.7 else Severity.MEDIUM,
                logical_path=blob.logical_path,
                source_path=blob.source_path,
                line=pair.line + blob.line_offset,
                column=1,
                secret=value,
                match_context=f"{pair.key_path} = {value}",
                confidence=round(max(0.05, min(0.95, confidence)), 3),
                entropy=round(score, 3),
                key_name=pair.key_path,
                media_type=blob.media_type,
            )

    # ------------------------------------------------------------------ #

    def _finalize(self, findings: List[Finding]) -> List[Finding]:
        kept: List[Finding] = []
        seen: Set[str] = set()
        for finding in findings:
            if finding.confidence < self.config.min_confidence:
                continue
            if finding.severity.rank < self.config.min_severity.rank:
                continue
            fingerprint = finding.fingerprint
            if fingerprint in self.config.baseline or fingerprint in seen:
                continue
            seen.add(fingerprint)
            kept.append(finding)
            if len(kept) >= self.config.max_findings_per_blob:
                break

        kept.sort(key=lambda f: (-f.severity.rank, -f.confidence, f.line))
        return kept


# --------------------------------------------------------------------------- #
# Position helpers
# --------------------------------------------------------------------------- #


def _line_offsets(text: str) -> List[int]:
    offsets = [0]
    index = text.find("\n")
    while index != -1:
        offsets.append(index + 1)
        index = text.find("\n", index + 1)
    return offsets


def _position(offsets: List[int], index: int) -> tuple[int, int]:
    low, high = 0, len(offsets) - 1
    while low < high:
        mid = (low + high + 1) // 2
        if offsets[mid] <= index:
            low = mid
        else:
            high = mid - 1
    return low + 1, index - offsets[low] + 1


def _line_text(text: str, offsets: List[int], index: int) -> str:
    line, _ = _position(offsets, index)
    start = offsets[line - 1]
    end = offsets[line] - 1 if line < len(offsets) else len(text)
    if end - start > 4096:  # minified single-line bundles
        local = index - start
        return text[max(start, index - 512) : min(end, start + local + 512)]
    return text[start:end]


def _context(text: str, start: int, length: int) -> str:
    left = max(0, start - CONTEXT_WINDOW)
    right = min(len(text), start + length + CONTEXT_WINDOW)
    snippet = text[left:right].replace("\r", " ").replace("\n", " ⏎ ")
    return snippet.strip()


_KEY_NEAR = re.compile(
    r"(?i)([A-Za-z0-9_.\-\[\]]{2,64})\s*(?:[:=]|=>|:=)\s*[\"']?[^\s\"']*$"
)


def _key_near(line_text: str) -> Optional[str]:
    match = _KEY_NEAR.search(line_text[:512])
    return match.group(1) if match else None


_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z_.]*$")


def _looks_like_prose(value: str) -> bool:
    """A value with internal spaces is documentation, not a credential."""
    stripped = value.strip().strip("\"'")
    return " " in stripped and len(stripped.split()) >= 2


def _looks_like_identifier(value: str) -> bool:
    """A pure word/dotted-name with no digits is a variable name, not a secret."""
    stripped = value.strip().strip("\"'")
    return bool(_IDENTIFIER.match(stripped)) and len(stripped) <= 40


# Multi-part credential families, declared not coded: an identifier rule, its
# secret rule, and the maximum line distance within which they count as a pair.
# When both appear inside `window` lines, both findings adopt a shared id:secret
# identity so a rotated secret under a reused id no longer dedupes against the
# old pair. Add a family here (or a pack can extend COMPOSITE_RULES) rather than
# editing the pairing logic.
@dataclass(slots=True)
class CompositeRule:
    id_rule: str
    secret_rule: str
    window: int = 40


COMPOSITE_RULES: List[CompositeRule] = [
    CompositeRule("aws.access-key-id", "aws.secret-access-key", window=40),
    CompositeRule("gcp.oauth-client-secret", "gcp.oauth-refresh-token", window=40),
]


def _link_multipart(
    findings: List[Finding], composites: Optional[List[CompositeRule]] = None
) -> None:
    by_rule: dict[str, List[Finding]] = {}
    for finding in findings:
        by_rule.setdefault(finding.rule_id, []).append(finding)

    for rule in composites if composites is not None else COMPOSITE_RULES:
        ids = by_rule.get(rule.id_rule)
        secrets = by_rule.get(rule.secret_rule)
        if not ids or not secrets:
            continue
        for id_finding in ids:
            partner = min(secrets, key=lambda s: abs(s.line - id_finding.line))
            if abs(partner.line - id_finding.line) > rule.window:
                continue  # too far apart to be one credential
            combined = f"{id_finding.secret}:{partner.secret}"
            id_finding.secret_v2 = combined
            partner.secret_v2 = combined
            id_finding.notes.append(f"paired with {rule.secret_rule}")
