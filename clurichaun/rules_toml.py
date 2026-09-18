"""Load rule packs written in gitleaks' TOML schema.

gitleaks' ``[[rules]]`` format is the de-facto interchange format for secret
patterns, and it is MIT-licensed, so Clurichaun reads it directly rather than
inventing a rival schema. That buys two things: users can extend the ruleset
without touching Python, and an existing ``gitleaks.toml`` works as-is.

Supported keys, with gitleaks' own semantics:

    [[rules]]
    id, description, regex, keywords, entropy, secretGroup, path
    [[rules.allowlists]]
    regexes, regexTarget = "match"|"line"|"secret", stopwords, paths

``secretGroup`` picks the capture group; when it is absent the secret is the
first non-empty capture group, falling back to the whole match. ``keywords``
become the rule's literal prefilter, which is exactly how gitleaks uses them.

Not supported (reported, not silently ignored): ``[extend]`` inheritance,
allowlist ``commits`` and ``condition = "AND"``, and rules whose only matcher is
``path`` — Clurichaun's scope categories already cover filename targeting.

See ``NOTICE.md``; gitleaks is MIT, Copyright (c) 2019 Zachary Rice.
"""

from __future__ import annotations

import re
import tomllib
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .models import Severity
from .patterns import Rule

DEFAULT_CONFIDENCE = 0.8
MAX_KEYWORDS = 24

# gitleaks carries no severity field; infer one from what the rule is about.
_CRITICAL_HINTS = (
    "private-key", "private_key", "aws", "gcp", "azure", "stripe", "github",
    "gitlab", "database", "postgres", "mysql", "mongo", "rsa", "pgp", "ssh",
    "kubernetes", "vault", "root", "master",
)
_MEDIUM_HINTS = ("generic", "id", "client-id", "public", "username", "webhook")


@dataclass(slots=True)
class LoadReport:
    """What happened while loading a pack — surfaced, never swallowed."""

    path: str
    loaded: int = 0
    skipped: List[Tuple[str, str]] = field(default_factory=list)
    unsupported: List[Tuple[str, str]] = field(default_factory=list)

    @property
    def summary(self) -> str:
        parts = [f"{self.loaded} rules from {self.path}"]
        if self.skipped:
            parts.append(f"{len(self.skipped)} skipped")
        if self.unsupported:
            parts.append(f"{len(self.unsupported)} with unsupported keys")
        return ", ".join(parts)


BUNDLED_DIR = Path(__file__).with_name("rules")


def bundled_packs() -> Dict[str, Path]:
    """Rule packs shipped with Clurichaun, by name (TOML and Nosey Parker YAML)."""
    if not BUNDLED_DIR.is_dir():  # pragma: no cover - source layout
        return {}
    packs: Dict[str, Path] = {}
    for pattern in ("*.toml", "*.yml"):
        for path in sorted(BUNDLED_DIR.glob(pattern)):
            packs[path.stem] = path
    return packs


def load_any(path: str | Path) -> Tuple[List[Rule], "LoadReport"]:
    """Load a pack by extension: ``.yml`` -> Nosey Parker, else gitleaks TOML."""
    path = Path(path)
    if path.suffix.lower() in (".yml", ".yaml"):
        from .rules_np import load_np_dir, load_np_text

        if path.is_dir():
            return load_np_dir(path)
        return load_np_text(path.read_text(encoding="utf-8"), str(path))
    return load_pack(path)


def resolve_pack(name_or_path: str) -> Path:
    """Accept either a bundled pack name or a filesystem path."""
    packs = bundled_packs()
    if name_or_path in packs:
        return packs[name_or_path]
    path = Path(name_or_path).expanduser()
    if path.is_file():
        return path
    known = ", ".join(sorted(packs)) or "none bundled"
    raise FileNotFoundError(f"no rule pack {name_or_path!r}; bundled packs: {known}")


def load_pack(path: str | Path) -> Tuple[List[Rule], LoadReport]:
    """Parse a gitleaks-shaped TOML file into Clurichaun rules."""
    text = Path(path).read_text(encoding="utf-8")
    return load_pack_text(text, str(path))


def load_pack_text(text: str, origin: str = "<memory>") -> Tuple[List[Rule], LoadReport]:
    report = LoadReport(path=origin)
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"{origin}: invalid TOML: {exc}") from exc

    if "extend" in doc:
        report.unsupported.append(("<config>", "[extend] inheritance ignored"))

    global_allow = _allowlists(doc.get("allowlist") or {}, doc.get("allowlists") or [])

    rules: List[Rule] = []
    for entry in doc.get("rules") or []:
        if not isinstance(entry, dict):
            continue
        rule_id = str(entry.get("id") or "").strip()
        if not rule_id:
            report.skipped.append(("<unnamed>", "missing id"))
            continue

        pattern = entry.get("regex")
        if not pattern:
            report.skipped.append(
                (rule_id, "path-only rule; use --include/--category instead")
            )
            continue

        try:
            regex = compile_re2(str(pattern))
        except re.error as exc:
            # A few RE2 constructs have no Python equivalent.
            report.skipped.append((rule_id, f"regex rejected by Python re: {exc}"))
            continue

        rule_allow = _allowlists(entry.get("allowlist") or {}, entry.get("allowlists") or [])
        allow_regexes = tuple(global_allow.value_regexes + rule_allow.value_regexes)
        deny_paths = tuple(global_allow.paths + rule_allow.paths)
        stopwords = global_allow.stopwords or rule_allow.stopwords

        if rule_allow.unsupported or global_allow.unsupported:
            for note in set(rule_allow.unsupported + global_allow.unsupported):
                report.unsupported.append((rule_id, note))

        path_regex: Optional[re.Pattern[str]] = None
        if entry.get("path"):
            try:
                path_regex = compile_re2(str(entry["path"]))
            except re.error as exc:
                report.unsupported.append((rule_id, f"path regex ignored: {exc}"))

        keywords = [
            str(word).lower()
            for word in (entry.get("keywords") or [])
            if str(word).strip()
        ][:MAX_KEYWORDS]

        secret_group = entry.get("secretGroup")
        group = int(secret_group) if isinstance(secret_group, int) else -1

        rules.append(
            Rule(
                rule_id=rule_id,
                title=_title(entry.get("description"), rule_id),
                regex=regex,
                severity=_severity(rule_id),
                confidence=DEFAULT_CONFIDENCE,
                group=group,
                tags=["pack", _family(rule_id)],
                min_entropy=float(entry.get("entropy") or 0.0),
                allow_regexes=allow_regexes,
                use_stopwords=stopwords,
                prefilter=tuple(keywords),
                path_regex=path_regex,
                deny_paths=deny_paths,
            )
        )

    report.loaded = len(rules)
    return rules, report


# --------------------------------------------------------------------------- #
# RE2 -> Python translation
# --------------------------------------------------------------------------- #

_INLINE_FLAGS = re.compile(r"\(\?([aimsux]+)\)")


def compile_re2(pattern: str) -> re.Pattern[str]:
    """Compile a Go RE2 pattern under Python's `re`.

    The one construct that routinely differs: RE2 allows an inline flag group
    like `(?i)` anywhere, applying it from that point to the end of the
    enclosing group, while Python demands global flags at position 0. Rewriting
    `pre(?i)post` as `pre(?i:post)` preserves RE2's meaning exactly, where
    hoisting the flag to the front would not — it would also case-fold the
    prefix, which for rules anchored on a literal like `sk_live_` changes what
    they match.
    """
    rewritten = _scope_inline_flags(pattern)
    with warnings.catch_warnings():
        # Third-party patterns use `[[...]`, which Python flags as a possible
        # nested set. It means a literal `[` here, which is what RE2 does.
        warnings.simplefilter("ignore", FutureWarning)
        return re.compile(rewritten)


def _scope_inline_flags(pattern: str) -> str:
    match = _INLINE_FLAGS.search(pattern)
    while match is not None and match.start() != 0:
        flags = match.group(1)
        head = pattern[: match.start()]
        tail = pattern[match.end() :]
        end = _group_end(tail)
        pattern = f"{head}(?{flags}:{tail[:end]}){tail[end:]}"
        match = _INLINE_FLAGS.search(pattern, match.start() + len(flags) + 4)
    return pattern


def _group_end(text: str) -> int:
    """Index of the `)` closing the group that contains `text`, or len(text)."""
    depth = 0
    index = 0
    in_class = False
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if in_class:
            if char == "]":
                in_class = False
        elif char == "[":
            in_class = True
        elif char == "(":
            depth += 1
        elif char == ")":
            if depth == 0:
                return index
            depth -= 1
        index += 1
    return len(text)


# --------------------------------------------------------------------------- #
# Allowlists
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class _Allow:
    value_regexes: List[re.Pattern[str]] = field(default_factory=list)
    paths: List[re.Pattern[str]] = field(default_factory=list)
    stopwords: bool = False
    unsupported: List[str] = field(default_factory=list)


def _allowlists(single: Dict[str, Any], many: Sequence[Any]) -> _Allow:
    out = _Allow()
    blocks: List[Dict[str, Any]] = []
    if isinstance(single, dict) and single:
        blocks.append(single)
    blocks.extend(block for block in many if isinstance(block, dict))

    for block in blocks:
        if str(block.get("condition") or "OR").upper() == "AND":
            # AND means "all clauses must match to allow"; treating it as OR
            # would over-suppress, so the block is dropped and reported.
            out.unsupported.append('allowlist condition = "AND" dropped')
            continue
        if block.get("commits"):
            out.unsupported.append("allowlist commits ignored (no git history yet)")

        target = str(block.get("regexTarget") or "secret").lower()
        for pattern in block.get("regexes") or []:
            try:
                compiled = compile_re2(str(pattern))
            except re.error:
                out.unsupported.append("allowlist regex rejected by Python re")
                continue
            if target in ("match", "secret"):
                out.value_regexes.append(compiled)
            else:
                # regexTarget = "line" needs the containing line, which the
                # rule engine does not hand to allowlists yet.
                out.unsupported.append('allowlist regexTarget = "line" ignored')

        for pattern in block.get("paths") or []:
            try:
                out.paths.append(compile_re2(str(pattern)))
            except re.error:
                out.unsupported.append("allowlist path regex rejected by Python re")

        if block.get("stopwords"):
            out.stopwords = True

    return out


# --------------------------------------------------------------------------- #
# Metadata inference
# --------------------------------------------------------------------------- #


def _title(description: Any, rule_id: str) -> str:
    text = str(description or "").strip()
    if not text:
        return rule_id.replace("-", " ").replace("_", " ").title()
    first = text.split(". ")[0].rstrip(".")
    return first[:120]


def _severity(rule_id: str) -> Severity:
    lowered = rule_id.lower()
    if any(hint in lowered for hint in _MEDIUM_HINTS):
        return Severity.MEDIUM
    if any(hint in lowered for hint in _CRITICAL_HINTS):
        return Severity.CRITICAL
    return Severity.HIGH


def _family(rule_id: str) -> str:
    return rule_id.split("-", 1)[0].lower()
