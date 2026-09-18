"""Load Nosey Parker's YAML rule corpus.

Nosey Parker (Praetorian, Apache-2.0) ships ~120 well-curated rules as YAML:

    rules:
    - name: AWS API Key
      id: np.aws.1
      pattern: '\\b((?:AKIA|ASIA|...)[A-Z0-9]{16})\\b'
      categories: [api, identifier]
      examples: [...]
      negative_examples: [...]

The corpus is Apache-2.0, so it is vendored here with attribution (`NOTICE.md`).
Patterns are Rust `regex` — RE2-family, like gitleaks' Go RE2 — so they reuse
``rules_toml.compile_re2`` for the one real difference (inline ``(?i)`` /
``(?x)`` mid-pattern, which Python's ``re`` rejects at nonzero position). The
first capture group is the secret, matching Nosey Parker's own extraction; a
rule with no group yields the whole match.

``keywords`` are not part of the schema, so a literal anchor is derived from the
pattern where an obvious one exists (a fixed prefix like ``AKIA`` or ``ghp_``),
otherwise the rule always runs — correctness first, the Aho-Corasick core (#8)
keeps that affordable.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .models import Severity
from .patterns import Rule
from .rules_toml import LoadReport, _family, _severity, compile_re2

try:  # pragma: no cover - PyYAML is a core dep, but guard anyway
    import yaml as _yaml
except Exception:  # pragma: no cover
    _yaml = None

# A leading literal run inside the pattern, usable as an Aho-Corasick anchor.
_LITERAL_PREFIX = re.compile(r"^[A-Za-z0-9_]{3,}")


def load_np_dir(path: str | Path) -> Tuple[List[Rule], LoadReport]:
    """Load every ``*.yml`` rule file under a Nosey Parker rules directory."""
    directory = Path(path)
    report = LoadReport(path=str(directory))
    rules: List[Rule] = []
    seen: set[str] = set()
    for yml in sorted(directory.glob("*.yml")):
        try:
            text = yml.read_text(encoding="utf-8")
        except OSError as exc:
            report.skipped.append((yml.name, f"unreadable: {exc}"))
            continue
        file_rules, file_report = load_np_text(text, yml.name)
        report.skipped.extend(file_report.skipped)
        report.unsupported.extend(file_report.unsupported)
        for rule in file_rules:
            if rule.rule_id in seen:
                continue
            seen.add(rule.rule_id)
            rules.append(rule)
    report.loaded = len(rules)
    return rules, report


def load_np_text(text: str, origin: str = "<memory>") -> Tuple[List[Rule], LoadReport]:
    report = LoadReport(path=origin)
    if _yaml is None:  # pragma: no cover
        raise RuntimeError("PyYAML is required to load Nosey Parker rules")
    try:
        doc = _yaml.safe_load(text) or {}
    except _yaml.YAMLError as exc:  # type: ignore[union-attr]
        raise ValueError(f"{origin}: invalid YAML: {exc}") from exc

    rules: List[Rule] = []
    for entry in doc.get("rules") or []:
        rule = _convert(entry, report)
        if rule is not None:
            rules.append(rule)
    report.loaded = len(rules)
    return rules, report


def _convert(entry: Dict[str, Any], report: LoadReport) -> Optional[Rule]:
    if not isinstance(entry, dict):
        return None
    rule_id = str(entry.get("id") or entry.get("name") or "").strip()
    pattern = entry.get("pattern")
    if not rule_id or not pattern:
        report.skipped.append((rule_id or "<unnamed>", "missing id or pattern"))
        return None
    try:
        regex = compile_re2(str(pattern))
    except re.error as exc:
        report.skipped.append((rule_id, f"regex rejected by Python re: {exc}"))
        return None

    prefilter = _anchor(str(pattern))
    return Rule(
        rule_id=rule_id,
        title=str(entry.get("name") or rule_id),
        regex=regex,
        severity=_np_severity(rule_id, entry),
        confidence=0.8,
        group=-1,  # Nosey Parker's secret is the first capture group
        tags=["pack", "noseyparker", _family(rule_id.replace("np.", ""))],
        prefilter=prefilter,
    )


def _anchor(pattern: str) -> Tuple[str, ...]:
    """Derive a lowercase literal anchor from a pattern's leading fixed text."""
    body = pattern.lstrip()
    # Skip a leading (?x)/(?i) flag group and a \b anchor.
    body = re.sub(r"^(?:\(\?[a-z]+\))+", "", body)
    body = re.sub(r"^\\b", "", body)
    body = body.lstrip("(")
    match = _LITERAL_PREFIX.match(body)
    if match:
        return (match.group(0).lower(),)
    return ()


def _np_severity(rule_id: str, entry: Dict[str, Any]) -> Severity:
    categories = {str(c).lower() for c in (entry.get("categories") or [])}
    if "secret" in categories:
        return Severity.HIGH
    if "identifier" in categories and "secret" not in categories:
        return Severity.MEDIUM
    return _severity(rule_id.replace("np.", ""))
