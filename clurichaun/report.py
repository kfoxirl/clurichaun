"""Output renderers: JSON, SARIF 2.1.0, and a human CLI table."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, TextIO

from . import paths
from .models import Finding, ScanStats, Severity, Verified, redact, scrub
from .patterns import RULES_BY_ID

TOOL_NAME = "clurichaun"
TOOL_VERSION = "0.3.0"
INFO_URI = "https://github.com/kfoxirl/clurichaun"

try:  # pragma: no cover - optional dependency
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
except Exception:  # pragma: no cover
    Console = None  # type: ignore[assignment]

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_ANSI = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}
_RESET = "\033[0m"


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #


def render_json(
    findings: Sequence[Finding],
    stats: ScanStats,
    roots: Sequence[str],
    unredact: bool = False,
) -> str:
    payload: Dict[str, Any] = {
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "scan": {
            "started": None,
            "completed": datetime.now(timezone.utc).isoformat(),
            "roots": list(roots),
            "redacted": not unredact,
        },
        "summary": summarize(findings, stats),
        "findings": _finding_dicts(findings, unredact),
        "errors": stats.errors[:500],
    }
    return json.dumps(payload, indent=2, sort_keys=False)


def _finding_dicts(
    findings: Sequence[Finding], unredact: bool
) -> List[Dict[str, Any]]:
    """Serialise findings, scrubbing every known secret out of every context."""
    rows = [f.to_dict(unredact) for f in findings]
    if unredact:
        return rows
    secrets = [f.secret for f in findings]
    for row in rows:
        row["match_context"] = scrub(row["match_context"], secrets)
    return rows


def summarize(findings: Sequence[Finding], stats: ScanStats) -> Dict[str, Any]:
    by_severity: Dict[str, int] = {s.value: 0 for s in Severity}
    by_rule: Dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity.value] += 1
        by_rule[finding.rule_id] = by_rule.get(finding.rule_id, 0) + 1
    return {
        "findings": len(findings),
        "by_severity": by_severity,
        "by_rule": dict(sorted(by_rule.items(), key=lambda kv: -kv[1])),
        "files_seen": stats.files_seen,
        "files_scanned": stats.files_scanned,
        "files_skipped": stats.files_skipped,
        "archives_opened": stats.archives_opened,
        "bytes_scanned": stats.bytes_scanned,
        "errors": len(stats.errors),
    }


# --------------------------------------------------------------------------- #
# SARIF
# --------------------------------------------------------------------------- #

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def render_sarif(
    findings: Sequence[Finding],
    stats: ScanStats,
    roots: Sequence[str],
    unredact: bool = False,
) -> str:
    rule_ids = sorted({f.rule_id for f in findings})
    rules = [_sarif_rule(rule_id, findings) for rule_id in rule_ids]
    index = {rule_id: position for position, rule_id in enumerate(rule_ids)}

    secrets = [f.secret for f in findings]
    results = []
    for finding in findings:
        secret = finding.secret if unredact else redact(finding.secret)
        snippet = finding.match_context if unredact else scrub(finding.match_context, secrets)
        results.append(
            {
                "ruleId": finding.rule_id,
                "ruleIndex": index[finding.rule_id],
                "level": _SARIF_LEVEL[finding.severity],
                "message": {
                    "text": f"{finding.title}: {secret}"
                    + (f" (key: {finding.key_name})" if finding.key_name else "")
                },
                "partialFingerprints": {"clurichaun/v1": finding.fingerprint},
                "properties": {
                    "detector": finding.detector.value,
                    "confidence": finding.confidence,
                    "entropy": finding.entropy,
                    "severity": finding.severity.value,
                    "verified": finding.verified.value,
                    "actionability": finding.actionability,
                    "logicalPath": finding.logical_path,
                    **({"access": finding.access} if finding.access else {}),
                    **(
                        {
                            "commit": finding.git.commit,
                            "author": finding.git.author,
                            "email": finding.git.email,
                            "date": finding.git.date,
                        }
                        if finding.git
                        else {}
                    ),
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": _uri(finding.source_path),
                                "uriBaseId": "SRCROOT",
                            },
                            "region": {
                                "startLine": max(1, finding.line),
                                "startColumn": max(1, finding.column),
                                "snippet": {"text": snippet},
                            },
                        },
                        "logicalLocations": [
                            {"name": finding.logical_path, "kind": "member"}
                        ],
                    }
                ],
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": INFO_URI,
                        "rules": rules,
                    }
                },
                "originalUriBaseIds": {
                    "SRCROOT": {"uri": _dir_uri(roots[0] if roots else ".")}
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc)
                        .isoformat(timespec="seconds")
                        .replace("+00:00", "Z"),
                        "toolExecutionNotifications": [
                            {"level": "warning", "message": {"text": error}}
                            for error in stats.errors[:100]
                        ],
                    }
                ],
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _sarif_rule(rule_id: str, findings: Sequence[Finding]) -> Dict[str, Any]:
    sample = next(f for f in findings if f.rule_id == rule_id)
    rule = RULES_BY_ID.get(rule_id)
    tags = ["security", "secret"] + (rule.tags if rule else [sample.detector.value])
    return {
        "id": rule_id,
        "name": rule_id.replace(".", "-"),
        "shortDescription": {"text": sample.title},
        "fullDescription": {
            "text": f"{sample.title} detected by the {sample.detector.value} engine."
        },
        "defaultConfiguration": {"level": _SARIF_LEVEL[sample.severity]},
        "properties": {
            "tags": tags,
            "security-severity": _SECURITY_SEVERITY[sample.severity],
        },
    }


def _uri(path: str) -> str:
    return paths.display(path).lstrip("/")


def _dir_uri(path: str) -> str:
    normalized = paths.strip_long_prefix(paths.normalize(path)).replace("\\", "/")
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return f"file://{normalized.rstrip('/')}/"


# --------------------------------------------------------------------------- #
# Table
# --------------------------------------------------------------------------- #


def render_table(
    findings: Sequence[Finding],
    stats: ScanStats,
    roots: Sequence[str],
    unredact: bool = False,
    stream: Optional[TextIO] = None,
    max_rows: int = 0,
) -> None:
    stream = stream or sys.stdout
    rows = list(findings[:max_rows]) if max_rows else list(findings)
    root = paths.normalize(roots[0]) if len(roots) == 1 else None

    if Console is not None:
        _rich_table(rows, findings, stats, unredact, stream, root)
        return
    _plain_table(rows, findings, stats, unredact, stream, root)


def short_path(logical_path: str, root: Optional[str]) -> str:
    """Trim the scan root off a (possibly archive-nested) logical path.

    Remote scans pass a URL as the root, which shares no prefix with the
    host-shaped logical paths — relativising there yields `../../host/file`, so
    only trim when the path actually lives under the root.
    """
    if not root:
        return logical_path
    head, sep, tail = logical_path.partition("!/")
    if not head.replace("\\", "/").startswith(paths.strip_long_prefix(root).replace("\\", "/")):
        return logical_path
    return paths.display(head, root) + sep + tail


_VERIFIED_MARK = {
    Verified.ACTIVE: ("ACTIVE", "bold red"),
    Verified.INACTIVE: ("dead", "green"),
    Verified.ERROR: ("err?", "yellow"),
    Verified.UNSUPPORTED: ("n/a", "dim"),
    Verified.UNKNOWN: ("-", "dim"),
}


def _verified_cell(verified: Verified):  # type: ignore[no-untyped-def]
    label, style = _VERIFIED_MARK[verified]
    return Text(label, style=style)


def _rich_table(
    rows: Sequence[Finding],
    findings: Sequence[Finding],
    stats: ScanStats,
    unredact: bool,
    stream: TextIO,
    root: Optional[str] = None,
) -> None:  # pragma: no cover - visual
    console = Console(file=stream, highlight=False)
    table = Table(
        title=f"clurichaun — {len(findings)} finding(s)",
        title_style="bold",
        header_style="bold",
        expand=True,
        show_lines=False,
    )
    show_verified = any(f.verified is not Verified.UNKNOWN for f in findings)
    table.add_column("Sev", width=8, no_wrap=True)
    table.add_column("Rule", width=28, no_wrap=True)
    table.add_column("Location", overflow="fold")
    table.add_column("Secret", overflow="fold")
    table.add_column("Conf", width=5, justify="right")
    if show_verified:
        table.add_column("Live", width=8, no_wrap=True)

    for finding in rows:
        secret = finding.secret if unredact else finding.redacted()
        cells = [
            Text(finding.severity.value.upper(), style=_SEVERITY_STYLE[finding.severity]),
            finding.rule_id,
            f"{short_path(finding.logical_path, root)}:{finding.line}",
            secret,
            f"{finding.confidence:.2f}",
        ]
        if show_verified:
            cells.append(_verified_cell(finding.verified))
        table.add_row(*cells)

    console.print(table)
    if len(rows) < len(findings):
        console.print(f"[dim]… {len(findings) - len(rows)} more suppressed by --max-rows[/dim]")
    console.print(_footer(findings, stats))


def _plain_table(
    rows: Sequence[Finding],
    findings: Sequence[Finding],
    stats: ScanStats,
    unredact: bool,
    stream: TextIO,
    root: Optional[str] = None,
) -> None:
    color = stream.isatty()
    header = f"{'SEVERITY':<9} {'RULE':<28} {'CONF':<5} LOCATION"
    print(header, file=stream)
    print("-" * len(header), file=stream)
    for finding in rows:
        secret = finding.secret if unredact else finding.redacted()
        prefix = _ANSI[finding.severity] if color else ""
        suffix = _RESET if color else ""
        print(
            f"{prefix}{finding.severity.value.upper():<9}{suffix} "
            f"{finding.rule_id:<28} {finding.confidence:<5.2f} "
            f"{short_path(finding.logical_path, root)}:{finding.line}  {secret}",
            file=stream,
        )
    if len(rows) < len(findings):
        print(f"... {len(findings) - len(rows)} more suppressed by --max-rows", file=stream)
    print(_footer(findings, stats), file=stream)


def _footer(findings: Sequence[Finding], stats: ScanStats) -> str:
    counts = summarize(findings, stats)["by_severity"]
    parts = [
        f"{name}={count}" for name, count in counts.items() if count
    ] or ["no findings"]
    return (
        f"\n{' '.join(parts)}  |  files scanned={stats.files_scanned} "
        f"skipped={stats.files_skipped} archives={stats.archives_opened} "
        f"bytes={stats.bytes_scanned} errors={len(stats.errors)}"
    )


# --------------------------------------------------------------------------- #


def render(
    fmt: str,
    findings: Sequence[Finding],
    stats: ScanStats,
    roots: Sequence[str],
    unredact: bool = False,
) -> str:
    if fmt == "json":
        return render_json(findings, stats, roots, unredact)
    if fmt == "sarif":
        return render_sarif(findings, stats, roots, unredact)
    raise ValueError(f"unknown format: {fmt}")


def load_baseline(path: str) -> set[str]:
    """Read fingerprints out of a previous JSON report to suppress known findings."""
    with open(path, "r", encoding="utf-8") as handle:
        doc = json.load(handle)
    if isinstance(doc, dict):
        items: Iterable[Any] = doc.get("findings", [])
    elif isinstance(doc, list):
        items = doc
    else:
        return set()
    out: set[str] = set()
    for item in items:
        if isinstance(item, dict) and item.get("fingerprint"):
            out.add(str(item["fingerprint"]))
        elif isinstance(item, str):
            out.add(item)
    return out


def exit_code(findings: Sequence[Finding], fail_on: Optional[Severity]) -> int:
    if fail_on is None:
        return 0
    return 1 if any(f.severity.rank >= fail_on.rank for f in findings) else 0


def group_by_file(findings: Sequence[Finding]) -> Dict[str, List[Finding]]:
    grouped: Dict[str, List[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.logical_path, []).append(finding)
    return grouped
