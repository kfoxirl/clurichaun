"""
Clurichaun command-line interface.
"""

from __future__ import annotations

import sys
from typing import List, Optional, Sequence, Tuple

import click

from . import report, scope
from .detect import DetectorConfig, SecretDetector
from .ingest import FileIngestor, IngestLimits
from .models import Finding, Severity, dedupe
from .patterns import ALL_TAGS, RULES
from .scanner import ScanConfig, ScannerEngine
from .scope import ALL_CATEGORIES, ScopeFilter

SEVERITIES = [s.value for s in Severity]


def _csv(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def _size(value: str) -> int:
    """Accept 100, 100k, 512M, 2G."""
    text = value.strip().lower()
    multipliers = {"k": 1024, "m": 1024**2, "g": 1024**3}
    if text and text[-1] in multipliers:
        return int(float(text[:-1]) * multipliers[text[-1]])
    return int(text)


class SizeParam(click.ParamType):
    name = "size"

    def convert(self, value, param, ctx):  # type: ignore[no-untyped-def]
        try:
            return _size(str(value))
        except ValueError:
            self.fail(f"{value!r} is not a size (e.g. 512k, 100M, 2G)", param, ctx)


SIZE = SizeParam()


@click.group(invoke_without_command=True, context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(report.TOOL_VERSION, prog_name=report.TOOL_NAME)
@click.pass_context
def main(ctx: click.Context) -> None:
    """Clurichaun — universal secret, credential and endpoint scanner."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@main.command("scan")
@click.argument("targets", nargs=-1, required=True, type=click.Path(exists=True))
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["table", "json", "sarif"]),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option("-o", "--output", type=click.Path(dir_okay=False), help="Write report to a file.")
@click.option("--unredact", is_flag=True, help="Print full secret values (dangerous).")
@click.option(
    "--min-confidence",
    type=click.FloatRange(0.0, 1.0),
    default=0.4,
    show_default=True,
    help="Drop findings below this confidence.",
)
@click.option(
    "--min-severity",
    type=click.Choice(SEVERITIES),
    default="low",
    show_default=True,
    help="Drop findings below this severity. Default excludes INFO (bare URLs/IPs); use 'info' for recon.",
)
@click.option(
    "--fail-on",
    type=click.Choice(SEVERITIES + ["never"]),
    default="never",
    show_default=True,
    help="Exit non-zero when a finding at or above this severity exists.",
)
@click.option(
    "--rule-pack",
    "rule_packs",
    multiple=True,
    help="Load a gitleaks-format TOML pack: a bundled name (see `clurichaun packs`) or a path.",
)
@click.option("--rules", help="Only these rule ids/prefixes/tags (comma separated).")
@click.option("--exclude-rules", help="Skip these rule ids/prefixes/tags.")
@click.option("--no-entropy", is_flag=True, help="Disable the entropy engine.")
@click.option("--no-decoders", is_flag=True, help="Do not re-scan base64/escape/percent/entity-decoded views.")
@click.option("--no-regex", is_flag=True, help="Disable the regex engine.")
@click.option("--no-keyname", is_flag=True, help="Disable structured key-name analysis.")
@click.option(
    "--scope-only",
    is_flag=True,
    help="Scan only paths inside the built-in target scope (see `clurichaun scope`).",
)
@click.option(
    "--category",
    "categories",
    multiple=True,
    type=click.Choice(ALL_CATEGORIES),
    help="Restrict to these target-scope categories (repeatable).",
)
@click.option("--include", "include_globs", multiple=True, help="Force-include glob.")
@click.option("--exclude", "exclude_globs", multiple=True, help="Force-exclude glob.")
@click.option("--all-dirs", is_flag=True, help="Descend into node_modules/vendor/etc.")
@click.option("--no-hidden", is_flag=True, help="Skip dotfiles and dotdirs.")
@click.option("--no-archives", is_flag=True, help="Do not unpack archives.")
@click.option("--no-binaries", is_flag=True, help="Do not carve strings from binaries.")
@click.option("--follow-symlinks", is_flag=True, help="Follow symlinks while walking.")
@click.option(
    "--max-file-size", type=SIZE, default="512M", show_default=True, help="Skip larger files."
)
@click.option(
    "--max-binary-size",
    type=SIZE,
    default="32M",
    show_default=True,
    help="Skip binaries larger than this (string carving gets expensive).",
)
@click.option(
    "--stream-threshold",
    type=SIZE,
    default="8M",
    show_default=True,
    help="Read files larger than this in chunks.",
)
@click.option("--archive-depth", type=int, default=3, show_default=True, help="Nesting limit.")
@click.option("--max-files", type=int, default=0, help="Stop after N files (0 = unlimited).")
@click.option(
    "--file-timeout",
    type=float,
    default=30.0,
    show_default=True,
    help="Per-file wall-clock budget in seconds (0 = unlimited).",
)
@click.option("-j", "--workers", type=int, default=0, help="Worker count (0 = cpu count).")
@click.option("--threads", is_flag=True, help="Use threads instead of processes (I/O bound).")
@click.option(
    "--git-history",
    is_flag=True,
    help="Also scan every blob in git history (finds committed-then-deleted secrets).",
)
@click.option("--git-since", help="With --git-history, limit to commits after this rev (e.g. HEAD~50).")
@click.option(
    "--staged",
    is_flag=True,
    help="Scan only git-staged content (pre-commit mode): fast, index-only.",
)
@click.option(
    "--verify",
    is_flag=True,
    help="Live-verify findings against their providers (READ-ONLY, sends secrets to GitHub/Slack/Stripe/OpenAI).",
)
@click.option("--verify-only", help="Restrict verification to these providers (comma separated: github,slack,stripe,openai).")
@click.option(
    "--fail-on-verified",
    is_flag=True,
    help="With --verify, exit non-zero only when a finding is confirmed ACTIVE.",
)
@click.option("--db", "db_path", type=click.Path(dir_okay=False), help="SQLite datastore for finding history (default: ~/.clurichaun/history.db).")
@click.option("--no-db", is_flag=True, help="Do not record findings to the history datastore.")
@click.option("--no-report", is_flag=True, help="Do not auto-save a JSON report (results are saved by default).")
@click.option("--incremental", is_flag=True, help="With the datastore, skip files unchanged since the last scan.")
@click.option("--token-efficiency", is_flag=True, help="Rescore fuzzy findings by BPE token efficiency (needs the [ml] extra).")
@click.option("--only-actionable", is_flag=True, help="Report only findings worth acting on now (verified-active, checksum-valid, or high-confidence).")
@click.option("--new-only", is_flag=True, help="With --db, report only findings not seen in a prior scan.")
@click.option("--baseline", type=click.Path(exists=True, dir_okay=False), help="Suppress fingerprints from a prior JSON report.")
@click.option("--max-rows", type=int, default=200, show_default=True, help="Table row cap (0 = all).")
@click.option("-q", "--quiet", is_flag=True, help="Suppress progress output.")
def scan(  # noqa: PLR0913 - a CLI is allowed its surface
    targets: Tuple[str, ...],
    output_format: str,
    output: Optional[str],
    unredact: bool,
    min_confidence: float,
    min_severity: str,
    fail_on: str,
    rule_packs: Tuple[str, ...],
    rules: Optional[str],
    exclude_rules: Optional[str],
    no_entropy: bool,
    no_decoders: bool,
    no_regex: bool,
    no_keyname: bool,
    scope_only: bool,
    categories: Tuple[str, ...],
    include_globs: Tuple[str, ...],
    exclude_globs: Tuple[str, ...],
    all_dirs: bool,
    no_hidden: bool,
    no_archives: bool,
    no_binaries: bool,
    follow_symlinks: bool,
    max_file_size: int,
    max_binary_size: int,
    stream_threshold: int,
    archive_depth: int,
    max_files: int,
    file_timeout: float,
    workers: int,
    threads: bool,
    git_history: bool,
    git_since: Optional[str],
    staged: bool,
    verify: bool,
    verify_only: Optional[str],
    fail_on_verified: bool,
    db_path: Optional[str],
    no_db: bool,
    no_report: bool,
    incremental: bool,
    token_efficiency: bool,
    only_actionable: bool,
    new_only: bool,
    baseline: Optional[str],
    max_rows: int,
    quiet: bool,
) -> None:
    """Scan TARGETS (files or directories) for secrets and configuration leakage."""
    baseline_fingerprints: set[str] = set()
    if baseline:
        try:
            baseline_fingerprints = report.load_baseline(baseline)
        except (OSError, ValueError) as exc:
            raise click.ClickException(f"baseline unreadable: {exc}") from exc

    # Results are persisted by default so a long scan is never lost to the
    # terminal scrollback: a history datastore plus an auto-saved JSON report.
    if not db_path and not no_db:
        db_path = str(_default_db_path())

    config = ScanConfig(
        roots=list(targets),
        scope=ScopeFilter(
            scope_only=scope_only,
            categories=frozenset(categories) if categories else None,
            include_globs=tuple(include_globs),
            exclude_globs=tuple(exclude_globs),
            follow_deny_dirs=all_dirs,
        ),
        limits=IngestLimits(
            max_file_size=max_file_size,
            max_binary_size=max_binary_size,
            stream_threshold=stream_threshold,
            max_archive_depth=archive_depth,
            scan_binaries=not no_binaries,
            scan_archives=not no_archives,
            follow_symlinks=follow_symlinks,
        ),
        detector=DetectorConfig(
            include_rules=_csv(rules) or None,
            exclude_rules=_csv(exclude_rules) or None,
            min_confidence=min_confidence,
            min_severity=Severity(min_severity),
            entropy_enabled=not no_entropy,
            decoders_enabled=not no_decoders,
            regex_enabled=not no_regex,
            keyname_enabled=not no_keyname,
            baseline=baseline_fingerprints,
            rule_packs=tuple(rule_packs),
        ),
        workers=workers,
        use_threads=threads,
        git_history=git_history,
        git_since=git_since,
        staged=staged,
        db_path=db_path,
        incremental=incremental,
        include_hidden=not no_hidden,
        max_files=max_files,
        file_timeout=file_timeout,
    )

    engine = ScannerEngine(config)
    progress = None if quiet else _progress_hook()
    findings = engine.run(progress=progress)
    if progress is not None:
        click.echo("", err=True)

    if verify:
        _run_verification(findings, verify_only, quiet, db_path)

    if token_efficiency:
        from .rescore import TokenEfficiency

        scorer = TokenEfficiency()
        if not scorer.available and not quiet:
            click.echo("--token-efficiency: tiktoken not installed (pip install 'clurichaun[ml]'); skipping", err=True)
        scorer.rescore(findings)

    if only_actionable:
        findings = [f for f in findings if f.actionability_rank >= 2]
    if new_only:
        findings = [f for f in findings if any("new since last scan" in n for n in f.notes)]

    findings.sort(
        key=lambda f: (-f.actionability_rank, -f.severity.rank, -f.confidence, f.logical_path, f.line)
    )

    if output_format == "table" and not output:
        report.render_table(
            findings, engine.stats, config.roots, unredact, max_rows=max_rows
        )
        # Terminal view shown; also auto-save a JSON snapshot so the results
        # survive the scrollback (unless the user opted out).
        if not no_report:
            _autosave_report(findings, engine.stats, config.roots, unredact, quiet)
    else:
        fmt = "json" if output_format == "table" else output_format
        text = report.render(fmt, findings, engine.stats, config.roots, unredact)
        if output:
            try:
                with open(output, "w", encoding="utf-8") as handle:
                    handle.write(text + "\n")
            except OSError as exc:
                raise click.ClickException(f"cannot write {output}: {exc}") from exc
            if not quiet:
                click.echo(f"wrote {len(findings)} finding(s) to {output}", err=True)
        else:
            click.echo(text)

    if db_path and not quiet:
        click.echo(f"history: {db_path}", err=True)

    if fail_on_verified:
        from .models import Verified

        active = [f for f in findings if f.verified is Verified.ACTIVE]
        sys.exit(1 if active else 0)
    threshold = None if fail_on == "never" else Severity(fail_on)
    sys.exit(report.exit_code(findings, threshold))


def _run_verification(findings, verify_only, quiet, db_path=None) -> None:  # type: ignore[no-untyped-def]
    from .verify import Verifier, VerifyConfig

    only = None
    if verify_only:
        only = frozenset(p.strip().lower() for p in verify_only.split(",") if p.strip())
    cfg = VerifyConfig(enabled=True, only=only)
    try:
        verifier = Verifier(cfg)
    except Exception as exc:  # noqa: BLE001
        raise click.ClickException(f"verification unavailable: {exc}") from exc

    providers = verifier.providers_for(findings)
    if not providers:
        if not quiet:
            click.echo("--verify: no findings have a supported verifier; skipping", err=True)
        return
    if not quiet:
        click.echo(
            "--verify: sending candidate secrets to " + ", ".join(providers)
            + " (read-only). Ctrl-C to abort.",
            err=True,
        )
    store = None
    if db_path:
        from .store import open_store
        from .models import Verified

        store = open_store(db_path)
    try:
        # Reuse cached verdicts, then persist new ones.
        if store is not None:
            from .models import Verified

            uncached = []
            for f in findings:
                cached = store.cached_verdict(f.secret_v2 or f.secret)
                if cached is not None:
                    f.verified, f.verification_note = cached[0], cached[1] or None
                else:
                    uncached.append(f)
            verifier.run(uncached)
            for f in uncached:
                if f.verified is not Verified.UNKNOWN:
                    store.cache_verdict(f.secret_v2 or f.secret, f.verified, f.verification_note or "")
            store.commit()
            store.close()
        else:
            verifier.run(findings)
    except ImportError as exc:
        raise click.ClickException(
            f"--verify needs the web extra: pip install 'clurichaun[web]' ({exc})"
        ) from exc


def _clurichaun_home():  # type: ignore[no-untyped-def]
    """The ~/.clurichaun state directory (override with CLURICHAUN_HOME)."""
    import os
    from pathlib import Path

    base = os.environ.get("CLURICHAUN_HOME")
    home = Path(base) if base else Path.home() / ".clurichaun"
    home.mkdir(parents=True, exist_ok=True)
    return home


def _default_db_path():  # type: ignore[no-untyped-def]
    return _clurichaun_home() / "history.db"


def _autosave_report(findings, stats, roots, unredact, quiet):  # type: ignore[no-untyped-def]
    """Write a timestamped JSON snapshot of the scan under ~/.clurichaun/reports."""
    from datetime import datetime, timezone

    reports = _clurichaun_home() / "reports"
    try:
        reports.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        label = _safe_label(roots[0] if roots else "scan")
        path = reports / f"{stamp}_{label}.json"
        path.write_text(
            report.render("json", findings, stats, roots, unredact) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        if not quiet:
            click.echo(f"could not auto-save report: {exc}", err=True)
        return
    if not quiet:
        click.echo(f"report: {path}", err=True)


def _safe_label(root: str) -> str:
    import re

    name = root.rstrip("/\\").replace("\\", "/").split("/")[-1] or "root"
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:48]


def _emit(findings, stats, roots, output_format, output, unredact, quiet, max_rows=200):  # type: ignore[no-untyped-def]
    """Render findings to a table, or JSON/SARIF to stdout or a file."""
    if output_format == "table" and not output:
        report.render_table(findings, stats, roots, unredact, max_rows=max_rows)
        return
    fmt = "json" if output_format == "table" else output_format
    text = report.render(fmt, findings, stats, roots, unredact)
    if output:
        try:
            with open(output, "w", encoding="utf-8") as handle:
                handle.write(text + "\n")
        except OSError as exc:
            raise click.ClickException(f"cannot write {output}: {exc}") from exc
        if not quiet:
            click.echo(f"wrote {len(findings)} finding(s) to {output}", err=True)
    else:
        click.echo(text)


def _progress_hook():  # type: ignore[no-untyped-def]
    state = {"count": 0}

    def hook(path: str, index: int) -> None:
        state["count"] = index
        if index % 25 == 0 or index == 1:
            click.echo(f"\rscanned {index} files…", nl=False, err=True)

    return hook


@main.command("rules")
@click.option("--tag", help="Only rules carrying this tag.")
def list_rules(tag: Optional[str]) -> None:
    """List the detection ruleset."""
    click.echo(f"{'RULE':<36} {'SEVERITY':<9} {'CONF':<5} TAGS")
    for rule in RULES:
        if tag and tag not in rule.tags:
            continue
        click.echo(
            f"{rule.rule_id:<36} {rule.severity.value:<9} "
            f"{rule.confidence:<5.2f} {','.join(rule.tags)}"
        )
    click.echo(f"\n{len(RULES)} rules; tags: {', '.join(ALL_TAGS)}")


@main.command("packs")
@click.argument("pack", required=False)
def packs(pack: Optional[str]) -> None:
    """List bundled rule packs, or describe what loading one yields."""
    from .rules_toml import bundled_packs, load_any, resolve_pack

    available = bundled_packs()
    if pack is None:
        if not available:
            click.echo("no bundled rule packs")
            return
        for name, path in available.items():
            rules, report = load_any(path)
            click.echo(f"{name:<12} {report.loaded:>4} rules  {path}")
        click.echo("\nLoad with: clurichaun scan <path> --rule-pack <name|file.toml>")
        return

    try:
        rules, report = load_any(resolve_pack(pack))
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo(report.summary)
    for rule_id, reason in report.skipped:
        click.echo(f"  skipped {rule_id}: {reason}")
    seen: dict[str, int] = {}
    for rule in rules:
        seen[rule.severity.value] = seen.get(rule.severity.value, 0) + 1
    click.echo("  severities: " + ", ".join(f"{k}={v}" for k, v in sorted(seen.items())))


@main.command("scope")
def show_scope() -> None:
    """Show the target-scope categories and their matchers."""
    for category in ALL_CATEGORIES:
        spec = scope.SCOPE[category]
        click.echo(click.style(category, bold=True))
        for kind in ("ext", "name", "glob"):
            values: Sequence[str] = spec.get(kind, ())
            if values:
                click.echo(f"  {kind}: {' '.join(values)}")
    click.echo(click.style("\ndenied extensions", bold=True))
    click.echo("  " + " ".join(sorted(scope.DENY_EXT)))
    click.echo(click.style("skipped directories", bold=True))
    click.echo("  " + " ".join(sorted(scope.DENY_DIRS)))


@main.command("classify")
@click.argument("paths", nargs=-1, required=True)
def classify(paths: Tuple[str, ...]) -> None:
    """Report which target-scope categories given paths fall into."""
    for path in paths:
        cats = sorted(scope.categories_of(path))
        boost = scope.interest_boost(path)
        label = ", ".join(cats) if cats else "-"
        click.echo(f"{path}\n  categories: {label}\n  confidence boost: +{boost:.2f}")


@main.command("revoke")
@click.argument("report_path", metavar="REPORT", type=click.Path(exists=True, dir_okay=False))
@click.option("--confirm", is_flag=True, help="Actually revoke (default is a dry-run plan).")
@click.option("--yes", is_flag=True, help="Skip the interactive confirmation prompt (with --confirm).")
def revoke_cmd(report_path: str, confirm: bool, yes: bool) -> None:
    """Revoke verified-ACTIVE credentials listed in a scan JSON REPORT.

    Reads a report produced by `scan --verify --unredact -f json` (the raw secret
    is needed to revoke). Dry-run by default: shows what would be revoked and
    which providers need manual action. Only verified-ACTIVE findings are ever
    touched, and only Slack self-revoke is automated today.
    """
    import json as _json

    from .models import Detector, Finding, GitContext, Severity, Verified
    from .revoke import Revoker

    try:
        with open(report_path, encoding="utf-8") as handle:
            doc = _json.load(handle)
    except (OSError, ValueError) as exc:
        raise click.ClickException(f"cannot read report: {exc}") from exc

    rows = doc.get("findings", []) if isinstance(doc, dict) else doc
    findings: List[Finding] = []
    for row in rows:
        if row.get("verified") != "active":
            continue
        if "..." in str(row.get("secret", "")):
            raise click.ClickException(
                "report is redacted; re-run `scan --verify --unredact -f json` so revocation has the raw secret"
            )
        findings.append(
            Finding(
                rule_id=row.get("rule_id", ""),
                title=row.get("title", ""),
                detector=Detector.REGEX,
                severity=Severity(row.get("severity", "info")),
                logical_path=row.get("logical_path", ""),
                source_path=row.get("source_path", ""),
                line=int(row.get("line", 0)),
                column=int(row.get("column", 1)),
                secret=row.get("secret", ""),
                secret_v2=row.get("secret_v2"),
                match_context=row.get("match_context", ""),
                verified=Verified.ACTIVE,
            )
        )

    revoker = Revoker()
    plans = revoker.plan(findings)
    if not plans:
        click.echo("no verified-active findings to revoke.")
        return

    click.echo(f"{len(plans)} verified-active finding(s):")
    for plan in plans:
        kind = "AUTO" if plan.automated else "MANUAL"
        click.echo(f"  [{kind}] {plan.finding.rule_id} {plan.finding.redacted()} — {plan.detail}")

    automated = [p for p in plans if p.automated]
    if not confirm:
        click.echo(f"\ndry-run. {len(automated)} can be auto-revoked; re-run with --confirm to do it.")
        return
    if not automated:
        click.echo("\nnothing can be auto-revoked; act on the MANUAL items above.")
        return
    if not yes and not click.confirm(f"\nRevoke {len(automated)} credential(s)? This cannot be undone"):
        click.echo("aborted.")
        return

    for result in revoker.execute(automated):
        mark = "revoked" if result.ok else "FAILED"
        click.echo(f"  {mark}: {result.finding.rule_id} — {result.detail}")


@main.command("scan-bucket")
@click.argument("uri")
@click.option("-f", "--format", "output_format", type=click.Choice(["table", "json", "sarif"]), default="table", show_default=True)
@click.option("-o", "--output", type=click.Path(dir_okay=False))
@click.option("--unredact", is_flag=True)
@click.option("--rule-pack", "rule_packs", multiple=True)
@click.option("--fail-on", type=click.Choice(SEVERITIES + ["never"]), default="never", show_default=True)
@click.option("-q", "--quiet", is_flag=True)
def scan_bucket(uri, output_format, output, unredact, rule_packs, fail_on, quiet):  # type: ignore[no-untyped-def]
    """Scan an object-storage bucket (s3://bucket/prefix or gs://bucket/prefix)."""
    from .cloudsource import make_source

    try:
        source = make_source(uri)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    except ImportError as exc:
        raise click.ClickException(f"scan-bucket needs the cloud extra: pip install 'clurichaun[cloud]' ({exc})") from exc

    config = ScanConfig(roots=[uri], scope=ScopeFilter(),
                        detector=DetectorConfig(rule_packs=tuple(rule_packs)), workers=1)
    engine = ScannerEngine(config)
    findings = engine.scan_blob_stream(source.blobs(engine.stats))
    findings.sort(key=lambda f: (-f.actionability_rank, -f.severity.rank, -f.confidence))
    _emit(findings, engine.stats, [uri], output_format, output, unredact, quiet)
    sys.exit(report.exit_code(findings, None if fail_on == "never" else Severity(fail_on)))


@main.command("scan-github")
@click.argument("target")
@click.option("--token", envvar="GITHUB_TOKEN", help="GitHub token (or set GITHUB_TOKEN).")
@click.option("-f", "--format", "output_format", type=click.Choice(["table", "json", "sarif"]), default="table", show_default=True)
@click.option("-o", "--output", type=click.Path(dir_okay=False))
@click.option("--unredact", is_flag=True)
@click.option("--rule-pack", "rule_packs", multiple=True)
@click.option("--fail-on", type=click.Choice(SEVERITIES + ["never"]), default="never", show_default=True)
@click.option("-q", "--quiet", is_flag=True)
def scan_github(target, token, output_format, output, unredact, rule_packs, fail_on, quiet):  # type: ignore[no-untyped-def]
    """Scan a GitHub repo or org's issue/PR comment bodies (owner/repo or owner).

    A common leak surface a clone never sees — tokens pasted into bug reports and
    review threads. Read-only; TARGET is `owner/repo` or `owner` (whole org/user).
    """
    from .scmsource import GitHubSource

    owner, _, repo = target.partition("/")
    if not owner:
        raise click.ClickException("TARGET must be owner/repo or owner")
    try:
        source = GitHubSource(owner=owner, repo=repo or None, token=token)
    except ImportError as exc:
        raise click.ClickException(f"scan-github needs the web extra: pip install 'clurichaun[web]' ({exc})") from exc

    config = ScanConfig(roots=[target], scope=ScopeFilter(),
                        detector=DetectorConfig(rule_packs=tuple(rule_packs)), workers=1)
    engine = ScannerEngine(config)
    findings = engine.scan_blob_stream(source.blobs(engine.stats))
    findings.sort(key=lambda f: (-f.actionability_rank, -f.severity.rank, -f.confidence))
    _emit(findings, engine.stats, [target], output_format, output, unredact, quiet)
    sys.exit(report.exit_code(findings, None if fail_on == "never" else Severity(fail_on)))


@main.command("scan-image")
@click.argument("image")
@click.option("-f", "--format", "output_format", type=click.Choice(["table", "json", "sarif"]), default="table", show_default=True)
@click.option("-o", "--output", type=click.Path(dir_okay=False))
@click.option("--unredact", is_flag=True)
@click.option("--rule-pack", "rule_packs", multiple=True)
@click.option("--fail-on", type=click.Choice(SEVERITIES + ["never"]), default="never", show_default=True)
@click.option("--engine", type=click.Choice(["docker", "podman"]), default="docker", show_default=True)
@click.option("-q", "--quiet", is_flag=True)
def scan_image(
    image: str,
    output_format: str,
    output: Optional[str],
    unredact: bool,
    rule_packs: Tuple[str, ...],
    fail_on: str,
    engine: str,
    quiet: bool,
) -> None:
    """Scan a container IMAGE (name or a saved .tar) for secrets in its layers.

    A saved image is a tar of layer tars, which the normal ingestion pipeline
    already unpacks — so a name is saved to a temp tar and scanned the same way.
    """
    import os
    import subprocess
    import tempfile

    tarball = image
    temp: Optional[str] = None
    if not os.path.isfile(image):
        # An image name: materialise it with `docker save`.
        fd, temp = tempfile.mkstemp(suffix=".tar", prefix="clurichaun-img-")
        os.close(fd)
        if not quiet:
            click.echo(f"saving {image} via {engine}…", err=True)
        try:
            subprocess.run([engine, "save", "-o", temp, image], check=True, capture_output=True)
        except FileNotFoundError as exc:
            os.unlink(temp)
            raise click.ClickException(f"{engine} not found; pass a saved .tar instead ({exc})") from exc
        except subprocess.CalledProcessError as exc:
            os.unlink(temp)
            raise click.ClickException(
                f"{engine} save failed: {exc.stderr.decode('utf-8', 'replace')[:200]}"
            ) from exc
        tarball = temp

    try:
        config = ScanConfig(
            roots=[tarball],
            scope=ScopeFilter(),  # scan every layer file
            detector=DetectorConfig(rule_packs=tuple(rule_packs)),
            workers=1,
        )
        eng = ScannerEngine(config)
        findings = eng.run()
        # Re-label the temp path back to the image name for the report.
        for finding in findings:
            finding.logical_path = finding.logical_path.replace(tarball, image, 1)
            finding.source_path = image
        findings.sort(key=lambda f: (-f.severity.rank, -f.confidence))
        _emit(findings, eng.stats, [image], output_format, output, unredact, quiet)
    finally:
        if temp and os.path.isfile(temp):
            os.unlink(temp)

    threshold = None if fail_on == "never" else Severity(fail_on)
    sys.exit(report.exit_code(findings, threshold))


@main.command("scan-web")
@click.argument("url")
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["table", "json", "sarif"]),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option("-o", "--output", type=click.Path(dir_okay=False), help="Write report to a file.")
@click.option("--unredact", is_flag=True, help="Print full secret values (dangerous).")
@click.option("--depth", type=int, default=3, show_default=True, help="Crawl depth.")
@click.option("--max-files", type=int, default=1000, show_default=True, help="Resource cap.")
@click.option("--timeout", type=int, default=10, show_default=True, help="HTTP timeout (s).")
@click.option("--delay", type=float, default=0.2, show_default=True, help="Seconds between requests.")
@click.option(
    "--max-bytes", type=SIZE, default="32M", show_default=True, help="Per-resource download cap."
)
@click.option(
    "--no-robots",
    is_flag=True,
    help="Ignore robots.txt. Only for hosts you are authorised to test.",
)
@click.option(
    "--no-ai-txt",
    is_flag=True,
    help="Ignore ai.txt policy and its Rate-Limit. Only for hosts you are authorised to test.",
)
@click.option("--no-llms-txt", is_flag=True, help="Do not use llms.txt as a seed index.")
@click.option("--any-host", is_flag=True, help="Follow assets off the starting host.")
@click.option(
    "--min-confidence", type=click.FloatRange(0.0, 1.0), default=0.4, show_default=True,
    help="Drop findings below this confidence.",
)
@click.option(
    "--min-severity", type=click.Choice(SEVERITIES), default="info", show_default=True,
    help="Drop findings below this severity.",
)
@click.option(
    "--fail-on", type=click.Choice(SEVERITIES + ["never"]), default="never", show_default=True,
    help="Exit non-zero when a finding at or above this severity exists.",
)
@click.option("--no-decoders", is_flag=True, help="Skip decoded views of fetched content.")
@click.option("-q", "--quiet", is_flag=True, help="Suppress progress output.")
def scan_web(  # noqa: PLR0913 - a CLI is allowed its surface
    url: str,
    output_format: str,
    output: Optional[str],
    unredact: bool,
    depth: int,
    max_files: int,
    timeout: int,
    delay: float,
    max_bytes: int,
    no_robots: bool,
    no_ai_txt: bool,
    no_llms_txt: bool,
    any_host: bool,
    min_confidence: float,
    min_severity: str,
    fail_on: str,
    no_decoders: bool,
    quiet: bool,
) -> None:
    """Crawl URL and scan everything it serves — the same engine as `scan`.

    Fetched bytes go through the normal ingestion pipeline, so remote archives,
    source maps and binaries are handled exactly as they are on disk.
    """
    try:
        from .web.crawler import WebConfig, WebCrawler
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise click.ClickException(
            f"scan-web needs the web extra: pip install 'clurichaun[web]' ({exc})"
        ) from exc

    crawler = WebCrawler(
        WebConfig(
            url=url,
            depth=depth,
            max_files=max_files,
            timeout=timeout,
            delay=delay,
            max_bytes=max_bytes,
            respect_robots=not no_robots,
            respect_ai_txt=not no_ai_txt,
            use_llms_txt=not no_llms_txt,
            same_host_only=not any_host,
        )
    )
    detector = SecretDetector(
        DetectorConfig(
            min_confidence=min_confidence,
            min_severity=Severity(min_severity),
            decoders_enabled=not no_decoders,
        )
    )
    ingestor = FileIngestor()
    findings: List[Finding] = []
    stats = crawler.stats

    fetched_any = False
    for fetched in crawler.crawl_and_fetch():
        if not fetched_any and crawler.ai_policy.declared and not quiet:
            click.echo(crawler.ai_policy.summary(), err=True)
        fetched_any = True
        if not quiet:
            click.echo(f"scanning {fetched.url}", err=True)
        for blob in ingestor.blobs_from_bytes(
            fetched.content, fetched.logical_path, fetched.url, 0, stats
        ):
            findings.extend(detector.scan(blob))

    findings = dedupe(findings)
    findings.sort(key=lambda f: (-f.severity.rank, -f.confidence, f.logical_path, f.line))

    if output_format == "table" and not output:
        report.render_table(findings, stats, [url], unredact)
    else:
        fmt = "json" if output_format == "table" else output_format
        text = report.render(fmt, findings, stats, [url], unredact)
        if output:
            try:
                with open(output, "w", encoding="utf-8") as handle:
                    handle.write(text + "\n")
            except OSError as exc:
                raise click.ClickException(f"cannot write {output}: {exc}") from exc
            if not quiet:
                click.echo(f"wrote {len(findings)} finding(s) to {output}", err=True)
        else:
            click.echo(text)

    threshold = None if fail_on == "never" else Severity(fail_on)
    sys.exit(report.exit_code(findings, threshold))


if __name__ == "__main__":  # pragma: no cover
    main()
