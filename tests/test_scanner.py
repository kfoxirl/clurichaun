from __future__ import annotations

import io
import json
import time
import zipfile
from pathlib import Path

import pytest

from clurichaun import entropy, ingest, parsers, report, scope
from clurichaun.detect import DetectorConfig, SecretDetector
from clurichaun.models import Blob, ScanStats, Severity, redact
from clurichaun.scanner import ScanConfig, ScannerEngine

AWS_KEY = "AKIA" + "Q7JZ3MPLXK2NRTVW"
AWS_SECRET = "Xk9Qw2mZ7pLt4RvB8NcJ3HdF6SyA1GuE5TrKoWiP"
GITHUB_TOKEN = "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"  # checksum-valid


def detect(text: str, path: str = "sample.txt", **kwargs: object) -> list:
    config = DetectorConfig(min_confidence=0.0, **kwargs)  # type: ignore[arg-type]
    blob = Blob(logical_path=path, source_path=path, text=text)
    return SecretDetector(config).scan(blob)


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #


def test_aws_access_key_detected() -> None:
    findings = detect(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n")
    assert any(f.rule_id == "aws.access-key-id" for f in findings)
    assert all(f.severity is not Severity.INFO for f in findings if "aws" in f.rule_id)


def test_aws_secret_requires_key_context() -> None:
    findings = detect(f"aws_secret_access_key = {AWS_SECRET}\n")
    assert any(f.rule_id == "aws.secret-access-key" for f in findings)


def test_documented_fakes_suppressed() -> None:
    findings = detect("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    assert not [f for f in findings if f.rule_id == "aws.access-key-id"]


def test_github_token_and_private_key() -> None:
    text = f"token: {GITHUB_TOKEN}\n-----BEGIN RSA PRIVATE KEY-----\n"
    ids = {f.rule_id for f in detect(text)}
    assert "github.token" in ids
    assert "crypto.private-key" in ids


def test_jwt_structure_validated() -> None:
    good = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        ".dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    )
    assert any(f.rule_id == "jwt" for f in detect(good))
    bad = "eyJub3RqcGVnIjoxfQ.YWJjZGVmZ2hp.c2lnbmF0dXJl"
    assert not [f for f in detect(bad) if f.rule_id == "jwt"]


def test_database_uri_with_credentials() -> None:
    text = "DATABASE_URL=postgres://svc_user:Hunter2Hunter2@db.prod.example.com:5432/app\n"
    assert any(f.rule_id == "generic.database-uri" for f in detect(text, ".env"))


def test_inline_ignore_respected() -> None:
    text = f"key = {GITHUB_TOKEN}  # clurichaun:ignore\n"
    assert not detect(text)


def test_uuid_and_git_sha_not_entropy_findings() -> None:
    text = (
        "id = 550e8400-e29b-41d4-a716-446655440000\n"
        "commit = 8f14e45fceea167a5a36dedd4bea2543a1b2c3d4\n"
    )
    assert not [f for f in detect(text) if f.detector.value == "entropy"]


def test_entropy_finds_base64_blob() -> None:
    text = "SESSION_KEY=k4Jd8Zx2Qw7Lp0Vt5Ry9Bn3Mc6Hs1Ae4Gu7Ti2Ko5Pz8Xv==\n"
    findings = detect(text, ".env")
    assert any(f.detector.value in ("entropy", "keyname") for f in findings)


def test_safe_context_suppresses_hashes() -> None:
    text = 'integrity: "sha512-Qw7Lp0Vt5Ry9Bn3Mc6Hs1Ae4Gu7Ti2Ko5Pz8XvJd8Zx2k4=="\n'
    assert not [f for f in detect(text, "package-lock.json") if f.detector.value == "entropy"]


def test_keyname_pass_on_nested_json() -> None:
    doc = json.dumps({"services": {"redis": {"auth_token": "s3cr3t-Hd82Kd91Lx03Qm"}}})
    findings = detect(doc, "values.json")
    assert any(f.detector.value == "keyname" for f in findings)


def test_keyname_ignores_placeholder_values() -> None:
    doc = json.dumps({"db": {"password": "changeme"}, "api": {"key": "${API_KEY}"}})
    assert not [f for f in detect(doc, "config.json") if f.detector.value == "keyname"]


def test_private_vs_public_ip() -> None:
    from clurichaun.models import Severity as _S

    # IPs are INFO (informational, not secrets), below the default floor.
    findings = detect("hosts = 10.1.2.3, 93.184.216.34\n", "hosts.conf", min_severity=_S.INFO)
    ids = {f.rule_id for f in findings}
    assert "generic.ipv4-private" in ids
    assert "generic.ipv4-public" in ids


def test_info_findings_below_default_floor() -> None:
    # An external URL alone is INFO and must not appear at the default severity.
    default = {f.rule_id for f in detect("see https://example.com/docs\n")}
    assert "generic.external-url" not in default
    with_info = {
        f.rule_id
        for f in detect("see https://example.com/docs\n", min_severity=__import__("clurichaun.models", fromlist=["Severity"]).Severity.INFO)
    }
    assert "generic.external-url" in with_info


# --------------------------------------------------------------------------- #
# Entropy engine
# --------------------------------------------------------------------------- #


def test_shannon_bounds() -> None:
    assert entropy.shannon("") == 0.0
    assert entropy.shannon("aaaaaaaa") == 0.0
    assert entropy.shannon("ab" * 8) == pytest.approx(1.0)


def test_structural_noise_detection() -> None:
    assert entropy.is_structural_noise("550e8400-e29b-41d4-a716-446655440000")
    assert entropy.is_structural_noise("getUserProfileData")
    assert not entropy.is_structural_noise("k4Jd8Zx2Qw7Lp0Vt5Ry9Bn3Mc6Hs1Ae")


# --------------------------------------------------------------------------- #
# Ingestion
# --------------------------------------------------------------------------- #


def test_decode_fallback_ladder() -> None:
    assert ingest.decode(b"caf\xe9 latte").startswith("caf")
    assert ingest.decode("naïve".encode("utf-8")) == "naïve"


def test_binary_string_extraction() -> None:
    payload = b"\x00\x01\x02" + GITHUB_TOKEN.encode() + b"\x00\xff"
    assert GITHUB_TOKEN in "\n".join(ingest.extract_strings(payload))


def test_zip_member_scanned(tmp_path: Path) -> None:
    archive = tmp_path / "bundle.zip"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("config/prod.env", f"AWS_ACCESS_KEY_ID={AWS_KEY}\n")
    archive.write_bytes(buffer.getvalue())

    stats = ScanStats()
    ingestor = ingest.FileIngestor()
    blobs = list(ingestor.blobs(archive, stats))
    assert any("!/config/prod.env" in blob.logical_path for blob in blobs)
    assert stats.archives_opened == 1


def test_sourcemap_sources_content(tmp_path: Path) -> None:
    sourcemap = tmp_path / "app.js.map"
    sourcemap.write_text(
        json.dumps(
            {
                "version": 3,
                "sources": ["src/secrets.ts"],
                "sourcesContent": [f'const token = "{GITHUB_TOKEN}";'],
            }
        ),
        encoding="utf-8",
    )
    stats = ScanStats()
    blobs = list(ingest.FileIngestor().blobs(sourcemap, stats))
    assert any(blob.logical_path.endswith("src/secrets.ts") for blob in blobs)


def test_archive_depth_limit(tmp_path: Path) -> None:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("leak.env", f"TOKEN={GITHUB_TOKEN}")
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as zf:
        zf.writestr("inner.zip", inner.getvalue())
    path = tmp_path / "outer.zip"
    path.write_bytes(outer.getvalue())

    limits = ingest.IngestLimits(max_archive_depth=1)
    stats = ScanStats()
    list(ingest.FileIngestor(limits).blobs(path, stats))
    assert any("depth limit" in error for error in stats.errors)


# --------------------------------------------------------------------------- #
# Parsers / scope
# --------------------------------------------------------------------------- #


def test_env_parser_handles_export_and_quotes() -> None:
    pairs = parsers.parse('export API_TOKEN="abc123def456"\n# comment\n', ".env")
    assert ("API_TOKEN", "abc123def456") in [(p.key, p.value) for p in pairs]


def test_hcl_parser() -> None:
    pairs = parsers.parse('variable "x" {}\naccess_key = "AKIAQ7JZ3MPLXK2NRTVW"\n', "main.tf")
    assert any(p.key == "access_key" for p in pairs)


def test_reg_parser() -> None:
    text = '[HKEY_CURRENT_USER\\Software\\App]\n"Password"="Sup3rSecret!"\n'
    assert any(p.key == "Password" for p in parsers.parse(text, "export.reg"))


def test_systemd_parser() -> None:
    text = "[Service]\nEnvironment=\"DB_PASSWORD=Hd82Kd91Lx03Qm\"\n"
    assert any(p.key == "DB_PASSWORD" for p in parsers.parse(text, "app.service"))


def test_scope_categories() -> None:
    assert "sourcemap" in scope.categories_of("dist/app.js.map")
    assert "keys" in scope.categories_of("home/user/.ssh/id_ed25519")
    assert "vcs" in scope.categories_of("repo/.git/config")
    assert "archive" in scope.categories_of("backup.tar.gz")
    assert "config" in scope.categories_of("app/.env.production")
    assert not scope.categories_of("notes.md")


def test_scope_filter_denies_media() -> None:
    sf = scope.ScopeFilter()
    assert not sf.allow("assets/logo.png")
    assert sf.allow("src/app.js")
    assert sf.skip_dir("node_modules")


def test_scope_only_and_globs() -> None:
    sf = scope.ScopeFilter(scope_only=True, exclude_globs=("*/vendor/*",))
    assert sf.allow("app/.env")
    assert not sf.allow("README.md")
    assert not sf.allow("app/vendor/.env")


# --------------------------------------------------------------------------- #
# Engine + output
# --------------------------------------------------------------------------- #


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "node_modules").mkdir()
    (tmp_path / ".env.production").write_text(
        f"AWS_ACCESS_KEY_ID={AWS_KEY}\nAWS_SECRET_ACCESS_KEY={AWS_SECRET}\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "app.js").write_text(
        f'const gh = "{GITHUB_TOKEN}";\n', encoding="utf-8"
    )
    (tmp_path / "node_modules" / "leak.env").write_text(
        f"TOKEN={GITHUB_TOKEN}\n", encoding="utf-8"
    )
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + AWS_KEY.encode())
    return tmp_path


def test_engine_walk_respects_denies(tree: Path) -> None:
    engine = ScannerEngine(ScanConfig(roots=[str(tree)], workers=1))
    walked = {Path(p).name for p in engine.walk()}
    assert ".env.production" in walked
    assert "app.js" in walked
    assert "leak.env" not in walked  # node_modules pruned
    assert "logo.png" not in walked  # denied extension


def test_engine_end_to_end(tree: Path) -> None:
    config = ScanConfig(
        roots=[str(tree)], workers=1, detector=DetectorConfig(min_confidence=0.5)
    )
    engine = ScannerEngine(config)
    findings = engine.run()
    ids = {f.rule_id for f in findings}
    assert "aws.access-key-id" in ids
    assert "github.token" in ids
    assert engine.stats.files_scanned >= 2


def test_engine_parallel_matches_serial(tree: Path) -> None:
    serial = ScannerEngine(ScanConfig(roots=[str(tree)], workers=1)).run()
    parallel = ScannerEngine(ScanConfig(roots=[str(tree)], workers=4)).run()
    assert {f.fingerprint for f in serial} == {f.fingerprint for f in parallel}


def test_baseline_suppression(tree: Path) -> None:
    first = ScannerEngine(ScanConfig(roots=[str(tree)], workers=1)).run()
    baseline = {f.fingerprint for f in first}
    config = ScanConfig(
        roots=[str(tree)], workers=1, detector=DetectorConfig(baseline=baseline)
    )
    assert ScannerEngine(config).run() == []


def test_redaction_and_json_report(tree: Path) -> None:
    engine = ScannerEngine(ScanConfig(roots=[str(tree)], workers=1))
    findings = engine.run()
    text = report.render_json(findings, engine.stats, [str(tree)])
    assert AWS_KEY not in text
    assert redact(AWS_KEY) in text

    unredacted = report.render_json(findings, engine.stats, [str(tree)], unredact=True)
    assert AWS_KEY in unredacted


def test_sarif_shape(tree: Path) -> None:
    engine = ScannerEngine(ScanConfig(roots=[str(tree)], workers=1))
    findings = engine.run()
    doc = json.loads(report.render_sarif(findings, engine.stats, [str(tree)]))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["rules"]
    assert len(run["results"]) == len(findings)
    assert all(r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1 for r in run["results"])


def test_exit_code_threshold(tree: Path) -> None:
    findings = ScannerEngine(ScanConfig(roots=[str(tree)], workers=1)).run()
    assert report.exit_code(findings, Severity.CRITICAL) == 1
    assert report.exit_code(findings, None) == 0


def test_unreadable_file_is_reported(tmp_path: Path) -> None:
    missing = tmp_path / "gone.env"
    stats = ScanStats()
    assert list(ingest.FileIngestor().blobs(missing, stats)) == []
    assert stats.errors and stats.files_skipped == 1


# --------------------------------------------------------------------------- #
# Decoder layer (technique adopted from TruffleHog's pkg/decoders)
# --------------------------------------------------------------------------- #


def test_base64_wrapped_secret_recovered() -> None:
    import base64 as b64

    payload = b64.b64encode(f"AWS_ACCESS_KEY_ID={AWS_KEY}".encode()).decode()
    findings = detect(f'config = "{payload}"\n', "deploy.yml")
    aws = [f for f in findings if f.rule_id == "aws.access-key-id"]
    assert aws, "base64-wrapped AWS key should be recovered"
    assert any("base64" in note for note in aws[0].notes)
    assert aws[0].logical_path.endswith("#base64")


def test_unicode_escaped_secret_recovered() -> None:
    escaped = "".join(f"\\u00{ord(c):02x}" for c in GITHUB_TOKEN)
    findings = detect(f'{{"t": "{escaped}"}}\n', "bundle.js")
    assert any(f.rule_id == "github.token" for f in findings)


def test_percent_encoded_uri_recovered() -> None:
    text = "url=postgres://svc:p%40ssw0rd%2Dreal@db.prod.internal:5432/app\n"
    assert any(f.rule_id == "generic.database-uri" for f in detect(text, ".env"))


def test_html_entity_encoded_secret_recovered() -> None:
    text = f"&lt;token&gt;{GITHUB_TOKEN}&lt;/token&gt;\n"
    findings = detect(text, "config.xml")
    assert any(f.rule_id == "github.token" for f in findings)


def test_plaintext_hit_wins_over_decoded_duplicate() -> None:
    text = f"TOKEN={GITHUB_TOKEN}\nALSO=%41%42{GITHUB_TOKEN}\n"
    hits = [f for f in detect(text, ".env") if f.rule_id == "github.token"]
    assert len(hits) == 1
    assert "#" not in hits[0].logical_path


def test_decoders_can_be_disabled() -> None:
    import base64 as b64

    payload = b64.b64encode(f"AWS_ACCESS_KEY_ID={AWS_KEY}".encode()).decode()
    findings = detect(f'c = "{payload}"\n', "deploy.yml", decoders_enabled=False)
    assert not [f for f in findings if f.rule_id == "aws.access-key-id"]


def test_decoder_rejects_mixed_alphabet_and_noise() -> None:
    from clurichaun import decode

    assert decode.derive("plain text with no encodings at all") == []
    # `-` and `+` cannot both appear in one real base64 token.
    assert decode._try_b64(b"AAAA+AAAA-AAAA_AAAAAAAA") is None


def test_decoded_findings_stay_redacted(tmp_path: Path) -> None:
    import base64 as b64

    payload = b64.b64encode(f"AWS_ACCESS_KEY_ID={AWS_KEY}".encode()).decode()
    (tmp_path / "deploy.yml").write_text(f'c: "{payload}"\n', encoding="utf-8")
    engine = ScannerEngine(ScanConfig(roots=[str(tmp_path)], workers=1))
    findings = engine.run()
    text = report.render_json(findings, engine.stats, [str(tmp_path)])
    assert AWS_KEY not in text


# --------------------------------------------------------------------------- #
# Per-file budget (technique adopted from TruffleHog's archive maxTimeout)
# --------------------------------------------------------------------------- #


def test_file_timeout_reports_and_continues(tmp_path: Path) -> None:
    from clurichaun import scanner

    (tmp_path / "slow.env").write_text(f"TOKEN={GITHUB_TOKEN}\n", encoding="utf-8")
    (tmp_path / "fast.env").write_text(f"AWS={AWS_KEY}\n", encoding="utf-8")

    config = ScanConfig(roots=[str(tmp_path)], workers=1, file_timeout=0.05)
    scanner._init_worker(config)

    original = scanner._WORKER["detector"].scan

    def slow(blob):  # type: ignore[no-untyped-def]
        if blob.logical_path.endswith("slow.env"):
            time.sleep(0.4)
        return original(blob)

    scanner._WORKER["detector"].scan = slow  # type: ignore[method-assign]
    try:
        slow_result = scanner._scan_one(str(tmp_path / "slow.env"))
        fast_result = scanner._scan_one(str(tmp_path / "fast.env"))
    finally:
        scanner._WORKER["detector"].scan = original  # type: ignore[method-assign]

    assert any("timed out" in err for err in slow_result.stats.errors)
    assert fast_result.findings, "a later file must still scan after a timeout"
    assert not fast_result.stats.errors


def test_zero_timeout_disables_budget(tmp_path: Path) -> None:
    from clurichaun import scanner

    (tmp_path / "a.env").write_text(f"TOKEN={GITHUB_TOKEN}\n", encoding="utf-8")
    scanner._init_worker(ScanConfig(roots=[str(tmp_path)], workers=1, file_timeout=0))
    assert scanner._WORKER["timeout"] == 0.0
    assert scanner._scan_one(str(tmp_path / "a.env")).findings


# --------------------------------------------------------------------------- #
# Remote scanning
# --------------------------------------------------------------------------- #


pytest.importorskip  # noqa: B018 - referenced below for the web fixture


@pytest.fixture()
def site(tmp_path: Path):
    """A throwaway localhost site serving a leaky bundle, map, env and robots."""
    pytest.importorskip("requests")
    pytest.importorskip("bs4")

    import functools
    import http.server
    import threading

    root = tmp_path / "site"
    root.mkdir()
    (root / "index.html").write_text(
        '<html><head><script src="/app.js"></script>'
        '<link rel="stylesheet" href="/app.css"></head>'
        '<body><a href="/.env">env</a><a href="/private/">private</a></body></html>',
        encoding="utf-8",
    )
    (root / "app.js").write_text(
        f'var k="{AWS_KEY}";//# sourceMappingURL=app.js.map\n', encoding="utf-8"
    )
    (root / "app.js.map").write_text(
        json.dumps(
            {
                "version": 3,
                "sources": ["src/keys.ts"],
                "sourcesContent": [f'export const gh = "{GITHUB_TOKEN}";'],
            }
        ),
        encoding="utf-8",
    )
    (root / "app.css").write_text("body{color:red}\n", encoding="utf-8")
    (root / ".env").write_text(f"AWS_SECRET_ACCESS_KEY={AWS_SECRET}\n", encoding="utf-8")
    (root / "robots.txt").write_text("User-agent: *\nDisallow: /private/\n", encoding="utf-8")
    private = root / "private"
    private.mkdir()
    (private / "index.html").write_text(f"<p>{GITHUB_TOKEN}</p>", encoding="utf-8")

    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(root))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture()
def site_policy(tmp_path: Path):
    """A localhost site whose policy files the test can write on demand."""
    pytest.importorskip("requests")
    pytest.importorskip("bs4")

    import functools
    import http.server
    import threading

    root = tmp_path / "policy-site"
    root.mkdir()
    (root / "index.html").write_text(
        '<html><body><a href="/a.env">a</a></body></html>', encoding="utf-8"
    )
    (root / "a.env").write_text(f"AWS={AWS_KEY}\n", encoding="utf-8")

    def write(relative: str, text: str) -> None:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(root))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/", write
    finally:
        server.shutdown()
        server.server_close()


def test_web_crawl_discovers_assets(site: str) -> None:
    from clurichaun.web import WebConfig, WebCrawler

    crawler = WebCrawler(WebConfig(url=site, delay=0))
    found = {u.rsplit("/", 1)[-1] for u in crawler.crawl()}
    assert {"app.js", "app.js.map", ".env"} <= found


def test_web_scan_finds_secrets_through_the_pipeline(site: str) -> None:
    from clurichaun.detect import DetectorConfig, SecretDetector
    from clurichaun.ingest import FileIngestor
    from clurichaun.web import WebConfig, WebCrawler

    crawler = WebCrawler(WebConfig(url=site, delay=0))
    detector = SecretDetector(DetectorConfig(min_confidence=0.4))
    ingestor = FileIngestor()
    findings = []
    for fetched in crawler.crawl_and_fetch():
        for blob in ingestor.blobs_from_bytes(
            fetched.content, fetched.logical_path, fetched.url, 0, crawler.stats
        ):
            findings.extend(detector.scan(blob))

    ids = {f.rule_id for f in findings}
    assert "aws.access-key-id" in ids          # inline in the bundle
    assert "aws.secret-access-key" in ids      # served .env
    assert "github.token" in ids               # source map sourcesContent
    assert any(".js.map!/" in f.logical_path for f in findings)


def test_web_scan_respects_robots(site: str) -> None:
    from clurichaun.web import WebConfig, WebCrawler

    crawler = WebCrawler(WebConfig(url=site, delay=0))
    list(crawler.crawl())
    assert any("robots.txt" in err for err in crawler.stats.errors)
    assert not any("/private/" in url for url in crawler.seen_urls if "robots" not in url) or any(
        "disallowed" in err for err in crawler.stats.errors
    )

    ignoring = WebCrawler(WebConfig(url=site, delay=0, respect_robots=False))
    list(ignoring.crawl())
    assert not any("disallowed" in err for err in ignoring.stats.errors)


def test_web_max_bytes_truncates(site: str) -> None:
    from clurichaun.web import WebConfig, WebCrawler

    crawler = WebCrawler(WebConfig(url=site, delay=0, max_bytes=8))
    fetched = [f for f in crawler.crawl_and_fetch()]
    assert any("max-bytes" in err for err in crawler.stats.errors)
    assert all(len(f.content) <= 65536 for f in fetched)


def test_fetched_logical_path_is_path_shaped() -> None:
    from clurichaun.web import Fetched

    assert Fetched("https://h.tld/a/b.env", b"x", "text/plain").logical_path == "h.tld/a/b.env"
    assert Fetched("https://h.tld/", b"x", "text/html").logical_path == "h.tld/index.html"


# --------------------------------------------------------------------------- #
# Rule-level filters (technique + wordlist ported from gitleaks, MIT)
# --------------------------------------------------------------------------- #


def test_assignment_template_spans_syntaxes() -> None:
    secret = "Qw7Lp0Vt5Ry9Bn3Mc6Hs1Ae4Gu"
    for line in (
        f'api_key = "{secret}"',
        f"apiKey: {secret}",
        f'"secret" => "{secret}"',
        f"access_token := {secret}",
        f"PASSWORD||{secret}",
        f'{{"client_secret": "{secret}"}}',
    ):
        hits = [f for f in detect(line) if f.rule_id == "generic.api-key-assignment"]
        assert hits, f"no generic hit for: {line}"
        assert hits[0].secret == secret


def test_generic_rule_allowlist_kills_key_name_lookalikes() -> None:
    for line in (
        "api_version = 20240101020304",
        "primary_key = customer_identifier",
        "csrf_token = aaaaaaaaaaaaaaaaaaaa",
        "key_vault_name = production-vault-name",
        "keystore_file = /etc/ssl/keystore.jks",
    ):
        assert not [
            f for f in detect(line) if f.rule_id == "generic.api-key-assignment"
        ], f"should be allowlisted: {line}"


def test_generic_rule_drops_stopword_values() -> None:
    from clurichaun.stopwords import contains_stopword

    assert contains_stopword("my_account_key_12345") == "account"
    assert contains_stopword("Xk9Qw2mZ7pLt4RvB8NcJ3HdF6SyA1GuE5TrKoWiP") is None
    assert not [
        f
        for f in detect("api_key = production_account_placeholder")
        if f.rule_id == "generic.api-key-assignment"
    ]


def test_generic_rule_enforces_min_entropy() -> None:
    from clurichaun.patterns import RULES_BY_ID

    assert RULES_BY_ID["generic.api-key-assignment"].min_entropy == 3.5
    # Low-entropy value clears the regex but fails the rule's entropy floor.
    assert not [
        f for f in detect("api_key = aaaaaaaaaaaaaaaaaaaaa") if f.detector.value == "regex"
    ]
    assert [
        f
        for f in detect("api_key = Qw7Lp0Vt5Ry9Bn3Mc6Hs1Ae4Gu")
        if f.rule_id == "generic.api-key-assignment"
    ]


def test_real_credentials_survive_the_new_filters() -> None:
    text = (
        "LITELLM_MASTER_KEY=sk-z9Qw2mZ7pLt4RvB8NcJ3HdF6Sy\n"
        f"AWS_SECRET_ACCESS_KEY={AWS_SECRET}\n"
        f"GITHUB_TOKEN={GITHUB_TOKEN}\n"
    )
    ids = {f.rule_id for f in detect(text, ".env")}
    assert "aws.secret-access-key" in ids
    assert "github.token" in ids
    assert "generic.api-key-assignment" in ids


# --------------------------------------------------------------------------- #
# Rule packs (gitleaks TOML schema)
# --------------------------------------------------------------------------- #


def test_bundled_gitleaks_pack_loads() -> None:
    from clurichaun.rules_toml import bundled_packs, load_pack, resolve_pack

    assert "gitleaks" in bundled_packs()
    rules, report = load_pack(resolve_pack("gitleaks"))
    assert report.loaded > 200
    assert all(r.prefilter for r in rules), "keywords must become prefilters"
    assert any(r.min_entropy for r in rules)
    assert any(r.allow_regexes for r in rules)


def test_pack_rules_detect_through_the_engine(tmp_path: Path) -> None:
    pack = tmp_path / "custom.toml"
    pack.write_text(
        """
[[rules]]
id = "acme-token"
description = "ACME service token. Grants API access."
regex = '''(?i)acme[_-]?token\\s*[:=]\\s*"?(ACME-[A-Za-z0-9]{16})"?'''
keywords = ["acme"]
entropy = 3.0
  [[rules.allowlists]]
  regexTarget = "match"
  regexes = ['''ACME-0{16}''']
""",
        encoding="utf-8",
    )
    config = DetectorConfig(min_confidence=0.0, rule_packs=(str(pack),))
    blob = Blob(
        logical_path="app.yml",
        source_path="app.yml",
        text='acme_token: "ACME-Qw7Lp0Vt5Ry9Bn3M"\nacme_token: "ACME-0000000000000000"\n',
    )
    hits = [f for f in SecretDetector(config).scan(blob) if f.rule_id == "acme-token"]
    assert len(hits) == 1, "the allowlisted placeholder must be dropped"
    assert hits[0].secret == "ACME-Qw7Lp0Vt5Ry9Bn3M"
    assert hits[0].title.startswith("ACME service token")


def test_re2_inline_flags_translated() -> None:
    from clurichaun.rules_toml import compile_re2

    # Python rejects this outright; RE2 does not.
    pattern = compile_re2(r"sk_live_(?i)[a-z]{4}")
    assert pattern.match("sk_live_ABCD")
    assert not pattern.match("SK_LIVE_ABCD"), "prefix must stay case-sensitive"
    assert compile_re2(r"(?i)abc").match("ABC")


def test_pack_secret_group_semantics(tmp_path: Path) -> None:
    from clurichaun.rules_toml import load_pack_text

    rules, _ = load_pack_text(
        """
[[rules]]
id = "first-group"
regex = '''key=(\\w+)-(\\w+)'''
[[rules]]
id = "named-group"
regex = '''key=(\\w+)-(\\w+)'''
secretGroup = 2
"""
    )
    by_id = {r.rule_id: r for r in rules}
    match = by_id["first-group"].regex.search("key=alpha-beta")
    assert by_id["first-group"].pick(match)[0] == "alpha"
    assert by_id["named-group"].pick(match)[0] == "beta"


# --------------------------------------------------------------------------- #
# Site-declared agent policy: ai.txt and llms.txt
# --------------------------------------------------------------------------- #


def test_ai_txt_ietf_form_parsed() -> None:
    from clurichaun.web.policy import parse_ai_txt

    text = """# ai.txt
Spec-Version: 1.0
Site-Name: News Daily
Contact: ai@newsdaily.com
Training: conditional
Scraping: allow
Agent: *
  Rate-Limit: 30/minute
Agent: clurichaun
  Rate-Limit: 120/minute
Attribution: required
"""
    policy = parse_ai_txt(text, "clurichaun/0.1.0", "/.well-known/ai.txt")
    assert policy.site_name == "News Daily"
    assert policy.scraping == "allow"
    assert policy.training == "conditional"
    assert policy.attribution == "required"
    assert policy.delay_seconds == pytest.approx(0.5)  # our agent block wins
    assert policy.contact == "ai@newsdaily.com"
    assert "ai.txt" in policy.summary()


def test_ai_txt_scraping_deny_and_rate_windows() -> None:
    from clurichaun.web.policy import parse_ai_txt, parse_rate_limit

    policy = parse_ai_txt("Site-Name: X\nScraping: deny\n", "clurichaun/0.1.0", "/ai.txt")
    assert policy.scraping_denied
    assert parse_rate_limit("10/second") == pytest.approx(0.1)
    assert parse_rate_limit("60/hour") == pytest.approx(60.0)
    assert parse_rate_limit("nonsense") == 0.0
    assert parse_rate_limit(None) == 0.0


def test_ai_txt_spawning_form_parsed() -> None:
    from clurichaun.web.policy import parse_ai_txt

    policy = parse_ai_txt(
        "User-Agent: *\nDisallow: /private/\nAllow: /private/public/\n",
        "clurichaun/0.1.0",
        "/ai.txt",
    )
    assert not policy.scraping_denied      # only a subtree is off limits
    assert not policy.path_allowed("https://h.tld/private/x")
    assert policy.path_allowed("https://h.tld/private/public/x")
    assert policy.path_allowed("https://h.tld/elsewhere")


def test_llms_txt_seeds_extracted() -> None:
    from clurichaun.web.policy import parse_llms_txt

    text = """# Acme

> Acme docs.

## Docs

- [Quickstart](https://acme.tld/docs/quickstart.md): start here
- [Config](/docs/config.json)
- [Offsite](https://other.tld/x)

## Optional

- [Changelog](/changes.txt)
"""
    seeds = parse_llms_txt(text, "https://acme.tld/")
    assert seeds == [
        "https://acme.tld/docs/quickstart.md",
        "https://acme.tld/docs/config.json",
        "https://acme.tld/changes.txt",
    ]


def test_crawler_honours_ai_txt_deny(site_policy) -> None:
    from clurichaun.web import WebConfig, WebCrawler

    base, write = site_policy
    write("ai.txt", "Site-Name: Test\nScraping: deny\n")

    blocked = WebCrawler(WebConfig(url=base, delay=0))
    assert list(blocked.crawl()) == []
    assert any("Scraping: deny" in err for err in blocked.stats.errors)

    override = WebCrawler(WebConfig(url=base, delay=0, respect_ai_txt=False))
    assert list(override.crawl()), "--no-ai-txt must still scan"


def test_crawler_uses_llms_txt_seeds(site_policy) -> None:
    from clurichaun.web import WebConfig, WebCrawler

    base, write = site_policy
    write("llms.txt", f"# Test\n\n> t\n\n## Files\n\n- [Env]({base}deep/hidden.env)\n")
    write("deep/hidden.env", f"GITHUB_TOKEN={GITHUB_TOKEN}\n")

    crawler = WebCrawler(WebConfig(url=base, delay=0, depth=1))
    found = list(crawler.crawl())
    assert any(u.endswith("deep/hidden.env") for u in found), "llms.txt seed not crawled"
    assert any("llms.txt offered" in err for err in crawler.stats.errors)


def test_crawler_rate_limit_from_ai_txt(site_policy) -> None:
    from clurichaun.web import WebConfig, WebCrawler

    base, write = site_policy
    write(".well-known/ai.txt", "Site-Name: Test\nScraping: allow\nAgent: *\n  Rate-Limit: 4/second\n")

    crawler = WebCrawler(WebConfig(url=base, delay=0))
    list(crawler.crawl())
    assert crawler.ai_policy.delay_seconds == pytest.approx(0.25)
    assert crawler.ai_policy.source.endswith("/.well-known/ai.txt")


# --------------------------------------------------------------------------- #
# #2 Offline checksum validation
# --------------------------------------------------------------------------- #


def test_github_checksum_rejects_fabricated_token() -> None:
    from clurichaun import checksums

    real = "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"      # GitHub's own vector
    assert checksums.check_github(real) is True
    # Flip one checksum char: provably not a GitHub token.
    fake = real[:-1] + ("8" if real[-1] != "8" else "9")
    assert checksums.check_github(fake) is False
    assert checksums.check_github("not-a-token") is None


def test_checksum_drops_fake_github_token_in_engine() -> None:
    fake = "ghp_" + "A" * 36  # right shape, wrong checksum
    assert not [f for f in detect(f"token={fake}") if f.rule_id == "github.token"]
    assert GITHUB_TOKEN.startswith("ghp_")
    hits = [f for f in detect(f"token={GITHUB_TOKEN}") if f.rule_id == "github.token"]
    assert hits and hits[0].confidence == pytest.approx(0.99)
    assert any("checksum verified" in n for n in hits[0].notes)


def test_luhn_checksum_helper() -> None:
    from clurichaun import checksums

    assert checksums._luhn_ok([int(c) for c in "79927398713"]) is True
    assert checksums._luhn_ok([int(c) for c in "79927398710"]) is False


# --------------------------------------------------------------------------- #
# #4 Multi-part credential fingerprints
# --------------------------------------------------------------------------- #


def test_aws_pair_shares_identity() -> None:
    text = f"AWS_ACCESS_KEY_ID={AWS_KEY}\nAWS_SECRET_ACCESS_KEY={AWS_SECRET}\n"
    findings = detect(text, ".env")
    key_id = next(f for f in findings if f.rule_id == "aws.access-key-id")
    secret = next(f for f in findings if f.rule_id == "aws.secret-access-key")
    assert key_id.secret_v2 == f"{AWS_KEY}:{AWS_SECRET}"
    assert key_id.secret_v2 == secret.secret_v2
    # id-only identity differs from the paired identity
    from clurichaun.models import Finding as _F
    id_only = _F(
        rule_id="aws.access-key-id", title="t", detector=key_id.detector,
        severity=key_id.severity, logical_path=".env", source_path=".env",
        line=1, column=1, secret=AWS_KEY, match_context="x",
    )
    assert key_id.fingerprint != id_only.fingerprint


def test_rotated_secret_under_same_id_is_distinct() -> None:
    rotated = "Zq4Nd8Xc2Vb6Mk1Lp9Rt5Yw3Hs7Ju0Ae4Gu2Ti"
    a = detect(f"AWS_ACCESS_KEY_ID={AWS_KEY}\nAWS_SECRET_ACCESS_KEY={AWS_SECRET}\n", "a/.env")
    b = detect(f"AWS_ACCESS_KEY_ID={AWS_KEY}\nAWS_SECRET_ACCESS_KEY={rotated}\n", "a/.env")
    fa = next(f for f in a if f.rule_id == "aws.access-key-id").fingerprint
    fb = next(f for f in b if f.rule_id == "aws.access-key-id").fingerprint
    assert fa != fb, "a rotated secret under the same id must not dedupe away"


def test_fingerprint_ignores_line_number() -> None:
    from clurichaun.models import Finding as F, Detector as D, Severity as S

    base = dict(rule_id="r", title="t", detector=D.REGEX, severity=S.HIGH,
                logical_path="p", source_path="p", column=1,
                secret="SECRETVALUE123456", match_context="x")
    assert F(line=5, **base).fingerprint == F(line=900, **base).fingerprint


# --------------------------------------------------------------------------- #
# #7 Cross-chunk streaming: no duplicates, correct line numbers
# --------------------------------------------------------------------------- #


def _write_big(path: Path, secret_line_index: int, filler_bytes: int) -> Path:
    line = "y" * 99 + "\n"
    with open(path, "w", encoding="utf-8") as handle:
        written = 0
        while written < filler_bytes:
            handle.write(line)
            written += len(line)
        handle.write(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n")
        for _ in range(2000):
            handle.write(line)
    return path


def test_stream_secret_in_overlap_reported_once(tmp_path: Path) -> None:
    from clurichaun.ingest import FileIngestor, IngestLimits

    path = _write_big(tmp_path / "big.log", 0, 65536 - 3000)
    limits = IngestLimits(stream_threshold=1024, chunk_size=65536)
    detector = SecretDetector(DetectorConfig())
    stats = ScanStats()
    hits = [
        f.line
        for blob in FileIngestor(limits).blobs(path, stats)
        for f in detector.scan(blob)
        if f.rule_id == "aws.access-key-id"
    ]
    assert len(hits) == 1, f"secret in overlap window reported {len(hits)}x"

    true_line = None
    for index, text in enumerate(path.read_text().splitlines(), start=1):
        if AWS_KEY in text:
            true_line = index
            break
    assert hits[0] == true_line, f"reported line {hits[0]} != actual {true_line}"


def test_stream_secret_mid_chunk(tmp_path: Path) -> None:
    from clurichaun.ingest import FileIngestor, IngestLimits

    path = _write_big(tmp_path / "big2.log", 0, 2 * 1024 * 1024)
    limits = IngestLimits(stream_threshold=1024, chunk_size=4 * 1024 * 1024)
    detector = SecretDetector(DetectorConfig())
    stats = ScanStats()
    hits = [
        f.line
        for blob in FileIngestor(limits).blobs(path, stats)
        for f in detector.scan(blob)
        if f.rule_id == "aws.access-key-id"
    ]
    assert len(hits) == 1


# --------------------------------------------------------------------------- #
# #3 Git-history scanning + #5 batched pool
# --------------------------------------------------------------------------- #


@pytest.fixture()
def deleted_secret_repo(tmp_path: Path) -> Path:
    import subprocess

    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args: str) -> None:
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)

    git("init")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "Tester")
    (repo / ".env").write_text(f"AWS_SECRET_ACCESS_KEY={AWS_SECRET}\n", encoding="utf-8")
    git("add", ".env")
    git("commit", "-m", "add env")
    (repo / ".env").unlink()
    git("add", "-A")
    git("commit", "-m", "remove env")
    return repo


def test_worktree_scan_misses_deleted_secret(deleted_secret_repo: Path) -> None:
    engine = ScannerEngine(ScanConfig(roots=[str(deleted_secret_repo)], workers=1))
    findings = engine.run()
    assert not [f for f in findings if f.rule_id == "aws.secret-access-key"]


def test_git_history_finds_deleted_secret(deleted_secret_repo: Path) -> None:
    config = ScanConfig(roots=[str(deleted_secret_repo)], workers=1, git_history=True)
    engine = ScannerEngine(config)
    findings = engine.run()
    aws = [f for f in findings if f.rule_id == "aws.secret-access-key"]
    assert aws, "history scan must find the committed-then-deleted secret"
    assert aws[0].git is not None
    assert aws[0].git.author == "Tester"
    assert aws[0].git.commit
    assert any("git history" in n for n in aws[0].notes)


def test_git_source_dedupes_blobs(deleted_secret_repo: Path) -> None:
    from clurichaun.gitsource import GitHistorySource
    from clurichaun.models import ScanStats

    source = GitHistorySource(str(deleted_secret_repo))
    stats = ScanStats()
    shas = [b.sha for b in source.blobs(stats)]
    assert len(shas) == len(set(shas)), "each blob object scanned once"


def test_batched_parallel_matches_serial(tree: Path) -> None:
    serial = ScannerEngine(ScanConfig(roots=[str(tree)], workers=1)).run()
    batched = ScannerEngine(
        ScanConfig(roots=[str(tree)], workers=4, batch_size=2)
    ).run()
    assert {f.fingerprint for f in serial} == {f.fingerprint for f in batched}


def test_git_history_in_sarif(deleted_secret_repo: Path) -> None:
    config = ScanConfig(roots=[str(deleted_secret_repo)], workers=1, git_history=True)
    engine = ScannerEngine(config)
    findings = engine.run()
    doc = json.loads(report.render_sarif(findings, engine.stats, [str(deleted_secret_repo)]))
    props = [r["properties"] for r in doc["runs"][0]["results"] if "commit" in r["properties"]]
    assert props and props[0]["author"] == "Tester"


# --------------------------------------------------------------------------- #
# #8 Aho-Corasick keyword core
# --------------------------------------------------------------------------- #


def test_keyword_index_matches_loop_exactly() -> None:
    from clurichaun.detect import SecretDetector, DetectorConfig

    d = SecretDetector(DetectorConfig(rule_packs=("gitleaks",)))
    assert d._keyword_index is not None, "index should activate at 254 rules"
    for text in (
        "nothing interesting here at all",
        f"AWS_ACCESS_KEY_ID={AWS_KEY}\ntoken={GITHUB_TOKEN}\n",
        "slack xoxb- and stripe sk_live_ and a private key -----BEGIN",
        "api_key: x  password= y  secret => z",
    ):
        lowered = text.lower()
        loop = {
            r.rule_id
            for r in d.rules
            if not r.prefilter or any(a in lowered for a in r.prefilter)
        }
        ac = d._keyword_index.candidate_rules(text)
        assert loop == ac, f"AC/loop divergence on: {text!r}: {loop ^ ac}"


def test_keyword_index_inactive_for_small_ruleset() -> None:
    from clurichaun.detect import SecretDetector, DetectorConfig

    assert SecretDetector(DetectorConfig())._keyword_index is None


def test_pack_detection_unchanged_by_index(tmp_path: Path) -> None:
    from clurichaun.detect import SecretDetector, DetectorConfig

    blob = Blob("a.env", "a.env", f"AWS_ACCESS_KEY_ID={AWS_KEY}\n")
    without = SecretDetector(DetectorConfig(min_confidence=0.0))
    with_pack = SecretDetector(DetectorConfig(min_confidence=0.0, rule_packs=("gitleaks",)))
    ids_without = {f.rule_id for f in without.scan(blob)}
    ids_with = {f.rule_id for f in with_pack.scan(blob)}
    assert "aws.access-key-id" in ids_without
    assert ids_without <= ids_with  # pack only adds


# --------------------------------------------------------------------------- #
# #9 Test / example / comment context scoring
# --------------------------------------------------------------------------- #


def test_context_penalty_for_test_paths() -> None:
    from clurichaun import scope

    assert scope.context_penalty("src/config.py") == 0.0
    assert scope.context_penalty("tests/fixtures/creds.env") >= 0.2
    assert scope.context_penalty("app/foo_test.go") >= 0.2
    assert scope.context_penalty("src/app.js", "  // key = abc") >= 0.1
    # 'attestation' must not read as 'test'
    assert scope.context_penalty("src/attestation/keys.py") == 0.0


def test_test_context_lowers_confidence_but_keeps_finding() -> None:
    # A non-checksummed rule, so the checksum boost does not mask the penalty.
    line = f"aws_secret_access_key = {AWS_SECRET}"
    prod = next(f for f in detect(line, "src/config.yml") if f.rule_id == "aws.secret-access-key")
    test = next(
        f for f in detect(line, "tests/fixtures/config.yml") if f.rule_id == "aws.secret-access-key"
    )
    assert test.confidence < prod.confidence, "test context must score lower"
    assert test.confidence > 0, "but still surface the finding"


# --------------------------------------------------------------------------- #
# #1 Live verification (with an injected fake session — no real network)
# --------------------------------------------------------------------------- #


class _FakeResponse:
    def __init__(self, status: int, payload: dict | None = None, headers: dict | None = None) -> None:
        self.status_code = status
        self._payload = payload or {}
        self.headers = headers or {}

    def json(self) -> dict:
        return self._payload


class _FakeSession:
    """Records calls and returns a scripted verdict per token."""

    def __init__(self, active_tokens: set[str]) -> None:
        self.active = active_tokens
        self.calls: list[str] = []

    def get(self, url, headers=None, auth=None, **kw):  # type: ignore[no-untyped-def]
        self.calls.append(url)
        token = ""
        if headers and "Authorization" in headers:
            token = headers["Authorization"].split()[-1]
        elif auth:
            token = auth[0]
        if token in self.active:
            return _FakeResponse(200, {"login": "octocat"}, {"X-OAuth-Scopes": "repo, admin:org"})
        return _FakeResponse(401)

    def post(self, url, headers=None, **kw):  # type: ignore[no-untyped-def]
        self.calls.append(url)
        token = headers["Authorization"].split()[-1] if headers else ""
        return _FakeResponse(200, {"ok": token in self.active})


def test_verifier_marks_active_and_inactive() -> None:
    from clurichaun.verify import Verifier, VerifyConfig
    from clurichaun.models import Verified

    live = "ghp_" + "a" * 36
    dead = "ghp_" + "b" * 36
    findings = detect(f"a={live}\nb={dead}\n")
    findings = [f for f in findings if f.rule_id == "github.token"]
    # both fabricated tokens fail the offline checksum, so force them present:
    from clurichaun.models import Finding as F, Detector as D, Severity as Sv
    findings = [
        F("github.token", "t", D.REGEX, Sv.CRITICAL, "a", "a", 1, 1, live, "x", confidence=0.9),
        F("github.token", "t", D.REGEX, Sv.CRITICAL, "b", "b", 1, 1, dead, "x", confidence=0.9),
    ]
    session = _FakeSession(active_tokens={live})
    Verifier(VerifyConfig(enabled=True), session=session).run(findings)
    assert findings[0].verified is Verified.ACTIVE
    assert findings[1].verified is Verified.INACTIVE
    assert len(session.calls) == 2  # one request each


def test_verifier_caches_repeated_secret() -> None:
    from clurichaun.verify import Verifier, VerifyConfig
    from clurichaun.models import Finding as F, Detector as D, Severity as Sv

    tok = "ghp_" + "c" * 36
    findings = [
        F("github.token", "t", D.REGEX, Sv.CRITICAL, p, p, 1, 1, tok, "x", confidence=0.9)
        for p in ("a", "b", "c")
    ]
    session = _FakeSession(active_tokens={tok})
    Verifier(VerifyConfig(enabled=True), session=session).run(findings)
    assert len(session.calls) == 1, "same secret verified once, then cached"


def test_verifier_disabled_by_default() -> None:
    from clurichaun.verify import Verifier, VerifyConfig
    from clurichaun.models import Finding as F, Detector as D, Severity as Sv, Verified

    tok = "ghp_" + "d" * 36
    findings = [F("github.token", "t", D.REGEX, Sv.CRITICAL, "a", "a", 1, 1, tok, "x")]
    session = _FakeSession(active_tokens={tok})
    Verifier(VerifyConfig(enabled=False), session=session).run(findings)
    assert findings[0].verified is Verified.UNKNOWN
    assert not session.calls


def test_verifier_captures_github_scopes() -> None:
    from clurichaun.verify import Verifier, VerifyConfig
    from clurichaun.models import Finding as F, Detector as D, Severity as Sv, Verified

    tok = "ghp_" + "f" * 36
    finding = F("github.token", "t", D.REGEX, Sv.CRITICAL, "a", "a", 1, 1, tok, "x", confidence=0.9)
    Verifier(VerifyConfig(enabled=True), session=_FakeSession({tok})).run([finding])
    assert finding.verified is Verified.ACTIVE
    assert finding.access is not None
    assert finding.access["identity"] == "octocat"
    assert "admin:org" in finding.access["scopes"]
    assert "scopes:" in finding.verification_note


def test_verifier_providers_for_and_only_filter() -> None:
    from clurichaun.verify import Verifier, VerifyConfig
    from clurichaun.models import Finding as F, Detector as D, Severity as Sv

    gh = F("github.token", "t", D.REGEX, Sv.CRITICAL, "a", "a", 1, 1, "ghp_" + "e" * 36, "x", confidence=0.9)
    sl = F("slack.token", "t", D.REGEX, Sv.HIGH, "a", "a", 1, 1, "xoxb-1-2-abcdefghij", "x", confidence=0.9)
    v = Verifier(VerifyConfig(enabled=True, only=frozenset({"github"})), session=_FakeSession(set()))
    assert v.providers_for([gh, sl]) == ["github"]


# --------------------------------------------------------------------------- #
# #6 SQLite datastore + incremental scanning
# --------------------------------------------------------------------------- #


def test_store_incremental_skips_unchanged(tmp_path: Path) -> None:
    from clurichaun.store import Store

    f = tmp_path / "a.env"
    f.write_text(f"AWS={AWS_KEY}\n", encoding="utf-8")
    info = f.stat()
    with Store(str(tmp_path / "db.sqlite")) as store:
        assert not store.unchanged(str(f), info.st_mtime, info.st_size)
        store.record_file(str(f), info.st_mtime, info.st_size)
    with Store(str(tmp_path / "db.sqlite")) as store:
        assert store.unchanged(str(f), info.st_mtime, info.st_size)
        assert not store.unchanged(str(f), info.st_mtime + 1, info.st_size)


def test_store_content_dedup(tmp_path: Path) -> None:
    from clurichaun.store import Store

    with Store(str(tmp_path / "db.sqlite")) as store:
        assert store.seen_blob("hashA") is False
        assert store.seen_blob("hashA") is True
        assert store.seen_blob("hashB") is False


def test_store_finding_history_new_vs_known(tmp_path: Path) -> None:
    from clurichaun.store import Store

    findings = detect(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n", "a.env")
    db = str(tmp_path / "db.sqlite")
    with Store(db) as store:
        first = store.record_findings(findings)
    assert first.new == len(findings) and first.known == 0
    findings2 = detect(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n", "a.env")
    with Store(db) as store:
        second = store.record_findings(findings2)
    assert second.known == len(findings2) and second.new == 0


def test_incremental_skips_work_but_carries_findings(tmp_path: Path) -> None:
    # Option B: the second run does no scanning for an unchanged file, but its
    # findings are carried forward so the report stays COMPLETE.
    target = tmp_path / "proj"
    target.mkdir()
    (target / "a.env").write_text(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n", encoding="utf-8")
    db = str(tmp_path / "db.sqlite")  # outside the scanned tree

    first = ScannerEngine(
        ScanConfig(roots=[str(target)], workers=1, db_path=db, incremental=True)
    )
    found1 = first.run()
    assert any(f.rule_id == "aws.access-key-id" for f in found1)

    second = ScannerEngine(
        ScanConfig(roots=[str(target)], workers=1, db_path=db, incremental=True)
    )
    found2 = second.run()
    assert second.stats.files_scanned == 0, "unchanged file is not re-scanned"
    assert second.stats.files_skipped >= 1
    assert second.carried_forward >= 1
    # ...yet the report is still complete — the AWS key is present, carried.
    aws = [f for f in found2 if f.rule_id == "aws.access-key-id"]
    assert aws and aws[0].carried
    assert {f.fingerprint for f in found1} == {f.fingerprint for f in found2}


def test_verification_cache_roundtrip(tmp_path: Path) -> None:
    from clurichaun.store import Store
    from clurichaun.models import Verified

    with Store(str(tmp_path / "db.sqlite")) as store:
        assert store.cached_verdict("secret1") is None
        store.cache_verdict("secret1", Verified.ACTIVE, "github user x")
        verdict, note = store.cached_verdict("secret1")
        assert verdict is Verified.ACTIVE and note == "github user x"


# --------------------------------------------------------------------------- #
# #10 Nosey Parker rule corpus (Apache-2.0, vendored)
# --------------------------------------------------------------------------- #


def test_noseyparker_pack_bundled_and_loads() -> None:
    from clurichaun.rules_toml import bundled_packs, load_any, resolve_pack

    assert "noseyparker" in bundled_packs()
    rules, report = load_any(resolve_pack("noseyparker"))
    assert report.loaded > 150
    # First-group-is-secret convention
    aws = [r for r in rules if "aws" in r.rule_id.lower()]
    assert aws
    match = aws[0].regex.search(f"key {AWS_KEY} end")
    if match:
        assert aws[0].pick(match)[0] == AWS_KEY


def test_noseyparker_re2_verbose_and_inline_flags() -> None:
    from clurichaun.rules_np import load_np_text

    rules, report = load_np_text(
        """
rules:
- name: Verbose Rule
  id: np.test.1
  pattern: |
    (?x)(?i)
    \\b tok_ ([a-z0-9]{20}) \\b
  categories: [secret]
"""
    )
    assert len(rules) == 1
    rule = rules[0]
    assert rule.regex.search("tok_abcdefghij0123456789")
    assert rule.severity.value == "high"  # 'secret' category


def test_noseyparker_pack_detects_through_engine() -> None:
    from clurichaun.detect import SecretDetector, DetectorConfig

    d = SecretDetector(DetectorConfig(min_confidence=0.0, rule_packs=("noseyparker",)))
    assert d._keyword_index is not None  # >80 rules -> AC core active
    blob = Blob("a.env", "a.env", f"AWS_ACCESS_KEY_ID={AWS_KEY}\n")
    ids = {f.rule_id for f in d.scan(blob)}
    assert any(i.startswith("np.") for i in ids), "a np.* rule should fire"


# --------------------------------------------------------------------------- #
# G3 staged / G8 actionability / G7 new-only / G10 git age
# --------------------------------------------------------------------------- #


def test_staged_scan_only_index(tmp_path: Path) -> None:
    import subprocess

    def git(*a: str) -> None:
        subprocess.run(["git", "-C", str(tmp_path), *a], check=True, capture_output=True)

    git("init")
    git("config", "user.email", "t@e")
    git("config", "user.name", "t")
    (tmp_path / "committed.env").write_text(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n", encoding="utf-8")
    git("add", "committed.env")
    git("commit", "-m", "init")
    (tmp_path / "staged.env").write_text(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n", encoding="utf-8")
    git("add", "staged.env")
    (tmp_path / "unstaged.env").write_text(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n", encoding="utf-8")

    findings = ScannerEngine(ScanConfig(roots=[str(tmp_path)], staged=True)).run()
    paths = {f.logical_path for f in findings}
    assert paths == {"staged.env"}, f"staged mode scanned {paths}"


def test_actionability_ranks() -> None:
    from clurichaun.models import Finding as F, Detector as D, Severity as Sv, Verified

    def mk(**kw):  # type: ignore[no-untyped-def]
        base = dict(rule_id="r", title="t", detector=D.REGEX, severity=Sv.HIGH,
                    logical_path="p", source_path="p", line=1, column=1,
                    secret="s", match_context="x")
        base.update(kw)
        return F(**base)

    assert mk(verified=Verified.ACTIVE).actionability == "verified-active"
    assert mk(verified=Verified.INACTIVE).actionability == "verified-inactive"
    assert mk(notes=["checksum verified"]).actionability == "checksum-valid"
    assert mk(confidence=0.9).actionability == "high-confidence"
    assert mk(confidence=0.5).actionability == "candidate"
    assert mk(verified=Verified.ACTIVE).actionability_rank > mk(confidence=0.9).actionability_rank
    assert mk(verified=Verified.INACTIVE).actionability_rank < mk(confidence=0.5).actionability_rank


def test_git_history_note_has_age_and_owner(deleted_secret_repo: Path) -> None:
    config = ScanConfig(roots=[str(deleted_secret_repo)], workers=1, git_history=True)
    findings = ScannerEngine(config).run()
    aws = next(f for f in findings if f.rule_id == "aws.secret-access-key")
    note = " ".join(aws.notes)
    assert "git history" in note and "by Tester" in note and "d old" in note


def test_new_since_last_scan_note(tmp_path: Path) -> None:
    from clurichaun.store import Store

    findings = detect(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n", "a.env")
    db = str(tmp_path / "db.sqlite")
    with Store(db) as store:
        store.record_findings(findings)  # first pass: all new
    findings2 = detect(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n", "a.env")
    with Store(db) as store:
        store.record_findings(findings2)
    assert not any("new since last scan" in n for f in findings2 for n in f.notes)


# --------------------------------------------------------------------------- #
# G9 declarative composite rules (window enforcement)
# --------------------------------------------------------------------------- #


def test_composite_window_enforced() -> None:
    from clurichaun.detect import _link_multipart, CompositeRule
    from clurichaun.models import Finding as F, Detector as D, Severity as Sv

    def mk(rule_id, line, secret):  # type: ignore[no-untyped-def]
        return F(rule_id, "t", D.REGEX, Sv.HIGH, "p", "p", line, 1, secret, "x")

    near = [mk("aws.access-key-id", 1, AWS_KEY), mk("aws.secret-access-key", 3, AWS_SECRET)]
    _link_multipart(near)
    assert near[0].secret_v2 == f"{AWS_KEY}:{AWS_SECRET}"

    far = [mk("aws.access-key-id", 1, AWS_KEY), mk("aws.secret-access-key", 500, AWS_SECRET)]
    _link_multipart(far, [CompositeRule("aws.access-key-id", "aws.secret-access-key", window=40)])
    assert far[0].secret_v2 is None, "pairs beyond the window must not link"


# --------------------------------------------------------------------------- #
# G6 container image scanning
# --------------------------------------------------------------------------- #


def test_scan_image_tarball_layers(tmp_path: Path) -> None:
    import io
    import tarfile

    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as t:
        data = f"AWS_ACCESS_KEY_ID={AWS_KEY}\n".encode()
        info = tarfile.TarInfo("app/.env")
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    layer_bytes = layer.getvalue()

    image = tmp_path / "image.tar"
    with tarfile.open(image, "w") as t:
        info = tarfile.TarInfo("sha/layer.tar")
        info.size = len(layer_bytes)
        t.addfile(info, io.BytesIO(layer_bytes))

    engine = ScannerEngine(ScanConfig(roots=[str(image)], scope=scope.ScopeFilter(), workers=1))
    findings = engine.run()
    aws = [f for f in findings if f.rule_id == "aws.access-key-id"]
    assert aws, "secret nested in an image layer must be found"
    assert "layer.tar!/app/.env" in aws[0].logical_path


# --------------------------------------------------------------------------- #
# Token-efficiency rescoring (deterministic; no LLM in v1)
# --------------------------------------------------------------------------- #


def test_token_efficiency_degrades_without_tiktoken() -> None:
    from clurichaun.rescore import TokenEfficiency

    scorer = TokenEfficiency()
    # Whether or not tiktoken is installed, rescore must never raise.
    from clurichaun.models import Finding as F, Detector as D, Severity as Sv

    f = F("r", "t", D.REGEX, Sv.MEDIUM, "p", "p", 1, 1, "abc", "y", confidence=0.6)
    scorer.rescore([f])
    if not scorer.available:
        assert f.confidence == 0.6  # no-op when absent


# --------------------------------------------------------------------------- #
# G4 defender-led revocation (dry-run by default, verified-active only)
# --------------------------------------------------------------------------- #


def _mk_active(rule_id: str, secret: str):  # type: ignore[no-untyped-def]
    from clurichaun.models import Finding as F, Detector as D, Severity as Sv, Verified
    return F(rule_id, "t", D.REGEX, Sv.CRITICAL, "p", "p", 1, 1, secret, "x", verified=Verified.ACTIVE)


def test_revoke_plan_only_verified_active() -> None:
    from clurichaun.models import Finding as F, Detector as D, Severity as Sv, Verified
    from clurichaun.revoke import Revoker

    active = _mk_active("slack.token", "xoxb-1-2-abc")
    unverified = F("slack.token", "t", D.REGEX, Sv.CRITICAL, "p", "p", 1, 1, "xoxb-x", "y")
    plans = Revoker().plan([active, unverified])
    assert len(plans) == 1 and plans[0].provider == "slack" and plans[0].automated


def test_revoke_github_is_manual() -> None:
    from clurichaun.revoke import Revoker

    plans = Revoker().plan([_mk_active("github.token", "ghp_" + "a" * 36)])
    assert len(plans) == 1 and not plans[0].automated
    assert "github.com/settings/tokens" in plans[0].detail


def test_revoke_execute_with_mock_session() -> None:
    from clurichaun.revoke import Revoker

    class Resp:
        def json(self):  # type: ignore[no-untyped-def]
            return {"revoked": True}

    class Sess:
        def __init__(self):
            self.calls = []

        def post(self, url, headers=None, **kw):  # type: ignore[no-untyped-def]
            self.calls.append(url)
            return Resp()

    sess = Sess()
    revoker = Revoker(session=sess)
    plans = revoker.plan([_mk_active("slack.token", "xoxb-1-2-abc")])
    results = revoker.execute(plans)
    assert results[0].ok
    assert "auth.revoke" in sess.calls[0]


# --------------------------------------------------------------------------- #
# Track C: cloud bucket + GitHub comment sources (injected fakes, no network)
# --------------------------------------------------------------------------- #


def test_cloud_source_scans_objects() -> None:
    from clurichaun.cloudsource import CloudSource
    from clurichaun.models import ScanStats

    class FakeClient:
        def __init__(self, objs):
            self.objs = objs

        def list_objects(self, prefix):
            for k, v in self.objs.items():
                if k.startswith(prefix):
                    yield k, len(v)

        def get_object(self, key):
            return self.objs[key]

    objs = {
        "config/prod.env": f"AWS_ACCESS_KEY_ID={AWS_KEY}\n".encode(),
        "readme.txt": b"nothing here",
    }
    source = CloudSource(FakeClient(objs), prefix="", scheme="s3", bucket="mybucket")
    engine = ScannerEngine(ScanConfig(roots=["s3://mybucket"], scope=scope.ScopeFilter(), workers=1))
    findings = engine.scan_blob_stream(source.blobs(engine.stats))
    aws = [f for f in findings if f.rule_id == "aws.access-key-id"]
    assert aws and aws[0].logical_path == "s3://mybucket/config/prod.env"


def test_cloud_source_skips_oversized_object() -> None:
    from clurichaun.cloudsource import CloudSource
    from clurichaun.models import ScanStats

    class FakeClient:
        def list_objects(self, prefix):
            yield "huge.bin", 10**9

        def get_object(self, key):
            raise AssertionError("must not fetch an oversized object")

    stats = ScanStats()
    source = CloudSource(FakeClient(), max_object_bytes=1024, scheme="s3", bucket="b")
    assert list(source.blobs(stats)) == []
    assert any("over limit" in e for e in stats.errors)


def test_parse_bucket_uri() -> None:
    from clurichaun.cloudsource import parse_bucket_uri

    assert parse_bucket_uri("s3://bucket/a/b") == ("s3", "bucket", "a/b")
    assert parse_bucket_uri("gs://bucket/x") == ("gs", "bucket", "x")
    with pytest.raises(ValueError):
        parse_bucket_uri("http://not-a-bucket")


def test_github_source_scans_comment_bodies() -> None:
    from clurichaun.models import ScanStats
    from clurichaun.scmsource import GitHubSource

    pages = {
        "/repos/o/r/issues": [
            {"number": 1, "body": f"here is the key AWS_ACCESS_KEY_ID={AWS_KEY}"},
        ],
        "/repos/o/r/issues/comments": [
            {"id": 55, "body": "no secret in this comment"},
        ],
        "/repos/o/r/pulls/comments": [
            {"id": 99, "body": f"token: {GITHUB_TOKEN}"},
        ],
    }

    class Resp:
        def __init__(self, data):
            self.status_code = 200
            self._data = data

        def json(self):
            return self._data

    class FakeSession:
        def get(self, url):
            for path, data in pages.items():
                if path in url and "page=1" in url:
                    return Resp(data)
            return Resp([])  # page 2 empty -> stop

    stats = ScanStats()
    source = GitHubSource(owner="o", repo="r", session=FakeSession())
    engine = ScannerEngine(ScanConfig(roots=["o/r"], scope=scope.ScopeFilter(), workers=1))
    findings = engine.scan_blob_stream(source.blobs(engine.stats))
    ids = {f.rule_id for f in findings}
    assert "aws.access-key-id" in ids  # in an issue body
    assert "github.token" in ids       # in a PR review comment
    paths = {f.logical_path for f in findings}
    assert any("issue/1" in p for p in paths)
    assert any("review-comment/99" in p for p in paths)


# --------------------------------------------------------------------------- #
# Track B: AWS SigV4 verify + revoke
# --------------------------------------------------------------------------- #


def test_awssig_matches_aws_reference() -> None:
    import hashlib
    import hmac

    from clurichaun.awssig import signing_key

    def ref(key, date, region, service):  # AWS docs canonical code
        def s(k, m):
            return hmac.new(k, m.encode(), hashlib.sha256).digest()
        return s(s(s(s(("AWS4" + key).encode(), date), region), service), "aws4_request")

    for date in ("20120215", "20150830"):
        assert signing_key("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", date, "us-east-1", "iam") == \
            ref("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", date, "us-east-1", "iam")


def test_awssig_signs_with_expected_headers() -> None:
    from clurichaun.awssig import caller_identity_body, sign

    signed = sign("AKIAEXAMPLE", "secret", "us-east-1", "sts",
                  caller_identity_body(), "sts.amazonaws.com")
    assert signed.url == "https://sts.amazonaws.com/"
    auth = signed.headers["Authorization"]
    assert auth.startswith("AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/")
    assert "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date" in auth
    assert "x-amz-date" in signed.headers


def test_split_pair() -> None:
    from clurichaun.awssig import split_pair

    assert split_pair(f"{AWS_KEY}:{AWS_SECRET}") == (AWS_KEY, AWS_SECRET)
    assert split_pair("nopair") is None
    assert split_pair("notakey:secret") is None


class _AwsSession:
    def __init__(self, status, text):
        self.status = status
        self.text = text
        self.calls = []

    def post(self, url, data=None, headers=None, **kw):  # type: ignore[no-untyped-def]
        self.calls.append(url)

        class R:
            status_code = self.status
            text = self.text
        return R()


def test_verify_aws_active_maps_identity() -> None:
    from clurichaun.models import Finding as F, Detector as D, Severity as Sv, Verified
    from clurichaun.verify import Verifier, VerifyConfig

    finding = F("aws.access-key-id", "t", D.REGEX, Sv.CRITICAL, "p", "p", 1, 1,
                AWS_KEY, "x", secret_v2=f"{AWS_KEY}:{AWS_SECRET}", confidence=0.9)
    sts = "<GetCallerIdentityResult><Arn>arn:aws:iam::123:user/bob</Arn><Account>123</Account></GetCallerIdentityResult>"
    sess = _AwsSession(200, sts)
    Verifier(VerifyConfig(enabled=True), session=sess).run([finding])
    assert finding.verified is Verified.ACTIVE
    assert finding.access["identity"] == "arn:aws:iam::123:user/bob"
    assert finding.access["account"] == "123"
    assert "sts.amazonaws.com" in sess.calls[0]


def test_verify_aws_inactive() -> None:
    from clurichaun.models import Finding as F, Detector as D, Severity as Sv, Verified
    from clurichaun.verify import Verifier, VerifyConfig

    finding = F("aws.access-key-id", "t", D.REGEX, Sv.CRITICAL, "p", "p", 1, 1,
                AWS_KEY, "x", secret_v2=f"{AWS_KEY}:{AWS_SECRET}", confidence=0.9)
    Verifier(VerifyConfig(enabled=True), session=_AwsSession(403, "InvalidClientTokenId")).run([finding])
    assert finding.verified is Verified.INACTIVE


def test_revoke_aws_reports_access_denied() -> None:
    from clurichaun.revoke import revoke_aws

    sess = _AwsSession(403, "<Error><Code>AccessDenied</Code></Error>")
    ok, detail = revoke_aws(f"{AWS_KEY}:{AWS_SECRET}", sess)
    assert not ok and "AccessDenied" in detail
    assert "iam.amazonaws.com" in sess.calls[0]


# --------------------------------------------------------------------------- #
# Dependency-cache pruning (Go module cache etc.) by path fragment
# --------------------------------------------------------------------------- #


def test_skip_dependency_caches_by_path() -> None:
    from clurichaun.scope import ScopeFilter

    sf = ScopeFilter()
    # Dependency caches are pruned by path fragment...
    assert sf.skip_dir("mod", "/home/u/go/pkg/mod")
    assert sf.skip_dir("registry", "/home/u/.cargo/registry")
    assert sf.skip_dir("repository", "/home/u/.m2/repository")
    # ...but a real Go project's pkg/ or mod/ is NOT pruned.
    assert not sf.skip_dir("pkg", "/home/u/myproject/pkg")
    assert not sf.skip_dir("mod", "/home/u/myproject/mod")
    assert not sf.skip_dir("src", "/home/u/myproject/src")
    # --all-dirs disables all pruning.
    assert not ScopeFilter(follow_deny_dirs=True).skip_dir("mod", "/home/u/go/pkg/mod")


# --------------------------------------------------------------------------- #
# Results are persisted by default (history DB + auto-saved JSON report)
# --------------------------------------------------------------------------- #


def test_scan_persists_by_default(tmp_path: Path, monkeypatch) -> None:
    from click.testing import CliRunner
    from clurichaun.cli import main

    home = tmp_path / "state"
    target = tmp_path / "proj"
    target.mkdir()
    (target / "a.env").write_text(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n", encoding="utf-8")
    monkeypatch.setenv("CLURICHAUN_HOME", str(home))

    result = CliRunner().invoke(main, ["scan", str(target), "-q"])
    assert (home / "history.db").is_file(), "history DB created by default"
    reports = list((home / "reports").glob("*.json"))
    assert reports, "a JSON report auto-saved by default"
    doc = json.loads(reports[0].read_text())
    assert doc["summary"]["findings"] >= 1


def test_scan_no_save_flags(tmp_path: Path, monkeypatch) -> None:
    from click.testing import CliRunner
    from clurichaun.cli import main

    home = tmp_path / "state"
    target = tmp_path / "proj"
    target.mkdir()
    (target / "a.env").write_text(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n", encoding="utf-8")
    monkeypatch.setenv("CLURICHAUN_HOME", str(home))

    CliRunner().invoke(main, ["scan", str(target), "-q", "--no-db", "--no-report"])
    assert not (home / "history.db").exists()
    assert not (home / "reports").exists()


# --------------------------------------------------------------------------- #
# Content-hash incremental: skip by hash, not mtime/size
# --------------------------------------------------------------------------- #


def test_incremental_is_content_hash_based(tmp_path: Path) -> None:
    import os

    db = str(tmp_path / "db.sqlite")           # kept OUTSIDE the scanned tree
    target = tmp_path / "proj"
    target.mkdir()
    f = target / "a.env"
    f.write_text(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n", encoding="utf-8")

    def run():  # type: ignore[no-untyped-def]
        eng = ScannerEngine(
            ScanConfig(roots=[str(target)], workers=1, db_path=db, incremental=True)
        )
        found = eng.run()
        return eng.stats.files_scanned, eng.stats.files_skipped, found

    scanned1, skipped1, found1 = run()
    assert scanned1 == 1 and any(f.rule_id == "aws.access-key-id" for f in found1)

    # Second run, nothing changed -> skipped by hash.
    scanned2, skipped2, _ = run()
    assert scanned2 == 0 and skipped2 == 1

    # Bump mtime but keep content identical -> STILL skipped (mtime-based would rescan).
    os.utime(f, (0, 0))
    scanned3, skipped3, _ = run()
    assert scanned3 == 0 and skipped3 == 1, "mtime-only change must not trigger a rescan"

    # Change content but keep the SAME byte length -> must be rescanned
    # (this is the case a size/mtime check can miss).
    new = f"AWS_ACCESS_KEY_ID={AWS_KEY[:-1]}X\n"
    assert len(new) == len(f.read_text())
    f.write_text(new, encoding="utf-8")
    scanned4, skipped4, _ = run()
    assert scanned4 == 1, "a same-size content change must be rescanned"


def test_cli_incremental_default_keeps_report_complete(tmp_path: Path, monkeypatch) -> None:
    from click.testing import CliRunner
    from clurichaun.cli import main

    home = tmp_path / "state"
    target = tmp_path / "proj"
    target.mkdir()
    (target / "a.env").write_text(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n", encoding="utf-8")
    monkeypatch.setenv("CLURICHAUN_HOME", str(home))
    runner = CliRunner()

    # First scan (default: incremental on, empty DB -> scans everything).
    runner.invoke(main, ["scan", str(target), "-q"])
    # Second scan: unchanged file is not re-scanned, but the report must still
    # contain the finding (carried forward).
    runner.invoke(main, ["scan", str(target), "-q"])

    reports = sorted((home / "reports").glob("*.json"))
    assert len(reports) == 2
    latest = json.loads(reports[-1].read_text())
    ids = {f["rule_id"] for f in latest["findings"]}
    assert "aws.access-key-id" in ids, "second incremental run's report stays complete"


# --------------------------------------------------------------------------- #
# Live streaming: every source emits findings via on_result as they arrive
# --------------------------------------------------------------------------- #


def test_git_history_findings_stream(deleted_secret_repo: Path) -> None:
    streamed: list = []
    eng = ScannerEngine(
        ScanConfig(roots=[str(deleted_secret_repo)], workers=1, git_history=True)
    )
    findings = eng.run(on_result=lambda r: streamed.extend(r.findings))
    git = [f for f in findings if f.rule_id == "aws.secret-access-key"]
    streamed_git = [f for f in streamed if f.rule_id == "aws.secret-access-key"]
    assert git and len(streamed_git) == len(git)


def test_blob_stream_findings_stream() -> None:
    streamed: list = []
    eng = ScannerEngine(ScanConfig(roots=["x"], workers=1, scope=scope.ScopeFilter()))
    items = [("a.env", f"AWS_ACCESS_KEY_ID={AWS_KEY}\n".encode())]
    findings = eng.scan_blob_stream(items, on_result=lambda r: streamed.extend(r.findings))
    assert findings and {f.fingerprint for f in streamed} == {f.fingerprint for f in findings}


def test_staged_findings_stream(tmp_path: Path) -> None:
    import subprocess

    def git(*a: str) -> None:
        subprocess.run(["git", "-C", str(tmp_path), *a], check=True, capture_output=True)

    git("init"); git("config", "user.email", "t@e"); git("config", "user.name", "t")
    (tmp_path / "s.env").write_text(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n", encoding="utf-8")
    git("add", "s.env")
    streamed: list = []
    eng = ScannerEngine(ScanConfig(roots=[str(tmp_path)], staged=True))
    findings = eng.run(on_result=lambda r: streamed.extend(r.findings))
    assert findings and len(streamed) == len(findings)
