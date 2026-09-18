# Changelog

## v0.1.0 — 2026-09-18

First release. A cross-platform Python secret/credential/endpoint scanner that
reads virtually any file type and reports as table, JSON or SARIF.

### Detection
- Regex ruleset (AWS, Azure, GCP, GitHub/GitLab, Slack, Stripe, npm/PyPI, JWTs,
  private keys, DB URIs, more), Shannon-entropy analysis, and structured
  key-name detection over JSON/YAML/TOML/XML/plist/INI/HCL/.tfstate/.reg/systemd/
  Dockerfile.
- Decoder layer: re-scans base64 / `\uXXXX` / percent / HTML-entity views, so a
  secret behind one layer of encoding is still found.
- Offline checksum validation for GitHub tokens (CRC32/base62), and multi-part
  credential identity (AWS id+secret) so a rotated secret is not deduped away.
- Bundled rule packs in gitleaks TOML and Nosey Parker YAML formats
  (`--rule-pack gitleaks|noseyparker`), with an RE2→`re` translation layer.
- Measured on CredData: precision 0.80, recall 0.57, F1 0.67 at shipping
  defaults (`benchmarks/`).

### Ingestion
- Archives (zip/tar/gz/7z/rar, jar/apk/whl/…), binary string-carving, source-map
  `sourcesContent`, chunked streaming for large files (correct line numbers, no
  cross-chunk duplicates), cross-platform paths.

### Sources
- Filesystem, git history (`--git-history`, finds committed-then-deleted
  secrets), git staged (`--staged`, pre-commit), container images
  (`scan-image`), object storage (`scan-bucket` s3://|gs://), GitHub repo/org
  issue & PR comments (`scan-github`), and web crawl (`scan-web`) honouring
  robots.txt / ai.txt / llms.txt.

### Triage & response
- Live verification (`--verify`, read-only) for GitHub/Slack/Stripe/OpenAI/AWS,
  with blast-radius/scope capture; actionability tiers (`--only-actionable`);
  SQLite datastore for incremental scans, content dedup and finding history
  (`--db`, `--incremental`, `--new-only`); defender-led revocation
  (`clurichaun revoke`, dry-run default, verified-active only).

### Performance
- Aho-Corasick keyword prefilter (activates past 80 rules), batched process
  pool with a per-file wall-clock budget (`--file-timeout`) and BrokenProcessPool
  fallback. A 28k-file tree with an 823 MB packfile scans in ~163 s.

### Integrations
- SARIF 2.1.0 with git provenance and verification state, `.pre-commit-hooks.yaml`,
  a sample GitHub Action, redaction by default.

Deliberately deferred past v1: LLM-in-the-loop triage, GCP/Azure verification,
ML/high-recall detection, and cloud/SCM source breadth beyond the above.
