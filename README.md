# Clurichaun

Universal secret, credential, endpoint and configuration-leakage scanner. Reads
*anything* — plaintext, minified bundles, source maps, binaries, archives,
structured config — and reports in table, JSON or SARIF.

## Installation

Requires **Python ≥ 3.11**. The core has three small pure-Python dependencies
(`click`, `PyYAML`, `rich`); everything else is an opt-in extra.

```bash
# From GitHub (latest release)
pip install "git+https://github.com/kfoxirl/clurichaun.git@v0.3.0"

# ...or the current main
pip install "git+https://github.com/kfoxirl/clurichaun.git"

# ...or from a local clone
git clone https://github.com/kfoxirl/clurichaun.git
cd clurichaun
pip install .            # or `pip install -e .` for a development install
```

This installs the `clurichaun` command. Verify:

```bash
clurichaun --version
clurichaun scan --help
```

### Optional extras

The local scanner never imports a network or cloud library — each feature loads
its dependencies lazily and tells you which extra to install if they are
missing. Install only what you need:

| Extra | Enables | Pulls in |
|---|---|---|
| `web` | `scan-web`, `scan-github`, `--verify` | `requests`, `beautifulsoup4` |
| `cloud` | `scan-bucket` (S3 / GCS) | `boto3`, `google-cloud-storage` |
| `ml` | `--token-efficiency` rescoring | `tiktoken` |
| `full` | better type sniffing + 7z/rar archives + `web` | `python-magic`, `py7zr`, `rarfile`, `requests`, `beautifulsoup4` |
| `dev` | test/lint toolchain | `pytest`, `mypy`, `ruff` |

```bash
pip install "clurichaun[web] @ git+https://github.com/kfoxirl/clurichaun.git"
pip install ".[full]"          # from a clone
pip install ".[web,cloud,ml]"  # combine extras
```

> `python-magic` (in `full`) needs the system `libmagic` library
> (`apt install libmagic1`, `brew install libmagic`). It is optional — without
> it, Clurichaun falls back to pure-Python magic-byte sniffing.

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/kfoxirl/clurichaun
    rev: v0.3.0
    hooks:
      - id: clurichaun
```

## Usage

```bash
clurichaun scan ./repo                          # human table
clurichaun scan ./repo --scope-only             # only high-value target paths
clurichaun scan . -f sarif -o out.sarif --fail-on high
clurichaun scan ./dist --category sourcemap --category frontend
clurichaun scan /srv --baseline known.json -j 16
clurichaun rules                                # list the ruleset
clurichaun scope                                # list the target scope
clurichaun classify dist/app.js.map .env.prod   # explain path targeting
clurichaun scan-web https://target.tld/          # crawl a site, scan what it serves
clurichaun packs                                 # list bundled rule packs
clurichaun scan . --rule-pack gitleaks           # + 219 provider rules
```

`scan-web` crawls from a URL and pushes the fetched **bytes** through the same
ingestion pipeline, so remote archives, source maps and binaries behave exactly
as they do on disk. It stays on the starting host (`--any-host` to leave),
rate-limits with `--delay`, and caps each resource at `--max-bytes`.

### Site-declared agent policy

Pointing a secret scanner at someone else's host is an outward-facing act, so
three conventions are honoured by default:

| File | Read as | Override |
|---|---|---|
| `robots.txt` | per-path crawl permission | `--no-robots` |
| `/.well-known/ai.txt`, `/ai.txt` | AI usage policy | `--no-ai-txt` |
| `/llms.txt` | seed index of the site's own content | `--no-llms-txt` |

`ai.txt` is read in both dialects: the IETF draft's block key-value form
(`Scraping:`, `Training:`, `Rate-Limit: N/window`, `Contact:`, per-`Agent:`
overrides) and Spawning's earlier robots-shaped form. For a scanner the
operative field is **`Scraping`** — we fetch and analyse, we do not train — so
`Scraping: deny` stops the crawl and says so, while `Training:` and
`Attribution:` are reported but do not govern scanning. A declared
`Rate-Limit` is an instruction: the stricter of it and `--delay` wins.

`llms.txt` is not a permission file — it is a Markdown index a site publishes
*for* agents, so its links are used as crawl seeds, which finds content that no
amount of link-walking would reach.

Whatever policy the site declares is printed to stderr before the first
finding, contact address included.

### Results are saved automatically

Every `scan` keeps its results, so a long run is never lost to the terminal:

- a **JSON snapshot** per scan at `~/.clurichaun/reports/<timestamp>_<target>.json`
- a cumulative **history datastore** at `~/.clurichaun/history.db`

The human table still prints; the snapshot and history are written alongside it.
Override or disable:

```bash
clurichaun scan . -o report.json        # your own report path/format instead
clurichaun scan . --no-report           # do not auto-save a JSON snapshot
clurichaun scan . --no-db               # do not record to the history datastore
clurichaun scan . --db ./project.db     # a different datastore location
```

Set `CLURICHAUN_HOME` to relocate the whole state directory.

### Incremental by default, without losing completeness

A repeat scan of the same tree is fast: a file whose **content hash** is
unchanged since the last scan is not re-read for detection. But the report stays
**complete** — an unchanged file's findings are carried forward from the
datastore, so `scan .` always shows every secret present, not just the ones in
files that changed. Content-hash based, so a change that preserved a file's
mtime/size (a `git checkout`, a `cp -p`) is still caught.

```bash
clurichaun scan .              # incremental + carry-forward (default)
clurichaun scan . --full       # force a complete re-scan of everything
clurichaun scan . --new-only   # report only findings new since the last scan
```

### Live results

When printing to a terminal, findings stream into a live table as they are
found, with a running severity tally — no waiting until the end. Piped or
redirected output (`-o`, `-f json`, non-TTY) prints the final table/report as
usual.

Secrets are **redacted by default** (`AKIA...RTVW`) in every format, including
match context — `--unredact` opts out. `--fail-on <severity>` gives CI a gate;
`--baseline <prior.json>` suppresses fingerprints already triaged.

## Architecture

| Module | Role |
|---|---|
| `scope.py` | Target scope: allowlist categories, denylists, per-path confidence boost |
| `ingest.py` | `FileIngestor` — magic-byte sniffing, decode ladder, archive unpacking, binary strings, chunked streaming |
| `parsers.py` | Structured parsers + recursive `key.path -> value` flattening |
| `decode.py` | Decoder layer: base64/escape/percent/entity views of each blob |
| `entropy.py` | Shannon entropy with structural false-positive filters |
| `patterns.py` | Rule table: regex, severity, validator, entropy floor, allowlists |
| `rules_toml.py` | Loads gitleaks-format TOML rule packs (incl. RE2 → `re`) |
| `stopwords.py` | Wordlist filter for candidate values |
| `web/policy.py` | `robots.txt`, `ai.txt` (both dialects), `llms.txt` |
| `detect.py` | `SecretDetector` — regex / entropy / key-name passes, scoring, dedup |
| `scanner.py` | `ScannerEngine` — walker, symlink-loop guard, worker pool |
| `report.py` | JSON, SARIF 2.1.0, rich/plain table |
| `web/crawler.py` | `WebCrawler` — discovery, robots, throttling, byte fetching |
| `cli.py` | `click` entry point (`scan`, `scan-web`, `rules`, `scope`, `classify`) |

Everything downstream of ingestion consumes `Blob` objects, so the detector is
indifferent to whether text came from a file, a `.jar` inside a `.tar.gz`, a
source map's `sourcesContent`, or printable runs carved from a `.pyc`.

## Ingestion

* **Type detection** — magic bytes first, `libmagic` if installed, extension last.
* **Decoding** — `utf-8` → `utf-8-sig` → `cp1252` → `latin-1`, with
  `errors="replace"` as the floor. UTF-16 only on an explicit BOM (without one it
  silently turns single-byte text into CJK mojibake).
* **Archives** — ZIP, TAR, GZ/BZ2/XZ, 7z (`py7zr`), RAR (`rarfile`), plus every
  zip-shaped container: `jar`, `war`, `apk`, `whl`, `vsix`, `asar`, `nupkg`.
  Recursion is depth-, member-count-, member-size- and expansion-ratio-limited,
  and member names are traversal-neutralised (they are display data only).
* **Binaries** — printable ASCII and UTF-16LE runs are carved out and scanned
  (`.pyc`, `.class`, `.wasm`, `.so`, `.dex`, `.sqlite`, `.DS_Store`, swap files).
* **Source maps** — `sourcesContent` is exploded into per-source blobs, so
  pre-build code and developer comments are scanned as themselves.
* **Large files** — anything over `--stream-threshold` (8M) is read in 4M chunks
  with an 8K overlap so no token is split across a boundary; line numbers carry
  across chunks.

Nested content keeps a logical path: `dist/bundle.zip!/inner/prod.env`.

## Detection

Three passes, deduplicated by `sha256(rule, path, secret)` fingerprint, each run
over the raw text **and** over every decoded view of it (see Decoding below):

1. **Regex** — ~40 rules across AWS, Azure, GCP, GitHub/GitLab, Slack, Stripe,
   npm/PyPI, JWTs, private keys, DB URIs, basic-auth URLs, internal/external
   endpoints, IPv4/IPv6. Rules carry validators: JWT headers must base64-decode
   to JSON with an `alg`; DB URIs must carry a non-placeholder password; IPv4
   rules split RFC1918 from public. Rules may also carry a `min_entropy` floor
   on the captured value, match-allowlist regexes, and a stopword filter — a
   candidate containing an ordinary word or a known placeholder is dropped
   (ported from gitleaks, MIT; see `NOTICE.md`).
2. **Entropy** — Shannon scoring over base64 (≥4.3 bits) and hex (≥3.2) tokens,
   with thresholds raised inside minified bundles and lockfiles. UUIDs, git
   SHAs, camel/snake identifiers, paths, dates, `integrity:`/`sha512-`/ETag
   contexts and low-cardinality strings are suppressed.
3. **Key name** — documents are parsed and flattened, then keys matching
   `password|secret|token|api_key|…` with a non-placeholder value are reported.
   This catches `{"services":{"redis":{"auth_token":"…"}}}`, which no regex
   would flag. Parsers: JSON/JSONC, YAML, TOML, XML, plist, INI, `.env`,
   `.properties`, `.npmrc`, `.reg`, systemd units, shell, HCL/Terraform,
   `.tfstate`, Dockerfile.

Confidence combines the rule's base score, entropy margin, nearby key names and
a **path interest boost** — the same token is worth more in `.env.production`
(+0.20) or `~/.ssh/` (+0.25) than in a minified bundle (−0.10). Vendor-published
fakes (`AKIAIOSFODNN7EXAMPLE`) and inline ignores (`clurichaun:ignore`,
`pragma: allowlist secret`, `gitleaks:allow`) are dropped.

## Decoding

A secret behind one layer of encoding is invisible to every regex, so each blob
is also re-presented with encoded runs decoded in place — base64/base64url,
`\uXXXX` and `\xNN` escapes, percent-encoding, and HTML/XML entities — and the
three passes run again over each view. Substitution happens *in place* so
keyword-context rules still see their surroundings. A decoded finding carries a
`#<label>` logical-path suffix, a note, and slightly lower confidence; if the
plaintext pass already found the same secret, the decoded duplicate is dropped.
`--no-decoders` disables the layer. Technique adopted from TruffleHog
(`docs/dev/ASSIMILATION.md`); implementation is ours.

## Rule packs

The ruleset is extensible in gitleaks' TOML format, which Clurichaun reads
natively — an existing `gitleaks.toml` works unchanged:

```bash
clurichaun packs                          # bundled packs and their rule counts
clurichaun packs gitleaks                 # what loads, what does not, and why
clurichaun scan . --rule-pack gitleaks    # +219 gitleaks rules
clurichaun scan . --rule-pack noseyparker # +187 Nosey Parker rules (Apache-2.0)
clurichaun scan . --rule-pack ./house.toml
```

`keywords` become literal prefilters, `entropy` becomes a per-rule floor,
`secretGroup` picks the capture group (absent → first non-empty group), and
`[[rules.allowlists]]` regexes, stopwords and paths are applied. Keys we cannot
honour are listed by `clurichaun packs <pack>` rather than silently ignored.
Go's RE2 allows inline `(?i)` mid-pattern where Python does not; the loader
rewrites `pre(?i)post` as `pre(?i:post)`, preserving RE2's semantics. The
bundled pack is gitleaks' own, MIT-licensed — see `NOTICE.md`.

## Target scope

`clurichaun scope` prints the full matcher table. Categories: `frontend`,
`sourcemap`, `config`, `iac`, `vcs`, `ide`, `keys`, `manifest`, `dump`,
`archive`, `apispec`, `bytecode`. `--scope-only` restricts scanning to paths
that match one; `--category` narrows further; `--include`/`--exclude` globs
override both. Media, fonts and office formats are denied by extension, and
`node_modules`, `vendor`, `.venv`, `.terraform`, build caches and friends are
pruned from the walk (`--all-dirs` to descend anyway). `.git`, `.svn`, `.hg` and
`.bzr` are deliberately *not* pruned — their metadata is in scope.

## Performance

`ProcessPoolExecutor` over the file list, one detector per worker built once in
the initializer (`--threads` for I/O-bound network mounts, `-j` to pin the count).
Walk-time symlink-loop protection via `(st_dev, st_ino)`; permission and encoding
failures land in `stats.errors` instead of aborting the run. Cross-platform path
handling covers Win32 long paths (`\\?\`), UNC shares, and surrogate-escaped
filename bytes.

Each file gets a wall-clock budget (`--file-timeout`, default 30 s): a worker
that overruns keeps its partial findings, records the timeout in `stats.errors`
and moves on, so one pathological file cannot stall a scan.

Reference: ~770 files / 11.5 MB of mixed Python, YAML and JS in ~1.0 s wall.

## Cross-platform notes

Linux, macOS and Windows. Symlinks are not followed by default
(`--follow-symlinks`); device nodes, FIFOs and empty files are skipped. Long
paths are prefixed on Win32 only, and reports always render forward-slashed
paths relative to the scan root.

## Exit codes

`0` clean (or `--fail-on never`), `1` a finding at or above `--fail-on`,
`2` a CLI/usage error.

## Tests

```bash
python -m pytest -q     # 118 tests: detection, decoding, ingestion, parsers, packs, scope, engine, web, sources, verify, output
```

## About the name

A **clúrachán** (anglicised *clurichaun*) is a creature of Irish folklore — a
small, solitary fairy, often said to be a leprechaun's night-time cousin. Where
the leprechaun mends shoes, the clurichaun keeps to the **cellar**: he is the
self-appointed guardian of the household's hidden hoard, and he knows exactly
what is stashed behind every cask and in every dark corner. Cross him and he
turns the wine sour; keep on his good side and nothing goes missing without his
say-so.

It seemed a fitting patron for a tool that rummages through the cellars of a
codebase — the archives, the binaries, the forgotten `.env` in git history — and
tells you precisely which secrets are hidden where.
