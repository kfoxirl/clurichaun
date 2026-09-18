# Assimilating TruffleHog and gitleaks

Assessment of the two reference implementations and what Clurichaun should take
from each. Surveyed 2026-09-17 at `--depth 1`:

| Project | Licence | Size | What it is |
|---|---|---|---|
| trufflesecurity/trufflehog | **AGPL-3.0** | 3,312 Go files, 904 detectors | regex + live verification over many sources |
| gitleaks/gitleaks | **MIT** | 222 TOML rules, small Go core | regex + entropy + allowlists, config-driven |

The licences make these two completely different propositions: gitleaks' code
and rule corpus can be incorporated with attribution, TruffleHog's cannot.
Attribution for everything taken lives in `NOTICE.md`.

## The hard constraint: licence

**TruffleHog is AGPL-3.0. Clurichaun is MIT.**

* **Code cannot come across.** Copying, or translating Go→Python, makes
  Clurichaun a derivative work and forces it to AGPL-3.0 — which for a scanner
  people may run as a service is a much heavier obligation than Karl signed up
  for. That includes their 904 detector regexes as a body of work and their
  embedded false-positive wordlists (`fp_words.txt`, `fp_badlist.txt`,
  `fp_programmingbooks.txt`, `fp_uuids.txt`).
* **Techniques and architecture can.** Ideas, algorithm choices, interface
  shapes and "what to check for" are not copyrightable. A credential's public
  format (`AKIA` + 16 upper-alphanumerics) is a published vendor fact; writing
  our own pattern from the vendor's docs is clean.

So: read their code for *what problems they solved*, then solve them our way.
Everything below was implemented or judged on that basis. If the project ever adopts AGPL, this whole calculus changes and vendoring their detector corpus
becomes the single biggest win available.

## Adopted (done, tested)

### 1. Decoder layer — `clurichaun/decode.py`

Their `pkg/decoders` runs every detector over *decoded views* of each chunk
(UTF-8, base64, UTF-16, escaped unicode, HTML entities), substituting decoded
runs back in place so keyword-context rules still fire. This was Clurichaun's
biggest blind spot: `QUtJQVE3SlozTVBMWEsyTlJUVlc=` is an AWS key and no regex
in the ruleset could see it.

Ours derives up to four views per blob — base64/base64url, `\uXXXX`/`\xNN`
escapes, percent-encoding, HTML/XML entities — and re-runs all three detection
passes over each. Differences from theirs, on purpose:

* Strict alphabets: a run must match std *or* urlsafe base64 wholly, never a
  mix, and `=` may only trail. Without that, `KEY_ID=AKIA…` reads as one token
  and "decodes" to noise.
* Decoded output must be ≥90% printable and ≥8 bytes to be substituted.
* Plaintext wins: if `(rule, secret)` was already found in the undecoded pass,
  the decoded duplicate is dropped, and surviving decoded findings carry a
  `recovered after <label> decoding` note, a `#<label>` logical-path suffix and
  −0.05 confidence.
* UTF-16 is not a decoder here — `ingest` already handles BOM'd UTF-16 files and
  carves UTF-16LE runs out of binaries.

Cost on a real project tree: findings 1650 → 1687, wall time unchanged at ~1.0 s, and only
5 of the new findings came from a decoded view (all benign URL-decodes). No
false-positive blow-up. `--no-decoders` turns it off.

### 2. Per-file wall-clock budget — `--file-timeout` (default 30 s)

`pkg/handlers/archive.go` caps archive processing with `maxTimeout = 60s`. We had
no such bound, which is exactly the shape of a parallel-scan stall (since fixed): one
worker ground on a single file for 686 s while the pool sat idle. A worker now
arms `SIGALRM` per file, keeps whatever findings it had, records
`timed out after Ns, partially scanned` in `stats.errors`, and moves on. Falls
back to no budget where `SIGALRM` is unavailable (Windows, `--threads`).

This bounds the symptom; it does not explain the stall. §3 stays open.

## Adopt next, in priority order

1. **Verification.** Their whole edge: a detector says *maybe*, an API call says
   *yes*. `detectors.Result.Verified` plus `pkg/verificationcache` (cache
   verdicts so re-scans don't re-hit the API). Build `--verify` with
   GitHub `/user`, Slack `auth.test`, Stripe `/v1/account`, OpenAI `/v1/models`
   first (simple bearer GETs); AWS needs SigV4 for `sts:GetCallerIdentity`, so
   do it second. Off by default — this is the one feature that puts credentials
   on the wire.
2. **Multi-part fingerprints.** Their `Raw` vs `RawV2` split: fingerprint on the
   *identifier* where one exists, and on identifier+secret for multi-part
   credentials (AWS id + secret). Ours hashes `(rule, path, secret)`, so an AWS
   key id found next to two different secrets dedupes wrongly. Cheap fix,
   real correctness gain for baselines.
3. **Git history.** `pkg/gitparse` walks commits, staged and unstaged content.
   We only see the working tree plus `.git` metadata, so a secret that was
   committed and later deleted is invisible.
4. ~~**Dictionary false-positive filter.**~~ **Done, via gitleaks instead.**
   TruffleHog's `IsKnownFalsePositive` rejects a candidate containing an English
   word, but its wordlists are AGPL. gitleaks ships the same capability under
   MIT, so that is where ours came from — see the gitleaks section below.
5. ~~**Custom detectors from config.**~~ Superseded: adopt gitleaks' TOML
   `[[rules]]` schema instead (below), which is proven and gives existing
   gitleaks users a migration path.
6. **More sources.** S3/GCS buckets, Docker images, Postman, Jenkins,
   Elasticsearch. Each is a `blobs()`-shaped adapter on our side; the ingestion
   model already fits.

## Deliberately not adopted, with reasons

* **Aho-Corasick keyword core** (`pkg/engine/ahocorasick`). Their engine matches
  ~900 detectors' keywords in one automaton pass. We already got the same *kind*
  of win with plain literal prefilters (`patterns.PREFILTERS`, 41 MB file
  20 s → 8.8 s) because at ~40 rules, N calls to C-implemented `str.__contains__`
  beat a pure-Python trie walk. Revisit if the ruleset passes ~200 rules or if
  `pyahocorasick` becomes an accepted dependency.
* **Their 904 detectors.** Licence, plus 904 detectors is a maintenance
  organism, not a feature. Grow our ruleset from vendor docs as demand appears.
* **10 KB chunks / 3 KB peek.** Right for their streaming-source model; wrong
  for ours. We read whole files under 8 MB and use 4 MB chunks with 8 KB overlap
  above that, which is far fewer passes for the same coverage.
* **2 GB archive cap, depth 10.** Too permissive for a laptop or a scan of
  `$HOME`. Ours: 512 MB file / 32 MB binary / 64 MB member / depth 3, plus an
  expansion-ratio bomb guard they lack.
* **TUI, analyzers, Go concurrency model.** Not our shape.

## Where Clurichaun is already ahead (don't regress these while assimilating)

* **Structured key-name pass.** We parse JSON/YAML/TOML/XML/plist/INI/`.env`/
  `.reg`/systemd/HCL/`.tfstate`/Dockerfile and flatten to `key.path -> value`,
  so `{"services":{"redis":{"auth_token":"…"}}}` is caught by *key semantics*.
  TruffleHog is regex-and-verify over raw bytes; it has no structural view.
* **Target-scope categories and path-interest scoring** — the same token scores
  higher in `.env.production` or `~/.ssh/` than in a minified bundle.
* **SARIF 2.1.0** output with rule metadata and `security-severity`.
* **Source-map explosion** — `sourcesContent` becomes per-source blobs.
* **Redaction by default**, including cross-finding context scrubbing.

## Numbers

| | before | after |
|---|---|---|
| Tests | 35 | 66 |
| a real project tree findings | 1650 | 1687 |
| a real project tree wall time | ~1.0 s | ~1.0 s |
| Encoded-secret recall | none | base64, `\uXXXX`, `\xNN`, percent, entities |
| Stalled-file exposure | unbounded | 30 s per file, partial results kept |


---

# gitleaks — MIT, so code is on the table

gitleaks is the opposite case to TruffleHog: a smaller, config-driven engine
under a licence that lets us take the actual assets. Its value is not the
architecture (ours is richer: archives, binaries, structured parsers, decoders)
but its **rule craft** — 222 rules whose false-positive handling has been beaten
into shape by years of user reports.

## Adopted (done, tested)

### 1. The assignment-proximity pattern — `patterns.assignment()`

Their keyword-anchored rules all share one shape:

    [\w.-]{0,50}?(?:KEYWORD)(?:[ \t\w.-]{0,20})[\s'"]{0,3}
    (?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(CAPTURE)(?:[\x60'"\s;]|\\[nr]|$)

One pattern that covers `=`, `:`, `=>`, `:=`, `||`, `?=` and `,` with optional
quoting on both sides, which is why it works unchanged across YAML, JSON, INI,
shell, Java properties, JS and Go. Our old `generic.api-key-assignment` regex
handled `[:=]`, `=>` and `:=` only, and anchored on a hand-written keyword list.
Replaced.

### 2. Per-rule filters — `min_entropy`, `allow_regexes`, `use_stopwords`

gitleaks attaches false-positive controls to the *rule*, not the engine: an
`entropy` floor on the captured group, `allowlists.regexes` with
`regexTarget = "match"`, and `allowlists.stopwords`. Our engine only had a
global entropy pass that ran independently of the regex rules, so a rule could
not say "this capture must look random". All three now exist on `Rule` and are
enforced in `detect._regex_pass`.

### 3. The stopword list — `clurichaun/stopwords.py`

1,446 substrings from their `generic-api-key` rule: English words, placeholder
values, common dummy hashes. This is the dictionary false-positive filter that
the TruffleHog assessment listed as wanted-but-unlicensable — gitleaks supplies
the same capability under MIT. A candidate containing any of them is dropped.

### 4. The generic-key match allowlist — `GENERIC_KEY_ALLOWLIST`

Their curated regex for key names that *look* secret and never are:
`api_version`, `primary_key`, `public_token`, `keystore_file`, `csrf_token`,
`issuerkeyhash`, and — my favourite evidence that this list came from real bug
reports — `monkey` and `turkey`.

### Measured effect

On a real project tree (774 files, 11.5 MB), with no true positives lost:

| | before | after |
|---|---|---|
| `generic.api-key-assignment` hits | 126 | **12** |
| total findings | 1687 | 1568 |
| medium-severity findings | 217 | 98 |
| wall time | ~1.0 s | ~1.0 s |

All 12 survivors are genuine credentials in a real developer config. That is a ~90% cut in the
noisiest rule's false positives — the single largest precision gain so far.

### 5. TOML rule packs — `clurichaun/rules_toml.py` *(done)*

Their `[[rules]]` schema is the de-facto interchange format for secret
patterns, so Clurichaun reads it directly instead of inventing a rival:

    clurichaun packs                      # list bundled packs
    clurichaun packs gitleaks             # what loads, what does not, and why
    clurichaun scan . --rule-pack gitleaks
    clurichaun scan . --rule-pack ./house-rules.toml

Supported with gitleaks' own semantics: `id`, `description`, `regex`,
`keywords` (→ our literal prefilter, exactly as they use them), `entropy`
(→ `min_entropy`), `secretGroup` (→ `Rule.pick()`: named group, else first
non-empty group, else whole match), `path`, and `[[rules.allowlists]]` with
`regexes`/`regexTarget`/`stopwords`/`paths`. Unsupported keys are *reported*
by `clurichaun packs <pack>`, never silently dropped: `[extend]` inheritance,
allowlist `commits`, `condition = "AND"` (treating AND as OR would
over-suppress), and `regexTarget = "line"`.

**One translation was needed.** Go's RE2 permits an inline flag group like
`(?i)` anywhere, applying from that point to the end of the enclosing group;
Python's `re` demands global flags at position 0 and rejects the rest. Naively
hoisting `(?i)` to the front is wrong — it case-folds the prefix too, so
`sk_live_(?i)[a-z]{4}` would start matching `SK_LIVE_`. `compile_re2()`
rewrites `pre(?i)post` as `pre(?i:post)`, which is exactly RE2's meaning. That
took the pack from 199 of 222 rules to **219**; the 3 remaining are 2 patterns
with inline flags nested inside groups and 1 path-only rule.

### 6. Their whole rule corpus *(done, bundled)*

`clurichaun/rules/gitleaks.toml` ships verbatim with its MIT licence beside it
(`NOTICE.md`). Loading it costs ~0.65 s on 774 files — 1.0 s → 1.65 s — and on
a real project tree it adds 15 hits over the built-ins: 12 that duplicate our own generic
rule, 2 GCP API keys and 1 Telegram bot token. Opt-in rather than default,
since most of the 219 are provider patterns irrelevant to any given tree and
findings from packs can duplicate built-in rules (dedup keys on rule id).

## Adopt next from gitleaks
1. **`condition = "AND"` allowlists and `regexTarget = "line"`.** Both need the
   containing line handed to the allowlist evaluator. `allowlists.paths` is
   already wired (`Rule.deny_paths`).
2. **`.gitleaksignore`-compatible baseline.** Ours is a JSON report; theirs is a
   line-oriented fingerprint file. Reading both costs little and helps adoption.
3. **Severity metadata.** gitleaks has none, so `rules_toml._severity()` infers
   it from the rule id. That is a heuristic and will mislabel some rules; a
   curated id→severity table would be better.

## Not adopted

* **Their engine and source model.** Ours already covers more ground
  (archives, binaries, source maps, decoders, structured parsers, remote
  crawling) and is what the rest of this project is built around.
* **`secretGroup` as an integer field.** We already carry `group` on `Rule`;
  same idea, no change needed.
* **Their git-log-based scanning** as an implementation. The *capability* is
  still wanted (see TruffleHog item 3), but it should be built on our ingestion
  model rather than lifted.

## The licence lesson, stated plainly

Two projects solving the same problem, and the licence decided what each could
contribute: from AGPL TruffleHog, only ideas; from MIT gitleaks, the assets
themselves. Anything else imported from either must be checked against
`NOTICE.md` first, and any future import from TruffleHog must be an
independently written implementation of a described technique — never a
translation of their source.
