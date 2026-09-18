# Clurichaun: red-team analysis and 10 improvements

A deep look at where Clurichaun stands against the field — TruffleHog, gitleaks,
Nosey Parker, and MongoDB's Kingfisher — from the point of view of an attacker
who wants the scanner to *miss* their planted credential, and a defender who
wants triage to be fast and trustworthy. Every claim below was checked against
the actual code, not assumed; the probes are noted so they can be re-run.

## Where the field has moved

The mature tools converge on one idea: **the hard question is not "does this
look like a secret" but "is it real, whose is it, and what does it unlock."**

* **Kingfisher** (MongoDB, 2025, Rust) chains regex → Tree-sitter parser context
  → entropy → **checksum verification** → **live API validation**, on Intel
  Hyperscan/Vectorscan with a compiled, cacheable rule database.
* **Nosey Parker** (Praetorian) pioneered content-addressed **blob dedup** — the
  same file reached three ways is scanned once — and a SQLite datastore for
  results, dedup and metadata.
* **TruffleHog** built its reputation on **live verification** (700+ detectors
  that call the provider) plus a verification cache.
* **gitleaks** owns **git-history** scanning and a battle-tested rule corpus with
  per-rule allowlists — both of which we have already assimilated the rule half
  of.

Clurichaun is genuinely ahead on **ingestion breadth** (archives, binaries,
source maps, decoders, structured parsers, remote crawling with `ai.txt`/
`llms.txt`) and on **structured key-name detection**, which none of the four do.
It is behind on exactly the axis the field has moved to: **proving a finding is
real**, and the plumbing that makes proof cheap (git history, dedup, a datastore).

The ten improvements are ranked by attacker/defender impact.

---

## 1. Live credential verification (`--verify`)

**The single biggest gap.** A finding today is "this matches a pattern." Every
serious competitor answers "and the key still works." Verification collapses a
1,500-finding report into the handful that are live, and it is the only thing
that reliably separates a real leak from a rotated or fake one.

* Build a `verify.py` with a per-provider, read-only, rate-limited probe:
  GitHub `GET /user`, Slack `auth.test`, Stripe `GET /v1/account`, OpenAI
  `GET /v1/models`, GCP token-info, AWS `sts:GetCallerIdentity` (SigV4).
* Add `Finding.verified: Optional[bool]` and a verdict cache keyed by secret
  hash so re-scans and CI hooks never re-hit the API.
* **Off by default and loudly gated** — this is the one feature that puts
  credentials on the wire. Local-first is on-brand for this project: a
  `--verify` that refuses unless `--verify-i-understand` or an allowlist of
  providers is set.

Impact: turns the tool from a linter into a breach-triage instrument. This is
what `ASSIMILATION.md` already flags as item 1; it is
listed here for completeness because no analysis of this tool is honest without
it at the top.

## 2. Offline checksum validation for token formats that carry one

A cheaper, zero-network cousin of #1 that eliminates false positives outright.
GitHub's `gh[pousr]_`/`github_pat_` tokens embed a **CRC32 checksum, base62-
encoded, in the last 6 characters** (verified against GitHub's engineering blog).
npm, Stripe (Luhn-like), and several others do the same.

* Add an optional `checksum: Callable[[str], bool]` to `Rule`. When present, a
  match whose checksum fails is dropped with certainty — not down-weighted.
* This makes `github.token` and friends essentially false-positive-free with no
  API call, and it is the exact mechanism GitHub built secret-scanning partners
  around ("check the token input matches the checksum … without hitting our
  database").

Impact: removes a whole class of fake-token noise for free, and lays the
`Rule`-level groundwork #1 reuses.

## 3. Git-history scanning

**Probed and confirmed: we are blind here.** I committed a secret, `git rm`'d it,
committed again, and scanned the tree — Clurichaun reported it *0 times*, because
the secret now lives only in a zlib-compressed loose object whose bytes are not
printable, so even the binary-strings carver cannot see it (probe:
`scratchpad/gitprobe`). This is the most common real-world leak — a key committed
and later "removed" — and it is exactly gitleaks' and TruffleHog's home turf.

* Add a `git` source: shell `git rev-list --all` + `git cat-file --batch`, or
  parse packfiles, and feed each blob through the existing `blobs_from_bytes`
  pipeline. The ingestion layer already accepts arbitrary bytes with a logical
  path, so this is a source adapter, not an engine change.
* Report `commit`, `author`, `date` on the finding (SARIF has slots for it).
* `--since <rev>` and a `--staged` pre-commit mode fall out naturally.

Impact: closes the highest-value blind spot in the whole tool. Ranked below #1/#2
only because those are smaller and reusable.

## 4. Multi-part credential fingerprints (RawV2)

**Probed and confirmed a real correctness bug.** The fingerprint is
`sha256(rule, path, secret)`. An AWS access-key id paired with two *different*
secret keys (a rotation, or a stolen pair) produces two findings with the same
key id but is never linked, and — worse — the reverse: the `aws.access-key-id`
rule fingerprints on the id alone, so the id sitting next to a rotated secret is
*indistinguishable* from the old one for baseline/dedup purposes (probe printed
`the rotated secret under the same id is invisible to triage`).

* Adopt TruffleHog's `Raw`/`RawV2` split: fingerprint multi-part credentials on
  **id + secret**, and carry a `related` link so the id and its secret surface
  as one finding.
* AWS, GCP service accounts, Azure connection strings, and basic-auth URIs are
  all multi-part and all currently mis-keyed.

Impact: correct dedup and baselines for exactly the credentials that matter most.

## 5. Deterministic parallelism — fix the stalled-worker bug and dedup blobs

A known parallel-scan stall (since fixed) had a 26k-file scan hang at 686 s with one live
worker. `--file-timeout` (which I added) bounds the *symptom* but the root cause
is unproven, and submitting 26k individual futures is heavy IPC either way.

* **Batch the work unit**: submit N paths per task (32–64), returning a list of
  `FileResult`. This is the standard fix and cuts scheduling overhead ~30×.
* **Content-addressed blob dedup** (Nosey Parker's core trick): hash each blob's
  bytes; scan a given content once even if it appears in ten archives or three
  branches. On a monorepo with vendored copies this is a large win and it makes
  git-history scanning (#3) tractable.
* Add explicit `BrokenProcessPool` handling so a crashed worker is reported, not
  silently absorbed.

Impact: makes large and historical scans finish predictably; unblocks #3.

## 6. A results datastore and true incremental scanning

Every mature tool has a datastore (Nosey Parker/Kingfisher: SQLite). We
re-scan everything every time and emit a flat JSON report.

* A SQLite store keyed by `(path, mtime, size, blob-hash)` lets a scan skip
  unchanged files entirely and only re-examine what moved — the difference
  between a 20-minute nightly `$HOME` scan and a 20-second one.
* It also gives verification caching (#1), historical finding tracking, and a
  proper baseline mechanism that survives line-number churn (our fingerprint
  already ignores line numbers — verified — so this composes cleanly).

Impact: turns Clurichaun into something you can run on a cron or a pre-commit
hook without dread.

## 7. Cross-chunk duplicate findings on large files

**Probed and confirmed a bug.** For files over `stream_threshold`, chunks carry
an 8 KB overlap so a secret split across a boundary still matches. But a secret
that lands *inside* the overlap window is scanned twice and reported twice, with
two different (wrong) line numbers — I planted one in the overlap and got hits at
lines 627 and 709 for a secret truly on line 634 (probe: `scratchpad/big3.log`).
A single-chunk file is fine; large streamed files are not.

* Track a "committed offset" and only emit findings whose start is past the
  previous chunk's non-overlap boundary, or dedup post-hoc by
  `(rule, byte-offset)` before line numbers are computed.
* While here, fix streamed-chunk line numbers: they are currently approximate
  because `line_offset` accumulates per chunk but the overlap re-counts lines.

Impact: correctness on exactly the big log/dump files where a leak is most likely
to hide, and where a doubled finding erodes trust in the whole report.

## 8. Rule-database scaling before the corpus grows

**Probed the cost.** With the gitleaks pack loaded (254 rules) on a 69 KB HTML
file, the prefilter loop itself costs ~10 ms/scan and only 18 rules survive it —
but that is a linear `any(substr in text)` over 254 rules × their keywords, run
on every blob. At 500+ rules (the field norm) this dominates. gitleaks uses a
per-file keyword set; Kingfisher compiles to Hyperscan/Vectorscan.

* Replace the per-rule prefilter loop with a **single Aho-Corasick pass** over
  all rule keywords (`pyahocorasick`), yielding the set of candidate rules in one
  traversal. I explicitly *deferred* this in `ASSIMILATION.md` at 40 rules, and
  said to revisit past ~200 — we are now at 254 with `--rule-pack gitleaks`, so
  the condition I set has been met.
* Optionally gate it behind rule count so small runs keep the zero-dependency
  path.

Impact: keeps scan time flat as the ruleset grows toward parity with the field.

## 9. Parser-context verification (the Tree-sitter idea, applied cheaply)

Kingfisher's precision edge is asking the parser "is this string a *value*, or a
variable name / a comment / a test fixture?" We have half of this already — the
structured `keyname` pass — but the regex and entropy passes are context-blind.

* Reuse the ingestion signal we already compute: a candidate inside a
  `test/`, `spec/`, `fixture/`, `example/`, or `*_test.*` path, or on a comment
  line, is far more likely benign. Fold path/line context into confidence
  scoring (we already have `scope.interest_boost`; add the inverse — a
  *test-context penalty*).
* For the languages worth it, an optional `tree-sitter` pass distinguishing a
  string literal from an identifier would raise precision on minified/obfuscated
  JS, where entropy alone is noisy (verified: our own entropy pass down-weights
  but still fires inside `.min.js`).

Impact: fewer false positives in the two noisiest surfaces — test trees and
bundles — without a new detection pass.

## 10. Assimilate the Nosey Parker / Kingfisher rule corpora (licence-clean)

Nosey Parker (Apache-2.0) and Kingfisher (Apache-2.0) publish large,
well-curated rule sets in a YAML/TOML shape close to what `rules_toml.py`
already parses. Both licences are permissive and compatible with our MIT.

* Write thin adapters (Nosey Parker's `rules/*.yml`, Kingfisher's rule format)
  onto the `Rule` model, exactly as we did for gitleaks. The `compile_re2`
  translation layer already handles the Go-regex quirks; Nosey Parker uses Rust
  `regex` (also RE2-family), so the same translation largely applies.
* This is the fastest path to detector *breadth* parity (Titus ships 487 rules
  drawn from these two) without hand-writing patterns — and every one arrives
  with attribution in `NOTICE.md`, the discipline already established.

Impact: closes the coverage gap against the 400–900-rule tools with mechanical,
licence-clean work rather than months of pattern authoring.

---

## Summary table

| # | Improvement | Kind | Effort | Evidence |
|---|---|---|---|---|
| 1 | Live verification `--verify` | capability | L | field consensus; already flagged |
| 2 | Offline checksum validation | precision | S | GitHub CRC32/base62 confirmed |
| 3 | Git-history scanning | **coverage bug** | M | probe: deleted secret found 0× |
| 4 | Multi-part fingerprints | **correctness bug** | S | probe: rotated secret mis-keyed |
| 5 | Batched pool + blob dedup | perf/correctness | M | parallel-scan stall |
| 6 | SQLite datastore + incremental | capability | M | field consensus |
| 7 | Cross-chunk duplicate fix | **correctness bug** | S | probe: dup hits, wrong lines |
| 8 | Aho-Corasick keyword core | perf | S | probe: 10 ms prefilter @254 rules |
| 9 | Parser/test-context scoring | precision | M | entropy fires in `.min.js` |
| 10 | NoseyParker/Kingfisher corpora | coverage | S | Apache-2.0, adapter-ready |

Three of these (3, 4, 7) are outright **bugs** confirmed by probe, not
enhancements — they should jump the queue regardless of the roadmap. The probes
live under the session scratchpad and are cheap to turn into regression tests.

## Sources

* [Kingfisher (MongoDB)](https://github.com/mongodb/kingfisher) — Rust,
  Hyperscan/Vectorscan, checksum + live validation, multi-stage pipeline.
* [Kingfisher 2026 writeup](https://appsecsanta.com/kingfisher)
* [Nosey Parker (Praetorian)](https://github.com/praetorian-inc/noseyparker) —
  content-addressed blob dedup, SQLite datastore.
* [Titus](https://github.com/praetorian-inc/titus) — 487 rules drawn from
  NoseyParker and Kingfisher.
* [Behind GitHub's new token formats](https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/)
  — CRC32 + base62 checksum in the last 6 chars, offline-verifiable.
* TruffleHog `pkg/verificationcache`, gitleaks `config/gitleaks.toml` — examined
  directly in this project's assimilation work (`ASSIMILATION.md`).
