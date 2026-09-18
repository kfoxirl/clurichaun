# Clurichaun vs. the field — gap analysis

A survey of the 2026 secret-scanning landscape and an honest accounting of where
Clurichaun is ahead, at parity, and behind. Grounded in the actual capabilities
of eleven tools (sources at the end), and in what Clurichaun's code actually does
today — not what a README claims.

This is a companion to `IMPROVEMENTS.md` (which is now 10/10 done). Those closed
the gaps against TruffleHog and gitleaks specifically. This document looks wider —
Kingfisher, Nosey Parker, CredSweeper/CredData, GitGuardian, detect-secrets,
Betterleaks — and finds the gaps that remain.

## The field, one line each

| Tool | Licence | The thing it is known for |
|---|---|---|
| **gitleaks** | MIT | Ubiquity; pre-commit; 150+ regex rules; composite rules (v8.28) |
| **TruffleHog** | AGPL-3.0 | Live verification (800+ detectors); many sources; identity mapping |
| **Kingfisher** | Apache-2.0 | Validate → **map blast radius** → **revoke**; Vectorscan; 942 rules |
| **Nosey Parker** | Apache-2.0 | Curated rules; content-addressed blob dedup; SQLite store |
| **CredSweeper** | MIT | **ML model** + rules; benchmarked on **CredData** (R 80.7 / P 91.6) |
| **Betterleaks** | MIT | **BPE-tokenization** recall (98.6% on CredData); gitleaks drop-in |
| **detect-secrets** | Apache-2.0 | Baseline + **audit/label** workflow for legacy repos |
| **GitGuardian** | Commercial | Real-time SCM + Slack/Jira/Confluence; NHI governance; honeytokens |
| **GitHub Secret Scanning** | GHAS | **Push protection**; partner **auto-revocation** |
| **Cycode / Spectral** | Commercial | ASPM: IaC + secrets, impact scoring, IDE/PR placement |
| **AWS git-secrets / Talisman** | Apache/MIT | Tiny targeted pre-commit hooks |

## Where Clurichaun already leads (keep these)

These are genuine differentiators — several tools on the list do **none** of them:

1. **Universal file ingestion.** Archives (zip/tar/gz/7z/rar, jar/apk/whl/…),
   binary string-carving, source-map `sourcesContent` explosion, and a decoder
   layer that re-scans base64 / `\uXXXX` / percent / HTML-entity views. Only
   TruffleHog has comparable decoders; nobody else combines all of this.
2. **Structured key-name detection.** Parsing JSON/YAML/TOML/XML/plist/INI/HCL/
   `.tfstate`/`.reg`/systemd/Dockerfile and flagging by *key semantics*
   (`{"db":{"password":"…"}}`). This is a class of finding pure regex misses,
   and it is rare in the field.
3. **Web crawling that honours `ai.txt` / `llms.txt` / `robots.txt`.** Unique —
   no other scanner treats a crawl as an outward-facing act with a policy layer.
4. **Two vendored corpora on one engine** (gitleaks TOML + Nosey Parker YAML),
   with a licence-clean RE2→`re` translation layer.
5. **Redaction by default**, cross-finding context scrubbing, SARIF 2.1.0.

Nothing below should come at the cost of these.

---

## Gaps that remain, ranked by impact

### G1 — No benchmark. We have never been measured. *(highest priority)*

Every credible tool reports precision/recall on **CredData** (Samsung's public,
obfuscated 19M-line, 11k-file benchmark): CredSweeper 80.7% recall / 91.6%
precision, Betterleaks 98.6% recall. **Clurichaun has no number at all.** Without
one, every claim in the README is unfalsifiable, and we cannot tell whether a
change helped or hurt.

- Build `benchmarks/creddata.py`: clone `Samsung/CredData`, run `clurichaun
  scan --format json`, and score findings against its labelled `(file, line,
  value)` truth set — precision, recall, F1, MCC, at the *secret* level.
- Wire it into CI as a regression gate: a PR that drops recall or precision fails.
- This retroactively validates #2/#4/#9 (which claimed FP reductions) with an
  actual figure, and it is the prerequisite for tuning anything else honestly.

**Effort: M. Impact: foundational — do this first.**

### G2 — Blast-radius / access mapping after verification.

Kingfisher's headline feature and TruffleHog's "identity mapping" (20+ types):
once a credential verifies, enumerate *what it can reach* — IAM permissions, role
assumption (AWS), service-account impersonation (GCP), token scopes (GitHub).
"This AWS key is live" is useful; "this AWS key is live and can read every S3
bucket and assume the admin role" is a page-someone-at-2am finding.

- Extend `verify.py`: on an ACTIVE verdict, a second read-only call for scope —
  GitHub token scopes from the `X-OAuth-Scopes` response header (free, already
  in the verification response), Slack `auth.test` team/scopes, AWS
  `iam:GetUser` + `iam:ListAttachedUserPolicies`, GCP token-info scopes.
- Attach `Finding.access = {identity, scopes, reachable}` and surface it in the
  report and SARIF. GitHub scopes alone are a cheap, high-value first step —
  the header comes back on the `/user` call we already make.

**Effort: M (GitHub/Slack scopes: S). Impact: high — the current frontier.**

### G3 — Pre-commit / CI-native surface.

gitleaks, detect-secrets, Talisman and git-secrets all *live* in the pre-commit
hook and the CI step — that is 80% of real-world usage. Clurichaun is a scan CLI
with SARIF (CI-consumable) and `--git-history`, but has **no staged-diff mode and
no packaged hook**.

- Add `clurichaun scan --staged` (scan `git diff --cached` only) — fast enough
  for a commit hook. The git plumbing from `gitsource.py` already exists.
- Ship a `.pre-commit-hooks.yaml` so `pre-commit` can consume it directly, and a
  ready GitHub Action / GitLab CI snippet in the README.
- `--fail-on` / `--fail-on-verified` already give the CI gate; this is packaging,
  not new detection.

**Effort: S. Impact: high — it is how the tool gets adopted.**

### G4 — Defender-led revocation.

Kingfisher's `kingfisher revoke` and GitHub's partner auto-revocation let a
responder *contain* a leak from the CLI, not just report it. Clurichaun stops at
detection + verification.

- `clurichaun revoke` for providers whose API supports it (GitHub token deletion,
  Slack `auth.revoke`, AWS `iam:UpdateAccessKey --status Inactive`). Strictly
  opt-in, confirmation-gated, and only for a verified-ACTIVE finding.
- Higher-risk than anything else here (it mutates), so it needs a dry-run default
  and an explicit `--yes-revoke <fingerprint>`.

**Effort: M. Impact: high, but sequenced after G2 (need identity to revoke safely).**

### G5 — ML / high-recall detection.

The recall frontier has moved to learned models: CredSweeper ships an optional ML
classifier, Betterleaks reports **98.6% recall via BPE tokenization** vs ~70% for
entropy filtering, and there is active LLM-based research (arXiv 2506.13090).
Clurichaun is regex + Shannon entropy + key-name — the ~70% tier.

- Two tiers, both optional:
  - **Cheap:** a BPE/token-efficiency scorer as an entropy *replacement* for the
    generic/high-entropy path — Betterleaks shows this alone is a large recall
    jump, and it needs no model weights, just a tokenizer.
  - **Rich:** the LLM-triage layer already sketched in `ASSIMILATION.md` §8 —
    run a local model (a local model) over the 0.4–0.75 confidence
    band to adjudicate, never to gate. Local-only keeps secrets off remote APIs.
- **G1 is a hard prerequisite** — you cannot claim a recall gain without the
  benchmark to prove it, and ML changes are exactly where unmeasured "improvements"
  regress precision.

**Effort: L. Impact: high recall ceiling, but gated on G1.**

### G6 — More sources: cloud storage, container images, org-wide SCM.

TruffleHog and Kingfisher scan S3/GCS buckets, Docker images, and whole
GitHub/GitLab orgs including **PR comments and issues** (a very common leak
surface). Clurichaun does filesystem + git history + a single-host web crawl.

- Each is a `blobs_from_bytes`-shaped adapter — the ingestion model already fits,
  which is why this is breadth, not architecture:
  - **Docker image**: pull, walk layer tarballs (we already unpack tar/gz).
  - **S3/GCS**: list + get objects (optional `boto3`/`google-cloud-storage`).
  - **GitHub/GitLab org**: enumerate repos + issue/PR comment bodies via API.
- Prioritise **Docker images** (self-contained, no cloud creds needed to demo)
  and **SCM issue/PR comments** (high real-world hit rate) first.

**Effort: M per source. Impact: medium-high, breadth-driven.**

### G7 — Audit / triage workflow.

detect-secrets' baseline + **audit mode** (interactively label each finding
real/false in the baseline) is why it wins in legacy repos with hundreds of
existing hits. Clurichaun has `--baseline` (suppress known fingerprints) and now a
SQLite store, but no *labelling* — no way to mark a finding "reviewed, accepted"
and have it stay quiet with a reason.

- Extend `store.py`: a `triage(fingerprint, verdict, reason, who)` and a
  `clurichaun audit` TUI/prompt that walks new findings. The datastore schema is
  already most of the way there (`findings` table, `first_seen`).
- `--new-only` (report only findings not in the store) is a one-liner on top of
  the datastore and covers the most common ask.

**Effort: S–M. Impact: medium — the difference between "usable in a legacy repo"
and not.**

### G8 — Actionability tiers in output.

Kingfisher's `--validation-filter actionable` / `--only-valid` lets a user ask
for "only things I must act on now." Clurichaun has `--min-severity` /
`--min-confidence` but no single "actionable" axis that folds in verification.

- A derived `actionability` (verified-active > checksum-valid > high-confidence >
  entropy-only) and `--only-actionable`. Cheap once G1/G2 exist; mostly a
  reporting concern.
- Consider a token-efficient output for LLM/agent consumption (Kingfisher added
  "TOON") — minor, but the direction of travel.

**Effort: S. Impact: medium — triage ergonomics.**

### G9 — Composite / proximity rule authoring.

gitleaks v8.28 added composite rules (pattern + proximity constraints);
TruffleHog custom detectors express multi-part credentials generally. Clurichaun
hard-codes its one multi-part pairing (`_MULTIPART_PAIRS` = AWS id+secret) in
`detect.py`. Every other multi-part credential (GCP client id+secret, Azure
tenant+secret, DB host+user+pass split across keys) needs a code change.

- Generalise `_link_multipart` into a declarative rule field: a rule may name a
  partner rule and a proximity window, so multi-part pairing is authored, not
  coded. Feeds the TOML/YAML pack loaders too.

**Effort: S. Impact: medium — extensibility.**

### G10 — Non-human-identity lifecycle (ownership, rotation age).

The commercial frontier (GitGuardian, Cycode) pairs detection with *ownership*
and *lifecycle*: who owns this credential, how old is it, when was it last
rotated. Most of this needs an org directory Clurichaun does not have, so it is
**largely out of scope for a local CLI** — but two pieces are reachable:

- **Age from git**: `--git-history` already has each secret's introducing commit
  date; report "this key has been in history 400 days."
- **Owner from git**: the introducing commit's author is a first, imperfect owner
  signal — already captured in `GitContext`, just not surfaced as "likely owner."

**Effort: S for the git-derived pieces. Impact: low-medium; full NHI is out of
scope.**

---

## Suggested sequence

1. **G1 (benchmark)** — nothing else can be honestly claimed without it.
2. **G3 (pre-commit/CI)** and **G8 (actionability)** — small, adoption-driving.
3. **G2 (access mapping)** — the current competitive frontier; GitHub scopes are
   a one-call quick win.
4. **G9 (composite rules)**, **G7 (audit)**, **G10 (git-derived age/owner)** —
   small extensibility/ergonomics wins.
5. **G6 (Docker/SCM sources)** and **G5 (ML recall)** — larger, and G5 must wait
   on G1.
6. **G4 (revocation)** — powerful but mutating; last, after G2.

The through-line: Clurichaun's *detection breadth* is already top-tier (arguably
the widest ingestion of any tool here). The gaps are all on the far side of
detection — **measure it (G1), prove exploitability (G2), fit the workflow (G3,
G7, G8), contain it (G4)** — which is precisely where the whole field has moved.

## Sources

- [GitGuardian — Secret Scanning Tools 2026](https://blog.gitguardian.com/secret-scanning-tools/)
- [AppSecSanta — Best Secret Scanning Tools 2026](https://appsecsanta.com/secret-scanning-tools)
- [Kingfisher (MongoDB)](https://github.com/mongodb/kingfisher)
- [Samsung/CredData benchmark](https://github.com/Samsung/CredData) and
  [CredSweeper](https://github.com/Samsung/CredSweeper)
- [Aikido — token efficiency / BPE for secrets scanning](https://www.aikido.dev/blog/token-efficiency-secrets-scan)
- [Detecting Hard-Coded Credentials via LLMs (arXiv 2506.13090)](https://arxiv.org/html/2506.13090v1)
- [Apono — Top Secret Scanning Tools 2026](https://www.apono.io/blog/top-7-secret-scanning-tools-for-2026/)
- TruffleHog, gitleaks, Nosey Parker — examined directly in this repo's
  `ASSIMILATION.md`.

---

## Status (implemented 2026-09-17)

All ten gaps have a landed first implementation. Tests 96 → 109.

| Gap | Landed as |
|---|---|
| G1 benchmark | `benchmarks/creddata.py` + baseline (P0.69/R0.34→R0.40 with packs) |
| G2 access mapping | `verify.py` captures GitHub/Slack scopes; `Finding.access` |
| G3 pre-commit/CI | `scan --staged`, `.pre-commit-hooks.yaml`, `examples/github-action.yml` |
| G4 revocation | `revoke.py` + `clurichaun revoke` (dry-run default, verified-active only, Slack automated) |
| G5 ML recall | `rescore.py`: optional `--token-efficiency` (`[ml]` extra). LLM triage deferred past v1 by choice. |
| G6 sources | `scan-image` (container layers); S3/GCS/SCM remain documented adapters |
| G7 audit | `--new-only` over the datastore |
| G8 actionability | `Finding.actionability` + `--only-actionable` |
| G9 composite rules | declarative `COMPOSITE_RULES` (AWS, GCP) with a proximity window |
| G10 age/owner | git-history findings note introducing author + age in days |

Deliberately still open, and why:
- **G2/G4 depth** — only GitHub/Slack scopes and Slack self-revoke are wired;
  AWS SigV4 (verify + `iam:UpdateAccessKey`) is the biggest remaining piece.
- **G5 scope** — v1 deliberately ships **no LLM-in-the-loop decision making**:
  findings must not be adjudicated by a sampled model. Only the deterministic
  token-efficiency scorer remains (optional, off by default, `[ml]` extra), and
  no recall figure is claimed for it — no tokenizer was available to measure it
  here. Run it against `benchmarks/creddata.py` before claiming a gain. An
  LLM-triage layer can be revisited post-v1 if wanted.
- **G6 breadth** — Docker images work through existing archive ingestion; S3/GCS
  buckets and org-wide SCM (issue/PR comments) are each another
  `blobs_from_bytes` adapter, not yet written.
