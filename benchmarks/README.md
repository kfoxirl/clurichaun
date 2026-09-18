# Benchmarks

## CredData (Samsung)

`creddata.py` scores Clurichaun against [Samsung/CredData](https://github.com/Samsung/CredData),
the standard public hard-coded-credential benchmark (~11k files, ~15.7k labelled
true credentials). Scoring is line-level: a finding on a `T` line is a true
positive, on an `F`/`X` line a false positive, a `T` line with no finding a false
negative (±1 line tolerance for multi-line value drift).

### Running it

```bash
# 1. get the data (clones the source repos; Linux, Python 3.10 per CredData)
git clone https://github.com/Samsung/CredData && cd CredData
python download_data.py            # full set is ~337 repos

# 2. score
cd /path/to/clurichaun
python -m benchmarks.creddata /path/to/CredData
python -m benchmarks.creddata /path/to/CredData --rule-pack gitleaks --rule-pack noseyparker
```

A partial download scores honestly over exactly the files present on disk, so a
14-repo slice gives a real (if not representative) number.

### Results (2026-09-18, 70-repo / 2,441-file sample)

Measured on a 70-of-337-repo sample (2,441 files) — representative, not a slice.

| Configuration | Precision | Recall | F1 |
|---|---|---|---|
| **shipping defaults** (min-sev low, min-conf 0.4) | **0.80** | 0.57 | **0.67** |
| raw detection (min-sev info, min-conf 0.0) | 0.74 | 0.60 | 0.66 |
| pre-precision-pass baseline (2026-09-17) | 0.68 | 0.64 | 0.66 |

For reference, published full-corpus numbers: CredSweeper R 0.81 / P 0.92,
Betterleaks R 0.99.

**The precision pass (2026-09-18)** took precision 0.68 → **0.80** (+12 pts) for
F1 0.66 → 0.67, by attacking the measured false-positive sources:

- **Endpoint/IP rules are informational, not secrets.** `generic.external-url`
  alone was ~85% of all false positives (precision 0.29). These are INFO
  severity, and the default `--min-severity` is now **low**, so bare URLs and IP
  addresses no longer clutter a secret scan (`--min-severity info` brings them
  back for recon). Practical effect: a real ~11k-file project tree dropped from 1,568
  to 454 findings — 71% less noise — with every credential finding preserved.
- **`keyname.sensitive-assignment`** (was precision 0.44) no longer fires when the
  value is prose (`"the SASL password"`) or a bare identifier (`stong_password`).
- **Entropy** candidates containing a dictionary word are penalised, not skipped,
  so a real secret with a common substring still surfaces (lower ranked).
- **`generic.ipv6`** no longer matches timestamps like `19:53:57` (a real regex
  bug — it required only two colons).

**Remaining lever is recall** (0.57): the 1,466 misses are CredData's generic
`Password` / `Key` / `UUID` / `Secret` values — context-dependent, and the ML /
context frontier (deferred past v1). Any recall work must hold precision ≥ 0.80
here.

Wire `python -m benchmarks.creddata` into CI once the dataset is cached, and fail
a PR that regresses either axis.
