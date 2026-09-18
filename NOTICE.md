# Third-party notices

Clurichaun is MIT-licensed. This file records third-party material incorporated
into it, and the boundaries observed while doing so.

## gitleaks — MIT

    MIT License
    Copyright (c) 2019 Zachary Rice
    https://github.com/gitleaks/gitleaks

gitleaks is MIT-licensed, so material can be incorporated here with attribution.
The following is derived from gitleaks' default configuration
(`config/gitleaks.toml`) and allowlist semantics (`config/allowlist.go`):

* `clurichaun/rules/gitleaks.toml` — gitleaks' default rule configuration,
  bundled **verbatim** and loaded by `clurichaun/rules_toml.py` as the
  `gitleaks` rule pack (219 of its 222 rules load; the rest are reported by
  `clurichaun packs gitleaks`). The MIT licence as published with gitleaks is
  included alongside it as `clurichaun/rules/gitleaks-LICENSE.txt`.
* `clurichaun/stopwords.py` — the 1,446-entry stopword list from the
  `generic-api-key` rule, used as a substring filter on candidate values.
* `clurichaun/patterns.py`
  * `GENERIC_KEY_ALLOWLIST` — the `generic-api-key` rule's match allowlist
    (`api_version`, `primary_key`, `csrf_token`, `monkey`, `turkey`, …).
  * `assignment()` — the keyword-proximity assignment pattern shape used by
    gitleaks' keyword-anchored rules.
  * The per-rule `min_entropy`, `allow_regexes` and `use_stopwords` fields
    reimplement gitleaks' `entropy`, `allowlists.regexes` (with
    `regexTarget = "match"`) and `allowlists.stopwords`.
  * `Rule.pick()` follows gitleaks' `secretGroup` semantics: the named group,
    else the first non-empty capture group, else the whole match.

A copy of the MIT licence text as published with gitleaks is reproduced in full
in that project's `LICENSE`; the notice above satisfies its attribution
requirement.

## Nosey Parker — Apache-2.0

    Apache License 2.0
    Copyright Praetorian Security, Inc.
    https://github.com/praetorian-inc/noseyparker

Nosey Parker is Apache-2.0, compatible with this project's MIT licence. Its
default rule corpus is vendored as `clurichaun/rules/noseyparker.yml` (the
concatenation of its `data/default/builtin/rules/*.yml`) and loaded by
`clurichaun/rules_np.py` as the `noseyparker` rule pack (187 of 189 rules load;
`clurichaun packs noseyparker` reports the two that use RE2 constructs Python's
`re` cannot express). The Apache-2.0 licence text as published with Nosey Parker
is included as `clurichaun/rules/noseyparker-LICENSE.txt`.

## TruffleHog — AGPL-3.0: techniques only, no code

    https://github.com/trufflesecurity/trufflehog

TruffleHog is AGPL-3.0. **No TruffleHog code, regex corpus or wordlist is
present in Clurichaun**, because incorporating any of it would require
relicensing this project under the AGPL. What was taken is architectural: the
idea of re-running detection over decoded views of content
(`clurichaun/decode.py`), and the idea of bounding per-item processing with a
wall-clock timeout (`--file-timeout`). Both were implemented from scratch here.
See `docs/dev/ASSIMILATION.md` for the full assessment and the reasoning behind each
adopt/reject decision.

## Site-declared agent policy

`clurichaun/web/policy.py` implements three public conventions from their
specifications, not from anyone's source:

* `robots.txt` — parsed with the standard library's `urllib.robotparser`.
* `ai.txt` — both dialects: the IETF draft
  `draft-car-ai-txt-wellknown-00` at `/.well-known/ai.txt`, and Spawning's
  earlier robots-shaped file at `/ai.txt`.
* `llms.txt` — the format described at <https://llmstxt.org/>, read as a seed
  index rather than a permission file.

## Runtime dependencies

`click`, `PyYAML`, `rich`, `requests`, `beautifulsoup4`, and the optional
`python-magic`, `py7zr`, `rarfile` are used as published libraries under their
own licences and are not vendored here.
