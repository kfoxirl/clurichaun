"""Post-detection rescoring: adjust confidence with signals a regex cannot see.

Advisory only — a rescorer may lower or modestly raise a finding's confidence
and attach a rationale, but never suppresses a finding outright and never gates
the exit code.

v1 ships one rescorer, and it is deterministic — no model is in the decision
loop:

* :class:`TokenEfficiency` — the BPE insight (Betterleaks): a real secret
  fragments into many subword tokens, while natural language and identifiers
  tokenize efficiently. Needs a tokenizer (``tiktoken``, the ``[ml]`` extra) and
  is a no-op without one, so it is never a hard dependency. Off by default.

(LLM-in-the-loop triage was deliberately left out of v1: findings must not be
decided by a sampled model.)

The scorer is gated on the CredData benchmark (`benchmarks/`): any recall claim
must move that number without dropping precision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Protocol

from .models import Finding


class Rescorer(Protocol):
    def rescore(self, findings: List[Finding]) -> None: ...


# --------------------------------------------------------------------------- #
# Token-efficiency (BPE) scorer — optional, deterministic
# --------------------------------------------------------------------------- #


@dataclass
class TokenEfficiency:
    """Boost low-token-efficiency values (many tokens/char ⇒ likely random secret).

    Needs a BPE tokenizer; a no-op without one, so callers can always construct it.
    """

    encoding_name: str = "cl100k_base"
    threshold: float = 0.35  # tokens-per-char above this looks secret-like
    delta: float = 0.1
    _encoder: object = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        try:  # optional dependency
            import tiktoken

            self._encoder = tiktoken.get_encoding(self.encoding_name)
        except Exception:  # noqa: BLE001
            self._encoder = None

    @property
    def available(self) -> bool:
        return self._encoder is not None

    def efficiency(self, value: str) -> Optional[float]:
        """Tokens per character. Higher ⇒ fragments more ⇒ more secret-like."""
        if self._encoder is None or not value:
            return None
        return len(self._encoder.encode(value)) / len(value)

    def rescore(self, findings: List[Finding]) -> None:
        if self._encoder is None:
            return
        for finding in findings:
            # Only the fuzzy rules benefit; a checksummed/high-confidence hit
            # is already decided.
            if finding.confidence >= 0.85 or finding.detector.value == "keyname":
                continue
            score = self.efficiency(finding.secret)
            if score is None:
                continue
            if score >= self.threshold:
                finding.confidence = round(min(0.9, finding.confidence + self.delta), 3)
                finding.notes.append(f"token-efficiency {score:.2f}")
            elif score < self.threshold / 2:
                finding.confidence = round(max(0.05, finding.confidence - self.delta), 3)
