"""Score Clurichaun against Samsung's CredData benchmark.

CredData (https://github.com/Samsung/CredData) is the standard public
hard-coded-credential benchmark: ~11k files, ~15.7k labelled true credentials,
each row marking a ``(file, line)`` as a real secret (``T``), a false-positive
candidate (``F``), or a template/placeholder (``X``). Tools are compared by
precision / recall / F1 at the line level.

Usage:

    python download_data.py         # in the CredData checkout (clones repos)
    python -m benchmarks.creddata /path/to/CredData [--rule-pack gitleaks]

The harness reads the ``meta/*.csv`` truth set, runs a scan over ``data/``, and
scores line-level: a finding on a ``T`` line is a true positive, on an ``F``/``X``
line a false positive, and a ``T`` line with no finding a false negative. Only
files actually present on disk are scored, so a partial download yields an
honest partial number over exactly the files it downloaded.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from clurichaun.detect import DetectorConfig  # noqa: E402
from clurichaun.models import Severity  # noqa: E402
from clurichaun.scanner import ScanConfig, ScannerEngine  # noqa: E402
from clurichaun.scope import ScopeFilter  # noqa: E402

# CredData marks placeholders/templates 'X'; count them as negatives (a scanner
# should not fire on them), matching CredSweeper's own scoring convention.
TRUE = "T"


@dataclass
class Score:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def load_truth(root: Path) -> Tuple[Dict[str, Set[int]], Dict[str, Set[int]]]:
    """Return (true_lines, candidate_lines) keyed by on-disk file path.

    ``true_lines`` are lines labelled T; ``candidate_lines`` is every labelled
    line (T/F/X), used to decide which files were reviewed at all.
    """
    true_lines: Dict[str, Set[int]] = defaultdict(set)
    all_lines: Dict[str, Set[int]] = defaultdict(set)
    for csv_path in sorted((root / "meta").glob("*.csv")):
        with open(csv_path, newline="", encoding="utf-8", errors="replace") as handle:
            for row in csv.DictReader(handle):
                rel = row.get("FilePath", "")
                if not rel:
                    continue
                try:
                    start = int(row["LineStart"])
                    end = int(row.get("LineEnd") or start)
                except (ValueError, KeyError):
                    continue
                lines = set(range(start, end + 1))
                all_lines[rel].update(lines)
                if row.get("GroundTruth") == TRUE:
                    true_lines[rel].update(lines)
    return true_lines, all_lines


def scan(root: Path, rule_packs: Tuple[str, ...]) -> Dict[str, Set[int]]:
    """Scan CredData's data/ and return {relative-path: {finding lines}}."""
    data = root / "data"
    config = ScanConfig(
        roots=[str(data)],
        # Benchmark fairly: no scope filtering, scan everything CredData ships.
        scope=ScopeFilter(),
        detector=DetectorConfig(min_confidence=0.0, min_severity=Severity.INFO,
                                rule_packs=rule_packs),
        workers=0,
    )
    engine = ScannerEngine(config)
    hits: Dict[str, Set[int]] = defaultdict(set)
    for finding in engine.run():
        # Logical path back to CredData's "data/<repo>/..." relative form.
        path = finding.source_path
        marker = "/data/"
        idx = path.rfind(marker)
        rel = ("data/" + path[idx + len(marker):]) if idx != -1 else path
        hits[rel].add(finding.line)
    return hits


def score(
    true_lines: Dict[str, Set[int]],
    all_lines: Dict[str, Set[int]],
    hits: Dict[str, Set[int]],
    root: Path,
) -> Score:
    result = Score()
    scored_files = 0
    for rel, labelled in all_lines.items():
        if not (root / rel).is_file():
            continue  # not downloaded; skip honestly
        scored_files += 1
        truths = true_lines.get(rel, set())
        found = hits.get(rel, set())
        # A finding within +/-1 line of a labelled true line counts as a hit
        # (line numbering across tools drifts by a line on multi-line values).
        for line in truths:
            if found & {line - 1, line, line + 1}:
                result.tp += 1
            else:
                result.fn += 1
        for line in found:
            near_true = any(abs(line - t) <= 1 for t in truths)
            if not near_true and line in labelled:
                result.fp += 1
    print(f"scored {scored_files} files present on disk", file=sys.stderr)
    return result


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Score Clurichaun on CredData.")
    parser.add_argument("creddata", help="Path to a CredData checkout")
    parser.add_argument("--rule-pack", action="append", default=[], dest="packs")
    args = parser.parse_args(argv)

    root = Path(args.creddata)
    if not (root / "meta").is_dir():
        parser.error(f"{root} does not look like a CredData checkout (no meta/)")
    if not (root / "data").is_dir():
        parser.error(f"{root}/data missing — run CredData's download_data.py first")

    true_lines, all_lines = load_truth(root)
    total_true = sum(len(v) for v in true_lines.values())
    print(f"truth: {total_true} true-credential lines across {len(all_lines)} files",
          file=sys.stderr)

    hits = scan(root, tuple(args.packs))
    result = score(true_lines, all_lines, hits, root)

    print("\n=== CredData score ===")
    print(f"true positives : {result.tp}")
    print(f"false positives: {result.fp}")
    print(f"false negatives: {result.fn}")
    print(f"precision      : {result.precision:.4f}")
    print(f"recall         : {result.recall:.4f}")
    print(f"F1             : {result.f1:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
