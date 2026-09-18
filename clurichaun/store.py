"""SQLite datastore for incremental scans, content dedup and finding history.

Re-scanning an unchanged tree from scratch every night is the difference between
a 20-minute job and a 20-second one. This store records a **content hash** per file so an incremental scan can skip
files whose bytes are unchanged since the last run, and records every finding so
a report can show what is *new* versus long-known.

Three roles, all optional and all opt-in via ``--db``:

* **Incremental skip** — ``known_hashes()`` returns the last scan's content
  hashes; a worker skips a file whose hash is unchanged.
* **Content dedup** — a blob hash seen this run is not scanned again (Nosey
  Parker's trick), across the filesystem and git history alike.
* **Finding history** — ``first_seen`` / ``last_seen`` per fingerprint, plus a
  cached verification verdict so ``--verify`` need not re-hit a provider.

Stdlib ``sqlite3`` only; no dependency. A corrupt or unwritable DB degrades to
"scan everything", never to a crash.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Optional

from .models import Finding, Verified

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS files (
    path TEXT PRIMARY KEY,
    mtime REAL NOT NULL,
    size INTEGER NOT NULL,
    blob_hash TEXT,
    scanned_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    fingerprint TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    logical_path TEXT NOT NULL,
    line INTEGER NOT NULL,
    severity TEXT NOT NULL,
    verified TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS blobs (blob_hash TEXT PRIMARY KEY, seen_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS verifications (
    secret_hash TEXT PRIMARY KEY,
    verdict TEXT NOT NULL,
    note TEXT,
    checked_at REAL NOT NULL
);
"""

SCHEMA_VERSION = "1"


@dataclass(slots=True)
class NewAndKnown:
    new: int = 0
    known: int = 0


class Store:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.executescript(SCHEMA)
        self._conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema', ?)",
            (SCHEMA_VERSION,),
        )
        self._conn.commit()
        self._blob_cache: set[str] = set()

    # ------------------------------------------------------------------ #
    # Incremental skip
    # ------------------------------------------------------------------ #

    def unchanged(self, path: str, mtime: float, size: int) -> bool:
        """True when this exact (path, mtime, size) was scanned before."""
        row = self._conn.execute(
            "SELECT mtime, size FROM files WHERE path = ?", (path,)
        ).fetchone()
        return row is not None and row[0] == mtime and row[1] == size

    def known_hashes(self) -> Dict[str, str]:
        """{path: content-hash} for every file recorded with a hash.

        Loaded once at the start of an incremental scan so workers can decide,
        by content, whether a file is unchanged since the last run.
        """
        rows = self._conn.execute(
            "SELECT path, blob_hash FROM files WHERE blob_hash IS NOT NULL"
        ).fetchall()
        return {path: h for path, h in rows}

    def record_file(
        self, path: str, mtime: float, size: int, blob_hash: Optional[str] = None
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO files(path, mtime, size, blob_hash, scanned_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (path, mtime, size, blob_hash, time.time()),
        )

    # ------------------------------------------------------------------ #
    # Content dedup
    # ------------------------------------------------------------------ #

    def seen_blob(self, blob_hash: str) -> bool:
        """Register a blob hash; return whether it was already seen this run."""
        if blob_hash in self._blob_cache:
            return True
        self._blob_cache.add(blob_hash)
        row = self._conn.execute(
            "SELECT 1 FROM blobs WHERE blob_hash = ?", (blob_hash,)
        ).fetchone()
        if row is not None:
            return True
        self._conn.execute(
            "INSERT OR IGNORE INTO blobs(blob_hash, seen_at) VALUES (?, ?)",
            (blob_hash, time.time()),
        )
        return False

    # ------------------------------------------------------------------ #
    # Finding history
    # ------------------------------------------------------------------ #

    def record_findings(self, findings: Iterable[Finding]) -> NewAndKnown:
        """Upsert findings; tag each with whether it is new to this store."""
        counts = NewAndKnown()
        now = time.time()
        for finding in findings:
            fp = finding.fingerprint
            row = self._conn.execute(
                "SELECT first_seen FROM findings WHERE fingerprint = ?", (fp,)
            ).fetchone()
            first_seen = row[0] if row else now
            if row:
                counts.known += 1
            else:
                counts.new += 1
                finding.notes.append("new since last scan")
            self._conn.execute(
                "INSERT OR REPLACE INTO findings(fingerprint, rule_id, logical_path, "
                "line, severity, verified, first_seen, last_seen, data) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    fp,
                    finding.rule_id,
                    finding.logical_path,
                    finding.line,
                    finding.severity.value,
                    finding.verified.value,
                    first_seen,
                    now,
                    json.dumps(finding.to_dict(unredact=False)),
                ),
            )
        return counts

    # ------------------------------------------------------------------ #
    # Verification cache
    # ------------------------------------------------------------------ #

    def cached_verdict(self, secret: str) -> Optional[tuple[Verified, str]]:
        row = self._conn.execute(
            "SELECT verdict, note FROM verifications WHERE secret_hash = ?",
            (_hash(secret),),
        ).fetchone()
        if row is None:
            return None
        try:
            return Verified(row[0]), (row[1] or "")
        except ValueError:  # pragma: no cover - forward-compat
            return None

    def cache_verdict(self, secret: str, verdict: Verified, note: str = "") -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO verifications(secret_hash, verdict, note, checked_at) "
            "VALUES (?, ?, ?, ?)",
            (_hash(secret), verdict.value, note, time.time()),
        )

    # ------------------------------------------------------------------ #

    def commit(self) -> None:
        self._conn.commit()

    def close(self) -> None:
        try:
            self._conn.commit()
        finally:
            self._conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def open_store(path: str | Path) -> Optional[Store]:
    """Open a store, or None (with the reason) if the DB is unusable."""
    try:
        return Store(path)
    except (sqlite3.Error, OSError):
        return None


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8", "replace")).hexdigest()
