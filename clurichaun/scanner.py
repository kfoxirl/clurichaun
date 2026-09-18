"""Scanner engine: directory walker, worker pool and stream manager."""

from __future__ import annotations

import os
import signal
from concurrent.futures import (
    FIRST_COMPLETED,
    Executor,
    ProcessPoolExecutor,
    ThreadPoolExecutor,
    wait,
)
from itertools import islice
from dataclasses import dataclass, field
from typing import Callable, Iterator, List, Optional, Sequence, Set, Tuple

from . import paths
from .detect import DetectorConfig, SecretDetector
from .ingest import FileIngestor, IngestLimits
from .models import FileResult, Finding, ScanStats
from .scope import ScopeFilter

ProgressHook = Callable[[str, int], None]


@dataclass(slots=True)
class ScanConfig:
    roots: Sequence[str]
    scope: ScopeFilter = field(default_factory=ScopeFilter)
    limits: IngestLimits = field(default_factory=IngestLimits)
    detector: DetectorConfig = field(default_factory=DetectorConfig)
    workers: int = 0  # 0 -> os.cpu_count()
    use_threads: bool = False
    include_hidden: bool = True
    max_files: int = 0  # 0 -> unlimited
    file_timeout: float = 30.0  # 0 -> no budget
    batch_size: int = 48  # paths per worker task, to cut IPC overhead
    git_history: bool = False
    git_since: Optional[str] = None
    staged: bool = False  # scan only git-staged content (pre-commit mode)
    db_path: Optional[str] = None  # SQLite datastore for history/dedup
    incremental: bool = False  # skip files unchanged since the last scan

    @property
    def worker_count(self) -> int:
        if self.workers > 0:
            return self.workers
        return max(1, min(32, (os.cpu_count() or 2)))


# --------------------------------------------------------------------------- #
# Worker-side state (one detector/ingestor per process, built once)
# --------------------------------------------------------------------------- #

_WORKER: dict[str, object] = {}


def _init_worker(config: ScanConfig) -> None:
    _WORKER["detector"] = SecretDetector(config.detector)
    _WORKER["ingestor"] = FileIngestor(config.limits, allow=config.scope.allow)
    _WORKER["root"] = config.roots[0] if len(config.roots) == 1 else ""
    _WORKER["timeout"] = config.file_timeout if _can_alarm() else 0.0


class _Budget(Exception):
    """Raised in-process when one file exceeds its wall-clock budget."""


def _can_alarm() -> bool:
    """SIGALRM is main-thread-only and POSIX-only; threads fall back to no budget."""
    import threading

    return (
        hasattr(signal, "SIGALRM")
        and threading.current_thread() is threading.main_thread()
    )


def _raise_budget(signum: int, frame: object) -> None:  # noqa: ARG001
    raise _Budget()


def _scan_one(path: str) -> FileResult:
    """Runs in a worker. Never raises: failures come back as stats.errors."""
    detector = _WORKER.get("detector")
    ingestor = _WORKER.get("ingestor")
    if detector is None or ingestor is None:  # pragma: no cover - defensive
        result = FileResult(path=path)
        result.stats.errors.append(f"{path}: worker not initialised")
        return result

    assert isinstance(detector, SecretDetector)
    assert isinstance(ingestor, FileIngestor)

    stats = ScanStats(files_seen=1)
    findings: List[Finding] = []
    budget = float(_WORKER.get("timeout") or 0.0)
    armed = _arm(budget)
    try:
        for blob in ingestor.blobs(path, stats):
            try:
                findings.extend(detector.scan(blob))
            except (ValueError, RecursionError, MemoryError) as exc:
                stats.errors.append(f"{blob.logical_path}: detect failed: {exc}")
    except _Budget:
        # Partial findings are kept: whatever was found before the bell still counts.
        stats.errors.append(f"{path}: timed out after {budget:g}s, partially scanned")
    except Exception as exc:  # noqa: BLE001 - worker must always return
        stats.errors.append(f"{path}: {type(exc).__name__}: {exc}")
    finally:
        if armed:
            signal.setitimer(signal.ITIMER_REAL, 0)

    return FileResult(path=path, findings=findings, stats=stats)


def _scan_batch(batch: List[str]) -> List[FileResult]:
    """Scan several paths in one worker task, so 26k files are not 26k futures."""
    return [_scan_one(path) for path in batch]


def _chunks(items: Iterator[str], size: int) -> Iterator[List[str]]:
    while True:
        batch = list(islice(items, size))
        if not batch:
            return
        yield batch


def _git_note(ctx: "object") -> str:
    """A finding note carrying the introducing commit, its author, and age."""
    from datetime import datetime, timezone

    commit = getattr(ctx, "commit", "")[:12]
    author = getattr(ctx, "author", "")
    date = getattr(ctx, "date", "")
    age = ""
    if date:
        try:
            when = datetime.fromisoformat(date)
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            days = (datetime.now(timezone.utc) - when).days
            age = f", {days}d old"
        except (ValueError, TypeError):
            pass
    owner = f" by {author}" if author else ""
    return f"git history {commit}{owner}{age}"


def _arm(budget: float) -> bool:
    if budget <= 0:
        return False
    try:
        signal.signal(signal.SIGALRM, _raise_budget)
        signal.setitimer(signal.ITIMER_REAL, budget)
        return True
    except (ValueError, OSError, AttributeError):  # pragma: no cover - platform
        return False


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #


class ScannerEngine:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.stats = ScanStats()
        # The store lives only in the main process (it walks and records); it is
        # never sent to workers, which just scan bytes.
        self.store = None
        self._scanned_files: List[Tuple[str, float, int]] = []
        if config.db_path:
            from .store import open_store

            self.store = open_store(config.db_path)
            if self.store is None:
                self.stats.errors.append(
                    f"{config.db_path}: datastore unusable; scanning without it"
                )

    def walk(self) -> Iterator[str]:
        """Yield candidate filesystem paths, honouring scope and symlink safety."""
        seen_dirs: Set[Tuple[int, int]] = set()
        emitted = 0

        for root in self.config.roots:
            normalized = paths.normalize(root)
            if os.path.isfile(normalized):
                if self.config.scope.allow(paths.display(normalized)):
                    emitted += 1
                    yield normalized
                continue
            for path in self._walk_dir(normalized, seen_dirs):
                emitted += 1
                yield path
                if self.config.max_files and emitted >= self.config.max_files:
                    return

    def _walk_dir(
        self, root: str, seen_dirs: Set[Tuple[int, int]]
    ) -> Iterator[str]:
        stack = [root]
        while stack:
            current = stack.pop()
            try:
                entries = list(os.scandir(current))
            except (PermissionError, FileNotFoundError, NotADirectoryError, OSError) as exc:
                self.stats.errors.append(f"{current}: {exc}")
                continue

            for entry in entries:
                try:
                    if entry.is_dir(follow_symlinks=self.config.limits.follow_symlinks):
                        name = paths.safe_name(entry.path)
                        if self.config.scope.skip_dir(name, entry.path):
                            continue
                        if not self.config.include_hidden and name.startswith("."):
                            continue
                        key = self._dir_key(entry)
                        if key is not None:
                            if key in seen_dirs:
                                continue  # symlink / bind-mount loop
                            seen_dirs.add(key)
                        stack.append(entry.path)
                        continue

                    if not entry.is_file(
                        follow_symlinks=self.config.limits.follow_symlinks
                    ):
                        continue

                    self.stats.files_seen += 1
                    if not self.config.scope.allow(paths.display(entry.path)):
                        self.stats.files_skipped += 1
                        continue
                    if self.config.incremental and self.store is not None:
                        try:
                            info = entry.stat(follow_symlinks=False)
                            if self.store.unchanged(entry.path, info.st_mtime, info.st_size):
                                self.stats.files_skipped += 1
                                continue
                            self._scanned_files.append(
                                (entry.path, info.st_mtime, info.st_size)
                            )
                        except (OSError, ValueError):
                            pass
                    yield entry.path
                except (OSError, ValueError) as exc:
                    self.stats.errors.append(f"{entry.path}: {exc}")

    def _dir_key(self, entry: os.DirEntry[str]) -> Optional[Tuple[int, int]]:
        try:
            info = entry.stat(follow_symlinks=True)
            return (info.st_dev, info.st_ino)
        except (OSError, ValueError):
            return None

    # ------------------------------------------------------------------ #

    def run(self, progress: Optional[ProgressHook] = None) -> List[Finding]:
        """Walk and scan concurrently, keeping a bounded window in flight."""
        findings: List[Finding] = []
        worker_count = self.config.worker_count

        if self.config.staged:
            # Pre-commit mode: scan the index, nothing else.
            findings = self.scan_staged(progress)
            if self.store is not None:
                self._persist(findings)
            return findings

        if worker_count == 1:
            _init_worker(self.config)
            for index, path in enumerate(self.walk(), start=1):
                result = _scan_one(path)
                findings.extend(result.findings)
                self.stats.merge(result.stats)
                if progress:
                    progress(path, index)
        else:
            findings.extend(self._run_parallel(progress))

        if self.config.git_history:
            findings.extend(self.scan_git_history(progress))

        if self.store is not None:
            self._persist(findings)
        return findings

    def _persist(self, findings: List[Finding]) -> None:
        assert self.store is not None
        try:
            for path, mtime, size in self._scanned_files:
                self.store.record_file(path, mtime, size)
            counts = self.store.record_findings(findings)
            self.store.commit()
            self.stats.errors.append(
                f"datastore: {counts.new} new, {counts.known} previously seen"
            )
        except Exception as exc:  # noqa: BLE001 - persistence must never fail a scan
            self.stats.errors.append(f"datastore write failed: {exc}")
        finally:
            self.store.close()

    def _run_parallel(self, progress: Optional[ProgressHook]) -> List[Finding]:
        from concurrent.futures.process import BrokenProcessPool

        findings: List[Finding] = []
        worker_count = self.config.worker_count
        batches = _chunks(self.walk(), max(1, self.config.batch_size))
        window = worker_count * 4
        done = 0
        executor = self._make_executor(worker_count)
        try:
            with executor:
                pending = {
                    executor.submit(_scan_batch, batch)
                    for batch in islice(batches, window)
                }
                while pending:
                    finished, pending = wait(pending, return_when=FIRST_COMPLETED)
                    pending = set(pending)
                    for future in finished:
                        try:
                            results = future.result()
                        except Exception as exc:  # noqa: BLE001 - pool-level failure
                            self.stats.errors.append(f"worker task crashed: {exc}")
                            continue
                        for result in results:
                            done += 1
                            findings.extend(result.findings)
                            self.stats.merge(result.stats)
                            if progress:
                                progress(result.path, done)
                    for batch in islice(batches, len(finished)):
                        pending.add(executor.submit(_scan_batch, batch))
        except BrokenProcessPool as exc:
            self.stats.errors.append(
                f"process pool broke ({exc}); retrying serially with threads"
            )
            findings.extend(self._run_serial_fallback(progress, done))
        return findings

    def _run_serial_fallback(
        self, progress: Optional[ProgressHook], done: int
    ) -> List[Finding]:
        _init_worker(self.config)
        findings: List[Finding] = []
        for path in self.walk():
            result = _scan_one(path)
            findings.extend(result.findings)
            self.stats.merge(result.stats)
            done += 1
            if progress:
                progress(path, done)
        return findings

    def scan_blob_stream(
        self,
        items,  # Iterable[tuple[str, bytes]]  (logical_path, content)
        progress: Optional[ProgressHook] = None,
    ) -> List[Finding]:
        """Scan an arbitrary stream of (logical_path, bytes) through the pipeline.

        The common back end for every non-filesystem source — S3/GCS objects,
        SCM comment bodies — so each source is just an iterator of bytes and the
        ingestion, decoding and detection are shared, exactly as for files.
        """
        detector = SecretDetector(self.config.detector)
        ingestor = FileIngestor(self.config.limits, allow=lambda _p: True)
        out: List[Finding] = []
        done = 0
        for logical_path, content in items:
            self.stats.files_seen += 1
            if not self.config.scope.allow(logical_path):
                self.stats.files_skipped += 1
                continue
            self.stats.files_scanned += 1
            self.stats.bytes_scanned += len(content)
            for blob in ingestor.blobs_from_bytes(
                content, logical_path, logical_path, 0, self.stats
            ):
                out.extend(detector.scan(blob))
            done += 1
            if progress:
                progress(logical_path, done)
        return out

    def scan_staged(self, progress: Optional[ProgressHook] = None) -> List[Finding]:
        """Scan git-staged content across the target repos (pre-commit mode)."""
        from . import gitsource

        detector = SecretDetector(self.config.detector)
        ingestor = FileIngestor(self.config.limits, allow=lambda _p: True)
        out: List[Finding] = []
        done = 0
        for root in self.config.roots:
            if not gitsource.is_git_repo(root):
                self.stats.errors.append(f"{root}: not a git repo; --staged needs one")
                continue
            for git_blob in gitsource.staged_blobs(root, self.stats):
                if not self.config.scope.allow(git_blob.path):
                    self.stats.files_skipped += 1
                    continue
                for blob in ingestor.blobs_from_bytes(
                    git_blob.content, git_blob.path, git_blob.path, 0, self.stats
                ):
                    out.extend(detector.scan(blob))
                done += 1
                if progress:
                    progress(git_blob.path, done)
        return out

    def scan_git_history(self, progress: Optional[ProgressHook] = None) -> List[Finding]:
        """Scan every blob reachable from git history, attributed to its commit.

        Runs in the main process: git plumbing is serial and I/O-bound, and each
        blob still flows through the normal ingestion + detection pipeline.
        """
        from . import gitsource

        detector = SecretDetector(self.config.detector)
        ingestor = FileIngestor(self.config.limits, allow=lambda _p: True)
        out: List[Finding] = []
        done = 0
        for root in self.config.roots:
            if not os.path.isdir(root) or not gitsource.is_git_repo(root):
                continue
            source = gitsource.GitHistorySource(
                root,
                since=self.config.git_since,
                max_blob_bytes=self.config.limits.max_member_size,
            )
            for git_blob in source.blobs(self.stats):
                logical = f"{root}@{git_blob.context.commit[:12]}:{git_blob.path}"
                if not self.config.scope.allow(git_blob.path):
                    self.stats.files_skipped += 1
                    continue
                for blob in ingestor.blobs_from_bytes(
                    git_blob.content, logical, logical, 0, self.stats
                ):
                    for finding in detector.scan(blob):
                        finding.git = git_blob.context
                        finding.notes.append(_git_note(git_blob.context))
                        out.append(finding)
                done += 1
                if progress:
                    progress(logical, done)
        return out

    def _make_executor(self, worker_count: int) -> Executor:
        if self.config.use_threads:
            _init_worker(self.config)  # threads share the parent's globals
            return ThreadPoolExecutor(max_workers=worker_count)
        try:
            return ProcessPoolExecutor(
                max_workers=worker_count,
                initializer=_init_worker,
                initargs=(self.config,),
            )
        except (OSError, ValueError, NotImplementedError):  # pragma: no cover
            _init_worker(self.config)
            return ThreadPoolExecutor(max_workers=worker_count)
