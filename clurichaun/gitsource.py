"""Git-history source: scan every blob ever committed, not just the worktree.

The most common real-world leak is a credential that was committed and later
"removed" — deleted from the working tree but still reachable in history. The
filesystem scanner cannot see it: the secret survives only inside a
zlib-compressed object whose bytes are not printable, so even the binary-strings
carver misses it.

This walks the object graph with ``git`` itself (no libgit2 dependency) and
feeds each blob's bytes through the normal ingestion pipeline, tagged with the
commit that introduced it. It is a *source*, not an engine change: the bytes go
to ``FileIngestor.blobs_from_bytes`` exactly like a file or an archive member.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from .models import GitContext, ScanStats

MAX_BLOB_BYTES = 16 * 1024 * 1024


@dataclass(slots=True)
class GitBlob:
    sha: str
    path: str
    content: bytes
    context: GitContext


def is_git_repo(root: str | Path) -> bool:
    try:
        result = _git(root, "rev-parse", "--is-inside-work-tree")
    except (OSError, subprocess.SubprocessError):
        return False
    return result.strip() == "true"


def staged_blobs(
    root: str | Path, stats: ScanStats, max_blob_bytes: int = MAX_BLOB_BYTES
) -> "Iterator[GitBlob]":
    """Yield the staged (index) content of files added/modified in `git diff --cached`.

    This is the pre-commit surface: scan exactly what is about to be committed,
    not the whole tree, so a commit hook stays fast.
    """
    try:
        out = _git(root, "diff", "--cached", "--name-only", "--diff-filter=ACM")
    except (OSError, subprocess.SubprocessError) as exc:
        stats.errors.append(f"{root}: git diff --cached failed: {exc}")
        return
    context = GitContext(commit="STAGED", message="staged (uncommitted) changes")
    for path in out.splitlines():
        path = path.strip()
        if not path:
            continue
        try:
            data = _git_bytes(root, "show", f":{path}")
        except (OSError, subprocess.SubprocessError) as exc:
            stats.errors.append(f"staged {path}: {exc}")
            continue
        if len(data) > max_blob_bytes:
            continue
        stats.files_scanned += 1
        stats.bytes_scanned += len(data)
        yield GitBlob(sha="staged", path=path, content=data, context=context)


class GitHistorySource:
    """Enumerate the blobs reachable from history, newest introduction first."""

    def __init__(
        self,
        root: str | Path,
        since: Optional[str] = None,
        max_blob_bytes: int = MAX_BLOB_BYTES,
        include_all_refs: bool = True,
    ) -> None:
        self.root = str(root)
        self.since = since
        self.max_blob_bytes = max_blob_bytes
        self.include_all_refs = include_all_refs

    def blobs(self, stats: ScanStats) -> Iterator[GitBlob]:
        """Yield each distinct blob once, attributed to the commit that added it.

        A blob object can be shared by many commits (an unchanged file); it is
        scanned once, credited to the earliest commit in the walk that names it.
        """
        seen: set[str] = set()
        try:
            commits = self._commits()
        except (OSError, subprocess.SubprocessError) as exc:
            stats.errors.append(f"{self.root}: git log failed: {exc}")
            return

        for commit in commits:
            try:
                entries = self._blobs_in(commit.commit)
            except (OSError, subprocess.SubprocessError) as exc:
                stats.errors.append(f"{commit.commit[:12]}: git ls-tree failed: {exc}")
                continue
            for sha, path in entries:
                if sha in seen:
                    continue
                seen.add(sha)
                content = self._read_blob(sha, stats)
                if content is None:
                    continue
                stats.files_scanned += 1
                stats.bytes_scanned += len(content)
                yield GitBlob(sha=sha, path=path, content=content, context=commit)

    # ------------------------------------------------------------------ #

    def _commits(self) -> List[GitContext]:
        args = ["log", "--no-merges", "--format=%H%x1f%an%x1f%ae%x1f%aI%x1f%s"]
        if self.include_all_refs and self.since is None:
            args.append("--all")
        if self.since:
            args.append(f"{self.since}..HEAD")
        out = _git(self.root, *args)
        commits: List[GitContext] = []
        for line in out.splitlines():
            parts = line.split("\x1f")
            if len(parts) != 5:
                continue
            commits.append(
                GitContext(
                    commit=parts[0],
                    author=parts[1],
                    email=parts[2],
                    date=parts[3],
                    message=parts[4],
                )
            )
        return commits

    def _blobs_in(self, commit: str) -> List[Tuple[str, str]]:
        """(blob-sha, path) for every file introduced by this commit.

        ``diff-tree`` against the first parent lists only what the commit
        changed, so a 10,000-commit repo is not re-listed in full each step.
        The root commit has no parent, so its whole tree is listed.
        """
        out = _git(
            self.root,
            "diff-tree",
            "--no-commit-id",
            "--root",
            "-r",
            "--diff-filter=AM",
            commit,
        )
        entries: List[Tuple[str, str]] = []
        for line in out.splitlines():
            # Format: :<mode> <mode> <sha> <sha> <status>\t<path>
            meta, _, path = line.partition("\t")
            fields = meta.split()
            if len(fields) < 5 or not path:
                continue
            new_sha = fields[3]
            if new_sha and set(new_sha) != {"0"}:
                entries.append((new_sha, path))
        return entries

    def _read_blob(self, sha: str, stats: ScanStats) -> Optional[bytes]:
        try:
            size_out = _git(self.root, "cat-file", "-s", sha).strip()
            if size_out.isdigit() and int(size_out) > self.max_blob_bytes:
                return None
            return _git_bytes(self.root, "cat-file", "blob", sha)
        except (OSError, subprocess.SubprocessError) as exc:
            stats.errors.append(f"blob {sha[:12]}: {exc}")
            return None


# --------------------------------------------------------------------------- #
# git plumbing
# --------------------------------------------------------------------------- #


def _git(root: str | Path, *args: str) -> str:
    return _run(root, args).decode("utf-8", "replace")


def _git_bytes(root: str | Path, *args: str) -> bytes:
    return _run(root, args)


def _run(root: str | Path, args: Tuple[str, ...] | List[str]) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        check=True,
        timeout=120,
    )
    return result.stdout
