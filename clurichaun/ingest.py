"""FileIngestor: safe reader, decoder, archive unpacker and binary strings miner.

Everything downstream consumes :class:`~clurichaun.models.Blob` objects, so the
detector never has to care whether the text came from a plain file, a nested
``.jar`` inside a ``.tar.gz``, a source map's ``sourcesContent``, or printable
runs carved out of a ``.pyc``.
"""

from __future__ import annotations

import bz2
import gzip
import io
import json
import lzma
import os
import re
import tarfile
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, List, Optional, Tuple

from .models import Blob, ScanStats

try:  # pragma: no cover - optional dependency
    import magic as _magic  # type: ignore
except Exception:  # pragma: no cover
    _magic = None

try:  # pragma: no cover - optional dependency
    import py7zr as _py7zr  # type: ignore
except Exception:  # pragma: no cover
    _py7zr = None

try:  # pragma: no cover - optional dependency
    import rarfile as _rarfile  # type: ignore
except Exception:  # pragma: no cover
    _rarfile = None


DEFAULT_MAX_FILE_SIZE = 512 * 1024 * 1024
# Carving strings out of a 100MB shared object costs minutes and yields little;
# real leaks in binaries live in small artefacts (.pyc, .class, .DS_Store, swaps).
DEFAULT_MAX_BINARY_SIZE = 32 * 1024 * 1024
DEFAULT_STREAM_THRESHOLD = 8 * 1024 * 1024
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024
CHUNK_OVERLAP = 8 * 1024
DEFAULT_MAX_ARCHIVE_DEPTH = 3
DEFAULT_MAX_MEMBERS = 5000
DEFAULT_MAX_MEMBER_SIZE = 64 * 1024 * 1024
DEFAULT_MAX_EXPANSION = 200  # zip-bomb guard: compressed -> uncompressed ratio

ENCODINGS: Tuple[str, ...] = ("utf-8", "utf-8-sig", "cp1252", "latin-1")

_ASCII_RUN = re.compile(rb"[\x20-\x7e\t]{6,}")
_UTF16LE_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")

_TEXTUAL_MAGIC: Tuple[bytes, ...] = (b"<?xml", b"{", b"[", b"#!", b"---", b"<!DOCTYPE")

_ARCHIVE_MAGIC: Tuple[Tuple[bytes, str], ...] = (
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"PK\x07\x08", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
    (b"ustar", "tar"),
)


@dataclass(slots=True)
class IngestLimits:
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    max_binary_size: int = DEFAULT_MAX_BINARY_SIZE
    stream_threshold: int = DEFAULT_STREAM_THRESHOLD
    chunk_size: int = DEFAULT_CHUNK_SIZE
    max_archive_depth: int = DEFAULT_MAX_ARCHIVE_DEPTH
    max_members: int = DEFAULT_MAX_MEMBERS
    max_member_size: int = DEFAULT_MAX_MEMBER_SIZE
    max_expansion: int = DEFAULT_MAX_EXPANSION
    scan_binaries: bool = True
    scan_archives: bool = True
    follow_symlinks: bool = False


class FileIngestor:
    """Turn a filesystem path into a stream of scannable blobs."""

    def __init__(
        self,
        limits: Optional[IngestLimits] = None,
        allow: Optional[Callable[[str], bool]] = None,
    ) -> None:
        self.limits = limits or IngestLimits()
        self.allow = allow or (lambda _path: True)

    # ------------------------------------------------------------------ #
    # Entry point
    # ------------------------------------------------------------------ #

    def blobs(self, path: os.PathLike[str] | str, stats: ScanStats) -> Iterator[Blob]:
        source = str(path)
        try:
            info = os.stat(source, follow_symlinks=self.limits.follow_symlinks)
        except (OSError, ValueError) as exc:
            stats.errors.append(f"{source}: stat failed: {exc}")
            stats.files_skipped += 1
            return

        if not _is_regular(info.st_mode):
            stats.files_skipped += 1
            return
        if info.st_size == 0:
            stats.files_skipped += 1
            return
        if info.st_size > self.limits.max_file_size:
            stats.files_skipped += 1
            stats.errors.append(
                f"{source}: skipped, {info.st_size} bytes exceeds max-file-size"
            )
            return

        try:
            yield from self._ingest_path(source, info.st_size, stats)
        except (OSError, ValueError, MemoryError) as exc:
            stats.errors.append(f"{source}: read failed: {exc}")
            stats.files_skipped += 1

    # ------------------------------------------------------------------ #
    # Path-level handling
    # ------------------------------------------------------------------ #

    def _ingest_path(self, source: str, size: int, stats: ScanStats) -> Iterator[Blob]:
        with open(source, "rb") as handle:
            head = handle.read(8192)
            kind = sniff(head, source)

            if kind.archive and self.limits.scan_archives:
                handle.seek(0)
                payload = handle.read()
                stats.files_scanned += 1
                stats.bytes_scanned += len(payload)
                yield from self._walk_container(
                    payload, source, source, kind.archive, depth=0, stats=stats
                )
                return

            if kind.binary:
                if not self.limits.scan_binaries:
                    stats.files_skipped += 1
                    return
                if size > self.limits.max_binary_size:
                    stats.files_skipped += 1
                    stats.errors.append(
                        f"{source}: skipped, {size} bytes exceeds max-binary-size"
                    )
                    return

            stats.files_scanned += 1

            if size > self.limits.stream_threshold:
                handle.seek(0)
                yield from self._stream_file(handle, source, kind.binary, stats)
                return

            handle.seek(0)
            payload = handle.read()

        stats.bytes_scanned += len(payload)
        yield from self.blobs_from_bytes(payload, source, source, 0, stats)

    def _stream_file(
        self,
        handle: io.BufferedReader,
        source: str,
        binary: bool,
        stats: ScanStats,
    ) -> Iterator[Blob]:
        """Chunked read for very large files.

        Text is cut on line boundaries and each blob carries an overlap of the
        previous blob's trailing lines so a token split across a chunk boundary
        still matches. ``commit_line`` marks where the overlap ends, so the
        detector reports a secret in that window exactly once and with a correct
        line number (``line_offset`` + its line within the blob).
        """
        if binary:
            yield from self._stream_binary(handle, source, stats)
            return

        overlap_lines = self._overlap_lines()
        pending = b""
        emitted_lines = 0  # complete lines already owned by an earlier blob
        overlap: List[str] = []
        overlap_first = 1

        while True:
            chunk = handle.read(self.limits.chunk_size)
            if not chunk:
                break
            stats.bytes_scanned += len(chunk)
            pending += chunk
            newline = pending.rfind(b"\n")
            if newline == -1:
                continue  # no complete line yet; keep accumulating
            body, pending = pending[: newline + 1], pending[newline + 1 :]

            lines = decode(body).splitlines()
            if not lines:
                continue
            block = overlap + lines
            first_line = overlap_first if overlap else emitted_lines + 1
            yield Blob(
                logical_path=source,
                source_path=source,
                text="\n".join(block),
                media_type="text/plain",
                line_offset=first_line - 1,
                commit_line=len(overlap) + 1,
            )
            emitted_lines += len(lines)
            overlap = lines[-overlap_lines:]
            overlap_first = emitted_lines - len(overlap) + 1

        if pending:
            tail = decode(pending).splitlines()
            block = overlap + tail
            first_line = overlap_first if overlap else emitted_lines + 1
            if block:
                yield Blob(
                    logical_path=source,
                    source_path=source,
                    text="\n".join(block),
                    media_type="text/plain",
                    line_offset=first_line - 1,
                    commit_line=len(overlap) + 1,
                )

    def _stream_binary(
        self, handle: io.BufferedReader, source: str, stats: ScanStats
    ) -> Iterator[Blob]:
        """Binary carving: byte overlap, and dedup carried by the detector."""
        byte_offset = 0
        carry = b""
        while True:
            chunk = handle.read(self.limits.chunk_size)
            if not chunk:
                break
            stats.bytes_scanned += len(chunk)
            buffer = carry + chunk
            yield Blob(
                logical_path=source,
                source_path=source,
                text="\n".join(extract_strings(buffer)),
                is_binary=True,
                media_type="application/octet-stream",
                byte_offset=byte_offset,
            )
            carry = buffer[-CHUNK_OVERLAP:] if len(buffer) > CHUNK_OVERLAP else b""
            byte_offset += len(chunk)

    def _overlap_lines(self) -> int:
        # Enough complete lines to span the largest token we would split on.
        return 64

    # ------------------------------------------------------------------ #
    # Byte-level handling (also the recursion target for archive members)
    # ------------------------------------------------------------------ #

    def blobs_from_bytes(
        self,
        payload: bytes,
        logical_path: str,
        source_path: str,
        depth: int,
        stats: ScanStats,
    ) -> Iterator[Blob]:
        kind = sniff(payload[:8192], logical_path)

        if kind.archive and self.limits.scan_archives:
            yield from self._walk_container(
                payload, logical_path, source_path, kind.archive, depth, stats
            )
            return

        if kind.binary:
            if not self.limits.scan_binaries:
                return
            if len(payload) > self.limits.max_binary_size:
                stats.files_skipped += 1
                return
            yield Blob(
                logical_path=logical_path,
                source_path=source_path,
                text="\n".join(extract_strings(payload)),
                is_binary=True,
                media_type=kind.media_type,
                container_depth=depth,
            )
            return

        text = decode(payload)
        yield Blob(
            logical_path=logical_path,
            source_path=source_path,
            text=text,
            media_type=kind.media_type,
            container_depth=depth,
        )

        # Source maps carry whole pre-build trees plus developer comments.
        if logical_path.lower().endswith(".map"):
            yield from self._sourcemap_blobs(text, logical_path, source_path, depth)

    def _sourcemap_blobs(
        self, text: str, logical_path: str, source_path: str, depth: int
    ) -> Iterator[Blob]:
        try:
            doc = json.loads(text)
        except (ValueError, RecursionError):
            return
        if not isinstance(doc, dict):
            return
        sources = doc.get("sources") or []
        contents = doc.get("sourcesContent") or []
        if not isinstance(contents, list):
            return
        for index, content in enumerate(contents):
            if not isinstance(content, str) or not content:
                continue
            name = (
                sources[index]
                if index < len(sources) and isinstance(sources[index], str)
                else f"source{index}"
            )
            yield Blob(
                logical_path=f"{logical_path}!/{name.lstrip('./')}",
                source_path=source_path,
                text=content,
                media_type="application/javascript",
                container_depth=depth + 1,
            )

    # ------------------------------------------------------------------ #
    # Containers
    # ------------------------------------------------------------------ #

    def _walk_container(
        self,
        payload: bytes,
        logical_path: str,
        source_path: str,
        kind: str,
        depth: int,
        stats: ScanStats,
    ) -> Iterator[Blob]:
        if depth >= self.limits.max_archive_depth:
            stats.errors.append(f"{logical_path}: archive depth limit reached")
            return

        stats.archives_opened += 1
        try:
            members = self._members(payload, kind, logical_path, stats)
        except Exception as exc:  # noqa: BLE001 - archive libs raise freely
            stats.errors.append(f"{logical_path}: {kind} open failed: {exc}")
            return

        count = 0
        for name, data in members:
            if count >= self.limits.max_members:
                stats.errors.append(f"{logical_path}: member limit reached")
                break
            count += 1
            nested = f"{logical_path}!/{name}"
            if not self.allow(nested):
                stats.files_skipped += 1
                continue
            stats.files_scanned += 1
            stats.bytes_scanned += len(data)
            yield from self.blobs_from_bytes(data, nested, source_path, depth + 1, stats)

    def _members(
        self, payload: bytes, kind: str, logical_path: str, stats: ScanStats
    ) -> Iterator[Tuple[str, bytes]]:
        if kind == "zip":
            return self._zip_members(payload, logical_path, stats)
        if kind == "tar":
            return self._tar_members(payload, "", logical_path, stats)
        if kind in ("gzip", "bzip2", "xz"):
            return self._compressed_members(payload, kind, logical_path, stats)
        if kind == "7z":
            return self._7z_members(payload, logical_path, stats)
        if kind == "rar":
            return self._rar_members(payload, logical_path, stats)
        return iter(())

    def _zip_members(
        self, payload: bytes, logical_path: str, stats: ScanStats
    ) -> Iterator[Tuple[str, bytes]]:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                if info.file_size > self.limits.max_member_size:
                    stats.errors.append(f"{logical_path}!/{info.filename}: member too large")
                    continue
                if _bomb(info.compress_size, info.file_size, self.limits.max_expansion):
                    stats.errors.append(
                        f"{logical_path}!/{info.filename}: suspicious expansion ratio"
                    )
                    continue
                try:
                    with archive.open(info) as member:
                        yield _safe_name(info.filename), member.read(
                            self.limits.max_member_size
                        )
                except (zipfile.BadZipFile, OSError, RuntimeError, EOFError) as exc:
                    stats.errors.append(f"{logical_path}!/{info.filename}: {exc}")

    def _tar_members(
        self, payload: bytes, mode: str, logical_path: str, stats: ScanStats
    ) -> Iterator[Tuple[str, bytes]]:
        with tarfile.open(fileobj=io.BytesIO(payload), mode=f"r{mode or ':*'}") as archive:
            for member in archive:
                if not member.isfile():
                    continue
                if member.size > self.limits.max_member_size:
                    stats.errors.append(f"{logical_path}!/{member.name}: member too large")
                    continue
                try:
                    handle = archive.extractfile(member)
                    if handle is None:
                        continue
                    with handle:
                        yield _safe_name(member.name), handle.read(
                            self.limits.max_member_size
                        )
                except (tarfile.TarError, OSError, EOFError) as exc:
                    stats.errors.append(f"{logical_path}!/{member.name}: {exc}")

    def _compressed_members(
        self, payload: bytes, kind: str, logical_path: str, stats: ScanStats
    ) -> Iterator[Tuple[str, bytes]]:
        """Single-stream compressors: decompress, then re-dispatch (often a tar)."""
        try:
            if kind == "gzip":
                data = gzip.decompress(payload)
            elif kind == "bzip2":
                data = bz2.decompress(payload)
            else:
                data = lzma.decompress(payload)
        except (OSError, EOFError, zlib.error, lzma.LZMAError, ValueError) as exc:
            stats.errors.append(f"{logical_path}: {kind} decompress failed: {exc}")
            return
        if len(data) > self.limits.max_member_size:
            data = data[: self.limits.max_member_size]
        if _bomb(len(payload), len(data), self.limits.max_expansion):
            stats.errors.append(f"{logical_path}: suspicious expansion ratio")
            return

        inner = _strip_compression_suffix(logical_path)
        if data[257:262] == b"ustar" or inner.endswith(".tar"):
            yield from self._tar_members(data, "", logical_path, stats)
            return
        yield _safe_name(os.path.basename(inner) or "payload"), data

    def _7z_members(
        self, payload: bytes, logical_path: str, stats: ScanStats
    ) -> Iterator[Tuple[str, bytes]]:
        if _py7zr is None:
            stats.errors.append(f"{logical_path}: 7z support needs py7zr")
            return
        with _py7zr.SevenZipFile(io.BytesIO(payload)) as archive:  # type: ignore[union-attr]
            for name, buffer in (archive.readall() or {}).items():
                data = buffer.read(self.limits.max_member_size)
                if data:
                    yield _safe_name(name), data

    def _rar_members(
        self, payload: bytes, logical_path: str, stats: ScanStats
    ) -> Iterator[Tuple[str, bytes]]:
        if _rarfile is None:
            stats.errors.append(f"{logical_path}: rar support needs rarfile + unrar")
            return
        with _rarfile.RarFile(io.BytesIO(payload)) as archive:  # type: ignore[union-attr]
            for info in archive.infolist():
                if info.isdir():
                    continue
                if info.file_size > self.limits.max_member_size:
                    continue
                try:
                    with archive.open(info) as member:
                        yield _safe_name(info.filename), member.read(
                            self.limits.max_member_size
                        )
                except Exception as exc:  # noqa: BLE001 - unrar backend errors vary
                    stats.errors.append(f"{logical_path}!/{info.filename}: {exc}")


# --------------------------------------------------------------------------- #
# Type sniffing / decoding helpers
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class FileKind:
    media_type: str
    binary: bool
    archive: Optional[str] = None


def sniff(head: bytes, path: str = "") -> FileKind:
    """Magic-byte first, libmagic second, extension last."""
    if not head:
        return FileKind("inode/empty", binary=False)

    for magic_bytes, kind in _ARCHIVE_MAGIC:
        if kind == "tar":
            continue
        if head.startswith(magic_bytes):
            return FileKind(f"application/{kind}", binary=True, archive=kind)
    if len(head) > 262 and head[257:262] == b"ustar":
        return FileKind("application/x-tar", binary=True, archive="tar")

    lower = path.lower()
    if lower.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".gz", ".bz2", ".xz")):
        # Extension says compressed even if the header check above missed it.
        if head[:2] == b"\x1f\x8b":
            return FileKind("application/gzip", binary=True, archive="gzip")

    media_type = "text/plain"
    if _magic is not None:  # pragma: no cover - depends on libmagic
        try:
            media_type = _magic.from_buffer(head, mime=True) or media_type
        except Exception:
            media_type = "text/plain"

    if looks_binary(head):
        return FileKind(
            media_type if media_type != "text/plain" else "application/octet-stream",
            binary=True,
        )
    return FileKind(media_type, binary=False)


def looks_binary(head: bytes) -> bool:
    """NUL bytes or a high ratio of non-text bytes mean 'carve strings instead'."""
    if not head:
        return False
    if head.startswith(_TEXTUAL_MAGIC):
        return False
    if b"\x00" in head:
        # UTF-16 text is full of NULs but still decodes cleanly.
        if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
            return False
        return True
    printable = sum(
        1 for byte in head if 32 <= byte <= 126 or byte in (9, 10, 13, 12, 27)
    )
    return printable / len(head) < 0.75


def decode(payload: bytes) -> str:
    """Decode with a fallback ladder; never raises.

    UTF-16 is only attempted on an explicit BOM — without one it happily decodes
    arbitrary single-byte text into CJK mojibake.
    """
    if payload[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return payload.decode("utf-16")
        except (UnicodeDecodeError, LookupError):
            pass
    for encoding in ENCODINGS:
        try:
            return payload.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return payload.decode("utf-8", errors="replace")


def extract_strings(payload: bytes, min_length: int = 6) -> List[str]:
    """Printable ASCII and UTF-16LE runs carved out of a binary payload."""
    out: List[str] = []
    for match in _ASCII_RUN.finditer(payload):
        run = match.group(0)
        if len(run) >= min_length:
            out.append(run.decode("ascii", "replace"))
    for match in _UTF16LE_RUN.finditer(payload):
        run = match.group(0)
        if len(run) >= min_length * 2:
            out.append(run.decode("utf-16-le", "replace"))
    return out


def _bomb(compressed: int, uncompressed: int, limit: int) -> bool:
    if compressed <= 0 or uncompressed <= 1024 * 1024:
        return False
    return uncompressed / compressed > limit


def _safe_name(name: str) -> str:
    """Neutralise traversal in member names — they are display data only."""
    cleaned = name.replace("\\", "/").lstrip("/")
    parts = [part for part in cleaned.split("/") if part not in ("", ".", "..")]
    return "/".join(parts) or "member"


def _strip_compression_suffix(path: str) -> str:
    for suffix in (".gz", ".bz2", ".xz", ".tgz", ".txz", ".tbz2"):
        if path.lower().endswith(suffix):
            base = path[: -len(suffix)]
            if suffix in (".tgz", ".txz", ".tbz2"):
                return base + ".tar"
            return base
    return path


def _is_regular(mode: int) -> bool:
    import stat

    return stat.S_ISREG(mode)


def logical_root(path: str) -> str:
    """The real filesystem path behind a possibly-nested logical path."""
    return path.split("!/", 1)[0]


def as_posix(path: os.PathLike[str] | str) -> str:
    return Path(path).as_posix()
