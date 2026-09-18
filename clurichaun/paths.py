"""Cross-platform path handling: long paths, UNC shares, odd filename bytes."""

from __future__ import annotations

import os
import sys
from pathlib import Path, PurePath
from typing import Optional

IS_WINDOWS = sys.platform.startswith("win")
_LONG_PATH_LIMIT = 240


def normalize(path: os.PathLike[str] | str) -> str:
    """Absolute, symlink-preserving path; prefixed for Win32 long-path support."""
    raw = os.fspath(path)
    try:
        absolute = os.path.abspath(os.path.expanduser(os.path.expandvars(raw)))
    except (ValueError, OSError):
        absolute = raw

    if not IS_WINDOWS:
        return absolute

    if absolute.startswith("\\\\?\\"):
        return absolute
    if len(absolute) < _LONG_PATH_LIMIT:
        return absolute
    if absolute.startswith("\\\\"):  # UNC: \\server\share -> \\?\UNC\server\share
        return "\\\\?\\UNC" + absolute[1:]
    return "\\\\?\\" + absolute


def display(path: os.PathLike[str] | str, root: Optional[str] = None) -> str:
    """Stable, forward-slashed path for reports (relative to root when possible)."""
    text = strip_long_prefix(os.fspath(path))
    if root:
        root_text = strip_long_prefix(root)
        try:
            text = os.path.relpath(text, root_text)
        except ValueError:
            pass
    return PurePath(text).as_posix()


def strip_long_prefix(text: str) -> str:
    if text.startswith("\\\\?\\UNC\\"):
        return "\\" + text[len("\\\\?\\UNC") :]
    if text.startswith("\\\\?\\"):
        return text[4:]
    return text


def safe_name(path: os.PathLike[str] | str) -> str:
    """Basename that survives surrogate-escaped filesystem bytes."""
    name = os.path.basename(strip_long_prefix(os.fspath(path)).replace("\\", "/"))
    return name.encode("utf-8", "surrogateescape").decode("utf-8", "replace")


def is_hidden(path: os.PathLike[str] | str) -> bool:
    name = safe_name(path)
    if name.startswith("."):
        return True
    if not IS_WINDOWS:
        return False
    try:  # pragma: no cover - Windows-only
        import stat

        attrs = os.stat(path, follow_symlinks=False).st_file_attributes  # type: ignore[attr-defined]
        return bool(attrs & stat.FILE_ATTRIBUTE_HIDDEN)
    except (OSError, AttributeError, ValueError):
        return False


def readable(path: os.PathLike[str] | str) -> bool:
    try:
        return os.access(path, os.R_OK)
    except (OSError, ValueError):
        return False


def resolve_root(path: os.PathLike[str] | str) -> Path:
    return Path(normalize(path))
