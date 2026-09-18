"""Structured-config parsers with recursive key/value harvesting.

Regex alone misses secrets whose *key* is the only signal (``"db_pw": "hunter2"``
inside a deeply nested JSON blob). These parsers flatten a document into
``key.path -> value`` pairs so the key-name detector can reason about them.
"""

from __future__ import annotations

import configparser
import io
import json
import os
import plistlib
import re
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional, Tuple

try:  # pragma: no cover - optional dependency
    import yaml as _yaml  # type: ignore
except Exception:  # pragma: no cover
    _yaml = None


MAX_DEPTH = 24
MAX_PAIRS = 20000


@dataclass(slots=True)
class KeyValue:
    key_path: str
    key: str
    value: str
    line: int = 0


SUSPICIOUS_KEY = re.compile(
    r"(?i)(?:^|[._\-\[])(?:"
    r"pass(?:wd|word)?|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|"
    r"secret[_\-]?key|private[_\-]?key|client[_\-]?secret|auth|authorization|"
    r"credential|cred|bearer|session[_\-]?key|encryption[_\-]?key|signing[_\-]?key|"
    r"master[_\-]?key|salt|dsn|conn(?:ection)?[_\-]?string|sas|sa[_\-]?key|"
    r"refresh[_\-]?token|id[_\-]?token|otp|pin|passphrase|keystore[_\-]?pass|"
    r"_key|_token|_secret"
    r")(?:$|[._\-\]])"
)

BENIGN_VALUE = re.compile(
    r"(?i)^(?:|true|false|null|none|nil|undefined|0|1|-|n/?a|\*+|x+|"
    r"\$\{[^}]*\}|\{\{[^}]*\}\}|%[A-Z_]+%|<[^>]*>|/[a-z0-9/._\-]*|"
    r"\d+(?:\.\d+)*|[a-f0-9]{0,7}|(?:changeme|example|placeholder|dummy|secret|password|"
    r"your[-_ ]?\w+|todo|fixme|redacted|hidden|masked|env|default|local(?:host)?)\.?)$"
)

_ENV_LINE = re.compile(
    r"""^\s*(?:export\s+|set\s+)?([A-Za-z_][A-Za-z0-9_.\-]*)\s*=\s*(.*?)\s*$"""
)
_SHELL_ASSIGN = re.compile(
    r"""(?m)^\s*(?:export\s+|declare\s+-\w+\s+|readonly\s+)?"""
    r"""([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"]*)"|'([^']*)'|([^\s;#|&]+))"""
)
_HCL_ASSIGN = re.compile(
    r"""(?m)^\s*([A-Za-z_][A-Za-z0-9_.\-]*)\s*=\s*(?:"([^"\n]{0,4096})"|([^\s#]+))"""
)
_REG_VALUE = re.compile(r'''(?m)^\s*"?([^"=\r\n]+)"?\s*=\s*(?:"([^"]*)"|([^\r\n]+))''')
_SYSTEMD_ENV = re.compile(
    r"(?mi)^\s*(?:Environment|SetEnv)\s*=\s*\"?([A-Za-z_][A-Za-z0-9_]*)=([^\"\r\n]*)\"?"
)
_PROPERTIES = re.compile(r"(?m)^\s*([A-Za-z0-9_.\-]+)\s*[:=]\s*(.*?)\s*$")
_NPMRC = re.compile(r"(?m)^\s*(//[^:]+:_(?:auth|authToken|password)|_auth\w*)\s*=\s*(.+)$")


def parse(text: str, logical_path: str) -> List[KeyValue]:
    """Best-effort structured parse; returns [] when the format does not apply."""
    base = os.path.basename(logical_path.replace("\\", "/"))
    lower = base.lower()
    ext = os.path.splitext(lower)[1]

    handlers = _dispatch(lower, ext)
    for handler in handlers:
        try:
            pairs = handler(text)
        except Exception:  # noqa: BLE001 - every parser here is best-effort
            continue
        if pairs:
            return _with_lines(pairs, text)[:MAX_PAIRS]
    return []


def _dispatch(lower: str, ext: str) -> List[Any]:
    if lower.startswith(".env") or ext == ".env" or lower.endswith(".env"):
        return [_parse_env]
    if ext in (".json", ".json5", ".jsonc", ".har", ".webmanifest") or lower in (
        "package.json",
        "composer.json",
        "swagger.json",
        "openapi.json",
        "insomnia.json",
    ):
        return [_parse_json, _parse_env]
    if ext in (".yaml", ".yml"):
        return [_parse_yaml]
    if ext == ".toml" or lower in ("pyproject.toml", "wrangler.toml", "cargo.toml"):
        return [_parse_toml]
    if ext in (".xml", ".plist", ".config", ".csproj", ".props", ".iml"):
        return [_parse_plist, _parse_xml]
    if ext in (".ini", ".cfg", ".conf", ".properties", ".netrc") or lower in (
        "config",
        "gitconfig",
        ".gitconfig",
        "hgrc",
        "credentials",
        "pypirc",
        ".pypirc",
    ):
        return [_parse_ini, _parse_properties, _parse_env]
    if lower in (".npmrc", "npmrc", ".yarnrc"):
        return [_parse_npmrc, _parse_env]
    if ext in (".tf", ".tfvars", ".hcl", ".bicep"):
        return [_parse_hcl]
    if ext == ".tfstate" or lower.endswith(".tfstate.backup"):
        return [_parse_json]
    if ext in (".service", ".timer", ".socket", ".mount", ".target"):
        return [_parse_systemd, _parse_ini]
    if ext == ".reg":
        return [_parse_reg]
    if ext in (".sh", ".bash", ".zsh", ".ksh", ".fish", ".ps1", ".bat", ".cmd"):
        return [_parse_shell]
    if ext in (".properties",):
        return [_parse_properties]
    if lower == "dockerfile" or lower.startswith("dockerfile."):
        return [_parse_dockerfile]
    # Unknown type: a cheap generic assignment sweep still helps.
    return [_parse_env]


# --------------------------------------------------------------------------- #
# Individual parsers
# --------------------------------------------------------------------------- #


def _parse_json(text: str) -> List[Tuple[str, str]]:
    doc = json.loads(_strip_json_comments(text))
    return list(_flatten(doc))


def _parse_yaml(text: str) -> List[Tuple[str, str]]:
    if _yaml is None:  # pragma: no cover
        return []
    pairs: List[Tuple[str, str]] = []
    for doc in _yaml.safe_load_all(text):
        pairs.extend(_flatten(doc))
    return pairs


def _parse_toml(text: str) -> List[Tuple[str, str]]:
    return list(_flatten(tomllib.loads(text)))


def _parse_plist(text: str) -> List[Tuple[str, str]]:
    doc = plistlib.loads(text.encode("utf-8", "replace"))
    return list(_flatten(doc))


def _parse_xml(text: str) -> List[Tuple[str, str]]:
    root = ET.fromstring(text)  # noqa: S314 - config surface, not untrusted RPC
    pairs: List[Tuple[str, str]] = []

    def walk(node: ET.Element, prefix: str, depth: int) -> None:
        if depth > MAX_DEPTH or len(pairs) > MAX_PAIRS:
            return
        tag = _localname(node.tag)
        path = f"{prefix}.{tag}" if prefix else tag
        for name, value in node.attrib.items():
            if isinstance(value, str) and value.strip():
                pairs.append((f"{path}@{_localname(name)}", value))
        if node.text and node.text.strip():
            pairs.append((path, node.text.strip()))
        for child in node:
            walk(child, path, depth + 1)

    walk(root, "", 0)
    return pairs


def _parse_ini(text: str) -> List[Tuple[str, str]]:
    parser = configparser.RawConfigParser(strict=False, allow_no_value=True)
    parser.read_string(text)
    pairs: List[Tuple[str, str]] = []
    for section in parser.sections():
        for key, value in parser.items(section):
            if value:
                pairs.append((f"{section}.{key}", value))
    for key, value in parser.defaults().items():
        if value:
            pairs.append((key, value))
    return pairs


def _parse_env(text: str) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        match = _ENV_LINE.match(line)
        if not match:
            continue
        key, value = match.group(1), match.group(2)
        value = _unquote(value.split(" #", 1)[0].strip())
        if value:
            pairs.append((key, value))
    return pairs


def _parse_shell(text: str) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    for match in _SHELL_ASSIGN.finditer(text):
        key = match.group(1)
        value = match.group(2) or match.group(3) or match.group(4) or ""
        if value:
            pairs.append((key, value))
    return pairs


def _parse_hcl(text: str) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    for match in _HCL_ASSIGN.finditer(text):
        value = match.group(2) if match.group(2) is not None else (match.group(3) or "")
        if value:
            pairs.append((match.group(1), value.strip('"')))
    return pairs


def _parse_reg(text: str) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    for match in _REG_VALUE.finditer(text):
        name = match.group(1).strip()
        value = (match.group(2) or match.group(3) or "").strip()
        if not value or name.startswith("[") or value.startswith(("dword:", "hex(")):
            continue
        pairs.append((name, value.replace("\\\\", "\\")))
    return pairs


def _parse_systemd(text: str) -> List[Tuple[str, str]]:
    return [(m.group(1), m.group(2)) for m in _SYSTEMD_ENV.finditer(text) if m.group(2)]


def _parse_properties(text: str) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "!", ";", "[")):
            continue
        match = _PROPERTIES.match(line)
        if match and match.group(2):
            pairs.append((match.group(1), _unquote(match.group(2))))
    return pairs


def _parse_npmrc(text: str) -> List[Tuple[str, str]]:
    pairs = [(m.group(1), m.group(2).strip()) for m in _NPMRC.finditer(text)]
    return pairs or _parse_properties(text)


def _parse_dockerfile(text: str) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    pattern = re.compile(r"(?mi)^\s*(?:ENV|ARG)\s+([A-Za-z_][A-Za-z0-9_]*)[\s=]+(.+?)\s*$")
    for match in pattern.finditer(text):
        pairs.append((match.group(1), _unquote(match.group(2))))
    return pairs


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _flatten(node: Any, prefix: str = "", depth: int = 0) -> Iterator[Tuple[str, str]]:
    if depth > MAX_DEPTH:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            label = str(key)
            path = f"{prefix}.{label}" if prefix else label
            yield from _flatten(value, path, depth + 1)
    elif isinstance(node, (list, tuple)):
        for index, value in enumerate(node):
            path = f"{prefix}[{index}]"
            yield from _flatten(value, path, depth + 1)
    elif isinstance(node, (str, bytes)):
        text = node.decode("utf-8", "replace") if isinstance(node, bytes) else node
        if text.strip():
            yield (prefix, text)
    elif node is not None and not isinstance(node, bool):
        yield (prefix, str(node))


def _with_lines(pairs: List[Tuple[str, str]], text: str) -> List[KeyValue]:
    """Attach a best-effort line number by locating the value in the raw text."""
    index = _line_index(text)
    out: List[KeyValue] = []
    cursor = 0
    for key_path, value in pairs:
        key = key_path.split(".")[-1].split("[")[0] or key_path
        line = 0
        needle = value[:96]
        if needle:
            position = text.find(needle, cursor)
            if position == -1:
                position = text.find(needle)
            if position != -1:
                line = _line_of(index, position)
                cursor = position + 1
        out.append(KeyValue(key_path=key_path, key=key, value=value, line=line))
    return out


def _line_index(text: str) -> List[int]:
    offsets = [0]
    start = text.find("\n")
    while start != -1:
        offsets.append(start + 1)
        start = text.find("\n", start + 1)
    return offsets


def _line_of(offsets: List[int], position: int) -> int:
    low, high = 0, len(offsets) - 1
    while low < high:
        mid = (low + high + 1) // 2
        if offsets[mid] <= position:
            low = mid
        else:
            high = mid - 1
    return low + 1


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _localname(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _strip_json_comments(text: str) -> str:
    """Tolerate JSONC/JSON5-style comments and trailing commas."""
    if "//" not in text and "/*" not in text:
        return text
    out = io.StringIO()
    in_string = False
    escape = False
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if in_string:
            out.write(char)
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            out.write(char)
            index += 1
            continue
        if char == "/" and index + 1 < length:
            nxt = text[index + 1]
            if nxt == "/":
                end = text.find("\n", index)
                index = length if end == -1 else end
                continue
            if nxt == "*":
                end = text.find("*/", index + 2)
                index = length if end == -1 else end + 2
                continue
        out.write(char)
        index += 1
    return re.sub(r",(\s*[}\]])", r"\1", out.getvalue())


def is_suspicious_key(key_path: str) -> bool:
    return bool(SUSPICIOUS_KEY.search(key_path)) or bool(
        SUSPICIOUS_KEY.search(f".{key_path}.")
    )


def is_benign_value(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 6:
        return True
    return bool(BENIGN_VALUE.match(stripped))
