"""Target scope: which paths are worth opening, and how interesting they are.

Filtering is two-layered:

* a *denylist* that keeps the walker out of vendored trees and media, and
* an *allowlist* of high-value names/extensions/globs (the target scope) that,
  when enabled with ``--scope-only``, restricts scanning to those paths.

Category membership also feeds a confidence boost: a token in ``.env.production``
deserves more trust than the same token in ``README.md``.
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

Category = str

# --------------------------------------------------------------------------- #
# Target scope (per category: extensions, exact names, globs)
# --------------------------------------------------------------------------- #

SCOPE: Dict[Category, Dict[str, Tuple[str, ...]]] = {
    "frontend": {
        "ext": (
            ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte",
            ".html", ".htm", ".xhtml", ".ejs", ".hbs", ".handlebars", ".pug",
            ".jade", ".css", ".scss", ".sass", ".less", ".astro",
        ),
        "glob": ("chunk-*.js", "*.min.js", "*.bundle.js", "main.*.js", "app.*.js"),
    },
    "sourcemap": {
        "ext": (".map",),
        "glob": ("*.js.map", "*.css.map", "*.mjs.map"),
    },
    "config": {
        "ext": (
            ".json", ".json5", ".jsonc", ".yaml", ".yml", ".xml", ".toml", ".ini",
            ".conf", ".config", ".cfg", ".properties", ".plist", ".reg", ".env",
            ".service", ".timer", ".socket", ".netrc",
        ),
        "name": (
            ".env", ".netrc", "_netrc", "web.config", "app.config",
            "application.properties", "settings.py", "local_settings.py",
            "credentials", "config", "secrets.yaml", "secrets.yml",
        ),
        "glob": (".env*", "*.env", "*rc", "*.conf.d/*"),
    },
    "iac": {
        "ext": (".tf", ".tfvars", ".tfstate", ".hcl", ".bicep"),
        "name": (
            "values.yaml", "values.yml", "wrangler.toml", "serverless.yml",
            "serverless.yaml", "sam.yaml", "sam.yml", "template.yaml",
            "kustomization.yaml", "ansible.cfg", "inventory", "vault.yml",
        ),
        "glob": (
            "*.tfstate.backup", "k8s*.y*ml", "*.k8s.y*ml", "helm*.y*ml",
            "*playbook*.y*ml", "*.auto.tfvars",
        ),
    },
    "vcs": {
        "name": (
            "config", "index", "COMMIT_EDITMSG", "HEAD", "packed-refs", "FETCH_HEAD",
            "ORIG_HEAD", ".gitignore", ".gitmodules", ".git-credentials",
            "entries", "wc.db", "hgrc", "dirstate",
        ),
        "glob": (
            ".git/*", "*/.git/*", ".svn/*", "*/.svn/*", ".hg/*", "*/.hg/*",
            ".bzr/*", "*/.bzr/*",
        ),
    },
    "ide": {
        "name": (
            "settings.json", "launch.json", "tasks.json", "workspace.xml",
            "misc.xml", "dataSources.xml", "dataSources.local.xml", "webServers.xml",
            ".DS_Store", "Thumbs.db", "desktop.ini",
        ),
        "ext": (".sublime-project", ".sublime-workspace", ".iml", ".editorconfig"),
        "glob": (".vscode/*", "*/.vscode/*", ".idea/*", "*/.idea/*"),
    },
    "keys": {
        "ext": (
            ".pem", ".key", ".pkcs12", ".pfx", ".p12", ".crt", ".cer", ".der",
            ".jks", ".keystore", ".kdbx", ".ovpn", ".asc", ".gpg", ".ppk", ".csr",
            ".kubeconfig",
        ),
        "name": (
            "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ed25519_sk",
            "authorized_keys", "known_hosts", "identity", "server.key",
            "privkey.pem", "kubeconfig", ".htpasswd", "shadow", "keyring",
        ),
        "glob": (
            "id_*", "*.pem", ".aws/*", "*/.aws/*", ".azure/*", "*/.azure/*",
            ".gcp/*", "*/.gcp/*", ".ssh/*", "*/.ssh/*", ".docker/config.json",
            ".kube/*", "*/.kube/*",
        ),
    },
    "manifest": {
        "name": (
            "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
            ".npmrc", ".yarnrc", ".yarnrc.yml", "requirements.txt", "Pipfile",
            "Pipfile.lock", "poetry.lock", "pyproject.toml", "setup.py",
            "setup.cfg", ".pypirc", "pypirc", "composer.json", "composer.lock",
            "Gemfile", "Gemfile.lock", "go.mod", "go.sum", "Cargo.toml",
            "Cargo.lock", "Dockerfile", "Containerfile", "docker-compose.yml",
            "docker-compose.yaml", "compose.yaml", "Makefile", "Jenkinsfile",
            "gradle.properties", "build.gradle", "pom.xml", ".gitlab-ci.yml",
            ".travis.yml", "cloudbuild.yaml",
        ),
        "glob": (
            "requirements*.txt", "docker-compose.*.y*ml", "Dockerfile.*",
            ".github/workflows/*",
        ),
    },
    "dump": {
        "ext": (
            ".sql", ".dump", ".sqlite", ".sqlite3", ".db", ".db3", ".mdb",
            ".accdb", ".rdb", ".bak", ".old", ".orig", ".save", ".swp", ".swo",
            ".swn", ".core", ".log", ".out", ".csv", ".tsv", ".ldf", ".mdf",
        ),
        "name": ("access.log", "error.log", "debug.log", "dump.rdb", "npm-debug.log"),
        "glob": ("*~", "*.sql.gz", "*.bak.*", "*.log.[0-9]*", "core.[0-9]*"),
    },
    "archive": {
        "ext": (
            ".zip", ".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz",
            ".7z", ".rar", ".jar", ".war", ".ear", ".apk", ".aab", ".ipa",
            ".whl", ".egg", ".nupkg", ".vsix", ".crx", ".asar", ".deb", ".rpm",
        ),
        "glob": ("*.tar.gz", "*.tar.bz2", "*.tar.xz"),
    },
    "apispec": {
        "name": (
            "swagger.json", "swagger.yaml", "swagger.yml", "openapi.json",
            "openapi.yaml", "openapi.yml", "schema.graphql", "insomnia.json",
            "api.json", "thunder-collection.json",
        ),
        "ext": (".graphql", ".gql", ".raml", ".har"),
        "glob": (
            "*.postman_collection.json", "*.postman_environment.json",
            "*.postman_globals.json", "*openapi*.y*ml", "*swagger*.json",
            "*insomnia*.json",
        ),
    },
    "bytecode": {
        "ext": (
            ".class", ".pyc", ".pyo", ".wasm", ".dll", ".exe", ".so", ".dylib",
            ".node", ".dex", ".elf", ".o", ".a", ".bin", ".dat", ".pdb",
        ),
    },
}

# Extensions never worth opening: pure media / fonts / raster assets.
DENY_EXT: frozenset[str] = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".icns", ".tiff", ".tif",
        ".webp", ".avif", ".heic", ".psd", ".ai", ".eps", ".svgz",
        ".mp3", ".wav", ".flac", ".ogg", ".oga", ".m4a", ".aac", ".opus", ".mid",
        ".mp4", ".mkv", ".mov", ".avi", ".webm", ".flv", ".m4v", ".ts.mp4",
        ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods",
        ".iso", ".img", ".vmdk", ".qcow2", ".dmg",
    }
)

# Directories the walker refuses to descend into.
DENY_DIRS: frozenset[str] = frozenset(
    {
        "node_modules", "bower_components", "vendor", "venv", ".venv", "env",
        "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox",
        "site-packages", "dist-info", ".gradle", ".m2", ".cargo", ".rustup",
        ".cache", ".npm", ".yarn", "Pods", ".terraform", ".next", ".nuxt",
        ".svelte-kit", ".angular", ".parcel-cache", "coverage", ".nyc_output",
        ".DS_Store", "Trash", ".steam", ".wine",
    }
)

# Keep .git and friends: their metadata is in scope. They are explicitly
# excluded from DENY_DIRS above and handled by the vcs category.

_INTEREST: Dict[Category, float] = {
    "keys": 0.25,
    "config": 0.2,
    "iac": 0.2,
    "vcs": 0.15,
    "apispec": 0.12,
    "dump": 0.12,
    "sourcemap": 0.1,
    "ide": 0.1,
    "manifest": 0.05,
    "frontend": 0.0,
    "archive": 0.0,
    "bytecode": 0.0,
}


@dataclass(slots=True)
class ScopeFilter:
    scope_only: bool = False
    categories: Optional[frozenset[Category]] = None
    include_globs: Sequence[str] = field(default_factory=tuple)
    exclude_globs: Sequence[str] = field(default_factory=tuple)
    follow_deny_dirs: bool = False

    def skip_dir(self, name: str) -> bool:
        if self.follow_deny_dirs:
            return False
        return name in DENY_DIRS

    def allow(self, path: str) -> bool:
        """Decide whether a filesystem path should be opened at all."""
        norm = path.replace("\\", "/")
        base = posixpath.basename(norm)

        for pattern in self.exclude_globs:
            if _glob(norm, base, pattern):
                return False
        for pattern in self.include_globs:
            if _glob(norm, base, pattern):
                return True

        cats = categories_of(norm)
        if self.categories is not None:
            return bool(cats & self.categories)
        if self.scope_only:
            return bool(cats)
        return _ext_of(base) not in DENY_EXT


def _glob(norm: str, base: str, pattern: str) -> bool:
    return fnmatch.fnmatch(norm, pattern) or fnmatch.fnmatch(base, pattern)


def _ext_of(base: str) -> str:
    dot = base.rfind(".")
    return base[dot:].lower() if dot > 0 else ""


_COMPOUND_EXT = re.compile(r"(?i)\.(tar\.(?:gz|bz2|xz)|js\.map|css\.map|sql\.gz)$")


def categories_of(path: str) -> frozenset[Category]:
    """Every target-scope category a path belongs to (possibly empty)."""
    norm = path.replace("\\", "/")
    base = posixpath.basename(norm)
    lower_base = base.lower()
    ext = _ext_of(lower_base)
    compound = _COMPOUND_EXT.search(lower_base)
    hits: set[Category] = set()

    if compound:
        token = compound.group(1).lower()
        if token.endswith(".map"):
            hits.add("sourcemap")
        else:
            hits.add("archive")

    for category, spec in SCOPE.items():
        if ext and ext in spec.get("ext", ()):
            hits.add(category)
            continue
        if base in spec.get("name", ()) or lower_base in {
            n.lower() for n in spec.get("name", ())
        }:
            hits.add(category)
            continue
        for pattern in spec.get("glob", ()):
            if _glob(norm, base, pattern):
                hits.add(category)
                break

    # `.env.production`, `.env.bak` etc. do not have a useful extension.
    if lower_base.startswith(".env"):
        hits.add("config")
    if "/.git/" in norm or norm.startswith(".git/"):
        hits.add("vcs")

    return frozenset(hits)


def interest_boost(path: str) -> float:
    """Confidence bonus derived from where the finding lives."""
    cats = categories_of(path)
    if not cats:
        return 0.0
    return max(_INTEREST.get(cat, 0.0) for cat in cats)


# Path segments that mark non-production content: a secret here is far more
# likely a fixture than a live credential. Matched on path segments, not as a
# bare substring, so `attestation/` is not mistaken for a test.
_TEST_SEGMENTS = frozenset(
    {
        "test", "tests", "testing", "spec", "specs", "fixture", "fixtures",
        "example", "examples", "sample", "samples", "mock", "mocks", "__tests__",
        "__mocks__", "testdata", "e2e", "demo", "demos", "stub", "stubs",
    }
)
_TEST_FILE = re.compile(r"(?i)(?:[._-](?:test|spec|fixture|mock|example|sample)s?)\.[a-z0-9]+$")
_COMMENT = re.compile(r"^\s*(?:#|//|\*|--|;|<!--)")


def context_penalty(path: str, line_text: str = "") -> float:
    """Confidence penalty for test/example/comment context (0.0 .. 0.3).

    A secret under ``tests/fixtures/`` or on a comment line is usually benign;
    this lowers its confidence without suppressing it, so it still surfaces at a
    lower rank. The inverse of :func:`interest_boost`.
    """
    penalty = 0.0
    norm = path.replace("\\", "/").lower()
    segments = set(norm.split("/"))
    base = posixpath.basename(norm)
    if segments & _TEST_SEGMENTS or _TEST_FILE.search(base):
        penalty += 0.2
    if line_text and _COMMENT.match(line_text):
        penalty += 0.1
    return min(0.3, penalty)


ALL_CATEGORIES: List[Category] = sorted(SCOPE)
