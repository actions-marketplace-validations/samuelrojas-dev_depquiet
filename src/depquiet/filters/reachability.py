"""Dependency usage heuristics based on imports, commands and project mentions.

These observations do not establish vulnerable-function execution or product
impact. Python imports use AST extraction with a regex fallback on parse errors;
the other supported languages use import-pattern heuristics.

Strategy (v7 — multi-language import analysis, conservative):
1. Python files are parsed with ``ast`` to extract real import statements,
   ignoring comments, strings, and partial-name matches that trip up regex.
2. JS/TS files are parsed with a comment/string-stripping regex pipeline
   followed by import/require/export pattern matching — catches ESM imports,
   CommonJS require(), dynamic import(), and re-exports while ignoring
   package names that only appear inside comments or string literals.
3. Go files are parsed for ``import`` statements with module path resolution.
4. Rust files are parsed for ``use``/``extern crate`` with hyphen normalization.
5. Java/Kotlin files are parsed for ``import`` statements with Maven group ID
   matching (``groupId:artifactId`` coordinates).
6. C# files are parsed for ``using`` directives with NuGet namespace matching.
7. PHP files are parsed for ``use`` statements with Composer package matching.
8. Ruby files are parsed for ``require`` statements with gem name matching
   (hyphen-to-slash convention for hyphenated gems).
9. Swift files are parsed for ``import`` statements with SwiftPM package-to-module
   mapping (hyphen-to-underscore convention).
10. Dart files are parsed for ``import 'package:name/...'`` statements with
    pub.dev package name matching.
11. If vulnerable_functions are known, check if any of those specific functions
    appear in the source (string search — conservative).
12. Only mark as unreachable if we're confident the package/function isn't used.

Source read or enumeration errors leave coverage incomplete. In that case,
absence of observed imports cannot justify an unreachable verdict. Regex
fallbacks preserve their existing behavior and do not establish parse coverage.
"""

from __future__ import annotations

import ast
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import lru_cache, partial
from pathlib import Path

from depquiet.depgraph import DependencyGraph
from depquiet.filters.dynamic_imports import (
    DynamicImport,
    js_dynamic_imports,
    python_dynamic_imports,
)
from depquiet.models import FilterReason, Vulnerability
from depquiet.pynames import import_candidates

_TEXT_CACHE: dict[tuple[str, int, int], str] = {}
_TextReader = Callable[[Path], str]
_ScopeErrorHandler = Callable[[Path, str | OSError], None]


def _read_text(f: Path) -> str:
    """Read a source file once per scan.

    Every package check walks every source file, so without this a project
    with hundreds of files and alerts re-reads (and, via the cached
    extractors below, re-parses) the same files thousands of times. Keyed by
    size and mtime so an edited file is read again. Raises OSError like
    ``Path.read_text``.
    """
    st = f.stat()
    key = (str(f), st.st_mtime_ns, st.st_size)
    text = _TEXT_CACHE.get(key)
    if text is None:
        if len(_TEXT_CACHE) > 20000:
            _TEXT_CACHE.clear()
        text = f.read_text(errors="replace")
        _TEXT_CACHE[key] = text
    return text


# Files whose text can show a dependency is in use without an import:
# settings (INSTALLED_APPS = ["allauth"]), database URLs ("postgresql+psycopg2"),
# service scripts ("celery flower"), bundler/linter configs.
_MENTION_SUFFIXES = {
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".vue",
    ".rb",
    ".php",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".cs",
    ".swift",
    ".dart",
    ".sh",
    ".bash",
    ".zsh",
    ".conf",
    ".ini",
    ".cfg",
    ".yml",
    ".yaml",
    ".env",
    ".service",
    ".toml",
    ".json",
    ".xml",
}
# Manifests and lockfiles list every dependency; docs mention them in prose.
_MENTION_EXCLUDED_NAMES = {
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "pyproject.toml",
    "poetry.lock",
    "uv.lock",
    "Pipfile",
    "Pipfile.lock",
    "setup.cfg",
    "composer.json",
    "composer.lock",
    "Cargo.toml",
    "Cargo.lock",
    "go.mod",
    "go.sum",
    "Gemfile",
    "Gemfile.lock",
    "pubspec.yaml",
    "pubspec.lock",
    "packages.lock.json",
    "dependabot.yml",
    "renovate.json",
    ".pre-commit-config.yaml",
}
_MENTION_EXCLUDED_DIRS = {"docs", "doc", ".github", "site", "examples"}
_MENTION_MAX_BYTES = 512 * 1024

# Test code is not shipped as the application. Deliberately narrow: a
# directory or file counts only when its name is an established test
# convention, so ordinary application code is never mistaken for a test.
_TEST_DIRS = {"test", "tests", "__tests__", "__mocks__", "e2e"}
_TEST_FILE = re.compile(
    r"""(?x)
    \.(?:test|spec)\.[A-Za-z]+$                 # app.test.ts, api.spec.js
    | ^test_[^/]*\.py$ | _test\.(?:py|go|rb)$     # test_x.py, x_test.go
    | ^conftest\.py$ | _spec\.rb$
    | ^(?:jest|vitest|playwright|cypress|karma)\.(?:config|preset|setup|conf)\.[A-Za-z]+$
    """
)


def is_test_path(relative: Path) -> bool:
    """True when a project-relative path is test code or test-runner configuration."""
    return any(part in _TEST_DIRS for part in relative.parts[:-1]) or bool(
        _TEST_FILE.search(relative.name)
    )


_WORD = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_\-]*")


class _SourceScope:
    """Keep traversal inside the requested root without following source links."""

    def __init__(self, project: Path, exclude_roots: list[Path] | None = None):
        self.project = project.resolve()
        self.excluded = [
            (path if path.is_absolute() else self.project / path).resolve()
            for path in exclude_roots or []
        ]

    def includes(self, path: Path, on_scope_error: _ScopeErrorHandler | None = None) -> bool:
        try:
            resolved = path.resolve()
            if any(resolved.is_relative_to(excluded) for excluded in self.excluded):
                return False
            if not resolved.is_relative_to(self.project):
                reason = "resolved source path is outside the requested project"
            elif path.is_symlink() or getattr(path, "is_junction", lambda: False)():
                reason = "source symlink or junction is not followed"
            else:
                return True
        except (OSError, RuntimeError) as error:
            if on_scope_error is not None:
                on_scope_error(
                    path,
                    error
                    if isinstance(error, OSError)
                    else f"source path resolution failed: {error}",
                )
            return False
        if on_scope_error is not None:
            on_scope_error(path, reason)
        return False


def _mention_words(
    project: Path,
    *,
    read_text: _TextReader | None = None,
    onerror: Callable[[OSError], None] | None = None,
    on_read_error: Callable[[str, Path, OSError], None] | None = None,
    exclude_roots: list[Path] | None = None,
    on_scope_error: _ScopeErrorHandler | None = None,
    skip_tests: bool = False,
) -> set[str]:
    """Lower-cased words in the project's code, scripts and config files.

    With ``skip_tests`` the words come only from files outside test code.
    """
    words: set[str] = set()
    scope = _SourceScope(project, exclude_roots)
    for root, dirs, files in os.walk(project, onerror=onerror):
        dirs[:] = [
            d
            for d in dirs
            if d not in _SKIP_DIRS
            and d not in _MENTION_EXCLUDED_DIRS
            and not d.startswith(".")
            and scope.includes(Path(root) / d, on_scope_error)
        ]
        for name in files:
            if name in _MENTION_EXCLUDED_NAMES or name.startswith("requirements"):
                continue
            path = Path(root) / name
            if skip_tests and is_test_path(path.relative_to(project)):
                continue
            suffix = path.suffix.lower()
            extensionless = not suffix and not name.startswith(".")
            if suffix not in _MENTION_SUFFIXES and not extensionless:
                continue
            if not scope.includes(path, on_scope_error):
                continue
            try:
                size = path.stat().st_size
            except OSError as error:
                if on_read_error is not None:
                    on_read_error("inspect source metadata", path, error)
                continue
            if size > _MENTION_MAX_BYTES:
                continue
            try:
                text = _read_text(path) if read_text is None else read_text(path)
            except OSError as error:
                if on_read_error is not None:
                    on_read_error("read source", path, error)
                continue
            if extensionless and "\x00" in text[:1024]:
                continue  # binary
            for w in _WORD.findall(text):
                w = w.lower()
                words.add(w)
                words.add(w.replace("-", "_"))
    return words


@dataclass
class ReachabilityDecision:
    """Outcome of the reachability filter for one vulnerability.

    ``unreachable`` is True only when the filter can justify it: the package
    is a direct dependency that no source file imports, or it is transitive
    and none of the direct dependencies that pull it in are imported.
    """

    unreachable: bool
    dependency_type: str  # "direct" | "transitive" | "unknown"
    introduced_by: list[str] = field(default_factory=list)
    # Direct dependencies (introduced_by) that the source code imports or the
    # project runs as a command.
    imported_ancestors: list[str] = field(default_factory=list)
    # The package is used, but every production use found is in test code
    # (see ``ReachabilityFilter._test_only``). Never True with ``unreachable``.
    test_only: bool = False


# File extensions to search for imports
_JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
_PY_EXTENSIONS = {".py"}
_GO_EXTENSIONS = {".go"}
_RS_EXTENSIONS = {".rs"}
_JAVA_EXTENSIONS = {".java", ".kt", ".kts"}
_CS_EXTENSIONS = {".cs"}
_PHP_EXTENSIONS = {".php"}
_RB_EXTENSIONS = {".rb"}
_SWIFT_EXTENSIONS = {".swift"}
_DART_EXTENSIONS = {".dart"}
_ALL_EXTENSIONS = (
    _JS_EXTENSIONS
    | _PY_EXTENSIONS
    | _GO_EXTENSIONS
    | _RS_EXTENSIONS
    | _JAVA_EXTENSIONS
    | _CS_EXTENSIONS
    | _PHP_EXTENSIONS
    | _RB_EXTENSIONS
    | _SWIFT_EXTENSIONS
    | _DART_EXTENSIONS
)

# Directories to skip
_SKIP_DIRS = {
    "node_modules",
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "coverage",
    "vendor",
    "target",
    ".build",
    ".dart_tool",
}


def _source_files(
    project: Path,
    extensions: set[str],
    *,
    onerror: Callable[[OSError], None] | None = None,
    exclude_roots: list[Path] | None = None,
    on_scope_error: _ScopeErrorHandler | None = None,
) -> list[Path]:
    """Walk project tree and collect source files, skipping vendored dirs."""
    files: list[Path] = []
    scope = _SourceScope(project, exclude_roots)
    for root, dirs, filenames in os.walk(project, onerror=onerror):
        dirs[:] = [
            d
            for d in dirs
            if d not in _SKIP_DIRS and scope.includes(Path(root) / d, on_scope_error)
        ]
        for f in filenames:
            p = Path(root) / f
            if p.suffix in extensions and scope.includes(p, on_scope_error):
                files.append(p)
    return files


def _file_mentions(
    files: list[Path], pattern: str, *, read_text: _TextReader | None = None
) -> list[str]:
    """Return file paths where pattern appears (case-sensitive)."""
    matches: list[str] = []
    regex = re.compile(re.escape(pattern))
    for f in files:
        try:
            text = _read_text(f) if read_text is None else read_text(f)
            if regex.search(text):
                matches.append(str(f))
        except OSError:
            continue
    return matches


@lru_cache(maxsize=8192)
def _ast_imports(source: str) -> set[str] | None:
    """Extract all top-level package names from Python source using AST.

    Returns the set of top-level module names found in import and
    from-import statements, plus any ``__import__('name')`` calls.

    Returns ``None`` on parse failure (SyntaxError) — the caller should
    fall back to regex. Returns an empty ``set()`` when parsing succeeds
    but no imports are found (meaning the file genuinely has no imports).
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                # 'import foo.bar' → top-level is 'foo'
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            # 'from foo.bar import baz' → top-level is 'foo'
            names.add(node.module.split(".")[0])
    names.update(
        observation.target.split(".")[0]
        for observation in python_dynamic_imports(source)
        if observation.target is not None
    )
    return names


def _py_imports_package(
    files: list[Path],
    package: str,
    project: Path | None = None,
    *,
    read_text: _TextReader | None = None,
) -> bool:
    """Check whether any Python file imports the given package using AST.

    Uses ``ast.parse()`` for proper import detection — immune to false
    positives from comments, docstrings, and partial name matches.

    Falls back to regex for files that fail to parse (encoding issues,
    syntax errors in Python 2 files, etc.) — conservative: if we can't
    parse it, we check with regex so we don't accidentally filter a real
    import.
    """
    # The distribution name (PyYAML, Django) rarely equals the module name
    # (yaml, django); see depquiet.pynames.
    candidates = import_candidates(package, project)
    return any(_py_text_imports(f, candidates, read_text=read_text) for f in files)


def _py_text_imports(
    f: Path, candidates: set[str], *, read_text: _TextReader | None = None
) -> bool:
    try:
        text = _read_text(f) if read_text is None else read_text(f)
    except OSError:
        return False
    imports = _ast_imports(text)
    if imports is None:
        # AST parse failed — fall back to regex (conservative: don't miss a
        # real import in a file we can't parse).
        return any(_regex_py_imports(text, c, ignore_case=True) for c in candidates)
    return any(i.lower() in candidates for i in imports)


def _regex_py_imports(text: str, import_name: str, *, ignore_case: bool = False) -> bool:
    """Regex fallback for Python import detection (used when AST fails)."""
    esc = re.escape(import_name)
    pattern = re.compile(
        rf"(?:^|\n)\s*import\s+(?:\w+\s*,\s*)*{esc}(?:\s|,|\.|\)|$)"
        r"|"
        rf"(?:^|\n)\s*from\s+{esc}(?:\s|\.)"
        r"|"
        rf"__import__\(\s*['\"]" + esc + r"['\"]",
        re.MULTILINE | (re.IGNORECASE if ignore_case else 0),
    )
    return bool(pattern.search(text))


def _strip_js_comments_and_strings(source: str) -> str:
    """Remove comments and string literals from JS/TS source.

    Strips:
    - Single-line comments (// ...)
    - Multi-line comments (/* ... */)
    - Template literals (`...`)
    - Double-quoted strings ("...")
    - Single-quoted strings ('...')

    This lets us run import patterns on what remains without false positives
    from package names that appear only inside comments or strings.
    """
    return re.sub(
        r"//[^\n]*"  # single-line comment
        r"|/\*[\s\S]*?\*/"  # multi-line comment
        r"|`(?:[^`\\]|\\.)*`"  # template literal
        r"|\"(?:[^\"\\]|\\.)*\""  # double-quoted string
        r"|'(?:[^'\\]|\\.)*'",  # single-quoted string
        " ",
        source,
    )


def _strip_js_comments(source: str) -> str:
    """Remove only comments from JS/TS source, preserving strings.

    We strip comments so that ``// import x from 'x'`` and block-commented
    imports are ignored.  String literals are kept intact because the import
    regex patterns need the specifier strings (``'lodash'``) to extract the
    package name.  The import-specific regexes are narrow enough that a bare
    string mention like ``"uses lodash"`` won't false-positive.

    A full ``import … from 'pkg'`` inside a string *will* match — that is
    the conservative choice (treating it as reachable is safe).
    """
    return re.sub(
        r"//[^\n]*"  # single-line comment
        r"|/\*[\s\S]*?\*/",  # multi-line comment
        " ",
        source,
    )


@lru_cache(maxsize=8192)
def _js_extract_imports(source: str) -> set[str]:
    """Extract package names from JS/TS source using regex on stripped code.

    Handles:
    - ESM: import X from 'pkg', import {a} from 'pkg', import 'pkg'
    - CommonJS: require('pkg'), require("pkg")
    - Dynamic: import('pkg')
    - Re-exports: export {a} from 'pkg', export * from 'pkg'

    Returns the set of top-level package names (for scoped packages like
    ``@scope/name``, returns ``@scope/name``).
    """
    stripped = _strip_js_comments(source)

    names: set[str] = set()

    # ESM import: import ... from 'pkg' / import 'pkg' (side-effect)
    for m in re.finditer(
        r"""\bimport\s+"""
        r"""(?:"""
        r"""(?:[\w*{}\s,]+)\s+from\s+"""  # import X from 'pkg'
        r"""|"""  # OR
        r""")"""  # import 'pkg' (side-effect)
        r"""["']([^"']+)["']""",
        stripped,
    ):
        names.add(_js_package_name(m.group(1)))

    # Loader calls use lexical context so strings/comments/regex are not code.
    names.update(
        _js_package_name(observation.target)
        for observation in js_dynamic_imports(source)
        if observation.target is not None
    )

    # Re-exports: export ... from 'pkg'
    for m in re.finditer(
        r"""\bexport\s+(?:[\w*{}\s,]+)\s+from\s+["']([^"']+)["']""",
        stripped,
    ):
        names.add(_js_package_name(m.group(1)))

    return names


def _js_package_name(specifier: str) -> str:
    """Extract the package name from a JS import specifier.

    - ``lodash`` → ``lodash``
    - ``lodash/merge`` → ``lodash``
    - ``@scope/name`` → ``@scope/name``
    - ``@scope/name/sub`` → ``@scope/name``
    - ``./local`` → ``./local`` (relative, won't match any package)
    """
    if specifier.startswith(".") or specifier.startswith("/"):
        return specifier  # relative/absolute — never matches a package name
    if specifier.startswith("@"):
        # Scoped package: @scope/name(/subpath)?
        parts = specifier.split("/")
        return "/".join(parts[:2]) if len(parts) >= 2 else specifier
    # Unscoped: name(/subpath)?
    return specifier.split("/")[0]


def _js_imports_package(
    files: list[Path], package: str, *, read_text: _TextReader | None = None
) -> bool:
    """Check whether any JS/TS file imports the given package.

    Uses comment/string stripping + regex for proper import detection —
    immune to false positives from package names in comments or strings.
    """
    for f in files:
        try:
            text = _read_text(f) if read_text is None else read_text(f)
        except OSError:
            continue
        imports = _js_extract_imports(text)
        if package in imports:
            return True
    return False


def _js_file_imports_package(
    f: Path, package: str, *, read_text: _TextReader | None = None
) -> bool:
    """Check whether a single JS/TS file imports the given package."""
    try:
        text = _read_text(f) if read_text is None else read_text(f)
    except OSError:
        return False
    return package in _js_extract_imports(text)


def _py_file_imports_package(
    f: Path,
    package: str,
    project: Path | None = None,
    *,
    read_text: _TextReader | None = None,
) -> bool:
    """Check whether a single Python file imports the given package."""
    return _py_text_imports(f, import_candidates(package, project), read_text=read_text)


def _strip_go_comments(source: str) -> str:
    """Remove comments from Go source, preserving string literals.

    Go comments use the same ``//`` and ``/* */`` syntax as JS/TS.
    We preserve string literals (double-quoted and backtick raw strings)
    so the import path strings remain intact.
    """
    return re.sub(
        r"//[^\n]*"  # single-line comment
        r"|/\*[\s\S]*?\*/",  # multi-line comment
        " ",
        source,
    )


@lru_cache(maxsize=8192)
def _go_extract_imports(source: str) -> set[str]:
    """Extract Go module paths from import statements.

    Handles:
    - Single: ``import "fmt"``
    - Grouped: ``import ( "fmt" ; "net/http" )``
    - Aliased: ``import m "github.com/user/pkg"``
    - Dot import: ``import . "pkg"``
    - Blank import: ``import _ "pkg"``

    Returns the full import path for each (e.g. ``github.com/user/repo/sub``).
    """
    stripped = _strip_go_comments(source)
    names: set[str] = set()

    # Grouped imports: import ( ... )
    for m in re.finditer(r"\bimport\s*\(([^)]*)\)", stripped):
        block = m.group(1)
        # Each import inside the parens: optional alias + quoted path
        for line_m in re.finditer(r'(?:[\w._]+\s+)?"([^"]+)"', block):
            names.add(line_m.group(1))

    # Single imports: import "pkg" or import alias "pkg"
    for m in re.finditer(r'\bimport\s+(?:[\w._]+\s+)?"([^"]+)"', stripped):
        names.add(m.group(1))

    return names


def _go_module_name(import_path: str) -> str:
    """Extract the module name from a Go import path.

    Go modules typically have 3 path segments (host/user/repo).
    Standard library packages have 1-2 segments (fmt, net/http).
    Sub-packages extend the module path (github.com/user/repo/sub).

    For vulnerability matching, we need the module root:
    - ``github.com/user/repo/sub`` → ``github.com/user/repo``
    - ``golang.org/x/crypto/ssh`` → ``golang.org/x/crypto``
    - ``fmt`` → ``fmt``
    - ``net/http`` → ``net/http``

    We return up to the first 3 segments for hosted modules, or the
    full path for stdlib.
    """
    parts = import_path.split("/")
    # Standard library: no dots in first segment
    if "." not in parts[0]:
        return import_path
    # Hosted module: typically host/user/repo, take first 3 parts
    return "/".join(parts[:3]) if len(parts) >= 3 else import_path


def _go_imports_package(
    files: list[Path], package: str, *, read_text: _TextReader | None = None
) -> bool:
    """Check whether any Go file imports the given package/module.

    Matches if the package name equals any imported module root or if the
    package is a prefix of any import path (module + sub-package).
    """
    for f in files:
        try:
            text = _read_text(f) if read_text is None else read_text(f)
        except OSError:
            continue
        imports = _go_extract_imports(text)
        for imp in imports:
            # Exact match or the import is a sub-package of the vulnerable module
            module = _go_module_name(imp)
            if module == package or imp == package or imp.startswith(package + "/"):
                return True
    return False


def _go_file_imports_package(
    f: Path, package: str, *, read_text: _TextReader | None = None
) -> bool:
    """Check whether a single Go file imports the given package."""
    try:
        text = _read_text(f) if read_text is None else read_text(f)
    except OSError:
        return False
    imports = _go_extract_imports(text)
    for imp in imports:
        module = _go_module_name(imp)
        if module == package or imp == package or imp.startswith(package + "/"):
            return True
    return False


def _strip_rust_comments(source: str) -> str:
    """Remove comments from Rust source, preserving string literals.

    Rust uses ``//`` for line comments and ``/* */`` for block comments
    (which can nest, but we don't handle nesting — conservative: a nested
    comment left partly in is safe, just potentially noisy).
    """
    return re.sub(
        r"//[^\n]*"  # single-line comment
        r"|/\*[\s\S]*?\*/",  # multi-line comment (non-nested)
        " ",
        source,
    )


@lru_cache(maxsize=8192)
def _rs_extract_imports(source: str) -> set[str]:
    """Extract crate names from Rust source using regex on stripped code.

    Handles:
    - ``use crate_name::...``
    - ``use crate_name;`` (re-export of whole crate)
    - ``extern crate crate_name;``
    - ``extern crate crate_name as alias;``
    - Nested use: ``use crate_name::{a, b};``

    Returns the set of top-level crate names (e.g. ``serde``, ``tokio``).
    Skips Rust keywords used as path roots: ``self``, ``super``, ``crate``.
    """
    stripped = _strip_rust_comments(source)
    names: set[str] = set()
    _skip = {"self", "super", "crate", "std", "core", "alloc"}

    # use crate_name::... or use crate_name;
    for m in re.finditer(r"\buse\s+([a-zA-Z_]\w*)", stripped):
        name = m.group(1)
        if name not in _skip:
            names.add(name)

    # extern crate crate_name [as alias];
    for m in re.finditer(r"\bextern\s+crate\s+([a-zA-Z_]\w*)", stripped):
        name = m.group(1)
        if name not in _skip:
            names.add(name)

    return names


def _rs_imports_package(
    files: list[Path], package: str, *, read_text: _TextReader | None = None
) -> bool:
    """Check whether any Rust file imports the given crate.

    Crate names in Cargo.toml use hyphens but Rust source uses underscores,
    so we normalize: ``my-crate`` becomes ``my_crate``.
    """
    crate_name = package.replace("-", "_")
    for f in files:
        try:
            text = _read_text(f) if read_text is None else read_text(f)
        except OSError:
            continue
        imports = _rs_extract_imports(text)
        if crate_name in imports:
            return True
    return False


def _rs_file_imports_package(
    f: Path, package: str, *, read_text: _TextReader | None = None
) -> bool:
    """Check whether a single Rust file imports the given crate."""
    crate_name = package.replace("-", "_")
    try:
        text = _read_text(f) if read_text is None else read_text(f)
    except OSError:
        return False
    return crate_name in _rs_extract_imports(text)


# ---------------------------------------------------------------------------
# Java / Kotlin helpers
# ---------------------------------------------------------------------------


def _strip_java_comments(source: str) -> str:
    """Remove comments from Java/Kotlin source.

    Java and Kotlin both use ``//`` for line comments and ``/* */`` for block
    comments.  Like the Go/Rust strippers this is regex-based and may strip
    ``//`` inside string literals — conservative and safe.
    """
    return re.sub(
        r"//[^\n]*"  # single-line comment
        r"|/\*[\s\S]*?\*/",  # multi-line comment
        " ",
        source,
    )


@lru_cache(maxsize=8192)
def _java_extract_imports(source: str) -> set[str]:
    """Extract package prefixes from Java/Kotlin import statements.

    Handles:
    - ``import com.example.Foo;``         → ``com.example``
    - ``import com.example.*;``           → ``com.example``
    - ``import static com.example.Foo.*;``→ ``com.example``
    - Kotlin: ``import com.example.Foo``  (no semicolon required)

    Returns a set of *group IDs* — the first two or three dot-separated
    segments, which is what Maven/Gradle dependency coordinates look like
    (``groupId:artifactId``).  For example, ``import com.fasterxml.jackson.databind.ObjectMapper``
    yields ``com.fasterxml.jackson``.

    The heuristic: take segments until we hit one that starts with an uppercase
    letter (a class name) or ``*``.  This mirrors Maven convention where package
    segments are lowercase and class names are CamelCase.
    """
    stripped = _strip_java_comments(source)
    packages: set[str] = set()

    for m in re.finditer(
        r"\bimport\s+(?:static\s+)?([a-zA-Z_][\w]*(?:\.[a-zA-Z_][\w]*)*(?:\.\*)?)\s*;?",
        stripped,
    ):
        full_path = m.group(1)  # e.g. "com.fasterxml.jackson.databind.ObjectMapper"
        parts = full_path.split(".")
        # Walk until we hit an uppercase-starting segment (class name) or *
        pkg_parts: list[str] = []
        for part in parts:
            if part == "*" or (part[0].isupper() if part else False):
                break
            pkg_parts.append(part)
        if pkg_parts:
            packages.add(".".join(pkg_parts))

    return packages


def _java_group_id(package: str) -> str:
    """Normalise a Maven/Gradle coordinate to a group ID prefix.

    Scanner output typically uses ``groupId:artifactId`` (e.g.
    ``com.fasterxml.jackson.core:jackson-databind``) or just the group ID.
    We keep only the group ID (before ``:``) for matching.
    """
    return package.split(":")[0]


def _java_imports_package(
    files: list[Path], package: str, *, read_text: _TextReader | None = None
) -> bool:
    """Check whether any Java/Kotlin file imports something from *package*.

    *package* can be a Maven coordinate (``group:artifact``) or a plain
    group ID.  We match when any import's package prefix starts with the
    group ID.
    """
    group = _java_group_id(package)
    for f in files:
        try:
            text = _read_text(f) if read_text is None else read_text(f)
        except OSError:
            continue
        for imp in _java_extract_imports(text):
            if imp == group or imp.startswith(group + "."):
                return True
    return False


def _java_file_imports_package(
    f: Path, package: str, *, read_text: _TextReader | None = None
) -> bool:
    """Check whether a single Java/Kotlin file imports the given package."""
    group = _java_group_id(package)
    try:
        text = _read_text(f) if read_text is None else read_text(f)
    except OSError:
        return False
    return any(imp == group or imp.startswith(group + ".") for imp in _java_extract_imports(text))


# ---------------------------------------------------------------------------
# C# (.cs)
# ---------------------------------------------------------------------------


def _strip_cs_comments(source: str) -> str:
    """Remove ``//`` and ``/* */`` comments from C# source.

    Same strategy as Java/Kotlin — we strip conservatively rather than
    parsing full syntax.  String literals containing ``//`` will also be
    stripped, which is safe (may only add false negatives, never false
    positives).
    """
    text = re.sub(r"/\*.*?\*/", " ", source, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


@lru_cache(maxsize=8192)
def _cs_extract_namespaces(source: str) -> set[str]:
    r"""Return the set of namespace prefixes found in ``using`` directives.

    Handles:
    - ``using System.IO;``
    - ``using static System.Math;``
    - ``using Alias = Full.Namespace;``
    - Global usings: ``global using System.Linq;``

    Returns the *full namespace* from each ``using`` (the part before the
    last ``.``-separated segment if it starts uppercase — matching C#
    convention where the final segment is a type name for ``using static``
    and alias forms).  For plain namespace imports we keep the whole thing.
    """
    stripped = _strip_cs_comments(source)
    namespaces: set[str] = set()

    for m in re.finditer(
        r"\b(?:global\s+)?using\s+(?:static\s+)?"
        r"(?:[A-Za-z_]\w*\s*=\s*)?"
        r"([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*;",
        stripped,
    ):
        full = m.group(1)  # e.g. "Newtonsoft.Json.JsonConvert"
        namespaces.add(full)
        # Also add parent namespace(s) so prefix matching works
        parts = full.split(".")
        for i in range(1, len(parts)):
            namespaces.add(".".join(parts[:i]))

    return namespaces


def _cs_imports_package(
    files: list[Path], package: str, *, read_text: _TextReader | None = None
) -> bool:
    """Check whether any C# file uses a namespace matching *package*.

    NuGet package names typically match the root namespace (e.g. the
    ``Newtonsoft.Json`` package provides ``Newtonsoft.Json.*`` namespaces).
    We match when any using directive's namespace equals or starts with the
    package name.
    """
    for f in files:
        try:
            text = _read_text(f) if read_text is None else read_text(f)
        except OSError:
            continue
        for ns in _cs_extract_namespaces(text):
            if ns == package or ns.startswith(package + "."):
                return True
    return False


def _cs_file_imports_package(
    f: Path, package: str, *, read_text: _TextReader | None = None
) -> bool:
    """Check whether a single C# file uses a namespace matching the package."""
    try:
        text = _read_text(f) if read_text is None else read_text(f)
    except OSError:
        return False
    return any(ns == package or ns.startswith(package + ".") for ns in _cs_extract_namespaces(text))


# ---------------------------------------------------------------------------
# PHP (.php)
# ---------------------------------------------------------------------------


def _strip_php_comments(source: str) -> str:
    """Remove ``//``, ``#`` and ``/* */`` comments from PHP source.

    PHP uses three comment styles: C-style ``/* */``, C++ ``//``, and
    shell-style ``#``.  We strip all three conservatively — string literals
    containing comment tokens are also stripped, which is safe (may only add
    false negatives, never false positives).
    """
    text = re.sub(r"/\*.*?\*/", " ", source, flags=re.DOTALL)
    return re.sub(r"(?://|#)[^\n]*", "", text)


@lru_cache(maxsize=8192)
def _php_extract_uses(source: str) -> set[str]:
    r"""Return Composer-style vendor/package names from PHP ``use`` statements.

    Handles:
    - ``use Vendor\Package\Class;``
    - ``use Vendor\Package\{ClassA, ClassB};`` (group use)
    - ``use function Vendor\Package\func;``
    - ``use const Vendor\Package\CONST;``

    Returns ``vendor/package`` style names (first two namespace segments,
    lowercased, joined with ``/``), which matches Composer package naming
    convention (e.g. ``monolog/monolog``, ``symfony/http-foundation``).
    """
    stripped = _strip_php_comments(source)
    packages: set[str] = set()

    for m in re.finditer(
        r"\buse\s+(?:function\s+|const\s+)?"
        r"([A-Za-z_]\w*(?:\\[A-Za-z_]\w*)*)",
        stripped,
    ):
        full = m.group(1)  # e.g. "Monolog\Logger\Handler"
        parts = full.split("\\")
        if len(parts) >= 2:
            # Composer convention: vendor/package from first two namespace parts
            packages.add(parts[0].lower() + "/" + parts[1].lower())

    return packages


def _php_imports_package(
    files: list[Path], package: str, *, read_text: _TextReader | None = None
) -> bool:
    """Check whether any PHP file uses a namespace matching *package*.

    *package* should be in Composer format (``vendor/package``).  We match
    when any ``use`` statement's first two namespace segments, lowercased
    and joined with ``/``, equal the package name.
    """
    pkg_lower = package.lower()
    for f in files:
        try:
            text = _read_text(f) if read_text is None else read_text(f)
        except OSError:
            continue
        if pkg_lower in _php_extract_uses(text):
            return True
    return False


def _php_file_imports_package(
    f: Path, package: str, *, read_text: _TextReader | None = None
) -> bool:
    """Check whether a single PHP file uses a namespace matching the package."""
    try:
        text = _read_text(f) if read_text is None else read_text(f)
    except OSError:
        return False
    return package.lower() in _php_extract_uses(text)


# ---------------------------------------------------------------------------
# Ruby
# ---------------------------------------------------------------------------


def _strip_rb_comments(source: str) -> str:
    r"""Remove Ruby comments from source (conservative).

    Handles single-line ``#`` comments and multi-line ``=begin``/``=end``
    heredoc-style comments.  Does not track string boundaries — a ``#``
    inside a string is stripped too, which is safe (conservative).
    """
    # Remove =begin...=end blocks (must start at column 0)
    text = re.sub(r"(?m)^=begin\b.*?^=end\b[^\n]*", " ", source, flags=re.DOTALL)
    return re.sub(r"#[^\n]*", "", text)


@lru_cache(maxsize=8192)
def _rb_extract_requires(source: str) -> set[str]:
    r"""Return gem names from Ruby ``require`` / ``require_relative`` statements.

    Handles:
    - ``require 'gem_name'``
    - ``require "gem_name"``
    - ``require "gem_name/sub"`` → extracts ``gem_name``
    - Skips ``require_relative`` (project-internal)

    Returns the top-level gem name (first path segment of the required string).
    Gem names with hyphens stay as-is (e.g., ``require 'aws-sdk-s3'`` → ``aws-sdk-s3``).
    """
    stripped = _strip_rb_comments(source)
    gems: set[str] = set()

    for m in re.finditer(
        r"""\brequire\s+(?!_relative\b)['"]([^'"]+)['"]""",
        stripped,
    ):
        required = m.group(1)  # e.g. "nokogiri" or "aws-sdk-s3/client"
        # Keep the full required path for slash-form matching
        gems.add(required)
        # Top-level gem name is the first path segment
        top = required.split("/")[0]
        if top:
            gems.add(top)

    return gems


def _rb_gem_require_names(gem_name: str) -> set[str]:
    """Return the set of require names a gem might use.

    Most gems: ``require 'gem_name'``.
    Hyphenated gems also try slash form: ``my-gem`` → ``my/gem``.
    This is conservative — we check both variants.
    """
    names = {gem_name}
    if "-" in gem_name:
        # Hyphen convention: activesupport/core_ext for active-support, etc.
        names.add(gem_name.replace("-", "/"))
    return names


def _rb_imports_package(
    files: list[Path], package: str, *, read_text: _TextReader | None = None
) -> bool:
    """Check whether any Ruby file requires *package*.

    Matches when the required string (top-level segment) matches the gem
    name or its hyphen-to-slash variant.
    """
    require_names = _rb_gem_require_names(package)
    for f in files:
        try:
            text = _read_text(f) if read_text is None else read_text(f)
        except OSError:
            continue
        extracted = _rb_extract_requires(text)
        if require_names & extracted:
            return True
    return False


def _rb_file_imports_package(
    f: Path, package: str, *, read_text: _TextReader | None = None
) -> bool:
    """Check whether a single Ruby file requires the package."""
    try:
        text = _read_text(f) if read_text is None else read_text(f)
    except OSError:
        return False
    return bool(_rb_gem_require_names(package) & _rb_extract_requires(text))


# ---------------------------------------------------------------------------
# Swift
# ---------------------------------------------------------------------------


def _strip_swift_comments(source: str) -> str:
    r"""Remove Swift comments from source (conservative).

    Handles single-line ``//`` comments and multi-line ``/* */`` comments.
    Does not track string boundaries — conservative.
    """
    text = re.sub(r"/\*.*?\*/", " ", source, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


@lru_cache(maxsize=8192)
def _swift_extract_imports(source: str) -> set[str]:
    r"""Return module names from Swift ``import`` statements.

    Handles:
    - ``import ModuleName``
    - ``import struct ModuleName.StructName``
    - ``import class ModuleName.ClassName``
    - ``import func ModuleName.funcName``
    - ``@testable import ModuleName``

    Returns the top-level module name (first dot-separated segment).
    """
    stripped = _strip_swift_comments(source)
    modules: set[str] = set()

    for m in re.finditer(
        r"(?:@\w+\s+)*\bimport\s+"
        r"(?:(?:struct|class|enum|protocol|typealias|func|var|let)\s+)?"
        r"([A-Za-z_]\w*)",
        stripped,
    ):
        modules.add(m.group(1))

    return modules


def _swift_module_name(package: str) -> str:
    """Derive the Swift module name from a SwiftPM package name.

    SwiftPM convention: hyphens in package names become underscores in module
    names (e.g., ``swift-argument-parser`` → ``ArgumentParser`` is the actual
    module, but we can't guess CamelCase).  We do the safe transform:
    ``my-pkg`` → ``my_pkg``, and also keep the original.
    """
    return package.replace("-", "_")


def _swift_imports_package(
    files: list[Path], package: str, *, read_text: _TextReader | None = None
) -> bool:
    """Check whether any Swift file imports *package*.

    Matches the package name and its hyphen-to-underscore variant.
    """
    names = {package, _swift_module_name(package)}
    for f in files:
        try:
            text = _read_text(f) if read_text is None else read_text(f)
        except OSError:
            continue
        if names & _swift_extract_imports(text):
            return True
    return False


def _swift_file_imports_package(
    f: Path, package: str, *, read_text: _TextReader | None = None
) -> bool:
    """Check whether a single Swift file imports the package."""
    try:
        text = _read_text(f) if read_text is None else read_text(f)
    except OSError:
        return False
    return bool({package, _swift_module_name(package)} & _swift_extract_imports(text))


# ---------------------------------------------------------------------------
# Dart / Flutter
# ---------------------------------------------------------------------------


def _strip_dart_comments(source: str) -> str:
    r"""Remove Dart comments from source (conservative).

    Handles single-line ``//`` comments and multi-line ``/* */`` comments.
    Does not track string boundaries — conservative.
    """
    text = re.sub(r"/\*.*?\*/", " ", source, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


@lru_cache(maxsize=8192)
def _dart_extract_imports(source: str) -> set[str]:
    r"""Return package names from Dart ``import`` statements.

    Handles:
    - ``import 'package:name/file.dart';``
    - ``import 'package:name/src/sub.dart';``
    - ``import 'dart:core';`` → skipped (SDK library)

    Returns the package name (first path segment after ``package:``).
    Skips ``dart:`` imports (SDK-internal) and relative imports.
    """
    stripped = _strip_dart_comments(source)
    packages: set[str] = set()

    for m in re.finditer(
        r"""\bimport\s+['"]package:([^/'"]+)""",
        stripped,
    ):
        packages.add(m.group(1))

    return packages


def _dart_imports_package(
    files: list[Path], package: str, *, read_text: _TextReader | None = None
) -> bool:
    """Check whether any Dart file imports *package*."""
    # Dart pub packages use underscores; hyphens aren't allowed in package names
    # but some tools may report with hyphens
    names = {package, package.replace("-", "_")}
    for f in files:
        try:
            text = _read_text(f) if read_text is None else read_text(f)
        except OSError:
            continue
        if names & _dart_extract_imports(text):
            return True
    return False


def _dart_file_imports_package(
    f: Path, package: str, *, read_text: _TextReader | None = None
) -> bool:
    """Check whether a single Dart file imports the package."""
    try:
        text = _read_text(f) if read_text is None else read_text(f)
    except OSError:
        return False
    return bool({package, package.replace("-", "_")} & _dart_extract_imports(text))


class ReachabilityFilter:
    """Check whether a vulnerable package/function is imported in the project."""

    reason = FilterReason.UNREACHABLE

    def __init__(self, project: Path, *, exclude_roots: list[Path] | None = None):
        self._project = project
        self._exclude_roots = _SourceScope(project, exclude_roots).excluded
        self._js_files: list[Path] | None = None
        self._py_files: list[Path] | None = None
        self._go_files: list[Path] | None = None
        self._rs_files: list[Path] | None = None
        self._java_files: list[Path] | None = None
        self._cs_files: list[Path] | None = None
        self._php_files: list[Path] | None = None
        self._rb_files: list[Path] | None = None
        self._swift_files: list[Path] | None = None
        self._dart_files: list[Path] | None = None
        self._import_cache: dict[str, bool] = {}
        self._sites_cache: dict[str, list[str]] = {}
        self._words: set[str] | None = None
        self._non_test_words: set[str] | None = None
        self._source_inventory: list[Path] | None = None
        self._included_source_paths: set[Path] = set()
        self._text_by_path: dict[Path, str] = {}
        self._text_errors: dict[Path, OSError] = {}
        self._coverage_errors: dict[tuple[str, Path], str] = {}
        self._scope_errors: dict[Path, str] = {}
        self._dynamic_imports: dict[Path, tuple[DynamicImport, ...]] | None = None

    def _display_path(self, path: Path) -> str:
        try:
            return path.relative_to(self._project).as_posix() or "."
        except ValueError:
            return str(path)

    def _scope_error(self, path: Path, reason: str | OSError) -> None:
        if isinstance(reason, OSError):
            self._record_coverage_error("inspect source metadata", path, reason)
            return
        self._scope_errors[path] = (
            f"Source analysis incomplete: skipped {self._display_path(path)} ({reason})."
        )

    def _mention_scope_error(self, path: Path, reason: str | OSError) -> None:
        if path in self._included_source_paths:
            self._scope_error(path, reason)

    def _record_coverage_error(self, operation: str, path: Path, error: OSError) -> None:
        try:
            display_path = path.relative_to(self._project).as_posix() or "."
        except ValueError:
            display_path = str(path)
        detail = " ".join(str(error).split())
        self._coverage_errors[(operation, path)] = (
            f"Source coverage incomplete: could not {operation} {display_path} "
            f"({type(error).__name__}: {detail})."
        )

    def _enumeration_error(self, error: OSError) -> None:
        path = Path(os.fsdecode(error.filename)) if error.filename else self._project
        self._record_coverage_error("enumerate source directory", path, error)

    def _mention_error(self, operation: str, path: Path, error: OSError) -> None:
        if path in self._included_source_paths:
            self._record_coverage_error(operation, path, error)

    def _read_project_text(self, path: Path) -> str:
        """Snapshot each attempted read once, including failures, for this scan."""
        if path in self._text_by_path:
            return self._text_by_path[path]
        if path in self._text_errors:
            raise self._text_errors[path]
        try:
            text = _read_text(path)
        except OSError as error:
            self._text_errors[path] = error
            if path in self._included_source_paths:
                self._record_coverage_error("read source", path, error)
            raise
        self._text_by_path[path] = text
        return text

    def _ensure_source_inventory(self) -> None:
        if self._source_inventory is not None:
            return
        self._source_inventory = _source_files(
            self._project,
            _ALL_EXTENSIONS,
            onerror=self._enumeration_error,
            exclude_roots=self._exclude_roots,
            on_scope_error=self._scope_error,
        )
        self._included_source_paths = set(self._source_inventory)
        for path in self._source_inventory:
            try:
                self._read_project_text(path)
            except OSError:
                # The failed path is retained in coverage evidence, not imports.
                continue

    def _files_for_extensions(self, extensions: set[str]) -> list[Path]:
        self._ensure_source_inventory()
        assert self._source_inventory is not None
        return [
            path
            for path in self._source_inventory
            if path.suffix in extensions and path not in self._text_errors
        ]

    @property
    def source_coverage_complete(self) -> bool:
        """Whether included source enumeration and reads completed without errors."""
        self._ensure_source_inventory()
        return not self._coverage_errors

    @property
    def source_coverage_observations(self) -> list[str]:
        """Read/enumeration failures, without inventing import sites for them."""
        self._ensure_source_inventory()
        keys = sorted(self._coverage_errors, key=lambda key: (str(key[1]), key[0]))
        return [self._coverage_errors[key] for key in keys]

    def _ensure_dynamic_imports(self) -> None:
        self._ensure_source_inventory()
        if self._dynamic_imports is not None:
            return
        self._dynamic_imports = {}
        for path in self.py_files + self.js_files:
            text = self._text_by_path[path]
            analyzer = (
                python_dynamic_imports if path.suffix in _PY_EXTENSIONS else js_dynamic_imports
            )
            self._dynamic_imports[path] = analyzer(text)

    @property
    def dynamic_import_observations(self) -> list[str]:
        """Recognized static loader calls, with source locations and uncertainty."""
        self._ensure_dynamic_imports()
        assert self._dynamic_imports is not None
        observations: list[str] = []
        for path, imports in sorted(self._dynamic_imports.items(), key=lambda item: str(item[0])):
            for item in imports:
                site = f"{self._display_path(path)}:{item.line}"
                if item.target is None:
                    observations.append(
                        f"Dynamic import unresolved at {site}: {item.loader} ({item.reason})."
                    )
                else:
                    observations.append(
                        f"Dynamic import literal at {site}: {item.loader}({item.target!r}); "
                        "static source observation, not proof of runtime execution."
                    )
        return observations

    @property
    def analysis_coverage_complete(self) -> bool:
        """Whether source coverage and recognized dynamic loaders permit absence claims.

        This does not assert complete parsing or support for arbitrary loader
        aliases/dataflow. Explicit source exclusions define the analysis scope.
        """
        self._ensure_dynamic_imports()
        assert self._dynamic_imports is not None
        return (
            self.source_coverage_complete
            and not self._scope_errors
            and all(
                item.target is not None
                for items in self._dynamic_imports.values()
                for item in items
            )
        )

    @property
    def analysis_coverage_observations(self) -> list[str]:
        """Read/scope failures and unresolved loaders, plus intentional scope exclusions."""
        observations = self.source_coverage_observations
        observations.extend(
            self._scope_errors[path] for path in sorted(self._scope_errors, key=str)
        )
        observations.extend(
            item
            for item in self.dynamic_import_observations
            if item.startswith("Dynamic import unresolved")
        )
        observations.extend(
            f"Source scope excludes {self._display_path(path)}."
            for path in sorted(self._exclude_roots, key=str)
        )
        return observations

    @property
    def js_files(self) -> list[Path]:
        if self._js_files is None:
            self._js_files = self._files_for_extensions(_JS_EXTENSIONS)
        return self._js_files

    @property
    def py_files(self) -> list[Path]:
        if self._py_files is None:
            self._py_files = self._files_for_extensions(_PY_EXTENSIONS)
        return self._py_files

    @property
    def go_files(self) -> list[Path]:
        if self._go_files is None:
            self._go_files = self._files_for_extensions(_GO_EXTENSIONS)
        return self._go_files

    @property
    def rs_files(self) -> list[Path]:
        if self._rs_files is None:
            self._rs_files = self._files_for_extensions(_RS_EXTENSIONS)
        return self._rs_files

    @property
    def java_files(self) -> list[Path]:
        if self._java_files is None:
            self._java_files = self._files_for_extensions(_JAVA_EXTENSIONS)
        return self._java_files

    @property
    def cs_files(self) -> list[Path]:
        if self._cs_files is None:
            self._cs_files = self._files_for_extensions(_CS_EXTENSIONS)
        return self._cs_files

    @property
    def php_files(self) -> list[Path]:
        if self._php_files is None:
            self._php_files = self._files_for_extensions(_PHP_EXTENSIONS)
        return self._php_files

    @property
    def rb_files(self) -> list[Path]:
        if self._rb_files is None:
            self._rb_files = self._files_for_extensions(_RB_EXTENSIONS)
        return self._rb_files

    @property
    def swift_files(self) -> list[Path]:
        if self._swift_files is None:
            self._swift_files = self._files_for_extensions(_SWIFT_EXTENSIONS)
        return self._swift_files

    @property
    def dart_files(self) -> list[Path]:
        if self._dart_files is None:
            self._dart_files = self._files_for_extensions(_DART_EXTENSIONS)
        return self._dart_files

    def check(self, vuln: Vulnerability) -> bool:
        """Return True if no source file imports the package (import-level check).

        This treats the package as if it were a direct dependency. Callers that
        filter on it must use :meth:`decide`, which handles transitive packages.

        Conservative: returns True only when we're confident the package or its
        vulnerable functions are never referenced in source code. Checks both
        JS and Python source files so mixed-language projects work correctly.
        """
        pkg = vuln.package
        if not self.analysis_coverage_complete:
            return False

        # If we know which specific functions are vulnerable, check those
        # across all source files
        if vuln.vulnerable_functions:
            all_files = (
                self.js_files
                + self.py_files
                + self.go_files
                + self.rs_files
                + self.java_files
                + self.cs_files
                + self.php_files
                + self.rb_files
                + self.swift_files
                + self.dart_files
            )
            if not all_files:
                return False
            return all(
                not _file_mentions(all_files, func, read_text=self._read_project_text)
                for func in vuln.vulnerable_functions
            )

        return self._package_unused(pkg)

    def _has_source(self) -> bool:
        return bool(
            self.js_files
            or self.py_files
            or self.go_files
            or self.rs_files
            or self.java_files
            or self.cs_files
            or self.php_files
            or self.rb_files
            or self.swift_files
            or self.dart_files
        )

    def _imports_package(self, pkg: str) -> bool:
        """True if any source file, in any supported language, imports ``pkg``.

        Memoized: transitive decisions ask about the same few direct
        dependencies for every alert, and each check reads every source file.
        """
        if pkg not in self._import_cache:
            self._import_cache[pkg] = self._imports_package_uncached(pkg)
        return self._import_cache[pkg]

    def _imports_package_uncached(self, pkg: str) -> bool:
        checks = (
            (self.js_files, partial(_js_imports_package, read_text=self._read_project_text)),
            (
                self.py_files,
                partial(
                    _py_imports_package, project=self._project, read_text=self._read_project_text
                ),
            ),
            (self.go_files, partial(_go_imports_package, read_text=self._read_project_text)),
            (self.rs_files, partial(_rs_imports_package, read_text=self._read_project_text)),
            (self.java_files, partial(_java_imports_package, read_text=self._read_project_text)),
            (self.cs_files, partial(_cs_imports_package, read_text=self._read_project_text)),
            (self.php_files, partial(_php_imports_package, read_text=self._read_project_text)),
            (self.rb_files, partial(_rb_imports_package, read_text=self._read_project_text)),
            (self.swift_files, partial(_swift_imports_package, read_text=self._read_project_text)),
            (self.dart_files, partial(_dart_imports_package, read_text=self._read_project_text)),
        )
        return any(files and func(files, pkg) for files, func in checks)

    def _mentioned(self, pkg: str) -> bool:
        """True when the package (or a module it provides) is named in project files.

        Only ever used to *keep* an alert: a stray word match makes depquiet
        filter less, never more.
        """
        if self._words is None:
            self._ensure_source_inventory()
            self._words = _mention_words(
                self._project,
                read_text=self._read_project_text,
                onerror=self._enumeration_error,
                on_read_error=self._mention_error,
                exclude_roots=self._exclude_roots,
                on_scope_error=self._mention_scope_error,
            )
        names = {pkg.lower(), pkg.rsplit("/", 1)[-1].lower()}
        names |= import_candidates(pkg, self._project)
        names |= {n.replace("-", "_") for n in names}
        return bool(names & self._words)

    def _package_unused(self, pkg: str) -> bool:
        """True when there is source to inspect and none of it imports ``pkg``."""
        return self._has_source() and not self._imports_package(pkg)

    def is_used(self, package: str, graph: DependencyGraph) -> bool:
        """Whether project imports, commands or configuration name a package."""
        return (
            self._imports_package(package) or graph.is_executed(package) or self._mentioned(package)
        )

    def references_absent(self, names: list[str]) -> bool:
        """Prove names absent from readable source, for template conditions.

        A missing or unreadable source tree supplies no evidence for dismissing
        an alert. Check the final component too: ``lodash.merge`` may be called
        through a namespace alias such as ``_.merge``.
        """
        self._ensure_source_inventory()
        if not self.analysis_coverage_complete:
            return False
        files = self._source_inventory
        if not files or not names:
            return False
        needles = {part for name in names for part in (name, name.rsplit(".", 1)[-1])}
        if "" in needles:
            return False
        for source in files:
            try:
                text = self._read_project_text(source)
            except OSError:
                return False
            if any(name in text for name in needles):
                return False
        return True

    def _mentioned_outside_tests(self, pkg: str) -> bool:
        """Like :meth:`_mentioned`, reading only files that are not test code."""
        if self._non_test_words is None:
            self._ensure_source_inventory()
            self._non_test_words = _mention_words(
                self._project,
                read_text=self._read_project_text,
                onerror=self._enumeration_error,
                on_read_error=self._mention_error,
                exclude_roots=self._exclude_roots,
                on_scope_error=self._mention_scope_error,
                skip_tests=True,
            )
        names = {pkg.lower(), pkg.rsplit("/", 1)[-1].lower()}
        names |= import_candidates(pkg, self._project)
        names |= {n.replace("-", "_") for n in names}
        return bool(names & self._non_test_words)

    def _is_test_site(self, site: str) -> bool:
        try:
            return is_test_path(Path(site).relative_to(self._project))
        except ValueError:
            return False

    def _test_only(self, package: str, used_roots: list[str], graph: DependencyGraph) -> bool:
        """True when the only use of ``package`` that reaches production is in tests.

        Checked for the package and for each used direct dependency that pulls
        it in. Development-only roots are skipped: they never ship. Every
        remaining name must not be run as a project command, must not be named
        in any non-test file, and may be imported only from test files; at
        least one such import must exist. Incomplete coverage proves nothing.
        """
        if not (self.analysis_coverage_complete and getattr(graph, "coverage_complete", True)):
            return False
        names = [package, *(r for r in used_roots if not graph.is_dev_only([r]))]
        found = False
        for name in dict.fromkeys(names):
            if graph.is_executed(name) or self._mentioned_outside_tests(name):
                return False
            sites = self.find_imports_for(name)
            if not all(self._is_test_site(site) for site in sites):
                return False
            found = found or bool(sites)
        return found

    def decide(self, vuln: Vulnerability, graph: DependencyGraph) -> ReachabilityDecision:
        """Reachability verdict that accounts for transitive dependencies.

        - **direct**: unreachable when no source file imports the package (or,
          if the advisory names vulnerable functions, none of them appear).
        - **transitive**: unreachable only when the package itself and every
          direct dependency that pulls it in are unused. Applications can
          import hoisted dependencies even without declaring them directly.
        - **unknown**: no manifest tells us which it is. Never filtered.
        """
        kind = graph.directness(vuln.package)
        if kind == "unknown" and vuln.is_direct is False:
            kind = "transitive"  # the scanner knows (npm audit, Snyk)

        def used(name: str) -> bool:
            return self.is_used(name, graph)

        if kind == "direct":
            # A package can be both direct and transitive: listed in the
            # manifest but unused by the app, while a dependency the app does
            # use calls it. Any imported ancestor keeps it reachable, and so
            # does running it as a command (``pm2 start`` in package.json).
            ancestors = sorted(graph.direct_ancestors(vuln.package))
            imported = [a for a in ancestors if used(a)]
            unreachable = (
                not imported
                and not graph.is_executed(vuln.package)
                and not self._mentioned(vuln.package)
                and self.check(vuln)
                and getattr(graph, "coverage_complete", True)
            )
            return ReachabilityDecision(
                unreachable=unreachable,
                dependency_type="direct",
                introduced_by=ancestors,
                imported_ancestors=imported,
                test_only=not unreachable and self._test_only(vuln.package, imported, graph),
            )

        if kind == "transitive":
            ancestors = sorted(graph.direct_ancestors(vuln.package))
            imported = [a for a in ancestors if used(a)]
            unreachable = (
                bool(ancestors)
                and self._has_source()
                and not imported
                and not used(vuln.package)
                and self.analysis_coverage_complete
                and getattr(graph, "coverage_complete", True)
            )
            return ReachabilityDecision(
                unreachable=unreachable,
                dependency_type="transitive",
                introduced_by=ancestors,
                imported_ancestors=imported,
                test_only=bool(ancestors)
                and not unreachable
                and self._test_only(vuln.package, imported, graph),
            )

        return ReachabilityDecision(unreachable=False, dependency_type="unknown")

    def find_imports(self, vuln: Vulnerability) -> list[str]:
        """Return list of files where the vulnerable package is imported.

        Uses AST for Python files, import-pattern regex for JS/TS, Go, and Rust files.
        """
        return self.find_imports_for(vuln.package)

    def find_imports_for(self, pkg: str) -> list[str]:
        """Files that import the package named ``pkg`` (memoized per scan)."""
        if pkg not in self._sites_cache:
            self._sites_cache[pkg] = self._find_imports_uncached(pkg)
        return list(self._sites_cache[pkg])

    def _find_imports_uncached(self, pkg: str) -> list[str]:
        results: list[str] = []
        # Check JS/TS files by import/require detection
        for f in self.js_files:
            if _js_file_imports_package(f, pkg, read_text=self._read_project_text):
                results.append(str(f))
        # Check Python files by AST-based import detection
        for f in self.py_files:
            if _py_file_imports_package(f, pkg, self._project, read_text=self._read_project_text):
                results.append(str(f))
        # Check Go files by import detection
        for f in self.go_files:
            if _go_file_imports_package(f, pkg, read_text=self._read_project_text):
                results.append(str(f))
        # Check Rust files by import detection
        for f in self.rs_files:
            if _rs_file_imports_package(f, pkg, read_text=self._read_project_text):
                results.append(str(f))
        # Check Java/Kotlin files by import detection
        for f in self.java_files:
            if _java_file_imports_package(f, pkg, read_text=self._read_project_text):
                results.append(str(f))
        # Check C# files by using-directive detection
        for f in self.cs_files:
            if _cs_file_imports_package(f, pkg, read_text=self._read_project_text):
                results.append(str(f))
        # Check PHP files by use-statement detection
        for f in self.php_files:
            if _php_file_imports_package(f, pkg, read_text=self._read_project_text):
                results.append(str(f))
        # Check Ruby files by require detection
        for f in self.rb_files:
            if _rb_file_imports_package(f, pkg, read_text=self._read_project_text):
                results.append(str(f))
        # Check Swift files by import detection
        for f in self.swift_files:
            if _swift_file_imports_package(f, pkg, read_text=self._read_project_text):
                results.append(str(f))
        # Check Dart files by import detection
        for f in self.dart_files:
            if _dart_file_imports_package(f, pkg, read_text=self._read_project_text):
                results.append(str(f))
        return results
