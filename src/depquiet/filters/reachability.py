"""Filter: is the vulnerable function actually imported/used?

This is the highest-value filter. 60-80% of CVEs flagged by scanners affect
functions that the project never calls. A prototype pollution in lodash.merge()
doesn't matter if you only use lodash.get().

Strategy (v3 — AST-based for Python AND JS/TS, conservative):
1. Python files are parsed with ``ast`` to extract real import statements,
   ignoring comments, strings, and partial-name matches that trip up regex.
2. JS/TS files are parsed with a comment/string-stripping regex pipeline
   followed by import/require/export pattern matching — catches ESM imports,
   CommonJS require(), dynamic import(), and re-exports while ignoring
   package names that only appear inside comments or string literals.
3. If vulnerable_functions are known, check if any of those specific functions
   appear in the source (string search — conservative).
4. Only mark as unreachable if we're confident the package/function isn't used.

Conservative by design: we'd rather let a false positive through than dismiss
a real vulnerability. Files that fail to parse are treated as *possibly*
importing the package (safe fallback).
"""

from __future__ import annotations

import ast
import os
import re
from pathlib import Path

from depquiet.models import FilterReason, Vulnerability

# File extensions to search for imports
_JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
_PY_EXTENSIONS = {".py"}
_ALL_EXTENSIONS = _JS_EXTENSIONS | _PY_EXTENSIONS

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
}


def _source_files(project: Path, extensions: set[str]) -> list[Path]:
    """Walk project tree and collect source files, skipping vendored dirs."""
    files: list[Path] = []
    for root, dirs, filenames in os.walk(project):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for f in filenames:
            p = Path(root) / f
            if p.suffix in extensions:
                files.append(p)
    return files


def _file_mentions(files: list[Path], pattern: str) -> list[str]:
    """Return file paths where pattern appears (case-sensitive)."""
    matches: list[str] = []
    regex = re.compile(re.escape(pattern))
    for f in files:
        try:
            text = f.read_text(errors="replace")
            if regex.search(text):
                matches.append(str(f))
        except OSError:
            continue
    return matches


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
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                # 'from foo.bar import baz' → top-level is 'foo'
                names.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            # __import__('foo')
            func = node.func
            if (
                isinstance(func, ast.Name)
                and func.id == "__import__"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                names.add(node.args[0].value.split(".")[0])
    return names


def _py_imports_package(files: list[Path], package: str) -> bool:
    """Check whether any Python file imports the given package using AST.

    Uses ``ast.parse()`` for proper import detection — immune to false
    positives from comments, docstrings, and partial name matches.

    Falls back to regex for files that fail to parse (encoding issues,
    syntax errors in Python 2 files, etc.) — conservative: if we can't
    parse it, we check with regex so we don't accidentally filter a real
    import.
    """
    # PyPI packages often use hyphens but Python imports use underscores
    import_name = package.replace("-", "_")

    for f in files:
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue

        imports = _ast_imports(text)
        if imports is None:
            # AST parse failed — fall back to regex (conservative: don't
            # miss a real import in a file we can't parse).
            if _regex_py_imports(text, import_name):
                return True
        else:
            # AST parsed successfully — trust the extracted import set
            if import_name in imports:
                return True
    return False


def _regex_py_imports(text: str, import_name: str) -> bool:
    """Regex fallback for Python import detection (used when AST fails)."""
    esc = re.escape(import_name)
    pattern = re.compile(
        rf"(?:^|\n)\s*import\s+(?:\w+\s*,\s*)*{esc}(?:\s|,|\.|\)|$)"
        r"|"
        rf"(?:^|\n)\s*from\s+{esc}(?:\s|\.)"
        r"|"
        rf"__import__\(\s*['\"]" + esc + r"['\"]",
        re.MULTILINE,
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

    # CommonJS require: require('pkg') or require("pkg")
    for m in re.finditer(r"""\brequire\s*\(\s*["']([^"']+)["']\s*\)""", stripped):
        names.add(_js_package_name(m.group(1)))

    # Dynamic import: import('pkg')
    for m in re.finditer(r"""\bimport\s*\(\s*["']([^"']+)["']\s*\)""", stripped):
        names.add(_js_package_name(m.group(1)))

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


def _js_imports_package(files: list[Path], package: str) -> bool:
    """Check whether any JS/TS file imports the given package.

    Uses comment/string stripping + regex for proper import detection —
    immune to false positives from package names in comments or strings.
    """
    for f in files:
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        imports = _js_extract_imports(text)
        if package in imports:
            return True
    return False


def _js_file_imports_package(f: Path, package: str) -> bool:
    """Check whether a single JS/TS file imports the given package."""
    try:
        text = f.read_text(errors="replace")
    except OSError:
        return False
    return package in _js_extract_imports(text)


def _py_file_imports_package(f: Path, package: str) -> bool:
    """Check whether a single Python file imports the given package."""
    import_name = package.replace("-", "_")
    try:
        text = f.read_text(errors="replace")
    except OSError:
        return False

    imports = _ast_imports(text)
    if imports is None:
        # AST parse failed — fall back to regex
        return _regex_py_imports(text, import_name)
    return import_name in imports


class ReachabilityFilter:
    """Check whether a vulnerable package/function is imported in the project."""

    reason = FilterReason.UNREACHABLE

    def __init__(self, project: Path):
        self._project = project
        self._js_files: list[Path] | None = None
        self._py_files: list[Path] | None = None

    @property
    def js_files(self) -> list[Path]:
        if self._js_files is None:
            self._js_files = _source_files(self._project, _JS_EXTENSIONS)
        return self._js_files

    @property
    def py_files(self) -> list[Path]:
        if self._py_files is None:
            self._py_files = _source_files(self._project, _PY_EXTENSIONS)
        return self._py_files

    def check(self, vuln: Vulnerability) -> bool:
        """Return True if the vulnerable code is unreachable (safe to filter).

        Conservative: returns True only when we're confident the package or its
        vulnerable functions are never referenced in source code. Checks both
        JS and Python source files so mixed-language projects work correctly.
        """
        pkg = vuln.package

        # If we know which specific functions are vulnerable, check those
        # across all source files
        if vuln.vulnerable_functions:
            all_files = self.js_files + self.py_files
            if not all_files:
                return False
            return all(not _file_mentions(all_files, func) for func in vuln.vulnerable_functions)

        # Check JS/TS files for actual import/require statements
        if self.js_files and _js_imports_package(self.js_files, pkg):
            return False

        # Check Python files for actual import statements (AST-based)
        if self.py_files and _py_imports_package(self.py_files, pkg):
            return False

        # Only filter if we had files to check
        return bool(self.js_files or self.py_files)

    def find_imports(self, vuln: Vulnerability) -> list[str]:
        """Return list of files where the vulnerable package is imported.

        Uses AST for Python files, string matching for JS files.
        """
        results: list[str] = []
        pkg = vuln.package
        # Check JS/TS files by import/require detection
        for f in self.js_files:
            if _js_file_imports_package(f, pkg):
                results.append(str(f))
        # Check Python files by AST-based import detection
        for f in self.py_files:
            if _py_file_imports_package(f, pkg):
                results.append(str(f))
        return results
