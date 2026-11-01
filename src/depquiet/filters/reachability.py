"""Filter: is the vulnerable function actually imported/used?

This is the highest-value filter. 60-80% of CVEs flagged by scanners affect
functions that the project never calls. A prototype pollution in lodash.merge()
doesn't matter if you only use lodash.get().

Strategy (v1 — grep-based, conservative):
1. Check if the vulnerable PACKAGE is imported anywhere in the source code.
2. If vulnerable_functions are known, check if any of those specific functions
   appear in the source.
3. Only mark as unreachable if we're confident the package/function isn't used.

Conservative by design: we'd rather let a false positive through than dismiss
a real vulnerability. grep misses dynamic imports and re-exports, so we only
filter when we see ZERO references.
"""

from __future__ import annotations

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


def _py_imports_package(files: list[Path], package: str) -> bool:
    """Check whether any Python file imports the given package.

    Looks for:
      - import <pkg>
      - import <pkg>.submodule
      - from <pkg> import ...
      - from <pkg>.submodule import ...
      - __import__('<pkg>')  /  __import__("<pkg>")

    The top-level package name is extracted (e.g. "Pillow" is imported as
    "PIL", but most PyPI names match their import name). We normalise
    hyphens to underscores because that's the pip convention.
    """
    # PyPI packages often use hyphens but Python imports use underscores
    import_name = package.replace("-", "_")
    esc = re.escape(import_name)
    pattern = re.compile(
        # 'import pkg' or 'import pkg.sub' at start of line (possibly after
        # other imports separated by commas: 'import os, pkg, sys')
        rf"(?:^|\n)\s*import\s+(?:\w+\s*,\s*)*{esc}(?:\s|,|\.|\)|$)"
        r"|"
        # 'from pkg import ...' or 'from pkg.sub import ...'
        rf"(?:^|\n)\s*from\s+{esc}(?:\s|\.)"
        r"|"
        # __import__('pkg') or __import__("pkg") — can appear anywhere
        rf"__import__\(\s*['\"]" + esc + r"['\"]",
        re.MULTILINE,
    )
    for f in files:
        try:
            text = f.read_text(errors="replace")
            if pattern.search(text):
                return True
        except OSError:
            continue
    return False


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

        # Check JS files for package name (require/import patterns)
        if self.js_files and _file_mentions(self.js_files, pkg):
            return False

        # Check Python files for actual import statements
        if self.py_files and _py_imports_package(self.py_files, pkg):
            return False

        # Only filter if we had files to check
        return bool(self.js_files or self.py_files)

    def find_imports(self, vuln: Vulnerability) -> list[str]:
        """Return list of files where the vulnerable package is imported.

        Used for the ACTION output — showing the dev WHERE the risk is.
        """
        results: list[str] = []
        pkg = vuln.package
        # Check JS files by name mention
        results.extend(_file_mentions(self.js_files, pkg))
        # Check Python files by import pattern
        import_name = pkg.replace("-", "_")
        esc = re.escape(import_name)
        pattern = re.compile(
            rf"(?:^|\n)\s*import\s+(?:\w+\s*,\s*)*{esc}(?:\s|,|\.|\)|$)"
            rf"|(?:^|\n)\s*from\s+{esc}(?:\s|\.)"
            rf"|__import__\(\s*['\"]" + esc + r"['\"]",
            re.MULTILINE,
        )
        for f in self.py_files:
            try:
                text = f.read_text(errors="replace")
                if pattern.search(text):
                    results.append(str(f))
            except OSError:
                continue
        return results
