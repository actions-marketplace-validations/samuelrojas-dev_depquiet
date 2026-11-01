"""Tests for the improved reachability filter — Python import detection."""

from __future__ import annotations

import tempfile
from pathlib import Path

from depquiet.filters.reachability import (
    ReachabilityFilter,
    _py_imports_package,
)
from depquiet.models import Severity, Vulnerability


def _vuln(package: str = "requests", **kw) -> Vulnerability:  # type: ignore[no-untyped-def]
    return Vulnerability(
        cve="CVE-2023-0001",
        package=package,
        version="1.0.0",
        severity=Severity.HIGH,
        **kw,
    )


# ── _py_imports_package unit tests ───────────────────────────────────


class TestPyImportsPackage:
    """Unit tests for the Python import pattern matcher."""

    def _check(self, code: str, package: str = "requests") -> bool:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "app.py"
            p.write_text(code)
            return _py_imports_package([p], package)

    def test_import_statement(self) -> None:
        assert self._check("import requests\n") is True

    def test_from_import(self) -> None:
        assert self._check("from requests import get\n") is True

    def test_from_submodule_import(self) -> None:
        assert self._check("from requests.auth import HTTPBasicAuth\n") is True

    def test_import_submodule(self) -> None:
        assert self._check("import requests.sessions\n") is True

    def test_import_with_alias(self) -> None:
        assert self._check("import requests as req\n") is True

    def test_dunder_import(self) -> None:
        assert self._check("mod = __import__('requests')\n") is True

    def test_dunder_import_double_quotes(self) -> None:
        assert self._check('mod = __import__("requests")\n') is True

    def test_no_match_substring(self) -> None:
        """'requests' inside another word should NOT match."""
        assert self._check("# we handle HTTP requests here\n") is False

    def test_no_match_different_package(self) -> None:
        assert self._check("import flask\n") is False

    def test_no_match_comment_only(self) -> None:
        assert self._check("# import requests\n") is False

    def test_hyphenated_package(self) -> None:
        """PyPI packages with hyphens import with underscores."""
        assert self._check("import my_package\n", "my-package") is True

    def test_hyphenated_from_import(self) -> None:
        assert self._check("from my_package import foo\n", "my-package") is True

    def test_multiple_imports_on_line(self) -> None:
        assert self._check("import os, requests, sys\n") is True

    def test_empty_file(self) -> None:
        assert self._check("") is False

    def test_multiline_from_import(self) -> None:
        code = "from requests import (\n    get,\n    post,\n)\n"
        assert self._check(code) is True


# ── ReachabilityFilter with Python files ─────────────────────────────


class TestReachabilityPython:
    """Test the filter's check() method with Python source files."""

    def test_python_import_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "app.py").write_text("import requests\n")
            rf = ReachabilityFilter(project)
            assert rf.check(_vuln("requests")) is False  # reachable

    def test_python_not_imported_unreachable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "app.py").write_text("import flask\n")
            rf = ReachabilityFilter(project)
            assert rf.check(_vuln("requests")) is True  # unreachable

    def test_mixed_project_js_package(self) -> None:
        """In a mixed project, a JS package found in JS files is reachable."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "app.js").write_text("const _ = require('lodash');\n")
            (project / "util.py").write_text("import os\n")
            rf = ReachabilityFilter(project)
            assert rf.check(_vuln("lodash")) is False  # reachable via JS

    def test_mixed_project_py_package(self) -> None:
        """In a mixed project, a Python package found in .py files is reachable."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "app.js").write_text("console.log('hello');\n")
            (project / "util.py").write_text("import requests\n")
            rf = ReachabilityFilter(project)
            assert rf.check(_vuln("requests")) is False  # reachable via Python

    def test_mixed_project_neither(self) -> None:
        """Package not found in either JS or Python — unreachable."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "app.js").write_text("console.log('hello');\n")
            (project / "util.py").write_text("import flask\n")
            rf = ReachabilityFilter(project)
            assert rf.check(_vuln("requests")) is True  # unreachable

    def test_no_source_files(self) -> None:
        """No source files at all — can't determine, don't filter."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "README.md").write_text("# hello\n")
            rf = ReachabilityFilter(project)
            assert rf.check(_vuln("requests")) is False

    def test_find_imports_python(self) -> None:
        """find_imports returns Python files that import the package."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "a.py").write_text("import requests\n")
            (project / "b.py").write_text("import flask\n")
            rf = ReachabilityFilter(project)
            imports = rf.find_imports(_vuln("requests"))
            assert len(imports) == 1
            assert "a.py" in imports[0]

    def test_find_imports_mixed(self) -> None:
        """find_imports returns both JS and Python files."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "a.js").write_text("const x = require('lodash');\n")
            (project / "b.py").write_text("import lodash\n")
            rf = ReachabilityFilter(project)
            imports = rf.find_imports(_vuln("lodash"))
            assert len(imports) == 2

    def test_vulnerable_functions_across_ecosystems(self) -> None:
        """vulnerable_functions check searches all file types."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "app.py").write_text("from lodash import merge\n")
            rf = ReachabilityFilter(project)
            v = _vuln("lodash", vulnerable_functions=["merge"])
            assert rf.check(v) is False  # function found
