"""Tests for the reachability filter — AST-based Python import detection."""

from __future__ import annotations

import tempfile
from pathlib import Path

from depquiet.filters.reachability import (
    ReachabilityFilter,
    _ast_imports,
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


# ── _ast_imports unit tests ──────────────────────────────────────────


class TestAstImports:
    """Unit tests for the AST-based import extractor."""

    def test_import_simple(self) -> None:
        assert "requests" in _ast_imports("import requests\n")

    def test_import_submodule(self) -> None:
        """'import requests.sessions' → top-level is 'requests'."""
        assert "requests" in _ast_imports("import requests.sessions\n")

    def test_from_import(self) -> None:
        assert "requests" in _ast_imports("from requests import get\n")

    def test_from_submodule_import(self) -> None:
        assert "requests" in _ast_imports("from requests.auth import HTTPBasicAuth\n")

    def test_import_with_alias(self) -> None:
        assert "requests" in _ast_imports("import requests as req\n")

    def test_from_import_with_alias(self) -> None:
        assert "requests" in _ast_imports("from requests import get as http_get\n")

    def test_dunder_import(self) -> None:
        assert "requests" in _ast_imports("mod = __import__('requests')\n")

    def test_dunder_import_double_quotes(self) -> None:
        assert "requests" in _ast_imports('mod = __import__("requests")\n')

    def test_dunder_import_submodule(self) -> None:
        """__import__('requests.auth') → top-level is 'requests'."""
        assert "requests" in _ast_imports("mod = __import__('requests.auth')\n")

    def test_multiple_imports(self) -> None:
        imports = _ast_imports("import os, requests, sys\n")
        assert "os" in imports
        assert "requests" in imports
        assert "sys" in imports

    def test_multiple_from_imports(self) -> None:
        code = "from requests import get, post, put\n"
        assert "requests" in _ast_imports(code)

    def test_multiline_from_import(self) -> None:
        code = "from requests import (\n    get,\n    post,\n)\n"
        assert "requests" in _ast_imports(code)

    def test_no_imports(self) -> None:
        assert _ast_imports("x = 1\n") == set()

    def test_empty_string(self) -> None:
        assert _ast_imports("") == set()

    def test_syntax_error_returns_none(self) -> None:
        """Unparseable code returns None (triggers regex fallback)."""
        assert _ast_imports("def broken(\n") is None

    def test_comment_import_ignored(self) -> None:
        """'# import requests' should NOT appear in imports."""
        assert "requests" not in _ast_imports("# import requests\n")

    def test_string_import_ignored(self) -> None:
        """'import requests' inside a string should NOT appear."""
        assert "requests" not in _ast_imports('x = "import requests"\n')

    def test_docstring_import_ignored(self) -> None:
        """Import inside a docstring should NOT appear."""
        code = '"""Example:\nimport requests\nrequests.get("url")\n"""\nimport os\n'
        imports = _ast_imports(code)
        assert "os" in imports
        assert "requests" not in imports

    def test_multiline_string_import_ignored(self) -> None:
        """Package name inside a multiline string should NOT appear."""
        code = "description = '''\nThis uses requests for HTTP.\n'''\n"
        assert "requests" not in _ast_imports(code)

    def test_variable_name_ignored(self) -> None:
        """A variable named like a package should NOT appear."""
        assert "requests" not in _ast_imports("requests_count = 5\n")

    def test_function_call_ignored(self) -> None:
        """A function call is not an import."""
        assert "requests" not in _ast_imports("print(requests)\n")

    def test_relative_import_excluded(self) -> None:
        """Relative imports (from . import x) have no top-level module."""
        imports = _ast_imports("from . import utils\n")
        # node.module is None for 'from . import ...'
        assert "utils" not in imports

    def test_star_import(self) -> None:
        """from requests import * should detect requests."""
        assert "requests" in _ast_imports("from requests import *\n")

    def test_conditional_import(self) -> None:
        """Import inside try/except should still be detected."""
        code = "try:\n    import requests\nexcept ImportError:\n    pass\n"
        assert "requests" in _ast_imports(code)

    def test_function_scoped_import(self) -> None:
        """Import inside a function should still be detected."""
        code = "def fetch():\n    import requests\n    return requests.get('url')\n"
        assert "requests" in _ast_imports(code)


# ── _py_imports_package unit tests ───────────────────────────────────


class TestPyImportsPackage:
    """Unit tests for the AST-based Python import checker."""

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
        """'requests' inside prose should NOT match (AST ignores it)."""
        assert self._check("# we handle HTTP requests here\n") is False

    def test_no_match_in_string(self) -> None:
        """'requests' inside a string literal should NOT match."""
        assert self._check('log = "uses requests library"\n') is False

    def test_no_match_in_docstring(self) -> None:
        """'import requests' in a docstring should NOT match."""
        code = '"""Usage:\nimport requests\nrequests.get("url")\n"""\nx = 1\n'
        assert self._check(code) is False

    def test_no_match_variable_name(self) -> None:
        """Variable named 'requests_total' should NOT match."""
        assert self._check("requests_total = 42\n") is False

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

    def test_syntax_error_falls_back_to_regex(self) -> None:
        """Files with syntax errors should use regex fallback."""
        # This is valid Python 2 but not 3 — AST will fail, regex catches it
        code = "import requests\nprint 'hello'\n"
        assert self._check(code) is True

    def test_conditional_import(self) -> None:
        code = "try:\n    import requests\nexcept ImportError:\n    requests = None\n"
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

    def test_comment_import_not_reachable(self) -> None:
        """A commented-out import should NOT count as reachable (AST advantage)."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "app.py").write_text("# import requests\nimport flask\n")
            rf = ReachabilityFilter(project)
            assert rf.check(_vuln("requests")) is True  # unreachable

    def test_string_mention_not_reachable(self) -> None:
        """Package name in a string should NOT count as reachable."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "app.py").write_text('description = "uses requests"\nimport flask\n')
            rf = ReachabilityFilter(project)
            assert rf.check(_vuln("requests")) is True  # unreachable

    def test_docstring_mention_not_reachable(self) -> None:
        """Package name in a docstring should NOT count as reachable."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            code = '"""Uses requests for HTTP."""\nimport flask\n'
            (project / "app.py").write_text(code)
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

    def test_find_imports_ignores_comments(self) -> None:
        """find_imports should NOT return files with only commented imports."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "a.py").write_text("# import requests\n")
            (project / "b.py").write_text("import requests\n")
            rf = ReachabilityFilter(project)
            imports = rf.find_imports(_vuln("requests"))
            assert len(imports) == 1
            assert "b.py" in imports[0]

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

    def test_find_imports_syntax_error_fallback(self) -> None:
        """find_imports uses regex fallback for files with syntax errors."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            # Valid import but invalid Python 3 syntax → AST fails, regex works
            (project / "legacy.py").write_text("import requests\nprint 'hi'\n")
            rf = ReachabilityFilter(project)
            imports = rf.find_imports(_vuln("requests"))
            assert len(imports) == 1
            assert "legacy.py" in imports[0]
