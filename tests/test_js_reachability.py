"""Tests for JS/TS AST-based import detection in the reachability filter."""

from __future__ import annotations

import tempfile
from pathlib import Path

from depquiet.filters.reachability import (
    ReachabilityFilter,
    _js_extract_imports,
    _js_imports_package,
    _js_package_name,
    _strip_js_comments,
    _strip_js_comments_and_strings,
)
from depquiet.models import Severity, Vulnerability


def _vuln(package: str = "lodash", **kw) -> Vulnerability:  # type: ignore[no-untyped-def]
    return Vulnerability(
        cve="CVE-2023-0001",
        package=package,
        version="1.0.0",
        severity=Severity.HIGH,
        **kw,
    )


# ── _strip_js_comments_and_strings ─────────────────────────────────


class TestStripJsCommentsAndStrings:
    """Verify comment/string removal before import matching."""

    def test_single_line_comment(self) -> None:
        result = _strip_js_comments_and_strings("// import lodash\n")
        assert "lodash" not in result

    def test_multi_line_comment(self) -> None:
        result = _strip_js_comments_and_strings("/* import lodash */\n")
        assert "lodash" not in result

    def test_multi_line_comment_spanning(self) -> None:
        result = _strip_js_comments_and_strings("/*\nimport lodash\n*/\n")
        assert "lodash" not in result

    def test_double_quoted_string(self) -> None:
        result = _strip_js_comments_and_strings('const x = "import lodash";\n')
        assert "lodash" not in result

    def test_single_quoted_string(self) -> None:
        result = _strip_js_comments_and_strings("const x = 'import lodash';\n")
        assert "lodash" not in result

    def test_template_literal(self) -> None:
        result = _strip_js_comments_and_strings("const x = `import lodash`;\n")
        assert "lodash" not in result

    def test_escaped_quote_in_string(self) -> None:
        result = _strip_js_comments_and_strings(r"const x = 'it\'s lodash';")
        assert "lodash" not in result

    def test_real_import_preserved(self) -> None:
        result = _strip_js_comments_and_strings("import lodash from 'lodash';\n")
        # 'lodash' after from is in a string → stripped, but the 'import lodash' remains
        assert "import" in result

    def test_code_after_comment_preserved(self) -> None:
        code = "// comment\nimport x from 'y';\n"
        result = _strip_js_comments_and_strings(code)
        assert "import" in result


# ── _strip_js_comments ────────────────────────────────────────────


class TestStripJsComments:
    """Verify comment-only stripping preserves strings."""

    def test_single_line_comment_stripped(self) -> None:
        result = _strip_js_comments("// import lodash\n")
        assert "lodash" not in result

    def test_multi_line_comment_stripped(self) -> None:
        result = _strip_js_comments("/* import lodash */\n")
        assert "lodash" not in result

    def test_string_preserved(self) -> None:
        result = _strip_js_comments("import x from 'lodash';\n")
        assert "'lodash'" in result

    def test_double_quoted_string_preserved(self) -> None:
        result = _strip_js_comments('import x from "lodash";\n')
        assert '"lodash"' in result

    def test_template_literal_preserved(self) -> None:
        result = _strip_js_comments("const x = `hello ${name}`;\n")
        assert "`hello ${name}`" in result


# ── _js_package_name ───────────────────────────────────────────────


class TestJsPackageName:
    """Verify extraction of package root from JS import specifiers."""

    def test_simple(self) -> None:
        assert _js_package_name("lodash") == "lodash"

    def test_subpath(self) -> None:
        assert _js_package_name("lodash/merge") == "lodash"

    def test_scoped(self) -> None:
        assert _js_package_name("@babel/core") == "@babel/core"

    def test_scoped_subpath(self) -> None:
        assert _js_package_name("@babel/core/lib/parser") == "@babel/core"

    def test_scoped_no_name(self) -> None:
        assert _js_package_name("@babel") == "@babel"

    def test_relative(self) -> None:
        assert _js_package_name("./utils") == "./utils"

    def test_relative_parent(self) -> None:
        assert _js_package_name("../lib/helper") == "../lib/helper"

    def test_absolute(self) -> None:
        assert _js_package_name("/root/path") == "/root/path"


# ── _js_extract_imports ───────────────────────────────────────────


class TestJsExtractImports:
    """Unit tests for the JS/TS import extractor."""

    # ── ESM import ──

    def test_esm_default_import(self) -> None:
        assert "lodash" in _js_extract_imports("import lodash from 'lodash';\n")

    def test_esm_named_import(self) -> None:
        assert "lodash" in _js_extract_imports("import { merge } from 'lodash';\n")

    def test_esm_named_import_double_quotes(self) -> None:
        assert "lodash" in _js_extract_imports('import { merge } from "lodash";\n')

    def test_esm_namespace_import(self) -> None:
        assert "lodash" in _js_extract_imports("import * as _ from 'lodash';\n")

    def test_esm_side_effect_import(self) -> None:
        assert "lodash" in _js_extract_imports("import 'lodash';\n")

    def test_esm_side_effect_double_quotes(self) -> None:
        assert "lodash" in _js_extract_imports('import "lodash";\n')

    def test_esm_default_and_named(self) -> None:
        code = "import lodash, { merge } from 'lodash';\n"
        assert "lodash" in _js_extract_imports(code)

    def test_esm_multiline_named(self) -> None:
        code = "import {\n  merge,\n  get,\n} from 'lodash';\n"
        assert "lodash" in _js_extract_imports(code)

    def test_esm_subpath(self) -> None:
        """import merge from 'lodash/merge' → package is 'lodash'."""
        assert "lodash" in _js_extract_imports("import merge from 'lodash/merge';\n")

    def test_esm_scoped_package(self) -> None:
        code = "import { parse } from '@babel/core';\n"
        assert "@babel/core" in _js_extract_imports(code)

    def test_esm_scoped_subpath(self) -> None:
        code = "import x from '@babel/core/lib/parser';\n"
        assert "@babel/core" in _js_extract_imports(code)

    # ── CommonJS require ──

    def test_require_single_quotes(self) -> None:
        assert "lodash" in _js_extract_imports("const _ = require('lodash');\n")

    def test_require_double_quotes(self) -> None:
        assert "lodash" in _js_extract_imports('const _ = require("lodash");\n')

    def test_require_destructured(self) -> None:
        code = "const { merge } = require('lodash');\n"
        assert "lodash" in _js_extract_imports(code)

    def test_require_no_assignment(self) -> None:
        assert "lodash" in _js_extract_imports("require('lodash');\n")

    def test_require_subpath(self) -> None:
        code = "const merge = require('lodash/merge');\n"
        assert "lodash" in _js_extract_imports(code)

    def test_require_scoped(self) -> None:
        code = "const core = require('@babel/core');\n"
        assert "@babel/core" in _js_extract_imports(code)

    # ── Dynamic import ──

    def test_dynamic_import(self) -> None:
        assert "lodash" in _js_extract_imports("const _ = await import('lodash');\n")

    def test_dynamic_import_double_quotes(self) -> None:
        assert "lodash" in _js_extract_imports('import("lodash").then(m => m);\n')

    def test_dynamic_import_scoped(self) -> None:
        code = "const x = await import('@scope/pkg');\n"
        assert "@scope/pkg" in _js_extract_imports(code)

    # ── Re-exports ──

    def test_reexport_named(self) -> None:
        code = "export { merge } from 'lodash';\n"
        assert "lodash" in _js_extract_imports(code)

    def test_reexport_star(self) -> None:
        code = "export * from 'lodash';\n"
        assert "lodash" in _js_extract_imports(code)

    def test_reexport_star_as(self) -> None:
        code = "export * as _ from 'lodash';\n"
        assert "lodash" in _js_extract_imports(code)

    def test_reexport_default(self) -> None:
        code = "export { default } from 'lodash';\n"
        assert "lodash" in _js_extract_imports(code)

    # ── False positive rejection ──

    def test_comment_import_ignored(self) -> None:
        code = "// import lodash from 'lodash';\nconst x = 1;\n"
        assert "lodash" not in _js_extract_imports(code)

    def test_multiline_comment_import_ignored(self) -> None:
        code = "/* import lodash from 'lodash'; */\nconst x = 1;\n"
        assert "lodash" not in _js_extract_imports(code)

    def test_string_require_is_not_a_loader_call(self) -> None:
        """A loader expression quoted as data supplies no import site."""
        code = "const x = \"require('lodash')\";\n"
        assert "lodash" not in _js_extract_imports(code)

    def test_template_literal_import_matches_conservatively(self) -> None:
        """A full import in a template literal matches — conservative (safe)."""
        code = "const x = `import lodash from 'lodash'`;\n"
        assert "lodash" in _js_extract_imports(code)

    def test_bare_string_mention_not_matched(self) -> None:
        """A package name in a string WITHOUT import syntax does NOT match."""
        code = "const desc = 'uses lodash for utility';\n"
        assert "lodash" not in _js_extract_imports(code)

    def test_comment_require_ignored(self) -> None:
        code = "// const _ = require('lodash');\n"
        assert "lodash" not in _js_extract_imports(code)

    def test_relative_import_not_a_package(self) -> None:
        code = "import utils from './utils';\n"
        imports = _js_extract_imports(code)
        assert "utils" not in imports
        assert "./utils" in imports  # stored but won't match any package

    def test_no_imports(self) -> None:
        assert _js_extract_imports("const x = 1;\n") == set()

    def test_empty_string(self) -> None:
        assert _js_extract_imports("") == set()

    def test_multiple_imports(self) -> None:
        code = (
            "import lodash from 'lodash';\n"
            "import express from 'express';\n"
            "const axios = require('axios');\n"
        )
        imports = _js_extract_imports(code)
        assert "lodash" in imports
        assert "express" in imports
        assert "axios" in imports

    def test_typescript_import(self) -> None:
        """TS type imports are still imports — the package must be installed."""
        code = "import type { Config } from 'lodash';\n"
        assert "lodash" in _js_extract_imports(code)

    def test_mjs_cjs_patterns(self) -> None:
        """Both ESM and CJS patterns in the same file."""
        code = "import lodash from 'lodash';\nconst express = require('express');\n"
        imports = _js_extract_imports(code)
        assert "lodash" in imports
        assert "express" in imports


# ── _js_imports_package ────────────────────────────────────────────


class TestJsImportsPackage:
    """Integration tests for JS/TS import detection across files."""

    def _check(self, code: str, package: str = "lodash", ext: str = ".js") -> bool:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / f"app{ext}"
            p.write_text(code)
            return _js_imports_package([p], package)

    def test_esm_import(self) -> None:
        assert self._check("import lodash from 'lodash';\n") is True

    def test_require(self) -> None:
        assert self._check("const _ = require('lodash');\n") is True

    def test_not_imported(self) -> None:
        assert self._check("const x = 1;\n") is False

    def test_comment_only(self) -> None:
        assert self._check("// import lodash from 'lodash';\n") is False

    def test_string_mention_only(self) -> None:
        assert self._check("const desc = 'uses lodash for utility';\n") is False

    def test_tsx_file(self) -> None:
        code = "import { merge } from 'lodash';\nconst App = () => <div/>;\n"
        assert self._check(code, ext=".tsx") is True

    def test_ts_file(self) -> None:
        code = "import type { Config } from 'lodash';\n"
        assert self._check(code, ext=".ts") is True

    def test_mjs_file(self) -> None:
        code = "import lodash from 'lodash';\n"
        assert self._check(code, ext=".mjs") is True

    def test_cjs_file(self) -> None:
        code = "const _ = require('lodash');\n"
        assert self._check(code, ext=".cjs") is True

    def test_scoped_package(self) -> None:
        code = "import { parse } from '@babel/core';\n"
        assert self._check(code, package="@babel/core") is True

    def test_scoped_not_imported(self) -> None:
        code = "import lodash from 'lodash';\n"
        assert self._check(code, package="@babel/core") is False

    def test_unreadable_file(self) -> None:
        """Unreadable files are silently skipped (conservative)."""
        nonexistent = Path("/nonexistent/app.js")
        assert _js_imports_package([nonexistent], "lodash") is False

    def test_unreadable_single_file(self) -> None:
        """_js_file_imports_package returns False for unreadable files."""
        from depquiet.filters.reachability import _js_file_imports_package

        nonexistent = Path("/nonexistent/app.js")
        assert _js_file_imports_package(nonexistent, "lodash") is False


# ── ReachabilityFilter with JS/TS files ────────────────────────────


class TestReachabilityJsTs:
    """Test the filter's check() and find_imports() with JS/TS source files."""

    def test_js_import_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "app.js").write_text("import lodash from 'lodash';\n")
            rf = ReachabilityFilter(project)
            assert rf.check(_vuln("lodash")) is False  # reachable

    def test_js_require_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "app.js").write_text("const _ = require('lodash');\n")
            rf = ReachabilityFilter(project)
            assert rf.check(_vuln("lodash")) is False  # reachable

    def test_js_not_imported_unreachable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "app.js").write_text("import express from 'express';\n")
            rf = ReachabilityFilter(project)
            assert rf.check(_vuln("lodash")) is True  # unreachable

    def test_js_comment_import_not_reachable(self) -> None:
        """A commented-out import should NOT count as reachable."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            code = "// import lodash from 'lodash';\nimport express from 'express';\n"
            (project / "app.js").write_text(code)
            rf = ReachabilityFilter(project)
            assert rf.check(_vuln("lodash")) is True  # unreachable

    def test_js_string_mention_not_reachable(self) -> None:
        """Package name in a string should NOT count as reachable."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            code = "const desc = 'uses lodash';\nimport express from 'express';\n"
            (project / "app.js").write_text(code)
            rf = ReachabilityFilter(project)
            assert rf.check(_vuln("lodash")) is True  # unreachable

    def test_ts_import_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "app.ts").write_text("import { merge } from 'lodash';\n")
            rf = ReachabilityFilter(project)
            assert rf.check(_vuln("lodash")) is False  # reachable

    def test_tsx_import_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "App.tsx").write_text(
                "import React from 'react';\nimport { merge } from 'lodash';\n"
            )
            rf = ReachabilityFilter(project)
            assert rf.check(_vuln("lodash")) is False  # reachable

    def test_dynamic_import_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "app.js").write_text("const _ = await import('lodash');\n")
            rf = ReachabilityFilter(project)
            assert rf.check(_vuln("lodash")) is False  # reachable

    def test_reexport_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "index.js").write_text("export * from 'lodash';\n")
            rf = ReachabilityFilter(project)
            assert rf.check(_vuln("lodash")) is False  # reachable

    def test_scoped_package_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "app.ts").write_text("import { parse } from '@babel/core';\n")
            rf = ReachabilityFilter(project)
            assert rf.check(_vuln("@babel/core")) is False  # reachable

    def test_find_imports_js(self) -> None:
        """find_imports returns JS files that import the package."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "a.js").write_text("import lodash from 'lodash';\n")
            (project / "b.js").write_text("import express from 'express';\n")
            rf = ReachabilityFilter(project)
            imports = rf.find_imports(_vuln("lodash"))
            assert len(imports) == 1
            assert "a.js" in imports[0]

    def test_find_imports_ignores_comments_js(self) -> None:
        """find_imports should NOT return files with only commented imports."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "a.js").write_text("// import lodash from 'lodash';\n")
            (project / "b.js").write_text("import lodash from 'lodash';\n")
            rf = ReachabilityFilter(project)
            imports = rf.find_imports(_vuln("lodash"))
            assert len(imports) == 1
            assert "b.js" in imports[0]

    def test_mixed_project_js_ast_and_py_ast(self) -> None:
        """Both JS and Python use AST-based detection in mixed projects."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "app.js").write_text("// const _ = require('lodash');\n")
            (project / "util.py").write_text("# import lodash\nx = 1\n")
            rf = ReachabilityFilter(project)
            # Both are commented out — should be unreachable
            assert rf.check(_vuln("lodash")) is True

    def test_mixed_project_js_real_import(self) -> None:
        """Real JS import makes package reachable even with no Python import."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "app.js").write_text("const _ = require('lodash');\n")
            (project / "util.py").write_text("import os\n")
            rf = ReachabilityFilter(project)
            assert rf.check(_vuln("lodash")) is False  # reachable via JS

    def test_find_imports_mixed_uses_ast_for_both(self) -> None:
        """find_imports uses AST for both JS and Python."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "a.js").write_text("// require('lodash');\n")
            (project / "b.js").write_text("const _ = require('lodash');\n")
            (project / "c.py").write_text("# import lodash\n")
            rf = ReachabilityFilter(project)
            imports = rf.find_imports(_vuln("lodash"))
            # Only b.js should match — a.js is commented, c.py is commented
            assert len(imports) == 1
            assert "b.js" in imports[0]
