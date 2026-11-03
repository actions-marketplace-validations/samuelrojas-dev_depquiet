"""Tests for Dart/Flutter reachability analysis.

Covers:
- Comment stripping for Dart source
- Import extraction (package: imports, dart: skipped, relative skipped)
- Pub.dev package name matching
- ReachabilityFilter integration with Dart files
"""

from __future__ import annotations

from pathlib import Path

from depquiet.filters.reachability import (
    ReachabilityFilter,
    _dart_extract_imports,
    _dart_file_imports_package,
    _dart_imports_package,
    _strip_dart_comments,
)
from depquiet.models import Severity, Vulnerability

# ---------------------------------------------------------------------------
# _strip_dart_comments
# ---------------------------------------------------------------------------


class TestStripDartComments:
    """Tests for Dart comment stripping."""

    def test_single_line_comment(self) -> None:
        src = "import 'package:http/http.dart'; // HTTP client\nclass Foo {}"
        result = _strip_dart_comments(src)
        assert "http" in result
        assert "HTTP client" not in result

    def test_multi_line_comment(self) -> None:
        src = "/* import 'package:evil/evil.dart'; */\nimport 'package:http/http.dart';"
        result = _strip_dart_comments(src)
        assert "evil" not in result
        assert "http" in result

    def test_doc_comment(self) -> None:
        """/// doc comments are line comments and should be stripped."""
        src = "/// import 'package:evil/evil.dart';\nimport 'package:http/http.dart';"
        result = _strip_dart_comments(src)
        assert "evil" not in result
        assert "http" in result

    def test_empty_source(self) -> None:
        assert _strip_dart_comments("") == ""

    def test_no_comments(self) -> None:
        src = "import 'package:http/http.dart';\nclass Foo {}"
        result = _strip_dart_comments(src)
        assert "http" in result


# ---------------------------------------------------------------------------
# _dart_extract_imports
# ---------------------------------------------------------------------------


class TestDartExtractImports:
    """Tests for Dart import extraction."""

    def test_simple_package_import(self) -> None:
        src = "import 'package:http/http.dart';\n"
        result = _dart_extract_imports(src)
        assert "http" in result

    def test_double_quote_import(self) -> None:
        src = 'import "package:http/http.dart";\n'
        result = _dart_extract_imports(src)
        assert "http" in result

    def test_subpath_import(self) -> None:
        src = "import 'package:http/src/response.dart';\n"
        result = _dart_extract_imports(src)
        assert "http" in result

    def test_multiple_imports(self) -> None:
        src = (
            "import 'package:http/http.dart';\n"
            "import 'package:provider/provider.dart';\n"
            "import 'package:flutter_bloc/flutter_bloc.dart';\n"
        )
        result = _dart_extract_imports(src)
        assert "http" in result
        assert "provider" in result
        assert "flutter_bloc" in result

    def test_dart_sdk_import_skipped(self) -> None:
        """dart: imports are SDK-internal — not pub packages."""
        src = "import 'dart:core';\nimport 'dart:async';\nimport 'package:http/http.dart';\n"
        result = _dart_extract_imports(src)
        assert "core" not in result
        assert "async" not in result
        assert "http" in result

    def test_relative_import_skipped(self) -> None:
        """Relative imports are project-internal."""
        src = "import 'src/helper.dart';\nimport 'package:http/http.dart';\n"
        result = _dart_extract_imports(src)
        assert "src" not in result
        assert "http" in result

    def test_commented_import_ignored(self) -> None:
        src = "// import 'package:evil/evil.dart';\nimport 'package:http/http.dart';\n"
        result = _dart_extract_imports(src)
        assert "evil" not in result
        assert "http" in result

    def test_block_commented_import_ignored(self) -> None:
        src = "/* import 'package:evil/evil.dart'; */\nimport 'package:http/http.dart';\n"
        result = _dart_extract_imports(src)
        assert "evil" not in result
        assert "http" in result

    def test_no_imports(self) -> None:
        src = "class Main {}\n"
        assert _dart_extract_imports(src) == set()

    def test_empty_source(self) -> None:
        assert _dart_extract_imports("") == set()

    def test_underscore_package_name(self) -> None:
        src = "import 'package:flutter_bloc/flutter_bloc.dart';\n"
        result = _dart_extract_imports(src)
        assert "flutter_bloc" in result


# ---------------------------------------------------------------------------
# _dart_imports_package / _dart_file_imports_package
# ---------------------------------------------------------------------------


class TestDartImportsPackage:
    """Tests for Dart package import checking."""

    def test_exact_match(self, tmp_path: Path) -> None:
        f = tmp_path / "main.dart"
        f.write_text("import 'package:http/http.dart';\n")
        assert _dart_imports_package([f], "http")

    def test_no_match(self, tmp_path: Path) -> None:
        f = tmp_path / "main.dart"
        f.write_text("import 'package:http/http.dart';\n")
        assert not _dart_imports_package([f], "provider")

    def test_hyphen_to_underscore(self, tmp_path: Path) -> None:
        """Some tools report with hyphens; Dart uses underscores."""
        f = tmp_path / "main.dart"
        f.write_text("import 'package:flutter_bloc/flutter_bloc.dart';\n")
        assert _dart_imports_package([f], "flutter-bloc")

    def test_commented_import_not_counted(self, tmp_path: Path) -> None:
        f = tmp_path / "main.dart"
        f.write_text("// import 'package:http/http.dart';\n")
        assert not _dart_imports_package([f], "http")

    def test_multiple_files(self, tmp_path: Path) -> None:
        f1 = tmp_path / "main.dart"
        f1.write_text("import 'dart:core';\n")
        f2 = tmp_path / "network.dart"
        f2.write_text("import 'package:http/http.dart';\n")
        assert _dart_imports_package([f1, f2], "http")

    def test_file_read_error(self, tmp_path: Path) -> None:
        f = tmp_path / "missing.dart"
        assert not _dart_imports_package([f], "http")

    def test_single_file_function(self, tmp_path: Path) -> None:
        f = tmp_path / "main.dart"
        f.write_text("import 'package:http/http.dart';\n")
        assert _dart_file_imports_package(f, "http")

    def test_single_file_no_match(self, tmp_path: Path) -> None:
        f = tmp_path / "main.dart"
        f.write_text("import 'package:provider/provider.dart';\n")
        assert not _dart_file_imports_package(f, "http")

    def test_single_file_read_error(self, tmp_path: Path) -> None:
        f = tmp_path / "missing.dart"
        assert not _dart_file_imports_package(f, "http")


# ---------------------------------------------------------------------------
# ReachabilityFilter integration with Dart files
# ---------------------------------------------------------------------------


class TestReachabilityDartIntegration:
    """Test ReachabilityFilter with Dart/Flutter projects."""

    def test_dart_package_imported_not_filtered(self, tmp_path: Path) -> None:
        f = tmp_path / "main.dart"
        f.write_text("import 'package:http/http.dart';\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="http",
            version="0.13.6",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is False  # NOT unreachable

    def test_dart_package_not_imported_filtered(self, tmp_path: Path) -> None:
        f = tmp_path / "main.dart"
        f.write_text("import 'package:provider/provider.dart';\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="http",
            version="0.13.6",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is True  # unreachable

    def test_dart_find_imports(self, tmp_path: Path) -> None:
        f = tmp_path / "main.dart"
        f.write_text("import 'package:http/http.dart';\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="http",
            version="0.13.6",
            severity=Severity.HIGH,
        )
        result = rf.find_imports(vuln)
        assert len(result) == 1
        assert result[0].endswith("main.dart")

    def test_empty_dart_project_no_filter(self, tmp_path: Path) -> None:
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="http",
            version="0.13.6",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is False

    def test_dart_build_dir_skipped(self, tmp_path: Path) -> None:
        """Files under .dart_tool/ should be skipped."""
        tool_dir = tmp_path / ".dart_tool" / "package_config"
        tool_dir.mkdir(parents=True)
        (tool_dir / "http.dart").write_text("import 'package:http/http.dart';\n")
        f = tmp_path / "lib" / "main.dart"
        f.parent.mkdir()
        f.write_text("import 'package:provider/provider.dart';\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="http",
            version="0.13.6",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is True  # .dart_tool/ import doesn't count

    def test_dart_vulnerable_functions(self, tmp_path: Path) -> None:
        f = tmp_path / "main.dart"
        f.write_text(
            "import 'package:http/http.dart';\nfinal response = await http.get(Uri.parse(url));\n"
        )
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="http",
            version="0.13.6",
            severity=Severity.HIGH,
            vulnerable_functions=["get"],
        )
        assert rf.check(vuln) is False  # function is referenced

    def test_dart_vulnerable_functions_not_present(self, tmp_path: Path) -> None:
        f = tmp_path / "main.dart"
        f.write_text(
            "import 'package:http/http.dart';\nfinal response = await http.post(Uri.parse(url));\n"
        )
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="http",
            version="0.13.6",
            severity=Severity.HIGH,
            vulnerable_functions=["get"],
        )
        assert rf.check(vuln) is True  # get not referenced

    def test_dart_files_lazy_loaded(self, tmp_path: Path) -> None:
        rf = ReachabilityFilter(tmp_path)
        assert rf._dart_files is None
        _ = rf.dart_files
        assert rf._dart_files is not None

    def test_dart_hyphen_package_match(self, tmp_path: Path) -> None:
        """Hyphenated package names match underscore form."""
        f = tmp_path / "main.dart"
        f.write_text("import 'package:flutter_bloc/flutter_bloc.dart';\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="flutter-bloc",
            version="8.0.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is False  # matched via hyphen convention
