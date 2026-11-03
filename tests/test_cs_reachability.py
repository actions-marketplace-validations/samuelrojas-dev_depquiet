"""Tests for C# reachability analysis.

Covers:
- Comment stripping for C# source
- Namespace extraction from using directives (standard, static, alias, global)
- NuGet package namespace matching
- ReachabilityFilter integration with C# files
"""

from __future__ import annotations

from pathlib import Path

from depquiet.filters.reachability import (
    ReachabilityFilter,
    _cs_extract_namespaces,
    _cs_file_imports_package,
    _cs_imports_package,
    _strip_cs_comments,
)
from depquiet.models import Severity, Vulnerability

# ---------------------------------------------------------------------------
# _strip_cs_comments
# ---------------------------------------------------------------------------


class TestStripCsComments:
    """Tests for C# comment stripping."""

    def test_single_line_comment(self) -> None:
        src = "using System.IO; // file operations\nclass Foo {}"
        result = _strip_cs_comments(src)
        assert "System.IO" in result
        assert "file operations" not in result

    def test_multi_line_comment(self) -> None:
        src = "/* using Evil.Namespace; */\nusing System.IO;"
        result = _strip_cs_comments(src)
        assert "Evil" not in result
        assert "System.IO" in result

    def test_xml_doc_comment(self) -> None:
        """/// XML doc comments are line comments and should be stripped."""
        src = "/// using Evil.Namespace;\nusing System.IO;"
        result = _strip_cs_comments(src)
        assert "Evil" not in result
        assert "System.IO" in result

    def test_comment_inside_string_stripped_conservative(self) -> None:
        """A // inside a string is stripped — conservative but safe."""
        src = 'string s = "// not a comment";\nusing System.IO;'
        result = _strip_cs_comments(src)
        assert "System.IO" in result

    def test_empty_source(self) -> None:
        assert _strip_cs_comments("") == ""


# ---------------------------------------------------------------------------
# _cs_extract_namespaces
# ---------------------------------------------------------------------------


class TestCsExtractNamespaces:
    """Tests for C# using directive extraction."""

    def test_simple_using(self) -> None:
        src = "using Newtonsoft.Json;\nclass Foo {}"
        result = _cs_extract_namespaces(src)
        assert "Newtonsoft.Json" in result
        assert "Newtonsoft" in result

    def test_using_with_subnamespace(self) -> None:
        src = "using Newtonsoft.Json.Linq;\n"
        result = _cs_extract_namespaces(src)
        assert "Newtonsoft.Json.Linq" in result
        assert "Newtonsoft.Json" in result
        assert "Newtonsoft" in result

    def test_static_using(self) -> None:
        src = "using static System.Math;\n"
        result = _cs_extract_namespaces(src)
        assert "System.Math" in result
        assert "System" in result

    def test_alias_using(self) -> None:
        src = "using Json = Newtonsoft.Json.JsonConvert;\n"
        result = _cs_extract_namespaces(src)
        assert "Newtonsoft.Json.JsonConvert" in result
        assert "Newtonsoft.Json" in result

    def test_global_using(self) -> None:
        src = "global using System.Linq;\n"
        result = _cs_extract_namespaces(src)
        assert "System.Linq" in result
        assert "System" in result

    def test_global_static_using(self) -> None:
        src = "global using static System.Console;\n"
        result = _cs_extract_namespaces(src)
        assert "System.Console" in result

    def test_multiple_usings(self) -> None:
        src = (
            "using System;\n"
            "using System.IO;\n"
            "using Newtonsoft.Json;\n"
            "using Microsoft.Extensions.Logging;\n"
        )
        result = _cs_extract_namespaces(src)
        assert "System" in result
        assert "System.IO" in result
        assert "Newtonsoft.Json" in result
        assert "Microsoft.Extensions.Logging" in result

    def test_commented_using_ignored(self) -> None:
        src = "// using Evil.Namespace;\nusing System;\n"
        result = _cs_extract_namespaces(src)
        assert "Evil" not in result
        assert "System" in result

    def test_block_commented_using_ignored(self) -> None:
        src = "/* using Evil.Namespace; */\nusing System;\n"
        result = _cs_extract_namespaces(src)
        assert "Evil" not in result
        assert "System" in result

    def test_no_usings(self) -> None:
        src = "namespace MyApp;\nclass Program {}\n"
        assert _cs_extract_namespaces(src) == set()

    def test_empty_source(self) -> None:
        assert _cs_extract_namespaces("") == set()

    def test_single_segment_namespace(self) -> None:
        src = "using Dapper;\n"
        result = _cs_extract_namespaces(src)
        assert "Dapper" in result


# ---------------------------------------------------------------------------
# _cs_imports_package / _cs_file_imports_package
# ---------------------------------------------------------------------------


class TestCsImportsPackage:
    """Tests for C# package import checking."""

    def test_exact_match(self, tmp_path: Path) -> None:
        f = tmp_path / "Program.cs"
        f.write_text("using Newtonsoft.Json;\nclass Program {}\n")
        assert _cs_imports_package([f], "Newtonsoft.Json")

    def test_subnamespace_matches(self, tmp_path: Path) -> None:
        """using Newtonsoft.Json.Linq matches Newtonsoft.Json."""
        f = tmp_path / "Program.cs"
        f.write_text("using Newtonsoft.Json.Linq;\n")
        assert _cs_imports_package([f], "Newtonsoft.Json")

    def test_root_namespace_matches(self, tmp_path: Path) -> None:
        """using Newtonsoft.Json matches Newtonsoft."""
        f = tmp_path / "Program.cs"
        f.write_text("using Newtonsoft.Json;\n")
        assert _cs_imports_package([f], "Newtonsoft")

    def test_no_match(self, tmp_path: Path) -> None:
        f = tmp_path / "Program.cs"
        f.write_text("using System;\n")
        assert not _cs_imports_package([f], "Newtonsoft.Json")

    def test_commented_using_not_counted(self, tmp_path: Path) -> None:
        f = tmp_path / "Program.cs"
        f.write_text("// using Newtonsoft.Json;\n")
        assert not _cs_imports_package([f], "Newtonsoft.Json")

    def test_multiple_files(self, tmp_path: Path) -> None:
        f1 = tmp_path / "Program.cs"
        f1.write_text("using System;\n")
        f2 = tmp_path / "Service.cs"
        f2.write_text("using Newtonsoft.Json;\n")
        assert _cs_imports_package([f1, f2], "Newtonsoft.Json")

    def test_file_read_error(self, tmp_path: Path) -> None:
        f = tmp_path / "Missing.cs"
        assert not _cs_imports_package([f], "Newtonsoft.Json")

    def test_single_file_function(self, tmp_path: Path) -> None:
        f = tmp_path / "Program.cs"
        f.write_text("using Newtonsoft.Json;\n")
        assert _cs_file_imports_package(f, "Newtonsoft.Json")

    def test_single_file_no_match(self, tmp_path: Path) -> None:
        f = tmp_path / "Program.cs"
        f.write_text("using System;\n")
        assert not _cs_file_imports_package(f, "Newtonsoft.Json")

    def test_single_file_read_error(self, tmp_path: Path) -> None:
        f = tmp_path / "Missing.cs"
        assert not _cs_file_imports_package(f, "Newtonsoft.Json")

    def test_prefix_mismatch_no_false_positive(self, tmp_path: Path) -> None:
        """Newtonsoft should NOT match NewtonsoftExtra."""
        f = tmp_path / "Program.cs"
        f.write_text("using NewtonsoftExtra.Json;\n")
        assert not _cs_imports_package([f], "Newtonsoft")


# ---------------------------------------------------------------------------
# ReachabilityFilter integration with C# files
# ---------------------------------------------------------------------------


class TestReachabilityCsIntegration:
    """Test ReachabilityFilter with C# projects."""

    def test_cs_package_imported_not_filtered(self, tmp_path: Path) -> None:
        f = tmp_path / "Program.cs"
        f.write_text("using Newtonsoft.Json;\nclass Program { static void Main() {} }\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="Newtonsoft.Json",
            version="13.0.1",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is False  # NOT unreachable

    def test_cs_package_not_imported_filtered(self, tmp_path: Path) -> None:
        f = tmp_path / "Program.cs"
        f.write_text("using System;\nclass Program {}\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="Newtonsoft.Json",
            version="13.0.1",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is True  # unreachable

    def test_cs_find_imports(self, tmp_path: Path) -> None:
        f = tmp_path / "Program.cs"
        f.write_text("using Newtonsoft.Json;\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="Newtonsoft.Json",
            version="13.0.1",
            severity=Severity.HIGH,
        )
        result = rf.find_imports(vuln)
        assert len(result) == 1
        assert result[0].endswith("Program.cs")

    def test_empty_cs_project_no_filter(self, tmp_path: Path) -> None:
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="Newtonsoft.Json",
            version="13.0.1",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is False

    def test_cs_build_dir_skipped(self, tmp_path: Path) -> None:
        """Files under build/ should be skipped."""
        build = tmp_path / "build" / "Debug"
        build.mkdir(parents=True)
        (build / "Program.cs").write_text("using Newtonsoft.Json;\n")
        f = tmp_path / "src" / "Program.cs"
        f.parent.mkdir()
        f.write_text("using System;\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="Newtonsoft.Json",
            version="13.0.1",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is True  # build/ using doesn't count

    def test_mixed_cs_and_python(self, tmp_path: Path) -> None:
        cs_file = tmp_path / "Program.cs"
        cs_file.write_text("using Newtonsoft.Json;\n")
        py_file = tmp_path / "app.py"
        py_file.write_text("import os\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="Newtonsoft.Json",
            version="13.0.1",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is False  # C# file uses it

    def test_cs_vulnerable_functions(self, tmp_path: Path) -> None:
        f = tmp_path / "Program.cs"
        f.write_text(
            "using Newtonsoft.Json;\n"
            "class Program {\n"
            "  void Run() { JsonConvert.DeserializeObject(json); }\n"
            "}\n"
        )
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="Newtonsoft.Json",
            version="13.0.1",
            severity=Severity.HIGH,
            vulnerable_functions=["DeserializeObject"],
        )
        assert rf.check(vuln) is False  # function is referenced

    def test_cs_vulnerable_functions_not_present(self, tmp_path: Path) -> None:
        f = tmp_path / "Program.cs"
        f.write_text(
            "using Newtonsoft.Json;\n"
            "class Program {\n"
            "  void Run() { JsonConvert.SerializeObject(obj); }\n"
            "}\n"
        )
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="Newtonsoft.Json",
            version="13.0.1",
            severity=Severity.HIGH,
            vulnerable_functions=["DeserializeObject"],
        )
        assert rf.check(vuln) is True  # DeserializeObject not referenced

    def test_cs_files_lazy_loaded(self, tmp_path: Path) -> None:
        rf = ReachabilityFilter(tmp_path)
        assert rf._cs_files is None
        _ = rf.cs_files
        assert rf._cs_files is not None
