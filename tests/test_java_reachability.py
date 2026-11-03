"""Tests for Java/Kotlin reachability analysis.

Covers:
- Comment stripping for Java/Kotlin source
- Import extraction (standard, static, wildcard, Kotlin)
- Maven group ID matching and coordinate splitting
- Package-level import checking
- ReachabilityFilter integration with Java/Kotlin files
"""

from __future__ import annotations

from pathlib import Path

from depquiet.filters.reachability import (
    ReachabilityFilter,
    _java_extract_imports,
    _java_file_imports_package,
    _java_group_id,
    _java_imports_package,
    _strip_java_comments,
)
from depquiet.models import Severity, Vulnerability

# ---------------------------------------------------------------------------
# _strip_java_comments
# ---------------------------------------------------------------------------


class TestStripJavaComments:
    """Tests for Java/Kotlin comment stripping."""

    def test_single_line_comment(self) -> None:
        src = "import com.example.Foo; // utility class\nclass Bar {}"
        result = _strip_java_comments(src)
        assert "com.example.Foo" in result
        assert "utility class" not in result

    def test_multi_line_comment(self) -> None:
        src = "/* import com.evil.Bad; */\nimport com.example.Foo;"
        result = _strip_java_comments(src)
        assert "com.evil" not in result
        assert "com.example.Foo" in result

    def test_javadoc_comment(self) -> None:
        src = "/** import com.evil.Bad; */\nimport com.example.Foo;"
        result = _strip_java_comments(src)
        assert "com.evil" not in result
        assert "com.example.Foo" in result

    def test_comment_inside_string_stripped_conservative(self) -> None:
        """A // inside a string is stripped — conservative but safe."""
        src = 'String s = "// not a comment";\nimport com.example.Foo;'
        result = _strip_java_comments(src)
        assert "com.example.Foo" in result

    def test_empty_source(self) -> None:
        assert _strip_java_comments("") == ""


# ---------------------------------------------------------------------------
# _java_extract_imports
# ---------------------------------------------------------------------------


class TestJavaExtractImports:
    """Tests for Java/Kotlin import extraction."""

    def test_simple_import(self) -> None:
        src = "package com.myapp;\n\nimport com.fasterxml.jackson.databind.ObjectMapper;\n"
        result = _java_extract_imports(src)
        assert "com.fasterxml.jackson.databind" in result

    def test_wildcard_import(self) -> None:
        src = "import com.fasterxml.jackson.databind.*;\n"
        result = _java_extract_imports(src)
        assert "com.fasterxml.jackson.databind" in result

    def test_static_import(self) -> None:
        src = "import static org.junit.Assert.assertEquals;\n"
        result = _java_extract_imports(src)
        assert "org.junit" in result

    def test_static_wildcard_import(self) -> None:
        src = "import static org.junit.Assert.*;\n"
        result = _java_extract_imports(src)
        assert "org.junit" in result

    def test_multiple_imports(self) -> None:
        src = (
            "import com.fasterxml.jackson.databind.ObjectMapper;\n"
            "import org.apache.commons.lang3.StringUtils;\n"
            "import io.netty.channel.Channel;\n"
        )
        result = _java_extract_imports(src)
        assert "com.fasterxml.jackson.databind" in result
        assert "org.apache.commons.lang3" in result
        assert "io.netty.channel" in result

    def test_kotlin_import_no_semicolon(self) -> None:
        """Kotlin doesn't require semicolons after imports."""
        src = "import com.fasterxml.jackson.databind.ObjectMapper\n"
        result = _java_extract_imports(src)
        assert "com.fasterxml.jackson.databind" in result

    def test_commented_import_ignored(self) -> None:
        src = "// import com.evil.Bad;\nimport com.example.Foo;\n"
        result = _java_extract_imports(src)
        assert "com.evil" not in result
        assert "com.example" in result

    def test_block_commented_import_ignored(self) -> None:
        src = "/* import com.evil.Bad; */\nimport com.example.Foo;\n"
        result = _java_extract_imports(src)
        assert "com.evil" not in result
        assert "com.example" in result

    def test_no_imports(self) -> None:
        src = "package com.myapp;\n\nclass Main {}\n"
        assert _java_extract_imports(src) == set()

    def test_empty_source(self) -> None:
        assert _java_extract_imports("") == set()

    def test_android_import(self) -> None:
        src = "import android.os.Bundle;\nimport android.widget.TextView;\n"
        result = _java_extract_imports(src)
        assert "android.os" in result
        assert "android.widget" in result

    def test_javax_import(self) -> None:
        src = "import javax.servlet.http.HttpServletRequest;\n"
        result = _java_extract_imports(src)
        assert "javax.servlet.http" in result

    def test_deep_package_path(self) -> None:
        """Deep package: segments before the uppercase class name are the package."""
        src = "import com.google.cloud.storage.BlobInfo;\n"
        result = _java_extract_imports(src)
        assert "com.google.cloud.storage" in result


# ---------------------------------------------------------------------------
# _java_group_id
# ---------------------------------------------------------------------------


class TestJavaGroupId:
    """Tests for Maven coordinate splitting."""

    def test_group_artifact(self) -> None:
        coord = "com.fasterxml.jackson.core:jackson-databind"
        assert _java_group_id(coord) == "com.fasterxml.jackson.core"

    def test_plain_group(self) -> None:
        assert _java_group_id("com.fasterxml.jackson.core") == "com.fasterxml.jackson.core"

    def test_org_prefix(self) -> None:
        assert _java_group_id("org.apache.commons:commons-lang3") == "org.apache.commons"

    def test_io_prefix(self) -> None:
        assert _java_group_id("io.netty:netty-all") == "io.netty"


# ---------------------------------------------------------------------------
# _java_imports_package / _java_file_imports_package
# ---------------------------------------------------------------------------


class TestJavaImportsPackage:
    """Tests for Java package import checking."""

    def test_exact_group_match(self, tmp_path: Path) -> None:
        """Maven coordinate: group matches import package prefix."""
        f = tmp_path / "Main.java"
        f.write_text(
            "package com.myapp;\n\nimport org.apache.commons.lang3.StringUtils;\n\nclass Main {}\n"
        )
        assert _java_imports_package([f], "org.apache.commons:commons-lang3")

    def test_subpackage_matches(self, tmp_path: Path) -> None:
        """import com.fasterxml.jackson.databind starts with com.fasterxml.jackson."""
        f = tmp_path / "Main.java"
        f.write_text("import com.fasterxml.jackson.databind.ObjectMapper;\n")
        assert _java_imports_package([f], "com.fasterxml.jackson")

    def test_no_match(self, tmp_path: Path) -> None:
        f = tmp_path / "Main.java"
        f.write_text("import com.example.Foo;\n")
        assert not _java_imports_package([f], "com.fasterxml.jackson")

    def test_commented_import_not_counted(self, tmp_path: Path) -> None:
        f = tmp_path / "Main.java"
        f.write_text("// import com.fasterxml.jackson.databind.ObjectMapper;\n")
        assert not _java_imports_package([f], "com.fasterxml.jackson")

    def test_multiple_files(self, tmp_path: Path) -> None:
        f1 = tmp_path / "Main.java"
        f1.write_text("import com.example.Foo;\n")
        f2 = tmp_path / "Service.java"
        f2.write_text("import com.fasterxml.jackson.databind.ObjectMapper;\n")
        assert _java_imports_package([f1, f2], "com.fasterxml.jackson")

    def test_file_read_error(self, tmp_path: Path) -> None:
        f = tmp_path / "Missing.java"
        assert not _java_imports_package([f], "com.fasterxml.jackson")

    def test_kotlin_file(self, tmp_path: Path) -> None:
        f = tmp_path / "Main.kt"
        f.write_text("import com.fasterxml.jackson.databind.ObjectMapper\n")
        assert _java_imports_package([f], "com.fasterxml.jackson")

    def test_single_file_function(self, tmp_path: Path) -> None:
        f = tmp_path / "Main.java"
        f.write_text("import com.fasterxml.jackson.databind.ObjectMapper;\n")
        assert _java_file_imports_package(f, "com.fasterxml.jackson")

    def test_single_file_no_match(self, tmp_path: Path) -> None:
        f = tmp_path / "Main.java"
        f.write_text("import com.example.Foo;\n")
        assert not _java_file_imports_package(f, "com.fasterxml.jackson")

    def test_single_file_read_error(self, tmp_path: Path) -> None:
        f = tmp_path / "Missing.java"
        assert not _java_file_imports_package(f, "com.fasterxml.jackson")

    def test_prefix_mismatch_no_false_positive(self, tmp_path: Path) -> None:
        """com.example should NOT match com.examplefoo."""
        f = tmp_path / "Main.java"
        f.write_text("import com.examplefoo.Bar;\n")
        assert not _java_imports_package([f], "com.example")


# ---------------------------------------------------------------------------
# ReachabilityFilter integration with Java/Kotlin files
# ---------------------------------------------------------------------------


class TestReachabilityJavaIntegration:
    """Test ReachabilityFilter with Java/Kotlin projects."""

    def test_java_package_imported_not_filtered(self, tmp_path: Path) -> None:
        f = tmp_path / "Main.java"
        f.write_text(
            "package com.myapp;\nimport org.apache.commons.lang3.StringUtils;\nclass Main {}\n"
        )
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="org.apache.commons:commons-lang3",
            version="3.12.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is False  # NOT unreachable

    def test_java_package_not_imported_filtered(self, tmp_path: Path) -> None:
        f = tmp_path / "Main.java"
        f.write_text("package com.myapp;\nimport com.example.Foo;\nclass Main {}\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="org.apache.commons:commons-lang3",
            version="3.12.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is True  # unreachable

    def test_kotlin_file_detected(self, tmp_path: Path) -> None:
        f = tmp_path / "Main.kt"
        f.write_text("import com.fasterxml.jackson.databind.ObjectMapper\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="com.fasterxml.jackson",
            version="2.15.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is False

    def test_java_find_imports(self, tmp_path: Path) -> None:
        f = tmp_path / "Main.java"
        f.write_text("import com.fasterxml.jackson.databind.ObjectMapper;\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="com.fasterxml.jackson",
            version="2.15.0",
            severity=Severity.HIGH,
        )
        result = rf.find_imports(vuln)
        assert len(result) == 1
        assert result[0].endswith("Main.java")

    def test_empty_java_project_no_filter(self, tmp_path: Path) -> None:
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="com.fasterxml.jackson",
            version="2.15.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is False

    def test_java_build_dir_skipped(self, tmp_path: Path) -> None:
        """Files under build/ should be skipped."""
        build = tmp_path / "build" / "classes"
        build.mkdir(parents=True)
        (build / "Main.java").write_text("import com.fasterxml.jackson.databind.ObjectMapper;\n")
        f = tmp_path / "src" / "Main.java"
        f.parent.mkdir()
        f.write_text("import com.example.Foo;\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="com.fasterxml.jackson",
            version="2.15.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is True  # build/ import doesn't count

    def test_mixed_java_and_python(self, tmp_path: Path) -> None:
        java_file = tmp_path / "Main.java"
        java_file.write_text("import com.fasterxml.jackson.databind.ObjectMapper;\n")
        py_file = tmp_path / "app.py"
        py_file.write_text("import os\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="com.fasterxml.jackson",
            version="2.15.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is False  # Java file imports it

    def test_java_vulnerable_functions(self, tmp_path: Path) -> None:
        f = tmp_path / "Main.java"
        f.write_text(
            "import com.fasterxml.jackson.databind.ObjectMapper;\n"
            "class Main {\n"
            "  void run() { new ObjectMapper().readValue(json, Map.class); }\n"
            "}\n"
        )
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="com.fasterxml.jackson",
            version="2.15.0",
            severity=Severity.HIGH,
            vulnerable_functions=["readValue"],
        )
        assert rf.check(vuln) is False  # function is referenced

    def test_java_vulnerable_functions_not_present(self, tmp_path: Path) -> None:
        f = tmp_path / "Main.java"
        f.write_text(
            "import com.fasterxml.jackson.databind.ObjectMapper;\n"
            "class Main {\n"
            "  void run() { new ObjectMapper().writeValueAsString(obj); }\n"
            "}\n"
        )
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="com.fasterxml.jackson",
            version="2.15.0",
            severity=Severity.HIGH,
            vulnerable_functions=["readValue"],
        )
        assert rf.check(vuln) is True  # readValue not referenced

    def test_java_files_lazy_loaded(self, tmp_path: Path) -> None:
        rf = ReachabilityFilter(tmp_path)
        assert rf._java_files is None
        _ = rf.java_files
        assert rf._java_files is not None
