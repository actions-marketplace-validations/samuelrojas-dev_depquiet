"""Tests for Swift reachability analysis.

Covers:
- Comment stripping for Swift source
- Import extraction (import, @testable import, kind imports)
- SwiftPM package-to-module name mapping (hyphen-to-underscore)
- ReachabilityFilter integration with Swift files
"""

from __future__ import annotations

from pathlib import Path

from depquiet.filters.reachability import (
    ReachabilityFilter,
    _strip_swift_comments,
    _swift_extract_imports,
    _swift_file_imports_package,
    _swift_imports_package,
    _swift_module_name,
)
from depquiet.models import Severity, Vulnerability

# ---------------------------------------------------------------------------
# _strip_swift_comments
# ---------------------------------------------------------------------------


class TestStripSwiftComments:
    """Tests for Swift comment stripping."""

    def test_single_line_comment(self) -> None:
        src = "import Foundation // standard lib\nclass Foo {}"
        result = _strip_swift_comments(src)
        assert "Foundation" in result
        assert "standard lib" not in result

    def test_multi_line_comment(self) -> None:
        src = "/* import Evil */\nimport Foundation"
        result = _strip_swift_comments(src)
        assert "Evil" not in result
        assert "Foundation" in result

    def test_nested_style_comment(self) -> None:
        """Multi-line comments — conservative, outer pair removed."""
        src = "/* outer /* inner */ still comment */\nimport Foundation"
        result = _strip_swift_comments(src)
        assert "Foundation" in result

    def test_empty_source(self) -> None:
        assert _strip_swift_comments("") == ""

    def test_no_comments(self) -> None:
        src = "import Foundation\nclass Foo {}"
        result = _strip_swift_comments(src)
        assert "Foundation" in result


# ---------------------------------------------------------------------------
# _swift_extract_imports
# ---------------------------------------------------------------------------


class TestSwiftExtractImports:
    """Tests for Swift import extraction."""

    def test_simple_import(self) -> None:
        src = "import Foundation\n"
        result = _swift_extract_imports(src)
        assert "Foundation" in result

    def test_multiple_imports(self) -> None:
        src = "import Foundation\nimport UIKit\nimport SwiftUI\n"
        result = _swift_extract_imports(src)
        assert "Foundation" in result
        assert "UIKit" in result
        assert "SwiftUI" in result

    def test_testable_import(self) -> None:
        src = "@testable import MyModule\n"
        result = _swift_extract_imports(src)
        assert "MyModule" in result

    def test_struct_import(self) -> None:
        """import struct ModuleName.StructName → extracts ModuleName."""
        src = "import struct Foundation.URL\n"
        result = _swift_extract_imports(src)
        assert "Foundation" in result

    def test_class_import(self) -> None:
        src = "import class UIKit.UIViewController\n"
        result = _swift_extract_imports(src)
        assert "UIKit" in result

    def test_func_import(self) -> None:
        src = "import func Darwin.sqrt\n"
        result = _swift_extract_imports(src)
        assert "Darwin" in result

    def test_enum_import(self) -> None:
        src = "import enum Foundation.JSONSerialization.ReadingOptions\n"
        result = _swift_extract_imports(src)
        assert "Foundation" in result

    def test_commented_import_ignored(self) -> None:
        src = "// import Evil\nimport Foundation\n"
        result = _swift_extract_imports(src)
        assert "Evil" not in result
        assert "Foundation" in result

    def test_block_commented_import_ignored(self) -> None:
        src = "/* import Evil */\nimport Foundation\n"
        result = _swift_extract_imports(src)
        assert "Evil" not in result
        assert "Foundation" in result

    def test_no_imports(self) -> None:
        src = "class Main {}\n"
        assert _swift_extract_imports(src) == set()

    def test_empty_source(self) -> None:
        assert _swift_extract_imports("") == set()

    def test_underscore_module_name(self) -> None:
        """Module names with underscores are valid."""
        src = "import Alamofire\nimport swift_argument_parser\n"
        result = _swift_extract_imports(src)
        assert "Alamofire" in result
        assert "swift_argument_parser" in result


# ---------------------------------------------------------------------------
# _swift_module_name
# ---------------------------------------------------------------------------


class TestSwiftModuleName:
    """Tests for SwiftPM package-to-module name mapping."""

    def test_no_hyphens(self) -> None:
        assert _swift_module_name("Alamofire") == "Alamofire"

    def test_hyphens_to_underscores(self) -> None:
        assert _swift_module_name("swift-argument-parser") == "swift_argument_parser"

    def test_single_hyphen(self) -> None:
        assert _swift_module_name("vapor-core") == "vapor_core"


# ---------------------------------------------------------------------------
# _swift_imports_package / _swift_file_imports_package
# ---------------------------------------------------------------------------


class TestSwiftImportsPackage:
    """Tests for Swift package import checking."""

    def test_exact_match(self, tmp_path: Path) -> None:
        f = tmp_path / "App.swift"
        f.write_text("import Alamofire\n")
        assert _swift_imports_package([f], "Alamofire")

    def test_no_match(self, tmp_path: Path) -> None:
        f = tmp_path / "App.swift"
        f.write_text("import Foundation\n")
        assert not _swift_imports_package([f], "Alamofire")

    def test_hyphenated_package_underscore_import(self, tmp_path: Path) -> None:
        """import swift_argument_parser matches package swift-argument-parser."""
        f = tmp_path / "App.swift"
        f.write_text("import swift_argument_parser\n")
        assert _swift_imports_package([f], "swift-argument-parser")

    def test_hyphenated_package_direct_import(self, tmp_path: Path) -> None:
        """Some packages keep hyphens in module names (rare but possible)."""
        f = tmp_path / "App.swift"
        f.write_text("import vapor_core\n")
        assert _swift_imports_package([f], "vapor-core")

    def test_commented_import_not_counted(self, tmp_path: Path) -> None:
        f = tmp_path / "App.swift"
        f.write_text("// import Alamofire\n")
        assert not _swift_imports_package([f], "Alamofire")

    def test_multiple_files(self, tmp_path: Path) -> None:
        f1 = tmp_path / "App.swift"
        f1.write_text("import Foundation\n")
        f2 = tmp_path / "Network.swift"
        f2.write_text("import Alamofire\n")
        assert _swift_imports_package([f1, f2], "Alamofire")

    def test_file_read_error(self, tmp_path: Path) -> None:
        f = tmp_path / "Missing.swift"
        assert not _swift_imports_package([f], "Alamofire")

    def test_single_file_function(self, tmp_path: Path) -> None:
        f = tmp_path / "App.swift"
        f.write_text("import Alamofire\n")
        assert _swift_file_imports_package(f, "Alamofire")

    def test_single_file_no_match(self, tmp_path: Path) -> None:
        f = tmp_path / "App.swift"
        f.write_text("import Foundation\n")
        assert not _swift_file_imports_package(f, "Alamofire")

    def test_single_file_read_error(self, tmp_path: Path) -> None:
        f = tmp_path / "Missing.swift"
        assert not _swift_file_imports_package(f, "Alamofire")


# ---------------------------------------------------------------------------
# ReachabilityFilter integration with Swift files
# ---------------------------------------------------------------------------


class TestReachabilitySwiftIntegration:
    """Test ReachabilityFilter with Swift projects."""

    def test_swift_package_imported_not_filtered(self, tmp_path: Path) -> None:
        f = tmp_path / "App.swift"
        f.write_text("import Alamofire\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="Alamofire",
            version="5.8.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is False  # NOT unreachable

    def test_swift_package_not_imported_filtered(self, tmp_path: Path) -> None:
        f = tmp_path / "App.swift"
        f.write_text("import Foundation\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="Alamofire",
            version="5.8.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is True  # unreachable

    def test_swift_find_imports(self, tmp_path: Path) -> None:
        f = tmp_path / "App.swift"
        f.write_text("import Alamofire\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="Alamofire",
            version="5.8.0",
            severity=Severity.HIGH,
        )
        result = rf.find_imports(vuln)
        assert len(result) == 1
        assert result[0].endswith("App.swift")

    def test_empty_swift_project_no_filter(self, tmp_path: Path) -> None:
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="Alamofire",
            version="5.8.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is False

    def test_swift_build_dir_skipped(self, tmp_path: Path) -> None:
        """Files under .build/ should be skipped."""
        build = tmp_path / ".build" / "debug"
        build.mkdir(parents=True)
        (build / "Alamofire.swift").write_text("import Alamofire\n")
        f = tmp_path / "Sources" / "App.swift"
        f.parent.mkdir()
        f.write_text("import Foundation\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="Alamofire",
            version="5.8.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is True  # .build/ import doesn't count

    def test_swift_vulnerable_functions(self, tmp_path: Path) -> None:
        f = tmp_path / "App.swift"
        f.write_text("import Alamofire\nAF.request(url).responseJSON { response in }\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="Alamofire",
            version="5.8.0",
            severity=Severity.HIGH,
            vulnerable_functions=["responseJSON"],
        )
        assert rf.check(vuln) is False  # function is referenced

    def test_swift_vulnerable_functions_not_present(self, tmp_path: Path) -> None:
        f = tmp_path / "App.swift"
        f.write_text(
            "import Alamofire\nAF.request(url).responseDecodable(of: MyType.self) { response in }\n"
        )
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="Alamofire",
            version="5.8.0",
            severity=Severity.HIGH,
            vulnerable_functions=["responseJSON"],
        )
        assert rf.check(vuln) is True  # responseJSON not referenced

    def test_swift_files_lazy_loaded(self, tmp_path: Path) -> None:
        rf = ReachabilityFilter(tmp_path)
        assert rf._swift_files is None
        _ = rf.swift_files
        assert rf._swift_files is not None

    def test_swift_hyphenated_package_match(self, tmp_path: Path) -> None:
        """Hyphenated packages match via underscore convention."""
        f = tmp_path / "App.swift"
        f.write_text("import swift_argument_parser\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="swift-argument-parser",
            version="1.2.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is False  # matched via hyphen convention
