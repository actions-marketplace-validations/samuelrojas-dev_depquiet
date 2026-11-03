"""Tests for Rust reachability analysis.

Covers:
- Comment stripping for Rust source
- Import extraction (use, extern crate, nested use, aliases)
- Hyphen-to-underscore crate name normalization
- Package-level import checking
- ReachabilityFilter integration with Rust files
"""

from __future__ import annotations

from pathlib import Path

from depquiet.filters.reachability import (
    ReachabilityFilter,
    _rs_extract_imports,
    _rs_file_imports_package,
    _rs_imports_package,
    _strip_rust_comments,
)
from depquiet.models import Severity, Vulnerability

# ---------------------------------------------------------------------------
# _strip_rust_comments
# ---------------------------------------------------------------------------


class TestStripRustComments:
    """Tests for Rust comment stripping."""

    def test_single_line_comment(self) -> None:
        src = "use serde::Deserialize; // serialization\nfn main() {}"
        result = _strip_rust_comments(src)
        assert "serde" in result
        assert "serialization" not in result

    def test_multi_line_comment(self) -> None:
        src = "/* use tokio::runtime; */\nuse serde::Deserialize;"
        result = _strip_rust_comments(src)
        assert "tokio" not in result
        assert "serde" in result

    def test_doc_comment(self) -> None:
        """/// doc comments are line comments and should be stripped."""
        src = "/// use evil_crate::bad;\nuse serde::Deserialize;"
        result = _strip_rust_comments(src)
        assert "evil_crate" not in result
        assert "serde" in result

    def test_comment_inside_string_stripped_conservative(self) -> None:
        """A // inside a string is stripped — conservative but safe."""
        src = 'let s = "// not a comment";\nuse serde::Deserialize;'
        result = _strip_rust_comments(src)
        assert "serde" in result

    def test_empty_source(self) -> None:
        assert _strip_rust_comments("") == ""

    def test_nested_block_comment_partial(self) -> None:
        """Nested block comments aren't fully handled — conservative."""
        src = "/* outer /* inner */ still comment */\nuse serde::Deserialize;"
        result = _strip_rust_comments(src)
        # The inner */ ends the match; "still comment */" remains — conservative
        assert "serde" in result


# ---------------------------------------------------------------------------
# _rs_extract_imports
# ---------------------------------------------------------------------------


class TestRsExtractImports:
    """Tests for Rust import extraction."""

    def test_simple_use(self) -> None:
        src = "use serde::Deserialize;\nfn main() {}"
        assert _rs_extract_imports(src) == {"serde"}

    def test_use_whole_crate(self) -> None:
        src = "use serde;\nfn main() {}"
        assert _rs_extract_imports(src) == {"serde"}

    def test_nested_use(self) -> None:
        src = "use serde::{Deserialize, Serialize};\nfn main() {}"
        assert _rs_extract_imports(src) == {"serde"}

    def test_extern_crate(self) -> None:
        src = "extern crate serde;\nfn main() {}"
        assert _rs_extract_imports(src) == {"serde"}

    def test_extern_crate_with_alias(self) -> None:
        src = "extern crate serde as s;\nfn main() {}"
        assert _rs_extract_imports(src) == {"serde"}

    def test_multiple_imports(self) -> None:
        src = "use serde::Deserialize;\nuse tokio::runtime;\nuse reqwest::Client;\n"
        assert _rs_extract_imports(src) == {"serde", "tokio", "reqwest"}

    def test_skips_self(self) -> None:
        src = "use self::module::Thing;\nuse serde::Deserialize;"
        result = _rs_extract_imports(src)
        assert "self" not in result
        assert "serde" in result

    def test_skips_super(self) -> None:
        src = "use super::parent::Item;\nuse tokio::spawn;"
        result = _rs_extract_imports(src)
        assert "super" not in result
        assert "tokio" in result

    def test_skips_crate_keyword(self) -> None:
        src = "use crate::my_module::Thing;\nuse serde::Deserialize;"
        result = _rs_extract_imports(src)
        assert "crate" not in result
        assert "serde" in result

    def test_skips_std(self) -> None:
        src = "use std::collections::HashMap;\nuse serde::Deserialize;"
        result = _rs_extract_imports(src)
        assert "std" not in result
        assert "serde" in result

    def test_skips_core(self) -> None:
        src = "use core::fmt;\nuse serde::Deserialize;"
        result = _rs_extract_imports(src)
        assert "core" not in result
        assert "serde" in result

    def test_skips_alloc(self) -> None:
        src = "use alloc::vec::Vec;\nuse serde::Deserialize;"
        result = _rs_extract_imports(src)
        assert "alloc" not in result
        assert "serde" in result

    def test_commented_import_ignored(self) -> None:
        src = "// use evil::Thing;\nuse serde::Deserialize;"
        result = _rs_extract_imports(src)
        assert result == {"serde"}

    def test_block_commented_import_ignored(self) -> None:
        src = "/* use evil::Thing; */\nuse serde::Deserialize;"
        result = _rs_extract_imports(src)
        assert result == {"serde"}

    def test_no_imports(self) -> None:
        src = 'fn main() { println!("hello"); }'
        assert _rs_extract_imports(src) == set()

    def test_empty_source(self) -> None:
        assert _rs_extract_imports("") == set()

    def test_deep_path(self) -> None:
        src = "use tokio::io::AsyncReadExt;\n"
        assert _rs_extract_imports(src) == {"tokio"}

    def test_underscore_crate_name(self) -> None:
        """Crate names with underscores are valid identifiers."""
        src = "use my_crate::Thing;\n"
        assert _rs_extract_imports(src) == {"my_crate"}


# ---------------------------------------------------------------------------
# _rs_imports_package / _rs_file_imports_package
# ---------------------------------------------------------------------------


class TestRsImportsPackage:
    """Tests for Rust package import checking with hyphen normalization."""

    def test_exact_match(self, tmp_path: Path) -> None:
        f = tmp_path / "main.rs"
        f.write_text("use serde::Deserialize;\nfn main() {}\n")
        assert _rs_imports_package([f], "serde")

    def test_hyphen_to_underscore(self, tmp_path: Path) -> None:
        """Cargo.toml uses hyphens, Rust source uses underscores."""
        f = tmp_path / "main.rs"
        f.write_text("use my_crate::Thing;\nfn main() {}\n")
        assert _rs_imports_package([f], "my-crate")

    def test_no_match(self, tmp_path: Path) -> None:
        f = tmp_path / "main.rs"
        f.write_text("use serde::Deserialize;\nfn main() {}\n")
        assert not _rs_imports_package([f], "tokio")

    def test_extern_crate_match(self, tmp_path: Path) -> None:
        f = tmp_path / "lib.rs"
        f.write_text("extern crate serde;\n")
        assert _rs_imports_package([f], "serde")

    def test_commented_import_not_counted(self, tmp_path: Path) -> None:
        f = tmp_path / "main.rs"
        f.write_text("// use serde::Deserialize;\nfn main() {}\n")
        assert not _rs_imports_package([f], "serde")

    def test_multiple_files(self, tmp_path: Path) -> None:
        f1 = tmp_path / "main.rs"
        f1.write_text("fn main() {}\n")
        f2 = tmp_path / "lib.rs"
        f2.write_text("use tokio::runtime;\n")
        assert _rs_imports_package([f1, f2], "tokio")

    def test_file_read_error(self, tmp_path: Path) -> None:
        f = tmp_path / "missing.rs"
        assert not _rs_imports_package([f], "serde")

    def test_single_file_function(self, tmp_path: Path) -> None:
        f = tmp_path / "main.rs"
        f.write_text("use serde::Deserialize;\n")
        assert _rs_file_imports_package(f, "serde")

    def test_single_file_no_match(self, tmp_path: Path) -> None:
        f = tmp_path / "main.rs"
        f.write_text("use serde::Deserialize;\n")
        assert not _rs_file_imports_package(f, "tokio")

    def test_single_file_read_error(self, tmp_path: Path) -> None:
        f = tmp_path / "missing.rs"
        assert not _rs_file_imports_package(f, "serde")

    def test_single_file_hyphen_normalization(self, tmp_path: Path) -> None:
        f = tmp_path / "main.rs"
        f.write_text("use my_crate::Thing;\n")
        assert _rs_file_imports_package(f, "my-crate")


# ---------------------------------------------------------------------------
# ReachabilityFilter integration with Rust files
# ---------------------------------------------------------------------------


class TestReachabilityRustIntegration:
    """Test ReachabilityFilter with Rust projects."""

    def test_rust_package_imported_not_filtered(self, tmp_path: Path) -> None:
        f = tmp_path / "main.rs"
        f.write_text("use serde::Deserialize;\nfn main() {}\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="serde",
            version="1.0.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is False  # NOT unreachable

    def test_rust_package_not_imported_filtered(self, tmp_path: Path) -> None:
        f = tmp_path / "main.rs"
        f.write_text("use serde::Deserialize;\nfn main() {}\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="tokio",
            version="1.0.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is True  # unreachable, safe to filter

    def test_rust_hyphen_package_name(self, tmp_path: Path) -> None:
        """Cargo.toml uses hyphens, Rust source uses underscores."""
        f = tmp_path / "main.rs"
        f.write_text("use my_crate::Thing;\nfn main() {}\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="my-crate",
            version="0.1.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is False  # my_crate == my-crate

    def test_rust_find_imports(self, tmp_path: Path) -> None:
        f = tmp_path / "main.rs"
        f.write_text("use serde::Deserialize;\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="serde",
            version="1.0.0",
            severity=Severity.HIGH,
        )
        result = rf.find_imports(vuln)
        assert len(result) == 1
        assert result[0].endswith("main.rs")

    def test_empty_rust_project_no_filter(self, tmp_path: Path) -> None:
        """Empty project: no files to check, don't filter (conservative)."""
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="serde",
            version="1.0.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is False

    def test_rust_target_dir_skipped(self, tmp_path: Path) -> None:
        """Files under target/ should be skipped."""
        target = tmp_path / "target" / "debug"
        target.mkdir(parents=True)
        (target / "deps.rs").write_text("use serde::Deserialize;\n")
        # Only target files, no actual source files
        f = tmp_path / "main.rs"
        f.write_text("fn main() {}\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="serde",
            version="1.0.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is True  # target/ import doesn't count

    def test_mixed_rust_and_python(self, tmp_path: Path) -> None:
        """Mixed project: Rust file imports the package, Python doesn't."""
        rs_file = tmp_path / "main.rs"
        rs_file.write_text("use serde::Deserialize;\n")
        py_file = tmp_path / "app.py"
        py_file.write_text("import os\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="serde",
            version="1.0.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is False  # Rust file imports it

    def test_rust_vulnerable_functions(self, tmp_path: Path) -> None:
        """Vulnerable function check works with Rust files."""
        f = tmp_path / "main.rs"
        f.write_text('use serde::Deserialize;\n\nfn main() {\n    serde::from_str("x");\n}\n')
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="serde",
            version="1.0.0",
            severity=Severity.HIGH,
            vulnerable_functions=["from_str"],
        )
        assert rf.check(vuln) is False  # function is referenced

    def test_rust_vulnerable_functions_not_present(self, tmp_path: Path) -> None:
        """Vulnerable function not used — safe to filter."""
        f = tmp_path / "main.rs"
        f.write_text("use serde::Deserialize;\n\nfn main() {\n    let x = 1;\n}\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="serde",
            version="1.0.0",
            severity=Severity.HIGH,
            vulnerable_functions=["from_str"],
        )
        assert rf.check(vuln) is True  # from_str not referenced

    def test_rust_files_lazy_loaded(self, tmp_path: Path) -> None:
        """Rust files are lazily loaded on first access."""
        rf = ReachabilityFilter(tmp_path)
        assert rf._rs_files is None
        _ = rf.rs_files
        assert rf._rs_files is not None
