"""Tests for Ruby reachability analysis.

Covers:
- Comment stripping for Ruby source
- Require extraction (require, require_relative skipped)
- Gem name matching with hyphen-to-slash convention
- ReachabilityFilter integration with Ruby files
"""

from __future__ import annotations

from pathlib import Path

from depquiet.filters.reachability import (
    ReachabilityFilter,
    _rb_extract_requires,
    _rb_file_imports_package,
    _rb_gem_require_names,
    _rb_imports_package,
    _strip_rb_comments,
)
from depquiet.models import Severity, Vulnerability

# ---------------------------------------------------------------------------
# _strip_rb_comments
# ---------------------------------------------------------------------------


class TestStripRbComments:
    """Tests for Ruby comment stripping."""

    def test_single_line_hash(self) -> None:
        src = "require 'nokogiri' # XML parser\nclass Foo; end"
        result = _strip_rb_comments(src)
        assert "nokogiri" in result
        assert "XML parser" not in result

    def test_multiline_begin_end(self) -> None:
        src = "=begin\nrequire 'evil'\n=end\nrequire 'nokogiri'"
        result = _strip_rb_comments(src)
        assert "evil" not in result
        assert "nokogiri" in result

    def test_empty_source(self) -> None:
        assert _strip_rb_comments("") == ""

    def test_no_comments(self) -> None:
        src = "require 'nokogiri'\nclass Foo; end"
        result = _strip_rb_comments(src)
        assert "nokogiri" in result


# ---------------------------------------------------------------------------
# _rb_extract_requires
# ---------------------------------------------------------------------------


class TestRbExtractRequires:
    """Tests for Ruby require extraction."""

    def test_simple_require_single_quotes(self) -> None:
        src = "require 'nokogiri'\n"
        result = _rb_extract_requires(src)
        assert "nokogiri" in result

    def test_simple_require_double_quotes(self) -> None:
        src = 'require "nokogiri"\n'
        result = _rb_extract_requires(src)
        assert "nokogiri" in result

    def test_require_with_subpath(self) -> None:
        src = "require 'aws-sdk-s3/client'\n"
        result = _rb_extract_requires(src)
        assert "aws-sdk-s3" in result

    def test_multiple_requires(self) -> None:
        src = (
            "require 'nokogiri'\n"
            "require 'rails'\n"
            "require 'sinatra'\n"
        )
        result = _rb_extract_requires(src)
        assert "nokogiri" in result
        assert "rails" in result
        assert "sinatra" in result

    def test_require_relative_skipped(self) -> None:
        """require_relative is for local files, not gems."""
        src = "require_relative 'lib/helper'\nrequire 'nokogiri'\n"
        result = _rb_extract_requires(src)
        assert "lib" not in result
        assert "nokogiri" in result

    def test_commented_require_ignored(self) -> None:
        src = "# require 'evil'\nrequire 'nokogiri'\n"
        result = _rb_extract_requires(src)
        assert "evil" not in result
        assert "nokogiri" in result

    def test_begin_end_commented_require_ignored(self) -> None:
        src = "=begin\nrequire 'evil'\n=end\nrequire 'nokogiri'\n"
        result = _rb_extract_requires(src)
        assert "evil" not in result
        assert "nokogiri" in result

    def test_no_requires(self) -> None:
        src = "class Main; end\n"
        assert _rb_extract_requires(src) == set()

    def test_empty_source(self) -> None:
        assert _rb_extract_requires("") == set()

    def test_hyphenated_gem(self) -> None:
        src = "require 'aws-sdk-s3'\n"
        result = _rb_extract_requires(src)
        assert "aws-sdk-s3" in result

    def test_nested_require(self) -> None:
        """require 'active_support/core_ext' → top-level 'active_support'."""
        src = "require 'active_support/core_ext/hash'\n"
        result = _rb_extract_requires(src)
        assert "active_support" in result


# ---------------------------------------------------------------------------
# _rb_gem_require_names
# ---------------------------------------------------------------------------


class TestRbGemRequireNames:
    """Tests for gem name to require name mapping."""

    def test_simple_gem(self) -> None:
        result = _rb_gem_require_names("nokogiri")
        assert "nokogiri" in result

    def test_hyphenated_gem(self) -> None:
        result = _rb_gem_require_names("aws-sdk-s3")
        assert "aws-sdk-s3" in result
        assert "aws/sdk/s3" in result

    def test_no_hyphen_no_extra(self) -> None:
        result = _rb_gem_require_names("rails")
        assert result == {"rails"}


# ---------------------------------------------------------------------------
# _rb_imports_package / _rb_file_imports_package
# ---------------------------------------------------------------------------


class TestRbImportsPackage:
    """Tests for Ruby package import checking."""

    def test_exact_match(self, tmp_path: Path) -> None:
        f = tmp_path / "app.rb"
        f.write_text("require 'nokogiri'\n")
        assert _rb_imports_package([f], "nokogiri")

    def test_no_match(self, tmp_path: Path) -> None:
        f = tmp_path / "app.rb"
        f.write_text("require 'nokogiri'\n")
        assert not _rb_imports_package([f], "rails")

    def test_hyphenated_gem_direct(self, tmp_path: Path) -> None:
        """require 'aws-sdk-s3' matches gem aws-sdk-s3."""
        f = tmp_path / "app.rb"
        f.write_text("require 'aws-sdk-s3'\n")
        assert _rb_imports_package([f], "aws-sdk-s3")

    def test_hyphenated_gem_slash_form(self, tmp_path: Path) -> None:
        """require 'aws/sdk/s3' matches gem aws-sdk-s3 via convention."""
        f = tmp_path / "app.rb"
        f.write_text("require 'aws/sdk/s3'\n")
        assert _rb_imports_package([f], "aws-sdk-s3")

    def test_commented_require_not_counted(self, tmp_path: Path) -> None:
        f = tmp_path / "app.rb"
        f.write_text("# require 'nokogiri'\n")
        assert not _rb_imports_package([f], "nokogiri")

    def test_multiple_files(self, tmp_path: Path) -> None:
        f1 = tmp_path / "app.rb"
        f1.write_text("require 'sinatra'\n")
        f2 = tmp_path / "lib.rb"
        f2.write_text("require 'nokogiri'\n")
        assert _rb_imports_package([f1, f2], "nokogiri")

    def test_file_read_error(self, tmp_path: Path) -> None:
        f = tmp_path / "missing.rb"
        assert not _rb_imports_package([f], "nokogiri")

    def test_single_file_function(self, tmp_path: Path) -> None:
        f = tmp_path / "app.rb"
        f.write_text("require 'nokogiri'\n")
        assert _rb_file_imports_package(f, "nokogiri")

    def test_single_file_no_match(self, tmp_path: Path) -> None:
        f = tmp_path / "app.rb"
        f.write_text("require 'sinatra'\n")
        assert not _rb_file_imports_package(f, "nokogiri")

    def test_single_file_read_error(self, tmp_path: Path) -> None:
        f = tmp_path / "missing.rb"
        assert not _rb_file_imports_package(f, "nokogiri")


# ---------------------------------------------------------------------------
# ReachabilityFilter integration with Ruby files
# ---------------------------------------------------------------------------


class TestReachabilityRbIntegration:
    """Test ReachabilityFilter with Ruby projects."""

    def test_rb_package_imported_not_filtered(self, tmp_path: Path) -> None:
        f = tmp_path / "app.rb"
        f.write_text("require 'nokogiri'\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="nokogiri",
            version="1.15.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is False  # NOT unreachable

    def test_rb_package_not_imported_filtered(self, tmp_path: Path) -> None:
        f = tmp_path / "app.rb"
        f.write_text("require 'sinatra'\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="nokogiri",
            version="1.15.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is True  # unreachable

    def test_rb_find_imports(self, tmp_path: Path) -> None:
        f = tmp_path / "app.rb"
        f.write_text("require 'nokogiri'\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="nokogiri",
            version="1.15.0",
            severity=Severity.HIGH,
        )
        result = rf.find_imports(vuln)
        assert len(result) == 1
        assert result[0].endswith("app.rb")

    def test_empty_rb_project_no_filter(self, tmp_path: Path) -> None:
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="nokogiri",
            version="1.15.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is False

    def test_rb_vendor_dir_skipped(self, tmp_path: Path) -> None:
        """Files under vendor/ should be skipped."""
        vendor = tmp_path / "vendor" / "bundle"
        vendor.mkdir(parents=True)
        (vendor / "nokogiri.rb").write_text("require 'nokogiri'\n")
        f = tmp_path / "app.rb"
        f.write_text("require 'sinatra'\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="nokogiri",
            version="1.15.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is True  # vendor/ require doesn't count

    def test_rb_vulnerable_functions(self, tmp_path: Path) -> None:
        f = tmp_path / "app.rb"
        f.write_text(
            "require 'nokogiri'\n"
            "doc = Nokogiri::XML(xml_string)\n"
        )
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="nokogiri",
            version="1.15.0",
            severity=Severity.HIGH,
            vulnerable_functions=["XML"],
        )
        assert rf.check(vuln) is False  # function is referenced

    def test_rb_vulnerable_functions_not_present(self, tmp_path: Path) -> None:
        f = tmp_path / "app.rb"
        f.write_text(
            "require 'nokogiri'\n"
            "doc = Nokogiri::HTML(html_string)\n"
        )
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="nokogiri",
            version="1.15.0",
            severity=Severity.HIGH,
            vulnerable_functions=["XML"],
        )
        assert rf.check(vuln) is True  # XML not referenced

    def test_rb_files_lazy_loaded(self, tmp_path: Path) -> None:
        rf = ReachabilityFilter(tmp_path)
        assert rf._rb_files is None
        _ = rf.rb_files
        assert rf._rb_files is not None

    def test_rb_hyphenated_gem_match(self, tmp_path: Path) -> None:
        """Hyphenated gems match via slash convention."""
        f = tmp_path / "app.rb"
        f.write_text("require 'aws/sdk/s3'\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="aws-sdk-s3",
            version="1.0.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is False  # matched via hyphen convention
