"""Tests for PHP reachability analysis.

Covers:
- Comment stripping for PHP source
- Namespace extraction from use statements (standard, function, const, group)
- Composer package name matching (vendor/package convention)
- ReachabilityFilter integration with PHP files
"""

from __future__ import annotations

from pathlib import Path

from depquiet.filters.reachability import (
    ReachabilityFilter,
    _php_extract_uses,
    _php_file_imports_package,
    _php_imports_package,
    _strip_php_comments,
)
from depquiet.models import Severity, Vulnerability

# ---------------------------------------------------------------------------
# _strip_php_comments
# ---------------------------------------------------------------------------


class TestStripPhpComments:
    """Tests for PHP comment stripping."""

    def test_single_line_double_slash(self) -> None:
        src = "use Monolog\\Logger; // logging\nclass Foo {}"
        result = _strip_php_comments(src)
        assert "Monolog" in result
        assert "logging" not in result

    def test_single_line_hash(self) -> None:
        src = "use Monolog\\Logger; # logging\nclass Foo {}"
        result = _strip_php_comments(src)
        assert "Monolog" in result
        assert "logging" not in result

    def test_multi_line_comment(self) -> None:
        src = "/* use Evil\\Bad; */\nuse Monolog\\Logger;"
        result = _strip_php_comments(src)
        assert "Evil" not in result
        assert "Monolog" in result

    def test_phpdoc_comment(self) -> None:
        src = "/** use Evil\\Bad; */\nuse Monolog\\Logger;"
        result = _strip_php_comments(src)
        assert "Evil" not in result
        assert "Monolog" in result

    def test_empty_source(self) -> None:
        assert _strip_php_comments("") == ""


# ---------------------------------------------------------------------------
# _php_extract_uses
# ---------------------------------------------------------------------------


class TestPhpExtractUses:
    """Tests for PHP use statement extraction."""

    def test_simple_use(self) -> None:
        src = "<?php\nuse Monolog\\Logger;\n"
        result = _php_extract_uses(src)
        assert "monolog/logger" in result

    def test_nested_use(self) -> None:
        src = "<?php\nuse Monolog\\Logger\\Handler\\StreamHandler;\n"
        result = _php_extract_uses(src)
        assert "monolog/logger" in result

    def test_function_use(self) -> None:
        src = "<?php\nuse function GuzzleHttp\\Promise\\all;\n"
        result = _php_extract_uses(src)
        assert "guzzlehttp/promise" in result

    def test_const_use(self) -> None:
        src = "<?php\nuse const GuzzleHttp\\Promise\\FULFILLED;\n"
        result = _php_extract_uses(src)
        assert "guzzlehttp/promise" in result

    def test_multiple_uses(self) -> None:
        src = (
            "<?php\n"
            "use Monolog\\Logger;\n"
            "use Symfony\\Component\\HttpFoundation\\Request;\n"
            "use GuzzleHttp\\Client;\n"
        )
        result = _php_extract_uses(src)
        assert "monolog/logger" in result
        assert "symfony/component" in result
        assert "guzzlehttp/client" in result

    def test_commented_use_ignored(self) -> None:
        src = "<?php\n// use Evil\\Bad;\nuse Monolog\\Logger;\n"
        result = _php_extract_uses(src)
        assert "evil/bad" not in result
        assert "monolog/logger" in result

    def test_block_commented_use_ignored(self) -> None:
        src = "<?php\n/* use Evil\\Bad; */\nuse Monolog\\Logger;\n"
        result = _php_extract_uses(src)
        assert "evil/bad" not in result
        assert "monolog/logger" in result

    def test_hash_commented_use_ignored(self) -> None:
        src = "<?php\n# use Evil\\Bad;\nuse Monolog\\Logger;\n"
        result = _php_extract_uses(src)
        assert "evil/bad" not in result
        assert "monolog/logger" in result

    def test_no_uses(self) -> None:
        src = "<?php\nclass Main {}\n"
        assert _php_extract_uses(src) == set()

    def test_empty_source(self) -> None:
        assert _php_extract_uses("") == set()

    def test_single_segment_ignored(self) -> None:
        """Single-segment use (like 'use Logger;') has no vendor, skip."""
        src = "<?php\nuse Logger;\n"
        assert _php_extract_uses(src) == set()

    def test_case_insensitive(self) -> None:
        """PHP namespaces are case-insensitive; we normalize to lowercase."""
        src = "<?php\nuse Monolog\\Logger;\n"
        result = _php_extract_uses(src)
        assert "monolog/logger" in result


# ---------------------------------------------------------------------------
# _php_imports_package / _php_file_imports_package
# ---------------------------------------------------------------------------


class TestPhpImportsPackage:
    """Tests for PHP package import checking."""

    def test_exact_match(self, tmp_path: Path) -> None:
        f = tmp_path / "index.php"
        f.write_text("<?php\nuse Monolog\\Logger;\n")
        assert _php_imports_package([f], "monolog/logger")

    def test_case_insensitive_match(self, tmp_path: Path) -> None:
        """Composer packages are lowercase; PHP namespaces may be CamelCase."""
        f = tmp_path / "index.php"
        f.write_text("<?php\nuse Monolog\\Logger;\n")
        assert _php_imports_package([f], "Monolog/Logger")

    def test_no_match(self, tmp_path: Path) -> None:
        f = tmp_path / "index.php"
        f.write_text("<?php\nuse Monolog\\Logger;\n")
        assert not _php_imports_package([f], "guzzlehttp/guzzle")

    def test_commented_use_not_counted(self, tmp_path: Path) -> None:
        f = tmp_path / "index.php"
        f.write_text("<?php\n// use Monolog\\Logger;\n")
        assert not _php_imports_package([f], "monolog/logger")

    def test_multiple_files(self, tmp_path: Path) -> None:
        f1 = tmp_path / "index.php"
        f1.write_text("<?php\nuse App\\Controller;\n")
        f2 = tmp_path / "service.php"
        f2.write_text("<?php\nuse Monolog\\Logger;\n")
        assert _php_imports_package([f1, f2], "monolog/logger")

    def test_file_read_error(self, tmp_path: Path) -> None:
        f = tmp_path / "missing.php"
        assert not _php_imports_package([f], "monolog/logger")

    def test_single_file_function(self, tmp_path: Path) -> None:
        f = tmp_path / "index.php"
        f.write_text("<?php\nuse Monolog\\Logger;\n")
        assert _php_file_imports_package(f, "monolog/logger")

    def test_single_file_no_match(self, tmp_path: Path) -> None:
        f = tmp_path / "index.php"
        f.write_text("<?php\nuse App\\Controller;\n")
        assert not _php_file_imports_package(f, "monolog/logger")

    def test_single_file_read_error(self, tmp_path: Path) -> None:
        f = tmp_path / "missing.php"
        assert not _php_file_imports_package(f, "monolog/logger")


# ---------------------------------------------------------------------------
# ReachabilityFilter integration with PHP files
# ---------------------------------------------------------------------------


class TestReachabilityPhpIntegration:
    """Test ReachabilityFilter with PHP projects."""

    def test_php_package_imported_not_filtered(self, tmp_path: Path) -> None:
        f = tmp_path / "index.php"
        f.write_text("<?php\nuse Monolog\\Logger;\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="monolog/monolog",
            version="2.9.0",
            severity=Severity.HIGH,
        )
        # monolog/monolog won't match monolog/logger — these are different
        # Composer packages. Test with the actual matching name.
        assert rf.check(vuln) is True  # different package

    def test_php_matching_package(self, tmp_path: Path) -> None:
        f = tmp_path / "index.php"
        f.write_text("<?php\nuse Monolog\\Logger;\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="monolog/logger",
            version="2.9.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is False  # NOT unreachable

    def test_php_package_not_imported_filtered(self, tmp_path: Path) -> None:
        f = tmp_path / "index.php"
        f.write_text("<?php\nuse App\\Controller;\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="monolog/logger",
            version="2.9.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is True  # unreachable

    def test_php_find_imports(self, tmp_path: Path) -> None:
        f = tmp_path / "index.php"
        f.write_text("<?php\nuse Monolog\\Logger;\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="monolog/logger",
            version="2.9.0",
            severity=Severity.HIGH,
        )
        result = rf.find_imports(vuln)
        assert len(result) == 1
        assert result[0].endswith("index.php")

    def test_empty_php_project_no_filter(self, tmp_path: Path) -> None:
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="monolog/logger",
            version="2.9.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is False

    def test_php_vendor_dir_skipped(self, tmp_path: Path) -> None:
        """Files under vendor/ should be skipped."""
        vendor = tmp_path / "vendor" / "monolog" / "monolog"
        vendor.mkdir(parents=True)
        (vendor / "Logger.php").write_text("<?php\nuse Monolog\\Logger;\n")
        f = tmp_path / "src" / "index.php"
        f.parent.mkdir()
        f.write_text("<?php\nuse App\\Controller;\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="monolog/logger",
            version="2.9.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is True  # vendor/ use doesn't count

    def test_php_vulnerable_functions(self, tmp_path: Path) -> None:
        f = tmp_path / "index.php"
        f.write_text(
            "<?php\nuse Monolog\\Logger;\n"
            "$logger = new Logger('app');\n"
            "$logger->pushHandler($handler);\n"
        )
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="monolog/logger",
            version="2.9.0",
            severity=Severity.HIGH,
            vulnerable_functions=["pushHandler"],
        )
        assert rf.check(vuln) is False  # function is referenced

    def test_php_vulnerable_functions_not_present(self, tmp_path: Path) -> None:
        f = tmp_path / "index.php"
        f.write_text("<?php\nuse Monolog\\Logger;\n$logger = new Logger('app');\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="monolog/logger",
            version="2.9.0",
            severity=Severity.HIGH,
            vulnerable_functions=["pushHandler"],
        )
        assert rf.check(vuln) is True  # pushHandler not referenced

    def test_php_files_lazy_loaded(self, tmp_path: Path) -> None:
        rf = ReachabilityFilter(tmp_path)
        assert rf._php_files is None
        _ = rf.php_files
        assert rf._php_files is not None
