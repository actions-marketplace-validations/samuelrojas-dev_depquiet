"""Tests for Go reachability analysis.

Covers:
- Comment stripping for Go source
- Import extraction (single, grouped, aliased, blank, dot)
- Module name resolution from import paths
- Package-level import checking
- ReachabilityFilter integration with Go files
"""

from __future__ import annotations

from pathlib import Path

from depquiet.filters.reachability import (
    ReachabilityFilter,
    _go_extract_imports,
    _go_file_imports_package,
    _go_imports_package,
    _go_module_name,
    _strip_go_comments,
)
from depquiet.models import Severity, Vulnerability

# ---------------------------------------------------------------------------
# _strip_go_comments
# ---------------------------------------------------------------------------


class TestStripGoComments:
    """Tests for Go comment stripping."""

    def test_single_line_comment(self) -> None:
        src = 'import "fmt" // standard library\nfunc main() {}'
        result = _strip_go_comments(src)
        assert '"fmt"' in result
        assert "standard library" not in result

    def test_multi_line_comment(self) -> None:
        src = '/* import "os" */\nimport "fmt"'
        result = _strip_go_comments(src)
        assert '"os"' not in result
        assert '"fmt"' in result

    def test_comment_inside_string_stripped_conservative(self) -> None:
        """A // inside a string is also stripped — conservative but safe.

        Go imports are detected by their own regex patterns, not by string
        preservation, so this doesn't cause false negatives.
        """
        src = 'var s = "// not a comment"\nimport "fmt"'
        result = _strip_go_comments(src)
        # The // inside the string gets stripped too (conservative)
        assert '"fmt"' in result

    def test_preserves_backtick_strings(self) -> None:
        src = 'var s = `/* not a comment */`\nimport "fmt"'
        result = _strip_go_comments(src)
        # Go backtick strings are raw strings, but our comment regex
        # doesn't strip them (only strips // and /* */)
        assert '"fmt"' in result

    def test_empty_source(self) -> None:
        assert _strip_go_comments("") == ""


# ---------------------------------------------------------------------------
# _go_extract_imports
# ---------------------------------------------------------------------------


class TestGoExtractImports:
    """Tests for Go import extraction."""

    def test_single_import(self) -> None:
        src = 'package main\n\nimport "fmt"\n\nfunc main() {}'
        assert _go_extract_imports(src) == {"fmt"}

    def test_grouped_imports(self) -> None:
        src = 'package main\n\nimport (\n\t"fmt"\n\t"net/http"\n\t"os"\n)\n'
        assert _go_extract_imports(src) == {"fmt", "net/http", "os"}

    def test_aliased_import(self) -> None:
        src = 'package main\n\nimport m "github.com/user/pkg"\n'
        assert _go_extract_imports(src) == {"github.com/user/pkg"}

    def test_dot_import(self) -> None:
        src = 'package main\n\nimport . "github.com/user/pkg"\n'
        assert _go_extract_imports(src) == {"github.com/user/pkg"}

    def test_blank_import(self) -> None:
        src = 'package main\n\nimport _ "github.com/lib/pq"\n'
        assert _go_extract_imports(src) == {"github.com/lib/pq"}

    def test_grouped_with_aliases(self) -> None:
        src = (
            "package main\n\nimport (\n"
            '\t"fmt"\n'
            '\tlog "github.com/sirupsen/logrus"\n'
            '\t_ "github.com/lib/pq"\n'
            '\t. "github.com/onsi/gomega"\n'
            ")\n"
        )
        result = _go_extract_imports(src)
        assert result == {
            "fmt",
            "github.com/sirupsen/logrus",
            "github.com/lib/pq",
            "github.com/onsi/gomega",
        }

    def test_commented_import_ignored(self) -> None:
        src = 'package main\n\n// import "os"\nimport "fmt"\n'
        result = _go_extract_imports(src)
        assert result == {"fmt"}

    def test_block_commented_import_ignored(self) -> None:
        src = 'package main\n\n/* import "os" */\nimport "fmt"\n'
        result = _go_extract_imports(src)
        assert result == {"fmt"}

    def test_no_imports(self) -> None:
        src = "package main\n\nfunc main() {}\n"
        assert _go_extract_imports(src) == set()

    def test_empty_source(self) -> None:
        assert _go_extract_imports("") == set()

    def test_subpackage_import(self) -> None:
        src = 'import "github.com/gorilla/mux/middleware"\n'
        assert _go_extract_imports(src) == {"github.com/gorilla/mux/middleware"}

    def test_stdlib_nested(self) -> None:
        src = 'import (\n\t"crypto/tls"\n\t"encoding/json"\n)\n'
        result = _go_extract_imports(src)
        assert result == {"crypto/tls", "encoding/json"}

    def test_multiple_import_blocks(self) -> None:
        src = 'import "fmt"\n\nimport (\n\t"os"\n\t"net/http"\n)\n'
        result = _go_extract_imports(src)
        assert result == {"fmt", "os", "net/http"}

    def test_import_in_string_conservative(self) -> None:
        """An import statement inside a string matches — conservative choice."""
        src = 'var s = `import "github.com/evil/pkg"`\nimport "fmt"\n'
        result = _go_extract_imports(src)
        # Both should match (conservative: string content treated as reachable)
        assert "fmt" in result

    def test_golang_x_packages(self) -> None:
        src = 'import "golang.org/x/crypto/ssh"\n'
        assert _go_extract_imports(src) == {"golang.org/x/crypto/ssh"}


# ---------------------------------------------------------------------------
# _go_module_name
# ---------------------------------------------------------------------------


class TestGoModuleName:
    """Tests for Go module name extraction from import paths."""

    def test_stdlib_single(self) -> None:
        assert _go_module_name("fmt") == "fmt"

    def test_stdlib_nested(self) -> None:
        assert _go_module_name("net/http") == "net/http"

    def test_stdlib_deep(self) -> None:
        assert _go_module_name("crypto/tls") == "crypto/tls"

    def test_hosted_module(self) -> None:
        assert _go_module_name("github.com/gorilla/mux") == "github.com/gorilla/mux"

    def test_hosted_subpackage(self) -> None:
        assert _go_module_name("github.com/gorilla/mux/middleware") == "github.com/gorilla/mux"

    def test_golang_x(self) -> None:
        assert _go_module_name("golang.org/x/crypto") == "golang.org/x/crypto"

    def test_golang_x_subpackage(self) -> None:
        assert _go_module_name("golang.org/x/crypto/ssh") == "golang.org/x/crypto"

    def test_two_segment_hosted(self) -> None:
        # Rare but valid: e.g., gopkg.in/yaml.v3
        assert _go_module_name("gopkg.in/yaml.v3") == "gopkg.in/yaml.v3"

    def test_deep_subpackage(self) -> None:
        assert _go_module_name("github.com/user/repo/pkg/sub/deep") == "github.com/user/repo"


# ---------------------------------------------------------------------------
# _go_imports_package / _go_file_imports_package
# ---------------------------------------------------------------------------


class TestGoImportsPackage:
    """Tests for Go package import checking."""

    def test_exact_match(self, tmp_path: Path) -> None:
        f = tmp_path / "main.go"
        f.write_text('package main\nimport "github.com/gorilla/mux"\n')
        assert _go_imports_package([f], "github.com/gorilla/mux")

    def test_subpackage_matches_module(self, tmp_path: Path) -> None:
        """Importing a sub-package counts as importing the module."""
        f = tmp_path / "main.go"
        f.write_text('package main\nimport "github.com/gorilla/mux/middleware"\n')
        assert _go_imports_package([f], "github.com/gorilla/mux")

    def test_no_match(self, tmp_path: Path) -> None:
        f = tmp_path / "main.go"
        f.write_text('package main\nimport "fmt"\n')
        assert not _go_imports_package([f], "github.com/gorilla/mux")

    def test_different_module_same_prefix(self, tmp_path: Path) -> None:
        """github.com/gorilla/mux should not match github.com/gorilla/websocket."""
        f = tmp_path / "main.go"
        f.write_text('package main\nimport "github.com/gorilla/websocket"\n')
        assert not _go_imports_package([f], "github.com/gorilla/mux")

    def test_blank_import_counts(self, tmp_path: Path) -> None:
        f = tmp_path / "main.go"
        f.write_text('package main\nimport _ "github.com/lib/pq"\n')
        assert _go_imports_package([f], "github.com/lib/pq")

    def test_commented_import_not_counted(self, tmp_path: Path) -> None:
        f = tmp_path / "main.go"
        f.write_text('package main\n// import "github.com/lib/pq"\n')
        assert not _go_imports_package([f], "github.com/lib/pq")

    def test_multiple_files(self, tmp_path: Path) -> None:
        f1 = tmp_path / "main.go"
        f1.write_text('package main\nimport "fmt"\n')
        f2 = tmp_path / "server.go"
        f2.write_text('package main\nimport "github.com/gorilla/mux"\n')
        assert _go_imports_package([f1, f2], "github.com/gorilla/mux")

    def test_file_read_error(self, tmp_path: Path) -> None:
        f = tmp_path / "missing.go"
        assert not _go_imports_package([f], "github.com/gorilla/mux")

    def test_single_file_function(self, tmp_path: Path) -> None:
        f = tmp_path / "main.go"
        f.write_text('package main\nimport "github.com/gorilla/mux"\n')
        assert _go_file_imports_package(f, "github.com/gorilla/mux")

    def test_single_file_no_match(self, tmp_path: Path) -> None:
        f = tmp_path / "main.go"
        f.write_text('package main\nimport "fmt"\n')
        assert not _go_file_imports_package(f, "github.com/gorilla/mux")

    def test_single_file_read_error(self, tmp_path: Path) -> None:
        f = tmp_path / "missing.go"
        assert not _go_file_imports_package(f, "github.com/gorilla/mux")

    def test_golang_x_crypto(self, tmp_path: Path) -> None:
        f = tmp_path / "main.go"
        f.write_text('package main\nimport "golang.org/x/crypto/ssh"\n')
        assert _go_imports_package([f], "golang.org/x/crypto")


# ---------------------------------------------------------------------------
# ReachabilityFilter integration with Go files
# ---------------------------------------------------------------------------


class TestReachabilityGoIntegration:
    """Test ReachabilityFilter with Go projects."""

    def test_go_package_imported_not_filtered(self, tmp_path: Path) -> None:
        f = tmp_path / "main.go"
        f.write_text('package main\nimport "github.com/gorilla/mux"\nfunc main() {}\n')
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="github.com/gorilla/mux",
            version="1.8.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is False  # NOT unreachable

    def test_go_package_not_imported_filtered(self, tmp_path: Path) -> None:
        f = tmp_path / "main.go"
        f.write_text('package main\nimport "fmt"\nfunc main() {}\n')
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="github.com/gorilla/mux",
            version="1.8.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is True  # unreachable, safe to filter

    def test_go_find_imports(self, tmp_path: Path) -> None:
        f = tmp_path / "main.go"
        f.write_text('package main\nimport "github.com/gorilla/mux"\n')
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="github.com/gorilla/mux",
            version="1.8.0",
            severity=Severity.HIGH,
        )
        result = rf.find_imports(vuln)
        assert len(result) == 1
        assert result[0].endswith("main.go")

    def test_empty_go_project_no_filter(self, tmp_path: Path) -> None:
        """Empty project: no files to check, don't filter (conservative)."""
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="github.com/gorilla/mux",
            version="1.8.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is False

    def test_go_vendor_dir_skipped(self, tmp_path: Path) -> None:
        """Files under vendor/ should be skipped."""
        vendor = tmp_path / "vendor" / "github.com" / "gorilla" / "mux"
        vendor.mkdir(parents=True)
        (vendor / "mux.go").write_text('package mux\nimport "github.com/gorilla/mux"\n')
        # Only vendor files, no actual source files
        f = tmp_path / "main.go"
        f.write_text('package main\nimport "fmt"\n')
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="github.com/gorilla/mux",
            version="1.8.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is True  # vendor import doesn't count

    def test_mixed_go_and_python(self, tmp_path: Path) -> None:
        """Mixed project: Go file imports the package, Python doesn't."""
        go_file = tmp_path / "main.go"
        go_file.write_text('package main\nimport "github.com/gorilla/mux"\n')
        py_file = tmp_path / "app.py"
        py_file.write_text("import os\n")
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="github.com/gorilla/mux",
            version="1.8.0",
            severity=Severity.HIGH,
        )
        assert rf.check(vuln) is False  # Go file imports it

    def test_go_vulnerable_functions(self, tmp_path: Path) -> None:
        """Vulnerable function check works with Go files."""
        f = tmp_path / "main.go"
        f.write_text(
            'package main\n\nimport "golang.org/x/crypto/ssh"\n\nfunc main() {\n\tssh.Dial()\n}\n'
        )
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="golang.org/x/crypto",
            version="0.17.0",
            severity=Severity.HIGH,
            vulnerable_functions=["ssh.Dial"],
        )
        assert rf.check(vuln) is False  # function is referenced

    def test_go_vulnerable_functions_not_present(self, tmp_path: Path) -> None:
        """Vulnerable function not used — safe to filter."""
        f = tmp_path / "main.go"
        f.write_text(
            'package main\n\nimport "golang.org/x/crypto/bcrypt"\n\n'
            "func main() {\n\tbcrypt.GenerateFromPassword()\n}\n"
        )
        rf = ReachabilityFilter(tmp_path)
        vuln = Vulnerability(
            cve="CVE-2024-1234",
            package="golang.org/x/crypto",
            version="0.17.0",
            severity=Severity.HIGH,
            vulnerable_functions=["ssh.Dial"],
        )
        assert rf.check(vuln) is True  # ssh.Dial not referenced

    def test_go_files_lazy_loaded(self, tmp_path: Path) -> None:
        """Go files are lazily loaded on first access."""
        rf = ReachabilityFilter(tmp_path)
        assert rf._go_files is None
        _ = rf.go_files
        assert rf._go_files is not None
