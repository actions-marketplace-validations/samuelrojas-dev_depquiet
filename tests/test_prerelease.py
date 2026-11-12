"""A fix that exists only as a pre-release must be labeled as one."""

from __future__ import annotations

import pytest

from depquiet.models import (
    ScanResult,
    Severity,
    TriageResult,
    Verdict,
    Vulnerability,
    is_prerelease,
)
from depquiet.output import print_scan_result


@pytest.mark.parametrize(
    "version", ["26.10.0rc1", "1.0a1", "1.0b2", "1.0.dev3", "2.0.0-beta.1", "3.0.0-rc.1"]
)
def test_prereleases(version):
    assert is_prerelease(version)


@pytest.mark.parametrize("version", ["6.6", "1.2.22", "1.0.post1", "1.0.0+local", "4.17.21"])
def test_final_releases(version):
    assert not is_prerelease(version)


def _scan(fix: str) -> ScanResult:
    v = Vulnerability(
        cve="CVE-2026-1",
        package="twisted",
        version="26.4.0",
        severity=Severity.HIGH,
        fix_version=fix,
    )
    return ScanResult(
        results=[TriageResult(vuln=v, verdict=Verdict.ACTION)],
        project_path=".",
        package_manager="pip",
        total_dependencies=1,
    )


def test_terminal_labels_a_prerelease_fix(capsys):
    print_scan_result(_scan("26.10.0rc1"))
    assert "update to 26.10.0rc1 (pre-release)" in capsys.readouterr().out


def test_terminal_leaves_a_final_fix_unlabeled(capsys):
    print_scan_result(_scan("26.10.1"))
    assert "(pre-release)" not in capsys.readouterr().out
