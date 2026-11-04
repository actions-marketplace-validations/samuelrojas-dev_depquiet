"""Tests for SPDX 2.3 SBOM generation."""

from __future__ import annotations

import json
from pathlib import Path

from depquiet.models import (
    FilterReason,
    ScanResult,
    Severity,
    TriageResult,
    Verdict,
    Vulnerability,
)
from depquiet.spdx import (
    _spdx_id,
    _verdict_to_annotation,
    generate_spdx_json,
    write_spdx,
)

# -- Fixtures (same shape as test_sbom.py) --


def _vuln(
    cve: str = "CVE-2024-1234",
    package: str = "lodash",
    version: str = "4.17.20",
    severity: Severity = Severity.HIGH,
    title: str = "Prototype pollution",
    url: str = "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
    fix_version: str = "4.17.21",
) -> Vulnerability:
    return Vulnerability(
        cve=cve,
        package=package,
        version=version,
        severity=severity,
        title=title,
        url=url,
        fix_version=fix_version,
    )


def _result(
    vuln: Vulnerability | None = None,
    verdict: Verdict = Verdict.ACTION,
    reasons: list[FilterReason] | None = None,
) -> TriageResult:
    return TriageResult(
        vuln=vuln or _vuln(),
        verdict=verdict,
        reasons=reasons or [],
    )


_SENTINEL = object()


def _scan_result(
    results: list[TriageResult] | object | None = _SENTINEL,
    project: str = "/tmp/my-project",
) -> ScanResult:
    if results is _SENTINEL:
        results = [_result()]
    return ScanResult(
        project_path=project,
        package_manager="npm",
        total_dependencies=100,
        results=results,  # type: ignore[arg-type]
    )


# -- _spdx_id tests --


class TestSpdxId:
    def test_simple_package(self):
        result = _spdx_id("lodash", "4.17.21")
        assert result == "SPDXRef-Package-lodash-4.17.21"

    def test_scoped_npm_package(self):
        result = _spdx_id("@babel/core", "7.24.0")
        # @ and / are replaced with hyphens
        assert result == "SPDXRef-Package--babel-core-7.24.0"

    def test_underscore_replaced(self):
        result = _spdx_id("my_package", "1.0.0")
        assert result == "SPDXRef-Package-my-package-1.0.0"

    def test_only_valid_chars(self):
        result = _spdx_id("pkg!@#$%", "1.0")
        # Only alphanumeric, dot and hyphen survive
        for c in result:
            assert c.isalnum() or c in ".-", f"Invalid char: {c!r}"


# -- _verdict_to_annotation tests --


class TestVerdictToAnnotation:
    def test_action_verdict(self):
        tr = _result(verdict=Verdict.ACTION)
        ann = _verdict_to_annotation(tr)
        assert "action" in ann

    def test_filtered_verdict(self):
        tr = _result(verdict=Verdict.FILTERED, reasons=[FilterReason.LOW_EPSS])
        ann = _verdict_to_annotation(tr)
        assert "filtered" in ann


# -- generate_spdx_json tests --


class TestGenerateSpdxJson:
    def test_document_structure(self):
        doc = generate_spdx_json(_scan_result())
        assert doc["spdxVersion"] == "SPDX-2.3"
        assert doc["dataLicense"] == "CC0-1.0"
        assert doc["SPDXID"] == "SPDXRef-DOCUMENT"
        assert "name" in doc
        assert "documentNamespace" in doc
        assert doc["documentNamespace"].startswith("https://spdx.org/spdxdocs/")

    def test_creation_info(self):
        doc = generate_spdx_json(_scan_result())
        info = doc["creationInfo"]
        assert "created" in info
        assert any("depquiet" in c for c in info["creators"])
        assert "licenseListVersion" in info

    def test_packages_from_scan_results(self):
        """When no lockfile packages, components come from scan results."""
        tr = _result(vuln=_vuln(package="lodash", version="4.17.20"))
        doc = generate_spdx_json(_scan_result(results=[tr]))
        assert len(doc["packages"]) == 1
        pkg = doc["packages"][0]
        assert pkg["name"] == "lodash"
        assert pkg["versionInfo"] == "4.17.20"
        assert pkg["downloadLocation"] == "NOASSERTION"
        assert pkg["filesAnalyzed"] is False

    def test_packages_from_lockfile(self):
        """Lockfile packages produce proper purls."""
        packages = [("lodash", "4.17.21", "npm"), ("requests", "2.31.0", "PyPI")]
        doc = generate_spdx_json(_scan_result(results=[]), packages=packages)
        assert len(doc["packages"]) == 2
        names = {p["name"] for p in doc["packages"]}
        assert names == {"lodash", "requests"}
        # Check purl refs
        for pkg in doc["packages"]:
            purl_refs = [r for r in pkg["externalRefs"] if r["referenceType"] == "purl"]
            assert len(purl_refs) == 1
            assert purl_refs[0]["referenceCategory"] == "PACKAGE-MANAGER"

    def test_deduplication(self):
        """Same package+version from lockfile is not duplicated."""
        packages = [
            ("lodash", "4.17.21", "npm"),
            ("lodash", "4.17.21", "npm"),
        ]
        doc = generate_spdx_json(_scan_result(results=[]), packages=packages)
        assert len(doc["packages"]) == 1

    def test_deduplication_scan_results(self):
        """Same package+version from scan results is not duplicated."""
        v = _vuln(package="lodash", version="4.17.20")
        v2 = _vuln(cve="CVE-2024-5678", package="lodash", version="4.17.20")
        tr1 = _result(vuln=v)
        tr2 = _result(vuln=v2)
        doc = generate_spdx_json(_scan_result(results=[tr1, tr2]))
        assert len(doc["packages"]) == 1

    def test_security_external_refs(self):
        """CVEs appear as SECURITY external references."""
        tr = _result(
            vuln=_vuln(cve="CVE-2024-1234"),
            reasons=[FilterReason.LOW_EPSS],
        )
        doc = generate_spdx_json(_scan_result(results=[tr]))
        pkg = doc["packages"][0]
        sec_refs = [r for r in pkg["externalRefs"] if r["referenceCategory"] == "SECURITY"]
        assert len(sec_refs) == 1
        assert "CVE-2024-1234" in sec_refs[0]["referenceLocator"]
        assert "comment" in sec_refs[0]

    def test_multiple_cves_same_package(self):
        """Multiple CVEs for the same package produce multiple SECURITY refs."""
        v1 = _vuln(cve="CVE-2024-1111", package="lodash", version="4.17.20")
        v2 = _vuln(cve="CVE-2024-2222", package="lodash", version="4.17.20")
        doc = generate_spdx_json(_scan_result(results=[_result(vuln=v1), _result(vuln=v2)]))
        # One package entry with two SECURITY refs
        assert len(doc["packages"]) == 1
        sec_refs = [
            r for r in doc["packages"][0]["externalRefs"] if r["referenceCategory"] == "SECURITY"
        ]
        assert len(sec_refs) == 2

    def test_relationships_describes(self):
        """Every package has a DESCRIBES relationship from the document."""
        packages = [("a", "1.0", "npm"), ("b", "2.0", "PyPI")]
        doc = generate_spdx_json(_scan_result(results=[]), packages=packages)
        assert len(doc["relationships"]) == 2
        for rel in doc["relationships"]:
            assert rel["spdxElementId"] == "SPDXRef-DOCUMENT"
            assert rel["relationshipType"] == "DESCRIBES"

    def test_empty_results(self):
        """Empty scan with no packages produces a valid document."""
        doc = generate_spdx_json(_scan_result(results=[]))
        assert doc["spdxVersion"] == "SPDX-2.3"
        assert doc["packages"] == []
        assert doc["relationships"] == []

    def test_project_name_in_doc(self):
        """Project directory name goes into the document name."""
        doc = generate_spdx_json(_scan_result(project="/home/user/my-app"))
        assert "my-app" in doc["name"]

    def test_no_cve_skips_security_ref(self):
        """A vulnerability with no CVE does not produce a SECURITY ref."""
        v = _vuln(cve="")
        doc = generate_spdx_json(_scan_result(results=[_result(vuln=v)]))
        pkg = doc["packages"][0]
        sec_refs = [r for r in pkg["externalRefs"] if r["referenceCategory"] == "SECURITY"]
        assert len(sec_refs) == 0


# -- write_spdx tests --


class TestWriteSpdx:
    def test_write_creates_valid_json(self, tmp_path: Path):
        out = tmp_path / "sbom.spdx.json"
        write_spdx(_scan_result(), out)
        doc = json.loads(out.read_text())
        assert doc["spdxVersion"] == "SPDX-2.3"
        assert doc["dataLicense"] == "CC0-1.0"

    def test_write_with_packages(self, tmp_path: Path):
        out = tmp_path / "sbom.spdx.json"
        packages = [("lodash", "4.17.21", "npm")]
        write_spdx(_scan_result(), out, packages=packages)
        doc = json.loads(out.read_text())
        assert len(doc["packages"]) >= 1


# -- Integration: write_sbom with fmt="spdx" --


class TestWriteSbomSpdxIntegration:
    def test_write_sbom_spdx_format(self, tmp_path: Path):
        from depquiet.sbom import write_sbom

        out = tmp_path / "out.spdx.json"
        write_sbom(_scan_result(), out, fmt="spdx")
        doc = json.loads(out.read_text())
        assert doc["spdxVersion"] == "SPDX-2.3"

    def test_write_sbom_json_still_cyclonedx(self, tmp_path: Path):
        from depquiet.sbom import write_sbom

        out = tmp_path / "out.json"
        write_sbom(_scan_result(), out, fmt="json")
        doc = json.loads(out.read_text())
        assert doc.get("bomFormat") == "CycloneDX"
