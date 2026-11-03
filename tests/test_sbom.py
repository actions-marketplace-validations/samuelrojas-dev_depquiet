"""Tests for CycloneDX SBOM generation."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from depquiet.models import (
    FilterReason,
    ScanResult,
    Severity,
    TriageResult,
    Verdict,
    Vulnerability,
)
from depquiet.sbom import (
    _make_purl,
    _verdict_to_state,
    generate_cyclonedx_json,
    generate_cyclonedx_xml,
    write_sbom,
)

# -- Fixtures --


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


# -- purl tests --


class TestMakePurl:
    def test_npm_package(self):
        assert _make_purl("lodash", "4.17.21", "npm") == "pkg:npm/lodash@4.17.21"

    def test_npm_scoped_package(self):
        assert _make_purl("@babel/core", "7.24.0", "npm") == "pkg:npm/%40babel/core@7.24.0"

    def test_pypi_package(self):
        assert _make_purl("requests", "2.31.0", "PyPI") == "pkg:pypi/requests@2.31.0"

    def test_go_module(self):
        assert (
            _make_purl("golang.org/x/net", "0.17.0", "Go") == "pkg:golang/golang.org/x/net@0.17.0"
        )

    def test_cargo_crate(self):
        assert _make_purl("serde", "1.0.0", "crates.io") == "pkg:cargo/serde@1.0.0"

    def test_maven_artifact(self):
        assert (
            _make_purl("org.apache/log4j", "2.17.1", "Maven") == "pkg:maven/org.apache/log4j@2.17.1"
        )

    def test_nuget_package(self):
        assert (
            _make_purl("Newtonsoft.Json", "13.0.3", "NuGet") == "pkg:nuget/Newtonsoft.Json@13.0.3"
        )

    def test_rubygems_package(self):
        assert _make_purl("rails", "7.1.0", "RubyGems") == "pkg:gem/rails@7.1.0"

    def test_composer_package(self):
        assert (
            _make_purl("symfony/console", "6.4.0", "Packagist")
            == "pkg:composer/symfony/console@6.4.0"
        )

    def test_pub_package(self):
        assert _make_purl("http", "1.2.0", "Pub") == "pkg:pub/http@1.2.0"

    def test_unknown_ecosystem_lowercased(self):
        assert _make_purl("foo", "1.0.0", "CustomEco") == "pkg:customeco/foo@1.0.0"


# -- verdict mapping --


class TestVerdictToState:
    def test_action_maps_to_exploitable(self):
        tr = _result(verdict=Verdict.ACTION)
        assert _verdict_to_state(tr) == "exploitable"

    def test_review_maps_to_in_triage(self):
        tr = _result(verdict=Verdict.REVIEW)
        assert _verdict_to_state(tr) == "in_triage"

    def test_filtered_with_reasons_maps_to_false_positive(self):
        tr = _result(
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.UNREACHABLE],
        )
        assert _verdict_to_state(tr) == "false_positive"

    def test_filtered_without_reasons_maps_to_not_affected(self):
        tr = _result(verdict=Verdict.FILTERED, reasons=[])
        assert _verdict_to_state(tr) == "not_affected"


# -- JSON generation --


class TestGenerateCycloneDXJson:
    def test_basic_structure(self):
        bom = generate_cyclonedx_json(_scan_result())
        assert bom["bomFormat"] == "CycloneDX"
        assert bom["specVersion"] == "1.5"
        assert bom["version"] == 1
        assert bom["serialNumber"].startswith("urn:uuid:")
        assert "metadata" in bom
        assert "components" in bom

    def test_metadata_tool(self):
        bom = generate_cyclonedx_json(_scan_result())
        tools = bom["metadata"]["tools"]["components"]
        assert len(tools) == 1
        assert tools[0]["name"] == "depquiet"
        assert tools[0]["type"] == "application"

    def test_metadata_component_name_from_path(self):
        bom = generate_cyclonedx_json(_scan_result(project="/home/user/my-app"))
        assert bom["metadata"]["component"]["name"] == "my-app"

    def test_components_from_packages(self):
        packages = [
            ("lodash", "4.17.21", "npm"),
            ("express", "4.18.2", "npm"),
        ]
        bom = generate_cyclonedx_json(_scan_result(), packages=packages)
        assert len(bom["components"]) == 2
        c0 = bom["components"][0]
        assert c0["name"] == "lodash"
        assert c0["version"] == "4.17.21"
        assert c0["purl"] == "pkg:npm/lodash@4.17.21"
        assert c0["type"] == "library"
        assert c0["bom-ref"] == c0["purl"]

    def test_components_deduped(self):
        packages = [
            ("lodash", "4.17.21", "npm"),
            ("lodash", "4.17.21", "npm"),
        ]
        bom = generate_cyclonedx_json(_scan_result(), packages=packages)
        assert len(bom["components"]) == 1

    def test_components_fallback_to_scan_results(self):
        bom = generate_cyclonedx_json(_scan_result())
        assert len(bom["components"]) == 1
        assert bom["components"][0]["name"] == "lodash"

    def test_vulnerabilities_present(self):
        bom = generate_cyclonedx_json(_scan_result())
        assert "vulnerabilities" in bom
        assert len(bom["vulnerabilities"]) == 1
        v = bom["vulnerabilities"][0]
        assert v["id"] == "CVE-2024-1234"
        assert v["description"] == "Prototype pollution"
        assert v["analysis"]["state"] == "exploitable"

    def test_vulnerabilities_with_severity_ratings(self):
        bom = generate_cyclonedx_json(_scan_result())
        v = bom["vulnerabilities"][0]
        assert "ratings" in v
        assert v["ratings"][0]["severity"] == "high"

    def test_vulnerabilities_deduped_by_cve(self):
        results = [
            _result(_vuln(cve="CVE-2024-1234", package="a")),
            _result(_vuln(cve="CVE-2024-1234", package="b")),
        ]
        bom = generate_cyclonedx_json(_scan_result(results=results))
        assert len(bom["vulnerabilities"]) == 1

    def test_empty_results_no_vulnerabilities_key(self):
        bom = generate_cyclonedx_json(_scan_result(results=[]))
        assert "vulnerabilities" not in bom

    def test_vulnerability_without_url_uses_default_source(self):
        vuln = _vuln(url="")
        bom = generate_cyclonedx_json(_scan_result(results=[_result(vuln)]))
        v = bom["vulnerabilities"][0]
        assert "depquiet" in v["source"]["url"]

    def test_filtered_vulnerability_analysis_state(self):
        tr = _result(
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.LOW_EPSS],
        )
        bom = generate_cyclonedx_json(_scan_result(results=[tr]))
        assert bom["vulnerabilities"][0]["analysis"]["state"] == "false_positive"


# -- XML generation --


class TestGenerateCycloneDXXml:
    def test_returns_bytes(self):
        data = generate_cyclonedx_xml(_scan_result())
        assert isinstance(data, bytes)

    def test_valid_xml(self):
        data = generate_cyclonedx_xml(_scan_result())
        root = ET.fromstring(data)
        # Namespace is in the tag
        assert "cyclonedx" in root.tag.lower() or "bom" in root.tag.lower()

    def test_has_components(self):
        data = generate_cyclonedx_xml(_scan_result())
        root = ET.fromstring(data)
        ns = {"cdx": "http://cyclonedx.org/schema/bom/1.5"}
        components = root.findall(".//cdx:component", ns)
        assert len(components) >= 1

    def test_has_vulnerabilities(self):
        data = generate_cyclonedx_xml(_scan_result())
        root = ET.fromstring(data)
        ns = {"cdx": "http://cyclonedx.org/schema/bom/1.5"}
        vulns = root.findall(".//cdx:vulnerability", ns)
        assert len(vulns) == 1

    def test_components_from_packages(self):
        packages = [("requests", "2.31.0", "PyPI")]
        data = generate_cyclonedx_xml(_scan_result(), packages=packages)
        root = ET.fromstring(data)
        ns = {"cdx": "http://cyclonedx.org/schema/bom/1.5"}
        names = [c.find("cdx:name", ns).text for c in root.findall(".//cdx:component", ns)]
        assert "requests" in names

    def test_empty_results(self):
        data = generate_cyclonedx_xml(_scan_result(results=[]))
        root = ET.fromstring(data)
        ns = {"cdx": "http://cyclonedx.org/schema/bom/1.5"}
        vulns = root.findall(".//cdx:vulnerability", ns)
        assert len(vulns) == 0


# -- write_sbom --


class TestWriteSbom:
    def test_write_json(self, tmp_path: Path):
        out = tmp_path / "sbom.json"
        write_sbom(_scan_result(), out, fmt="json")
        assert out.exists()
        bom = json.loads(out.read_text())
        assert bom["bomFormat"] == "CycloneDX"

    def test_write_xml(self, tmp_path: Path):
        out = tmp_path / "sbom.xml"
        write_sbom(_scan_result(), out, fmt="xml")
        assert out.exists()
        root = ET.fromstring(out.read_bytes())
        assert "bom" in root.tag.lower()

    def test_write_with_packages(self, tmp_path: Path):
        out = tmp_path / "sbom.json"
        packages = [("express", "4.18.2", "npm")]
        write_sbom(_scan_result(), out, fmt="json", packages=packages)
        bom = json.loads(out.read_text())
        assert bom["components"][0]["name"] == "express"

    def test_default_format_is_json(self, tmp_path: Path):
        out = tmp_path / "sbom.cdx"
        write_sbom(_scan_result(), out)
        bom = json.loads(out.read_text())
        assert bom["bomFormat"] == "CycloneDX"
