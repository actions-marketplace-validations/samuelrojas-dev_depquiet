"""Tests for OpenVEX document generation."""

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
from depquiet.vex import (
    _CONTEXT,
    _JUSTIFICATION_MAP,
    _STATUS_MAP,
    VexDocument,
    build_vex,
    vex_to_json,
    write_vex,
)

# ── helpers ──────────────────────────────────────────────────────────


def _vuln(
    cve: str = "CVE-2024-0001",
    pkg: str = "lodash",
    ver: str = "4.17.20",
    severity: Severity = Severity.HIGH,
    fix: str = "4.17.21",
    **kw,
) -> Vulnerability:
    return Vulnerability(
        cve=cve,
        package=pkg,
        version=ver,
        severity=severity,
        title=f"Test vuln in {pkg}",
        fix_version=fix,
        **kw,
    )


def _result(
    trs: list[TriageResult] | None = None,
    project: str = "/app",
    manager: str = "npm",
) -> ScanResult:
    if trs is None:
        trs = [
            TriageResult(vuln=_vuln(), verdict=Verdict.ACTION),
            TriageResult(
                vuln=_vuln("CVE-2024-0002", "express", "4.18.0"),
                verdict=Verdict.FILTERED,
                reasons=[FilterReason.LOW_EPSS],
                epss_score=0.02,
            ),
            TriageResult(
                vuln=_vuln("CVE-2024-0003", "debug", "4.3.0"),
                verdict=Verdict.REVIEW,
            ),
        ]
    return ScanResult(
        project_path=project,
        package_manager=manager,
        total_dependencies=42,
        results=trs,
    )


# ── status mapping ──────────────────────────────────────────────────


class TestStatusMapping:
    def test_action_maps_to_affected(self):
        assert _STATUS_MAP[Verdict.ACTION.value] == "affected"

    def test_review_maps_to_under_investigation(self):
        assert _STATUS_MAP[Verdict.REVIEW.value] == "under_investigation"

    def test_filtered_maps_to_not_affected(self):
        assert _STATUS_MAP[Verdict.FILTERED.value] == "not_affected"


# ── justification mapping ───────────────────────────────────────────


class TestJustificationMapping:
    def test_unreachable(self):
        assert (
            _JUSTIFICATION_MAP[FilterReason.UNREACHABLE.value]
            == "vulnerable_code_not_in_execute_path"
        )

    def test_dev_dependency(self):
        assert (
            _JUSTIFICATION_MAP[FilterReason.DEV_DEPENDENCY.value]
            == "vulnerable_code_not_in_execute_path"
        )

    def test_low_epss(self):
        assert _JUSTIFICATION_MAP[FilterReason.LOW_EPSS.value] == "inline_mitigations_already_exist"

    def test_community_template(self):
        assert _JUSTIFICATION_MAP[FilterReason.COMMUNITY_TEMPLATE.value] == "component_not_present"

    def test_ignored(self):
        assert _JUSTIFICATION_MAP[FilterReason.IGNORED.value] == "vulnerability_not_exploitable"


# ── build_vex ────────────────────────────────────────────────────────


class TestBuildVex:
    def test_returns_vex_document(self):
        doc = build_vex(_result())
        assert isinstance(doc, VexDocument)

    def test_statement_count_matches_results(self):
        doc = build_vex(_result())
        assert len(doc.statements) == 3

    def test_default_product_id(self):
        doc = build_vex(_result())
        assert doc.statements[0].product_id == "pkg:npm/app"

    def test_custom_product_id(self):
        doc = build_vex(_result(), product_id="pkg:npm/my-app@1.0.0")
        assert doc.statements[0].product_id == "pkg:npm/my-app@1.0.0"

    def test_custom_author(self):
        doc = build_vex(_result(), author="security-team")
        assert doc.author == "security-team"

    def test_custom_timestamp(self):
        ts = "2024-01-15T00:00:00+00:00"
        doc = build_vex(_result(), timestamp=ts)
        assert doc.timestamp == ts

    def test_tooling_includes_version(self):
        doc = build_vex(_result())
        assert doc.tooling.startswith("depquiet/")

    def test_doc_id_is_openvex_uri(self):
        doc = build_vex(_result())
        assert doc.doc_id.startswith("https://openvex.dev/docs/")

    def test_counts_are_correct(self):
        doc = build_vex(_result())
        assert doc.affected == 1
        assert doc.under_investigation == 1
        assert doc.not_affected == 1


# ── statement generation ─────────────────────────────────────────────


class TestStatementGeneration:
    def test_action_becomes_affected(self):
        tr = TriageResult(vuln=_vuln(), verdict=Verdict.ACTION)
        doc = build_vex(_result([tr]))
        assert doc.statements[0].status == "affected"

    def test_review_becomes_under_investigation(self):
        tr = TriageResult(vuln=_vuln(), verdict=Verdict.REVIEW)
        doc = build_vex(_result([tr]))
        assert doc.statements[0].status == "under_investigation"

    def test_filtered_becomes_not_affected(self):
        tr = TriageResult(
            vuln=_vuln(),
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.UNREACHABLE],
        )
        doc = build_vex(_result([tr]))
        assert doc.statements[0].status == "not_affected"

    def test_vulnerability_id_is_cve(self):
        tr = TriageResult(vuln=_vuln("CVE-2024-9999"), verdict=Verdict.ACTION)
        doc = build_vex(_result([tr]))
        assert doc.statements[0].vulnerability_id == "CVE-2024-9999"

    def test_subcomponent_is_purl(self):
        tr = TriageResult(vuln=_vuln(pkg="lodash", ver="4.17.20"), verdict=Verdict.ACTION)
        doc = build_vex(_result([tr]))
        assert doc.statements[0].subcomponent_id == "pkg:generic/lodash@4.17.20"


# ── justifications for not_affected ──────────────────────────────────


class TestJustifications:
    def test_unreachable_justification(self):
        tr = TriageResult(
            vuln=_vuln(),
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.UNREACHABLE],
        )
        doc = build_vex(_result([tr]))
        assert doc.statements[0].justification == "vulnerable_code_not_in_execute_path"

    def test_dev_dependency_justification(self):
        tr = TriageResult(
            vuln=_vuln(),
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.DEV_DEPENDENCY],
        )
        doc = build_vex(_result([tr]))
        assert doc.statements[0].justification == "vulnerable_code_not_in_execute_path"

    def test_low_epss_justification(self):
        tr = TriageResult(
            vuln=_vuln(),
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.LOW_EPSS],
            epss_score=0.02,
        )
        doc = build_vex(_result([tr]))
        assert doc.statements[0].justification == "inline_mitigations_already_exist"

    def test_community_template_justification(self):
        tr = TriageResult(
            vuln=_vuln(),
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.COMMUNITY_TEMPLATE],
        )
        doc = build_vex(_result([tr]))
        assert doc.statements[0].justification == "component_not_present"

    def test_ignored_justification(self):
        tr = TriageResult(
            vuln=_vuln(),
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.IGNORED],
        )
        doc = build_vex(_result([tr]))
        assert doc.statements[0].justification == "vulnerability_not_exploitable"

    def test_no_justification_for_affected(self):
        tr = TriageResult(vuln=_vuln(), verdict=Verdict.ACTION)
        doc = build_vex(_result([tr]))
        assert doc.statements[0].justification is None

    def test_no_justification_for_under_investigation(self):
        tr = TriageResult(vuln=_vuln(), verdict=Verdict.REVIEW)
        doc = build_vex(_result([tr]))
        assert doc.statements[0].justification is None


# ── impact statements ────────────────────────────────────────────────


class TestImpactStatements:
    def test_unreachable_impact(self):
        tr = TriageResult(
            vuln=_vuln(),
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.UNREACHABLE],
        )
        doc = build_vex(_result([tr]))
        assert "not reachable" in doc.statements[0].impact_statement

    def test_dev_dependency_impact(self):
        tr = TriageResult(
            vuln=_vuln(),
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.DEV_DEPENDENCY],
        )
        doc = build_vex(_result([tr]))
        assert "development-only" in doc.statements[0].impact_statement

    def test_low_epss_impact_includes_score(self):
        tr = TriageResult(
            vuln=_vuln(),
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.LOW_EPSS],
            epss_score=0.02,
        )
        doc = build_vex(_result([tr]))
        assert "2.0%" in doc.statements[0].impact_statement

    def test_multiple_reasons_joined(self):
        tr = TriageResult(
            vuln=_vuln(),
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.DEV_DEPENDENCY, FilterReason.LOW_EPSS],
            epss_score=0.01,
        )
        doc = build_vex(_result([tr]))
        impact = doc.statements[0].impact_statement
        assert "development-only" in impact
        assert "exploitation probability" in impact
        assert ";" in impact

    def test_no_impact_for_affected(self):
        tr = TriageResult(vuln=_vuln(), verdict=Verdict.ACTION)
        doc = build_vex(_result([tr]))
        assert doc.statements[0].impact_statement is None


# ── action statements ────────────────────────────────────────────────


class TestActionStatements:
    def test_action_statement_for_affected(self):
        tr = TriageResult(vuln=_vuln(fix="4.17.21"), verdict=Verdict.ACTION)
        doc = build_vex(_result([tr]))
        assert "Update lodash to 4.17.21" in doc.statements[0].action_statement

    def test_action_without_fix_version(self):
        tr = TriageResult(vuln=_vuln(fix=""), verdict=Verdict.ACTION)
        doc = build_vex(_result([tr]))
        assert "Update lodash." in doc.statements[0].action_statement

    def test_action_with_high_epss(self):
        tr = TriageResult(
            vuln=_vuln(),
            verdict=Verdict.ACTION,
            epss_score=0.85,
        )
        doc = build_vex(_result([tr]))
        assert "85.0%" in doc.statements[0].action_statement

    def test_action_with_kev(self):
        from types import SimpleNamespace

        kev = SimpleNamespace(
            date_added="2024-01-01",
            due_date="2024-01-15",
            required_action="Apply update.",
            ransomware_use="Known",
        )
        tr = TriageResult(vuln=_vuln(), verdict=Verdict.ACTION, kev_entry=kev)
        doc = build_vex(_result([tr]))
        assert "CISA" in doc.statements[0].action_statement

    def test_no_action_for_filtered(self):
        tr = TriageResult(
            vuln=_vuln(),
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.LOW_EPSS],
        )
        doc = build_vex(_result([tr]))
        assert doc.statements[0].action_statement is None


# ── JSON serialization ───────────────────────────────────────────────


class TestVexToJson:
    def test_context_is_openvex(self):
        doc = build_vex(_result())
        data = vex_to_json(doc)
        assert data["@context"] == _CONTEXT

    def test_id_is_present(self):
        doc = build_vex(_result())
        data = vex_to_json(doc)
        assert "@id" in data

    def test_author_is_present(self):
        doc = build_vex(_result())
        data = vex_to_json(doc)
        assert data["author"] == "depquiet"

    def test_timestamp_is_present(self):
        ts = "2024-06-01T12:00:00+00:00"
        doc = build_vex(_result(), timestamp=ts)
        data = vex_to_json(doc)
        assert data["timestamp"] == ts

    def test_tooling_is_present(self):
        doc = build_vex(_result())
        data = vex_to_json(doc)
        assert "depquiet" in data["tooling"]

    def test_statements_structure(self):
        tr = TriageResult(vuln=_vuln("CVE-2024-0001"), verdict=Verdict.ACTION)
        doc = build_vex(_result([tr]))
        data = vex_to_json(doc)
        stmt = data["statements"][0]
        assert stmt["vulnerability"]["@id"] == "CVE-2024-0001"
        assert stmt["status"] == "affected"
        assert len(stmt["products"]) == 1

    def test_products_contain_subcomponents(self):
        tr = TriageResult(vuln=_vuln(pkg="lodash", ver="4.17.20"), verdict=Verdict.ACTION)
        doc = build_vex(_result([tr]))
        data = vex_to_json(doc)
        product = data["statements"][0]["products"][0]
        assert len(product["subcomponents"]) == 1
        assert product["subcomponents"][0]["@id"] == "pkg:generic/lodash@4.17.20"

    def test_justification_in_not_affected(self):
        tr = TriageResult(
            vuln=_vuln(),
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.UNREACHABLE],
        )
        doc = build_vex(_result([tr]))
        data = vex_to_json(doc)
        assert "justification" in data["statements"][0]

    def test_no_justification_in_affected(self):
        tr = TriageResult(vuln=_vuln(), verdict=Verdict.ACTION)
        doc = build_vex(_result([tr]))
        data = vex_to_json(doc)
        assert "justification" not in data["statements"][0]

    def test_action_statement_in_affected(self):
        tr = TriageResult(vuln=_vuln(), verdict=Verdict.ACTION)
        doc = build_vex(_result([tr]))
        data = vex_to_json(doc)
        assert "action_statement" in data["statements"][0]

    def test_roundtrip_valid_json(self):
        doc = build_vex(_result())
        data = vex_to_json(doc)
        text = json.dumps(data, indent=2)
        parsed = json.loads(text)
        assert parsed["@context"] == _CONTEXT
        assert len(parsed["statements"]) == 3


# ── file output ──────────────────────────────────────────────────────


class TestWriteVex:
    def test_writes_file(self, tmp_path: Path):
        doc = build_vex(_result())
        out = tmp_path / "vex.json"
        write_vex(doc, out)
        assert out.exists()

    def test_file_is_valid_json(self, tmp_path: Path):
        doc = build_vex(_result())
        out = tmp_path / "vex.json"
        write_vex(doc, out)
        data = json.loads(out.read_text())
        assert data["@context"] == _CONTEXT

    def test_file_has_all_statements(self, tmp_path: Path):
        doc = build_vex(_result())
        out = tmp_path / "vex.json"
        write_vex(doc, out)
        data = json.loads(out.read_text())
        assert len(data["statements"]) == 3


# ── edge cases ───────────────────────────────────────────────────────


class TestEdgeCases:
    def test_empty_results(self):
        doc = build_vex(_result([]))
        assert len(doc.statements) == 0
        assert doc.affected == 0
        assert doc.not_affected == 0

    def test_all_filtered(self):
        trs = [
            TriageResult(
                vuln=_vuln(f"CVE-2024-{i:04d}"),
                verdict=Verdict.FILTERED,
                reasons=[FilterReason.LOW_EPSS],
                epss_score=0.01,
            )
            for i in range(5)
        ]
        doc = build_vex(_result(trs))
        assert doc.not_affected == 5
        assert doc.affected == 0

    def test_all_action(self):
        trs = [
            TriageResult(vuln=_vuln(f"CVE-2024-{i:04d}"), verdict=Verdict.ACTION) for i in range(3)
        ]
        doc = build_vex(_result(trs))
        assert doc.affected == 3
        assert doc.not_affected == 0

    def test_pip_manager(self):
        doc = build_vex(_result(manager="pip"))
        assert doc.statements[0].product_id == "pkg:pip/app"

    def test_unique_doc_ids(self):
        doc1 = build_vex(_result())
        doc2 = build_vex(_result())
        assert doc1.doc_id != doc2.doc_id
