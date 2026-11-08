"""OpenVEX generation separates automatic priority from product impact."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from depquiet.models import FilterReason, ScanResult, Severity, TriageResult, Verdict, Vulnerability
from depquiet.vex import VexDocument, VexStatement, build_vex, vex_to_json, write_vex


def _finding(verdict: Verdict = Verdict.ACTION) -> TriageResult:
    return TriageResult(Vulnerability("CVE-2024-0001", "lodash", "4.17.20", Severity.HIGH), verdict)


def _result(findings: list[TriageResult] | None = None) -> ScanResult:
    return ScanResult("/app", "npm", 1, [_finding()] if findings is None else findings)


class TestBuildVex:
    def test_metadata_and_defaults(self):
        document = build_vex(_result())
        assert isinstance(document, VexDocument)
        assert document.doc_id.startswith("https://openvex.dev/docs/")
        assert document.author == "depquiet"
        assert document.tooling.startswith("depquiet/")
        assert document.version == 1
        assert document.statements[0].product_id == "pkg:npm/app"

    def test_explicit_metadata_is_preserved(self):
        document = build_vex(
            _result(),
            author="security-team",
            product_id="pkg:npm/my-app@1.0.0",
            timestamp="2024-01-15T00:00:00+00:00",
        )
        assert document.author == "security-team"
        assert document.timestamp == "2024-01-15T00:00:00+00:00"
        assert document.statements[0].product_id == "pkg:npm/my-app@1.0.0"

    @pytest.mark.parametrize("verdict", list(Verdict))
    def test_priority_does_not_establish_product_status(self, verdict):
        finding = _finding(verdict)
        document = build_vex(_result([finding]))
        statement = document.statements[0]
        assert statement.status == "under_investigation"
        assert f"Priority: {verdict.value}." in statement.status_notes
        assert "does not prove" in statement.status_notes
        assert statement.justification is None
        assert statement.impact_statement is None
        assert statement.action_statement is None

    def test_counts_are_assessments_not_priority_counts(self):
        findings = [_finding(verdict) for verdict in Verdict]
        document = build_vex(_result(findings))
        assert len(document.statements) == 3
        assert document.under_investigation == 3
        assert document.affected == document.not_affected == 0

    def test_low_epss_is_a_note_not_a_mitigation(self):
        finding = _finding(Verdict.FILTERED)
        finding.reasons = [FilterReason.LOW_EPSS]
        finding.epss_score = 0.02
        statement = vex_to_json(build_vex(_result([finding])))["statements"][0]
        assert statement["status"] == "under_investigation"
        assert "0.02" in statement["status_notes"]
        assert "justification" not in statement
        assert "impact_statement" not in statement

    def test_subcomponent_identifies_finding_context(self):
        statement = build_vex(_result()).statements[0]
        assert statement.vulnerability_id == "CVE-2024-0001"
        assert statement.subcomponent_id == "pkg:generic/lodash@4.17.20"

    def test_unique_document_ids(self):
        assert build_vex(_result()).doc_id != build_vex(_result()).doc_id

    def test_vulnerability_name_and_reference_are_distinct(self):
        finding = _finding()
        finding.vuln.url = "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"
        statement = vex_to_json(build_vex(_result([finding])))["statements"][0]
        assert statement["vulnerability"] == {
            "name": "CVE-2024-0001",
            "@id": finding.vuln.url,
        }

    def test_missing_advisory_cannot_produce_an_anonymous_statement(self):
        finding = _finding()
        finding.vuln.cve = ""
        with pytest.raises(ValueError, match="vulnerability identifier"):
            build_vex(_result([finding]))

    def test_completed_empty_scan_has_no_statements(self):
        document = build_vex(_result([]))
        assert document.statements == []
        assert document.under_investigation == document.affected == document.not_affected == 0


class TestVexSerialization:
    def test_required_document_fields_and_statement_notes(self):
        document = vex_to_json(build_vex(_result()))
        assert document["@context"] == "https://openvex.dev/ns/v0.2.0"
        assert {"@id", "author", "timestamp", "version", "statements"} <= document.keys()
        assert document["version"] == 1
        statement = document["statements"][0]
        assert statement["vulnerability"]["name"] == "CVE-2024-0001"
        assert "@id" not in statement["vulnerability"]
        assert statement["products"][0]["subcomponents"][0]["@id"] == ("pkg:generic/lodash@4.17.20")
        assert statement["status_notes"]

    @pytest.mark.parametrize("status", ["affected", "not_affected", "fixed"])
    def test_explicit_statements_remain_serializable(self, status):
        statement = VexStatement(
            "CVE-2024-0001",
            status,
            justification="vulnerable_code_not_present" if status == "not_affected" else None,
            impact_statement="Reviewed the released artifact."
            if status == "not_affected"
            else None,
            product_id="pkg:npm/app@1",
            subcomponent_id="pkg:npm/lodash@4.17.20",
            action_statement="Install release 2." if status == "affected" else None,
            status_notes="Explicit assessment supplied by the caller.",
        )
        document = VexDocument(
            "https://example.com/vex", "team", "2024-01-01T00:00:00Z", [statement]
        )
        document.version = 2
        serialized = vex_to_json(document)
        assert serialized["version"] == 2
        actual = serialized["statements"][0]
        assert actual["status"] == status
        assert actual["status_notes"] == statement.status_notes
        if status == "not_affected":
            assert actual["justification"] == statement.justification
            assert actual["impact_statement"] == statement.impact_statement
        elif status == "affected":
            assert actual["action_statement"] == statement.action_statement

    def test_write_utf8_document(self, tmp_path: Path):
        document = build_vex(_result(), author="Equipo de investigación")
        output = tmp_path / "vex.json"
        write_vex(document, output)
        parsed = json.loads(output.read_text(encoding="utf-8"))
        assert parsed["author"] == "Equipo de investigación"
        assert len(parsed["statements"]) == 1
