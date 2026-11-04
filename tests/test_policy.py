"""Tests for the policy engine."""

from __future__ import annotations

from pathlib import Path

from depquiet.models import (
    Severity,
    TriageResult,
    Verdict,
    Vulnerability,
)
from depquiet.policy import Policy, PolicyRule, _parse_severities, load_policy

# -- Fixtures --


def _vuln(
    cve: str = "CVE-2024-1234",
    package: str = "lodash",
    version: str = "4.17.20",
    severity: Severity = Severity.HIGH,
    is_dev: bool = False,
    fix_version: str = "",
) -> Vulnerability:
    return Vulnerability(
        cve=cve,
        package=package,
        version=version,
        severity=severity,
        is_dev=is_dev,
        fix_version=fix_version,
    )


def _tr(
    vuln: Vulnerability | None = None,
    verdict: Verdict = Verdict.REVIEW,
    epss_score: float | None = None,
) -> TriageResult:
    return TriageResult(
        vuln=vuln or _vuln(),
        verdict=verdict,
        epss_score=epss_score,
    )


# -- PolicyRule.matches --


class TestPolicyRuleMatches:
    def test_empty_rule_matches_everything(self):
        rule = PolicyRule(id="all", action=Verdict.ACTION)
        assert rule.matches(_tr())

    def test_severity_match(self):
        rule = PolicyRule(id="crit", action=Verdict.ACTION, severity=[Severity.CRITICAL])
        assert not rule.matches(_tr(_vuln(severity=Severity.HIGH)))
        assert rule.matches(_tr(_vuln(severity=Severity.CRITICAL)))

    def test_severity_list_match(self):
        rule = PolicyRule(id="low", action=Verdict.FILTERED, severity=[Severity.LOW, Severity.INFO])
        assert rule.matches(_tr(_vuln(severity=Severity.LOW)))
        assert rule.matches(_tr(_vuln(severity=Severity.INFO)))
        assert not rule.matches(_tr(_vuln(severity=Severity.HIGH)))

    def test_package_match(self):
        rule = PolicyRule(id="pkg", action=Verdict.ACTION, packages=["express", "lodash"])
        assert rule.matches(_tr(_vuln(package="lodash")))
        assert rule.matches(_tr(_vuln(package="express")))
        assert not rule.matches(_tr(_vuln(package="react")))

    def test_epss_below_match(self):
        rule = PolicyRule(id="low-epss", action=Verdict.FILTERED, epss_below=0.01)
        assert rule.matches(_tr(epss_score=0.005))
        assert not rule.matches(_tr(epss_score=0.05))
        assert not rule.matches(_tr(epss_score=None))

    def test_epss_above_match(self):
        rule = PolicyRule(id="high-epss", action=Verdict.ACTION, epss_above=0.5)
        assert rule.matches(_tr(epss_score=0.8))
        assert not rule.matches(_tr(epss_score=0.3))
        assert not rule.matches(_tr(epss_score=None))

    def test_is_dev_match(self):
        rule = PolicyRule(id="dev", action=Verdict.FILTERED, is_dev=True)
        assert rule.matches(_tr(_vuln(is_dev=True)))
        assert not rule.matches(_tr(_vuln(is_dev=False)))

    def test_has_fix_match(self):
        rule = PolicyRule(id="fix", action=Verdict.ACTION, has_fix=True)
        assert rule.matches(_tr(_vuln(fix_version="4.17.21")))
        assert not rule.matches(_tr(_vuln(fix_version="")))

    def test_cve_match(self):
        rule = PolicyRule(id="cve", action=Verdict.ACTION, cves=["CVE-2024-1234"])
        assert rule.matches(_tr(_vuln(cve="CVE-2024-1234")))
        assert not rule.matches(_tr(_vuln(cve="CVE-2024-9999")))

    def test_multiple_conditions_and_logic(self):
        """All conditions must match (AND logic)."""
        rule = PolicyRule(
            id="strict",
            action=Verdict.ACTION,
            severity=[Severity.CRITICAL],
            packages=["express"],
        )
        # Both match
        assert rule.matches(_tr(_vuln(severity=Severity.CRITICAL, package="express")))
        # Only severity matches
        assert not rule.matches(_tr(_vuln(severity=Severity.CRITICAL, package="lodash")))
        # Only package matches
        assert not rule.matches(_tr(_vuln(severity=Severity.HIGH, package="express")))


# -- Policy.apply --


class TestPolicyApply:
    def test_no_rules_returns_original_verdict(self):
        policy = Policy(rules=[])
        tr = _tr(verdict=Verdict.REVIEW)
        verdict, rule_id = policy.apply(tr)
        assert verdict == Verdict.REVIEW
        assert rule_id is None

    def test_first_matching_rule_wins(self):
        policy = Policy(
            rules=[
                PolicyRule(id="first", action=Verdict.ACTION, severity=[Severity.CRITICAL]),
                PolicyRule(id="second", action=Verdict.FILTERED),
            ]
        )
        tr = _tr(_vuln(severity=Severity.HIGH))
        verdict, rule_id = policy.apply(tr)
        # first rule doesn't match (HIGH != CRITICAL), second matches all
        assert verdict == Verdict.FILTERED
        assert rule_id == "second"

    def test_matching_rule_overrides_verdict(self):
        policy = Policy(
            rules=[
                PolicyRule(
                    id="block-critical", action=Verdict.ACTION, severity=[Severity.CRITICAL]
                ),
            ]
        )
        tr = _tr(_vuln(severity=Severity.CRITICAL), verdict=Verdict.FILTERED)
        verdict, rule_id = policy.apply(tr)
        assert verdict == Verdict.ACTION
        assert rule_id == "block-critical"

    def test_no_match_preserves_verdict(self):
        policy = Policy(
            rules=[
                PolicyRule(id="only-crit", action=Verdict.ACTION, severity=[Severity.CRITICAL]),
            ]
        )
        tr = _tr(_vuln(severity=Severity.LOW), verdict=Verdict.REVIEW)
        verdict, rule_id = policy.apply(tr)
        assert verdict == Verdict.REVIEW
        assert rule_id is None


# -- _parse_severities --


class TestParseSeverities:
    def test_single_string(self):
        result = _parse_severities("critical")
        assert result == [Severity.CRITICAL]

    def test_list_of_strings(self):
        result = _parse_severities(["high", "critical"])
        assert set(result) == {Severity.HIGH, Severity.CRITICAL}

    def test_unknown_severity_skipped(self):
        result = _parse_severities(["high", "unknown", "low"])
        assert set(result) == {Severity.HIGH, Severity.LOW}

    def test_all_unknown_returns_none(self):
        result = _parse_severities(["nope"])
        assert result is None


# -- load_policy --


class TestLoadPolicy:
    def test_load_from_explicit_path(self, tmp_path: Path):
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(
            "rules:\n  - id: block-critical\n    action: action\n    severity: critical\n"
        )
        policy = load_policy(tmp_path, policy_path=policy_file)
        assert policy is not None
        assert len(policy.rules) == 1
        assert policy.rules[0].id == "block-critical"
        assert policy.rules[0].action == Verdict.ACTION

    def test_load_from_project_root(self, tmp_path: Path):
        policy_file = tmp_path / ".depquiet-policy.yaml"
        policy_file.write_text("rules:\n  - id: test\n    action: filter\n")
        policy = load_policy(tmp_path)
        assert policy is not None
        assert len(policy.rules) == 1

    def test_no_policy_file_returns_none(self, tmp_path: Path):
        policy = load_policy(tmp_path)
        assert policy is None

    def test_missing_explicit_path_returns_none(self, tmp_path: Path):
        policy = load_policy(tmp_path, policy_path=tmp_path / "nope.yaml")
        assert policy is None

    def test_action_aliases(self, tmp_path: Path):
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(
            "rules:\n"
            "  - id: r1\n"
            "    action: block\n"
            "  - id: r2\n"
            "    action: dismiss\n"
            "  - id: r3\n"
            "    action: ignore\n"
            "  - id: r4\n"
            "    action: filtered\n"
        )
        policy = load_policy(tmp_path, policy_path=policy_file)
        assert policy is not None
        assert policy.rules[0].action == Verdict.ACTION
        assert policy.rules[1].action == Verdict.FILTERED
        assert policy.rules[2].action == Verdict.FILTERED
        assert policy.rules[3].action == Verdict.FILTERED

    def test_invalid_action_skipped(self, tmp_path: Path):
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(
            "rules:\n  - id: bad\n    action: explode\n  - id: good\n    action: action\n"
        )
        policy = load_policy(tmp_path, policy_path=policy_file)
        assert policy is not None
        assert len(policy.rules) == 1
        assert policy.rules[0].id == "good"

    def test_match_section_parsing(self, tmp_path: Path):
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(
            "rules:\n"
            "  - id: complex\n"
            "    action: filter\n"
            "    is_dev: true\n"
            "    has_fix: false\n"
            "    epss_below: 0.05\n"
        )
        policy = load_policy(tmp_path, policy_path=policy_file)
        assert policy is not None
        rule = policy.rules[0]
        assert rule.is_dev is True
        assert rule.has_fix is False
        assert rule.epss_below == 0.05

    def test_yml_extension(self, tmp_path: Path):
        policy_file = tmp_path / ".depquiet-policy.yml"
        policy_file.write_text("rules:\n  - id: test\n    action: review\n")
        policy = load_policy(tmp_path)
        assert policy is not None
        assert policy.rules[0].action == Verdict.REVIEW


# -- Engine integration --


class TestPolicyEngineIntegration:
    def test_policy_overrides_verdict(self, tmp_path: Path):
        """Policy can escalate a would-be-filtered vuln to ACTION."""
        from unittest.mock import patch

        from depquiet.engine import scan
        from depquiet.policy import Policy, PolicyRule

        # Create a minimal project with package-lock.json so npm is detected
        (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 2, "packages": {}}')
        (tmp_path / "package.json").write_text("{}")

        policy = Policy(
            rules=[
                PolicyRule(
                    id="block-all-critical",
                    action=Verdict.ACTION,
                    severity=[Severity.CRITICAL],
                ),
            ]
        )

        # Mock npm audit to return a critical vuln that would normally be filtered
        crit_vuln = Vulnerability(
            cve="CVE-2024-9999",
            package="fake-pkg",
            version="1.0.0",
            severity=Severity.CRITICAL,
            is_dev=True,  # Would normally be filtered by dev dep filter
        )

        with (
            patch("depquiet.engine._run_scanner", return_value=([crit_vuln], "npm", "")),
            patch("depquiet.engine.EpssFilter.lookup"),
        ):
            result = scan(tmp_path, skip_epss=True, policy=policy)

        # Policy should escalate from FILTERED to ACTION
        assert len(result.results) == 1
        assert result.results[0].verdict == Verdict.ACTION
