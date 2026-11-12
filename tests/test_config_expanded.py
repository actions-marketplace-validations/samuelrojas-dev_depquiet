"""Tests for v0.24.0 expanded .depquiet.yaml config support.

Covers: new config keys (fail_on, kev, license, input/output paths),
CLI-config merging semantics, validation of enum values, and end-to-end
CLI integration where config drives feature enablement.
"""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from depquiet.config import Config, load_config

# -- Fixtures --


def _write_config(tmp_path: Path, content: str) -> Path:
    """Write a .depquiet.yaml and return its path."""
    cfg = tmp_path / ".depquiet.yaml"
    cfg.write_text(dedent(content), encoding="utf-8")
    return cfg


# -- Test: Config dataclass defaults --


class TestConfigDefaults:
    def test_new_fields_default_none_or_false(self):
        c = Config()
        assert c.fail_on is None
        assert c.kev is False
        assert c.kev_file is None
        assert c.license is False
        assert c.policy is None
        assert c.ignore is None
        assert c.baseline is None
        assert c.sarif is None
        assert c.html is None
        assert c.summary is None
        assert c.sbom is None
        assert c.sbom_format is None
        assert c.vex is None
        assert c.annotations is None

    def test_original_fields_unchanged(self):
        c = Config()
        assert c.epss_threshold is None
        assert c.template_dirs == []
        assert c.always_flag == []
        assert c.offline is False


# -- Test: Parsing new keys --


class TestParseNewKeys:
    def test_fail_on_high(self, tmp_path: Path):
        _write_config(tmp_path, "fail_on: high\n")
        c = load_config(tmp_path)
        assert c.fail_on == "high"

    def test_fail_on_critical(self, tmp_path: Path):
        _write_config(tmp_path, "fail_on: critical\n")
        c = load_config(tmp_path)
        assert c.fail_on == "critical"

    def test_fail_on_none_string(self, tmp_path: Path):
        _write_config(tmp_path, "fail_on: none\n")
        c = load_config(tmp_path)
        assert c.fail_on == "none"

    def test_fail_on_invalid_warns(self, tmp_path: Path, capsys):
        _write_config(tmp_path, "fail_on: banana\n")
        c = load_config(tmp_path)
        assert c.fail_on is None
        assert "invalid fail_on" in capsys.readouterr().err

    def test_kev_true(self, tmp_path: Path):
        _write_config(tmp_path, "kev: true\n")
        c = load_config(tmp_path)
        assert c.kev is True

    def test_kev_false_by_default(self, tmp_path: Path):
        _write_config(tmp_path, "epss_threshold: 0.05\n")
        c = load_config(tmp_path)
        assert c.kev is False

    def test_kev_file(self, tmp_path: Path):
        _write_config(tmp_path, "kev_file: data/kev.json\n")
        c = load_config(tmp_path)
        assert c.kev_file == tmp_path / "data/kev.json"

    def test_license_true(self, tmp_path: Path):
        _write_config(tmp_path, "license: true\n")
        c = load_config(tmp_path)
        assert c.license is True

    def test_policy_path(self, tmp_path: Path):
        _write_config(tmp_path, "policy: custom-policy.yaml\n")
        c = load_config(tmp_path)
        assert c.policy == tmp_path / "custom-policy.yaml"

    def test_ignore_path(self, tmp_path: Path):
        _write_config(tmp_path, "ignore: .my-ignore\n")
        c = load_config(tmp_path)
        assert c.ignore == tmp_path / ".my-ignore"

    def test_baseline_path(self, tmp_path: Path):
        _write_config(tmp_path, "baseline: reports/baseline.json\n")
        c = load_config(tmp_path)
        assert c.baseline == tmp_path / "reports/baseline.json"

    def test_sarif_path(self, tmp_path: Path):
        _write_config(tmp_path, "sarif: out/scan.sarif\n")
        c = load_config(tmp_path)
        assert c.sarif == tmp_path / "out/scan.sarif"

    def test_html_path(self, tmp_path: Path):
        _write_config(tmp_path, "html: reports/report.html\n")
        c = load_config(tmp_path)
        assert c.html == tmp_path / "reports/report.html"

    def test_summary_path(self, tmp_path: Path):
        _write_config(tmp_path, "summary: reports/summary.md\n")
        c = load_config(tmp_path)
        assert c.summary == tmp_path / "reports/summary.md"

    def test_sbom_and_format(self, tmp_path: Path):
        _write_config(
            tmp_path,
            """\
            sbom: reports/sbom.cdx.json
            sbom_format: json
            """,
        )
        c = load_config(tmp_path)
        assert c.sbom == tmp_path / "reports/sbom.cdx.json"
        assert c.sbom_format == "json"

    def test_sbom_format_spdx(self, tmp_path: Path):
        _write_config(tmp_path, "sbom_format: spdx\n")
        c = load_config(tmp_path)
        assert c.sbom_format == "spdx"

    def test_sbom_format_invalid_warns(self, tmp_path: Path, capsys):
        _write_config(tmp_path, "sbom_format: csv\n")
        c = load_config(tmp_path)
        assert c.sbom_format is None
        assert "invalid sbom_format" in capsys.readouterr().err

    def test_vex_path(self, tmp_path: Path):
        _write_config(tmp_path, "vex: reports/vex.json\n")
        c = load_config(tmp_path)
        assert c.vex == tmp_path / "reports/vex.json"

    def test_annotations_path(self, tmp_path: Path):
        _write_config(tmp_path, "annotations: reports/annotations.json\n")
        c = load_config(tmp_path)
        assert c.annotations == tmp_path / "reports/annotations.json"


class TestParseFullConfig:
    """Parse a config with every key set."""

    def test_all_keys(self, tmp_path: Path):
        _write_config(
            tmp_path,
            """\
            epss_threshold: 0.05
            offline: true
            always_flag:
              - lodash
            template_dirs:
              - ./templates
            fail_on: high
            kev: true
            kev_file: data/kev.json
            license: true
            policy: my-policy.yaml
            ignore: my-ignore
            baseline: base.json
            sarif: out.sarif
            html: out.html
            summary: out.md
            sbom: out.cdx.json
            sbom_format: json
            vex: out.vex.json
            annotations: out.ann.json
            """,
        )
        c = load_config(tmp_path)
        assert c.epss_threshold == 0.05
        assert c.offline is True
        assert c.always_flag == ["lodash"]
        assert c.fail_on == "high"
        assert c.kev is True
        assert c.kev_file == tmp_path / "data/kev.json"
        assert c.license is True
        assert c.policy == tmp_path / "my-policy.yaml"
        assert c.ignore == tmp_path / "my-ignore"
        assert c.baseline == tmp_path / "base.json"
        assert c.sarif == tmp_path / "out.sarif"
        assert c.html == tmp_path / "out.html"
        assert c.summary == tmp_path / "out.md"
        assert c.sbom == tmp_path / "out.cdx.json"
        assert c.sbom_format == "json"
        assert c.vex == tmp_path / "out.vex.json"
        assert c.annotations == tmp_path / "out.ann.json"


# -- Test: merge_cli semantics --


class TestMergeCli:
    def test_cli_overrides_config_fail_on(self):
        c = Config(fail_on="high")
        m = c.merge_cli(fail_on="critical")
        assert m.fail_on == "critical"

    def test_cli_none_falls_through_to_config(self):
        c = Config(fail_on="high")
        m = c.merge_cli(fail_on=None)
        assert m.fail_on == "high"

    def test_cli_kev_true_overrides_config_false(self):
        c = Config(kev=False)
        m = c.merge_cli(kev=True)
        assert m.kev is True

    def test_config_kev_true_preserved_when_cli_false(self):
        c = Config(kev=True)
        m = c.merge_cli(kev=False)
        assert m.kev is True

    def test_cli_sarif_overrides_config(self):
        c = Config(sarif=Path("config.sarif"))
        m = c.merge_cli(sarif=Path("cli.sarif"))
        assert m.sarif == Path("cli.sarif")

    def test_config_sarif_preserved_when_cli_none(self):
        c = Config(sarif=Path("config.sarif"))
        m = c.merge_cli(sarif=None)
        assert m.sarif == Path("config.sarif")

    def test_cli_license_overrides_config(self):
        c = Config(license=False)
        m = c.merge_cli(license_scan=True)
        assert m.license is True

    def test_config_license_preserved(self):
        c = Config(license=True)
        m = c.merge_cli(license_scan=False)
        assert m.license is True

    def test_cli_policy_overrides_config(self):
        c = Config(policy=Path("a.yaml"))
        m = c.merge_cli(policy=Path("b.yaml"))
        assert m.policy == Path("b.yaml")

    def test_cli_ignore_overrides_config(self):
        c = Config(ignore=Path("a"))
        m = c.merge_cli(ignore=Path("b"))
        assert m.ignore == Path("b")

    def test_cli_baseline_overrides_config(self):
        c = Config(baseline=Path("a.json"))
        m = c.merge_cli(baseline=Path("b.json"))
        assert m.baseline == Path("b.json")

    def test_cli_html_overrides_config(self):
        c = Config(html=Path("a.html"))
        m = c.merge_cli(html=Path("b.html"))
        assert m.html == Path("b.html")

    def test_cli_sbom_format_overrides_config(self):
        c = Config(sbom_format="json")
        m = c.merge_cli(sbom_format="spdx")
        assert m.sbom_format == "spdx"

    def test_cli_vex_overrides_config(self):
        c = Config(vex=Path("a.json"))
        m = c.merge_cli(vex=Path("b.json"))
        assert m.vex == Path("b.json")

    def test_cli_annotations_overrides_config(self):
        c = Config(annotations=Path("a.json"))
        m = c.merge_cli(annotations=Path("b.json"))
        assert m.annotations == Path("b.json")

    def test_cli_kev_file_overrides_config(self):
        c = Config(kev_file=Path("a.json"))
        m = c.merge_cli(kev_file=Path("b.json"))
        assert m.kev_file == Path("b.json")

    def test_full_merge_preserves_all(self):
        """Config values survive when CLI passes nothing."""
        c = Config(
            fail_on="moderate",
            kev=True,
            license=True,
            sarif=Path("s.sarif"),
            html=Path("h.html"),
            summary=Path("sum.md"),
            sbom=Path("sbom.json"),
            sbom_format="spdx",
            vex=Path("v.json"),
            annotations=Path("a.json"),
            policy=Path("p.yaml"),
            ignore=Path("i"),
            baseline=Path("b.json"),
            kev_file=Path("k.json"),
        )
        m = c.merge_cli()
        assert m.fail_on == "moderate"
        assert m.kev is True
        assert m.license is True
        assert m.sarif == Path("s.sarif")
        assert m.html == Path("h.html")
        assert m.summary == Path("sum.md")
        assert m.sbom == Path("sbom.json")
        assert m.sbom_format == "spdx"
        assert m.vex == Path("v.json")
        assert m.annotations == Path("a.json")
        assert m.policy == Path("p.yaml")
        assert m.ignore == Path("i")
        assert m.baseline == Path("b.json")
        assert m.kev_file == Path("k.json")


# -- Test: Empty / missing path values --


class TestEdgeCases:
    def test_empty_path_string_becomes_none(self, tmp_path: Path):
        _write_config(tmp_path, "sarif: ''\n")
        c = load_config(tmp_path)
        assert c.sarif is None

    def test_missing_config_returns_defaults(self, tmp_path: Path):
        c = load_config(tmp_path)
        assert c.fail_on is None
        assert c.kev is False
        assert c.sarif is None

    def test_yml_extension(self, tmp_path: Path):
        cfg = tmp_path / ".depquiet.yml"
        cfg.write_text("fail_on: high\n", encoding="utf-8")
        c = load_config(tmp_path)
        assert c.fail_on == "high"

    def test_explicit_path_overrides_auto_detect(self, tmp_path: Path):
        # Auto-detect file says "high"
        _write_config(tmp_path, "fail_on: high\n")
        # Explicit path says "critical"
        explicit = tmp_path / "custom.yaml"
        explicit.write_text("fail_on: critical\n", encoding="utf-8")
        c = load_config(tmp_path, config_path=explicit)
        assert c.fail_on == "critical"

    def test_case_insensitive_fail_on(self, tmp_path: Path):
        _write_config(tmp_path, "fail_on: HIGH\n")
        c = load_config(tmp_path)
        assert c.fail_on == "high"

    def test_case_insensitive_sbom_format(self, tmp_path: Path):
        _write_config(tmp_path, "sbom_format: JSON\n")
        c = load_config(tmp_path)
        assert c.sbom_format == "json"

    def test_boolean_yes_no(self, tmp_path: Path):
        _write_config(tmp_path, "kev: yes\nlicense: no\n")
        c = load_config(tmp_path)
        assert c.kev is True
        assert c.license is False
