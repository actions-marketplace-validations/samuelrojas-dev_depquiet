"""Tests for .depquiet.yaml configuration file support."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from depquiet.config import Config, load_config


class TestConfigDefaults:
    """Config defaults are sane when no file exists."""

    def test_default_config_values(self) -> None:
        cfg = Config()
        assert cfg.epss_threshold is None
        assert cfg.template_dirs == []
        assert cfg.always_flag == []
        assert cfg.offline is False

    def test_load_config_no_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = load_config(Path(tmp))
            assert cfg.epss_threshold is None
            assert cfg.always_flag == []


class TestConfigParsing:
    """Parse .depquiet.yaml correctly."""

    def test_epss_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / ".depquiet.yaml").write_text("epss_threshold: 0.05\n")
            cfg = load_config(p)
            assert cfg.epss_threshold == 0.05

    def test_always_flag_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / ".depquiet.yaml").write_text("always_flag:\n  - lodash\n  - express\n")
            cfg = load_config(p)
            assert cfg.always_flag == ["lodash", "express"]

    def test_always_flag_inline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / ".depquiet.yaml").write_text('always_flag: ["lodash", "express"]\n')
            cfg = load_config(p)
            assert cfg.always_flag == ["lodash", "express"]

    def test_template_dirs_relative(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / ".depquiet.yaml").write_text("template_dirs:\n  - ./my-templates\n")
            cfg = load_config(p)
            assert cfg.template_dirs == [p / "./my-templates"]

    def test_offline_true(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / ".depquiet.yaml").write_text("offline: true\n")
            cfg = load_config(p)
            assert cfg.offline is True

    def test_offline_yes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / ".depquiet.yaml").write_text("offline: yes\n")
            cfg = load_config(p)
            assert cfg.offline is True

    def test_offline_false(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / ".depquiet.yaml").write_text("offline: false\n")
            cfg = load_config(p)
            assert cfg.offline is False

    def test_yml_extension(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / ".depquiet.yml").write_text("epss_threshold: 0.03\n")
            cfg = load_config(p)
            assert cfg.epss_threshold == 0.03

    def test_yaml_takes_precedence_over_yml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / ".depquiet.yaml").write_text("epss_threshold: 0.01\n")
            (p / ".depquiet.yml").write_text("epss_threshold: 0.09\n")
            cfg = load_config(p)
            assert cfg.epss_threshold == 0.01

    def test_full_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / ".depquiet.yaml").write_text(
                "epss_threshold: 0.05\n"
                "template_dirs:\n"
                "  - ./custom\n"
                "always_flag:\n"
                "  - lodash\n"
                "  - express\n"
                "offline: true\n"
            )
            cfg = load_config(p)
            assert cfg.epss_threshold == 0.05
            assert cfg.template_dirs == [p / "./custom"]
            assert cfg.always_flag == ["lodash", "express"]
            assert cfg.offline is True


class TestConfigErrors:
    """Malformed config files produce warnings, not crashes."""

    def test_invalid_threshold(self, capsys: pytest.CaptureFixture[str]) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / ".depquiet.yaml").write_text("epss_threshold: not_a_number\n")
            cfg = load_config(p)
            assert cfg.epss_threshold is None  # falls back to default
            captured = capsys.readouterr()
            assert "invalid epss_threshold" in captured.err

    def test_empty_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / ".depquiet.yaml").write_text("")
            cfg = load_config(p)
            assert cfg.epss_threshold is None

    def test_unreadable_file(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            config_path = p / ".depquiet.yaml"
            config_path.write_text("epss_threshold: 0.05\n")

            def unreadable(*args: object, **kwargs: object) -> str:
                raise PermissionError("Permission denied")

            monkeypatch.setattr(Path, "read_text", unreadable)
            cfg = load_config(p)
            assert cfg.epss_threshold is None  # fallback
            captured = capsys.readouterr()
            assert "could not read" in captured.err

    def test_single_string_template_dir(self) -> None:
        """template_dirs can be a single string, not a list."""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / ".depquiet.yaml").write_text("template_dirs: ./my-templates\n")
            cfg = load_config(p)
            assert cfg.template_dirs == [p / "./my-templates"]

    def test_single_string_always_flag(self) -> None:
        """always_flag can be a single string, not a list."""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / ".depquiet.yaml").write_text("always_flag: lodash\n")
            cfg = load_config(p)
            assert cfg.always_flag == ["lodash"]


class TestConfigMergeCli:
    """CLI flags override config-file values."""

    def test_cli_overrides_threshold(self) -> None:
        cfg = Config(epss_threshold=0.05)
        merged = cfg.merge_cli(epss_threshold=0.2)
        assert merged.epss_threshold == 0.2

    def test_cli_none_keeps_config(self) -> None:
        cfg = Config(epss_threshold=0.05)
        merged = cfg.merge_cli(epss_threshold=None)
        assert merged.epss_threshold == 0.05

    def test_cli_appends_template_dirs(self) -> None:
        cfg = Config(template_dirs=[Path("/from-config")])
        merged = cfg.merge_cli(template_dirs=[Path("/from-cli")])
        assert Path("/from-config") in merged.template_dirs
        assert Path("/from-cli") in merged.template_dirs

    def test_cli_no_duplicate_dirs(self) -> None:
        shared = Path("/shared")
        cfg = Config(template_dirs=[shared])
        merged = cfg.merge_cli(template_dirs=[shared])
        assert merged.template_dirs.count(shared) == 1

    def test_cli_offline_overrides(self) -> None:
        cfg = Config(offline=False)
        merged = cfg.merge_cli(offline=True)
        assert merged.offline is True

    def test_config_offline_preserved(self) -> None:
        cfg = Config(offline=True)
        merged = cfg.merge_cli(offline=False)
        assert merged.offline is True  # config says offline, CLI doesn't override

    def test_always_flag_preserved(self) -> None:
        cfg = Config(always_flag=["lodash"])
        merged = cfg.merge_cli()
        assert merged.always_flag == ["lodash"]


class TestAlwaysFlagIntegration:
    """always_flag prevents packages from being filtered."""

    def test_always_flag_forces_action(self) -> None:
        from depquiet.engine import scan
        from depquiet.models import Verdict

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            # Create a package.json so npm is detected
            (p / "package.json").write_text('{"dependencies": {"lodash": "4.17.21"}}')

            audit = {
                "auditReportVersion": 2,
                "vulnerabilities": {
                    "lodash": {
                        "name": "lodash",
                        "severity": "low",
                        "isDirect": True,
                        "via": [
                            {
                                "source": 99999,
                                "name": "lodash",
                                "title": "Prototype pollution",
                                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-99999",
                                "severity": "low",
                                "cwe": [],
                                "range": "<4.17.22",
                            }
                        ],
                        "effects": [],
                        "fixAvailable": {"name": "lodash", "version": "4.17.22"},
                    }
                },
            }

            # Without always_flag — low severity + no EPSS would be REVIEW
            result_normal = scan(
                p,
                audit_json=audit,
                skip_epss=True,
            )
            # It should be REVIEW (low severity, no filter reasons)
            assert len(result_normal.results) == 1

            # With always_flag — lodash is forced to ACTION
            result_flagged = scan(
                p,
                audit_json=audit,
                skip_epss=True,
                always_flag=["lodash"],
            )
            assert len(result_flagged.results) == 1
            assert result_flagged.results[0].verdict == Verdict.ACTION
            assert result_flagged.results[0].reasons == []  # no filter reasons


# --- A comment, a typo or a wrong scale must never weaken the configuration --


from depquiet.config import load_config as _load_cfg  # noqa: E402


def _cfg(tmp_path, text):
    (tmp_path / ".depquiet.yaml").write_text(text, encoding="utf-8")
    return _load_cfg(tmp_path)


def test_trailing_comments_are_not_part_of_values(tmp_path):
    cfg = _cfg(
        tmp_path,
        "kev: true  # exploited\nfail_on: high # gate\nalways_flag: [lodash] # core\n"
        "epss_threshold: 0.05 # 5%\n",
    )
    assert (cfg.kev, cfg.fail_on, cfg.always_flag, cfg.epss_threshold) == (
        True,
        "high",
        ["lodash"],
        0.05,
    )


@pytest.mark.parametrize("value", ["5", "10", "-0.1", "5%"])
def test_epss_threshold_outside_0_1_is_rejected(tmp_path, capsys, value):
    assert _cfg(tmp_path, f"epss_threshold: {value}\n").epss_threshold is None
    assert "between 0 and 1" in capsys.readouterr().err


def test_unknown_key_warns(tmp_path, capsys):
    _cfg(tmp_path, "fail-on: high\n")
    err = capsys.readouterr().err
    assert "unknown key(s)" in err and "fail-on" in err


def test_unreadable_bool_warns(tmp_path, capsys):
    assert _cfg(tmp_path, "kev: ture\n").kev is False
    assert "invalid kev" in capsys.readouterr().err


@pytest.mark.parametrize("value", ["5", "1.5", "-1"])
def test_cli_rejects_epss_threshold_outside_0_1(tmp_path, value):
    from depquiet.cli import main

    with pytest.raises(SystemExit) as exc:
        main(["--path", str(tmp_path), "--epss-threshold", value])
    assert exc.value.code == 2
