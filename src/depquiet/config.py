"""Configuration file support — .depquiet.yaml in the project root.

Lets teams commit their triage preferences alongside the code.  CLI flags
override config-file values, so CI can tighten thresholds without changing
the checked-in config.

Supported keys::

    # Triage tuning
    epss_threshold: 0.05        # filter alerts with EPSS below 5% (default: off)
    offline: false              # skip EPSS API (default: false)
    always_flag:                # packages that must never be filtered
      - lodash
      - express
    template_dirs:              # extra template directories (relative to project)
      - ./my-templates

    # CI gate
    fail_on: high               # severity threshold: critical | high | moderate | low | none

    # Integrations
    kev: true                   # check CISA KEV catalog
    license: true               # run license compliance analysis

    # Input overrides
    policy: .depquiet-policy.yaml   # policy file path (relative to project)
    ignore: .depquiet-ignore        # ignore file path
    baseline: reports/baseline.json # baseline scan for diffing

    # Output files (relative to project root)
    sarif: reports/depquiet.sarif
    html: reports/depquiet.html
    summary: reports/summary.md
    sbom: reports/sbom.cdx.json
    sbom_format: json           # json | xml | spdx
    vex: reports/vex.json
    annotations: reports/annotations.json

Every key is optional.  CLI flags always win when explicitly passed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from depquiet.filters.templates import _parse_yaml_simple
from depquiet.finding_identity import validate_project_id


@dataclass
class Config:
    """Parsed depquiet configuration."""

    # Triage tuning
    epss_threshold: float | None = None
    template_dirs: list[Path] = field(default_factory=list)
    always_flag: list[str] = field(default_factory=list)
    offline: bool = False

    # CI gate
    fail_on: str | None = None  # "critical" | "high" | "moderate" | "low" | "none"

    # Integrations
    kev: bool = False
    kev_file: Path | None = None
    license: bool = False

    # Input paths
    policy: Path | None = None
    ignore: Path | None = None
    baseline: Path | None = None

    # Output paths
    sarif: Path | None = None
    html: Path | None = None
    summary: Path | None = None
    sbom: Path | None = None
    sbom_format: str | None = None  # "json" | "xml" | "spdx"
    vex: Path | None = None
    annotations: Path | None = None
    project_id: str = ""

    def merge_cli(
        self,
        *,
        epss_threshold: float | None = None,
        template_dirs: list[Path] | None = None,
        offline: bool = False,
        fail_on: str | None = None,
        kev: bool = False,
        kev_file: Path | None = None,
        license_scan: bool = False,
        policy: Path | None = None,
        ignore: Path | None = None,
        baseline: Path | None = None,
        sarif: Path | None = None,
        html: Path | None = None,
        summary: Path | None = None,
        sbom: Path | None = None,
        sbom_format: str | None = None,
        vex: Path | None = None,
        annotations: Path | None = None,
        project_id: str | None = None,
    ) -> Config:
        """Return a new Config with CLI overrides applied.

        CLI flags win over config-file values.  ``None`` / ``False`` means
        "not specified on the CLI" and falls through to the config value.
        Lists (template_dirs) are appended so both sources contribute.
        """
        merged_templates = list(self.template_dirs)
        if template_dirs:
            for d in template_dirs:
                if d not in merged_templates:
                    merged_templates.append(d)

        return Config(
            # Triage
            epss_threshold=epss_threshold if epss_threshold is not None else self.epss_threshold,
            template_dirs=merged_templates,
            always_flag=list(self.always_flag),
            offline=offline or self.offline,
            # CI gate
            fail_on=fail_on if fail_on is not None else self.fail_on,
            # Integrations
            kev=kev or self.kev,
            kev_file=kev_file if kev_file is not None else self.kev_file,
            license=license_scan or self.license,
            # Input paths (CLI wins if set)
            policy=policy if policy is not None else self.policy,
            ignore=ignore if ignore is not None else self.ignore,
            baseline=baseline if baseline is not None else self.baseline,
            # Output paths (CLI wins if set)
            sarif=sarif if sarif is not None else self.sarif,
            html=html if html is not None else self.html,
            summary=summary if summary is not None else self.summary,
            sbom=sbom if sbom is not None else self.sbom,
            sbom_format=sbom_format if sbom_format is not None else self.sbom_format,
            vex=vex if vex is not None else self.vex,
            annotations=annotations if annotations is not None else self.annotations,
            project_id=project_id if project_id is not None else self.project_id,
        )


_CONFIG_NAMES = (".depquiet.yaml", ".depquiet.yml")

_VALID_FAIL_ON = {"critical", "high", "moderate", "low", "none"}
_KNOWN_KEYS = {
    "epss_threshold",
    "offline",
    "always_flag",
    "template_dirs",
    "fail_on",
    "kev",
    "kev_file",
    "license",
    "policy",
    "ignore",
    "baseline",
    "sarif",
    "html",
    "summary",
    "sbom",
    "sbom_format",
    "vex",
    "annotations",
    "project_id",
}
_VALID_SBOM_FORMATS = {"json", "xml", "spdx"}


def load_config(project: Path, *, config_path: Path | None = None) -> Config:
    """Load .depquiet.yaml from the project root (or *config_path*).

    Returns the default Config if no config file exists or if the file
    is malformed (with a warning to stderr).
    """
    if config_path is not None:
        if config_path.is_file():
            return _parse_config(config_path, project)
        import sys

        print(f"Warning: config file not found: {config_path}", file=sys.stderr)
        return Config()

    for name in _CONFIG_NAMES:
        candidate = project / name
        if candidate.is_file():
            return _parse_config(candidate, project)

    return Config()


def _parse_config(path: Path, project: Path) -> Config:
    """Parse a .depquiet.yaml file into a Config."""
    import sys

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Warning: could not read {path}: {exc}", file=sys.stderr)
        return Config()

    try:
        data = _parse_yaml_simple(text)
    except Exception:
        print(f"Warning: invalid YAML in {path}", file=sys.stderr)
        return Config()

    # --- Triage tuning ---

    unknown = sorted(set(data) - _KNOWN_KEYS)
    if unknown:
        print(
            f"Warning: unknown key(s) in {path} ignored: {', '.join(unknown)} "
            "(keys use underscores: fail_on, epss_threshold, always_flag, ...)",
            file=sys.stderr,
        )

    epss_threshold: float | None = None
    raw_threshold = data.get("epss_threshold")
    if raw_threshold is not None:
        try:
            value = float(str(raw_threshold))
        except (TypeError, ValueError):
            value = -1.0
        if 0.0 <= value <= 1.0:
            epss_threshold = value
        else:
            # EPSS is a probability: 5 would filter every scored alert as low.
            print(
                f"Warning: invalid epss_threshold in {path}: {raw_threshold!r} "
                "(a probability between 0 and 1, e.g. 0.05 for 5%); EPSS filtering stays off",
                file=sys.stderr,
            )

    template_dirs: list[Path] = []
    raw_dirs = data.get("template_dirs", [])
    if isinstance(raw_dirs, str):
        raw_dirs = [raw_dirs]
    if isinstance(raw_dirs, list):
        for d in raw_dirs:
            template_dirs.append(project / str(d))

    always_flag: list[str] = []
    raw_flag = data.get("always_flag", [])
    if isinstance(raw_flag, str):
        raw_flag = [raw_flag]
    if isinstance(raw_flag, list):
        always_flag = [str(p) for p in raw_flag]

    offline = _parse_bool(data, "offline")

    # --- CI gate ---

    fail_on: str | None = None
    raw_fail = data.get("fail_on")
    if raw_fail is not None:
        val = str(raw_fail).lower().strip()
        if val in _VALID_FAIL_ON:
            fail_on = val
        else:
            print(
                f"Warning: invalid fail_on in {path}: {raw_fail!r} "
                f"(expected one of {', '.join(sorted(_VALID_FAIL_ON))})",
                file=sys.stderr,
            )

    # --- Integrations ---

    kev = _parse_bool(data, "kev")
    kev_file = _parse_path(data, "kev_file", project)
    license_scan = _parse_bool(data, "license")

    # --- Input paths ---

    policy_path = _parse_path(data, "policy", project)
    ignore_path = _parse_path(data, "ignore", project)
    baseline_path = _parse_path(data, "baseline", project)

    # --- Output paths ---

    sarif_path = _parse_path(data, "sarif", project)
    html_path = _parse_path(data, "html", project)
    summary_path = _parse_path(data, "summary", project)
    sbom_path = _parse_path(data, "sbom", project)
    vex_path = _parse_path(data, "vex", project)
    annotations_path = _parse_path(data, "annotations", project)

    sbom_format: str | None = None
    raw_fmt = data.get("sbom_format")
    if raw_fmt is not None:
        val = str(raw_fmt).lower().strip()
        if val in _VALID_SBOM_FORMATS:
            sbom_format = val
        else:
            print(
                f"Warning: invalid sbom_format in {path}: {raw_fmt!r} "
                f"(expected one of {', '.join(sorted(_VALID_SBOM_FORMATS))})",
                file=sys.stderr,
            )

    return Config(
        epss_threshold=epss_threshold,
        project_id=validate_project_id(data["project_id"]) if "project_id" in data else "",
        template_dirs=template_dirs,
        always_flag=always_flag,
        offline=offline,
        fail_on=fail_on,
        kev=kev,
        kev_file=kev_file,
        license=license_scan,
        policy=policy_path,
        ignore=ignore_path,
        baseline=baseline_path,
        sarif=sarif_path,
        html=html_path,
        summary=summary_path,
        sbom=sbom_path,
        sbom_format=sbom_format,
        vex=vex_path,
        annotations=annotations_path,
    )


def _parse_bool(data: dict[str, Any], key: str) -> bool:
    """Parse a boolean value from config data; warn on anything unreadable."""
    import sys

    raw = data.get(key)
    if raw is None:
        return False
    value = str(raw).lower().strip()
    if value in ("true", "yes", "1", "on"):
        return True
    if value not in ("false", "no", "0", "off"):
        print(f"Warning: invalid {key}: {raw!r} (expected true or false)", file=sys.stderr)
    return False


def _parse_path(data: dict[str, Any], key: str, project: Path) -> Path | None:
    """Parse an optional path value, resolved relative to the project root."""
    raw = data.get(key)
    if raw is None:
        return None
    val = str(raw).strip()
    if not val:
        return None
    return project / val
