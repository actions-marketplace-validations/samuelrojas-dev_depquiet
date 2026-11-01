"""Configuration file support — .depquiet.yaml in the project root.

Lets teams commit their triage preferences alongside the code. CLI flags
override config-file values, so CI can tighten thresholds without changing
the checked-in config.

Supported keys:
    epss_threshold: float   — EPSS score cutoff (default: 0.1)
    template_dirs: list     — extra template directories (relative to project)
    always_flag: list       — packages that must never be filtered
    offline: bool           — skip EPSS API (default: false)

Example .depquiet.yaml:
    epss_threshold: 0.05
    template_dirs:
      - ./my-templates
    always_flag:
      - lodash
      - express
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from depquiet.filters.templates import _parse_yaml_simple


@dataclass
class Config:
    """Parsed depquiet configuration."""

    epss_threshold: float = 0.1
    template_dirs: list[Path] = field(default_factory=list)
    always_flag: list[str] = field(default_factory=list)
    offline: bool = False

    def merge_cli(
        self,
        *,
        epss_threshold: float | None = None,
        template_dirs: list[Path] | None = None,
        offline: bool = False,
    ) -> Config:
        """Return a new Config with CLI overrides applied.

        CLI flags win over config-file values. Lists (template_dirs) are
        appended so both sources contribute.
        """
        merged_templates = list(self.template_dirs)
        if template_dirs:
            for d in template_dirs:
                if d not in merged_templates:
                    merged_templates.append(d)

        return Config(
            epss_threshold=epss_threshold if epss_threshold is not None else self.epss_threshold,
            template_dirs=merged_templates,
            always_flag=list(self.always_flag),
            offline=offline or self.offline,
        )


_CONFIG_NAMES = (".depquiet.yaml", ".depquiet.yml")


def load_config(project: Path) -> Config:
    """Load .depquiet.yaml from the project root.

    Returns the default Config if no config file exists or if the file
    is malformed (with a warning to stderr).
    """
    for name in _CONFIG_NAMES:
        config_path = project / name
        if config_path.is_file():
            return _parse_config(config_path, project)

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

    # Parse epss_threshold
    epss_threshold = 0.1
    raw_threshold = data.get("epss_threshold")
    if raw_threshold is not None:
        try:
            epss_threshold = float(str(raw_threshold))
        except (TypeError, ValueError):
            print(
                f"Warning: invalid epss_threshold in {path}: {raw_threshold!r}",
                file=sys.stderr,
            )

    # Parse template_dirs (relative to project root)
    template_dirs: list[Path] = []
    raw_dirs = data.get("template_dirs", [])
    if isinstance(raw_dirs, str):
        raw_dirs = [raw_dirs]
    if isinstance(raw_dirs, list):
        for d in raw_dirs:
            template_dirs.append(project / str(d))

    # Parse always_flag
    always_flag: list[str] = []
    raw_flag = data.get("always_flag", [])
    if isinstance(raw_flag, str):
        raw_flag = [raw_flag]
    if isinstance(raw_flag, list):
        always_flag = [str(p) for p in raw_flag]

    # Parse offline
    offline = False
    raw_offline = data.get("offline")
    if raw_offline is not None:
        offline = str(raw_offline).lower() in ("true", "yes", "1")

    return Config(
        epss_threshold=epss_threshold,
        template_dirs=template_dirs,
        always_flag=always_flag,
        offline=offline,
    )
