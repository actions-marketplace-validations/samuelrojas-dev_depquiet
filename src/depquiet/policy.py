"""Policy engine — declarative triage rules in YAML.

Lets teams commit security policies alongside code. Rules match on
vulnerability attributes (severity, EPSS, package, dev status) and
override the default triage verdict.

Usage:
    depquiet --policy .depquiet-policy.yaml

Example policy::

    rules:
      - id: block-critical
        match:
          severity: critical
        action: action

      - id: dismiss-low-epss
        match:
          epss_below: 0.01
        action: filter

      - id: block-core-packages
        match:
          packages: [express, lodash]
        action: action

Rules are evaluated top-to-bottom; the first matching rule wins.
If no rule matches, the engine's default verdict applies.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from pathlib import Path

from depquiet.models import Severity, TriageResult, Verdict


@dataclass
class PolicyRule:
    """A single policy rule that matches vulnerabilities and overrides verdicts."""

    id: str
    action: Verdict
    description: str = ""
    # Match conditions — all specified conditions must match (AND logic)
    severity: list[Severity] | None = None
    packages: list[str] | None = None
    epss_below: float | None = None
    epss_above: float | None = None
    is_dev: bool | None = None
    has_fix: bool | None = None
    cves: list[str] | None = None
    reason: str = ""

    def matches(self, tr: TriageResult) -> bool:
        """Check if this rule matches a triage result."""
        v = tr.vuln

        if self.severity is not None and v.severity not in self.severity:
            return False

        if self.packages is not None and v.package not in self.packages:
            return False

        if self.epss_below is not None:
            score = tr.epss_score
            if score is None or score >= self.epss_below:
                return False

        if self.epss_above is not None:
            score = tr.epss_score
            if score is None or score <= self.epss_above:
                return False

        if self.is_dev is not None and v.is_dev != self.is_dev:
            return False

        if self.has_fix is not None:
            has = bool(v.fix_version)
            if has != self.has_fix:
                return False

        return not (self.cves is not None and v.cve not in self.cves)


@dataclass
class Policy:
    """A set of ordered rules that override triage verdicts."""

    rules: list[PolicyRule] = field(default_factory=list)

    def apply(self, tr: TriageResult) -> tuple[Verdict, str | None]:
        """Apply the first matching rule to a triage result.

        Returns:
            (verdict, rule_id) if a rule matched, or (original verdict, None).
        """
        for rule in self.rules:
            if rule.matches(tr):
                return rule.action, rule.id
        return tr.verdict, None


_POLICY_NAMES = (".depquiet-policy.yaml", ".depquiet-policy.yml")

_ACTION_MAP = {
    "action": Verdict.ACTION,
    "review": Verdict.REVIEW,
    "filter": Verdict.FILTERED,
    "filtered": Verdict.FILTERED,
    "block": Verdict.ACTION,
    "dismiss": Verdict.FILTERED,
    "ignore": Verdict.FILTERED,
}

_SEVERITY_MAP = {s.value: s for s in Severity}


def _parse_severities(raw: str | list[str]) -> list[Severity]:
    """Parse severity match from string or list."""
    if isinstance(raw, str):
        raw = [raw]
    result = []
    for s in raw:
        s_lower = str(s).strip().lower()
        if s_lower in _SEVERITY_MAP:
            result.append(_SEVERITY_MAP[s_lower])
    return result or None  # type: ignore[return-value]


def load_policy(project: Path, *, policy_path: Path | None = None) -> Policy | None:
    """Load a policy file from the project root or explicit path.

    Returns None if no policy file exists.
    """
    import sys

    if policy_path is not None:
        if policy_path.is_file():
            return _parse_policy(policy_path)
        print(f"Warning: policy file not found: {policy_path}", file=sys.stderr)
        return None

    for name in _POLICY_NAMES:
        candidate = project / name
        if candidate.is_file():
            return _parse_policy(candidate)

    return None


def _parse_policy_yaml(text: str) -> list[dict[str, str | list[str]]]:
    """Parse policy YAML into a list of rule dicts.

    Handles the subset of YAML needed for policy files:
    - Top-level ``rules:`` key containing a list of dicts
    - Each list item starts with ``- key: value``
    - Continuation lines (same or deeper indent) are ``key: value``
    - Inline lists: ``[a, b, c]``
    - Nested ``match:`` block is flattened into the rule dict

    This avoids requiring PyYAML for a simple config format.
    """
    rules: list[dict[str, str | list[str]]] = []
    current: dict[str, str | list[str]] | None = None
    in_rules = False

    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Detect top-level rules: key
        if stripped == "rules:" or stripped.startswith("rules:"):
            in_rules = True
            continue

        if not in_rules:
            continue

        # New list item
        if stripped.startswith("- "):
            if current is not None:
                rules.append(current)
            current = {}
            rest = stripped[2:].strip()
            if ":" in rest:
                k, v = rest.split(":", 1)
                current[k.strip()] = _parse_yaml_value(v.strip())
            continue

        if current is None:
            continue

        # Nested match: block — skip the key, flatten its children
        if stripped == "match:":
            continue

        # Key: value line (inside match or directly on rule)
        if ":" in stripped:
            k, v = stripped.split(":", 1)
            k = k.strip()
            v_parsed = _parse_yaml_value(v.strip())
            current[k] = v_parsed

    if current is not None:
        rules.append(current)

    return rules


def _parse_yaml_value(v: str) -> str | list[str]:
    """Parse a YAML value — handles inline lists and scalars."""
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1]
        return [item.strip().strip("'\"") for item in inner.split(",") if item.strip()]
    return v.strip("'\"")


def _parse_policy(path: Path) -> Policy | None:
    """Parse a policy YAML file."""
    import sys

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Warning: could not read {path}: {exc}", file=sys.stderr)
        return None

    try:
        raw_rules = _parse_policy_yaml(text)
    except Exception:
        print(f"Warning: invalid YAML in {path}", file=sys.stderr)
        return None

    rules: list[PolicyRule] = []
    for i, raw in enumerate(raw_rules):
        rule_id = str(raw.get("id", f"rule-{i}"))
        action_str = str(raw.get("action", "")).lower()
        action = _ACTION_MAP.get(action_str)
        if action is None:
            print(
                f"Warning: unknown action '{action_str}' in rule '{rule_id}' in {path}",
                file=sys.stderr,
            )
            continue

        severity = None
        raw_sev = raw.get("severity")
        if raw_sev is not None:
            severity = _parse_severities(raw_sev)  # type: ignore[arg-type]

        packages = None
        raw_pkg = raw.get("packages")
        if raw_pkg is not None:
            packages = [raw_pkg] if isinstance(raw_pkg, str) else list(raw_pkg)

        epss_below = None
        raw_eb = raw.get("epss_below")
        if raw_eb is not None:
            with contextlib.suppress(TypeError, ValueError):
                epss_below = float(str(raw_eb))

        epss_above = None
        raw_ea = raw.get("epss_above")
        if raw_ea is not None:
            with contextlib.suppress(TypeError, ValueError):
                epss_above = float(str(raw_ea))

        is_dev = None
        raw_dev = raw.get("is_dev")
        if raw_dev is not None:
            is_dev = str(raw_dev).lower() in ("true", "yes", "1")

        has_fix = None
        raw_fix = raw.get("has_fix")
        if raw_fix is not None:
            has_fix = str(raw_fix).lower() in ("true", "yes", "1")

        cves = None
        raw_cves = raw.get("cves")
        if raw_cves is not None:
            cves = [raw_cves] if isinstance(raw_cves, str) else list(raw_cves)

        rules.append(
            PolicyRule(
                id=rule_id,
                action=action,
                description=str(raw.get("description", "")),
                severity=severity,
                packages=packages,
                epss_below=epss_below,
                epss_above=epss_above,
                is_dev=is_dev,
                has_fix=has_fix,
                cves=cves,
                reason=str(raw.get("reason", "")),
            )
        )

    return Policy(rules=rules)
