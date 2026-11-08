"""Development dependency metadata used as a remediation-priority signal.

The engine checks for shared production dependency paths before applying
this filter. Metadata does not verify the contents of a deployed artifact
or prove that development tooling is unaffected by a vulnerability.
"""

from __future__ import annotations

from depquiet.models import FilterReason, Vulnerability


class DevDepFilter:
    """Mark devDependency vulnerabilities as filtered."""

    reason = FilterReason.DEV_DEPENDENCY

    @staticmethod
    def check(vuln: Vulnerability) -> bool:
        """Return True if this vulnerability should be filtered (is devDep)."""
        return vuln.is_dev
