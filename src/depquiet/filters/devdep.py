"""Filter: devDependencies never reach production.

A vulnerability in a devDependency (test runner, linter, bundler) only affects
the developer's machine during development, never the deployed application.
This is one of the simplest and most reliable filters — if it's in
devDependencies, it can't hurt users in production.
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
