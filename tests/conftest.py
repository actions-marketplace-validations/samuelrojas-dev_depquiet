"""Shared test setup."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_cve_alias_lookups(request, monkeypatch):
    """Scans in tests must not query OSV.dev for CVE aliases or write its cache.

    Tests of the lookup itself opt in with ``@pytest.mark.cve_alias_lookups``
    and fake the HTTP layer.
    """
    if request.node.get_closest_marker("cve_alias_lookups") is None:
        monkeypatch.setattr("depquiet.engine.resolve_cve_aliases", lambda vulns, **_: 0)
