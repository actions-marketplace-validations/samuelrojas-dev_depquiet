"""PURL version encoding applies to both npm and legacy opaque versions."""

from depquiet.component_refs import make_purl


def test_opaque_version_preserves_colon_and_encodes_build_separator():
    assert make_purl("example", "1:2.3+build", "generic") == "pkg:generic/example@1:2.3%2Bbuild"
