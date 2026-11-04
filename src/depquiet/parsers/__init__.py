"""Parsers for different scanner output formats."""

from depquiet.parsers.npm import NpmAuditParser
from depquiet.parsers.pip import PipAuditParser
from depquiet.parsers.sbom import SbomParser

__all__ = ["NpmAuditParser", "PipAuditParser", "SbomParser"]
