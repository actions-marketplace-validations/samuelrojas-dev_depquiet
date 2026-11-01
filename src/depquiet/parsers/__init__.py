"""Parsers for different scanner output formats."""

from depquiet.parsers.npm import NpmAuditParser
from depquiet.parsers.pip import PipAuditParser

__all__ = ["NpmAuditParser", "PipAuditParser"]
