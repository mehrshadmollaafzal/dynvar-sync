"""Hex-Rays variable extraction and classification placeholders.

IDA will eventually use this module to enumerate lvars, identify arguments,
and classify unsupported temporaries such as v1, v2, or v160 without guessing
runtime values.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VariableRecord:
    """IDA-side description of a decompiler variable."""

    name: str
    hexrays_kind: str
    size: int
    status: str = "unavailable"
    confidence: str = "unknown"
    reason: str = "not evaluated"


def unsupported_variable(name: str, size: int = 0) -> VariableRecord:
    """Create an honest unsupported-variable record."""
    return VariableRecord(
        name=name,
        hexrays_kind="unknown",
        size=size,
        status="unavailable",
        confidence="unsupported_variable",
        reason="variable does not have a reliable runtime location in v1",
    )
