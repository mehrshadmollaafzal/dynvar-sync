"""Core IDA-side orchestration for runtime variable display.

The future implementation will coordinate PC mapping, Hex-Rays variable
classification, request planning, response application, and stale-state rules.
"""

from __future__ import annotations

STATUS_FRESH = "fresh"
STATUS_STALE = "stale"
STATUS_UNAVAILABLE = "unavailable"
STATUS_UNSUPPORTED = "unsupported"

CONFIDENCE_EXACT_ENTRY = "exact_entry"
CONFIDENCE_EXACT_MEMORY_READ = "exact_memory_read"
CONFIDENCE_STALE_ENTRY_VALUE = "stale_entry_value"
CONFIDENCE_UNSUPPORTED_VARIABLE = "unsupported_variable"
CONFIDENCE_UNKNOWN = "unknown"


def is_current_response(response_pc_seq: int, current_pc_seq: int) -> bool:
    """Return true only when a runtime response belongs to the active PC."""
    return response_pc_seq == current_pc_seq
