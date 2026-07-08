"""Future IDA plugin entry point for DayVar Sync.

This module will register IDA actions, connect to the broker, handle PC sync,
and refresh the Live Variables view. Real IDA APIs are intentionally not used
in this skeleton so the module can be syntax-checked outside IDA.
"""

from __future__ import annotations


def plugin_status() -> str:
    """Return the current implementation status."""
    return "ida plugin skeleton: IDA APIs are not implemented yet"
