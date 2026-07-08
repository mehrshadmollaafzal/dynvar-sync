"""Static IDA address to runtime address mapping helpers.

The future IDA plugin will map runtime PCs from WinDbg into IDA EAs using the
runtime module base and the IDA image base.
"""

from __future__ import annotations


def runtime_pc_to_ida_ea(runtime_pc: int, runtime_module_base: int, ida_imagebase: int) -> int:
    """Map a runtime PC to an IDA EA using the module-relative offset."""
    return ida_imagebase + (runtime_pc - runtime_module_base)
