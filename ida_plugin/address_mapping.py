"""Static IDA address to runtime address mapping helpers.

IDA owns the static address space. WinDbg reports runtime addresses, and this
module keeps the deterministic module-relative mapping in one place.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PcMapping:
    """Mapped runtime PC context."""

    pc_seq: int
    runtime_pc: int
    runtime_module_base: int
    ida_imagebase: int
    ida_ea: int
    module: str


def parse_int(value: object) -> int:
    """Parse a protocol integer encoded as an int or hex/decimal string."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError(f"expected integer-compatible value, got {value!r}")


def format_hex(value: int) -> str:
    """Format an address or integer for protocol messages."""
    return f"0x{value:x}"


def runtime_pc_to_ida_ea(runtime_pc: int, runtime_module_base: int, ida_imagebase: int) -> int:
    """Map a runtime PC to an IDA EA using the module-relative offset."""
    return ida_imagebase + (runtime_pc - runtime_module_base)


def map_pc_update(payload: dict[str, object], ida_imagebase: int) -> PcMapping:
    """Map a `pc_update` payload to an IDA EA."""
    pc_seq = parse_int(payload["pc_seq"])
    runtime_pc = parse_int(payload["pc"])
    runtime_module_base = parse_int(payload["runtime_module_base"])
    ida_ea = runtime_pc_to_ida_ea(runtime_pc, runtime_module_base, ida_imagebase)
    return PcMapping(
        pc_seq=pc_seq,
        runtime_pc=runtime_pc,
        runtime_module_base=runtime_module_base,
        ida_imagebase=ida_imagebase,
        ida_ea=ida_ea,
        module=str(payload.get("module", "")),
    )
