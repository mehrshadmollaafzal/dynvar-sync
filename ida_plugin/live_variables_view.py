"""IDA-side live values display helpers.

For this milestone the display is intentionally a log/output view. It keeps
the runtime data visible without touching Hex-Rays pseudocode.
"""

from __future__ import annotations

from typing import Any

try:
    import ida_kernwin  # type: ignore
except ImportError:  # pragma: no cover - exercised only outside IDA.
    ida_kernwin = None  # type: ignore

COLUMNS = (
    "Name",
    "Kind",
    "Size",
    "Location",
    "Value",
    "Status",
    "Confidence",
    "Reason",
    "Last PC",
    "Current PC",
)


class LiveVariablesView:
    """Small log-backed live values view."""

    def log(self, message: str) -> None:
        """Write a DayVarSync log line."""
        line = f"[DayVarSync] {message}\n"
        if ida_kernwin is not None:
            ida_kernwin.msg(line)
        else:
            print(line, end="")

    def show_mapping(self, payload: dict[str, Any]) -> None:
        """Display the current PC mapping."""
        self.log(
            "pc_seq={pc_seq} runtime_pc={runtime_pc} ida_ea={ida_ea} module={module}".format(
                pc_seq=payload.get("pc_seq"),
                runtime_pc=payload.get("runtime_pc"),
                ida_ea=payload.get("ida_ea"),
                module=payload.get("module", ""),
            )
        )

    def show_reg_response(self, payload: dict[str, Any]) -> None:
        """Display a register response."""
        registers = payload.get("registers", {})
        self.log(
            "reg_response pc_seq={pc_seq} request_id={request_id} ok={ok} registers={registers}".format(
                pc_seq=payload.get("pc_seq"),
                request_id=payload.get("request_id"),
                ok=payload.get("ok"),
                registers=registers,
            )
        )

    def show_mem_response(self, payload: dict[str, Any]) -> None:
        """Display a memory response."""
        self.log(
            "mem_response pc_seq={pc_seq} request_id={request_id} ok={ok} address={address} size={size} bytes_hex={bytes_hex}".format(
                pc_seq=payload.get("pc_seq"),
                request_id=payload.get("request_id"),
                ok=payload.get("ok"),
                address=payload.get("address"),
                size=payload.get("size"),
                bytes_hex=payload.get("bytes_hex"),
            )
        )
