"""IDA-side Live Variables view.

The first UI is a simple chooser/table plus output log. It intentionally does
not modify Hex-Rays pseudocode.
"""

from __future__ import annotations

from typing import Any

from hexrays_variables import VariableRecord

try:
    import ida_kernwin  # type: ignore
except ImportError:  # pragma: no cover - exercised only outside IDA.
    ida_kernwin = None  # type: ignore

TITLE = "DayVarSync Live Variables"

COLUMNS = (
    "Name",
    "Kind",
    "ArgIndex",
    "Size",
    "Location",
    "Value",
    "Status",
    "Confidence",
    "Reason",
)


if ida_kernwin is not None:

    class _LiveVariablesChooser(ida_kernwin.Choose):
        """Non-modal IDA chooser for live variable rows."""

        def __init__(self, view: "LiveVariablesView") -> None:
            cols = [
                ["Name", 16],
                ["Kind", 12],
                ["ArgIndex", 8],
                ["Size", 6],
                ["Location", 18],
                ["Value", 22],
                ["Status", 12],
                ["Confidence", 20],
                ["Reason", 44],
            ]
            super().__init__(TITLE, cols, flags=ida_kernwin.Choose.CH_NOBTNS)
            self.view = view

        def OnGetSize(self) -> int:
            return len(self.view.rows)

        def OnGetLine(self, n: int) -> list[str]:
            return self.view.row_to_columns(self.view.rows[n])

else:
    _LiveVariablesChooser = None  # type: ignore


class LiveVariablesView:
    """Live Variables chooser with output-window logging."""

    def __init__(self) -> None:
        self.rows: list[VariableRecord] = []
        self.chooser: Any | None = None

    def log(self, message: str) -> None:
        """Write a DayVarSync log line."""
        line = f"[DayVarSync] {message}\n"
        if ida_kernwin is not None:
            ida_kernwin.msg(line)
        else:
            print(line, end="")

    def show(self) -> None:
        """Show the Live Variables chooser when running inside IDA."""
        if ida_kernwin is None or _LiveVariablesChooser is None:
            self.log("outside IDA: Live Variables chooser not available")
            return
        if self.chooser is None:
            self.chooser = _LiveVariablesChooser(self)
        self.chooser.Show(False)

    def update_rows(self, rows: list[VariableRecord]) -> None:
        """Replace rows and refresh the chooser/log view."""
        self.rows = list(rows)
        if ida_kernwin is not None:
            if self.chooser is None:
                self.chooser = _LiveVariablesChooser(self)
                self.chooser.Show(False)
            ida_kernwin.refresh_chooser(TITLE)
        else:
            for row in self.rows:
                self.log(" | ".join(self.row_to_columns(row)))

    def row_to_columns(self, row: VariableRecord) -> list[str]:
        """Convert one variable record to chooser columns."""
        return [
            row.name,
            row.hexrays_kind,
            "" if row.arg_index is None else str(row.arg_index),
            "" if row.size == 0 else str(row.size),
            row.location,
            row.value,
            row.status,
            row.confidence,
            row.reason,
        ]

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
        self.log(
            "reg_response pc_seq={pc_seq} request_id={request_id} ok={ok}".format(
                pc_seq=payload.get("pc_seq"),
                request_id=payload.get("request_id"),
                ok=payload.get("ok"),
            )
        )

    def show_mem_response(self, payload: dict[str, Any]) -> None:
        """Display a memory response."""
        self.log(
            "mem_response pc_seq={pc_seq} request_id={request_id} ok={ok} address={address} size={size}".format(
                pc_seq=payload.get("pc_seq"),
                request_id=payload.get("request_id"),
                ok=payload.get("ok"),
                address=payload.get("address"),
                size=payload.get("size"),
            )
        )
