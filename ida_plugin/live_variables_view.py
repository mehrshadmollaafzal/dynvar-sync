"""IDA-side Live Variables view.

The first UI is a simple chooser/table plus output log. It intentionally does
not modify Hex-Rays pseudocode.
"""

from __future__ import annotations

from typing import Any

from hexrays_variables import VariableRecord, is_v_temporary_name

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
    "LvarIndex",
    "Type",
    "Source EA",
    "Storage",
    "Last Update PC",
)

FILTER_ALL = "All"
FILTER_FRESH = "Fresh"
FILTER_RECOVERABLE = "Recoverable"
FILTER_ARGUMENTS = "Arguments"
FILTER_NAMED_LOCALS = "Named locals"
FILTER_UNAVAILABLE = "Unavailable"

FILTERS = (
    FILTER_ALL,
    FILTER_FRESH,
    FILTER_RECOVERABLE,
    FILTER_ARGUMENTS,
    FILTER_NAMED_LOCALS,
    FILTER_UNAVAILABLE,
)


def is_exact_row(row: VariableRecord) -> bool:
    return row.status == "fresh" and row.confidence.startswith("exact_")


def is_recoverable_row(row: VariableRecord) -> bool:
    """Return true for rows with a current or retained exact observation."""
    if row.status == "fresh" and row.value:
        return True
    if row.status == "stale" and (
        row.value or row.last_success_value or row.last_success_pc_seq is not None
    ):
        return True
    return False


def is_named_local_row(row: VariableRecord) -> bool:
    return (
        not row.is_arg
        and bool(row.name)
        and row.name != "<unnamed>"
        and not is_v_temporary_name(row.name)
    )


def row_matches_filter(row: VariableRecord, filter_name: str) -> bool:
    if filter_name == FILTER_ALL:
        return True
    if filter_name == FILTER_FRESH:
        return row.status == "fresh"
    if filter_name == FILTER_RECOVERABLE:
        return is_recoverable_row(row)
    if filter_name == FILTER_ARGUMENTS:
        return row.is_arg
    if filter_name == FILTER_NAMED_LOCALS:
        return is_named_local_row(row)
    if filter_name == FILTER_UNAVAILABLE:
        return row.status == "unavailable"
    return True


def presented_status(row: VariableRecord) -> str:
    """Map internal status/confidence/reason to a conservative UI label."""
    if is_exact_row(row):
        return "exact"
    if row.status == "stale":
        return "stale / last observed"
    reason = row.reason or ""
    confidence = row.confidence or ""
    if reason == "no_reaching_definition":
        return "not yet defined"
    if reason in {
        "ambiguous_register_location",
        "ambiguous_reaching_definition",
        "cross_block_liveness_unproven",
    }:
        return "ambiguous"
    if reason in {
        "unsupported_scattered_location",
        "unsupported_value_width",
    }:
        return "unsupported storage"
    if "alias" in reason or "byref" in reason or "address" in reason and "match" not in reason:
        return "address taken / alias unknown"
    if confidence == "unsupported_variable" and reason == "variable does not have a reliable runtime location in v1":
        return "optimized away / not materialized"
    if row.status == "unavailable":
        return "unavailable"
    return row.status


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
                ["LvarIndex", 9],
                ["Type", 24],
                ["Source EA", 16],
                ["Storage", 24],
                ["Last Update PC", 20],
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
        self.all_rows: list[VariableRecord] = []
        self.rows: list[VariableRecord] = []
        self.active_filter = FILTER_ALL
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
        """Replace underlying rows and refresh the filtered chooser/log view."""
        self.all_rows = list(rows)
        self._apply_filter()
        self._refresh()

    def set_filter(self, filter_name: str) -> None:
        """Set the active display filter without losing underlying row state."""
        if filter_name not in FILTERS:
            raise ValueError(f"unknown Live Variables filter: {filter_name}")
        self.active_filter = filter_name
        self._apply_filter()
        self._refresh()

    def _apply_filter(self) -> None:
        self.rows = [
            row for row in self.all_rows if row_matches_filter(row, self.active_filter)
        ]

    def _refresh(self) -> None:
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
            presented_status(row),
            row.confidence,
            row.reason,
            str(row.lvar_index),
            row.type_string,
            row.source_ea,
            row.storage,
            row.last_pc,
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
