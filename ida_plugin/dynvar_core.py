"""Core IDA-side orchestration for runtime variable display.

The core owns correlation state, exact-entry Windows x64 argument planning, and
runtime response application. Unsupported variables stay unavailable.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

from hexrays_variables import VariableRecord

STATUS_FRESH = "fresh"
STATUS_STALE = "stale"
STATUS_UNAVAILABLE = "unavailable"
STATUS_ERROR = "error"
STATUS_UNSUPPORTED = "unsupported"

CONFIDENCE_EXACT_ENTRY = "exact_entry"
CONFIDENCE_EXACT_MEMORY_READ = "exact_memory_read"
CONFIDENCE_STALE_ENTRY_VALUE = "stale_entry_value"
CONFIDENCE_UNSUPPORTED_VARIABLE = "unsupported_variable"
CONFIDENCE_UNSUPPORTED_LOCATION = "unsupported_location"
CONFIDENCE_READ_FAILED = "read_failed"
CONFIDENCE_UNKNOWN = "unknown"

PROTOCOL_VERSION = 1
ROLE_IDA = "ida"

TYPE_HELLO = "hello"
TYPE_IDA_PC_MAPPED = "ida_pc_mapped"
TYPE_REG_REQUEST = "reg_request"
TYPE_MEM_REQUEST = "mem_request"

ENTRY_REGISTERS = ("rcx", "rdx", "r8", "r9")
STACK_ARG_BASE_OFFSET = 0x28
STACK_ARG_SLOT_SIZE = 8


def is_current_response(response_pc_seq: int, current_pc_seq: int) -> bool:
    """Return true only when a runtime response belongs to the active PC."""
    return response_pc_seq == current_pc_seq


@dataclass
class PcContext:
    """Current runtime PC context tracked by IDA."""

    pc_seq: int
    runtime_pc: str
    ida_ea: str
    function_ea: str = ""
    at_function_entry: bool = False


@dataclass
class PendingRequest:
    """One outstanding runtime request."""

    kind: str
    pc_seq: int
    request_id: str
    runtime_pc: str
    variable_names: list[str] = field(default_factory=list)
    registers: list[str] = field(default_factory=list)
    address: str = ""
    size: int = 0


@dataclass
class RuntimeRequestPlan:
    """Requests to send after enumerating variables for one PC."""

    register_request: dict[str, Any] | None = None
    debug_lines: list[str] = field(default_factory=list)


@dataclass
class DayVarCore:
    """Protocol and live-variable state helper for the IDA plugin."""

    next_message_id: int = 1
    current_pc: PcContext | None = None
    pending_requests: dict[str, PendingRequest] = field(default_factory=dict)
    rows: list[VariableRecord] = field(default_factory=list)

    def take_message_id(self) -> int:
        """Return the next protocol message id."""
        message_id = self.next_message_id
        self.next_message_id += 1
        return message_id

    def envelope(self, message_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Build a protocol envelope from the IDA role."""
        return {
            "protocol": PROTOCOL_VERSION,
            "id": self.take_message_id(),
            "type": message_type,
            "role": ROLE_IDA,
            "payload": payload,
        }

    def make_hello(self, ida_version: str) -> dict[str, Any]:
        """Build the IDA plugin hello message."""
        return self.envelope(
            TYPE_HELLO,
            {
                "client_name": "dayvar-ida-plugin",
                "version": "0.1",
                "ida_version": ida_version,
            },
        )

    def start_pc_context(
        self,
        *,
        pc_seq: int,
        runtime_pc: str,
        ida_ea: str,
        function_ea: str = "",
        at_function_entry: bool = False,
    ) -> None:
        """Replace current PC context and drop stale pending requests."""
        self.current_pc = PcContext(
            pc_seq=pc_seq,
            runtime_pc=runtime_pc,
            ida_ea=ida_ea,
            function_ea=function_ea,
            at_function_entry=at_function_entry,
        )
        self.pending_requests.clear()

    def make_ida_pc_mapped(
        self,
        *,
        pc_seq: int,
        runtime_pc: str,
        ida_ea: str | None,
        module: str,
        ida_imagebase: str,
        ok: bool,
        error: str | None = None,
    ) -> dict[str, Any]:
        """Build an `ida_pc_mapped` response."""
        payload: dict[str, Any] = {
            "pc_seq": pc_seq,
            "runtime_pc": runtime_pc,
            "module": module,
            "ida_imagebase": ida_imagebase,
            "ok": ok,
        }
        if ida_ea is not None:
            payload["ida_ea"] = ida_ea
        if error is not None:
            payload["error"] = error
        return self.envelope(TYPE_IDA_PC_MAPPED, payload)

    def build_entry_plan(
        self,
        *,
        variables: list[VariableRecord],
        pc_seq: int,
        runtime_pc: str,
        ida_ea: str,
        function_ea: str,
        at_function_entry: bool,
    ) -> RuntimeRequestPlan:
        """Build row state and low-level requests for current Hex-Rays variables."""
        self.start_pc_context(
            pc_seq=pc_seq,
            runtime_pc=runtime_pc,
            ida_ea=ida_ea,
            function_ea=function_ea,
            at_function_entry=at_function_entry,
        )
        previous_rows = {(row.function_ea, row.name): row for row in self.rows}
        planned_rows: list[VariableRecord] = []
        needed_registers: list[str] = []
        reg_variables: list[str] = []
        stack_variables: list[str] = []
        needs_rsp = False
        debug_lines = [
            f"request plan function={function_ea} at_entry={at_function_entry} variables={len(variables)}"
        ]

        for variable in variables:
            row = replace(variable, current_pc=runtime_pc)
            if not row.is_arg or row.arg_index is None:
                row.status = STATUS_UNAVAILABLE
                row.confidence = CONFIDENCE_UNSUPPORTED_VARIABLE
                row.location = row.location or "unsupported"
                row.reason = "variable does not have a reliable runtime location in v1"
                planned_rows.append(row)
                continue

            debug_lines.append(
                "detected arg{arg_index} name={name} location={location}".format(
                    arg_index=row.arg_index,
                    name=row.name,
                    location=row.location,
                )
            )

            if not at_function_entry:
                prior = previous_rows.get((row.function_ea, row.name))
                if prior is not None and prior.value:
                    row.value = prior.value
                    row.last_pc = prior.last_pc or prior.current_pc
                    row.status = STATUS_STALE
                    row.confidence = CONFIDENCE_STALE_ENTRY_VALUE
                    row.location = prior.location
                    row.reason = "entry argument value is stale; current PC is not function entry"
                else:
                    row.status = STATUS_UNAVAILABLE
                    row.confidence = CONFIDENCE_UNKNOWN
                    row.reason = "argument mapping is exact only at function entry"
                planned_rows.append(row)
                continue

            if row.arg_index < len(ENTRY_REGISTERS):
                register = ENTRY_REGISTERS[row.arg_index]
                row.location = register
                row.status = STATUS_UNAVAILABLE
                row.confidence = CONFIDENCE_UNKNOWN
                row.reason = f"waiting for {register} at function entry"
                if register not in needed_registers:
                    needed_registers.append(register)
                reg_variables.append(row.name)
            else:
                offset = stack_arg_offset(row.arg_index)
                row.location = f"[rsp + 0x{offset:x}]"
                row.status = STATUS_UNAVAILABLE
                row.confidence = CONFIDENCE_UNKNOWN
                row.reason = "waiting for rsp to request stack argument"
                needs_rsp = True
                stack_variables.append(row.name)
            planned_rows.append(row)

        if needs_rsp and "rsp" not in needed_registers:
            needed_registers.append("rsp")

        self.rows = planned_rows
        debug_lines.append(f"registers requested={needed_registers}")
        debug_lines.append(f"stack args requested={stack_variables}")
        if not needed_registers:
            debug_lines.append("no reg_request sent: no supported entry arguments detected")
            return RuntimeRequestPlan(debug_lines=debug_lines)

        request_id = f"reg-{pc_seq}-entry"
        self.pending_requests[request_id] = PendingRequest(
            kind="reg",
            pc_seq=pc_seq,
            request_id=request_id,
            runtime_pc=runtime_pc,
            variable_names=reg_variables,
            registers=needed_registers,
        )
        return RuntimeRequestPlan(
            register_request=self.envelope(
                TYPE_REG_REQUEST,
                {
                    "pc_seq": pc_seq,
                    "request_id": request_id,
                    "runtime_pc": runtime_pc,
                    "registers": needed_registers,
                    "reason": "auto_live_refresh",
                },
            ),
            debug_lines=debug_lines,
        )

    def apply_reg_response(self, payload: dict[str, Any]) -> tuple[bool, str, list[dict[str, Any]]]:
        """Apply a register response and build stack-argument memory requests."""
        pending, reason = self._take_pending_response(payload, expected_kind="reg")
        if pending is None:
            return False, reason, []

        if payload.get("ok") is not True:
            self._mark_rows_error(pending.variable_names, "register read failed")
            return True, "register read failed", []

        registers = payload.get("registers")
        if not isinstance(registers, dict):
            self._mark_rows_error(pending.variable_names, "reg_response missing registers")
            return True, "reg_response missing registers", []

        for row in self.rows:
            if not row.is_arg or row.arg_index is None:
                continue
            if row.arg_index >= len(ENTRY_REGISTERS):
                continue
            register = ENTRY_REGISTERS[row.arg_index]
            value = registers.get(register)
            if isinstance(value, str) and value:
                row.value = value
                row.status = STATUS_FRESH
                row.confidence = CONFIDENCE_EXACT_ENTRY
                row.location = register
                row.reason = f"{register} at exact function entry"
                row.last_pc = pending.runtime_pc
            else:
                row.status = STATUS_ERROR
                row.confidence = CONFIDENCE_READ_FAILED
                row.reason = f"register {register} missing from response"

        return True, "accepted", self._build_stack_mem_requests(registers, pending)

    def apply_mem_response(self, payload: dict[str, Any]) -> tuple[bool, str]:
        """Apply a memory response for a stack argument."""
        pending, reason = self._take_pending_response(payload, expected_kind="mem")
        if pending is None:
            return False, reason

        for row in self.rows:
            if row.name not in pending.variable_names:
                continue
            row.location = pending.address
            row.last_pc = pending.runtime_pc
            if payload.get("ok") is True:
                bytes_hex = payload.get("bytes_hex", "")
                row.value = str(bytes_hex)
                row.status = STATUS_FRESH
                row.confidence = CONFIDENCE_EXACT_ENTRY
                row.reason = "stack argument memory read at exact function entry"
            else:
                row.status = STATUS_ERROR
                row.confidence = CONFIDENCE_READ_FAILED
                row.reason = _error_reason(payload)
        return True, "accepted"

    def _build_stack_mem_requests(
        self,
        registers: dict[str, Any],
        pending: PendingRequest,
    ) -> list[dict[str, Any]]:
        rsp_text = registers.get("rsp")
        if not isinstance(rsp_text, str) or not rsp_text:
            self._mark_stack_rows_error("rsp missing from register response")
            return []

        try:
            rsp = int(rsp_text, 0)
        except ValueError:
            self._mark_stack_rows_error(f"invalid rsp value {rsp_text!r}")
            return []

        messages: list[dict[str, Any]] = []
        for row in self.rows:
            if not row.is_arg or row.arg_index is None or row.arg_index < len(ENTRY_REGISTERS):
                continue
            address = rsp + stack_arg_offset(row.arg_index)
            address_text = f"0x{address:x}"
            request_id = f"mem-{pending.pc_seq}-{row.name}"
            size = STACK_ARG_SLOT_SIZE
            self.pending_requests[request_id] = PendingRequest(
                kind="mem",
                pc_seq=pending.pc_seq,
                request_id=request_id,
                runtime_pc=pending.runtime_pc,
                variable_names=[row.name],
                address=address_text,
                size=size,
            )
            row.location = address_text
            row.reason = "waiting for stack argument memory read"
            messages.append(
                self.envelope(
                    TYPE_MEM_REQUEST,
                    {
                        "pc_seq": pending.pc_seq,
                        "request_id": request_id,
                        "runtime_pc": pending.runtime_pc,
                        "address": address_text,
                        "size": size,
                        "reason": "stack_arg",
                        "variable": row.name,
                    },
                )
            )
        return messages

    def _take_pending_response(
        self,
        payload: dict[str, Any],
        *,
        expected_kind: str,
    ) -> tuple[PendingRequest | None, str]:
        if self.current_pc is None:
            return None, "no current pc context"

        pc_seq = payload.get("pc_seq")
        if pc_seq != self.current_pc.pc_seq:
            return None, f"stale pc_seq={pc_seq} current={self.current_pc.pc_seq}"

        runtime_pc = payload.get("runtime_pc")
        if runtime_pc and runtime_pc != self.current_pc.runtime_pc:
            return None, "runtime_pc does not match current context"

        request_id = payload.get("request_id")
        if not isinstance(request_id, str):
            return None, "missing request_id"

        pending = self.pending_requests.get(request_id)
        if pending is None:
            return None, f"unexpected request_id={request_id!r}"
        if pending.kind != expected_kind:
            return None, f"unexpected response kind for request_id={request_id!r}"

        self.pending_requests.pop(request_id, None)
        return pending, "accepted"

    def _mark_rows_error(self, names: list[str], reason: str) -> None:
        for row in self.rows:
            if row.name in names:
                row.status = STATUS_ERROR
                row.confidence = CONFIDENCE_READ_FAILED
                row.reason = reason

    def _mark_stack_rows_error(self, reason: str) -> None:
        for row in self.rows:
            if row.is_arg and row.arg_index is not None and row.arg_index >= len(ENTRY_REGISTERS):
                row.status = STATUS_ERROR
                row.confidence = CONFIDENCE_READ_FAILED
                row.reason = reason


def stack_arg_offset(arg_index: int) -> int:
    """Return the Windows x64 entry stack offset for argument index >= 4."""
    return STACK_ARG_BASE_OFFSET + STACK_ARG_SLOT_SIZE * (arg_index - 4)


def _error_reason(payload: dict[str, Any]) -> str:
    error = payload.get("error")
    if isinstance(error, dict):
        message = error.get("message")
        if isinstance(message, str) and message:
            return message
    if isinstance(error, str) and error:
        return error
    return "runtime read failed"
