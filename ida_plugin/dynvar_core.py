"""Core IDA-side orchestration for runtime variable display.

This phase keeps the live plan deliberately small: map a PC, request a fixed
register set, then request one memory read at RSP. Hex-Rays extraction and
argument recovery stay out of scope.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

STATUS_FRESH = "fresh"
STATUS_STALE = "stale"
STATUS_UNAVAILABLE = "unavailable"
STATUS_UNSUPPORTED = "unsupported"

CONFIDENCE_EXACT_ENTRY = "exact_entry"
CONFIDENCE_EXACT_MEMORY_READ = "exact_memory_read"
CONFIDENCE_STALE_ENTRY_VALUE = "stale_entry_value"
CONFIDENCE_UNSUPPORTED_VARIABLE = "unsupported_variable"
CONFIDENCE_UNKNOWN = "unknown"

PROTOCOL_VERSION = 1
ROLE_IDA = "ida"

TYPE_HELLO = "hello"
TYPE_IDA_PC_MAPPED = "ida_pc_mapped"
TYPE_REG_REQUEST = "reg_request"
TYPE_MEM_REQUEST = "mem_request"

AUTO_LIVE_REGISTERS = ("rcx", "rdx", "r8", "r9", "rsp")


def is_current_response(response_pc_seq: int, current_pc_seq: int) -> bool:
    """Return true only when a runtime response belongs to the active PC."""
    return response_pc_seq == current_pc_seq


@dataclass
class PcContext:
    """Current runtime PC context tracked by IDA."""

    pc_seq: int
    runtime_pc: str
    ida_ea: str


@dataclass
class DayVarCore:
    """Small protocol-state helper for the IDA plugin."""

    next_message_id: int = 1
    current_pc: PcContext | None = None
    pending_requests: dict[str, int] = field(default_factory=dict)

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

    def start_pc_context(self, pc_seq: int, runtime_pc: str, ida_ea: str) -> None:
        """Replace current PC context and drop stale pending requests."""
        self.current_pc = PcContext(pc_seq=pc_seq, runtime_pc=runtime_pc, ida_ea=ida_ea)
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

    def make_reg_request(self, pc_seq: int, runtime_pc: str) -> dict[str, Any]:
        """Build the fixed auto-live register request for this milestone."""
        request_id = f"reg-{pc_seq}-1"
        self.pending_requests[request_id] = pc_seq
        return self.envelope(
            TYPE_REG_REQUEST,
            {
                "pc_seq": pc_seq,
                "request_id": request_id,
                "runtime_pc": runtime_pc,
                "registers": list(AUTO_LIVE_REGISTERS),
                "reason": "auto_live_refresh",
            },
        )

    def make_mem_request_from_rsp(self, reg_response_payload: dict[str, Any]) -> dict[str, Any] | None:
        """Build one test memory request using RSP from a register response."""
        registers = reg_response_payload.get("registers")
        if not isinstance(registers, dict):
            return None
        rsp = registers.get("rsp")
        if not isinstance(rsp, str) or not rsp:
            return None

        pc_seq = int(reg_response_payload["pc_seq"])
        request_id = f"mem-{pc_seq}-rsp"
        self.pending_requests[request_id] = pc_seq
        return self.envelope(
            TYPE_MEM_REQUEST,
            {
                "pc_seq": pc_seq,
                "request_id": request_id,
                "runtime_pc": reg_response_payload.get("runtime_pc", ""),
                "address": rsp,
                "size": 8,
                "reason": "ida_rsp_test_read",
                "variable": "rsp_qword",
            },
        )

    def accept_response(self, payload: dict[str, Any]) -> tuple[bool, str]:
        """Validate that a runtime response belongs to the active PC context."""
        if self.current_pc is None:
            return False, "no current pc context"

        pc_seq = payload.get("pc_seq")
        if pc_seq != self.current_pc.pc_seq:
            return False, f"stale pc_seq={pc_seq} current={self.current_pc.pc_seq}"

        runtime_pc = payload.get("runtime_pc")
        if runtime_pc and runtime_pc != self.current_pc.runtime_pc:
            return False, "runtime_pc does not match current context"

        request_id = payload.get("request_id")
        if not isinstance(request_id, str) or request_id not in self.pending_requests:
            return False, f"unexpected request_id={request_id!r}"

        self.pending_requests.pop(request_id, None)
        return True, "accepted"
