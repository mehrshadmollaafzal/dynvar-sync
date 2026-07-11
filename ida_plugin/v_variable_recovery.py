"""Conservative runtime recovery for non-argument Hex-Rays lvars.

The entry-argument ABI model deliberately lives in :mod:`dynvar_core`.  This
module owns only local/``v*`` evidence, runtime requests, correlation, and
last-success history.  A printed Hex-Rays location is diagnostic text; it is
never sufficient evidence for a runtime read.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Callable

from hexrays_variables import VariableRecord

try:
    import ida_frame  # type: ignore
    import ida_funcs  # type: ignore
    import ida_gdl  # type: ignore
    import ida_hexrays  # type: ignore
    import ida_idaapi  # type: ignore
    import ida_idp  # type: ignore
    import ida_ua  # type: ignore
except ImportError:  # pragma: no cover - exercised by outside-IDA tests.
    ida_frame = None  # type: ignore
    ida_funcs = None  # type: ignore
    ida_gdl = None  # type: ignore
    ida_hexrays = None  # type: ignore
    ida_idaapi = None  # type: ignore
    ida_idp = None  # type: ignore
    ida_ua = None  # type: ignore


STATUS_FRESH = "fresh"
STATUS_STALE = "stale"
STATUS_UNAVAILABLE = "unavailable"
STATUS_ERROR = "error"

CONFIDENCE_EXACT_REGISTER_LOCATION = "exact_register_location"
CONFIDENCE_EXACT_STACK_LOCATION = "exact_stack_location"
CONFIDENCE_EXACT_CONSTANT = "exact_constant"
CONFIDENCE_STALE_RUNTIME_VALUE = "stale_runtime_value"
CONFIDENCE_READ_FAILED = "read_failed"
CONFIDENCE_UNKNOWN = "unknown"

REASON_NOT_LIVE = "not_live_at_current_pc"
REASON_AMBIGUOUS_REGISTER = "ambiguous_register_location"
REASON_SCATTERED = "unsupported_scattered_location"
REASON_UNRESOLVED_STACK = "unresolved_stack_location"
REASON_NO_DEFINITION = "no_reaching_definition"
REASON_MICROCODE = "microcode_unavailable"
REASON_UNSUPPORTED_WIDTH = "unsupported_value_width"
REASON_AMBIGUOUS_REACHING_DEFINITION = "ambiguous_reaching_definition"
REASON_CROSS_BLOCK_LIVENESS_UNPROVEN = "cross_block_liveness_unproven"
REASON_STORAGE_CLOBBERED = "storage_clobbered_before_current_pc"
REASON_UNRESOLVED_NATIVE_POINT = "unresolved_native_program_point"
REASON_ANALYSIS_DEFERRED = "analysis_deferred"

SUPPORTED_WIDTHS = (1, 2, 4, 8)

TYPE_REG_REQUEST = "reg_request"
TYPE_MEM_REQUEST = "mem_request"

EnvelopeFactory = Callable[[str, dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class RegisterSpec:
    """One supported x64 register spelling and its full-register projection."""

    alias: str
    full_register: str
    width: int
    bit_offset: int = 0


def _build_register_specs() -> dict[str, RegisterSpec]:
    specs: dict[str, RegisterSpec] = {}

    legacy = {
        "rax": ("eax", "ax", "al", "ah"),
        "rbx": ("ebx", "bx", "bl", "bh"),
        "rcx": ("ecx", "cx", "cl", "ch"),
        "rdx": ("edx", "dx", "dl", "dh"),
    }
    for full, (dword, word, low, high) in legacy.items():
        for alias, width, bit_offset in (
            (full, 8, 0),
            (dword, 4, 0),
            (word, 2, 0),
            (low, 1, 0),
            (high, 1, 8),
        ):
            specs[alias] = RegisterSpec(alias, full, width, bit_offset)

    for full, dword, word, byte in (
        ("rsi", "esi", "si", "sil"),
        ("rdi", "edi", "di", "dil"),
        ("rbp", "ebp", "bp", "bpl"),
        ("rsp", "esp", "sp", "spl"),
    ):
        for alias, width in ((full, 8), (dword, 4), (word, 2), (byte, 1)):
            specs[alias] = RegisterSpec(alias, full, width)

    for number in range(8, 16):
        full = f"r{number}"
        for alias, width in (
            (full, 8),
            (f"r{number}d", 4),
            (f"r{number}w", 2),
            (f"r{number}b", 1),
        ):
            specs[alias] = RegisterSpec(alias, full, width)
    return specs


REGISTER_SPECS = _build_register_specs()
FULL_REGISTER_ORDER = (
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "rbp",
    "rsp",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
)


def normalize_register_alias(name: str) -> RegisterSpec | None:
    """Return a supported x64 register projection for an exact alias."""
    normalized = name.strip().lower().replace("`", "")
    return REGISTER_SPECS.get(normalized)


def extract_register_value(value: object, spec: RegisterSpec, width: int) -> str:
    """Extract and format one lvar value from a full physical register read."""
    if width not in SUPPORTED_WIDTHS:
        raise ValueError(REASON_UNSUPPORTED_WIDTH)
    if width > spec.width:
        raise ValueError("variable width exceeds the proven register location")
    number = _parse_runtime_int(value)
    mask = (1 << (width * 8)) - 1
    return f"0x{(number >> spec.bit_offset) & mask:x}"


def decode_little_endian(bytes_hex: str, width: int) -> str:
    """Decode exactly one supported little-endian runtime memory value."""
    if width not in SUPPORTED_WIDTHS:
        raise ValueError(REASON_UNSUPPORTED_WIDTH)
    try:
        data = bytes.fromhex(bytes_hex)
    except ValueError as exc:
        raise ValueError("invalid memory response bytes") from exc
    if len(data) != width:
        raise ValueError(f"memory response size mismatch expected={width} actual={len(data)}")
    return f"0x{int.from_bytes(data, 'little', signed=False):x}"


def concrete_stack_address(stack_pointer: object, stack_pointer_offset: int) -> str:
    """Resolve a proven current-RSP-relative location to a runtime address."""
    address = _parse_runtime_int(stack_pointer) + stack_pointer_offset
    if address < 0 or address > ((1 << 64) - 1):
        raise ValueError("resolved stack address is outside the x64 address space")
    return f"0x{address:x}"


def _parse_runtime_int(value: object) -> int:
    if isinstance(value, bool):
        raise ValueError("boolean is not a runtime integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError(f"expected an integer-compatible runtime value, got {value!r}")


def _format_constant(value: int, width: int) -> str:
    if width not in SUPPORTED_WIDTHS:
        raise ValueError(REASON_UNSUPPORTED_WIDTH)
    return f"0x{value & ((1 << (width * 8)) - 1):x}"


@dataclass(frozen=True)
class RecoveryEvidence:
    """Static proof for one lvar at one mapped IDA EA."""

    lvar_index: int
    storage_kind: str = "unknown"
    storage: str = ""
    source_ea: int | None = None
    confidence: str = CONFIDENCE_UNKNOWN
    reason: str = REASON_NO_DEFINITION
    register: RegisterSpec | None = None
    stack_pointer_offset: int | None = None
    constant_value: int | None = None
    width: int = 0


@dataclass(frozen=True)
class RecoveryAnalysis:
    """Feature-detected Hex-Rays analysis result for one mapped PC."""

    ok: bool
    evidence_by_index: dict[int, RecoveryEvidence]
    error: str = ""
    debug_lines: list[str] = field(default_factory=list)


@dataclass
class VVariableRecoveryRecord:
    """Complete recovery model for one non-argument Hex-Rays lvar."""

    lvar_index: int
    name: str
    type_string: str
    width: int
    printed_location: str
    function_ea: int
    current_ea: int
    candidate_storage_kind: str
    recovery_status: str
    confidence: str
    reason: str
    storage: str = ""
    source_ea: int | None = None
    value: str = ""
    current_runtime_pc: str = ""
    current_pc_seq: int = 0
    last_successful_value: str = ""
    last_successful_pc_seq: int | None = None
    last_update_pc: str = ""


@dataclass(frozen=True)
class _HistoryValue:
    name: str
    width: int
    type_string: str
    lvar_defea: str
    value: str
    pc_seq: int
    runtime_pc: str
    source_ea: int | None


@dataclass
class _PendingVRequest:
    kind: str
    pc_seq: int
    request_id: str
    runtime_pc: str
    lvar_indexes: list[int]
    registers: list[str] = field(default_factory=list)
    address: str = ""
    size: int = 0


@dataclass
class VRecoveryPlan:
    """Runtime requests and diagnostics produced for one PC update."""

    register_request: dict[str, Any] | None = None
    debug_lines: list[str] = field(default_factory=list)


AnalysisProvider = Callable[
    [int, int, list[VariableRecord], object | None], RecoveryAnalysis
]


class VVariableRecovery:
    """Own non-argument lvar plans, history, and correlated runtime reads."""

    def __init__(
        self,
        analysis_provider: AnalysisProvider | None = None,
        *,
        max_history: int = 256,
    ) -> None:
        self._analysis_provider = analysis_provider or analyze_v_variable_candidates
        self._max_history = max(1, max_history)
        self._history: dict[tuple[int, int], _HistoryValue] = {}
        self._records: dict[int, VVariableRecoveryRecord] = {}
        self._evidence: dict[int, RecoveryEvidence] = {}
        self._pending: dict[str, _PendingVRequest] = {}
        self._pc_seq: int | None = None
        self._runtime_pc = ""
        self._function_ea = 0
        self._current_ea = 0
        self._source_variables: list[VariableRecord] = []

    @property
    def records(self) -> list[VVariableRecoveryRecord]:
        """Return the current recovery records in lvar order."""
        return [self._records[index] for index in sorted(self._records)]

    @staticmethod
    def is_v_request_id(request_id: object) -> bool:
        return isinstance(request_id, str) and request_id.startswith("v-")

    def begin_pc(
        self,
        *,
        variables: list[VariableRecord],
        function_ea: int,
        current_ea: int,
        runtime_pc: str,
        pc_seq: int,
        envelope: EnvelopeFactory,
        cfunc: object | None = None,
        analysis_lvar_indexes: set[int] | None = None,
    ) -> VRecoveryPlan:
        """Rebuild and revalidate every non-argument lvar for a mapped PC."""
        self._start_context(function_ea, current_ea, runtime_pc, pc_seq)
        local_variables = [variable for variable in variables if not variable.is_arg]
        self._source_variables = list(local_variables)
        selected_indexes = (
            {variable.lvar_index for variable in local_variables}
            if analysis_lvar_indexes is None
            else set(analysis_lvar_indexes)
        )
        analysis_variables = [
            variable for variable in local_variables if variable.lvar_index in selected_indexes
        ]

        try:
            analysis = self._analysis_provider(function_ea, current_ea, analysis_variables, cfunc)
        except Exception as exc:  # Recovery must never break PC sync/arguments.
            analysis = RecoveryAnalysis(
                ok=False,
                evidence_by_index={},
                error=f"{REASON_MICROCODE}: {exc}",
            )

        self._evidence = dict(analysis.evidence_by_index)
        debug_lines = list(analysis.debug_lines)
        if not analysis.ok:
            detail = analysis.error or REASON_MICROCODE
            debug_lines.append(f"v-microcode failure function=0x{function_ea:x} reason={detail}")

        needed_registers: set[str] = set()
        runtime_indexes: list[int] = []
        for variable in local_variables:
            printed_location = variable.printed_location or variable.location or "unknown"
            debug_lines.append(
                "v-candidate name={name} index={index} location={location} current_ea=0x{ea:x}".format(
                    name=variable.name,
                    index=variable.lvar_index,
                    location=printed_location,
                    ea=current_ea,
                )
            )

            if analysis.ok:
                if variable.lvar_index in selected_indexes:
                    evidence = self._evidence.get(
                        variable.lvar_index,
                        RecoveryEvidence(variable.lvar_index),
                    )
                else:
                    evidence = RecoveryEvidence(
                        variable.lvar_index,
                        reason=REASON_ANALYSIS_DEFERRED,
                    )
            else:
                evidence = RecoveryEvidence(
                    variable.lvar_index,
                    reason=REASON_MICROCODE,
                )
            record = self._new_record(variable, evidence, pc_seq, runtime_pc, current_ea)
            self._records[variable.lvar_index] = record

            if not analysis.ok:
                self._set_unavailable(record, REASON_MICROCODE, preserve_stale=False)
            elif evidence.storage_kind == "constant" and evidence.constant_value is not None:
                try:
                    value = _format_constant(evidence.constant_value, variable.size)
                except ValueError:
                    self._set_unavailable(record, REASON_UNSUPPORTED_WIDTH)
                else:
                    self._mark_fresh(record, value, evidence.confidence)
            elif evidence.storage_kind == "register" and evidence.register is not None:
                if variable.size not in SUPPORTED_WIDTHS or variable.size > evidence.register.width:
                    self._set_unavailable(record, REASON_UNSUPPORTED_WIDTH)
                else:
                    self._set_waiting(record, f"waiting for register {evidence.register.full_register}")
                    needed_registers.add(evidence.register.full_register)
                    runtime_indexes.append(variable.lvar_index)
            elif evidence.storage_kind == "stack" and evidence.stack_pointer_offset is not None:
                if variable.size not in SUPPORTED_WIDTHS:
                    self._set_unavailable(record, REASON_UNSUPPORTED_WIDTH)
                else:
                    self._set_waiting(record, "waiting for rsp to resolve exact stack location")
                    needed_registers.add("rsp")
                    runtime_indexes.append(variable.lvar_index)
            else:
                self._set_unavailable(record, evidence.reason)

            debug_lines.append(self._result_log_line(record))

        ordered_registers = _sort_registers(needed_registers)
        debug_lines.append(
            f"v-request pc_seq={pc_seq} registers={ordered_registers} memory=[]"
        )
        if not ordered_registers:
            return VRecoveryPlan(debug_lines=debug_lines)

        request_id = f"v-reg-{pc_seq}-runtime"
        self._pending[request_id] = _PendingVRequest(
            kind="reg",
            pc_seq=pc_seq,
            request_id=request_id,
            runtime_pc=runtime_pc,
            lvar_indexes=runtime_indexes,
            registers=ordered_registers,
        )
        request = envelope(
            TYPE_REG_REQUEST,
            {
                "pc_seq": pc_seq,
                "request_id": request_id,
                "runtime_pc": runtime_pc,
                "registers": ordered_registers,
                "reason": "v_variable_recovery",
            },
        )
        return VRecoveryPlan(register_request=request, debug_lines=debug_lines)

    def invalidate_pc(self, *, pc_seq: int, runtime_pc: str) -> None:
        """Reject all prior v responses when variable enumeration is unavailable."""
        self._start_context(0, 0, runtime_pc, pc_seq)

    def clear_runtime_state(self) -> None:
        """Drop pending runtime context without changing proven history."""
        self._pc_seq = None
        self._runtime_pc = ""
        self._function_ea = 0
        self._current_ea = 0
        self._pending.clear()
        self._records.clear()
        self._evidence.clear()
        self._source_variables.clear()

    def apply_reg_response(
        self,
        payload: dict[str, Any],
        *,
        envelope: EnvelopeFactory,
    ) -> tuple[bool, str, list[dict[str, Any]], list[str]]:
        """Apply one correlated v register response and create exact stack reads."""
        pending, reason = self._take_pending(payload, expected_kind="reg")
        if pending is None:
            return False, reason, [], []

        debug_lines: list[str] = []
        if payload.get("ok") is not True:
            self._mark_read_error(pending.lvar_indexes, "register read failed", debug_lines)
            return True, "register read failed", [], debug_lines

        registers = payload.get("registers")
        if not isinstance(registers, dict):
            self._mark_read_error(
                pending.lvar_indexes,
                "reg_response missing registers",
                debug_lines,
            )
            return True, "reg_response missing registers", [], debug_lines

        memory_requests: list[dict[str, Any]] = []
        memory_summaries: list[str] = []
        for lvar_index in pending.lvar_indexes:
            record = self._records.get(lvar_index)
            evidence = self._evidence.get(lvar_index)
            if record is None or evidence is None:
                continue

            if evidence.storage_kind == "register" and evidence.register is not None:
                raw_value = registers.get(evidence.register.full_register)
                try:
                    value = extract_register_value(raw_value, evidence.register, record.width)
                except (TypeError, ValueError) as exc:
                    self._set_error(record, f"register read failed: {exc}")
                else:
                    self._mark_fresh(record, value, CONFIDENCE_EXACT_REGISTER_LOCATION)
                debug_lines.append(self._result_log_line(record))
                continue

            if evidence.storage_kind != "stack" or evidence.stack_pointer_offset is None:
                continue
            try:
                address = concrete_stack_address(
                    registers.get("rsp"),
                    evidence.stack_pointer_offset,
                )
            except (TypeError, ValueError) as exc:
                self._set_error(record, f"{REASON_UNRESOLVED_STACK}: {exc}")
                debug_lines.append(self._result_log_line(record))
                continue

            request_id = f"v-mem-{pending.pc_seq}-{lvar_index}"
            self._pending[request_id] = _PendingVRequest(
                kind="mem",
                pc_seq=pending.pc_seq,
                request_id=request_id,
                runtime_pc=pending.runtime_pc,
                lvar_indexes=[lvar_index],
                address=address,
                size=record.width,
            )
            record.storage = f"stack:{address}"
            record.reason = "waiting for exact stack memory read"
            memory_requests.append(
                envelope(
                    TYPE_MEM_REQUEST,
                    {
                        "pc_seq": pending.pc_seq,
                        "request_id": request_id,
                        "runtime_pc": pending.runtime_pc,
                        "address": address,
                        "size": record.width,
                        "reason": "v_variable_stack",
                        "variable": record.name,
                        "lvar_index": lvar_index,
                    },
                )
            )
            memory_summaries.append(f"{record.name}@{address}/{record.width}")

        debug_lines.append(
            f"v-request pc_seq={pending.pc_seq} registers=[] memory={memory_summaries}"
        )
        return True, "accepted", memory_requests, debug_lines

    def apply_mem_response(
        self,
        payload: dict[str, Any],
    ) -> tuple[bool, str, list[str]]:
        """Apply one correlated exact-width v stack response."""
        pending, reason = self._take_pending(payload, expected_kind="mem")
        if pending is None:
            return False, reason, []

        if payload.get("address") not in (None, "", pending.address):
            self._pending[pending.request_id] = pending
            return False, "memory response address does not match pending request", []
        response_size = payload.get("size")
        if response_size not in (None, pending.size):
            self._pending[pending.request_id] = pending
            return False, "memory response size does not match pending request", []

        debug_lines: list[str] = []
        for lvar_index in pending.lvar_indexes:
            record = self._records.get(lvar_index)
            if record is None:
                continue
            if payload.get("ok") is not True:
                self._set_error(record, _runtime_error_reason(payload))
            else:
                try:
                    value = decode_little_endian(str(payload.get("bytes_hex", "")), pending.size)
                except ValueError as exc:
                    self._set_error(record, f"memory read failed: {exc}")
                else:
                    self._mark_fresh(record, value, CONFIDENCE_EXACT_STACK_LOCATION)
                    record.storage = f"stack:{pending.address}"
                    record.reason = f"exact stack memory read raw={payload.get('bytes_hex', '')}"
            debug_lines.append(self._result_log_line(record))
        return True, "accepted", debug_lines

    def overlay_rows(self, rows: list[VariableRecord]) -> list[VariableRecord]:
        """Overlay recovery state onto non-argument rows without touching arguments."""
        overlaid: list[VariableRecord] = []
        for row in rows:
            if row.is_arg:
                overlaid.append(row)
                continue
            record = self._records.get(row.lvar_index)
            if record is None:
                overlaid.append(row)
                continue
            overlaid.append(
                replace(
                    row,
                    value=record.value,
                    status=record.recovery_status,
                    confidence=record.confidence,
                    reason=record.reason,
                    last_pc=record.last_update_pc,
                    current_pc=record.current_runtime_pc,
                    current_ea=f"0x{record.current_ea:x}",
                    source_ea=(
                        "" if record.source_ea is None else f"0x{record.source_ea:x}"
                    ),
                    storage_kind=record.candidate_storage_kind,
                    storage=record.storage,
                    current_pc_seq=record.current_pc_seq,
                    last_success_value=record.last_successful_value,
                    last_success_pc_seq=record.last_successful_pc_seq,
                )
            )
        return overlaid

    def _start_context(
        self,
        function_ea: int,
        current_ea: int,
        runtime_pc: str,
        pc_seq: int,
    ) -> None:
        self._function_ea = function_ea
        self._current_ea = current_ea
        self._runtime_pc = runtime_pc
        self._pc_seq = pc_seq
        self._pending.clear()
        self._records.clear()
        self._evidence.clear()
        self._source_variables.clear()

    def _new_record(
        self,
        variable: VariableRecord,
        evidence: RecoveryEvidence,
        pc_seq: int,
        runtime_pc: str,
        current_ea: int,
    ) -> VVariableRecoveryRecord:
        history = self._matching_history(variable)
        return VVariableRecoveryRecord(
            lvar_index=variable.lvar_index,
            name=variable.name,
            type_string=variable.type_string,
            width=variable.size,
            printed_location=variable.printed_location or variable.location,
            function_ea=variable.function_start_ea,
            current_ea=current_ea,
            candidate_storage_kind=evidence.storage_kind,
            recovery_status=STATUS_UNAVAILABLE,
            confidence=CONFIDENCE_UNKNOWN,
            reason=evidence.reason,
            storage=evidence.storage,
            source_ea=evidence.source_ea,
            current_runtime_pc=runtime_pc,
            current_pc_seq=pc_seq,
            last_successful_value="" if history is None else history.value,
            last_successful_pc_seq=None if history is None else history.pc_seq,
            last_update_pc="" if history is None else history.runtime_pc,
        )

    def _matching_history(self, variable: VariableRecord) -> _HistoryValue | None:
        history = self._history.get((variable.function_start_ea, variable.lvar_index))
        if (
            history is None
            or history.name != variable.name
            or history.width != variable.size
            or history.type_string != variable.type_string
            or history.lvar_defea != variable.lvar_defea
        ):
            return None
        return history

    def _set_waiting(self, record: VVariableRecoveryRecord, reason: str) -> None:
        if record.last_successful_value:
            record.value = record.last_successful_value
            record.recovery_status = STATUS_STALE
            record.confidence = CONFIDENCE_STALE_RUNTIME_VALUE
        else:
            record.value = ""
            record.recovery_status = STATUS_UNAVAILABLE
            record.confidence = CONFIDENCE_UNKNOWN
        record.reason = reason

    def _set_unavailable(
        self,
        record: VVariableRecoveryRecord,
        reason: str,
        *,
        preserve_stale: bool = True,
    ) -> None:
        if preserve_stale and record.last_successful_value:
            record.value = record.last_successful_value
            record.recovery_status = STATUS_STALE
            record.confidence = CONFIDENCE_STALE_RUNTIME_VALUE
        else:
            record.value = ""
            record.recovery_status = STATUS_UNAVAILABLE
            record.confidence = CONFIDENCE_UNKNOWN
        record.reason = reason

    def _set_error(self, record: VVariableRecoveryRecord, reason: str) -> None:
        record.value = ""
        record.recovery_status = STATUS_ERROR
        record.confidence = CONFIDENCE_READ_FAILED
        record.reason = reason

    def _mark_fresh(
        self,
        record: VVariableRecoveryRecord,
        value: str,
        confidence: str,
    ) -> None:
        record.value = value
        record.recovery_status = STATUS_FRESH
        record.confidence = confidence
        if record.candidate_storage_kind == "constant":
            record.reason = "current reaching definition is an exact constant"
        elif record.candidate_storage_kind == "register":
            record.reason = "register location is proven live at current PC"
        record.last_successful_value = value
        record.last_successful_pc_seq = record.current_pc_seq
        record.last_update_pc = record.current_runtime_pc
        self._history[(record.function_ea, record.lvar_index)] = _HistoryValue(
            name=record.name,
            width=record.width,
            type_string=record.type_string,
            lvar_defea=self._row_lvar_defea(record.lvar_index),
            value=value,
            pc_seq=record.current_pc_seq,
            runtime_pc=record.current_runtime_pc,
            source_ea=record.source_ea,
        )
        self._prune_history()

    def _prune_history(self) -> None:
        overflow = len(self._history) - self._max_history
        if overflow <= 0:
            return
        oldest = sorted(
            self._history,
            key=lambda key: self._history[key].pc_seq,
        )
        for key in oldest[:overflow]:
            self._history.pop(key, None)

    def _row_lvar_defea(self, lvar_index: int) -> str:
        for row in getattr(self, "_source_variables", ()):
            if row.lvar_index == lvar_index:
                return row.lvar_defea
        return ""

    def _mark_read_error(
        self,
        indexes: list[int],
        reason: str,
        debug_lines: list[str],
    ) -> None:
        for lvar_index in indexes:
            record = self._records.get(lvar_index)
            if record is None:
                continue
            self._set_error(record, reason)
            debug_lines.append(self._result_log_line(record))

    def _take_pending(
        self,
        payload: dict[str, Any],
        *,
        expected_kind: str,
    ) -> tuple[_PendingVRequest | None, str]:
        if self._pc_seq is None:
            return None, "no current v recovery context"
        pc_seq = payload.get("pc_seq")
        if pc_seq != self._pc_seq:
            return None, f"stale pc_seq={pc_seq} current={self._pc_seq}"
        runtime_pc = payload.get("runtime_pc")
        if runtime_pc and runtime_pc != self._runtime_pc:
            return None, "runtime_pc does not match current v recovery context"
        request_id = payload.get("request_id")
        if not isinstance(request_id, str):
            return None, "missing request_id"
        pending = self._pending.get(request_id)
        if pending is None:
            return None, f"unexpected request_id={request_id!r}"
        if pending.kind != expected_kind:
            return None, f"unexpected response kind for request_id={request_id!r}"
        self._pending.pop(request_id, None)
        return pending, "accepted"

    @staticmethod
    def _result_log_line(record: VVariableRecoveryRecord) -> str:
        source = record.storage or record.candidate_storage_kind or "none"
        if (
            record.candidate_storage_kind == "register"
            and source != "none"
            and not source.startswith("register:")
        ):
            source = f"register:{source}"
        result = (
            "pending"
            if record.reason.startswith("waiting for ")
            else record.recovery_status
        )
        return (
            f"v-recovery name={record.name} result={result} "
            f"source={source} reason={record.reason}"
        )


def _sort_registers(registers: set[str]) -> list[str]:
    order = {name: index for index, name in enumerate(FULL_REGISTER_ORDER)}
    return sorted(registers, key=lambda name: (order.get(name, len(order)), name))


def _runtime_error_reason(payload: dict[str, Any]) -> str:
    error = payload.get("error")
    if isinstance(error, dict):
        message = error.get("message")
        if isinstance(message, str) and message:
            return message
    if isinstance(error, str) and error:
        return error
    return "runtime read failed"


@dataclass(frozen=True)
class _CtreeFact:
    lvar_index: int
    kind: str
    ea: int | None
    constant_value: int | None = None


@dataclass(frozen=True)
class _InsnAccess:
    uses: frozenset[int]
    targets: tuple[tuple[int, int, int], ...]


@dataclass(frozen=True)
class _MicroBlockData:
    block_id: int
    block: object
    instructions: tuple[object, ...]
    accesses: tuple[_InsnAccess, ...]
    eas: tuple[int | None, ...]
    predecessors: tuple[int, ...]
    successors: tuple[int, ...]


@dataclass(frozen=True)
class _RegisterWrite:
    full_register: str
    bit_offset: int
    bit_size: int

    def covers(self, spec: RegisterSpec, width: int) -> bool:
        wanted_start = spec.bit_offset
        wanted_end = wanted_start + width * 8
        return self.bit_offset <= wanted_start and self.bit_offset + self.bit_size >= wanted_end

    def overlaps(self, spec: RegisterSpec, width: int) -> bool:
        wanted_start = spec.bit_offset
        wanted_end = wanted_start + width * 8
        return self.bit_offset < wanted_end and wanted_start < self.bit_offset + self.bit_size


@dataclass(frozen=True)
class _CfgInstructionFact:
    """Candidate-specific lvar facts for one top-level microinstruction."""

    ea: int | None
    whole_definition: bool = False
    overlapping_definition: bool = False
    use: bool = False


@dataclass(frozen=True)
class _CfgBlockFacts:
    """Small, IDA-independent CFG block used by analysis and unit tests."""

    block_id: int
    instructions: tuple[_CfgInstructionFact, ...]
    predecessors: tuple[int, ...] = ()
    successors: tuple[int, ...] = ()


@dataclass(frozen=True)
class _DefinitionSite:
    block_id: int
    instruction_index: int
    ea: int | None
    crossed_block: bool = False


@dataclass(frozen=True)
class _ReachingDefinitionResult:
    definitions: tuple[_DefinitionSite, ...]
    unresolved_path: bool = False
    overlapping_definition: bool = False
    loop_detected: bool = False
    traversal_exhausted: bool = False
    visited_states: int = 0

    @property
    def count(self) -> int:
        return len(self.definitions)


@dataclass(frozen=True)
class _FutureUseResult:
    use_sites: tuple[_DefinitionSite, ...]
    redefinition_paths: int = 0
    unresolved_use: bool = False
    loop_detected: bool = False
    traversal_exhausted: bool = False
    visited_states: int = 0

    @property
    def has_use(self) -> bool:
        return bool(self.use_sites)


@dataclass(frozen=True)
class _NativeInstructionFact:
    ea: int
    size: int
    writes: tuple[_RegisterWrite, ...] = ()
    is_call: bool = False
    register_access_known: bool = True


@dataclass(frozen=True)
class _NativeBlockFacts:
    block_id: int
    start_ea: int
    end_ea: int
    instructions: tuple[_NativeInstructionFact, ...]
    predecessors: tuple[int, ...] = ()
    successors: tuple[int, ...] = ()


@dataclass(frozen=True)
class _StorageValidation:
    valid: bool
    reason: str
    clobber_ea: int | None = None
    visited_blocks: int = 0


def _find_reaching_definitions(
    blocks: dict[int, _CfgBlockFacts],
    current_block_id: int,
    current_instruction: int,
    *,
    max_states: int | None = None,
) -> _ReachingDefinitionResult:
    """Find first whole definitions on every backward path to a PC.

    ``current_instruction`` is a pre-instruction boundary: the instruction at
    that index has not executed.  A block/limit state is scanned once, so
    diamonds are deduplicated while loops remain bounded and detectable.
    """
    budget = max_states if max_states is not None else max(64, len(blocks) * 4 + 4)
    pending: list[tuple[int, int]] = [(current_block_id, current_instruction)]
    visited: set[tuple[int, int]] = set()
    edges: dict[tuple[int, int], set[tuple[int, int]]] = {}
    definitions: dict[tuple[int, int], _DefinitionSite] = {}
    unresolved_path = False
    overlapping_definition = False
    traversal_exhausted = False

    while pending:
        state = pending.pop()
        if state in visited:
            continue
        if len(visited) >= budget:
            traversal_exhausted = True
            break
        visited.add(state)
        edges.setdefault(state, set())

        block_id, limit = state
        block = blocks.get(block_id)
        if block is None or limit < 0 or limit > len(block.instructions):
            unresolved_path = True
            continue

        stopped = False
        for position in range(limit - 1, -1, -1):
            fact = block.instructions[position]
            if fact.overlapping_definition and not fact.whole_definition:
                overlapping_definition = True
                stopped = True
                break
            if fact.whole_definition:
                if fact.overlapping_definition:
                    overlapping_definition = True
                site = _DefinitionSite(block_id, position, fact.ea)
                definitions[(block_id, position)] = site
                stopped = True
                break
        if stopped:
            continue

        if not block.predecessors:
            unresolved_path = True
            continue
        for predecessor_id in block.predecessors:
            predecessor = blocks.get(predecessor_id)
            if predecessor is None:
                unresolved_path = True
                continue
            predecessor_state = (predecessor_id, len(predecessor.instructions))
            edges[state].add(predecessor_state)
            edges.setdefault(predecessor_state, set())
            if predecessor_state not in visited:
                pending.append(predecessor_state)

    ordered = tuple(
        sorted(
            definitions.values(),
            key=lambda site: (site.block_id, site.instruction_index),
        )
    )
    return _ReachingDefinitionResult(
        definitions=ordered,
        unresolved_path=unresolved_path,
        overlapping_definition=overlapping_definition,
        loop_detected=_graph_has_cycle(edges),
        traversal_exhausted=traversal_exhausted,
        visited_states=len(visited),
    )


def _find_future_uses(
    blocks: dict[int, _CfgBlockFacts],
    current_block_id: int,
    current_instruction: int,
    *,
    max_states: int | None = None,
) -> _FutureUseResult:
    """Search successors for any use before an overlapping redefinition."""
    budget = max_states if max_states is not None else max(64, len(blocks) * 4 + 4)
    pending: list[tuple[int, int]] = [(current_block_id, current_instruction)]
    visited: set[tuple[int, int]] = set()
    edges: dict[tuple[int, int], set[tuple[int, int]]] = {}
    use_sites: dict[tuple[int, int], _DefinitionSite] = {}
    redefinition_paths = 0
    unresolved_use = False
    traversal_exhausted = False
    initial_state = (current_block_id, current_instruction)

    while pending:
        state = pending.pop()
        if state in visited:
            continue
        if len(visited) >= budget:
            traversal_exhausted = True
            break
        visited.add(state)
        edges.setdefault(state, set())

        block_id, start = state
        block = blocks.get(block_id)
        if block is None or start < 0 or start > len(block.instructions):
            traversal_exhausted = True
            continue

        stopped = False
        for position in range(start, len(block.instructions)):
            fact = block.instructions[position]
            if fact.use:
                if fact.ea is None:
                    unresolved_use = True
                else:
                    use_sites[(block_id, position)] = _DefinitionSite(
                        block_id,
                        position,
                        fact.ea,
                        crossed_block=state != initial_state,
                    )
                    stopped = True
                    break
            if fact.whole_definition or fact.overlapping_definition:
                redefinition_paths += 1
                stopped = True
                break
        if stopped:
            continue

        for successor_id in block.successors:
            successor = blocks.get(successor_id)
            if successor is None:
                traversal_exhausted = True
                continue
            successor_state = (successor_id, 0)
            edges[state].add(successor_state)
            edges.setdefault(successor_state, set())
            if successor_state not in visited:
                pending.append(successor_state)

    ordered = tuple(
        sorted(
            use_sites.values(),
            key=lambda site: (site.block_id, site.instruction_index),
        )
    )
    return _FutureUseResult(
        use_sites=ordered,
        redefinition_paths=redefinition_paths,
        unresolved_use=unresolved_use,
        loop_detected=_graph_has_cycle(edges),
        traversal_exhausted=traversal_exhausted,
        visited_states=len(visited),
    )


def _reaching_definition_rejection_reason(
    result: _ReachingDefinitionResult,
) -> str | None:
    if result.overlapping_definition:
        return REASON_AMBIGUOUS_REACHING_DEFINITION
    if result.count == 0:
        return REASON_NO_DEFINITION
    if result.count > 1:
        return REASON_AMBIGUOUS_REACHING_DEFINITION
    if result.unresolved_path:
        return REASON_NO_DEFINITION
    if result.loop_detected or result.traversal_exhausted:
        return REASON_AMBIGUOUS_REACHING_DEFINITION
    return None


def _future_use_rejection_reason(result: _FutureUseResult) -> str | None:
    if result.has_use:
        return None
    if result.unresolved_use or result.loop_detected or result.traversal_exhausted:
        return REASON_CROSS_BLOCK_LIVENESS_UNPROVEN
    return REASON_NOT_LIVE


def _graph_has_cycle(edges: dict[tuple[int, int], set[tuple[int, int]]]) -> bool:
    nodes = set(edges)
    for destinations in edges.values():
        nodes.update(destinations)
    if not nodes:
        return False
    indegree = {node: 0 for node in nodes}
    for destinations in edges.values():
        for destination in destinations:
            indegree[destination] += 1
    ready = [node for node, degree in indegree.items() if degree == 0]
    removed = 0
    while ready:
        node = ready.pop()
        removed += 1
        for destination in edges.get(node, ()):
            indegree[destination] -= 1
            if indegree[destination] == 0:
                ready.append(destination)
    return removed != len(nodes)


def _validate_register_storage_cfg(
    blocks: dict[int, _NativeBlockFacts],
    definition_ea: int,
    current_ea: int,
    register: RegisterSpec,
    width: int,
) -> _StorageValidation:
    """Prove one physical GPR is unchanged on every def-to-PC CFG path.

    The native query runs backward from the exact pre-instruction PC.  Every
    predecessor path must reach the selected microcode definition before a
    call, overlapping physical-register write, decode uncertainty, or entry.
    """
    definition_matches = [
        (block.block_id, position, instruction)
        for block in blocks.values()
        for position, instruction in enumerate(block.instructions)
        if instruction.ea == definition_ea
    ]
    current_matches = [
        (block.block_id, position, instruction)
        for block in blocks.values()
        for position, instruction in enumerate(block.instructions)
        if instruction.ea == current_ea
    ]
    if len(definition_matches) != 1 or len(current_matches) != 1:
        return _StorageValidation(False, REASON_UNRESOLVED_NATIVE_POINT)

    definition_block_id, definition_position, _definition_instruction = definition_matches[0]
    current_block_id, current_position, _current_instruction = current_matches[0]
    if (
        definition_block_id == current_block_id
        and definition_position >= current_position
    ):
        return _StorageValidation(False, REASON_UNRESOLVED_NATIVE_POINT)

    budget = max(64, len(blocks) * 4 + 4)
    pending: list[tuple[int, int]] = [(current_block_id, current_position)]
    visited: set[tuple[int, int]] = set()
    edges: dict[tuple[int, int], set[tuple[int, int]]] = {}
    reached_definition = False
    unresolved = False
    traversal_exhausted = False
    clobber_ea: int | None = None

    while pending:
        state = pending.pop()
        if state in visited:
            continue
        if len(visited) >= budget:
            traversal_exhausted = True
            break
        visited.add(state)
        edges.setdefault(state, set())

        block_id, limit = state
        block = blocks.get(block_id)
        if (
            block is None
            or limit < 0
            or limit > len(block.instructions)
            or not block.instructions
        ):
            unresolved = True
            continue

        stopped = False
        for position in range(limit - 1, -1, -1):
            instruction = block.instructions[position]
            if instruction.ea == definition_ea:
                if not instruction.register_access_known or not any(
                    write.full_register == register.full_register
                    and write.covers(register, width)
                    for write in instruction.writes
                ):
                    clobber_ea = instruction.ea
                else:
                    reached_definition = True
                stopped = True
                break
            if not instruction.register_access_known:
                unresolved = True
                stopped = True
                break
            if instruction.is_call or any(
                write.full_register == register.full_register
                and write.overlaps(register, width)
                for write in instruction.writes
            ):
                clobber_ea = instruction.ea
                stopped = True
                break
        if stopped:
            continue

        if not block.predecessors:
            unresolved = True
            continue
        for predecessor_id in block.predecessors:
            predecessor = blocks.get(predecessor_id)
            if predecessor is None:
                unresolved = True
                continue
            predecessor_state = (predecessor_id, len(predecessor.instructions))
            edges[state].add(predecessor_state)
            edges.setdefault(predecessor_state, set())
            if predecessor_state not in visited:
                pending.append(predecessor_state)

    if clobber_ea is not None:
        return _StorageValidation(
            False,
            REASON_STORAGE_CLOBBERED,
            clobber_ea,
            len({block_id for block_id, _limit in visited}),
        )
    if (
        not reached_definition
        or unresolved
        or traversal_exhausted
        or _graph_has_cycle(edges)
    ):
        reason = (
            REASON_CROSS_BLOCK_LIVENESS_UNPROVEN
            if traversal_exhausted or _graph_has_cycle(edges)
            else REASON_UNRESOLVED_NATIVE_POINT
        )
        return _StorageValidation(
            False,
            reason,
            visited_blocks=len({block_id for block_id, _limit in visited}),
        )
    return _StorageValidation(
        True,
        "exact register storage survives to current PC",
        visited_blocks=len({block_id for block_id, _limit in visited}),
    )


def analyze_v_variable_candidates(
    function_ea: int,
    current_ea: int,
    variables: list[VariableRecord],
    cfunc: object | None = None,
) -> RecoveryAnalysis:
    """Prove a conservative CFG-aware recovery subset at ``current_ea``.

    The proof point is immediately before the native instruction at
    ``current_ea``.  A definition at that same EA therefore has not executed.
    """
    indexes = [variable.lvar_index for variable in variables]
    unavailable = {
        index: RecoveryEvidence(index, reason=REASON_MICROCODE) for index in indexes
    }
    required = (
        ida_frame,
        ida_funcs,
        ida_gdl,
        ida_hexrays,
        ida_idp,
        ida_ua,
    )
    if any(module is None for module in required):
        return RecoveryAnalysis(
            ok=False,
            evidence_by_index=unavailable,
            error="IDA/Hex-Rays recovery APIs are unavailable",
        )

    required_hexrays_names = (
        "MMAT_LVARS",
        "mop_l",
        "mop_n",
        "m_mov",
        "mop_visitor_t",
        "get_mreg_name",
        "mreg2reg",
    )
    if any(not hasattr(ida_hexrays, name) for name in required_hexrays_names):
        return RecoveryAnalysis(
            ok=False,
            evidence_by_index=unavailable,
            error="required IDA 9.3 microcode APIs are unavailable",
        )

    try:
        func = ida_funcs.get_func(current_ea)
        if func is None or int(func.start_ea) != function_ea:
            raise RuntimeError("mapped EA does not belong to the enumerated function")
        if (
            not hasattr(ida_idp, "ph_get_id")
            or not hasattr(ida_idp, "PLFM_386")
            or int(ida_idp.ph_get_id()) != int(ida_idp.PLFM_386)
            or int(ida_funcs.get_func_bits(func)) != 64
        ):
            raise RuntimeError("v recovery currently supports x64 functions only")
        if cfunc is None:
            cfunc = ida_hexrays.decompile(function_ea)
        if cfunc is None:
            raise RuntimeError("Hex-Rays decompilation returned no cfunc")
        mba = getattr(cfunc, "mba", None)
        if mba is None:
            raise RuntimeError("cfunc has no underlying microcode")
        if int(getattr(mba, "maturity", -1)) < int(ida_hexrays.MMAT_LVARS):
            raise RuntimeError("microcode has not reached MMAT_LVARS")
        if not hasattr(mba, "vars") or not hasattr(mba, "get_mblock"):
            raise RuntimeError("microcode lvar/block APIs are unavailable")
        decoded_current = _decode_instruction(current_ea)
        if decoded_current is None:
            raise RuntimeError(f"native instruction decode failed at 0x{current_ea:x}")
        native_bounds = _native_block_bounds(func, current_ea)
        micro_blocks = _collect_micro_blocks(mba)
        current_block, boundary = _find_exact_microcode_point(
            micro_blocks,
            current_ea,
        )
        if current_block is None:
            evidence = {
                index: RecoveryEvidence(index, reason=REASON_UNRESOLVED_NATIVE_POINT)
                for index in indexes
            }
            return RecoveryAnalysis(
                ok=True,
                evidence_by_index=evidence,
                debug_lines=[
                    "v-analysis current EA has no unique contiguous top-level MMAT_LVARS run"
                ],
            )
        native_cfg, native_cfg_error = _build_native_cfg_facts(func)
        ctree_facts = _collect_ctree_facts(cfunc, mba)
    except Exception as exc:
        return RecoveryAnalysis(
            ok=False,
            evidence_by_index=unavailable,
            error=f"{REASON_MICROCODE}: {exc}",
        )

    debug_lines = [
        "v-analysis function=0x{function:x} current_block={block} "
        "current_instruction={instruction} current_ea=0x{current:x} "
        "micro_blocks={blocks} micro_insns={count} ctree_facts={facts}".format(
            function=function_ea,
            block=current_block.block_id,
            instruction=boundary,
            current=current_ea,
            blocks=len(micro_blocks),
            count=len(current_block.instructions),
            facts=len(ctree_facts),
        )
    ]
    if native_cfg is None:
        debug_lines.append(f"v-native-cfg unavailable reason={native_cfg_error}")
    evidence_by_index: dict[int, RecoveryEvidence] = {}
    lvars = getattr(mba, "vars")
    lvar_count = _vector_size(lvars)

    for variable in variables:
        index = variable.lvar_index
        lvar: object | None = None
        candidate_debug: list[str] = []
        try:
            if index < 0 or index >= lvar_count:
                raise _CandidateRejected(REASON_NO_DEFINITION)
            lvar = _vector_at(lvars, index)
            lvar_name = str(getattr(lvar, "name", "") or "")
            display_name = "" if variable.name == "<unnamed>" else variable.name
            if lvar_name != display_name:
                raise _CandidateRejected(REASON_MICROCODE)
            if int(getattr(lvar, "width", 0) or 0) != variable.size:
                raise _CandidateRejected(REASON_UNSUPPORTED_WIDTH)
            evidence_by_index[index] = _analyze_one_lvar(
                variable=variable,
                lvar=lvar,
                lvars=lvars,
                mba=mba,
                cfunc=cfunc,
                func=func,
                micro_blocks=micro_blocks,
                current_block=current_block,
                boundary=boundary,
                current_ea=current_ea,
                native_bounds=native_bounds,
                native_cfg=native_cfg,
                native_cfg_error=native_cfg_error,
                ctree_facts=ctree_facts,
                debug_lines=candidate_debug,
            )
        except _CandidateRejected as rejected:
            evidence_by_index[index] = _unavailable_location_evidence(
                lvar,
                index,
                variable.size,
                rejected.reason,
            )
        except Exception as exc:
            evidence_by_index[index] = RecoveryEvidence(
                index,
                reason=REASON_MICROCODE,
            )
            debug_lines.append(
                f"v-analysis candidate index={index} failed reason={exc}"
            )
        _complete_candidate_diagnostics(
            candidate_debug,
            variable,
            current_block,
            boundary,
            current_ea,
            evidence_by_index[index],
        )
        debug_lines.extend(candidate_debug)

    _reject_duplicate_storage_claims(evidence_by_index)
    return RecoveryAnalysis(
        ok=True,
        evidence_by_index=evidence_by_index,
        debug_lines=debug_lines,
    )


class _CandidateRejected(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _complete_candidate_diagnostics(
    debug_lines: list[str],
    variable: VariableRecord,
    current_block: _MicroBlockData,
    boundary: int,
    current_ea: int,
    evidence: RecoveryEvidence,
) -> None:
    cfg_prefix = f"v-cfg-point name={variable.name} "
    if not any(line.startswith(cfg_prefix) for line in debug_lines):
        debug_lines.append(
            "v-cfg-point name={name} current_block={block} "
            "current_instruction={instruction} current_ea=0x{ea:x}".format(
                name=variable.name,
                block=current_block.block_id,
                instruction=boundary,
                ea=current_ea,
            )
        )
    reaching_prefix = f"v-reaching-def name={variable.name} "
    if not any(line.startswith(reaching_prefix) for line in debug_lines):
        debug_lines.append(
            "v-reaching-def name={name} def_ea=none def_block=none "
            "current_ea=0x{current:x} current_block={block} count=0 "
            "undefined_paths=0 overlap=0 loop=0 exhausted=0 reason={reason}".format(
                name=variable.name,
                current=current_ea,
                block=current_block.block_id,
                reason=evidence.reason,
            )
        )
    live_prefix = f"v-cross-block-live name={variable.name} "
    if not any(line.startswith(live_prefix) for line in debug_lines):
        debug_lines.append(
            "v-cross-block-live name={name} result=unproven use_ea=none "
            "use_block=none redefinitions=0 loop=0 exhausted=0 reason={reason}".format(
                name=variable.name,
                reason=evidence.reason,
            )
        )
    storage_prefix = f"v-storage-valid name={variable.name} "
    if not any(line.startswith(storage_prefix) for line in debug_lines):
        if evidence.confidence == CONFIDENCE_EXACT_CONSTANT:
            result = "not_required"
        elif evidence.confidence in (
            CONFIDENCE_EXACT_REGISTER_LOCATION,
            CONFIDENCE_EXACT_STACK_LOCATION,
        ):
            result = "valid"
        else:
            result = "unavailable"
        debug_lines.append(
            "v-storage-valid name={name} storage={storage} result={result} "
            "reason={reason} current_instruction={instruction}".format(
                name=variable.name,
                storage=evidence.storage or "unproven",
                result=result,
                reason=evidence.reason,
                instruction=boundary,
            )
        )


def _unavailable_location_evidence(
    lvar: object,
    index: int,
    width: int,
    reason: str,
) -> RecoveryEvidence:
    if _safe_bool_call(lvar, "is_scattered") or _safe_bool_call(
        lvar, "was_scattered_arg"
    ):
        return RecoveryEvidence(
            index,
            storage_kind="scattered",
            storage="scattered",
            reason=reason,
            width=width,
        )
    if _safe_bool_call(lvar, "is_reg_var"):
        spec = _register_spec_from_lvar(lvar, width)
        storage = "ambiguous" if spec is None else spec.alias
        return RecoveryEvidence(
            index,
            storage_kind="register",
            storage=storage,
            reason=reason,
            width=width,
        )
    if _safe_bool_call(lvar, "is_stk_var"):
        return RecoveryEvidence(
            index,
            storage_kind="stack",
            storage="stack:unresolved",
            reason=reason,
            width=width,
        )
    return RecoveryEvidence(index, reason=reason, width=width)


def _analyze_one_lvar(
    *,
    variable: VariableRecord,
    lvar: object,
    lvars: object,
    mba: object,
    cfunc: object,
    func: object,
    micro_blocks: dict[int, _MicroBlockData],
    current_block: _MicroBlockData,
    boundary: int,
    current_ea: int,
    native_bounds: tuple[int, int] | None,
    native_cfg: dict[int, _NativeBlockFacts] | None,
    native_cfg_error: str,
    ctree_facts: list[_CtreeFact],
    debug_lines: list[str],
) -> RecoveryEvidence:
    index = variable.lvar_index
    width = variable.size
    debug_lines.append(
        "v-cfg-point name={name} current_block={block} current_instruction={instruction} "
        "current_ea=0x{ea:x}".format(
            name=variable.name,
            block=current_block.block_id,
            instruction=boundary,
            ea=current_ea,
        )
    )
    if width not in SUPPORTED_WIDTHS:
        raise _CandidateRejected(REASON_UNSUPPORTED_WIDTH)
    if _safe_bool_call(lvar, "is_scattered") or _safe_bool_call(
        lvar, "was_scattered_arg"
    ):
        raise _CandidateRejected(REASON_SCATTERED)
    if (
        _safe_bool_call(lvar, "is_shared")
        or _safe_bool_call(lvar, "is_overlapped_var")
        or _safe_bool_call(lvar, "is_used_byref")
    ):
        reason = (
            REASON_AMBIGUOUS_REGISTER
            if _safe_bool_call(lvar, "is_reg_var")
            else REASON_UNRESOLVED_STACK
        )
        raise _CandidateRejected(reason)

    candidate_cfg = _candidate_cfg_facts(
        lvar,
        lvars,
        index,
        width,
        micro_blocks,
    )
    reaching = _find_reaching_definitions(
        candidate_cfg,
        current_block.block_id,
        boundary,
    )
    selected = reaching.definitions[0] if reaching.count == 1 else None
    debug_lines.append(
        "v-reaching-def name={name} def_ea={def_ea} def_block={def_block} "
        "current_ea=0x{current:x} current_block={current_block} count={count} "
        "undefined_paths={undefined} overlap={overlap} loop={loop} exhausted={exhausted}".format(
            name=variable.name,
            def_ea=(
                "none"
                if selected is None or selected.ea is None
                else f"0x{selected.ea:x}"
            ),
            def_block="none" if selected is None else selected.block_id,
            current=current_ea,
            current_block=current_block.block_id,
            count=reaching.count,
            undefined=int(reaching.unresolved_path),
            overlap=int(reaching.overlapping_definition),
            loop=int(reaching.loop_detected),
            exhausted=int(reaching.traversal_exhausted),
        )
    )
    reaching_rejection = _reaching_definition_rejection_reason(reaching)
    if reaching_rejection is not None:
        raise _CandidateRejected(reaching_rejection)
    assert selected is not None
    definition_block = micro_blocks.get(selected.block_id)
    if (
        definition_block is None
        or selected.instruction_index < 0
        or selected.instruction_index >= len(definition_block.instructions)
        or selected.ea is None
    ):
        raise _CandidateRejected(REASON_NO_DEFINITION)
    definition = definition_block.instructions[selected.instruction_index]
    definition_ea = selected.ea
    native_definition = _decode_instruction(definition_ea)
    if native_definition is None:
        raise _CandidateRejected(REASON_UNRESOLVED_NATIVE_POINT)

    liveness = _find_future_uses(
        candidate_cfg,
        current_block.block_id,
        boundary,
    )
    first_use = liveness.use_sites[0] if liveness.use_sites else None
    live_result = "not_live"
    if first_use is not None:
        live_result = (
            "cross_block_use" if first_use.crossed_block else "same_block_use"
        )
    elif (
        liveness.unresolved_use
        or liveness.loop_detected
        or liveness.traversal_exhausted
    ):
        live_result = "unproven"
    debug_lines.append(
        "v-cross-block-live name={name} result={result} use_ea={use_ea} "
        "use_block={use_block} redefinitions={redefinitions} loop={loop} exhausted={exhausted}".format(
            name=variable.name,
            result=live_result,
            use_ea=(
                "none"
                if first_use is None or first_use.ea is None
                else f"0x{first_use.ea:x}"
            ),
            use_block="none" if first_use is None else first_use.block_id,
            redefinitions=liveness.redefinition_paths,
            loop=int(liveness.loop_detected),
            exhausted=int(liveness.traversal_exhausted),
        )
    )
    liveness_rejection = _future_use_rejection_reason(liveness)
    if liveness_rejection is not None:
        raise _CandidateRejected(liveness_rejection)

    register = _register_spec_from_lvar(lvar, width)
    constant = _direct_constant_definition(definition, index, width)
    prefer_constant = constant is not None and (
        register is None or _native_definition_uses_immediate(native_definition)
    )
    if prefer_constant:
        # Ctree is supporting evidence and a diagnostic cross-check. Final
        # MMAT_LVARS `m_mov mop_n -> mop_l[idx]` remains the exact proof.
        contradictory = [
            fact
            for fact in ctree_facts
            if fact.lvar_index == index
            and fact.kind == "constant_def"
            and fact.ea == definition_ea
            and fact.constant_value is not None
            and _mask_value(fact.constant_value, width) != _mask_value(constant, width)
        ]
        if contradictory:
            raise _CandidateRejected(REASON_NO_DEFINITION)
        return RecoveryEvidence(
            lvar_index=index,
            storage_kind="constant",
            storage=f"constant:{_format_constant(constant, width)}",
            source_ea=definition_ea,
            confidence=CONFIDENCE_EXACT_CONSTANT,
            reason="unique CFG reaching definition proves an exact live constant",
            constant_value=constant,
            width=width,
        )

    if register is not None:
        if native_cfg is None:
            debug_lines.append(
                "v-storage-valid name={name} storage={storage} result=unavailable "
                "reason={reason}".format(
                    name=variable.name,
                    storage=register.alias,
                    reason=native_cfg_error or REASON_UNRESOLVED_NATIVE_POINT,
                )
            )
            raise _CandidateRejected(REASON_UNRESOLVED_NATIVE_POINT)
        storage_validation = _validate_register_storage_cfg(
            native_cfg,
            definition_ea,
            current_ea,
            register,
            width,
        )
        debug_lines.append(
            "v-storage-valid name={name} storage={storage} result={result} "
            "reason={reason} clobber_ea={clobber} blocks={blocks}".format(
                name=variable.name,
                storage=register.alias,
                result="valid" if storage_validation.valid else "unavailable",
                reason=storage_validation.reason,
                clobber=(
                    "none"
                    if storage_validation.clobber_ea is None
                    else f"0x{storage_validation.clobber_ea:x}"
                ),
                blocks=storage_validation.visited_blocks,
            )
        )
        if not storage_validation.valid:
            raise _CandidateRejected(storage_validation.reason)
        return RecoveryEvidence(
            lvar_index=index,
            storage_kind="register",
            storage=register.alias,
            source_ea=definition_ea,
            confidence=CONFIDENCE_EXACT_REGISTER_LOCATION,
            reason="unique CFG reaching definition and storage proof establish register liveness",
            register=register,
            width=width,
        )

    if _safe_bool_call(lvar, "is_reg_var"):
        raise _CandidateRejected(REASON_AMBIGUOUS_REGISTER)
    if _safe_bool_call(lvar, "is_stk_var"):
        if selected.block_id != current_block.block_id or native_bounds is None:
            raise _CandidateRejected(REASON_UNRESOLVED_STACK)
        if not (native_bounds[0] <= definition_ea < native_bounds[1]):
            raise _CandidateRejected(REASON_UNRESOLVED_STACK)
        if _safe_bool_call_with_arg(lvar, "is_aliasable", mba):
            raise _CandidateRejected(REASON_UNRESOLVED_STACK)
        rsp_offset, ida_stack_offset = _current_rsp_location_for_lvar(
            lvar=lvar,
            mba=mba,
            cfunc=cfunc,
            func=func,
            current_ea=current_ea,
        )
        if not _stack_definition_remains_valid(
            definition_ea=definition_ea,
            current_ea=current_ea,
            func=func,
            ida_stack_offset=ida_stack_offset,
            width=width,
        ):
            raise _CandidateRejected(REASON_UNRESOLVED_STACK)
        return RecoveryEvidence(
            lvar_index=index,
            storage_kind="stack",
            storage=f"stack:rsp{rsp_offset:+#x}",
            source_ea=definition_ea,
            confidence=CONFIDENCE_EXACT_STACK_LOCATION,
            reason="unique reaching definition and future use prove exact stack slot",
            stack_pointer_offset=rsp_offset,
            width=width,
        )
    raise _CandidateRejected(REASON_NO_DEFINITION)


def _collect_micro_blocks(mba: object) -> dict[int, _MicroBlockData]:
    qty = int(getattr(mba, "qty", 0) or 0)
    if qty <= 0:
        raise RuntimeError("microcode CFG has no blocks")
    blocks: dict[int, _MicroBlockData] = {}
    for serial in range(qty):
        block = mba.get_mblock(serial)
        if block is None or int(getattr(block, "serial", serial)) != serial:
            raise RuntimeError(f"microcode block serial mismatch at {serial}")
        instructions = tuple(_top_instructions(block))
        predecessors = _micro_edge_ids(block, "npred", "pred", qty)
        successors = _micro_edge_ids(block, "nsucc", "succ", qty)
        blocks[serial] = _MicroBlockData(
            block_id=serial,
            block=block,
            instructions=instructions,
            accesses=tuple(_collect_lvar_accesses(insn) for insn in instructions),
            eas=tuple(
                _real_micro_ea(mba, getattr(insn, "ea", None))
                for insn in instructions
            ),
            predecessors=predecessors,
            successors=successors,
        )
    _validate_cfg_reciprocity(blocks, "microcode")
    return blocks


def _micro_edge_ids(
    block: object,
    count_method_name: str,
    edge_method_name: str,
    qty: int,
) -> tuple[int, ...]:
    count_method = getattr(block, count_method_name, None)
    edge_method = getattr(block, edge_method_name, None)
    if not callable(count_method) or not callable(edge_method):
        raise RuntimeError(
            f"microcode CFG API missing {count_method_name}/{edge_method_name}"
        )
    count = int(count_method())
    if count < 0 or count > qty:
        raise RuntimeError(f"invalid microcode edge count {count}")
    edge_ids: list[int] = []
    for edge_index in range(count):
        edge = edge_method(edge_index)
        edge_id = int(getattr(edge, "serial", edge))
        if edge_id < 0 or edge_id >= qty:
            raise RuntimeError(f"invalid microcode edge serial {edge_id}")
        edge_ids.append(edge_id)
    return tuple(sorted(set(edge_ids)))


def _validate_cfg_reciprocity(blocks: dict[int, object], label: str) -> None:
    for block_id, block in blocks.items():
        predecessors = tuple(getattr(block, "predecessors", ()))
        successors = tuple(getattr(block, "successors", ()))
        for successor_id in successors:
            successor = blocks.get(int(successor_id))
            if successor is None or block_id not in tuple(
                getattr(successor, "predecessors", ())
            ):
                raise RuntimeError(
                    f"{label} CFG edge {block_id}->{successor_id} is not reciprocal"
                )
        for predecessor_id in predecessors:
            predecessor = blocks.get(int(predecessor_id))
            if predecessor is None or block_id not in tuple(
                getattr(predecessor, "successors", ())
            ):
                raise RuntimeError(
                    f"{label} CFG edge {predecessor_id}->{block_id} is not reciprocal"
                )


def _find_exact_microcode_point(
    micro_blocks: dict[int, _MicroBlockData],
    current_ea: int,
) -> tuple[_MicroBlockData | None, int]:
    matches: list[tuple[_MicroBlockData, list[int]]] = []
    for block in micro_blocks.values():
        positions = [
            position for position, ea in enumerate(block.eas) if ea == current_ea
        ]
        if not positions:
            continue
        expected = list(range(positions[0], positions[-1] + 1))
        if positions != expected:
            return None, 0
        matches.append((block, positions))
    if len(matches) != 1:
        return None, 0
    block, positions = matches[0]
    # All microinstructions for the current native instruction are still in
    # the future at a pre-instruction debugger PC.
    return block, positions[0]


def _candidate_cfg_facts(
    target_lvar: object,
    lvars: object,
    index: int,
    width: int,
    micro_blocks: dict[int, _MicroBlockData],
) -> dict[int, _CfgBlockFacts]:
    blocks: dict[int, _CfgBlockFacts] = {}
    for block_id, block in micro_blocks.items():
        facts: list[_CfgInstructionFact] = []
        for instruction, access, ea in zip(
            block.instructions,
            block.accesses,
            block.eas,
        ):
            whole_definition = _is_whole_lvar_definition(
                instruction,
                index,
                width,
            )
            overlapping_definition = False
            for other_index, offset, size in access.targets:
                if other_index == index:
                    if not (
                        whole_definition
                        and offset == 0
                        and size == width
                    ):
                        overlapping_definition = True
                    continue
                try:
                    other_lvar = _vector_at(lvars, other_index)
                    if bool(target_lvar.has_common(other_lvar)):
                        overlapping_definition = True
                except Exception:
                    overlapping_definition = True
            facts.append(
                _CfgInstructionFact(
                    ea=ea,
                    whole_definition=whole_definition,
                    overlapping_definition=overlapping_definition,
                    use=index in access.uses,
                )
            )
        blocks[block_id] = _CfgBlockFacts(
            block_id=block_id,
            instructions=tuple(facts),
            predecessors=block.predecessors,
            successors=block.successors,
        )
    return blocks


def _top_instructions(block: object) -> list[object]:
    instructions: list[object] = []
    current = getattr(block, "head", None)
    tail = getattr(block, "tail", None)
    if (current is None) != (tail is None):
        raise RuntimeError("incomplete microcode instruction list endpoints")
    seen: set[int] = set()
    reached_tail = current is None
    while current is not None:
        if len(instructions) >= 100000:
            raise RuntimeError("microcode instruction list cap exceeded")
        raw_identity = getattr(current, "obj_id", None)
        identity = id(current) if raw_identity is None else int(raw_identity)
        if identity in seen:
            raise RuntimeError("cycle in microcode instruction list")
        seen.add(identity)
        instructions.append(current)
        current_id = getattr(current, "obj_id", None)
        tail_id = getattr(tail, "obj_id", None)
        if current == tail or (
            current_id is not None
            and tail_id is not None
            and int(current_id) == int(tail_id)
        ):
            reached_tail = True
            break
        current = getattr(current, "next", None)
    if not reached_tail:
        raise RuntimeError("microcode instruction list ended before tail")
    return instructions


def _collect_lvar_accesses(insn: object) -> _InsnAccess:
    uses: set[int] = set()
    targets: list[tuple[int, int, int]] = []

    class Visitor(ida_hexrays.mop_visitor_t):  # type: ignore[misc,union-attr]
        def __init__(self) -> None:
            super().__init__()

        def visit_mop(self, op: object, tif: object, is_target: bool) -> int:
            del tif
            if getattr(op, "t", None) != ida_hexrays.mop_l:
                return 0
            reference = getattr(op, "l", None)
            if reference is None:
                return 0
            index = int(getattr(reference, "idx", -1))
            offset = int(getattr(reference, "off", 0) or 0)
            size = int(getattr(op, "size", 0) or 0)
            if is_target:
                targets.append((index, offset, size))
            else:
                uses.add(index)
            return 0

    visitor = Visitor()
    result = insn.for_all_ops(visitor)
    if result not in (None, 0):
        raise RuntimeError(f"microcode operand visitor stopped with result={result}")
    return _InsnAccess(frozenset(uses), tuple(targets))


def _is_whole_lvar_definition(insn: object, index: int, width: int) -> bool:
    try:
        if not bool(insn.modifies_d()):
            return False
    except Exception:
        return False
    destination = getattr(insn, "d", None)
    if destination is None or getattr(destination, "t", None) != ida_hexrays.mop_l:
        return False
    reference = getattr(destination, "l", None)
    return bool(
        reference is not None
        and int(getattr(reference, "idx", -1)) == index
        and int(getattr(reference, "off", 0) or 0) == 0
        and int(getattr(destination, "size", 0) or 0) == width
    )


def _direct_constant_definition(insn: object, index: int, width: int) -> int | None:
    if not _is_whole_lvar_definition(insn, index, width):
        return None
    if int(getattr(insn, "opcode", -1)) != int(ida_hexrays.m_mov):
        return None
    source = getattr(insn, "l", None)
    if source is None or getattr(source, "t", None) != ida_hexrays.mop_n:
        return None
    if int(getattr(source, "size", 0) or 0) not in (width, 0):
        return None
    try:
        return int(source.unsigned_value())
    except Exception:
        try:
            return int(source.nnn.value)
        except Exception:
            return None


def _validate_straight_line_micro_range(
    *,
    mba: object,
    instructions: list[object],
    start: int,
    end: int,
    native_bounds: tuple[int, int],
    current_ea: int,
) -> bool:
    real_eas: list[int] = []
    for position in range(start, end + 1):
        instruction = instructions[position]
        ea = _real_micro_ea(mba, getattr(instruction, "ea", None))
        if ea is None:
            try:
                if bool(instruction.is_assert()):
                    continue
            except Exception:
                pass
            return False
        if not (native_bounds[0] <= ea < native_bounds[1]):
            return False
        real_eas.append(ea)
    if not real_eas or any(left > right for left, right in zip(real_eas, real_eas[1:])):
        return False
    return real_eas[0] < current_ea <= real_eas[-1]


def _register_spec_from_lvar(lvar: object, width: int) -> RegisterSpec | None:
    if not _safe_bool_call(lvar, "is_reg1") or _safe_bool_call(lvar, "is_reg2"):
        return None
    try:
        micro_register = int(lvar.get_reg1())
    except Exception:
        return None

    names: list[str] = []
    try:
        names.append(str(ida_hexrays.get_mreg_name(micro_register, width)))
    except Exception:
        pass
    try:
        processor_register = int(ida_hexrays.mreg2reg(micro_register, width))
        if processor_register >= 0:
            names.append(str(ida_idp.get_reg_name(processor_register, width)))
    except Exception:
        pass
    for name in names:
        spec = normalize_register_alias(name)
        if spec is not None and width <= spec.width:
            return spec
    return None


def _current_rsp_location_for_lvar(
    *,
    lvar: object,
    mba: object,
    cfunc: object,
    func: object,
    current_ea: int,
) -> tuple[int, int]:
    analyzed_sp = getattr(func, "analyzed_sp", None)
    if not callable(analyzed_sp) or not bool(analyzed_sp()):
        raise _CandidateRejected(REASON_UNRESOLVED_STACK)
    fuzzy_flag = int(getattr(ida_funcs, "FUNC_FUZZY_SP", 0) or 0)
    if fuzzy_flag and int(getattr(func, "flags", 0) or 0) & fuzzy_flag:
        raise _CandidateRejected(REASON_UNRESOLVED_STACK)
    try:
        vd_offset = int(lvar.get_stkoff())
        if vd_offset < 0:
            raise ValueError("negative decompiler stack offset")
        ida_offset = int(mba.stkoff_vd2ida(vd_offset))
        sp_delta = int(ida_frame.get_spd(func, current_ea))
        return_offset = int(ida_frame.frame_off_retaddr(func))
        current_rsp_offset = -sp_delta + ida_offset - return_offset
    except _CandidateRejected:
        raise
    except Exception:
        try:
            raw_stack_offset = int(lvar.location.stkoff())
            ida_offset = raw_stack_offset - int(cfunc.get_stkoff_delta())
            sp_delta = int(ida_frame.get_spd(func, current_ea))
            return_offset = int(ida_frame.frame_off_retaddr(func))
            current_rsp_offset = -sp_delta + ida_offset - return_offset
        except Exception as exc:
            raise _CandidateRejected(REASON_UNRESOLVED_STACK) from exc
    if abs(current_rsp_offset) > 0x1000000:
        raise _CandidateRejected(REASON_UNRESOLVED_STACK)
    return current_rsp_offset, ida_offset


def _stack_definition_remains_valid(
    *,
    definition_ea: int,
    current_ea: int,
    func: object,
    ida_stack_offset: int,
    width: int,
) -> bool:
    """Require one exact native stack write and no later possible overwrite."""
    target_start = ida_stack_offset
    target_end = target_start + width
    ea = definition_ea
    first = True
    for _ in range(4096):
        if ea >= current_ea:
            return not first
        insn = _decode_instruction(ea)
        if insn is None or int(getattr(insn, "size", 0) or 0) <= 0:
            return False
        known, writes = _native_stack_writes(func, insn)
        if not known:
            return False
        overlaps = [
            (offset, size)
            for offset, size in writes
            if offset < target_end and target_start < offset + size
        ]
        if first:
            if not any(
                offset <= target_start and offset + size >= target_end
                for offset, size in overlaps
            ):
                return False
            first = False
        elif overlaps:
            return False
        ea += int(insn.size)
    return False


def _native_stack_writes(func: object, insn: object) -> tuple[bool, list[tuple[int, int]]]:
    writes: list[tuple[int, int]] = []
    try:
        feature = int(insn.get_canon_feature())
        operands = getattr(insn, "ops", ())
        for index, operand in enumerate(operands):
            if getattr(operand, "type", None) == getattr(ida_ua, "o_void", 0):
                break
            if not bool(ida_idp.has_cf_chg(feature, index)):
                continue
            operand_type = getattr(operand, "type", None)
            if operand_type not in (
                getattr(ida_ua, "o_phrase", -2),
                getattr(ida_ua, "o_displ", -3),
            ):
                continue
            frame_offset = int(ida_frame.calc_stkvar_struc_offset(func, insn, index))
            badaddr = int(getattr(ida_idaapi, "BADADDR", (1 << 64) - 1))
            if frame_offset == badaddr or frame_offset < 0:
                # An unresolved register-relative write could alias this stack
                # slot, so it makes the proof unavailable.
                return False, []
            size = int(ida_ua.get_dtype_size(operand.dtype))
            if size <= 0:
                return False, []
            writes.append((frame_offset, size))
    except Exception:
        return False, []
    return True, writes


def _native_definition_uses_immediate(insn: object) -> bool:
    """Return true only for a decoded native immediate source operand."""
    try:
        feature = int(insn.get_canon_feature())
        for operand_index, operand in enumerate(getattr(insn, "ops", ())):
            if getattr(operand, "type", None) == getattr(ida_ua, "o_void", 0):
                break
            if (
                getattr(operand, "type", None) == getattr(ida_ua, "o_imm", -1)
                and bool(ida_idp.has_cf_use(feature, operand_index))
            ):
                return True
    except Exception:
        return False
    return False


def _register_writes(insn: object) -> tuple[bool, list[_RegisterWrite]]:
    writes: list[_RegisterWrite] = []
    get_accesses = getattr(ida_idp, "ph_get_reg_accesses", None)
    accesses_type = getattr(ida_idp, "reg_accesses_t", None)
    if not callable(get_accesses) or accesses_type is None:
        return False, []
    try:
        accesses = accesses_type()
        result = int(get_accesses(accesses, insn, 0))
        if result <= 0:
            return False, []
        for index in range(_vector_size(accesses)):
            access = _vector_at(accesses, index)
            if getattr(access, "access_type", None) not in (
                getattr(ida_idp, "WRITE_ACCESS", object()),
                getattr(ida_idp, "RW_ACCESS", object()),
            ):
                continue
            bitrange = getattr(access, "range", None)
            if bitrange is None or not all(
                hasattr(bitrange, method) for method in ("bitoff", "bitsize")
            ):
                return False, []
            bit_offset = int(bitrange.bitoff())
            bit_size = int(bitrange.bitsize())
            if bit_size <= 0:
                return False, []
            byte_width = max(1, (bit_size + 7) // 8)
            name = str(ida_idp.get_reg_name(int(access.regnum), byte_width))
            spec = normalize_register_alias(name)
            if spec is None:
                # Segment, flags, vector, and other non-GPR writes are not
                # relevant to this x64 GPR-only recovery subset.
                continue
            if bit_offset == 0 and spec.bit_offset:
                bit_offset = spec.bit_offset
            # x64 32-bit GPR writes architecturally zero the high 32 bits.
            if bit_offset == 0 and bit_size == 32 and spec.full_register in FULL_REGISTER_ORDER:
                bit_size = 64
            writes.append(_RegisterWrite(spec.full_register, bit_offset, bit_size))
    except Exception:
        return False, []
    return True, writes


def _collect_ctree_facts(cfunc: object, mba: object) -> list[_CtreeFact]:
    if not all(
        hasattr(ida_hexrays, name)
        for name in ("ctree_visitor_t", "CV_PARENTS", "cot_var", "cot_num", "cot_asg")
    ):
        return []
    facts: list[_CtreeFact] = []
    assignment_ops = {
        getattr(ida_hexrays, name)
        for name in (
            "cot_asg",
            "cot_asgbor",
            "cot_asgxor",
            "cot_asgband",
            "cot_asgadd",
            "cot_asgsub",
            "cot_asgmul",
            "cot_asgsshr",
            "cot_asgushr",
            "cot_asgshl",
            "cot_asgsdiv",
            "cot_asgudiv",
            "cot_asgsmod",
            "cot_asgumod",
        )
        if hasattr(ida_hexrays, name)
    }

    class Visitor(ida_hexrays.ctree_visitor_t):  # type: ignore[misc,union-attr]
        def __init__(self) -> None:
            super().__init__(ida_hexrays.CV_PARENTS)

        def visit_expr(self, expression: object) -> int:
            if getattr(expression, "op", None) != ida_hexrays.cot_var:
                return 0
            reference = getattr(expression, "v", None)
            if reference is None:
                return 0
            index = int(getattr(reference, "idx", -1))
            parent = self.parent_expr()
            ea = _real_micro_ea(mba, getattr(expression, "ea", None))
            if parent is not None and getattr(parent, "op", None) in assignment_ops:
                left = getattr(parent, "x", None)
                if _same_swig_object(left, expression):
                    parent_ea = _real_micro_ea(mba, getattr(parent, "ea", None)) or ea
                    right = getattr(parent, "y", None)
                    if (
                        getattr(parent, "op", None) == ida_hexrays.cot_asg
                        and right is not None
                        and getattr(right, "op", None) == ida_hexrays.cot_num
                    ):
                        try:
                            value = int(right.numval())
                        except Exception:
                            value = None
                        facts.append(_CtreeFact(index, "constant_def", parent_ea, value))
                    else:
                        facts.append(_CtreeFact(index, "def", parent_ea))
                    return 0
            facts.append(_CtreeFact(index, "use", ea))
            return 0

    try:
        Visitor().apply_to(cfunc.body, None)
    except Exception:
        return []
    return facts


def _build_native_cfg_facts(
    func: object,
) -> tuple[dict[int, _NativeBlockFacts] | None, str]:
    """Snapshot IDA's native FlowChart without retaining SWIG block objects."""
    try:
        flowchart = _make_native_flowchart(func)
        raw_blocks = list(flowchart)
        if not raw_blocks:
            raise RuntimeError("native FlowChart has no blocks")
        raw_by_id: dict[int, object] = {}
        for raw_block in raw_blocks:
            block_id = int(getattr(raw_block, "id"))
            if block_id in raw_by_id:
                raise RuntimeError(f"duplicate native block id {block_id}")
            raw_by_id[block_id] = raw_block

        blocks: dict[int, _NativeBlockFacts] = {}
        badaddr = int(getattr(ida_idaapi, "BADADDR", (1 << 64) - 1))
        for block_id, raw_block in raw_by_id.items():
            start_ea = int(getattr(raw_block, "start_ea"))
            end_ea = int(getattr(raw_block, "end_ea"))
            if (
                start_ea == badaddr
                or end_ea == badaddr
                or start_ea < 0
                or end_ea < start_ea
            ):
                raise RuntimeError(f"invalid native block bounds id={block_id}")
            predecessors = _native_edge_ids(raw_block, "preds", raw_by_id)
            successors = _native_edge_ids(raw_block, "succs", raw_by_id)
            instructions: list[_NativeInstructionFact] = []
            ea = start_ea
            decoded_count = 0
            while ea < end_ea:
                if decoded_count >= 100000:
                    raise RuntimeError(f"native block {block_id} instruction cap exceeded")
                insn = _decode_instruction(ea)
                size = 0 if insn is None else int(getattr(insn, "size", 0) or 0)
                if insn is None or size <= 0 or ea + size > end_ea:
                    instructions.append(
                        _NativeInstructionFact(
                            ea=ea,
                            size=max(1, end_ea - ea),
                            register_access_known=False,
                        )
                    )
                    break
                register_access_known, writes = _register_writes(insn)
                try:
                    is_call = bool(ida_idp.is_call_insn(insn))
                except Exception:
                    is_call = False
                    register_access_known = False
                instructions.append(
                    _NativeInstructionFact(
                        ea=ea,
                        size=size,
                        writes=tuple(writes),
                        is_call=is_call,
                        register_access_known=register_access_known,
                    )
                )
                ea += size
                decoded_count += 1
            blocks[block_id] = _NativeBlockFacts(
                block_id=block_id,
                start_ea=start_ea,
                end_ea=end_ea,
                instructions=tuple(instructions),
                predecessors=predecessors,
                successors=successors,
            )
        _validate_cfg_reciprocity(blocks, "native")
        return blocks, ""
    except Exception as exc:
        return None, str(exc)


def _native_edge_ids(
    block: object,
    method_name: str,
    raw_by_id: dict[int, object],
) -> tuple[int, ...]:
    method = getattr(block, method_name, None)
    if not callable(method):
        raise RuntimeError(f"native FlowChart API missing {method_name}()")
    edge_ids: list[int] = []
    for edge in method():
        edge_id = int(getattr(edge, "id"))
        if edge_id not in raw_by_id:
            raise RuntimeError(f"native edge references unknown block {edge_id}")
        edge_ids.append(edge_id)
    return tuple(sorted(set(edge_ids)))


def _make_native_flowchart(func: object) -> object:
    flags = int(getattr(ida_gdl, "FC_NOEXT", 0) or 0)
    if flags:
        try:
            return ida_gdl.FlowChart(func, flags=flags)
        except TypeError:
            pass
    return ida_gdl.FlowChart(func)


def _native_block_bounds(func: object, ea: int) -> tuple[int, int] | None:
    try:
        matches = [
            (int(block.start_ea), int(block.end_ea))
            for block in _make_native_flowchart(func)
            if int(block.start_ea) <= ea < int(block.end_ea)
        ]
    except Exception:
        return None
    if len(matches) != 1:
        return None
    return matches[0]


def _decode_instruction(ea: int) -> object | None:
    try:
        insn = ida_ua.insn_t()
        if int(ida_ua.decode_insn(insn, ea)) <= 0:
            return None
        return insn
    except Exception:
        return None


def _real_micro_ea(mba: object, value: object) -> int | None:
    try:
        ea = int(value)
    except (TypeError, ValueError):
        return None
    badaddr = int(getattr(ida_idaapi, "BADADDR", (1 << 64) - 1))
    if ea == badaddr:
        return None
    mapper = getattr(mba, "map_fict_ea", None)
    if callable(mapper):
        try:
            mapped = int(mapper(ea))
            if mapped != badaddr:
                ea = mapped
        except Exception:
            pass
    return ea


def _vector_size(vector: object) -> int:
    size = getattr(vector, "size", None)
    if callable(size):
        return int(size())
    return len(vector)  # type: ignore[arg-type]


def _vector_at(vector: object, index: int) -> object:
    at = getattr(vector, "at", None)
    if callable(at):
        return at(index)
    return vector[index]  # type: ignore[index]


def _safe_bool_call(obj: object, method_name: str) -> bool:
    method = getattr(obj, method_name, None)
    if not callable(method):
        return False
    try:
        return bool(method())
    except Exception:
        return False


def _safe_bool_call_with_arg(obj: object, method_name: str, arg: object) -> bool:
    method = getattr(obj, method_name, None)
    if not callable(method):
        return True
    try:
        return bool(method(arg))
    except Exception:
        return True


def _same_swig_object(left: object, right: object) -> bool:
    if left is right:
        return True
    left_id = getattr(left, "obj_id", None)
    right_id = getattr(right, "obj_id", None)
    return left_id is not None and left_id == right_id


def _mask_value(value: int, width: int) -> int:
    return value & ((1 << (width * 8)) - 1)


def _reject_duplicate_storage_claims(
    evidence_by_index: dict[int, RecoveryEvidence],
) -> None:
    claims = list(evidence_by_index.items())
    rejected: dict[int, str] = {}
    for position, (left_index, left) in enumerate(claims):
        for right_index, right in claims[position + 1 :]:
            if left.storage_kind != right.storage_kind:
                continue
            if (
                left.storage_kind == "register"
                and left.register is not None
                and right.register is not None
                and left.register.full_register == right.register.full_register
            ):
                left_start = left.register.bit_offset
                left_end = left_start + left.width * 8
                right_start = right.register.bit_offset
                right_end = right_start + right.width * 8
                if left_start < right_end and right_start < left_end:
                    rejected[left_index] = REASON_AMBIGUOUS_REGISTER
                    rejected[right_index] = REASON_AMBIGUOUS_REGISTER
            elif (
                left.storage_kind == "stack"
                and left.stack_pointer_offset is not None
                and right.stack_pointer_offset is not None
            ):
                left_start = left.stack_pointer_offset
                left_end = left_start + left.width
                right_start = right.stack_pointer_offset
                right_end = right_start + right.width
                if left_start < right_end and right_start < left_end:
                    rejected[left_index] = REASON_UNRESOLVED_STACK
                    rejected[right_index] = REASON_UNRESOLVED_STACK
    for index, reason in rejected.items():
        evidence_by_index[index] = RecoveryEvidence(index, reason=reason)
