"""IDA plugin entry point for dynvar-sync.

This module implements the IDA-side broker connection, Hex-Rays lvar
enumeration, exact-entry argument reads, conservative local recovery, and the
Live Variables table. Pseudocode overlays are intentionally not implemented.
"""

from __future__ import annotations

import os
import queue
import sys
import time
from typing import Any, Callable

PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)

try:
    import ida_idaapi  # type: ignore
    import ida_kernwin  # type: ignore
    import idaapi  # type: ignore
except ImportError:  # pragma: no cover - outside IDA validation path.
    ida_idaapi = None  # type: ignore
    ida_kernwin = None  # type: ignore
    idaapi = None  # type: ignore

from address_mapping import format_hex, map_pc_update
from dynvar_core import DayVarCore
from hexrays_variables import VariableRecord, enumerate_hexrays_variables
from live_variables_view import FILTERS, LiveVariablesView, row_matches_filter
from protocol_client import ProtocolClient
from v_variable_recovery import VVariableRecovery

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9100
PLUGIN_DIAGNOSTIC_LEVEL = os.environ.get("DAYVARSYNC_LOG_LEVEL", "normal")
MAX_RECOVERY_ANALYSIS_CANDIDATES = 32

ACTION_CONNECT = "dayvarsync:connect"
ACTION_DISCONNECT = "dayvarsync:disconnect"
ACTION_STATUS = "dayvarsync:status"
ACTION_SHOW_LIVE = "dayvarsync:show_live"
ACTION_FILTER_PREFIX = "dayvarsync:filter:"

LOG_LEVELS = {
    "quiet": 0,
    "normal": 1,
    "verbose": 2,
    "trace": 3,
}


def normalize_diagnostic_level(level: str | None) -> str:
    normalized = (level or "normal").strip().lower()
    return normalized if normalized in LOG_LEVELS else "normal"


def diagnostic_line_level(line: str) -> str:
    """Classify existing diagnostic lines without changing recovery semantics."""
    lowered = line.lower()
    if "failure" in lowered or "failed" in lowered or "exception" in lowered:
        return "quiet"
    if line.startswith(
        (
            "v-analysis",
            "v-native-cfg",
            "v-cfg-point",
            "v-reaching-def",
            "v-cross-block-live",
            "v-storage-valid",
            "v-candidate",
        )
    ):
        return "trace"
    if line.startswith("v-recovery"):
        if "result=fresh" in line or "result=stale" in line or "result=error" in line:
            return "normal"
        return "verbose"
    if line.startswith("v-request") or "requested=" in line or line.startswith("request plan"):
        return "verbose"
    if line.startswith("detected arg") or line.startswith("no reg_request"):
        return "verbose"
    return "verbose"


def _variable_fingerprint(variables: list[VariableRecord]) -> tuple[tuple[object, ...], ...]:
    return tuple(
        (
            variable.lvar_index,
            variable.name,
            variable.type_string,
            variable.size,
            variable.is_arg,
            variable.arg_index,
            variable.lvar_defea,
        )
        for variable in variables
    )


def select_recovery_candidate_indexes(
    *,
    variables: list[VariableRecord],
    previous_rows: list[VariableRecord],
    active_filter: str,
    watched_lvar_indexes: set[int] | None = None,
    max_candidates: int = MAX_RECOVERY_ANALYSIS_CANDIDATES,
    fallback_cursor: int = 0,
) -> tuple[set[int], int]:
    """Pick a bounded, rotating non-argument recovery analysis set."""
    watched = watched_lvar_indexes or set()
    budget = max(0, max_candidates)
    locals_by_index = {
        variable.lvar_index: variable for variable in variables if not variable.is_arg
    }
    selected: list[int] = []
    selected_set: set[int] = set()

    def add(index: int) -> None:
        if len(selected) >= budget or index in selected_set or index not in locals_by_index:
            return
        selected.append(index)
        selected_set.add(index)

    for index in sorted(watched):
        add(index)

    previous_by_index = {
        row.lvar_index: row for row in previous_rows if not row.is_arg
    }
    for index in sorted(locals_by_index):
        previous = previous_by_index.get(index)
        if previous is not None and previous.status in {"fresh", "stale"}:
            add(index)

    def add_rotating(indexes: list[int], cursor: int) -> int:
        if not indexes or len(selected) >= budget:
            return cursor
        start = cursor % len(indexes)
        added = 0
        for offset in range(len(indexes)):
            add(indexes[(start + offset) % len(indexes)])
            if len(selected) >= budget:
                added = offset + 1
                break
            added = offset + 1
        return (start + added) % len(indexes)

    visible = [
        index
        for index, variable in sorted(locals_by_index.items())
        if row_matches_filter(previous_by_index.get(index, variable), active_filter)
    ]
    next_cursor = add_rotating(visible, fallback_cursor)
    remaining = [
        index for index in sorted(locals_by_index) if index not in selected_set
    ]
    next_cursor = add_rotating(remaining, next_cursor)
    return selected_set, next_cursor


class AnalysisSelectionCache:
    """Cache the bounded selection decision for one function/PC/view state."""

    def __init__(self) -> None:
        self.key: tuple[object, ...] | None = None
        self.indexes: tuple[int, ...] = ()
        self.cursor_by_function: dict[int, int] = {}

    def invalidate(self, *, clear_cursors: bool = False) -> None:
        self.key = None
        self.indexes = ()
        if clear_cursors:
            self.cursor_by_function.clear()

    def select(
        self,
        *,
        pc_seq: int,
        function_ea: int,
        current_ea: int,
        variables: list[VariableRecord],
        previous_rows: list[VariableRecord],
        active_filter: str,
        watched_lvar_indexes: set[int],
        max_candidates: int,
    ) -> set[int]:
        key = (
            pc_seq,
            function_ea,
            current_ea,
            active_filter,
            tuple(sorted(watched_lvar_indexes)),
            _variable_fingerprint(variables),
        )
        if key == self.key:
            return set(self.indexes)
        cursor = self.cursor_by_function.get(function_ea, 0)
        selected, next_cursor = select_recovery_candidate_indexes(
            variables=variables,
            previous_rows=previous_rows,
            active_filter=active_filter,
            watched_lvar_indexes=watched_lvar_indexes,
            max_candidates=max_candidates,
            fallback_cursor=cursor,
        )
        self.cursor_by_function[function_ea] = next_cursor
        self.key = key
        self.indexes = tuple(sorted(selected))
        return selected


def _ida_version() -> str:
    """Return the IDA kernel version when running inside IDA."""
    if ida_kernwin is None:
        return "outside-ida"
    try:
        return str(ida_kernwin.get_kernel_version())
    except Exception:
        return "unknown"


class DayVarController:
    """Main IDA-side controller."""

    def __init__(
        self,
        *,
        diagnostic_level: str | None = None,
        max_recovery_candidates: int = MAX_RECOVERY_ANALYSIS_CANDIDATES,
    ) -> None:
        self.core = DayVarCore()
        self.v_recovery = VVariableRecovery()
        self.view = LiveVariablesView()
        self.client: ProtocolClient | None = None
        self.messages: queue.Queue[dict[str, Any]] = queue.Queue()
        self.status = "disconnected"
        self.diagnostic_level = normalize_diagnostic_level(
            diagnostic_level or PLUGIN_DIAGNOSTIC_LEVEL
        )
        self.max_recovery_candidates = max(0, max_recovery_candidates)
        self.watched_lvar_indexes: set[int] = set()
        self.analysis_cache = AnalysisSelectionCache()
        self._active_pc_seq: int | None = None
        self._active_function_ea: int | None = None

    def connect(self, target: str | None = None) -> None:
        """Connect to the broker as role=ida."""
        try:
            host, port = self._parse_target(target or self._ask_target())
        except ValueError as exc:
            self._log(f"invalid broker target: {exc}", "quiet")
            return

        if self.client is not None and self.client.connected:
            self._log("already connected", "normal")
            return

        self.client = ProtocolClient(self._on_network_message, self._on_status)
        hello = self.core.make_hello(_ida_version())
        self.client.connect(host, port, hello)
        self.status = f"connecting to {host}:{port}"
        self._log(self.status, "normal")

    def disconnect(self) -> None:
        """Disconnect from the broker."""
        if self.client is not None:
            self.client.disconnect()
        self.status = "disconnected"
        self.core.pending_requests.clear()
        self.v_recovery.clear_runtime_state()
        self._invalidate_analysis_cache("disconnect", clear_cursors=True)
        self._log("disconnect requested", "normal")

    def show_status(self) -> None:
        """Print current plugin status."""
        connected = bool(self.client and self.client.connected)
        current = self.core.current_pc
        if current is None:
            pc_status = "pc=<none>"
        else:
            pc_status = (
                f"pc_seq={current.pc_seq} "
                f"runtime_pc={current.runtime_pc} ida_ea={current.ida_ea}"
            )
        self._log(
            "status connected={connected} {pc_status} state={status} "
            "diagnostics={diagnostics} filter={filter_name}".format(
                connected=connected,
                pc_status=pc_status,
                status=self.status,
                diagnostics=self.diagnostic_level,
                filter_name=self.view.active_filter,
            ),
            "normal",
        )

    def show_live_variables(self) -> None:
        """Show the Live Variables chooser."""
        self.view.show()

    def _ask_target(self) -> str:
        default = f"{DEFAULT_HOST}:{DEFAULT_PORT}"
        if ida_kernwin is None:
            return default
        value = ida_kernwin.ask_str(default, 0, "DayVarSync broker host:port")
        return value or default

    def _parse_target(self, target: str) -> tuple[str, int]:
        target = target.strip()
        if not target:
            return DEFAULT_HOST, DEFAULT_PORT
        if ":" not in target:
            return target, DEFAULT_PORT
        host, port_text = target.rsplit(":", 1)
        return host.strip(), int(port_text, 10)

    def _on_status(self, message: str) -> None:
        self.status = message
        self._run_on_ida_thread(lambda: self._log(message, "normal"))

    def _on_network_message(self, message: dict[str, Any]) -> None:
        self.messages.put(message)
        self._run_on_ida_thread(self._drain_messages)

    def _run_on_ida_thread(self, func: Callable[[], None]) -> None:
        if ida_kernwin is None:
            func()
            return

        def wrapper() -> int:
            func()
            return 1

        try:
            ida_kernwin.execute_sync(wrapper, ida_kernwin.MFF_WRITE)
        except Exception as exc:
            self.view.log(f"failed to execute on IDA thread: {exc}")

    def _drain_messages(self) -> None:
        while True:
            try:
                message = self.messages.get_nowait()
            except queue.Empty:
                return
            self._handle_message(message)

    def _handle_message(self, message: dict[str, Any]) -> None:
        message_type = message.get("type")
        payload = message.get("payload", {})
        if not isinstance(payload, dict):
            self._log(f"ignored message with non-object payload type={message_type}", "quiet")
            return

        if message_type == "hello_ack":
            self._log(f"hello_ack payload={payload}", "verbose")
        elif message_type == "pc_update":
            self._handle_pc_update(payload)
        elif message_type == "reg_response":
            self._handle_reg_response(payload)
        elif message_type == "mem_response":
            self._handle_mem_response(payload)
        elif message_type == "error":
            self._log(f"broker/error payload={payload}", "quiet")
        else:
            self._log(f"ignored incoming message type={message_type}", "verbose")

    def _handle_pc_update(self, payload: dict[str, Any]) -> None:
        if not payload.get("auto_live"):
            self._log(f"pc_update ignored because auto_live is false payload={payload}", "verbose")
            return

        analysis_started = time.perf_counter()
        runtime_pc = str(payload.get("pc", ""))
        module = str(payload.get("module", ""))
        ida_imagebase = self._get_imagebase()
        pc_seq = int(payload.get("pc_seq", 0) or 0)
        if self._active_pc_seq != pc_seq:
            self._invalidate_analysis_cache("new pc sequence")
            self._active_pc_seq = pc_seq

        try:
            mapping = map_pc_update(payload, ida_imagebase)
        except (KeyError, ValueError) as exc:
            self._log(f"pc_update mapping failed: {exc}", "quiet")
            self._invalidate_analysis_cache("mapping failure")
            # A failed mapping is still a newer debugger PC context. Drop all
            # prior argument/v pending requests before reporting the failure
            # so a late response cannot refresh the previous mapped PC.
            self.core.start_pc_context(
                pc_seq=pc_seq,
                runtime_pc=runtime_pc,
                ida_ea="",
            )
            self.v_recovery.invalidate_pc(
                pc_seq=pc_seq,
                runtime_pc=runtime_pc,
            )
            self._send(
                self.core.make_ida_pc_mapped(
                    pc_seq=pc_seq,
                    runtime_pc=runtime_pc,
                    ida_ea=None,
                    module=module,
                    ida_imagebase=format_hex(ida_imagebase),
                    ok=False,
                    error=str(exc),
                )
            )
            return

        runtime_pc_text = format_hex(mapping.runtime_pc)
        ida_ea_text = format_hex(mapping.ida_ea)
        self._jump_to(mapping.ida_ea)

        mapped = self.core.make_ida_pc_mapped(
            pc_seq=mapping.pc_seq,
            runtime_pc=runtime_pc_text,
            ida_ea=ida_ea_text,
            module=mapping.module,
            ida_imagebase=format_hex(mapping.ida_imagebase),
            ok=True,
        )
        self._log_mapping(mapped["payload"])
        self._send(mapped)
        self.v_recovery.invalidate_pc(
            pc_seq=mapping.pc_seq,
            runtime_pc=runtime_pc_text,
        )

        previous_rows = list(self.view.all_rows)
        enumeration = enumerate_hexrays_variables(mapping.ida_ea, current_pc=runtime_pc_text)
        if not enumeration.ok:
            self.core.start_pc_context(
                pc_seq=mapping.pc_seq,
                runtime_pc=runtime_pc_text,
                ida_ea=ida_ea_text,
                function_ea=enumeration.function_ea,
                at_function_entry=False,
            )
            self.v_recovery.invalidate_pc(
                pc_seq=mapping.pc_seq,
                runtime_pc=runtime_pc_text,
            )
            self._invalidate_analysis_cache("decompiler refresh failed")
            self.view.update_rows([])
            self._log(enumeration.error, "quiet")
            return

        if self._active_function_ea != enumeration.function_start_ea:
            self._invalidate_analysis_cache("function change")
            self._active_function_ea = enumeration.function_start_ea

        at_function_entry = enumeration.function_start_ea == mapping.ida_ea
        plan = self.core.build_entry_plan(
            variables=enumeration.variables,
            pc_seq=mapping.pc_seq,
            runtime_pc=runtime_pc_text,
            ida_ea=ida_ea_text,
            function_ea=enumeration.function_ea,
            at_function_entry=at_function_entry,
        )
        self._log(
            "enumerated {count} Hex-Rays variables function={function_ea} at_entry={at_entry}".format(
                count=len(enumeration.variables),
                function_ea=enumeration.function_ea,
                at_entry=at_function_entry,
            ),
            "normal",
        )
        self._emit_diagnostic_lines(plan.debug_lines)
        self._publish_rows()
        if plan.register_request is not None:
            self._send(plan.register_request)

        selected_indexes = self.analysis_cache.select(
            pc_seq=mapping.pc_seq,
            function_ea=int(enumeration.function_start_ea),
            current_ea=mapping.ida_ea,
            variables=enumeration.variables,
            previous_rows=previous_rows,
            active_filter=self.view.active_filter,
            watched_lvar_indexes=self.watched_lvar_indexes,
            max_candidates=self.max_recovery_candidates,
        )
        self._log(
            "v-analysis selection total_locals={total} selected={selected} filter={filter_name}".format(
                total=sum(1 for variable in enumeration.variables if not variable.is_arg),
                selected=len(selected_indexes),
                filter_name=self.view.active_filter,
            ),
            "verbose",
        )
        try:
            v_plan = self.v_recovery.begin_pc(
                variables=enumeration.variables,
                function_ea=int(enumeration.function_start_ea),
                current_ea=mapping.ida_ea,
                runtime_pc=runtime_pc_text,
                pc_seq=mapping.pc_seq,
                envelope=self.core.envelope,
                cfunc=enumeration.cfunc,
                analysis_lvar_indexes=selected_indexes,
            )
        except Exception as exc:
            # Recovery is best-effort. Entry arguments, mapped PC state, and
            # the network loop must remain usable after any Hex-Rays failure.
            self.v_recovery.invalidate_pc(
                pc_seq=mapping.pc_seq,
                runtime_pc=runtime_pc_text,
            )
            self._log(f"v-microcode failure reason={exc}", "quiet")
            self._publish_rows()
            return

        self._emit_diagnostic_lines(v_plan.debug_lines)
        self._publish_rows()
        if v_plan.register_request is not None:
            self._send(v_plan.register_request)
        self._log_analysis_summary(
            rows=self.view.all_rows,
            request_count=sum(
                1
                for request in (plan.register_request, v_plan.register_request)
                if request is not None
            ),
            duration_ms=(time.perf_counter() - analysis_started) * 1000.0,
        )

    def _handle_reg_response(self, payload: dict[str, Any]) -> None:
        if self.v_recovery.is_v_request_id(payload.get("request_id")):
            try:
                accepted, reason, mem_requests, debug_lines = self.v_recovery.apply_reg_response(
                    payload,
                    envelope=self.core.envelope,
                )
            except Exception as exc:
                self._log(f"ignored v reg_response after recovery failure: {exc}", "quiet")
                return
            if not accepted:
                self._log(f"ignored v reg_response: {reason}", "quiet")
                return
            self._log_response("reg_response", payload)
            self._emit_diagnostic_lines(debug_lines)
            self._publish_rows()
            for mem_request in mem_requests:
                self._send(mem_request)
            return

        accepted, reason, mem_requests = self.core.apply_reg_response(payload)
        if not accepted:
            self._log(f"ignored reg_response: {reason}", "quiet")
            return

        self._log_response("reg_response", payload)
        self._publish_rows()
        for mem_request in mem_requests:
            self._send(mem_request)

    def _handle_mem_response(self, payload: dict[str, Any]) -> None:
        if self.v_recovery.is_v_request_id(payload.get("request_id")):
            try:
                accepted, reason, debug_lines = self.v_recovery.apply_mem_response(payload)
            except Exception as exc:
                self._log(f"ignored v mem_response after recovery failure: {exc}", "quiet")
                return
            if not accepted:
                self._log(f"ignored v mem_response: {reason}", "quiet")
                return
            self._log_response("mem_response", payload)
            self._emit_diagnostic_lines(debug_lines)
            self._publish_rows()
            return

        accepted, reason = self.core.apply_mem_response(payload)
        if not accepted:
            self._log(f"ignored mem_response: {reason}", "quiet")
            return
        self._log_response("mem_response", payload)
        self._publish_rows()

    def _publish_rows(self) -> None:
        """Refresh the table with v recovery overlaid on argument-owned rows."""
        self.view.update_rows(self.v_recovery.overlay_rows(self.core.rows))

    def _get_imagebase(self) -> int:
        if idaapi is None:
            return 0x140000000
        return int(idaapi.get_imagebase())

    def _jump_to(self, ea: int) -> None:
        if ida_kernwin is None:
            self._log(f"outside IDA: would jump to {format_hex(ea)}", "verbose")
            return
        if not ida_kernwin.jumpto(ea):
            self._log(f"jumpto failed ea={format_hex(ea)}", "quiet")

    def _send(self, message: dict[str, Any]) -> None:
        if self.client is None:
            self._log(f"cannot send type={message.get('type')}: not connected", "quiet")
            return
        self._log(f"send type={message.get('type')} id={message.get('id')}", "verbose")
        self.client.send(message)

    def _set_filter(self, filter_name: str) -> None:
        self.view.set_filter(filter_name)
        self._invalidate_analysis_cache("filter changed")
        self._log(f"Live Variables filter={filter_name}", "normal")

    def _invalidate_analysis_cache(self, reason: str, *, clear_cursors: bool = False) -> None:
        self.analysis_cache.invalidate(clear_cursors=clear_cursors)
        self._log(f"analysis selection cache invalidated reason={reason}", "trace")

    def _log(self, message: str, level: str = "normal") -> None:
        if LOG_LEVELS[level] <= LOG_LEVELS[self.diagnostic_level]:
            self.view.log(message)

    def _emit_diagnostic_lines(self, lines: list[str]) -> None:
        for line in lines:
            self._log(line, diagnostic_line_level(line))

    def _log_mapping(self, payload: dict[str, Any]) -> None:
        self._log(
            "pc_seq={pc_seq} runtime_pc={runtime_pc} ida_ea={ida_ea} module={module}".format(
                pc_seq=payload.get("pc_seq"),
                runtime_pc=payload.get("runtime_pc"),
                ida_ea=payload.get("ida_ea"),
                module=payload.get("module", ""),
            ),
            "normal",
        )

    def _log_response(self, message_type: str, payload: dict[str, Any]) -> None:
        level = "quiet" if payload.get("ok") is not True else "verbose"
        details = ""
        if message_type == "mem_response":
            details = " address={address} size={size}".format(
                address=payload.get("address"),
                size=payload.get("size"),
            )
        self._log(
            "{message_type} pc_seq={pc_seq} request_id={request_id} ok={ok}{details}".format(
                message_type=message_type,
                pc_seq=payload.get("pc_seq"),
                request_id=payload.get("request_id"),
                ok=payload.get("ok"),
                details=details,
            ),
            level,
        )

    def _log_analysis_summary(
        self,
        *,
        rows: list[VariableRecord],
        request_count: int,
        duration_ms: float,
    ) -> None:
        counts = {
            "fresh": 0,
            "stale": 0,
            "not_defined": 0,
            "ambiguous": 0,
            "unsupported": 0,
        }
        for row in rows:
            if row.status == "fresh":
                counts["fresh"] += 1
            elif row.status == "stale":
                counts["stale"] += 1
            elif row.reason == "no_reaching_definition":
                counts["not_defined"] += 1
            elif row.reason in {
                "ambiguous_register_location",
                "ambiguous_reaching_definition",
                "cross_block_liveness_unproven",
            }:
                counts["ambiguous"] += 1
            elif row.reason in {
                "unsupported_scattered_location",
                "unsupported_value_width",
            } or row.confidence == "unsupported_variable":
                counts["unsupported"] += 1
        self._log(
            "analysis summary total_lvars={total} exact_fresh={fresh} stale={stale} "
            "not_defined={not_defined} ambiguous={ambiguous} unsupported={unsupported} "
            "requests_issued={requests} duration_ms={duration:.2f}".format(
                total=len(rows),
                fresh=counts["fresh"],
                stale=counts["stale"],
                not_defined=counts["not_defined"],
                ambiguous=counts["ambiguous"],
                unsupported=counts["unsupported"],
                requests=request_count,
                duration=duration_ms,
            ),
            "verbose",
        )


_controller = DayVarController()


class _ActionHandler(ida_kernwin.action_handler_t if ida_kernwin is not None else object):
    """IDA action handler wrapper."""

    def __init__(self, callback: Callable[[], None]) -> None:
        if ida_kernwin is not None:
            super().__init__()
        self.callback = callback

    def activate(self, ctx: object) -> int:
        del ctx
        self.callback()
        return 1

    def update(self, ctx: object) -> int:
        del ctx
        if ida_kernwin is None:
            return 1
        return ida_kernwin.AST_ENABLE_ALWAYS


def _register_action(name: str, label: str, callback: Callable[[], None]) -> None:
    if ida_kernwin is None:
        return
    ida_kernwin.unregister_action(name)
    desc = ida_kernwin.action_desc_t(name, label, _ActionHandler(callback), None, None, -1)
    ida_kernwin.register_action(desc)


def install_plugin() -> None:
    """Register DayVarSync actions and menu entries."""
    if ida_kernwin is None:
        _controller._log("outside IDA: plugin actions not registered", "normal")
        return

    _register_action(ACTION_CONNECT, "DayVarSync: Connect", _controller.connect)
    _register_action(ACTION_DISCONNECT, "DayVarSync: Disconnect", _controller.disconnect)
    _register_action(ACTION_STATUS, "DayVarSync: Status", _controller.show_status)
    _register_action(ACTION_SHOW_LIVE, "DayVarSync: Show Live Variables", _controller.show_live_variables)
    for filter_name in FILTERS:
        action_name = ACTION_FILTER_PREFIX + filter_name.lower().replace(" ", "_")
        _register_action(
            action_name,
            f"DayVarSync Filter: {filter_name}",
            lambda filter_name=filter_name: _controller._set_filter(filter_name),
        )

    ida_kernwin.attach_action_to_menu("Edit/DayVarSync/Connect", ACTION_CONNECT, ida_kernwin.SETMENU_APP)
    ida_kernwin.attach_action_to_menu(
        "Edit/DayVarSync/Disconnect",
        ACTION_DISCONNECT,
        ida_kernwin.SETMENU_APP,
    )
    ida_kernwin.attach_action_to_menu("Edit/DayVarSync/Status", ACTION_STATUS, ida_kernwin.SETMENU_APP)
    ida_kernwin.attach_action_to_menu(
        "Edit/DayVarSync/Show Live Variables",
        ACTION_SHOW_LIVE,
        ida_kernwin.SETMENU_APP,
    )
    for filter_name in FILTERS:
        action_name = ACTION_FILTER_PREFIX + filter_name.lower().replace(" ", "_")
        ida_kernwin.attach_action_to_menu(
            f"Edit/DayVarSync/Filter/{filter_name}",
            action_name,
            ida_kernwin.SETMENU_APP,
        )
    _controller._log("actions registered under Edit/DayVarSync", "normal")


def uninstall_plugin() -> None:
    """Unregister DayVarSync actions."""
    _controller.disconnect()
    if ida_kernwin is None:
        return
    action_names = [ACTION_CONNECT, ACTION_DISCONNECT, ACTION_STATUS, ACTION_SHOW_LIVE]
    action_names.extend(
        ACTION_FILTER_PREFIX + filter_name.lower().replace(" ", "_")
        for filter_name in FILTERS
    )
    for action in action_names:
        ida_kernwin.unregister_action(action)


def plugin_status() -> str:
    """Return the current implementation status."""
    return "ida plugin: entry arguments and conservative local recovery implemented"


if ida_idaapi is not None:

    class dayvar_sync_plugin_t(ida_idaapi.plugin_t):
        """IDA plugin wrapper."""

        flags = ida_idaapi.PLUGIN_KEEP
        comment = "DayVarSync broker client"
        help = "Synchronize WinDbg PC and runtime reads through the DayVar broker"
        wanted_name = "DayVarSync"
        wanted_hotkey = ""

        def init(self):
            install_plugin()
            return ida_idaapi.PLUGIN_KEEP

        def run(self, arg):
            del arg
            _controller.show_status()

        def term(self):
            uninstall_plugin()


    def PLUGIN_ENTRY():
        """IDA plugin entry point."""
        return dayvar_sync_plugin_t()


if __name__ == "__main__":
    install_plugin()
