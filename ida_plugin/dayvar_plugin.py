"""IDA plugin entry point for DayVar Sync.

This module implements the IDA-side broker connection, Hex-Rays lvar
enumeration, exact-entry argument reads, conservative local recovery, and the
Live Variables table. Pseudocode overlays are intentionally not implemented.
"""

from __future__ import annotations

import os
import queue
import sys
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
from hexrays_variables import enumerate_hexrays_variables
from live_variables_view import LiveVariablesView
from protocol_client import ProtocolClient
from v_variable_recovery import VVariableRecovery

DEFAULT_HOST = "172.28.70.90"
DEFAULT_PORT = 9100

ACTION_CONNECT = "dayvarsync:connect"
ACTION_DISCONNECT = "dayvarsync:disconnect"
ACTION_STATUS = "dayvarsync:status"
ACTION_SHOW_LIVE = "dayvarsync:show_live"


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

    def __init__(self) -> None:
        self.core = DayVarCore()
        self.v_recovery = VVariableRecovery()
        self.view = LiveVariablesView()
        self.client: ProtocolClient | None = None
        self.messages: queue.Queue[dict[str, Any]] = queue.Queue()
        self.status = "disconnected"

    def connect(self, target: str | None = None) -> None:
        """Connect to the broker as role=ida."""
        try:
            host, port = self._parse_target(target or self._ask_target())
        except ValueError as exc:
            self.view.log(f"invalid broker target: {exc}")
            return

        if self.client is not None and self.client.connected:
            self.view.log("already connected")
            return

        self.client = ProtocolClient(self._on_network_message, self._on_status)
        hello = self.core.make_hello(_ida_version())
        self.client.connect(host, port, hello)
        self.status = f"connecting to {host}:{port}"
        self.view.log(self.status)

    def disconnect(self) -> None:
        """Disconnect from the broker."""
        if self.client is not None:
            self.client.disconnect()
        self.status = "disconnected"
        self.view.log("disconnect requested")

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
        self.view.log(f"status connected={connected} {pc_status} state={self.status}")

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
        self._run_on_ida_thread(lambda: self.view.log(message))

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
            self.view.log(f"ignored message with non-object payload type={message_type}")
            return

        if message_type == "hello_ack":
            self.view.log(f"hello_ack payload={payload}")
        elif message_type == "pc_update":
            self._handle_pc_update(payload)
        elif message_type == "reg_response":
            self._handle_reg_response(payload)
        elif message_type == "mem_response":
            self._handle_mem_response(payload)
        elif message_type == "error":
            self.view.log(f"broker/error payload={payload}")
        else:
            self.view.log(f"ignored incoming message type={message_type}")

    def _handle_pc_update(self, payload: dict[str, Any]) -> None:
        if not payload.get("auto_live"):
            self.view.log(f"pc_update ignored because auto_live is false payload={payload}")
            return

        runtime_pc = str(payload.get("pc", ""))
        module = str(payload.get("module", ""))
        ida_imagebase = self._get_imagebase()

        try:
            mapping = map_pc_update(payload, ida_imagebase)
        except (KeyError, ValueError) as exc:
            self.view.log(f"pc_update mapping failed: {exc}")
            pc_seq = int(payload.get("pc_seq", 0) or 0)
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
        self.view.show_mapping(mapped["payload"])
        self._send(mapped)
        self.v_recovery.invalidate_pc(
            pc_seq=mapping.pc_seq,
            runtime_pc=runtime_pc_text,
        )

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
            self.view.update_rows([])
            self.view.log(enumeration.error)
            return

        at_function_entry = enumeration.function_start_ea == mapping.ida_ea
        plan = self.core.build_entry_plan(
            variables=enumeration.variables,
            pc_seq=mapping.pc_seq,
            runtime_pc=runtime_pc_text,
            ida_ea=ida_ea_text,
            function_ea=enumeration.function_ea,
            at_function_entry=at_function_entry,
        )
        self.view.log(
            "enumerated {count} Hex-Rays variables function={function_ea} at_entry={at_entry}".format(
                count=len(enumeration.variables),
                function_ea=enumeration.function_ea,
                at_entry=at_function_entry,
            )
        )
        for line in plan.debug_lines:
            self.view.log(line)
        self._publish_rows()
        if plan.register_request is not None:
            self._send(plan.register_request)

        try:
            v_plan = self.v_recovery.begin_pc(
                variables=enumeration.variables,
                function_ea=int(enumeration.function_start_ea),
                current_ea=mapping.ida_ea,
                runtime_pc=runtime_pc_text,
                pc_seq=mapping.pc_seq,
                envelope=self.core.envelope,
                cfunc=enumeration.cfunc,
            )
        except Exception as exc:
            # Recovery is best-effort. Entry arguments, mapped PC state, and
            # the network loop must remain usable after any Hex-Rays failure.
            self.v_recovery.invalidate_pc(
                pc_seq=mapping.pc_seq,
                runtime_pc=runtime_pc_text,
            )
            self.view.log(f"v-microcode failure reason={exc}")
            self._publish_rows()
            return

        for line in v_plan.debug_lines:
            self.view.log(line)
        self._publish_rows()
        if v_plan.register_request is not None:
            self._send(v_plan.register_request)

    def _handle_reg_response(self, payload: dict[str, Any]) -> None:
        if self.v_recovery.is_v_request_id(payload.get("request_id")):
            try:
                accepted, reason, mem_requests, debug_lines = self.v_recovery.apply_reg_response(
                    payload,
                    envelope=self.core.envelope,
                )
            except Exception as exc:
                self.view.log(f"ignored v reg_response after recovery failure: {exc}")
                return
            if not accepted:
                self.view.log(f"ignored v reg_response: {reason}")
                return
            self.view.show_reg_response(payload)
            for line in debug_lines:
                self.view.log(line)
            self._publish_rows()
            for mem_request in mem_requests:
                self._send(mem_request)
            return

        accepted, reason, mem_requests = self.core.apply_reg_response(payload)
        if not accepted:
            self.view.log(f"ignored reg_response: {reason}")
            return

        self.view.show_reg_response(payload)
        self._publish_rows()
        for mem_request in mem_requests:
            self._send(mem_request)

    def _handle_mem_response(self, payload: dict[str, Any]) -> None:
        if self.v_recovery.is_v_request_id(payload.get("request_id")):
            try:
                accepted, reason, debug_lines = self.v_recovery.apply_mem_response(payload)
            except Exception as exc:
                self.view.log(f"ignored v mem_response after recovery failure: {exc}")
                return
            if not accepted:
                self.view.log(f"ignored v mem_response: {reason}")
                return
            self.view.show_mem_response(payload)
            for line in debug_lines:
                self.view.log(line)
            self._publish_rows()
            return

        accepted, reason = self.core.apply_mem_response(payload)
        if not accepted:
            self.view.log(f"ignored mem_response: {reason}")
            return
        self.view.show_mem_response(payload)
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
            self.view.log(f"outside IDA: would jump to {format_hex(ea)}")
            return
        if not ida_kernwin.jumpto(ea):
            self.view.log(f"jumpto failed ea={format_hex(ea)}")

    def _send(self, message: dict[str, Any]) -> None:
        if self.client is None:
            self.view.log(f"cannot send type={message.get('type')}: not connected")
            return
        self.view.log(f"send type={message.get('type')} id={message.get('id')}")
        self.client.send(message)


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
        _controller.view.log("outside IDA: plugin actions not registered")
        return

    _register_action(ACTION_CONNECT, "DayVarSync: Connect", _controller.connect)
    _register_action(ACTION_DISCONNECT, "DayVarSync: Disconnect", _controller.disconnect)
    _register_action(ACTION_STATUS, "DayVarSync: Status", _controller.show_status)
    _register_action(ACTION_SHOW_LIVE, "DayVarSync: Show Live Variables", _controller.show_live_variables)

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
    _controller.view.log("actions registered under Edit/DayVarSync")


def uninstall_plugin() -> None:
    """Unregister DayVarSync actions."""
    _controller.disconnect()
    if ida_kernwin is None:
        return
    for action in (ACTION_CONNECT, ACTION_DISCONNECT, ACTION_STATUS, ACTION_SHOW_LIVE):
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
