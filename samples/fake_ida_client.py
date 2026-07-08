"""Fake IDA client for broker and WinDbg extension testing."""

from __future__ import annotations

import argparse
import socket
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from broker import protocol


class MessageIds:
    """Small monotonic message id allocator."""

    def __init__(self) -> None:
        self.next_id = 1

    def take(self) -> int:
        message_id = self.next_id
        self.next_id += 1
        return message_id


def send_message(sock: socket.socket, message: dict[str, Any]) -> None:
    """Send one protocol message."""
    print(f"[fake_ida] send type={message['type']} id={message['id']}", flush=True)
    sock.sendall(protocol.encode_jsonl(message))


def iter_messages(sock: socket.socket):
    """Yield JSONL messages from a socket while preserving partial lines."""
    buffer = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return
        buffer += chunk
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            if not line.strip():
                continue
            yield protocol.decode_jsonl_line(line)


def make_hello(ids: MessageIds) -> dict[str, Any]:
    """Build the fake IDA hello message."""
    return protocol.make_envelope(
        protocol.TYPE_HELLO,
        protocol.ROLE_IDA,
        {
            "client_name": "fake-ida-client",
            "version": "0.1",
            "ida_version": "fake",
        },
        message_id=ids.take(),
    )


def make_ida_pc_mapped(ids: MessageIds, pc_update: dict[str, Any]) -> dict[str, Any]:
    """Build a fake successful IDA PC mapping response."""
    payload = pc_update["payload"]
    return protocol.make_envelope(
        protocol.TYPE_IDA_PC_MAPPED,
        protocol.ROLE_IDA,
        {
            "pc_seq": payload["pc_seq"],
            "runtime_pc": payload["pc"],
            "ida_ea": "0x1406c9cb0",
            "module": payload.get("module", ""),
            "ida_imagebase": "0x140000000",
            "ok": True,
        },
        message_id=ids.take(),
    )


def make_reg_request(ids: MessageIds, pc_update: dict[str, Any]) -> dict[str, Any]:
    """Build a fake register request for auto-live refresh."""
    payload = pc_update["payload"]
    pc_seq = payload["pc_seq"]
    return protocol.make_envelope(
        protocol.TYPE_REG_REQUEST,
        protocol.ROLE_IDA,
        {
            "pc_seq": pc_seq,
            "request_id": f"reg-{pc_seq}-1",
            "runtime_pc": payload["pc"],
            "registers": ["rcx", "rdx", "r8", "r9", "rsp"],
            "reason": "auto_live_refresh",
        },
        message_id=ids.take(),
    )


def make_mem_request(ids: MessageIds, reg_response: dict[str, Any]) -> dict[str, Any] | None:
    """Build one fake memory request at RSP from a register response."""
    payload = reg_response["payload"]
    registers = payload.get("registers", {})
    rsp = registers.get("rsp")
    if not isinstance(rsp, str) or not rsp:
        print("[fake_ida] cannot send mem_request: reg_response has no rsp", flush=True)
        return None

    pc_seq = payload["pc_seq"]
    return protocol.make_envelope(
        protocol.TYPE_MEM_REQUEST,
        protocol.ROLE_IDA,
        {
            "pc_seq": pc_seq,
            "request_id": f"mem-{pc_seq}-rsp",
            "runtime_pc": payload["runtime_pc"],
            "address": rsp,
            "size": 8,
            "reason": "fake_rsp_read",
            "variable": "rsp_qword",
        },
        message_id=ids.take(),
    )


def run(host: str, port: int, once: bool) -> int:
    """Connect to the broker and perform fake IDA auto-live flows."""
    ids = MessageIds()
    completed_flows = 0

    with socket.create_connection((host, port)) as sock:
        print(f"[fake_ida] connected to {host}:{port}", flush=True)
        send_message(sock, make_hello(ids))

        for message in iter_messages(sock):
            message_type = message.get("type")
            print(
                f"[fake_ida] recv type={message_type} payload={message.get('payload')}",
                flush=True,
            )

            if message_type == protocol.TYPE_PC_UPDATE:
                payload = message["payload"]
                if payload.get("auto_live"):
                    send_message(sock, make_ida_pc_mapped(ids, message))
                    send_message(sock, make_reg_request(ids, message))
            elif message_type == protocol.TYPE_REG_RESPONSE:
                mem_request = make_mem_request(ids, message)
                if mem_request is not None:
                    send_message(sock, mem_request)
            elif message_type == protocol.TYPE_MEM_RESPONSE:
                completed_flows += 1
                if once:
                    return 0

    return 0


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Fake IDA client for broker tests")
    parser.add_argument("--host", default="127.0.0.1", help="broker host")
    parser.add_argument("--port", type=int, default=9100, help="broker port")
    parser.add_argument("--once", action="store_true", help="exit after one pc/reg/mem flow")
    return parser.parse_args()


def main() -> int:
    """Run the fake IDA client."""
    args = parse_args()
    return run(args.host, args.port, args.once)


if __name__ == "__main__":
    raise SystemExit(main())
