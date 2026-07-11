"""Fake WinDbg client for testing the Phase 1 broker."""

from __future__ import annotations

import argparse
import socket
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from broker import protocol


def send_message(sock: socket.socket, message: dict[str, Any]) -> None:
    """Send one protocol message."""
    print(f"[fake_windbg] send {message['type']} id={message['id']}", flush=True)
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


def make_hello() -> dict[str, Any]:
    """Build the fake WinDbg hello message."""
    return protocol.make_envelope(
        protocol.TYPE_HELLO,
        protocol.ROLE_WINDBG,
        {
            "client_name": "fake-windbg-client",
            "version": "0.1",
        },
        message_id=1,
    )


def make_pc_update() -> dict[str, Any]:
    """Build the fake WinDbg PC update."""
    return protocol.make_envelope(
        protocol.TYPE_PC_UPDATE,
        protocol.ROLE_WINDBG,
        {
            "pc_seq": 42,
            "pc": "0xfffff8010dac9cb0",
            "module": "ntkrnlmp.exe",
            "runtime_module_base": "0xfffff8010d400000",
            "auto_live": True,
            "reason": "fake_windbg_test",
        },
        message_id=10,
    )


def make_reg_response(reg_request: dict[str, Any]) -> dict[str, Any]:
    """Build a fake register response."""
    payload = reg_request["payload"]
    return protocol.make_envelope(
        protocol.TYPE_REG_RESPONSE,
        protocol.ROLE_WINDBG,
        {
            "pc_seq": payload["pc_seq"],
            "request_id": payload["request_id"],
            "runtime_pc": payload["runtime_pc"],
            "ok": True,
            "registers": {
                "rcx": "0x1111111111111111",
                "rdx": "0x2222222222222222",
                "r8": "0x3333333333333333",
                "r9": "0x4444444444444444",
                "rsp": "0xfffff8012222f000",
            },
        },
        message_id=101,
    )


def make_mem_response(mem_request: dict[str, Any]) -> dict[str, Any]:
    """Build a deterministic fake memory response."""
    payload = mem_request["payload"]
    size = int(payload["size"])
    pattern = bytes.fromhex("8877665544332211")
    data = (pattern * ((size + len(pattern) - 1) // len(pattern)))[:size]
    return protocol.make_envelope(
        protocol.TYPE_MEM_RESPONSE,
        protocol.ROLE_WINDBG,
        {
            "pc_seq": payload["pc_seq"],
            "request_id": payload["request_id"],
            "runtime_pc": payload["runtime_pc"],
            "ok": True,
            "address": payload["address"],
            "size": size,
            "bytes_hex": data.hex(),
        },
        message_id=102,
    )


def run(host: str, port: int) -> int:
    """Connect to the broker and perform the fake WinDbg side of the test."""
    with socket.create_connection((host, port)) as sock:
        print(f"[fake_windbg] connected to {host}:{port}", flush=True)
        send_message(sock, make_hello())

        sent_pc = False
        for message in iter_messages(sock):
            print(f"[fake_windbg] recv {message}", flush=True)
            if message.get("type") == protocol.TYPE_HELLO_ACK and not sent_pc:
                send_message(sock, make_pc_update())
                sent_pc = True
            elif message.get("type") == protocol.TYPE_REG_REQUEST:
                send_message(sock, make_reg_response(message))
            elif message.get("type") == protocol.TYPE_MEM_REQUEST:
                send_message(sock, make_mem_response(message))
                return 0

    return 0


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Fake WinDbg client for broker tests")
    parser.add_argument("--host", default="127.0.0.1", help="broker host")
    parser.add_argument("--port", type=int, default=9100, help="broker port")
    return parser.parse_args()


def main() -> int:
    """Run the fake WinDbg client."""
    args = parse_args()
    return run(args.host, args.port)


if __name__ == "__main__":
    raise SystemExit(main())
