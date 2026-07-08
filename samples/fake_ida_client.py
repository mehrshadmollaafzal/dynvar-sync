"""Fake IDA client for testing the Phase 1 broker."""

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
    print(f"[fake_ida] send {message['type']} id={message['id']}", flush=True)
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
    """Build the fake IDA hello message."""
    return protocol.make_envelope(
        protocol.TYPE_HELLO,
        protocol.ROLE_IDA,
        {
            "client_name": "fake-ida-client",
            "version": "0.1",
            "ida_version": "fake",
        },
        message_id=1,
    )


def make_ida_pc_mapped(pc_update: dict[str, Any]) -> dict[str, Any]:
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
        message_id=99,
    )


def make_reg_request(pc_update: dict[str, Any]) -> dict[str, Any]:
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
        message_id=100,
    )


def run(host: str, port: int) -> int:
    """Connect to the broker and perform the fake IDA side of the test."""
    with socket.create_connection((host, port)) as sock:
        print(f"[fake_ida] connected to {host}:{port}", flush=True)
        send_message(sock, make_hello())

        for message in iter_messages(sock):
            print(f"[fake_ida] recv {message}", flush=True)
            if message.get("type") == protocol.TYPE_PC_UPDATE:
                payload = message["payload"]
                if payload.get("auto_live"):
                    send_message(sock, make_ida_pc_mapped(message))
                    send_message(sock, make_reg_request(message))
            elif message.get("type") == protocol.TYPE_REG_RESPONSE:
                return 0

    return 0


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Fake IDA client for broker tests")
    parser.add_argument("--host", default="127.0.0.1", help="broker host")
    parser.add_argument("--port", type=int, default=9100, help="broker port")
    return parser.parse_args()


def main() -> int:
    """Run the fake IDA client."""
    args = parse_args()
    return run(args.host, args.port)


if __name__ == "__main__":
    raise SystemExit(main())
