"""IDA-side JSONL/TCP broker client.

The socket worker runs outside IDA's UI thread. Callbacks must marshal any IDA
API work back to the main thread.
"""

from __future__ import annotations

import json
import queue
import socket
import threading
from collections.abc import Callable
from typing import Any

MessageCallback = Callable[[dict[str, Any]], None]
StatusCallback = Callable[[str], None]


def encode_jsonl(message: dict[str, Any]) -> bytes:
    """Encode one JSON object as a JSONL byte string."""
    return (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")


def decode_jsonl_line(line: bytes) -> dict[str, Any]:
    """Decode one JSONL line."""
    message = json.loads(line.decode("utf-8").strip())
    if not isinstance(message, dict):
        raise ValueError("message is not a JSON object")
    return message


class ProtocolClient:
    """Small threaded broker client for IDA."""

    def __init__(
        self,
        on_message: MessageCallback,
        on_status: StatusCallback,
    ) -> None:
        self._on_message = on_message
        self._on_status = on_status
        self._send_queue: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self._thread: threading.Thread | None = None
        self._sock: socket.socket | None = None
        self._stop_event = threading.Event()
        self.connected = False

    def connect(self, host: str, port: int, hello_message: dict[str, Any]) -> None:
        """Start the background broker connection."""
        if self._thread and self._thread.is_alive():
            self._on_status("already connected or connecting")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            args=(host, port, hello_message),
            name="DayVarSyncBrokerClient",
            daemon=True,
        )
        self._thread.start()

    def send(self, message: dict[str, Any]) -> None:
        """Queue one protocol message for sending."""
        if self._stop_event.is_set():
            self._on_status(f"drop send while disconnected type={message.get('type')}")
            return
        self._send_queue.put(message)

    def disconnect(self) -> None:
        """Stop the worker and close the socket."""
        self._stop_event.set()
        self._send_queue.put(None)
        sock = self._sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        self.connected = False

    def _run(self, host: str, port: int, hello_message: dict[str, Any]) -> None:
        buffer = b""
        try:
            with socket.create_connection((host, port), timeout=3.0) as sock:
                self._sock = sock
                sock.settimeout(0.1)
                sock.sendall(encode_jsonl(hello_message))
                self.connected = True
                self._on_status(f"connected to broker {host}:{port}")

                while not self._stop_event.is_set():
                    self._drain_send_queue(sock)
                    try:
                        chunk = sock.recv(4096)
                    except socket.timeout:
                        continue
                    except OSError as exc:
                        if not self._stop_event.is_set():
                            self._on_status(f"socket receive failed: {exc}")
                        break

                    if not chunk:
                        self._on_status("broker disconnected")
                        break
                    buffer += chunk
                    buffer = self._drain_receive_buffer(buffer)
        except OSError as exc:
            self._on_status(f"connect failed: {exc}")
        finally:
            self.connected = False
            self._sock = None
            self._stop_event.set()
            self._on_status("disconnected")

    def _drain_send_queue(self, sock: socket.socket) -> None:
        while True:
            try:
                message = self._send_queue.get_nowait()
            except queue.Empty:
                return
            if message is None:
                return
            try:
                sock.sendall(encode_jsonl(message))
            except OSError as exc:
                self._on_status(f"send failed: {exc}")
                self._stop_event.set()
                return

    def _drain_receive_buffer(self, buffer: bytes) -> bytes:
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            if not line.strip():
                continue
            try:
                message = decode_jsonl_line(line)
            except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
                self._on_status(f"ignored invalid JSONL from broker: {exc}")
                continue
            self._on_message(message)
        return buffer
