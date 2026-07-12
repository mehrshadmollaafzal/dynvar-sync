"""JSONL-over-TCP broker for fake IDA and fake WinDbg clients."""

from __future__ import annotations

import argparse
import socket
import threading
from typing import Any

try:
    from . import protocol
    from .sessions import ClientRegistry, ClientSession, opposite_role
except ImportError:  # pragma: no cover - used for python3 broker/dayvar_broker.py.
    import protocol
    from sessions import ClientRegistry, ClientSession, opposite_role


ROUTES = {
    protocol.TYPE_PC_UPDATE: protocol.ROLE_IDA,
    protocol.TYPE_IDA_PC_MAPPED: protocol.ROLE_WINDBG,
    protocol.TYPE_REG_REQUEST: protocol.ROLE_WINDBG,
    protocol.TYPE_REG_RESPONSE: protocol.ROLE_IDA,
    protocol.TYPE_MEM_REQUEST: protocol.ROLE_WINDBG,
    protocol.TYPE_MEM_RESPONSE: protocol.ROLE_IDA,
}


class Broker:
    """Small threaded JSONL broker."""

    def __init__(self, host: str, port: int, verbose: bool = False) -> None:
        self.host = host
        self.port = port
        self.verbose = verbose
        self.registry = ClientRegistry()

    def log(self, message: str) -> None:
        """Print a readable broker log line."""
        print(f"[broker] {message}", flush=True)

    def verbose_log(self, message: str) -> None:
        """Print a verbose log line when enabled."""
        if self.verbose:
            self.log(message)

    def serve_forever(self) -> None:
        """Listen for clients and start one reader thread per connection."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen()
            self.log(f"listening on {self.host}:{self.port}")

            while True:
                client_sock, address = server.accept()
                self.log(f"client connected from {address[0]}:{address[1]}")
                thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_sock, address),
                    daemon=True,
                )
                thread.start()

    def handle_client(self, client_sock: socket.socket, address: tuple[str, int]) -> None:
        """Read JSONL messages from one client until disconnect."""
        buffer = b""
        session: ClientSession | None = None

        try:
            while True:
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                buffer += chunk

                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    if not line.strip():
                        continue

                    try:
                        message = protocol.decode_jsonl_line(line)
                        protocol.validate_message_shape(message)
                    except protocol.ProtocolError as exc:
                        self.log(f"invalid message from {address[0]}:{address[1]}: {exc}")
                        self.send_raw_error(
                            client_sock,
                            "invalid_message",
                            str(exc),
                        )
                        continue

                    session = self.handle_message(client_sock, address, session, message)
        except ConnectionError:
            pass
        except OSError as exc:
            self.verbose_log(f"client socket error from {address[0]}:{address[1]}: {exc}")
        finally:
            if session is not None:
                removed = self.registry.remove(session)
                if removed:
                    self.log(f"client disconnected role={session.role}")
            else:
                self.log(f"unregistered client disconnected from {address[0]}:{address[1]}")
            try:
                client_sock.close()
            except OSError:
                pass

    def handle_message(
        self,
        client_sock: socket.socket,
        address: tuple[str, int],
        session: ClientSession | None,
        message: dict[str, Any],
    ) -> ClientSession | None:
        """Handle one validated protocol message."""
        message_type = message["type"]
        message_id = message["id"]
        role = message["role"]

        if session is None:
            if message_type != protocol.TYPE_HELLO:
                self.log(
                    "client must send hello first "
                    f"from {address[0]}:{address[1]} type={message_type} id={message_id}"
                )
                self.send_raw_error(
                    client_sock,
                    "hello_required",
                    "client must send hello before other messages",
                    message_id=message_id,
                )
                return None

            if role not in {protocol.ROLE_IDA, protocol.ROLE_WINDBG}:
                self.send_raw_error(
                    client_sock,
                    "invalid_role",
                    "only ida and windbg clients can register",
                    message_id=message_id,
                )
                return None

            payload = message["payload"]
            session = ClientSession(
                role=role,
                sock=client_sock,
                address=address,
                client_name=str(payload.get("client_name", "")),
                version=str(payload.get("version", "")),
                protocol=int(message["protocol"]),
            )
            old = self.registry.register(session)
            if old is not None:
                self.log(f"replaced existing role={role} client")
            self.log(f"registered role={role}")
            self.send_to_socket(client_sock, protocol.create_hello_ack(message_id=message_id))
            return session

        if role != session.role:
            self.log(
                f"role mismatch id={message_id}: registered={session.role} message={role}"
            )
            self.send_to_session(
                session,
                protocol.create_error(
                    "role_mismatch",
                    "message role does not match registered client role",
                    message_id=message_id,
                ),
            )
            return session

        session.touch()
        if message_type == protocol.TYPE_HELLO:
            self.send_to_session(session, protocol.create_hello_ack(message_id=message_id))
            return session

        self.route_message(session, message)
        return session

    def route_message(self, source: ClientSession, message: dict[str, Any]) -> None:
        """Route one message to the opposite active client when supported."""
        message_type = message["type"]
        message_id = message["id"]

        if message_type == protocol.TYPE_ERROR:
            destination_role = opposite_role(source.role)
        else:
            destination_role = ROUTES.get(message_type)

        if destination_role is None:
            self.log(
                f"no route for {message_type} id={message_id} from role={source.role}"
            )
            return

        destination = self.registry.get(destination_role)
        if destination is None:
            self.log(
                f"destination {destination_role} not connected for "
                f"{message_type} id={message_id}"
            )
            self.send_to_session(
                source,
                protocol.create_error(
                    "destination_not_connected",
                    f"destination {destination_role} is not connected",
                    message_id=message_id,
                ),
            )
            return

        self.log(
            f"route {message_type} id={message_id} {source.role} -> {destination_role}"
        )
        self.send_to_session(destination, message)

    def send_raw_error(
        self,
        sock: socket.socket,
        code: str,
        message: str,
        *,
        message_id: int = 0,
    ) -> None:
        """Send an error to a socket that may not be registered yet."""
        self.send_to_socket(
            sock,
            protocol.create_error(code, message, message_id=message_id),
        )

    def send_to_session(self, session: ClientSession, message: dict[str, Any]) -> None:
        """Send a message to a registered client."""
        with session.send_lock:
            self.send_to_socket(session.sock, message)

    def send_to_socket(self, sock: socket.socket, message: dict[str, Any]) -> None:
        """Send one JSONL message to a socket."""
        try:
            sock.sendall(protocol.encode_jsonl(message))
        except OSError as exc:
            self.verbose_log(f"send failed: {exc}")


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="dynvar-sync JSONL/TCP broker")
    parser.add_argument("--host", default="127.0.0.1", help="host/interface to bind")
    parser.add_argument("--port", type=int, default=9100, help="TCP port to listen on")
    parser.add_argument("--verbose", action="store_true", help="enable verbose logs")
    return parser.parse_args()


def main() -> int:
    """Run the broker."""
    args = parse_args()
    broker = Broker(args.host, args.port, verbose=args.verbose)
    try:
        broker.serve_forever()
    except KeyboardInterrupt:
        broker.log("stopping")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
