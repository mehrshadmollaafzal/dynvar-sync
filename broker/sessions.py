"""Connected client registry for the broker."""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass, field

try:
    from .protocol import ROLE_IDA, ROLE_WINDBG
except ImportError:  # pragma: no cover - used when run as a script sibling.
    from protocol import ROLE_IDA, ROLE_WINDBG

Address = tuple[str, int]


@dataclass
class ClientSession:
    """Representation of one active broker client."""

    role: str
    sock: socket.socket
    address: Address
    connected_at: float = field(default_factory=time.time)
    last_seen_at: float = field(default_factory=time.time)
    client_name: str = ""
    version: str = ""
    protocol: int = 1
    send_lock: threading.Lock = field(default_factory=threading.Lock)

    def touch(self) -> None:
        """Update the last-seen timestamp."""
        self.last_seen_at = time.time()

    def close(self) -> None:
        """Close the underlying socket quietly."""
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class ClientRegistry:
    """Registry allowing one active IDA client and one active WinDbg client."""

    def __init__(self) -> None:
        self._clients: dict[str, ClientSession] = {}
        self._lock = threading.Lock()

    def register(self, session: ClientSession) -> ClientSession | None:
        """Register a session, replacing any existing client with the same role."""
        if session.role not in {ROLE_IDA, ROLE_WINDBG}:
            raise ValueError(f"client role cannot be registered: {session.role!r}")

        with self._lock:
            old = self._clients.get(session.role)
            self._clients[session.role] = session

        if old is not None and old.sock is not session.sock:
            old.close()
        return old

    def get(self, role: str) -> ClientSession | None:
        """Return the active session for a role."""
        with self._lock:
            return self._clients.get(role)

    def remove(self, session: ClientSession) -> bool:
        """Remove a session if it is still the active client for its role."""
        with self._lock:
            if self._clients.get(session.role) is session:
                del self._clients[session.role]
                return True
        return False


def opposite_role(role: str) -> str | None:
    """Return the peer role for IDA/WinDbg routing."""
    if role == ROLE_IDA:
        return ROLE_WINDBG
    if role == ROLE_WINDBG:
        return ROLE_IDA
    return None
