"""IDA-side broker client placeholder.

This module will eventually own JSONL/TCP connection handling for the IDA
plugin and send low-level register or memory requests generated from IDA-owned
variable semantics.
"""

from __future__ import annotations


class ProtocolClient:
    """Minimal stand-in for the future broker client."""

    def __init__(self) -> None:
        self.connected = False

    def connect(self, host: str, port: int) -> None:
        """Record the intended connection target without opening a socket."""
        del host, port
        self.connected = False
