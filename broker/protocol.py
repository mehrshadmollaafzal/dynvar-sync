"""Protocol helpers for newline-delimited JSON messages."""

from __future__ import annotations

import json
from typing import Any

PROTOCOL_VERSION = 1

ROLE_IDA = "ida"
ROLE_WINDBG = "windbg"
ROLE_BROKER = "broker"

TYPE_HELLO = "hello"
TYPE_HELLO_ACK = "hello_ack"
TYPE_PC_UPDATE = "pc_update"
TYPE_IDA_PC_MAPPED = "ida_pc_mapped"
TYPE_REG_REQUEST = "reg_request"
TYPE_REG_RESPONSE = "reg_response"
TYPE_MEM_REQUEST = "mem_request"
TYPE_MEM_RESPONSE = "mem_response"
TYPE_ERROR = "error"

SUPPORTED_ROLES = {
    ROLE_IDA,
    ROLE_WINDBG,
    ROLE_BROKER,
}

SUPPORTED_MESSAGE_TYPES = {
    TYPE_HELLO,
    TYPE_HELLO_ACK,
    TYPE_PC_UPDATE,
    TYPE_IDA_PC_MAPPED,
    TYPE_REG_REQUEST,
    TYPE_REG_RESPONSE,
    TYPE_MEM_REQUEST,
    TYPE_MEM_RESPONSE,
    TYPE_ERROR,
}


class ProtocolError(ValueError):
    """Raised when a protocol message is malformed."""


def encode_jsonl(message: dict[str, Any]) -> bytes:
    """Encode one JSON object as a JSONL byte string."""
    return (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")


def decode_jsonl_line(line: bytes | str) -> dict[str, Any]:
    """Decode one JSONL line into a dictionary."""
    if isinstance(line, bytes):
        text = line.decode("utf-8")
    else:
        text = line

    text = text.strip()
    if not text:
        raise ProtocolError("empty JSONL line")

    try:
        message = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProtocolError(f"invalid JSON: {exc.msg}") from exc

    if not isinstance(message, dict):
        raise ProtocolError("message must be a JSON object")
    return message


def check_protocol_version(message: dict[str, Any]) -> bool:
    """Return true when the message uses the supported protocol version."""
    return message.get("protocol") == PROTOCOL_VERSION


def validate_message_shape(message: dict[str, Any]) -> None:
    """Validate the minimal DayVar protocol envelope."""
    if not check_protocol_version(message):
        raise ProtocolError(f"unsupported protocol version: {message.get('protocol')!r}")

    message_id = message.get("id")
    if not isinstance(message_id, int):
        raise ProtocolError("message id must be an integer")

    message_type = message.get("type")
    if message_type not in SUPPORTED_MESSAGE_TYPES:
        raise ProtocolError(f"unsupported message type: {message_type!r}")

    role = message.get("role")
    if role not in SUPPORTED_ROLES:
        raise ProtocolError(f"unsupported role: {role!r}")

    payload = message.get("payload")
    if not isinstance(payload, dict):
        raise ProtocolError("payload must be an object")


def make_envelope(
    message_type: str,
    role: str,
    payload: dict[str, Any] | None = None,
    message_id: int = 0,
) -> dict[str, Any]:
    """Create a minimal protocol envelope for tests and clients."""
    return {
        "protocol": PROTOCOL_VERSION,
        "id": message_id,
        "type": message_type,
        "role": role,
        "payload": payload or {},
    }


def create_hello_ack(message_id: int = 0) -> dict[str, Any]:
    """Create a broker hello acknowledgement."""
    return make_envelope(
        TYPE_HELLO_ACK,
        ROLE_BROKER,
        {
            "ok": True,
            "broker_version": "0.1",
        },
        message_id=message_id,
    )


def create_error(
    code: str,
    message: str,
    *,
    message_id: int = 0,
    pc_seq: int | None = None,
    request_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a broker error message."""
    payload: dict[str, Any] = {
        "ok": False,
        "code": code,
        "message": message,
    }
    if pc_seq is not None:
        payload["pc_seq"] = pc_seq
    if request_id is not None:
        payload["request_id"] = request_id
    if details is not None:
        payload["details"] = details

    return make_envelope(TYPE_ERROR, ROLE_BROKER, payload, message_id=message_id)
