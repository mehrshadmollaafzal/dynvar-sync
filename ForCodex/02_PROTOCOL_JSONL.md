# Protocol — JSONL over TCP

## Transport

Use TCP sockets and newline-delimited JSON.

Each message is one complete JSON object followed by `\n`.

```text
{"type":"hello","role":"ida","protocol":1}\n
{"type":"pc_update","id":7,"role":"windbg","payload":{"pc":"0xfffff801..."}}\n
```

Reason:

- Easy to debug with netcat/log files.
- Easy to implement in C.
- Easy to parse in Python.
- Avoids packet-boundary assumptions.

## General message envelope

Every message should follow this shape:

```json
{
  "protocol": 1,
  "id": 1,
  "type": "message_type",
  "role": "ida|windbg|broker",
  "session": "optional-session-id",
  "time": 1720000000.123,
  "payload": {}
}
```

For C simplicity, `time` may be omitted by WinDbg and filled by broker logs.

## Correlation fields

Use both message-level `id` and payload-level correlation fields.

```text
id         unique message id, useful for logs and simple response matching
pc_seq     monotonically increasing sequence for the current runtime PC
request_id unique logical request id, useful when one PC creates multiple reads
```

Rules:

- WinDbg creates/increments `pc_seq` whenever it sends a new `pc_update`.
- IDA copies the same `pc_seq` into `ida_pc_mapped`, `reg_request`, and `mem_request`.
- WinDbg copies the same `pc_seq` and `request_id` into responses.
- IDA only marks values `fresh` when the response `pc_seq` still matches the current PC context.

## Required message types

### hello

Client announces itself.

```json
{
  "protocol": 1,
  "type": "hello",
  "role": "windbg",
  "payload": {
    "client_name": "dayvar-windbg-ext",
    "version": "0.1"
  }
}
```

```json
{
  "protocol": 1,
  "type": "hello",
  "role": "ida",
  "payload": {
    "client_name": "dayvar-ida-plugin",
    "version": "0.1",
    "ida_version": "9.3"
  }
}
```

### hello_ack

Broker confirms registration.

```json
{
  "protocol": 1,
  "type": "hello_ack",
  "role": "broker",
  "payload": {
    "ok": true,
    "broker_version": "0.1"
  }
}
```

### pc_update

WinDbg sends current execution position.

`auto_live` tells IDA that this PC update should trigger automatic live variable refresh when possible.

```json
{
  "protocol": 1,
  "id": 10,
  "type": "pc_update",
  "role": "windbg",
  "payload": {
    "pc_seq": 42,
    "pc": "0xfffff8010dac9cb0",
    "module": "ntkrnlmp.exe",
    "runtime_module_base": "0xfffff8010d400000",
    "auto_live": true,
    "reason": "dvs_pc"
  }
}
```

Recommended `reason` values:

```text
dvs_pc
dvs_step
manual_refresh
breakpoint
unknown
```

### ida_pc_mapped

IDA reports mapping result.

```json
{
  "protocol": 1,
  "id": 11,
  "type": "ida_pc_mapped",
  "role": "ida",
  "payload": {
    "pc_seq": 42,
    "runtime_pc": "0xfffff8010dac9cb0",
    "ida_ea": "0x1406c9cb0",
    "module": "ntkrnlmp.exe",
    "ida_imagebase": "0x140000000",
    "ok": true
  }
}
```

If mapping fails:

```json
{
  "protocol": 1,
  "id": 11,
  "type": "ida_pc_mapped",
  "role": "ida",
  "payload": {
    "pc_seq": 42,
    "runtime_pc": "0xfffff8010dac9cb0",
    "module": "ntkrnlmp.exe",
    "ok": false,
    "error": "module_not_loaded_in_ida"
  }
}
```

### reg_request

IDA asks WinDbg for register values. This is normally generated automatically after a successful `pc_update` mapping.

```json
{
  "protocol": 1,
  "id": 12,
  "type": "reg_request",
  "role": "ida",
  "payload": {
    "pc_seq": 42,
    "request_id": "reg-42-1",
    "runtime_pc": "0xfffff8010dac9cb0",
    "registers": ["rcx", "rdx", "r8", "r9", "rsp", "rbp"],
    "reason": "auto_live_refresh"
  }
}
```

### reg_response

WinDbg returns register values.

```json
{
  "protocol": 1,
  "id": 13,
  "type": "reg_response",
  "role": "windbg",
  "payload": {
    "pc_seq": 42,
    "request_id": "reg-42-1",
    "runtime_pc": "0xfffff8010dac9cb0",
    "ok": true,
    "registers": {
      "rcx": "0x0000000000000005",
      "rdx": "0xffffe00112345000",
      "r8":  "0x0000000000001000",
      "r9":  "0x0000000000000000",
      "rsp": "0xfffff8012222f000",
      "rbp": "0xfffff8012222f080"
    }
  }
}
```

### mem_request

IDA asks WinDbg to read memory.

For stack arguments, IDA should first request `rsp`, then compute concrete runtime addresses, then send memory requests.

```json
{
  "protocol": 1,
  "id": 20,
  "type": "mem_request",
  "role": "ida",
  "payload": {
    "pc_seq": 42,
    "request_id": "mem-42-arg4",
    "runtime_pc": "0xfffff8010dac9cb0",
    "address": "0xfffff8012222f028",
    "size": 8,
    "reason": "stack_arg",
    "variable": "a5"
  }
}
```

Explicit EA watch example:

```json
{
  "protocol": 1,
  "id": 21,
  "type": "mem_request",
  "role": "ida",
  "payload": {
    "pc_seq": 42,
    "request_id": "mem-42-ea-1",
    "runtime_pc": "0xfffff8010dac9cb0",
    "address": "0xfffff8010dac9cb0",
    "size": 16,
    "reason": "ea_watch"
  }
}
```

### mem_response

WinDbg returns memory bytes as hex.

```json
{
  "protocol": 1,
  "id": 22,
  "type": "mem_response",
  "role": "windbg",
  "payload": {
    "pc_seq": 42,
    "request_id": "mem-42-arg4",
    "runtime_pc": "0xfffff8010dac9cb0",
    "ok": true,
    "address": "0xfffff8012222f028",
    "size": 8,
    "bytes_hex": "8877665544332211"
  }
}
```

### live_refresh_done

Optional IDA message used for logs/UI. It is not required for correctness.

```json
{
  "protocol": 1,
  "id": 30,
  "type": "live_refresh_done",
  "role": "ida",
  "payload": {
    "pc_seq": 42,
    "runtime_pc": "0xfffff8010dac9cb0",
    "ida_ea": "0x1406c9cb0",
    "ok": true,
    "fresh_count": 4,
    "stale_count": 0,
    "unavailable_count": 8
  }
}
```

### step_request

IDA or broker requests WinDbg to step.

```json
{
  "protocol": 1,
  "id": 300,
  "type": "step_request",
  "role": "ida",
  "payload": {
    "mode": "p",
    "count": 1,
    "send_pc_after": true,
    "auto_live": true
  }
}
```

Allowed `mode` values:

- `p` — step over
- `t` — trace into

### step_response

WinDbg confirms step completion.

```json
{
  "protocol": 1,
  "id": 300,
  "type": "step_response",
  "role": "windbg",
  "payload": {
    "ok": true,
    "count": 1,
    "mode": "p"
  }
}
```

If `send_pc_after` is true, WinDbg should send a new `pc_update` after `step_response`.

## Recommended one-command flow

A single `!dvs_pc` should be able to produce this message sequence:

```text
1. windbg -> broker -> ida: pc_update(pc_seq=42, auto_live=true)
2. ida -> broker: ida_pc_mapped(pc_seq=42, ok=true)
3. ida -> broker -> windbg: reg_request(pc_seq=42, request_id=reg-42-1)
4. windbg -> broker -> ida: reg_response(pc_seq=42, request_id=reg-42-1)
5. ida -> broker -> windbg: mem_request(pc_seq=42, request_id=mem-42-arg4) optional
6. windbg -> broker -> ida: mem_response(pc_seq=42, request_id=mem-42-arg4) optional
7. ida -> broker: live_refresh_done(pc_seq=42) optional
```

## WinDbg command pump rule

WinDbg commands that send a `pc_update` may run a short bounded receive/poll loop after sending the PC.

Purpose:

- Let IDA immediately send `reg_request` / `mem_request`.
- Let WinDbg answer those requests during the same user command.
- Keep user experience as one command.

Requirements:

- The loop must be bounded by message count and timeout.
- It must never block WinDbg forever.
- It must preserve partial JSONL lines.
- It must stop cleanly when no messages are available.

Recommended initial behavior:

```text
!dvs_pc
  send pc_update(auto_live=true)
  pump up to 16 incoming messages or up to a short timeout

!dvs_step p 1
  execute step
  send step_response
  send pc_update(auto_live=true, reason=dvs_step)
  pump up to 16 incoming messages or up to a short timeout
```

## Error message

```json
{
  "protocol": 1,
  "id": 100,
  "type": "error",
  "role": "windbg",
  "payload": {
    "pc_seq": 42,
    "request_id": "mem-42-arg4",
    "ok": false,
    "code": "read_failed",
    "message": "Unable to read memory",
    "details": {
      "address": "0xffff...",
      "size": 8
    }
  }
}
```

## Staleness rule

Every request that depends on PC must include `pc_seq` and `runtime_pc`.

IDA must ignore or mark stale any response whose `pc_seq` does not match the current known PC sequence.

This prevents late responses from incorrectly updating the UI after stepping.

## Versioning rule

Start with:

```json
"protocol": 1
```

Any breaking change increments the protocol number.

Non-breaking additions should add optional fields only.
