# Protocol

The protocol is newline-delimited JSON over TCP. Each message is one JSON
object followed by `\n`.

## Envelope

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

`time` may be omitted by the WinDbg extension and filled in broker logs.

## Correlation

- `id` identifies a protocol message for logs and simple matching.
- `pc_seq` identifies the current runtime PC context.
- `request_id` identifies a logical runtime read request.

Every PC-dependent request and response must carry `pc_seq` and `runtime_pc`
when available. IDA must apply a response as fresh only when it matches the
current `pc_seq` and pending `request_id`.

## Phase 1 Message Types

Supported Phase 1 message types:

- `hello`
- `hello_ack`
- `pc_update`
- `ida_pc_mapped`
- `reg_request`
- `reg_response`
- `mem_request`
- `mem_response`
- `error`

Later phases may add `live_refresh_done`, `step_request`, and `step_response`.

## Broker Registration

Clients must send `hello` first. The broker accepts one active `ida` client and
one active `windbg` client. If a second client registers with the same role, the
broker replaces the old connection and logs the replacement.

Example `hello`:

```json
{
  "protocol": 1,
  "id": 1,
  "type": "hello",
  "role": "ida",
  "payload": {
    "client_name": "fake-ida-client",
    "version": "0.1"
  }
}
```

Example `hello_ack`:

```json
{
  "protocol": 1,
  "id": 1,
  "type": "hello_ack",
  "role": "broker",
  "payload": {
    "ok": true,
    "broker_version": "0.1"
  }
}
```

## PC Update Example

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

Recommended `reason` values are `dvs_pc`, `dvs_step`, `manual_refresh`,
`breakpoint`, and `unknown`.

## Staleness Rule

Late responses from older `pc_seq` values must not update the Live Variables
view as fresh. They may be ignored, logged, or used only to mark prior values
stale.

Protocol version starts at `1`. Breaking changes must increment it.

## Phase 1 Manual Flow

```text
fake_windbg -> broker -> fake_ida: pc_update
fake_ida -> broker -> fake_windbg: ida_pc_mapped
fake_ida -> broker -> fake_windbg: reg_request
fake_windbg -> broker -> fake_ida: reg_response
```

This tests routing and correlation fields only. It does not prove real
debugger, IDA, or Hex-Rays behavior.
