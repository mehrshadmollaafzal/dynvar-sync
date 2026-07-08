# Auto Live Refresh Flow

## Purpose

This file defines the preferred default behavior after WinDbg sends a PC update.

The goal is simple:

```text
One WinDbg command should update both IDA's current address and the Live Variables view.
```

The user should not normally need to run separate commands for:

1. Sync PC.
2. Ask IDA to map PC.
3. Ask IDA to request registers.
4. Ask WinDbg to poll.
5. Refresh the IDA table.

The protocol may use multiple messages internally, but the UX should feel like one operation.

## Main sequence

```text
1. User runs !dvs_pc or !dvs_step.
2. WinDbg sends pc_update with pc_seq and auto_live=true.
3. Broker forwards pc_update to IDA.
4. IDA maps runtime_pc to ida_ea.
5. IDA sends ida_pc_mapped.
6. IDA builds an internal live request plan.
7. IDA sends reg_request and/or mem_request.
8. Broker forwards requests to WinDbg.
9. WinDbg's bounded command pump handles the requests.
10. WinDbg sends reg_response and/or mem_response.
11. IDA applies only responses matching the current pc_seq.
12. IDA refreshes the Live Variables view.
```

## Example message sequence

### 1. WinDbg sends PC

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

### 2. IDA confirms mapping

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

### 3. IDA requests registers

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

### 4. WinDbg responds

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
      "rcx": "0x1111111111111111",
      "rdx": "0x2222222222222222",
      "r8": "0x3333333333333333",
      "r9": "0x4444444444444444",
      "rsp": "0xfffff8012222f000",
      "rbp": "0xfffff8012222f080"
    }
  }
}
```

## Bounded WinDbg command pump

After sending `pc_update`, WinDbg may briefly poll the broker for immediate requests.

Recommended pseudocode:

```c
DvsSendPcUpdate(auto_live=true);

for (int i = 0; i < max_messages; i++) {
    line = DvsSocketReceiveLine(timeout_ms);
    if (!line) {
        break;
    }

    if (IsRegRequest(line)) {
        HandleRegRequest(line);
    } else if (IsMemRequest(line)) {
        HandleMemRequest(line);
    } else {
        LogIgnoredOrUnsupportedMessage(line);
    }
}
```

Hard requirements:

- Never wait forever.
- Preserve partial JSONL lines.
- Do not assume one `recv` equals one message.
- Stop cleanly on timeout.
- Keep `!dvs_poll` available as a manual fallback.

## IDA-side acceptance rule

IDA must apply a response only when all are true:

```text
response.ok == true
response.pc_seq == current_pc_seq
response.runtime_pc == current_runtime_pc, when available
response.request_id is pending
```

Otherwise:

```text
ignore response, or mark it stale/error in logs
never update Live Variables as fresh
```

## Why this is the preferred default

This behavior is useful because it keeps the workflow close to ret-sync simplicity while adding live variable values.

The user action stays simple:

```text
!dvs_pc
```

or:

```text
!dvs_step p
```

The implementation stays safe because every runtime value is correlated by `pc_seq` and `request_id`.
