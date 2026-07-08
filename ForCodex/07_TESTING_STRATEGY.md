# Testing Strategy

## Why testing matters

This project can easily show wrong runtime values if stale state or variable mapping is handled incorrectly. Therefore, testing must focus on correctness, not just connectivity.

## Test levels

### 1. Protocol tests

Use fake clients before using IDA or WinDbg.

Test:

- hello/hello_ack
- pc_update forwarding
- reg_request/reg_response forwarding
- mem_request/mem_response forwarding
- pc_seq correlation across pc_update -> request -> response
- malformed JSON handling
- partial TCP line handling
- multiple JSON messages in one recv

### 2. WinDbg extension smoke tests

Manual commands:

```text
.load path\to\dayvar.dll
!dvs_connect 127.0.0.1 9100
!dvs_status
!dvs_pc
!dvs_poll
!dvs_step p 1
!dvs_disconnect
```

Expected:

- No WinDbg hang.
- No crash.
- Broker logs each command message.
- `!dvs_pc` includes PC/module/base/pc_seq.
- `!dvs_pc` can briefly pump and answer immediate IDA requests.

### 3. IDA plugin smoke tests

Manual actions:

- Load matching binary in IDA.
- Start broker.
- Connect IDA plugin.
- Connect WinDbg extension.
- Run `!dvs_pc`.

Expected:

- IDA maps runtime PC to IDA EA.
- IDA jumps to expected function.
- Mapping details are printed.

### 4. Auto live refresh test

Scenario:

1. Start broker.
2. Connect fake IDA and fake WinDbg clients.
3. Fake WinDbg sends `pc_update(pc_seq=42, auto_live=true)`.
4. Fake IDA replies `ida_pc_mapped(pc_seq=42, ok=true)`.
5. Fake IDA sends `reg_request(pc_seq=42, request_id=reg-42-1)`.
6. Fake WinDbg replies `reg_response(pc_seq=42, request_id=reg-42-1)`.

Expected:

- Broker routes all messages correctly.
- Correlation fields are preserved.
- Fake IDA accepts only matching `pc_seq`.

### 5. Variable model tests

Use sample functions with known arguments.

Example function:

```c
__declspec(noinline)
void probe6(void *a1, void *a2, unsigned long a3, void *a4, void *a5, void *a6)
{
    __debugbreak();
}
```

Expected at entry:

```text
a1 -> rcx -> fresh/exact_entry
a2 -> rdx -> fresh/exact_entry
a3 -> r8  -> fresh/exact_entry
a4 -> r9  -> fresh/exact_entry
a5 -> [rsp + 0x28] -> fresh/exact_entry
a6 -> [rsp + 0x30] -> fresh/exact_entry
```

After stepping:

```text
previous entry values remain visible but become stale/stale_entry_value
```

### 6. Negative tests

Test unsupported variables:

- arbitrary `vXXX` temporary
- local variable with no reliable storage
- inlined function variable

Expected:

```text
status = unavailable
confidence = unsupported_variable
```

### 7. Late response test

Scenario:

1. IDA sends `reg_request(pc_seq=42)` for PC A.
2. User steps to PC B and receives `pc_update(pc_seq=43)`.
3. Response for `pc_seq=42` arrives late.

Expected:

- IDA does not mark values fresh for PC B.
- Response is ignored or marked stale.

## Recommended sample folders

```text
samples/
├── many_args_probe/
├── ntqsi_probe/
├── ntcreatefile_probe/
└── README.md
```

Each sample should document:

- what it tests
- how to build
- where to break
- expected live variable output

