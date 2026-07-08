# Variable Model

## Problem

Hex-Rays variables are not always real runtime storage locations.

Some variables map cleanly to:

- function arguments
- stack slots
- explicit memory locations

But many `vXXX` variables are decompiler temporaries produced by analysis. They may live in registers only temporarily, be optimized away, or represent expressions rather than stable storage.

Therefore, the project must never pretend that every Hex-Rays variable has a reliable live runtime value.

## Core rule

Every displayed value must have a status and confidence.

Never show guessed data as if it were exact.

## Variable record

IDA should internally represent each variable as:

```json
{
  "name": "a1",
  "hexrays_kind": "arg|local|temporary|unknown",
  "ida_function_ea": "0x1406c9cb0",
  "size": 8,
  "arg_index": 0,
  "storage_kind": "reg_at_entry",
  "storage": "rcx",
  "status": "fresh|stale|unavailable|error",
  "confidence": "exact_entry|stale_entry_value|unsupported|unknown",
  "value": "0xffff...",
  "reason": "rcx at function entry",
  "last_value_pc": "0xffff...",
  "current_pc": "0xffff...",
  "entry_snapshot_pc": "0xffff...",
  "stale_reason": null,
  "last_update_time": 1720000000.123
}
```

## Status values

### fresh

The value is valid for the current PC and current context.

Example:

- function argument captured at exact function entry PC
- explicit memory watch just read at current PC

### stale

The value was once valid but may no longer be valid.

Example:

- function argument was captured at function entry
- user stepped inside the same function
- the original entry value is preserved but must not be shown as fresh

### unavailable

No reliable value is available.

Example:

- Hex-Rays temporary `v160`
- local variable with no reliable storage mapping
- argument requested after entry with no entry snapshot

### error

A supported read failed.

Example:

- memory read failed
- register read failed
- target is not responding

## Confidence values

Recommended initial set:

```text
exact_entry
exact_memory_read
stale_entry_value
unsupported_variable
unsupported_location
read_failed
unknown
```

## Windows x64 argument mapping

At exact function entry:

```text
arg0 -> rcx
arg1 -> rdx
arg2 -> r8
arg3 -> r9
arg4 -> [rsp + 0x28]
arg5 -> [rsp + 0x30]
arg6 -> [rsp + 0x38]
...
```

Important:

- This mapping is exact only at function entry.
- After the prologue or after stepping, registers may be overwritten.
- Stack arguments are more stable than register arguments but still must be treated carefully if stack pointer/frame changes are not tracked.

## v1 supported variables

Support only these first:

1. Function arguments 0..3 at exact function entry via RCX/RDX/R8/R9.
2. Function arguments 4+ at exact function entry via stack layout `[rsp + 0x28 + 8 * (arg_index - 4)]`.
3. Explicit EA watches, where the user asks to read bytes at a known IDA EA/runtime address.

## v1 unsupported variables

Do not guess values for:

- arbitrary Hex-Rays locals
- arbitrary `vXXX` temporaries
- expression-only variables
- register locations after unknown instruction flow
- variables from inlined functions

Show them as:

```text
status = unavailable
confidence = unsupported_variable
reason = variable does not have a reliable runtime location in v1
```

## Auto live refresh model

When IDA receives `pc_update(auto_live=true)`, it should:

1. Map runtime PC to IDA EA.
2. Send `ida_pc_mapped` with the same `pc_seq`.
3. Find the current function and Hex-Rays variables.
4. Build an internal live request plan.
5. Send only the low-level requests required for supported variables.
6. Apply responses only if `pc_seq` still matches the current PC.

Example internal plan:

```json
{
  "pc_seq": 42,
  "runtime_pc": "0xfffff8010dac9cb0",
  "ida_ea": "0x1406c9cb0",
  "function_ea": "0x1406c9cb0",
  "needed_registers": ["rcx", "rdx", "r8", "r9", "rsp"],
  "needed_memory_reads": [
    {"address_expr": "rsp+0x28", "size": 8, "variable": "a5", "reason": "stack_arg"},
    {"address_expr": "rsp+0x30", "size": 8, "variable": "a6", "reason": "stack_arg"}
  ]
}
```

The plan can stay IDA-local in v1. Do not force WinDbg to understand variables, function arguments, or Hex-Rays metadata.

## Entry snapshot model

When current PC equals function entry and the current `pc_seq` is active:

1. IDA extracts supported arguments.
2. IDA requests required registers/memory.
3. IDA stores an entry snapshot:

```json
{
  "function_ea": "0x1406c9cb0",
  "runtime_entry_pc": "0xfffff8010dac9cb0",
  "registers": {
    "rcx": "0x...",
    "rdx": "0x...",
    "r8": "0x...",
    "r9": "0x..."
  },
  "stack_args": {
    "arg4": "0x...",
    "arg5": "0x..."
  }
}
```

When user steps away from entry inside the same function:

- preserve the entry values
- change status to `stale`
- set confidence to `stale_entry_value`
- set `stale_reason` to explain that entry argument mapping is exact only at function entry
- do not let a late response from an older `pc_seq` turn the row fresh again

## Display model

Use a Live Variables table with columns:

```text
Name | Kind | Size | Location | Value | Status | Confidence | Reason | Last PC | Current PC
```

Only after this model is stable should pseudocode overlays be added.

