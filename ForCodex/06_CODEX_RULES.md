# Codex Development Rules

Give this file to Codex before implementation.

## Project constraints

- Target: Windows x64 only.
- IDA: IDA Pro 9.3.
- Debugger: WinDbg Preview.
- IDA plugin: Python / IDAPython.
- Broker: Python.
- WinDbg extension: C-first.
- C++ is allowed only when C would make the code unnecessarily complex.
- Keep dependencies minimal.
- Avoid heavy frameworks.
- Every protocol message is JSONL over TCP.

## General coding rules

- Prefer simple, readable code over clever abstractions.
- Keep modules small.
- Avoid global mutable state unless it is clearly needed.
- Add comments only where behavior is not obvious.
- Do not silently swallow errors.
- Log useful failure reasons.
- Do not block WinDbg forever on socket reads.
- Preserve partial JSONL lines across socket reads.
- Never assume one TCP recv equals one full message.

## Documentation rule

Every code change must update docs when behavior changes.

At minimum, update one of:

- `docs/01_architecture.md`
- `docs/02_protocol.md`
- `docs/03_variable_model.md`
- `docs/06_testing.md`
- component README files

## Auto-refresh protocol rules

- `!dvs_pc` and `!dvs_step` should be able to trigger automatic live refresh.
- Use `pc_seq` to correlate PC updates, mapping results, runtime requests, and responses.
- Use `request_id` for each logical register/memory request.
- Keep the protocol message-based; do not implement fragile direct synchronous coupling between IDA and WinDbg.
- WinDbg may run a short bounded pump after sending `pc_update`, but it must never wait forever.
- IDA must ignore responses from older `pc_seq` values.

## IDA rules

- Use the provided IDAPython/Hex-Rays skill for API usage.
- IDA owns decompiler variable interpretation.
- Do not make WinDbg understand Hex-Rays variable semantics.
- Do not mutate decompiled C text in v1.
- Use a separate Live Variables view first.
- Classify unsupported variables honestly.
- Build the live request plan on the IDA side after successful PC mapping.
- Never show guessed values as fresh.

## WinDbg extension rules

- Keep the extension low-level.
- Commands should be explicit and predictable.
- Do not use large JSON libraries unless absolutely necessary.
- JSON writing can be simple string formatting with proper escaping where needed.
- JSON parsing can be minimal and command-specific.
- DbgEng operations must run synchronously inside WinDbg command handlers.
- Network receive should be timeout-based.
- After `!dvs_pc` and `!dvs_step`, process immediate broker requests with a bounded pump.

## Broker rules

- Broker routes messages and tracks session state.
- Broker should not perform static analysis.
- Broker should not read target memory.
- Broker should reject incompatible protocol versions.
- Broker should log message type, id, role, and routing decision.

## Variable correctness rules

- Fresh means valid for the current `pc_seq` and PC/context.
- Stale means previously valid but not guaranteed anymore.
- Unavailable is better than wrong.
- Unsupported Hex-Rays temporaries must not be guessed.
- Function entry argument mapping is exact only at entry.
- Late responses for older PCs or older `pc_seq` values must be ignored or marked stale.

## Testing rule

Each phase must include at least one simple manual verification path.

Prefer small sample programs over complex real-world binaries for first tests.

