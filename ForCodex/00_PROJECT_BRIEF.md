# dayvar-sync-version2 — Project Brief for Codex

## Goal

Build **dayvar-sync-version2**, a lightweight synchronization system between **IDA Pro 9.3** and **WinDbg Preview** for **Windows x64** targets.

The system should synchronize:

1. The runtime instruction pointer / current PC between WinDbg and IDA.
2. Selected Hex-Rays decompiled variables and their runtime values.

The primary feature is to show runtime values for supported Hex-Rays variables without modifying the decompiled C code.

Example target UX:

```text
Hex-Rays variable: a1
Runtime value:     0xfffff80112345678
Status:            fresh
Source:            rcx at function entry
```

## Non-goals for the first version

Do not attempt to solve all decompiler variable recovery cases in v1.

Out of scope initially:

- x86 support
- ARM64 support
- non-Windows targets
- direct mutation of Hex-Rays pseudocode text
- universal recovery of all `vXXX` temporary variables
- symbolic execution
- complex data-flow reconstruction
- heavyweight frameworks

## Core principle

Keep the runtime side simple and reliable. Put complex logic in Python where it is easier to inspect, test, and update.

## Recommended top-level architecture

Use three main components:

```text
+----------------------+        JSONL/TCP        +----------------------+        JSONL/TCP        +----------------------+
| IDA Pro Plugin        | <--------------------> | Python Broker         | <--------------------> | WinDbg Extension DLL  |
| Python / IDAPython    |                         | Session + Protocol    |                         | C-first implementation|
+----------------------+                         +----------------------+                         +----------------------+
```

### Responsibilities

#### IDA plugin

- Extract Hex-Rays variables.
- Track the current IDA function and decompiler view.
- Map static addresses to runtime addresses using module base information.
- Decide which variables are supported.
- Render live variable values in a separate table/view first.
- Later, optionally add pseudocode overlays.

#### Python broker

- Accept TCP connections from IDA and WinDbg.
- Route JSONL messages.
- Track session state.
- Correlate requests/responses by message id.
- Handle stale responses.
- Maintain last known PC and module mapping.
- Keep protocol versioning and logging centralized.

#### WinDbg extension DLL

- Connect to the broker.
- Send current PC/module/base information.
- Perform debugger actions on explicit commands only:
  - step
  - read register
  - read memory
  - query current PC
- Return JSON responses.
- Avoid decompiler logic.
- Avoid complex state machines.

## Default runtime flow

The default user experience should be one command from the WinDbg side, followed by an automatic live refresh:

```text
WinDbg command: !dvs_pc or !dvs_step
    -> WinDbg sends pc_update
    -> IDA maps runtime PC to IDA EA
    -> IDA builds a live request plan for the mapped function
    -> IDA sends reg_request and/or mem_request
    -> WinDbg answers with reg_response and/or mem_response
    -> IDA updates the Live Variables view
```

This should feel synchronous to the user, but the protocol should stay message-based and correlation-safe internally.

## v1 success criteria

The first useful version is successful when:

1. WinDbg can connect to the broker.
2. IDA can connect to the broker.
3. `!dvs_pc` sends runtime PC to IDA.
4. IDA maps runtime PC to IDA EA and jumps there.
5. For a supported function entry, IDA can request argument values.
6. WinDbg returns register/stack values.
7. IDA displays those values as fresh/stale/unavailable.
8. Stepping invalidates entry-only values instead of falsely showing them as fresh.
9. A single `!dvs_pc` or `!dvs_step` can trigger the full PC-map-live-refresh cycle.

