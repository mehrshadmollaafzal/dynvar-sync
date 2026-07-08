# Architecture

## Design choice

Use a **Broker-centered architecture** instead of connecting IDA and WinDbg directly.

Reason:

- IDA plugin development is easier in Python.
- WinDbg extension code should remain C-first and minimal.
- The broker can own protocol routing, state, stale-response filtering, and logs.
- Both sides can reconnect independently.
- Future clients can be added without rewriting the WinDbg extension.

## Component diagram

```text
                 ┌──────────────────────────────────────┐
                 │              Broker                  │
                 │            Python process             │
                 │                                      │
                 │ - TCP server                          │
                 │ - JSONL message router                │
                 │ - request/response correlation         │
                 │ - session state                       │
                 │ - module mapping cache                │
                 │ - stale response filtering            │
                 │ - structured logs                     │
                 └───────────────┬──────────────────────┘
                                 │
              ┌──────────────────┴──────────────────┐
              │                                     │
              ▼                                     ▼
┌────────────────────────────┐       ┌────────────────────────────┐
│ IDA Pro Plugin             │       │ WinDbg Extension DLL        │
│ Python / IDAPython         │       │ C-first                     │
│                            │       │                            │
│ - Hex-Rays variable scan   │       │ - connect/disconnect        │
│ - current function context │       │ - current PC                │
│ - supported variable model │       │ - module/base lookup        │
│ - IDA EA/runtime mapping   │       │ - register reads            │
│ - live variable table      │       │ - memory reads              │
│ - UI refresh               │       │ - stepping commands         │
└────────────────────────────┘       └────────────────────────────┘
```

## Suggested repository layout

```text
dayvar-sync-version2/
├── broker/
│   ├── dayvar_broker.py
│   ├── protocol.py
│   ├── sessions.py
│   └── README.md
│
├── ida_plugin/
│   ├── dayvar_plugin.py
│   ├── dynvar_core.py
│   ├── hexrays_variables.py
│   ├── address_mapping.py
│   ├── live_variables_view.py
│   ├── protocol_client.py
│   └── README.md
│
├── windbg_ext/
│   ├── dayvar.c
│   ├── socket_client.c
│   ├── socket_client.h
│   ├── json_writer.c
│   ├── json_writer.h
│   ├── dbgeng_ops.c
│   ├── dbgeng_ops.h
│   ├── dayvar.def
│   ├── build.bat
│   └── README.md
│
├── samples/
│   ├── ntqsi_probe/
│   ├── ntcreatefile_probe/
│   └── README.md
│
├── docs/
│   ├── 00_index.md
│   ├── 01_architecture.md
│   ├── 02_protocol.md
│   ├── 03_variable_model.md
│   ├── 04_windbg_extension.md
│   ├── 05_ida_plugin.md
│   ├── 06_testing.md
│   └── 07_limitations.md
│
├── tools/
│   ├── build_windbg_ext.bat
│   └── smoke_test.py
│
└── README.md
```

## Runtime data flow

### Default PC + live refresh cycle

`!dvs_pc` and `!dvs_step` should both support automatic refresh. The user issues one command in WinDbg, but the protocol performs a short multi-message cycle.

```text
WinDbg command: !dvs_pc or !dvs_step
        │
        ▼
WinDbg extension reads:
- current RIP
- current module name
- runtime module base
        │
        ▼
WinDbg sends pc_update with pc_seq
        │
        ▼
Broker forwards pc_update to IDA
        │
        ▼
IDA computes:
ida_ea = ida_imagebase + (runtime_pc - runtime_module_base)
        │
        ▼
IDA sends ida_pc_mapped
        │
        ▼
IDA builds a live request plan for the mapped function
        │
        ▼
IDA sends reg_request and/or mem_request with same pc_seq
        │
        ▼
Broker forwards requests to WinDbg
        │
        ▼
WinDbg reads registers/memory synchronously during polling/pump
        │
        ▼
WinDbg sends reg_response and/or mem_response with same pc_seq/request_id
        │
        ▼
IDA accepts only matching pc_seq/current_pc responses
        │
        ▼
IDA updates Live Variables view
```

This flow should feel like a single operation to the user. Internally it must remain asynchronous and correlation-safe.

### Why `pc_seq` is required

The user can step again before an older response arrives. Therefore every `pc_update` gets a monotonically increasing `pc_seq`. Every request and response derived from that PC must carry the same `pc_seq`. IDA must not mark a value as fresh unless the response belongs to the current `pc_seq`.

### Live request plan

After IDA maps a PC, IDA should create an internal plan, for example:

```text
function: NtQuerySystemInformation
runtime_pc: 0xffff...
ida_ea: 0x140...
pc_seq: 42
needed_registers: rcx, rdx, r8, r9, rsp
needed_memory_reads:
  - [rsp + 0x28], size=8, reason=arg4
  - [rsp + 0x30], size=8, reason=arg5
```

The plan is not necessarily a protocol message in v1. It can be an IDA-side internal object used to generate `reg_request` and `mem_request`.

## Why no direct Hex-Rays pseudocode mutation in v1

Directly editing pseudocode lines is fragile because Hex-Rays output is regenerated often and variable positions may shift. v1 should show values in a separate live variables table. This is easier to validate, debug, and maintain.

A later phase may add visual overlays or comments, but only after the variable model is stable.

## State ownership

### IDA owns static semantics

IDA should own:

- function boundaries
- Hex-Rays variables
- argument index
- stack variable offsets
- decompiler metadata
- supported/unsupported classification

### WinDbg owns runtime reads

WinDbg should own:

- current PC
- current module base
- register values
- memory bytes
- step execution

### Broker owns transport/session state

Broker should own:

- connected clients
- protocol version
- message routing
- request ids
- stale response rejection
- logs

## Important implementation rule

Never let WinDbg guess what a Hex-Rays variable means. WinDbg should only answer low-level questions:

- What is `rcx`?
- What is memory at `0xffff...`?
- What is the current RIP?

IDA should convert Hex-Rays variables into those low-level requests.

