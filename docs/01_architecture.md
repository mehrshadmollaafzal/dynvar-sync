# Architecture

`dynvar-sync` uses a broker-centered design:

```text
IDA Plugin <-> Python Broker <-> WinDbg Extension DLL
```

The broker isolates the IDA plugin from the WinDbg extension, centralizes
transport routing, and lets both clients reconnect independently.

## Component Responsibilities

### IDA Plugin

- Owns static semantics and Hex-Rays interpretation.
- Extracts function arguments and other decompiler variables.
- Maps runtime PCs to IDA EAs.
- Owns pending request state and semantic `pc_seq` / `runtime_pc` validation.
- Classifies variables as exact, stale, unavailable, ambiguous, or unsupported.
- Owns recovery confidence, variable history, and rejection of old responses
  for current rows.
- Builds live request plans after PC updates.
- Displays values in a separate Live Variables view first.

### Python Broker

- Accepts JSONL/TCP clients.
- Registers active clients and replaces an old client when a role reconnects.
- Validates message envelopes.
- Routes messages between IDA and WinDbg.
- Preserves correlation fields such as `pc_seq`, `runtime_pc`, and
  `request_id`.
- Logs transport-level message type, id, role, and routing decision.

The broker does not decide whether a variable value is semantically fresh or
stale. IDA is authoritative for variable state.

### WinDbg Extension DLL

- Owns runtime reads and debugger actions.
- Sends current PC, module, runtime base, and `pc_seq`.
- Reads registers and memory only on explicit requests.
- Executes debugger stepping commands.
- Runs bounded receive pumps after `!dvs_pc` and `!dvs_step`.

## State Ownership

IDA owns variable meaning, pending requests, semantic response validation,
fresh/stale/unavailable decisions, confidence, and variable history. WinDbg
owns low-level runtime facts: current PC, module/base information, register
reads, memory reads, stepping, and bounded request pumping. The broker owns
TCP/JSONL transport, client registration, envelope validation, routing,
transport-level logging, and active client replacement.

WinDbg must never guess what a Hex-Rays variable means. It should only answer
questions such as "what is RCX?" or "what bytes are at this address?"
