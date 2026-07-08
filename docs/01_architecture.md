# Architecture

DayVar Sync uses a broker-centered design:

```text
IDA Plugin <-> Python Broker <-> WinDbg Extension DLL
```

The broker isolates the IDA plugin from the WinDbg extension, centralizes
protocol routing, and lets both clients reconnect independently.

## Component Responsibilities

### IDA Plugin

- Owns static semantics and Hex-Rays interpretation.
- Extracts function arguments and other decompiler variables.
- Maps runtime PCs to IDA EAs.
- Classifies variables as supported, unavailable, or unsupported.
- Builds live request plans after PC updates.
- Displays values in a separate Live Variables view first.

### Python Broker

- Accepts JSONL/TCP clients.
- Routes messages between IDA and WinDbg.
- Tracks sessions, protocol version, `pc_seq`, and request ids.
- Logs message type, id, role, and routing decision.
- Rejects or flags stale responses.

### WinDbg Extension DLL

- Owns runtime reads and debugger actions.
- Sends current PC, module, runtime base, and `pc_seq`.
- Reads registers and memory only on explicit requests.
- Executes debugger stepping commands.
- Runs bounded receive pumps after `!dvs_pc` and `!dvs_step`.

## State Ownership

IDA owns variable meaning. WinDbg owns low-level runtime facts. The broker owns
transport and session state.

WinDbg must never guess what a Hex-Rays variable means. It should only answer
questions such as "what is RCX?" or "what bytes are at this address?"
