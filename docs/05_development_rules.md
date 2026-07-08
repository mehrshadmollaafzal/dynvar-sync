# Development Rules

Project constraints:

- Target: Windows x64 only.
- IDA: IDA Pro 9.3.
- Debugger: WinDbg Preview.
- IDA plugin: Python / IDAPython.
- Broker: Python.
- WinDbg extension: C-first.
- JSONL over TCP for protocol messages.
- Keep dependencies minimal.

Coding rules:

- Prefer simple readable code.
- Keep modules small.
- Do not silently swallow errors.
- Preserve partial JSONL lines across socket reads.
- Never assume one TCP receive equals one full message.
- Do not block WinDbg forever.
- Update docs when behavior changes.

Correctness rules:

- IDA owns Hex-Rays variable interpretation.
- WinDbg answers only low-level runtime requests.
- Do not mutate decompiled C text in v1.
- Use a separate Live Variables view first.
- Never show guessed values as fresh.
- Unsupported Hex-Rays temporaries must be unavailable, not guessed.
- Late responses for older PCs or older `pc_seq` values must be ignored or
  marked stale.
