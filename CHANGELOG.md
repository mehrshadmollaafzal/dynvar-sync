# Changelog

## dynvar-sync v0.1.0-research

Release identity:

```text
dynvar-sync v0.1.0-research
```

`dynvar-sync v0.1.0-research` is a best-effort, confidence-aware research
prototype that synchronizes WinDbg runtime state with IDA Pro and recovers only
Hex-Rays variables whose runtime values can be structurally proven.

### Added

- JSONL/TCP broker for one active IDA client and one active WinDbg client.
- C-first WinDbg extension commands:
  `!dvs_connect`, `!dvs_disconnect`, `!dvs_status`, `!dvs_pc`, `!dvs_poll`,
  and asynchronous `!dvs_step p|t [count]`.
- IDA Pro 9.3 plugin that maps WinDbg runtime PCs to IDA EAs, jumps to the
  mapped address, enumerates Hex-Rays lvars, and displays a Live Variables
  table.
- Exact-entry Windows x64 argument recovery for supported register and stack
  argument locations.
- Conservative scalar local recovery for the first supported subset:
  register-backed lvars, narrow stack-backed lvars, and exact constants.
- Stale/last-observed handling and response correlation by `pc_seq`,
  `runtime_pc`, and request id.
- Diagnostic levels: `quiet`, `normal`, `verbose`, and `trace`.
- Live Variables filters: All, Fresh, Recoverable, Arguments, Named locals,
  and Unavailable.
- Bounded local candidate selection for usability and performance.
- Deterministic `samples/vvar_probe/` manual validation sample.

### Limitations

- Not a source-level debugger.
- Does not guarantee recovery of every Hex-Rays lvar.
- Unsupported rows fail closed as unavailable, ambiguous, unsupported, or
  stale / last observed.
- No XMM/SIMD/FPU recovery, aggregate decoding, scattered-variable
  reconstruction, broad stack recovery, alias analysis, dynamic tracing, or
  source-level scope model.

### Validation Baseline

- Outside-IDA unit suite: 45 tests.
- Python compile check for `broker/*.py`, `ida_plugin/*.py`, and `samples/*.py`.
- WinDbg extension build is environment-dependent and must be validated in a
  Windows SDK or compatible MinGW-w64 environment.
