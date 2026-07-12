# Changelog

## dynvar-sync v0.1.0-research

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
  register-backed lvars, exact constants, and a narrow same-block
  stack-backed subset.
- Stale/last-observed handling and response correlation by `pc_seq`,
  `runtime_pc`, and request id.
- Diagnostic levels: `quiet`, `normal`, `verbose`, and `trace`.
- Live Variables filters: All, Fresh, Recoverable, Arguments, Named locals,
  and Unavailable.
- Bounded local candidate selection for usability and performance.
- Deterministic `samples\vvar_probe\` manual validation sample.
- Windows localhost-first installation and quick-start documentation.
- Permanent multi-file IDA plugin installation workflow.

### Limitations

- Not a source-level debugger.
- Does not guarantee recovery of every Hex-Rays lvar.
- Unsupported rows fail closed as unavailable, ambiguous, unsupported, or
  stale / last observed.
- No XMM/SIMD/FPU recovery, aggregate decoding, scattered-variable
  reconstruction, broad stack recovery, alias analysis, dynamic tracing, or
  source-level scope model.
