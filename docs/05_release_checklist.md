# v0.1.0-research Release Checklist

Release identity:

```text
dynvar-sync v0.1.0-research
```

Completion for this release means:

- transport and synchronization prototype complete;
- exact-entry argument recovery complete for the documented Windows x64 scope;
- best-effort supported scalar lvar recovery implemented;
- unsupported cases explicitly fail closed;
- full Hex-Rays lvar recovery is out of scope for v0.1.0-research.

## Maintainer Checks

- Confirm `VERSION` contains `v0.1.0-research`.
- Build `windbg_ext\build\dayvar.dll` with the Windows SDK / Visual Studio
  x64 Native Tools command documented in [Installation](06_installation.md).
- Install the IDA plugin by copying all `ida_plugin\*.py` files into the user
  IDA plugin directory and restarting IDA.
- Start the broker on `127.0.0.1:9100`.
- Connect IDA to `127.0.0.1:9100`.
- Connect WinDbg with `!dvs_connect 127.0.0.1 9100`.
- Run a kernel-mode smoke test when a matching kernel debugging environment is
  available.
- Exercise diagnostic levels: `quiet`, `normal`, `verbose`, and `trace`.
- Exercise Live Variables filters: All, Fresh, Recoverable, Arguments, Named
  locals, and Unavailable.
- Verify at least one supported v-variable recovery class where the sample and
  Hex-Rays materialization permit it.
- Verify expected unsupported rows remain unavailable, ambiguous, unsupported,
  optimized away / not materialized, or stale / last observed.
- Verify disconnect and reconnect from both IDA and WinDbg.
- Confirm `git status --short` has no generated binaries, Python caches, logs,
  or unexpected editor files.

## Required Manual Evidence

- Broker shows IDA and WinDbg hello/registration.
- `!dvs_pc` produces a mapped PC in IDA.
- Entry arguments at exact function entry become exact current values.
- One asynchronous step produces a post-step `pc_update` matching WinDbg's
  stopped PC.
- Entry arguments away from entry become stale / last observed.
- Old `pc_seq` responses do not become exact current values.
- Unsupported or ambiguous Hex-Rays lvars are not guessed.

## Release Blockers

Treat any of these as blockers:

- docs describe `dynvar-sync` as production-ready or as a source-level
  debugger;
- docs claim recovery of all Hex-Rays lvars;
- broker or WinDbg extension interprets Hex-Rays variables;
- unsupported values are displayed as exact current values;
- old `pc_seq` responses can update current rows;
- the documented Windows localhost setup cannot complete the smoke test.
