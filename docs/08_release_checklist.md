# v0.1.0-research Release Checklist

Release identity:

```text
DayVarSync v0.1.0-research
```

Completion for this release means:

- transport and synchronization prototype complete;
- exact-entry argument recovery complete for the documented Windows x64 scope;
- best-effort supported scalar lvar recovery implemented;
- unsupported cases explicitly fail closed;
- full Hex-Rays lvar recovery is out of scope for v0.1.0-research.

## Maintainer Checklist

- Start from a clean checkout.
- Confirm `VERSION` contains `v0.1.0-research`.
- Run the Python compile check:

  ```bash
  python3 -m py_compile broker/*.py ida_plugin/*.py samples/*.py
  ```

- Run the outside-IDA tests:

  ```bash
  python3 -m unittest discover -s samples -p "test_*.py" -v
  ```

- Run whitespace validation:

  ```bash
  git diff --check
  ```

- Build `windbg_ext/build/dayvar.dll` using the documented Windows SDK or
  MinGW-w64 command.
- Start the broker.
- Connect IDA.
- Connect WinDbg.
- Run the user-mode smoke test in `docs/10_quick_start_validation.md`.
- Run the kernel-mode smoke test notes in `docs/10_quick_start_validation.md`
  when a kernel debugging environment is available.
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

- source or docs describe DayVarSync as a source-level debugger;
- docs claim recovery of all Hex-Rays lvars;
- broker or WinDbg extension interprets Hex-Rays variables;
- unsupported values are displayed as exact current values;
- old `pc_seq` responses can update current rows;
- `ForCodex/` is modified;
- a release commit or tag is created before the maintainer explicitly requests
  it.
