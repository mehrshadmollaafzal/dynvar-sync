# dynvar-sync v0.1.0-research Release Notes

`dynvar-sync v0.1.0-research` is a Windows x64 research prototype that links
WinDbg stopped-state facts to IDA Pro 9.3 and displays Hex-Rays variable
values only when the runtime value can be structurally proven.

It is best-effort, confidence-aware, fail-closed, and not a source-level
debugger.

## Highlights

- Localhost-first Windows setup for IDA, WinDbg, and the Python broker.
- Permanent multi-file IDA plugin installation under the user IDA plugin
  directory.
- WinDbg `!dvs_pc` and asynchronous `!dvs_step p|t [count]` synchronization.
- Exact-entry Windows x64 argument recovery.
- Partial scalar local recovery for structurally proven register-backed lvars,
  exact constants, and a narrow same-block stack-backed subset.
- Stale / last observed presentation when a previously exact value is no
  longer proven.
- Explicit unavailable/unsupported behavior for cases outside the research
  subset.

## Support Boundary

See [Research Prototype Status](07_research_prototype_status.md) for the
support matrix and detailed limitations.

Before release sign-off, run the maintainer checks in
[Release Checklist](05_release_checklist.md).
