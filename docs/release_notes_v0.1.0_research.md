# DayVarSync v0.1.0-research Release Notes

DayVarSync v0.1.0-research is a best-effort, confidence-aware research
prototype that synchronizes WinDbg runtime state with IDA Pro and recovers only
Hex-Rays variables whose runtime values can be structurally proven.

It is not a source-level debugger and does not claim recovery of all Hex-Rays
lvars.

## What Is Complete For This Release

- Transport and synchronization prototype:
  IDA Plugin <-> Python Broker <-> WinDbg Extension.
- WinDbg PC/module/base reporting and bounded register/memory request pumping.
- Asynchronous `!dvs_step p|t [count]` with post-step `pc_update`.
- Exact-entry Windows x64 argument recovery for the documented ABI scope.
- Best-effort scalar local recovery for structurally proven register-backed,
  narrow stack-backed, and constant lvars.
- Stale / last observed handling when a previous exact value is no longer
  valid for the current PC.
- Fail-closed behavior for unsupported, ambiguous, unavailable, and
  optimized-away values.
- Diagnostic levels and Live Variables filters for practical interactive use.

## Support Boundary

Supported local recovery remains intentionally narrow:

- One structural x64 GPR-backed lvar with a unique reaching definition,
  reachable use, and native storage proof.
- One structural, non-aliased stack lvar of width 1, 2, 4, or 8 bytes when
  IDA SP/frame state and same-native-block storage proof are reliable.
- One exact live constant definition.

All other cases remain unavailable unless the prototype can prove them.

## Expected Unsupported Results

Unavailable or unsupported rows are expected for:

- optimized-away variables;
- ambiguous reaching definitions;
- unresolved native or microcode program points;
- unresolved or fuzzy stack locations;
- address-taken or aliased locals;
- scattered variables;
- XMM/SIMD/FPU values;
- aggregates and unsupported widths;
- values requiring execution history after storage overwrite.

## Required Manual Sign-Off

Before treating a checkout as release-ready, run the checklist in
`docs/08_release_checklist.md` and the smoke tests in
`docs/10_quick_start_validation.md`.
