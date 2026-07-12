# Architecture Opinion and Risk Review

## Overall opinion

The project is valuable and realistic if v1 is scoped correctly.

The strongest part of the idea is extending PC synchronization into runtime decompiler context. For reverse engineering, seeing function argument values and selected memory values beside Hex-Rays variables can be very useful.

The biggest danger is trying to support every Hex-Rays variable too early. Many decompiler variables are not stable runtime objects. If the project guesses values for them, the tool will become misleading.

## Opinion on auto live refresh

The proposed behavior where `pc_update` immediately causes IDA to map the PC and request the required registers/memory is a good design. It makes the tool feel fast and natural because the user can run one WinDbg command and see IDA update both the current instruction and the live variable table.

The important detail is that it should be user-synchronous but protocol-asynchronous:

```text
Good: one command triggers a bounded message cycle
Bad: WinDbg blocks forever waiting for IDA
```

Use `pc_seq`, `request_id`, short timeouts, and stale-response rejection. With those rules, this behavior is worth making the default flow.

## Recommended strategy

Start with a narrow, correct tool:

1. PC sync.
2. Function entry arguments.
3. Stack arguments for arg5+.
4. Explicit memory watches.
5. Honest stale/unavailable states.

Then expand later.

## Main risks

### Risk 1 — Hex-Rays variables are not always runtime variables

`vXXX` values may be temporaries, optimized values, or expressions. Mapping them to runtime storage is not always possible.

Mitigation:

- Do not guess.
- Use clear status/confidence fields.
- Start with arguments and explicit watches.

### Risk 2 — Register values become stale after stepping

At function entry, RCX/RDX/R8/R9 are reliable for the first four arguments. After instructions execute, those registers may be reused.

Mitigation:

- Capture entry snapshot only at exact entry.
- Mark entry values stale after stepping.
- Never refresh them as fresh unless PC is back at a valid entry context.

### Risk 3 — WinDbg extension complexity

A complex WinDbg DLL is harder to debug and can hang the debugger.

Mitigation:

- Keep DLL low-level.
- Use C-first design.
- Use timeout-based socket reads.
- Put routing/state logic in Python broker.

### Risk 4 — UI complexity in IDA

Pseudocode overlays can become fragile.

Mitigation:

- Build a Live Variables table first.
- Add pseudocode overlay later only after the model is stable.

### Risk 5 — Auto-refresh can accidentally hang WinDbg

If `!dvs_pc` waits forever for IDA to reply, the debugger experience becomes bad.

Mitigation:

- Keep the auto-refresh pump bounded.
- Use short socket receive timeouts.
- Keep `!dvs_poll` as a manual fallback.
- Treat missing IDA responses as a non-fatal condition.

### Risk 6 — Protocol drift

If messages evolve without docs, Codex may break compatibility.

Mitigation:

- Keep `docs/02_protocol.md` updated.
- Use protocol version field.
- Add example messages for every message type.

## My recommended v1 boundary

v1 should not promise "live values for all decompiled variables".

v1 should promise:

```text
Live, confidence-tagged runtime values for supported Hex-Rays variables and explicit watches.
```

This wording is safer and more technically correct.

## Best project direction

Use the project as a reverse-engineering assistant, not as a perfect decompiler-runtime mapper.

A reliable tool that says:

```text
a1 = 0xffff...    fresh / exact_entry
v12 = unavailable / unsupported_variable
```

is much better than a flashy tool that shows wrong values.

## Suggested README wording

```text
dynvar-sync synchronizes IDA Pro and WinDbg Preview and displays confidence-tagged runtime values for supported Hex-Rays variables. The first version focuses on Windows x64 function arguments, stack arguments, explicit memory watches, and safe stale-state handling.
```
