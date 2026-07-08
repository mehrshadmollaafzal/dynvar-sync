# Implementation Roadmap

## Phase 0 — Repository and docs foundation

Goal: create a clean structure before coding features.

Tasks:

- Create repository folders.
- Add `docs/00_index.md`.
- Add architecture/protocol/variable model docs.
- Add minimal README.
- Add build notes for IDA, broker, and WinDbg extension.

Acceptance:

- Project layout is stable.
- Docs explain how the system is intended to work.

## Phase 1 — Broker MVP

Goal: route JSONL messages between clients.

Tasks:

- Implement TCP server.
- Support multiple clients but only one active IDA and one active WinDbg initially.
- Implement `hello` / `hello_ack`.
- Implement message logging.
- Implement forwarding by message type.

Acceptance:

- A fake IDA client and fake WinDbg client can connect.
- Messages are forwarded correctly.

## Phase 2 — WinDbg extension connection + PC sync

Goal: send current PC from WinDbg to broker.

Tasks:

- Implement `!dvs_connect`.
- Implement `!dvs_disconnect`.
- Implement `!dvs_pc`.
- Read current RIP.
- Resolve current module name and runtime module base.
- Send `pc_update`.

Acceptance:

- Broker receives current PC and module info.
- Fake IDA client receives forwarded `pc_update`.

## Phase 3 — IDA plugin connection + PC mapping

Goal: IDA receives runtime PC and jumps to mapped EA.

Tasks:

- Implement IDA protocol client.
- Receive `pc_update`.
- Track IDA imagebase.
- Compute mapped EA:

```text
ida_ea = ida_imagebase + (runtime_pc - runtime_module_base)
```

- Jump to EA.
- Display mapping status in output window.

Acceptance:

- `!dvs_pc` in WinDbg moves IDA to the correct function/instruction.

## Phase 4 — Register request/response

Goal: IDA can request WinDbg register values.

Tasks:

- Add `reg_request` in IDA.
- Add `reg_response` in WinDbg.
- Add broker forwarding.
- Preserve `pc_seq` and `request_id`.
- Add timeout/stale handling in IDA.

Acceptance:

- IDA can display RCX/RDX/R8/R9 values returned by WinDbg.
- A response from an older `pc_seq` cannot update the UI as fresh.

## Phase 4A — Auto live refresh after PC update

Goal: one WinDbg command can trigger PC sync and immediate live variable refresh.

Tasks:

- Add `pc_seq` to `pc_update`.
- Add `auto_live` flag to `pc_update`.
- After IDA maps the PC, send `ida_pc_mapped`.
- IDA builds an internal live request plan.
- IDA automatically sends `reg_request` for required registers.
- WinDbg implements a short bounded pump after `!dvs_pc`.
- WinDbg answers immediate `reg_request` messages during that same command.
- IDA applies responses only when `pc_seq` matches current PC.

Acceptance:

- User runs only `!dvs_pc`.
- IDA jumps to mapped EA.
- IDA sends register requests automatically.
- WinDbg returns register values without requiring a separate manual `!dvs_poll` in the normal case.
- IDA updates the Live Variables table.
- No WinDbg hang if IDA does not respond.

## Phase 5 — Hex-Rays variable extraction

Goal: extract and classify variables.

Tasks:

- Use IDAPython/Hex-Rays APIs to enumerate lvars.
- Identify function arguments.
- Determine arg index.
- Determine size.
- Classify:
  - supported register arg
  - supported stack arg
  - unsupported local/temp

Acceptance:

- IDA Live Variables view shows variables with status `unavailable` or supported locations.
- No runtime value is guessed.

## Phase 6 — Function entry argument values

Goal: show exact argument values at function entry.

Tasks:

- Detect when current PC maps to function start.
- For args 0..3, request RCX/RDX/R8/R9.
- For args 4+, request `[rsp + 0x28 + 8 * (arg_index - 4)]`.
- Add entry snapshot model.
- Display fresh values.

Acceptance:

- At function entry, supported args show `fresh/exact_entry`.

## Phase 7 — Staleness hardening

Goal: avoid misleading values after stepping.

Tasks:

- Add `pc_seq` and `runtime_pc` to requests.
- Ignore late responses for old `pc_seq` / old PC.
- After stepping inside same function, mark entry arg values stale.
- If no prior entry snapshot exists, mark args unavailable.

Acceptance:

- No old response marks a variable fresh after PC changed.
- Entry values remain visible but clearly stale.

## Phase 8 — Memory reads and EA watches

Goal: support explicit memory watches.

Tasks:

- Add `mem_request` / `mem_response`.
- Add IDA command: add EA watch.
- Map IDA EA to runtime address.
- Read bytes from WinDbg.
- Display value as hex.

Acceptance:

- User can watch bytes at selected IDA EA.

## Phase 9 — Step integration

Goal: IDA can request stepping through WinDbg.

Tasks:

- Add `step_request` / `step_response`.
- Implement `!dvs_poll` to process broker requests.
- Implement `!dvs_step p|t count` directly in WinDbg.
- After step, send `pc_update(auto_live=true, reason=dvs_step)` with a new `pc_seq`.
- Run the same bounded command pump used by `!dvs_pc`.
- Refresh IDA view.

Acceptance:

- Step in WinDbg updates IDA PC and variable statuses.

## Phase 10 — Quality pass

Goal: stabilize before adding advanced variable recovery.

Tasks:

- Add smoke tests.
- Add fake clients.
- Add protocol examples.
- Add troubleshooting docs.
- Add log toggles.
- Review for blocking socket operations.
- Review stale-state handling.

Acceptance:

- Basic workflow is repeatable and documented.

## Later phases

Only after v1 is reliable:

- Better stack local support.
- Register lifetime analysis.
- Pseudocode overlays.
- Type-aware value rendering.
- Pointer dereference preview.
- Struct field display.
- Multiple module support.
- Multiple IDA database support.

