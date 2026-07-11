# IDA Plugin

IDAPython plugin for the current DayVarSync auto-live flow.

Responsibilities:

- Connect to the Python broker.
- Receive `pc_update` messages from WinDbg through the broker.
- Map runtime PCs to IDA EAs.
- Jump IDA to the mapped EA.
- Enumerate Hex-Rays local variables and arguments.
- Build an exact-entry Windows x64 argument request plan.
- Rebuild a conservative non-argument lvar recovery plan at every mapped PC.
- Request only low-level register and memory reads from WinDbg.
- Display variables and runtime values in the Live Variables table.
- Mark late or outdated values as stale or unavailable.

## Current Behavior

Load or run `dayvar_plugin.py` in IDA. The plugin registers these actions under
`Edit/DayVarSync`:

- `DayVarSync: Connect`
- `DayVarSync: Disconnect`
- `DayVarSync: Status`
- `DayVarSync: Show Live Variables`

`Connect` prompts for a broker `host:port` and defaults to:

```text
172.28.70.90:9100
```

The connection runs in a background socket thread so the IDA UI does not block
when the broker is unavailable. Incoming messages are marshalled back onto the
IDA UI thread before using IDA APIs.

For each `pc_update(auto_live=true)`, IDA maps:

```text
ida_ea = idaapi.get_imagebase() + (runtime_pc - runtime_module_base)
```

Then it jumps to `ida_ea`, sends `ida_pc_mapped`, finds the current IDA
function, and decompiles it with Hex-Rays. The plugin enumerates `cfunc.lvars`
and records:

```text
name, type string, size, is_arg, arg_index, Hex-Rays location metadata,
function start EA
```

Both argument-looking `a*` variables and generated `v*` variables are listed.
Argument handling remains in `dynvar_core.py`; `v_variable_recovery.py` owns a
separate evidence model, history, and `v-reg-*`/`v-mem-*` request namespace.
The recovery layer records lvar index, type/width, printed location, function
and current EAs, candidate storage, source definition EA, status/confidence,
and last successful value/`pc_seq` for every non-argument lvar.

## First Supported Local/`v*` Subset

Recovery uses the already-decompiled `cfunc.mba` at `MMAT_LVARS`, where
`mop_l.l.idx` identifies the exact Hex-Rays lvar. At the debugger's
pre-instruction PC, candidate-specific dataflow follows `mblock_t` predecessor
edges to find whole definitions and accepts only one effective definition
covering every path. Future-use discovery is a separate successor traversal:
one use before redefinition is sufficient, including a use in another block.
Partial/overlapping definitions, undefined paths, ambiguous predecessor
definitions, malformed CFGs, and unresolved loops remain unavailable. Ctree
variable/constant facts remain only supporting checks.

Supported classes are:

- One physical x64 GPR location: `rax` through `r15`, including supported
  8/16/32-bit aliases. IDA must structurally report `is_reg1()`; printed text
  alone is ignored. The plugin requests the full register and masks/shifts the
  value to the proven lvar width. A separate native `ida_gdl.FlowChart` walk
  verifies that every path from the selected definition to the current PC is
  free of calls, decode gaps, and overlapping physical-register writes. x64
  32-bit writes zero-extend, so an `r12d` definition reads full `r12` and masks
  its low 32 bits. Result:

  ```text
  fresh / exact_register_location
  ```

- One structural, non-aliased stack lvar of exactly 1, 2, 4, or 8 bytes. IDA
  SP analysis must be complete and non-fuzzy. The plugin converts the
  decompiler stack offset to a current-RSP-relative offset, requests `rsp`,
  then reads exactly the lvar width and decodes it little-endian. Result:

  ```text
  fresh / exact_stack_location
  ```

- A direct whole-lvar `m_mov` from `mop_n` that is the live reaching
  definition. It is rendered without a debugger read when the native
  definition is also immediate (or no exact physical register is present).
  A structural register location with a non-immediate native definition uses
  the register proof instead, even if Hex-Rays folded its microcode source to
  a number. Result:

  ```text
  fresh / exact_constant
  ```

If current proof disappears after a successful read, the previous value is
preserved only as:

```text
status = stale
confidence = stale_runtime_value
```

No response can update a row unless `pc_seq`, optional `runtime_pc`,
`request_id`, response kind, and (for memory) expected address/size match the
current v-recovery plan.

At exact function entry only, the plugin maps Windows x64 arguments:

```text
arg0 -> rcx
arg1 -> rdx
arg2 -> r8
arg3 -> r9
arg4+ -> [rsp + 0x28 + 8 * (arg_index - 4)]
```

The register request is built from the arguments that exist in the current
Hex-Rays lvar list. `rsp` is requested only when stack arguments are present.
After a matching `reg_response`, the plugin sends one `mem_request` for each
needed stack argument.

If the mapped PC is not the function start EA, old entry values are preserved
only as `stale`; otherwise argument rows remain `unavailable`.

Argument responses continue to use their existing IDs and behavior. V-recovery
responses are routed only to their reserved `v-` IDs, so recovery cannot clear
or consume an entry-argument request.

Value display is normalized in the Live Variables table:

- Register values are shown as canonical `0x...` hex.
- Stack argument memory reads decode 1, 2, 4, or 8 bytes as little-endian
  numeric hex.
- Raw memory bytes are kept in the row reason for stack reads.
- The existing table columns remain, with `LvarIndex`, `Type`, `Source EA`,
  `Storage`, and `Last Update PC` appended.

## Manual Test

Start the broker in WSL:

```bash
python3 broker/dayvar_broker.py --host 172.28.70.90 --port 9100 --verbose
```

In IDA:

```text
Load ida_plugin/dayvar_plugin.py
DayVarSync -> Connect
Open/decompile a function near the synced PC
```

In WinDbg:

```text
.load C:\Users\Mehrshad\source\repos\dynvar-sync-version2\windbg_ext\build\dayvar.dll
!dvs_connect 172.28.70.90 9100
!dvs_pc
!dvs_step p 1
```

Expected baseline broker flow at an argument-bearing function entry:

```text
pc_update
ida_pc_mapped
reg_request
reg_response
mem_request
mem_response
```

Proven locals may add one `v-reg-*` request/response and exact-width
`v-mem-*` requests. Away from entry, those local requests may occur even when
the argument planner correctly sends no entry request.

Expected IDA behavior:

- IDA jumps to the mapped EA.
- `DayVarSync Live Variables` lists Hex-Rays variables.
- Supported entry arguments show `fresh/exact_entry`.
- After stepping away from entry in the same function, preserved entry values
  become `stale/stale_entry_value`.
- A proven local may become fresh with one of the three exact recovery
  confidences above.
- Unsupported/ambiguous locals remain unavailable with a concrete reason, or
  retain only a stale last-success value.
- IDA output includes `v-candidate`, `v-recovery`, and `v-request` diagnostics.
- CFG diagnostics include `v-cfg-point`, `v-reaching-def`,
  `v-cross-block-live`, and `v-storage-valid` before the final recovery and
  request lines.

## Limitations

The IDA plugin still does not promise universal local recovery. Supported
cross-block work is limited to a unique whole-lvar reaching definition plus a
provably unchanged x64 GPR. Unsupported cases include ambiguous/undefined
reaching paths, partial or overlapping definitions, native decode gaps,
register clobbers or calls, unsupported loop states, cross-block stack
definitions, scattered or multi-register locations, XMM/vector/FPU locations,
aliased or address-taken stack locals, fuzzy SP state, inlined-variable
ambiguity, and expression-only/optimized-away values. These remain unavailable
rather than being inferred from printed locations.

If decompilation, ctree traversal, microcode access, or instruction/SP analysis
fails, the plugin logs the failure and leaves affected local rows unavailable.
PC mapping/jump, stepping, argument planning, the socket loop, and the Live
Variables view continue operating. Pseudocode overlays are not implemented.
