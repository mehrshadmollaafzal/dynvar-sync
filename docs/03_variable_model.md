# Variable Model

Hex-Rays variables are not always real runtime storage locations. Arguments
and explicit memory objects can often be read reliably, but many locals named
like `v1` or `v160` are optimized expressions or have storage only during part
of a function.

Core rule:

```text
Unavailable is better than wrong.
```

Every row is one of:

- `fresh` - proven for the current PC and `pc_seq`.
- `stale` - previously proven, but not valid as a fresh current value.
- `unavailable` - no reliable current value exists.
- `error` - a proven runtime read was attempted and failed.

## Existing Argument Baseline

Argument handling remains separate from local/`v*` recovery. At exact Windows
x64 function entry:

```text
arg0 -> rcx
arg1 -> rdx
arg2 -> r8
arg3 -> r9
arg4 -> [rsp + 0x28]
arg5 -> [rsp + 0x30]
arg6 -> [rsp + 0x38]
```

The entry planner requests only registers needed by enumerated arguments and
requests `rsp` only for argument 4 or later. Stack arguments use:

```text
[rsp + 0x28 + 8 * (arg_index - 4)]
```

Argument register values are masked to a reported 1/2/4/8-byte width. Stack
arguments read that width when supported, otherwise the existing path reads
one 8-byte ABI slot. Successful entry reads are `fresh/exact_entry`. Away from
entry, captured values remain only `stale/stale_entry_value`.

## Per-PC Local/`v*` Model

Every successfully mapped `pc_update` rebuilds a model for each non-argument
entry in `cfunc.lvars`:

```text
lvar index
name
type and width
printed Hex-Rays location
function EA
current mapped EA
candidate storage kind and storage
source definition EA
recovery status, confidence, and reason
last successful value and pc_seq
last update runtime PC
```

The printed `lvar.location` is diagnostic text only. It can never authorize a
runtime read. Static evidence comes from the same cached `cfunc.mba` at
`MMAT_LVARS`, where `mop_l.l.idx` identifies the exact lvar.

The debugger PC denotes the next instruction to execute. A definition at the
current EA has not happened yet. If one native instruction maps to several
contiguous top-level microinstructions, the pre-instruction boundary is the
first of that run. Mappings split across blocks or non-contiguous runs remain
unavailable.

The recovery layer now separates two questions:

1. Which whole-lvar definition reaches the current pre-instruction point?
2. Is there any reachable future use of that value before a redefinition?

The first query scans the current microblock prefix backward and then follows
`mblock_t.pred()` edges. Each path stops at its nearest whole definition.
Exactly one effective `(block, instruction)` definition must cover every path;
different predecessor definitions, an undefined path, partial/overlapping
definitions, malformed CFG edges, or unresolved loop state remain unavailable.
A later definition in a successor or unrelated block does not invalidate the
current point because it does not reach it.

The second query scans the current suffix and then `mblock_t.succ()` edges. A
use before redefinition on any reachable path proves liveness; not every future
path must use the value. A redefinition kills only that path. Traversal uses
bounded block/program-point states, including a distinct full-block state when
a loop revisits the current block.

## Register-Backed Local/`v*`

The structural location must be exactly one `lvar.is_reg1()` x64 GPR:

```text
rax rbx rcx rdx rsi rdi rbp rsp r8-r15
```

The 8/16/32-bit aliases are supported, including `al`/`ah`, `sil`, and
`r8b`/`r8w`/`r8d` through `r15`. The recovery layer uses `get_reg1()`,
`get_mreg_name()`, and `mreg2reg()`; it does not parse the printed location as
evidence.

The defining native instruction must write the same physical register. A
separate native `ida_gdl.FlowChart` proof scans backward from the exact current
instruction along every predecessor path to the selected definition. Any
intervening overlapping subregister write, call, decode uncertainty, or path
that does not reach the definition rejects the candidate. IDA requests the
full register from WinDbg, then shifts a high-byte alias when needed and masks
to the lvar width. On x64, a 32-bit GPR write is modeled as zero-extending the
full register, so a proven `mov r12d, ...` is recovered by reading full `r12`
and extracting its low 32 bits:

```text
status = fresh
confidence = exact_register_location
```

## Stack-Backed Local/`v*`

A stack candidate must be structural, non-scattered, non-aliased, live by the
same reaching-definition proof, and exactly 1, 2, 4, or 8 bytes. This milestone
still requires its definition and current PC to share one native basic block.
IDA function SP analysis must be complete and must not have `FUNC_FUZZY_SP`.

The layer converts the decompiler offset with `mba.stkoff_vd2ida()`. With the
pre-instruction `spd = ida_frame.get_spd(func, current_ea)`, it derives a
current-RSP-relative offset using the frame return-address offset. Only then
does it request full `rsp`, resolve a concrete runtime address, and send an
exact-width `mem_request`. Bytes are decoded little-endian.

The defining native instruction must write the same IDA frame interval, and
no intervening register-relative write may overlap or ambiguously alias it.

On success:

```text
status = fresh
confidence = exact_stack_location
```

If SP/frame state or offset conversion is uncertain, no memory request is sent
and the reason is `unresolved_stack_location`.

## Exact Constant

A direct whole-lvar `m_mov` from `mop_n` can be used without a debugger read
when it is the live reaching definition. Ctree `cot_var`, assignment, and
number facts are collected as a supporting cross-check. The value is masked to
the lvar width:

```text
status = fresh
confidence = exact_constant
```

If Hex-Rays folds the microcode source to a number but the structural lvar is
register-backed and the defining native instruction obtains the value from a
register (for example `mov r12d, esi`), the exact physical-register proof takes
precedence. A genuine native immediate definition may still use the no-read
constant class.

## Unsupported and Ambiguous Cases

No value is guessed for:

- A printed register with no liveness/reaching-definition proof.
- Expression-only or optimized-away variables.
- Multiple, partial, overlapping, undefined-path, or synthetic-only
  definitions.
- Cross-block register paths with an unresolved native CFG, decode gap, call,
  clobber, or unsupported loop state.
- Cross-block stack definitions.
- Scattered, multi-register, XMM/vector, or FPU locations.
- Shared/overlapped variables and address-taken/aliased stack locals.
- Register locations across an unknown write, call, or instruction flow.
- Stack locations with missing/fuzzy SP state.
- Inlined-variable ambiguity.

Common reasons are:

```text
not_live_at_current_pc
ambiguous_reaching_definition
cross_block_liveness_unproven
storage_clobbered_before_current_pc
unresolved_native_program_point
ambiguous_register_location
unsupported_scattered_location
unresolved_stack_location
no_reaching_definition
microcode_unavailable
```

An unsupported row remains visible as unavailable. If it had a previous exact
success and current proof disappears, that value may remain only as:

```text
status = stale
confidence = stale_runtime_value
```

## Enumeration and Failure Isolation

For each mapped EA, the plugin:

1. Uses `ida_funcs.get_func()` and `ida_hexrays.decompile()`.
2. Enumerates `cfunc.lvars` and records stable lvar indexes.
3. Detects arguments through `cfunc.argidx`, `is_arg_var()`, prototype names,
   and the existing Windows x64 ABI-location fallback.
4. Runs the unchanged entry-argument planner.
5. Runs local/`v*` ctree, microcode, and instruction analysis independently.

If decompilation fails, `ida_pc_mapped` and the IDA jump have already happened.
If only recovery analysis fails, affected local rows become
`unavailable/unknown` with `microcode_unavailable`; PC synchronization,
arguments, stepping, socket processing, and the table continue.

## Correlation and Invalidation

Argument requests keep their existing IDs. Local recovery owns reserved IDs:

```text
v-reg-<pc_seq>-runtime
v-mem-<pc_seq>-<lvar_index>
```

A new PC clears every prior v pending request. A response is accepted only for
the current `pc_seq`, optional `runtime_pc`, request ID, and response kind.
Memory replies must also match the planned address and size. An old response
therefore cannot turn a stale/unavailable row fresh.

## Live Variables View

The existing columns remain and recovery metadata is appended:

```text
Name | Kind | ArgIndex | Size | Location | Value | Status | Confidence | Reason |
LvarIndex | Type | Source EA | Storage | Last Update PC
```

Pseudocode overlays remain out of scope.
