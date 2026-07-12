# Research Prototype Status

This document defines the measured closure baseline for `dynvar-sync
v0.1.0-research`. `dynvar-sync` is a best-effort, confidence-aware runtime
variable recovery research prototype for IDA Pro 9.3, Hex-Rays, and WinDbg
Preview on Windows x64. It is not a source-level debugger and does not
guarantee recovery of every Hex-Rays lvar.

## Project Scope

`dynvar-sync` synchronizes a stopped WinDbg target with IDA, maps the runtime PC
to an IDA EA, enumerates Hex-Rays lvars, and shows confidence-tagged runtime
values in a separate Live Variables table. IDA owns all decompiler and variable
meaning. WinDbg only supplies low-level PC, register, memory, module, and
stepping facts. The Python broker only validates, logs, and routes JSONL
messages between one active IDA client and one active WinDbg client.

The current prototype proves that a small, explicit subset of runtime values
can be recovered without blindly trusting printed Hex-Rays locations. It does
not prove general source-level local-variable debugging for optimized binaries.

## Status Definitions

`exact` means the row is `fresh` for the current `pc_seq` and was produced by a
supported proof class such as `exact_entry`, `exact_register_location`,
`exact_stack_location`, or `exact_constant`.

`stale` means the value was exact at an earlier accepted PC, but the current PC
no longer has valid proof. Stale values are shown only with stale confidence
such as `stale_entry_value` or `stale_runtime_value`.

`unavailable` means the row is known but the prototype does not currently have
enough evidence for a fresh value. This includes ambiguous, not-live,
optimized-away, unsupported, or failed-analysis cases.

`unsupported` means the row or storage class is outside the implemented
research subset. Unsupported rows should remain unavailable rather than being
guessed.

## Support Matrix

| Area | Current support | Notes |
| --- | --- | --- |
| Broker/protocol | Supported baseline | JSONL/TCP envelope validation, one active IDA and WinDbg client, hello/ack, routing for PC, map, register, memory, and error messages. It preserves message fields but does not interpret variables or enforce all stale semantics itself. |
| WinDbg connection | Supported baseline | `!dvs_connect`, `!dvs_disconnect`, `!dvs_status`, `!dvs_poll`, socket JSONL send/receive, bounded command pump. |
| WinDbg PC and stepping | Supported baseline | `!dvs_pc` reads PC/module/base from one DbgEng context. `!dvs_step p|t [count]` is asynchronous, reuses the initiating command client context, waits for `DEBUG_STATUS_BREAK`, then sends a post-step `pc_update`. No `WaitForEvent` command path. |
| Runtime reads | Supported baseline | Full x64 GPR reads for `rax`..`r15` and `rip`; virtual memory reads up to the extension cap. No SIMD/vector register protocol. |
| PC/module mapping | Supported baseline | IDA maps `ida_ea = ida_imagebase + (runtime_pc - runtime_module_base)`. It assumes the reported module base corresponds to the open IDB image. Multi-module symbol-to-IDB selection is not solved. |
| Entry arguments | Supported baseline | At exact Windows x64 function entry, args 0..3 map to `rcx`, `rdx`, `r8`, `r9`; args 4+ map to `[rsp + 0x28 + 8 * (index - 4)]`. Away from entry, previous argument values become stale only. |
| Register-backed lvars | Partial | Supports one structural `is_reg1()` x64 GPR lvar of width 1, 2, 4, or 8 bytes, with one unique whole-lvar reaching definition and a future use before redefinition. Native CFG proof must show the physical register survives to the current pre-instruction PC. |
| Stack-backed lvars | Partial | Supports one structural, non-aliased stack lvar of width 1, 2, 4, or 8 bytes with reliable SP/frame state and a same-native-block stack write proof. Cross-block stack recovery remains unsupported. |
| Constants | Partial | Supports a live whole-lvar `m_mov mop_n -> mop_l` reaching definition. If the lvar is structurally register-backed and the native definition is not immediate, the register proof takes precedence. |
| Partial registers | Partial | IDA-side aliases such as `al`, `ah`, `eax`, `r8d`, and `r12d` are projected from full-register WinDbg reads and masked or shifted. x64 32-bit GPR zero-extension is modeled. Debugger-side subregister reads are not a protocol feature. |
| XMM/SIMD/FPU | Unsupported | No vector/FPU register protocol, storage proof, decoding, or UI value model. |
| Aggregates | Unsupported | Structs, arrays, split fields, and widths outside 1/2/4/8 bytes are not generally decoded. |
| Scattered variables | Unsupported | Multi-location and scattered Hex-Rays lvars remain unavailable. |
| Address-taken or aliased variables | Unsupported | Shared, overlapped, byref, aliasable, or unresolved stack locals remain unavailable. |
| Stale values | Supported baseline | Entry arguments and v-recovered locals preserve last exact values only as stale. Old `pc_seq`, mismatched `runtime_pc`, unexpected `request_id`, and mismatched memory address/size cannot become fresh. |
| Optimized-away values | Unsupported | If Hex-Rays does not materialize a usable lvar/storage/definition, no value is recovered. Expression-only values remain unavailable. |
| Diagnostics | Supported usability layer | Plugin diagnostics have one level setting: `quiet`, `normal`, `verbose`, or `trace`. Normal suppresses per-variable CFG noise; trace preserves full recovery diagnostics. |
| Live Variables filters | Supported usability layer | The table can show All, Fresh, Recoverable, Arguments, Named locals, or Unavailable rows without destroying underlying row state. |

## Demonstrated Working Behavior

The outside-IDA test suite demonstrates protocol/core state that can be tested
without IDA: exact entry argument requests, stack argument memory reads, stale
argument transitions, v-recovery request namespaces, old-`pc_seq` rejection,
register alias masking, little-endian exact-width memory decoding, constant
rows without debugger reads, fresh-to-stale local history, mapping-failure
invalidation, isolated analysis failures, diagnostic-level suppression, filter
predicates, active-filter preservation, bounded candidate selection, selection
cache invalidation, and prioritization of fresh/stale rows.

Synthetic CFG tests demonstrate the pure algorithms for current-block and
predecessor reaching definitions, successor-block future uses, ambiguous
predecessor definitions, undefined paths, redefinitions, overlapping
definitions, register clobbers, native predecessor storage survival, exact
pre-instruction semantics, and bounded loop traversal.

Manual documentation covers real WinDbg and IDA flows for `!dvs_pc`,
`!dvs_step`, entry arguments, and the `samples/vvar_probe` local recovery
probe. Those live IDA/WinDbg checks remain required because outside-IDA tests
cannot execute Hex-Rays SWIG objects, IDA microcode, IDA SP analysis, processor
module register-access APIs, or DbgEng.

## PsOpenProcess Observation

The current implementation is designed to handle the observed
`nt!PsOpenProcess` case:

```text
0x1406D3495  xor esi, esi
0x1406D3498  mov r12d, esi       ; Hex-Rays v10 = 0
0x1406D349B  mov [rsp+4Ch], esi  ; current pre-instruction PC
```

At `0x1406D349B`, the recovery layer should accept `v10` only if IDA reports a
structural `r12d` location, microcode has exactly one reaching whole definition
at `0x1406D3498`, a reachable future use exists before redefinition, and the
native CFG proves no call or overlapping `r12` write occurs before the current
PC. The debugger request must read full `r12` and extract the low 32 bits.

Expected live diagnostics include:

```text
v-reaching-def name=v10 def_ea=0x1406d3498 ... count=1 ...
v-cross-block-live name=v10 result=cross_block_use ...
v-storage-valid name=v10 storage=r12d result=valid ...
v-recovery name=v10 result=pending source=register:r12d ...
v-request pc_seq=<pc_seq> registers=['r12'] memory=[]
```

This document does not claim that every `PsOpenProcess` lvar is recoverable or
that this scenario has passed in every live IDA/WinDbg database. It defines the
implemented behavior and the expected manual validation target.

## Architectural Limitations

The prototype depends on final Hex-Rays microcode (`MMAT_LVARS`) retaining
usable `mop_l` definitions and uses. If Hex-Rays propagates a value away,
represents it as an expression, scatters it, aliases it, or emits ambiguous
storage, `dynvar-sync` must leave the row unavailable.

PC handling is pre-instruction. A definition at the current EA has not executed
yet. Recovery requires a unique top-level microcode run for the current native
EA; split, non-contiguous, or synthetic program points are rejected.

Register recovery is intentionally stricter than liveness alone. It requires
both a unique lvar reaching definition and a native physical-storage proof. Any
decode gap, unknown register-access result, call, clobber, malformed CFG edge,
or unsupported loop state rejects the fresh value.

Stack recovery remains much narrower than register recovery. It requires
reliable IDA SP/frame state and currently only proves the native stack write in
a same-native-block range.

The broker does not store variable state and does not know which response is
semantically stale. IDA-side request correlation and pending-request invalidation
are the authoritative stale-response controls.

The Live Variables view is a diagnostic table. Pseudocode overlays,
watch-window editing, expression evaluation, source stepping, and source-level
scope visualization are out of scope.

For usability, the IDA plugin may analyze only a bounded subset of local
candidates at a given PC. The selector prioritizes explicitly watched indexes,
previously fresh/stale rows, rows visible under the current filter, and a
rotating fallback set. This reduces normal interaction noise and cost, but it
means a newly recoverable non-prioritized local may become visible after a later
selection pass rather than on the first possible instruction.

## Known Implementation Gaps

The implementation has no XMM/SIMD/FPU value path, no aggregate decoder, no
general alias analysis, no scattered-location reconstruction, no cross-block
stack recovery, no multi-module IDB selection, and no source-language scope
model.

Outside-IDA tests use synthetic objects and pure helper functions. They are
good regression coverage for state machines and conservative CFG rules, but
they cannot prove exact behavior of real `ida_hexrays`, `ida_gdl`, `ida_ua`,
`ida_idp`, `ida_frame`, or DbgEng APIs.

## What The Prototype Proves

The branch proves that IDA and WinDbg can be connected through a simple broker,
that stopped PCs can drive automatic IDA refreshes, that exact-entry Windows
x64 arguments can be read without changing debugger protocol semantics, and
that a limited set of non-argument Hex-Rays lvars can be recovered with explicit
confidence when static proof and runtime reads agree.

It also proves the negative behavior needed for a research prototype: printed
locations alone do not authorize reads, stale responses are rejected, old exact
values are marked stale rather than fresh, and unsupported locals stay
unavailable.

## What It Does Not Prove

The branch does not prove universal Hex-Rays local recovery, correctness for
all compiler optimizations, recovery across arbitrary control flow, recovery of
optimized-away values, source-level debugging semantics, or complete parity
with native debugger local-variable engines.
