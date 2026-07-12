# vvar Probe

This x64 sample provides exact machine-code landmarks for the first local/
`v*` recovery milestone. The C harness also contains `noinline` volatile local
probes. Hex-Rays names and lvar indexes can vary, so validate a row by function
EA, lvar index, Source EA, and Storage rather than assuming a name such as
`v6`.

## Build

Open an **x64 Native Tools Command Prompt for Visual Studio**, change to this
directory, and run:

```cmd
build.bat
```

The result is `build\vvar_probe.exe` with CodeView/PDB data. `/O2` allows a
real register lifetime, while the MASM functions make definition and reuse
instructions deterministic. ASLR remains enabled so the normal module-relative
PC mapping is exercised.

## Exported Test Points

The debugger PC is before the instruction at which it stops. Each `*_before_*`
symbol is on a defining/reusing instruction; each following symbol is exactly
after that instruction.

```text
vvar_register_before_def    lea r8d, [rcx+2]
vvar_register_live          retained use immediately after def; expected value 0x42
vvar_register_before_reuse  mov r8d, 0xA5A5A5A5
vvar_register_reused        first PC after reuse

vvar_stack_before_def       mov [rsp+0x20], rcx
vvar_stack_live             retained stack use immediately after def

vvar_constant_before_def    mov dword ptr [rsp+0x20], 2
vvar_constant_live          retained constant-local use after the definition
```

The fixed machine locations do not force Hex-Rays to materialize a particular
local: it may propagate a simple expression completely. Such a row is not a
failed recovery test because no corresponding lvar exists. Use whichever of
the MASM or C `noinline` probes produces a real non-argument lvar in the IDB,
and leave propagated/ambiguous rows unavailable.

## IDA/WinDbg Procedure

1. Load `build\vvar_probe.exe` and its PDB in IDA, decompile the three assembly
   probe functions, and connect the IDA plugin.
2. Start the broker and connect the WinDbg extension as documented in
   [`docs/09_installation.md`](../../docs/09_installation.md).
3. For the register case:

   ```text
   bp vvar_probe!vvar_register_before_def
   g
   !dvs_pc
   !dvs_step p 1
   ```

   At `before_def`, the r8-backed local must be unavailable. At
   `vvar_register_live`, a proven row may become `0x42 / fresh /
   exact_register_location`; the request must name full `r8`, even when the
   lvar is `r8d`. Continue to `vvar_register_reused`; the original value may
   remain only as `stale/stale_runtime_value`.

4. Repeat with `vvar_stack_before_def`. After one step, a proven stack row at
   `vvar_stack_live` should request `rsp`, resolve the concrete slot, request
   exactly 8 bytes, decode `0x8877665544332211`, and become
   `fresh/exact_stack_location`.
5. Repeat with `vvar_constant_before_def`. After one step, a proven constant
   row at `vvar_constant_live` should become `0x2/fresh/exact_constant` without
   a register or memory request for that candidate.
6. Confirm every ambiguous/undefined cross-block, cross-block stack,
   scattered, or optimized-away case remains unavailable. A unique,
   storage-valid cross-block register case may send one full-register request.
   Re-sync or step again before allowing any old response to arrive; its old
   `pc_seq` must be rejected.

Depending on breakpoint handling, use `r rip` and the exported symbol names to
confirm the stopped PC before comparing a transition.
