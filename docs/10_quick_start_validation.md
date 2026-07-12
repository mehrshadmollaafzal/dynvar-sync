# Quick Start

This Windows localhost workflow verifies that `dynvar-sync` can synchronize a
stopped WinDbg target with IDA and display proven runtime values.

If a value remains unavailable because Hex-Rays optimized it away or the
analysis cannot prove storage, that is expected fail-closed behavior.

## User-Mode Smoke Test

1. Build the WinDbg extension from an x64 Native Tools Command Prompt:

   ```cmd
   if not exist windbg_ext\build mkdir windbg_ext\build

   cl /nologo /LD /W4 /D_CRT_SECURE_NO_WARNINGS ^
     windbg_ext\dayvar.c ^
     windbg_ext\socket_client.c ^
     windbg_ext\json_writer.c ^
     windbg_ext\dbgeng_ops.c ^
     /Fe:windbg_ext\build\dayvar.dll ^
     /link /DEF:windbg_ext\dayvar.def Ws2_32.lib
   ```

2. Build the sample from an x64 Native Tools Command Prompt:

   ```cmd
   cd samples\vvar_probe
   build.bat
   ```

3. Install the IDA plugin as described in [Installation](09_installation.md),
   then restart IDA.

4. Open the matching sample executable and PDB in IDA:

   ```text
   samples\vvar_probe\build\vvar_probe.exe
   ```

5. Start the broker from the repository root:

   ```cmd
   py -3 .\broker\dayvar_broker.py --host 127.0.0.1 --port 9100 --verbose
   ```

6. In IDA, connect through:

   ```text
   Edit -> DayVarSync -> Connect
   127.0.0.1:9100
   ```

7. Open or attach `samples\vvar_probe\build\vvar_probe.exe` in WinDbg.

8. Load and connect the WinDbg extension:

   ```text
   .load C:\path\to\dynvar-sync\windbg_ext\build\dayvar.dll
   !dvs_connect 127.0.0.1 9100
   !dvs_status
   ```

9. Break at the register-backed sample landmark:

   ```text
   bp vvar_probe!vvar_register_before_def
   g
   !dvs_pc
   ```

   Expected:

   - the broker routes `pc_update` and `ida_pc_mapped`;
   - IDA jumps to the mapped EA;
   - the Live Variables table refreshes;
   - the candidate local is unavailable or not yet defined before the defining
     instruction.

10. Step once:

    ```text
    !dvs_step p 1
    ```

    Expected:

    - WinDbg sends `pc_update(auto_live=true, reason=dvs_step)` after the
      target stops;
    - IDA maps the post-step PC;
    - a structurally proven `r8d`-backed row may become an exact current value;
    - if Hex-Rays propagates the value away or leaves the row ambiguous,
      unavailable is the correct result.

11. Optional stack and constant checks use the documented sample symbols:

    ```text
    bp vvar_probe!vvar_stack_before_def
    bp vvar_probe!vvar_constant_before_def
    ```

    Step once from each breakpoint and inspect the Live Variables table. A
    narrow same-block stack-backed scalar may become exact only when reliable
    SP/frame and storage proof exists. A retained constant assignment may
    become exact without a debugger read.

## Kernel-Mode Notes

Kernel validation uses the same localhost broker, installed IDA plugin, and
WinDbg extension. A typical check is:

```text
bp nt!NtCreateFile
g
!dvs_pc
!dvs_step p 1
```

Expected:

- `!dvs_pc` maps the stopped kernel PC to the open IDA image when the module
  base corresponds to that IDB.
- At exact entry, supported Windows x64 arguments can become exact current
  values.
- After `!dvs_step p 1`, the post-step PC should match WinDbg's stopped PC.
- Entry arguments away from entry become stale / last observed.

Kernel validation depends on matching symbols, module base, loaded IDB, and
DbgEng context. Do not treat unavailable locals as failure unless the row is
inside the documented supported subset and the required proof exists.
