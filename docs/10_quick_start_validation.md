# Quick-Start Validation

This smoke test verifies the v0.1.0-research transport, PC sync, argument
recovery, stale transition, and one supported local when the sample permits it.

## User-Mode Smoke Test

1. Build the WinDbg extension as described in `docs/09_installation.md`.
2. Build `samples/vvar_probe/` from an x64 Native Tools Command Prompt:

   ```bat
   cd samples\vvar_probe
   build.bat
   ```

3. Load `samples\vvar_probe\build\vvar_probe.exe` and PDB in IDA Pro 9.3.
4. Start the broker:

   ```bash
   python3 broker/dayvar_broker.py --host 172.28.70.90 --port 9100 --verbose
   ```

5. Load `ida_plugin/dayvar_plugin.py` in IDA and connect to:

   ```text
   172.28.70.90:9100
   ```

6. In WinDbg, load and connect the extension:

   ```text
   .load C:\Users\Mehrshad\source\repos\dynvar-sync-version2\windbg_ext\build\dayvar.dll
   !dvs_connect 172.28.70.90 9100
   ```

7. Stop at a function entry with known Windows x64 arguments, then run:

   ```text
   !dvs_pc
   ```

   Expected:

   - broker routes `pc_update` and `ida_pc_mapped`;
   - IDA jumps to the mapped EA;
   - the Live Variables table lists arguments;
   - supported entry arguments become exact current values;
   - register/memory request and response messages preserve `pc_seq` and
     request ids.

8. Perform one asynchronous step:

   ```text
   !dvs_step p 1
   ```

   Expected:

   - WinDbg sends `pc_update(auto_live=true, reason=dvs_step)` after the target
     stops;
   - IDA maps the post-step PC;
   - `!dvs_pc` run immediately afterward reports the same stopped PC/module;
   - prior entry-argument values are shown only as stale / last observed when
     the new PC is no longer exact function entry.

9. Validate one supported register-backed local where `vvar_probe` and
   Hex-Rays materialization permit it:

   ```text
   bp vvar_probe!vvar_register_before_def
   g
   !dvs_pc
   !dvs_step p 1
   ```

   Expected:

   - before the defining instruction, the local is unavailable or not yet
     defined;
   - after the step, a structurally proven `r8d`-backed row may become an exact
     current value;
   - if the compiler/decompiler optimizes the row away or leaves it ambiguous,
     unavailable is the correct result.

## Kernel-Mode Notes

Kernel smoke testing uses the same broker, IDA plugin, and WinDbg extension.
Use a kernel function with known argument state, for example:

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
- After `!dvs_step p 1`, the post-step PC should match WinDbg's stopped PC
  such as `nt!NtCreateFile+0x7`, depending on the current binary.
- Entry arguments away from entry become stale / last observed.

Kernel validation still depends on matching symbols, module base, loaded IDB,
and DbgEng context. Do not treat unavailable locals as failure unless the row is
within the documented supported subset and the required proof exists.
