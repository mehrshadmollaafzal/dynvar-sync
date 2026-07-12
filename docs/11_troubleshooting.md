# Troubleshooting

This page covers the documented Windows localhost setup only.

## Broker Is Not Listening

Start the broker from the repository root:

```cmd
py -3 .\broker\dayvar_broker.py --host 127.0.0.1 --port 9100 --verbose
```

Expected:

```text
[broker] listening on 127.0.0.1:9100
```

If the port is already in use, stop the existing broker or choose a different
port for all three components.

## IDA Cannot Connect

- Confirm the broker window is still running.
- Use `Edit -> DayVarSync -> Connect`.
- Enter `127.0.0.1:9100`.
- Check the broker log for `registered role=ida`.

## Plugin Menu Does Not Appear

The plugin is multi-file. Reinstall all Python modules:

```powershell
$IdaPlugins = "$env:APPDATA\Hex-Rays\IDA Pro\plugins"

New-Item -ItemType Directory -Force -Path $IdaPlugins | Out-Null

Copy-Item `
    .\ida_plugin\*.py `
    $IdaPlugins `
    -Force
```

Restart IDA and check for:

```text
Edit -> DayVarSync
```

## WinDbg Cannot Connect

In WinDbg:

```text
!dvs_connect 127.0.0.1 9100
!dvs_status
```

Confirm the broker log shows `registered role=windbg`.

## WinDbg Extension Load Failure

Build the extension from an x64 Native Tools Command Prompt:

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

Then load the built DLL:

```text
.load C:\path\to\dynvar-sync\windbg_ext\build\dayvar.dll
```

## IDA Jumps To The Wrong Address

- Confirm the binary or kernel image open in IDA matches the module stopped in
  WinDbg.
- Confirm symbols/PDBs match the executable being debugged.
- Run `!dvs_pc` again after reconnecting both clients.

## Variables Remain Unavailable

Unavailable is expected when the prototype cannot prove a value. Common causes
include optimized-away values, ambiguous reaching definitions, unresolved
stack state, address-taken locals, scattered variables, aggregates, SIMD/FPU
storage, or storage overwritten before the current PC.

Use trace diagnostics only when investigating a specific candidate; normal
diagnostics intentionally suppress per-variable CFG detail.

## Stale Values

A stale / last observed value was exact at an earlier accepted PC but is not
proven for the current PC. Old `pc_seq` responses are rejected by the IDA-side
request state and must not become exact current values.

## Disconnect And Reconnect

WinDbg:

```text
!dvs_disconnect
!dvs_connect 127.0.0.1 9100
```

IDA:

```text
Edit -> DayVarSync -> Disconnect
Edit -> DayVarSync -> Connect
127.0.0.1:9100
```
