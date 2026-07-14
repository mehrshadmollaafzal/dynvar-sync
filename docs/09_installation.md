# Installation

This guide documents the supported public setup for
`dynvar-sync v0.1.0-research`:

- IDA Pro runs on Windows.
- WinDbg runs on Windows.
- The Python broker runs on the same Windows machine.
- All components connect through `127.0.0.1:9100`.

Custom network deployments are not covered by this guide.

## Prerequisites

- Windows x64 target process or kernel debugging session.
- IDA Pro 9.3 with Hex-Rays decompiler.
- WinDbg Preview or WinDbg with DbgEng extension support.
- Python 3.12 or higher.
- Windows SDK / Visual Studio x64 Native Tools Command Prompt for building the
  WinDbg extension.

## Repository Layout

```text
broker\      Python JSONL/TCP broker
ida_plugin\  IDAPython plugin modules
windbg_ext\  WinDbg extension source
samples\     Fake clients, tests, and vvar_probe
docs\        Documentation
tools\       Reserved helper-script area
```

## Install The IDA Plugin

The IDA plugin is multi-file. Install all Python modules from `ida_plugin\`,
not only `dayvar_plugin.py`.

From PowerShell at the repository root:

```powershell
$IdaPlugins = "$env:APPDATA\Hex-Rays\IDA Pro\plugins"

New-Item -ItemType Directory -Force -Path $IdaPlugins | Out-Null

Copy-Item `
    .\ida_plugin\*.py `
    $IdaPlugins `
    -Force
```

Restart IDA after copying the files. Verify the plugin loaded by checking for:

```text
Edit -> DayVarSync
```

To update the plugin later, repeat:

```powershell
Copy-Item `
    .\ida_plugin\*.py `
    "$env:APPDATA\Hex-Rays\IDA Pro\plugins" `
    -Force
```

To uninstall the plugin cleanly, remove the installed files:

```powershell
$IdaPlugins = "$env:APPDATA\Hex-Rays\IDA Pro\plugins"

Remove-Item -Force `
    "$IdaPlugins\address_mapping.py", `
    "$IdaPlugins\dayvar_plugin.py", `
    "$IdaPlugins\dynvar_core.py", `
    "$IdaPlugins\hexrays_variables.py", `
    "$IdaPlugins\live_variables_view.py", `
    "$IdaPlugins\protocol_client.py", `
    "$IdaPlugins\v_variable_recovery.py"
```

Do not copy `README.md`, `__pycache__`, generated files, tests, or unrelated
artifacts into the IDA plugin directory.

## Build The WinDbg Extension

Open an x64 Native Tools Command Prompt at the repository root:

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

The expected output is:

```text
windbg_ext\build\dayvar.dll
```

## Start The Broker

From Command Prompt at the repository root:

```cmd
py -3 .\broker\dayvar_broker.py --host 127.0.0.1 --port 9100 --verbose
```

Expected broker startup:

```text
[broker] listening on 127.0.0.1:9100
```

Leave this window open.

## Connect IDA

1. Start or restart IDA Pro 9.3.
2. Open the target binary or kernel image.
3. Ensure Hex-Rays can decompile the function you want to inspect.
4. Use `Edit -> DayVarSync -> Connect`.
5. Enter:

   ```text
   127.0.0.1:9100
   ```

Expected broker log:

```text
[broker] registered role=ida
```

## Load And Connect WinDbg

In WinDbg:

```text
.load C:\path\to\dynvar-sync\windbg_ext\build\dayvar.dll
!dvs_connect 127.0.0.1 9100
!dvs_status
```

Expected broker log:

```text
[broker] registered role=windbg
```

## Send The First PC

Stop the target at a function entry or known instruction, then run:

```text
!dvs_pc
```

Expected route sequence:

```text
pc_update
ida_pc_mapped
reg_request
reg_response
mem_request
mem_response
```

Some functions do not require memory requests. Unsupported or optimized-away
locals may remain unavailable; that is expected.

## Disconnect And Reconnect

WinDbg:

```text
!dvs_disconnect
```

IDA:

```text
Edit -> DayVarSync -> Disconnect
```

The broker accepts a new client for either role and replaces the old session
when another client registers with the same role. After reconnecting, run
`!dvs_pc` again to establish a fresh `pc_seq` context.

For common setup issues, see [Troubleshooting](11_troubleshooting.md).
