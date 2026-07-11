# Installation Guide

This guide starts from a clean checkout of DayVarSync v0.1.0-research.

## Prerequisites

- Windows x64 target process or kernel debugging session.
- WinDbg Preview or WinDbg with DbgEng extension support.
- IDA Pro 9.3 with Hex-Rays decompiler.
- Python 3 on the broker host.
- A Windows SDK / Visual Studio x64 Native Tools environment for the WinDbg
  extension build, or MinGW-w64 for the documented cross-check build.
- Network reachability between WinDbg, IDA, and the broker. In the documented
  WSL/Windows setup, the broker runs in WSL and Windows tools connect to the
  WSL IP address.

## Repository Layout

```text
broker/      Python JSONL/TCP broker
ida_plugin/  IDAPython plugin and Live Variables view
windbg_ext/  WinDbg extension source
samples/     Fake clients, tests, and vvar_probe
docs/        Architecture, testing, support, and release docs
tools/       Reserved for helper scripts; no required release scripts yet
ForCodex/    Original planning material, retained unchanged
```

## Start The Broker

From the repository root:

```bash
python3 broker/dayvar_broker.py --host 172.28.70.90 --port 9100 --verbose
```

Use the interface address that Windows can reach. For WSL, get the WSL address
with:

```bash
hostname -I
```

For local fake-client testing entirely inside one environment, use:

```bash
python3 broker/dayvar_broker.py --host 127.0.0.1 --port 9100 --verbose
```

Expected broker startup:

```text
[broker] listening on <host>:9100
```

## Build The WinDbg Extension

From a Windows x64 Native Tools Command Prompt at the repository root:

```bat
if not exist windbg_ext\build mkdir windbg_ext\build
cl /nologo /LD /W4 /D_CRT_SECURE_NO_WARNINGS ^
  windbg_ext\dayvar.c windbg_ext\socket_client.c ^
  windbg_ext\json_writer.c windbg_ext\dbgeng_ops.c ^
  /Fe:windbg_ext\build\dayvar.dll ^
  /link /DEF:windbg_ext\dayvar.def Ws2_32.lib
```

The documented MinGW-w64 cross-check command is:

```bash
mkdir -p windbg_ext/build
x86_64-w64-mingw32-gcc -shared -Wall -Wextra \
  -o windbg_ext/build/dayvar.dll \
  windbg_ext/dayvar.c windbg_ext/socket_client.c \
  windbg_ext/json_writer.c windbg_ext/dbgeng_ops.c \
  windbg_ext/dayvar.def -lws2_32
```

## Load The WinDbg Extension

In WinDbg:

```text
.load C:\Users\Mehrshad\source\repos\dynvar-sync-version2\windbg_ext\build\dayvar.dll
!dvs_status
```

Before connection, `!dvs_status` should report disconnected state.

## Load The IDA Plugin

In IDA Pro 9.3:

1. Open the target binary or kernel image.
2. Ensure Hex-Rays can decompile the functions you want to inspect.
3. Load or run `ida_plugin/dayvar_plugin.py`.
4. Use `Edit/DayVarSync/Connect`.

When prompted for the broker endpoint, use the broker host and port, for
example:

```text
172.28.70.90:9100
```

Expected broker log:

```text
[broker] registered role=ida
```

## Connect WinDbg

In WinDbg, connect to the same broker:

```text
!dvs_connect 172.28.70.90 9100
```

Expected broker log:

```text
[broker] registered role=windbg
```

Expected WinDbg output includes a successful connection and hello send.

## Send The First PC

Stop the target at a function entry or another known instruction, then run:

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

Some functions will not need memory requests. Unsupported or optimized-away
locals may remain unavailable; that is expected.

## Disconnect And Reconnect

WinDbg:

```text
!dvs_disconnect
```

IDA:

```text
Edit/DayVarSync/Disconnect
```

The broker accepts a new client for either role and replaces the old session
when another client registers with the same role. After reconnecting, run
`!dvs_pc` again to establish a fresh `pc_seq` context.
