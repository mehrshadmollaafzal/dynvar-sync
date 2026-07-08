# WinDbg Extension

The WinDbg extension implements the first C-first commands for broker
connection and PC synchronization.

Implemented commands:

```text
!dvs_connect <host> <port>
!dvs_disconnect
!dvs_status
!dvs_pc
!dvs_poll [max_messages]
```

Behavior:

- `!dvs_connect` opens a TCP connection to the Python broker and sends a
  `hello` message with `role = windbg`.
- `!dvs_disconnect` closes the socket.
- `!dvs_status` prints the current connection state.
- `!dvs_pc` reads the current instruction pointer, containing module name, and
  runtime module base through DbgEng, then sends a `pc_update` message with a
  monotonically increasing `pc_seq` and `auto_live=true`. It then runs a short
  bounded broker pump to handle immediate `reg_request` messages.
- `!dvs_poll [max_messages]` manually runs the same bounded broker pump.

DbgEng-specific lookup is isolated in `dbgeng_ops.c`. If PC/module/base lookup
fails, `!dvs_pc` reports the DbgEng error and does not send guessed data.

Register requests are handled with DbgEng register APIs. Supported registers:

```text
rax rbx rcx rdx rsi rdi rsp rbp r8 r9 r10 r11 r12 r13 r14 r15 rip
```

## Build Notes

Build on Windows with the Windows SDK / Visual Studio developer environment.
The extension uses `dbgeng.h`, WinSock2, and `Ws2_32.lib`. Keep generated
outputs under `windbg_ext/build/`.

Example command from the repository root:

```bat
if not exist windbg_ext\build mkdir windbg_ext\build
cl /nologo /LD /W4 /D_CRT_SECURE_NO_WARNINGS ^
  windbg_ext\dayvar.c windbg_ext\socket_client.c ^
  windbg_ext\json_writer.c windbg_ext\dbgeng_ops.c ^
  /Fe:windbg_ext\build\dayvar.dll ^
  /link /DEF:windbg_ext\dayvar.def Ws2_32.lib
```

MinGW-w64 cross-check command used in this environment:

```bash
mkdir -p windbg_ext/build
x86_64-w64-mingw32-gcc -shared -Wall -Wextra \
  -o windbg_ext/build/dayvar.dll \
  windbg_ext/dayvar.c windbg_ext/socket_client.c \
  windbg_ext/json_writer.c windbg_ext/dbgeng_ops.c \
  windbg_ext/dayvar.def -lws2_32
```

## Manual Test

Current WSL/Windows test environment:

```text
Codex runs inside WSL.
Broker runs inside WSL.
WinDbg Preview runs on the Windows host.
IDA Pro runs on the Windows host.

WSL IP:     172.28.70.90
Windows IP: 172.28.64.1
Broker port: 9100
```

Terminal 1:

```bash
python3 broker/dayvar_broker.py --host 0.0.0.0 --port 9100 --verbose
```

Terminal 2:

```bash
python3 samples/fake_ida_client.py --host 127.0.0.1 --port 9100
```

WinDbg:

```text
.load path\to\windbg_ext\build\dayvar.dll
!dvs_connect 172.28.70.90 9100
!dvs_status
!dvs_pc
!dvs_poll
!dvs_disconnect
```

Expected broker flow:

```text
windbg extension -> broker -> fake_ida: pc_update
fake_ida -> broker -> windbg extension: reg_request
windbg extension -> broker -> fake_ida: reg_response
```

The broker log or fake IDA output should show `pc_update` fields derived from
the current debugger context:

```text
payload.pc
payload.module
payload.runtime_module_base
payload.auto_live = true
payload.reason = dvs_pc
```

`reg_response` preserves the request `pc_seq`, `request_id`, and `runtime_pc`.

Current limitations:

- No `mem_request` handling yet.
- No stepping yet.
- No real IDA API integration yet.
- No Hex-Rays `v*` variable recovery yet.

The extension must stay low-level. It must not parse Hex-Rays variables, infer
decompiler semantics, block WinDbg forever, or guess values for unsupported
variables.
