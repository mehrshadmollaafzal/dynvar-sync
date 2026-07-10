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
!dvs_step <p|t> [count]
```

Behavior:

- `!dvs_connect` opens a TCP connection to the Python broker and sends a
  `hello` message with `role = windbg`.
- `!dvs_disconnect` closes the socket.
- `!dvs_status` prints the current connection state.
- `!dvs_pc` reads the current instruction pointer, containing module name, and
  runtime module base through DbgEng, then sends a `pc_update` message with a
  monotonically increasing `pc_seq` and `auto_live=true`. It then runs a short
  bounded broker pump to handle immediate `reg_request` and `mem_request`
  messages.
- `!dvs_poll [max_messages]` manually runs the same bounded broker pump.
- `!dvs_step p 1` steps over one instruction. `!dvs_step t 1` traces into one
  instruction. The command records pending step state, initiates the step, and
  returns immediately. When WinDbg later reports the session is accessible
  again, the extension sends `pc_update(auto_live=true, reason=dvs_step)` and
  runs the same bounded broker pump as `!dvs_pc`.

DbgEng-specific lookup is isolated in `dbgeng_ops.c`. If PC/module/base lookup
fails, `!dvs_pc` reports the DbgEng error and does not send guessed data.
Stepping initiation is isolated in `dbgeng_ops.c` and uses DbgEng execution
control APIs. Post-step synchronization is asynchronous through
`DebugExtensionNotify(DEBUG_NOTIFY_SESSION_ACCESSIBLE)`. The extension does not
call `WaitForEvent` from command paths.

Register requests are handled with DbgEng register APIs. Supported registers:

```text
rax rbx rcx rdx rsi rdi rsp rbp r8 r9 r10 r11 r12 r13 r14 r15 rip
```

Memory requests are handled with DbgEng virtual memory reads. Reads are capped
at 4096 bytes and return `bytes_hex` in lowercase hex. Failed reads return a
`mem_response` with `ok=false`.

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
python3 broker/dayvar_broker.py --host 172.28.70.90 --port 9100 --verbose
```

Terminal 2:

```bash
python3 samples/fake_ida_client.py --host 172.28.70.90 --port 9100
```

WinDbg:

```text
.load C:\Users\Mehrshad\source\repos\dynvar-sync-version2\windbg_ext\build\dayvar.dll
!dvs_connect 172.28.70.90 9100
!dvs_pc
!dvs_step p 1
!dvs_disconnect
```

Expected broker flow for `!dvs_pc` and for each `!dvs_step` refresh:

```text
pc_update
ida_pc_mapped
reg_request
reg_response
mem_request
mem_response
```

The broker log or fake IDA output should show `pc_update` fields derived from
the current debugger context:

```text
payload.pc
payload.module
payload.runtime_module_base
payload.auto_live = true
payload.reason = dvs_pc or dvs_step
```

For `!dvs_step`, the `pc_update` is sent only after the debugger stops at the
post-step PC. While the target is running, `!dvs_status` reports the pending
step mode/count.

`reg_response` and `mem_response` preserve the request `pc_seq`, `request_id`,
and `runtime_pc`.

Current limitations:

- No Hex-Rays `v*` variable recovery yet.
- No decompiler semantics in the WinDbg extension.

The extension must stay low-level. It must not parse Hex-Rays variables, infer
decompiler semantics, block WinDbg forever, or guess values for unsupported
variables.
