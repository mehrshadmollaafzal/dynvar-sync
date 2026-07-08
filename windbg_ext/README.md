# WinDbg Extension

Phase 2 implements the first C-first WinDbg extension commands for broker
connection and basic PC synchronization.

Implemented commands:

```text
!dvs_connect <host> <port>
!dvs_disconnect
!dvs_status
!dvs_pc
```

Behavior:

- `!dvs_connect` opens a TCP connection to the Python broker and sends a
  `hello` message with `role = windbg`.
- `!dvs_disconnect` closes the socket.
- `!dvs_status` prints the current connection state.
- `!dvs_pc` sends a `pc_update` message with a monotonically increasing
  `pc_seq`.

Current Phase 2 limitation: real DbgEng PC/module/base extraction is not
implemented yet. `dbgeng_ops.c` returns clearly marked placeholder values and
sets the `pc_update` reason to `dvs_pc_phase2_placeholder`.

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
!dvs_disconnect
```

Expected broker flow:

```text
windbg extension -> broker -> fake_ida: pc_update
```

The fake IDA client may reply with `ida_pc_mapped` and `reg_request`, but Phase
2 does not implement a receive pump or register responses yet.

The extension must stay low-level. It must not parse Hex-Rays variables, infer
decompiler semantics, block WinDbg forever, or guess values for unsupported
variables.
