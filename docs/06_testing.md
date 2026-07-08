# Testing

Testing must focus on correctness because stale state or guessed variable
mapping can show misleading runtime values.

## Protocol Tests

Use fake clients before using IDA or WinDbg.

Test:

- `hello` and `hello_ack`.
- `pc_update` forwarding.
- `reg_request` and `reg_response` forwarding.
- `mem_request` and `mem_response` forwarding.
- `pc_seq` correlation.
- Malformed JSON handling.
- Partial TCP line handling.
- Multiple JSON messages in one receive.

## Phase 1 Manual Broker Test

Terminal 1:

```bash
python3 broker/dayvar_broker.py --host 127.0.0.1 --port 9100 --verbose
```

Terminal 2:

```bash
python3 samples/fake_ida_client.py --host 127.0.0.1 --port 9100
```

Terminal 3:

```bash
python3 samples/fake_windbg_client.py --host 127.0.0.1 --port 9100
```

Expected broker logs include:

```text
[broker] listening on 127.0.0.1:9100
[broker] registered role=ida
[broker] registered role=windbg
[broker] route pc_update id=10 windbg -> ida
[broker] route ida_pc_mapped id=99 ida -> windbg
[broker] route reg_request id=100 ida -> windbg
[broker] route reg_response id=101 windbg -> ida
```

Known Phase 1 limitations:

- Fake clients only.
- No real IDA APIs.
- No real Hex-Rays variable recovery.
- No real WinDbg extension networking.
- No DbgEng register or memory reads.
- No broker-side stale-response rejection beyond preserving fields and routing.

## WinDbg Extension PC Test

Build `windbg_ext/dayvar.dll` on Windows with the Windows SDK / Visual Studio
developer environment. The extension depends on `dbgeng.h`, WinSock2, and
`Ws2_32.lib`. Build outputs should go under `windbg_ext/build/`.

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

Example build command:

```bat
if not exist windbg_ext\build mkdir windbg_ext\build
cl /nologo /LD /W4 /D_CRT_SECURE_NO_WARNINGS ^
  windbg_ext\dayvar.c windbg_ext\socket_client.c ^
  windbg_ext\json_writer.c windbg_ext\dbgeng_ops.c ^
  /Fe:windbg_ext\build\dayvar.dll ^
  /link /DEF:windbg_ext\dayvar.def Ws2_32.lib
```

MinGW-w64 cross-check command:

```bash
mkdir -p windbg_ext/build
x86_64-w64-mingw32-gcc -shared -Wall -Wextra \
  -o windbg_ext/build/dayvar.dll \
  windbg_ext/dayvar.c windbg_ext/socket_client.c \
  windbg_ext/json_writer.c windbg_ext/dbgeng_ops.c \
  windbg_ext/dayvar.def -lws2_32
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

Expected broker logs include a registered `windbg` client and a routed
`pc_update`:

```text
[broker] registered role=windbg
[broker] route pc_update id=<n> windbg -> ida
```

The fake IDA client should print a `pc_update` payload containing real
DbgEng-derived values from the current debugger context:

```text
pc
module
runtime_module_base
auto_live = true
reason = dvs_pc
```

Current limitations:

- No `!dvs_poll`.
- No `!dvs_step`.
- No `reg_response`.
- No `mem_response`.
- No real variable recovery.

## Future WinDbg Smoke Tests

Manual command path:

```text
.load path\to\dayvar.dll
!dvs_connect 127.0.0.1 9100
!dvs_status
!dvs_pc
!dvs_poll
!dvs_step p 1
!dvs_disconnect
```

Expected: no hang, no crash, useful broker logs, and bounded command pumping.

## IDA Smoke Tests

- Load the matching binary in IDA.
- Start the broker.
- Connect the IDA plugin.
- Connect the WinDbg extension.
- Run `!dvs_pc`.

Expected: IDA maps runtime PC to IDA EA and jumps to the expected location.

## Variable Tests

Use functions with known Windows x64 arguments. At function entry, first four
arguments should be fresh from `rcx`, `rdx`, `r8`, and `r9`; fifth and later
arguments should be fresh from stack slots.

After stepping, entry-derived values should remain visible only as stale.

Unsupported `v*` temporaries must be shown as unavailable or explicitly
unsupported, never guessed.
