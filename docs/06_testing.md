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
!dvs_pc
!dvs_disconnect
```

Expected broker logs include a registered `windbg` client and a routed
`pc_update`:

```text
[broker] registered role=windbg
[broker] route pc_update id=<n> windbg -> ida
[broker] route ida_pc_mapped id=<n> ida -> windbg
[broker] route reg_request id=<n> ida -> windbg
[broker] route reg_response id=<n> windbg -> ida
[broker] route mem_request id=<n> ida -> windbg
[broker] route mem_response id=<n> windbg -> ida
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

For the auto-refresh register path:

```text
!dvs_pc
  -> sends pc_update
  -> briefly pumps broker messages
  -> handles reg_request
  -> sends reg_response
  -> handles mem_request
  -> sends mem_response
```

`reg_response` and `mem_response` must preserve `pc_seq`, `request_id`, and
`runtime_pc`. The extension currently supports these x64 registers:

```text
rax rbx rcx rdx rsi rdi rsp rbp r8 r9 r10 r11 r12 r13 r14 r15 rip
```

The fake IDA client sends one `mem_request` after `reg_response`, using the
returned `rsp` value and reading 8 bytes from that address. Expected fake IDA
output includes:

```text
recv type=reg_response
recv type=mem_response
```

Current limitations:

- No `!dvs_step`.
- No real IDA plugin in this fake-client test.
- No real variable recovery.

## Real IDA Plugin Auto-Live Test

This flow replaces `samples/fake_ida_client.py` with the IDA plugin while
keeping the existing broker and WinDbg extension.

Terminal 1 in WSL:

```bash
python3 broker/dayvar_broker.py --host 172.28.70.90 --port 9100 --verbose
```

In IDA on the Windows host:

```text
Load ida_plugin/dayvar_plugin.py
DayVarSync -> Connect
Open/decompile a function near the synced PC
```

The connect action prompts for a broker endpoint. Use:

```text
172.28.70.90:9100
```

In WinDbg:

```text
.load C:\Users\Mehrshad\source\repos\dynvar-sync-version2\windbg_ext\build\dayvar.dll
!dvs_connect 172.28.70.90 9100
!dvs_pc
!dvs_pc
```

Expected broker flow for each `!dvs_pc`:

```text
[broker] route pc_update id=<n> windbg -> ida
[broker] route ida_pc_mapped id=<n> ida -> windbg
[broker] route reg_request id=<n> ida -> windbg
[broker] route reg_response id=<n> windbg -> ida
[broker] route mem_request id=<n> ida -> windbg
[broker] route mem_response id=<n> windbg -> ida
```

Expected IDA output log:

```text
[DayVarSync] hello_ack ...
[DayVarSync] pc_seq=<n> runtime_pc=<pc> ida_ea=<ea> module=<module>
[DayVarSync] enumerated <count> Hex-Rays variables function=<ea> at_entry=<bool>
[DayVarSync] request plan function=<ea> at_entry=True variables=<count>
[DayVarSync] detected arg0 name=<name> location=<location>
[DayVarSync] registers requested=['rcx', ...]
[DayVarSync] stack args requested=[...]
[DayVarSync] send type=reg_request id=<n>
[DayVarSync] reg_response pc_seq=<n> request_id=reg-<n>-entry ok=True
[DayVarSync] send type=mem_request id=<n>
[DayVarSync] mem_response pc_seq=<n> request_id=mem-<n>-<name> ok=True ...
```

The plugin computes:

```text
ida_ea = idaapi.get_imagebase() + (runtime_pc - runtime_module_base)
```

and jumps IDA to that address. It then uses Hex-Rays to enumerate `cfunc.lvars`
for the current function and refreshes the `DayVarSync Live Variables` table.
If a response has an old `pc_seq`, mismatched `runtime_pc`, or unknown
`request_id`, it is logged and ignored.

Expected Live Variables behavior:

- Argument rows are listed with `ArgIndex`.
- At exact function entry, args 0..3 can become `fresh/exact_entry`.
- At exact function entry, args 4+ can become `fresh/exact_entry` after the
  stack slot memory read succeeds.
- Away from function entry, preserved entry values are marked `stale`.
- Unsupported `v*` variables are listed as
  `unavailable/unsupported_variable`.

Current real IDA plugin limitations:

- Argument runtime values are exact only at function entry.
- Stack arguments are read as raw 8-byte memory slots.
- No real `v*` recovery.
- No microcode analysis.
- No complex register lifetime tracking.
- No stepping.
- No pseudocode overlays.

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
The Live Variables table should show Hex-Rays variables if decompilation
succeeds. If Hex-Rays is unavailable or decompilation fails, PC sync should
still work and the plugin should log the failure clearly.

## Variable Tests

Use functions with known Windows x64 arguments. At function entry, first four
arguments should be fresh from `rcx`, `rdx`, `r8`, and `r9`; fifth and later
arguments should be fresh from stack slots.

After stepping, entry-derived values should remain visible only as stale.

Unsupported `v*` temporaries must be shown as unavailable or explicitly
unsupported, never guessed.
