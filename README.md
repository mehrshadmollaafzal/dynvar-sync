# dynvar-sync-version2

`dynvar-sync-version2` is a planned synchronization system between IDA Pro 9.3
and WinDbg Preview for Windows x64 targets. It will synchronize the debugger's
runtime PC with IDA and display confidence-tagged runtime values for supported
Hex-Rays variables.

Current status: broker routing, WinDbg DbgEng-derived PC/register/memory
responses, and a real IDA-side plugin for the current auto-live flow. The IDA
plugin can connect to the broker, receive `pc_update`, map the runtime PC to an
IDA EA, jump there, request `rcx`, `rdx`, `r8`, `r9`, and `rsp`, then request
one 8-byte memory read at `rsp`.

Hex-Rays APIs, stepping, argument mapping, stack argument logic, pseudocode
overlays, and variable recovery are not implemented yet.

## Architecture

```text
IDA Plugin <-> Python Broker <-> WinDbg Extension DLL
```

- The IDA plugin owns Hex-Rays variable interpretation and static address
  mapping.
- The Python broker owns JSONL/TCP routing, sessions, protocol versioning, and
  stale-response correlation.
- The WinDbg extension owns low-level runtime facts such as current PC,
  registers, memory reads, module base, and debugger stepping.

## Folder Structure

```text
broker/      Python broker and protocol helpers
ida_plugin/  IDAPython plugin for current PC/reg/mem auto-live flow
windbg_ext/  C-first WinDbg extension skeleton
samples/     Fake broker test clients and future validation samples
docs/        Adapted architecture and implementation docs
tools/       Future helper scripts and build tools
ForCodex/    Original planning pack, retained unchanged
```

## Phase 1 Manual Test

Terminal 1:

```bash
python3 broker/dayvar_broker.py --host 172.28.70.90 --port 9100 --verbose
```

Terminal 2:

```bash
python3 samples/fake_ida_client.py --host 172.28.70.90 --port 9100
```

Terminal 3:

```bash
python3 samples/fake_windbg_client.py --host 127.0.0.1 --port 9100
```

Expected message flow:

```text
fake_windbg -> broker -> fake_ida: pc_update
fake_ida -> broker -> fake_windbg: ida_pc_mapped
fake_ida -> broker -> fake_windbg: reg_request
fake_windbg -> broker -> fake_ida: reg_response
```

## Phase 2 WinDbg Manual Test

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

Build outputs should go under `windbg_ext/build/`. Build
`windbg_ext/build/dayvar.dll`, then run:

Terminal 1:

```bash
python3 broker/dayvar_broker.py --host 127.0.0.1 --port 9100 --verbose
```

Terminal 2:

```bash
python3 samples/fake_ida_client.py --host 127.0.0.1 --port 9100
```

WinDbg:

```text
.load C:\Users\Mehrshad\source\repos\dynvar-sync-version2\windbg_ext\build\dayvar.dll
!dvs_connect 172.28.70.90 9100
!dvs_pc
!dvs_pc
!dvs_disconnect
```

`!dvs_pc` sends DbgEng-derived `pc`, `module`, and `runtime_module_base` fields
with `auto_live=true` and `reason=dvs_pc`. If DbgEng cannot provide those
values, the command reports an error instead of sending guessed data.

After sending `pc_update`, `!dvs_pc` runs a bounded pump that can answer
`reg_request` with `reg_response` and `mem_request` with `mem_response`.
Supported registers are:

```text
rax rbx rcx rdx rsi rdi rsp rbp r8 r9 r10 r11 r12 r13 r14 r15 rip
```

Expected broker flow for each `!dvs_pc`:

```text
pc_update
ida_pc_mapped
reg_request
reg_response
mem_request
mem_response
```

## Real IDA Plugin Manual Test

Start the broker in WSL:

```bash
python3 broker/dayvar_broker.py --host 172.28.70.90 --port 9100 --verbose
```

In IDA on the Windows host:

```text
Run/load ida_plugin/dayvar_plugin.py
Edit -> DayVarSync -> Connect
```

Use this broker endpoint when prompted:

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

For each `!dvs_pc`, the expected broker flow is:

```text
pc_update
ida_pc_mapped
reg_request
reg_response
mem_request
mem_response
```

The IDA plugin maps the PC with:

```text
ida_ea = idaapi.get_imagebase() + (runtime_pc - runtime_module_base)
```

Then it jumps to the mapped EA and logs the mapping, register response, and
memory response in the IDA output window. Stale responses from an older
`pc_seq` are ignored.

## MVP Goal

The first useful version should support PC synchronization and reliable runtime
values for Windows x64 function arguments at exact function entry:

```text
arg0 -> rcx
arg1 -> rdx
arg2 -> r8
arg3 -> r9
arg4+ -> [rsp + stack offset]
```

Values must be tagged as fresh, stale, unavailable, or unsupported. Responses
must be correlated with `pc_seq` so old debugger replies cannot update a newer
IDA view as fresh.

## Long-Term Goal

The more important long-term goal is live runtime recovery and display of
Hex-Rays decompiler variables, especially generated variables such as:

```text
v1
v2
v160
```

Those variables are often temporaries, optimized-away values, or expressions
rather than stable storage locations. The project must not invent values for
them.

## Correctness Rule

```text
Unavailable is better than wrong.
```

Unsupported variables must be marked unavailable or explicitly unsupported with
a clear confidence/reason field. Guessing a `v*` value would make the tool
misleading, so unsupported recovery must remain honest until the project can
prove an exact runtime location.
