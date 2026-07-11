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
!dvs_step p 1
!dvs_disconnect
```

Expected broker logs include a registered `windbg` client and routed refresh
messages for both `!dvs_pc` and `!dvs_step`:

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
reason = dvs_pc or dvs_step
```

For the auto-refresh register path:

```text
!dvs_pc or !dvs_step
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

- Fake IDA does not validate stale-state transitions.
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
!dvs_step p 1
```

Expected broker flow for `!dvs_pc` and for each `!dvs_step` refresh:

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
[DayVarSync] v-candidate name=v6 index=<n> location=r8d current_ea=<ea>
[DayVarSync] v-recovery name=v6 result=<status> source=<storage> reason=<reason>
[DayVarSync] v-request pc_seq=<n> registers=[...] memory=[...]
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
- Register values are displayed as canonical `0x...` hex.
- Stack argument memory bytes are decoded little-endian for 1/2/4/8-byte
  values and keep raw bytes in the row reason.
- Proven register, stack, or constant locals can become fresh with
  `exact_register_location`, `exact_stack_location`, or `exact_constant`.
- Every other local remains unavailable with a concrete conservative reason;
  a previous exact value can remain only `stale/stale_runtime_value`.
- `LvarIndex`, `Type`, `Source EA`, `Storage`, and `Last Update PC` are
  populated for recovered rows.

Current real IDA plugin limitations:

- Argument runtime values are exact only at function entry.
- Stack arguments read 1/2/4/8 bytes when Hex-Rays reports a safe size;
  other sizes fall back to an 8-byte slot read.
- Register recovery permits one effective whole-lvar definition from the
  current or predecessor microblock and a use in a reachable successor block.
- Ambiguous/undefined/partial reaching paths, unresolved loops, native calls
  or register clobbers, scattered/shared/aliased locations, vector registers,
  cross-block stack definitions, and fuzzy stack state remain unsupported.
- No pseudocode overlays.

## Outside-IDA Unit Tests

Run the stdlib-only regression suite from the repository root:

```bash
python3 -m unittest -v \
  samples.test_dynvar_core \
  samples.test_v_variable_recovery \
  samples.test_v_variable_cfg \
  samples.test_usability_controls
```

The tests cover the unchanged entry-argument register/stack behavior and stale
transition, old-`pc_seq` rejection, x64 subregister normalization/masking,
little-endian exact-width decoding, register/stack/constant v plan state,
fresh-to-stale history, concrete stack requests, and isolated microcode
failure. Synthetic CFG coverage includes current/predecessor definitions,
successor uses, ambiguous predecessors, killed definitions, overlapping
definitions, diamonds, undefined paths, native register clobbers, exact
pre-instruction semantics, and bounded forward/backward loops. They do not
replace real IDA tests because SWIG ctree/microcode and processor-module
register-access APIs are available only inside IDA.

Usability coverage includes diagnostic-level suppression and trace retention,
Live Variables filter predicates, recoverable/argument/named-local filters,
active-filter state preservation, bounded candidate selection, selection cache
invalidation, fresh/stale prioritization, and stale response rejection with
bounded selection enabled.

## PsOpenProcess Cross-Block Register Test

This live test requires IDA 9.3 and WinDbg and cannot be completed by the
outside-IDA suite. Break and synchronize at the pre-instruction PC:

```text
nt!PsOpenProcess+...:
0x1406D3495  xor esi, esi
0x1406D3498  mov r12d, esi
0x1406D349B  mov [rsp+4Ch], esi  ; current PC
```

For Hex-Rays lvar index 10, name `v10`, structural location `r12d`, expected
analysis/request diagnostics are:

```text
v-cfg-point name=v10 current_block=<current_block> current_instruction=<index> current_ea=0x1406d349b
v-reaching-def name=v10 def_ea=0x1406d3498 def_block=<def_block> current_ea=0x1406d349b current_block=<current_block> count=1 undefined_paths=0 overlap=0 loop=0 exhausted=0
v-cross-block-live name=v10 result=cross_block_use use_ea=<use_ea> use_block=<use_block> redefinitions=<n> loop=<0|1> exhausted=0
v-storage-valid name=v10 storage=r12d result=valid reason=exact register storage survives to current PC clobber_ea=none blocks=<n>
v-recovery name=v10 result=pending source=register:r12d reason=waiting for register r12
v-request pc_seq=<pc_seq> registers=['r12'] memory=[]
```

After the matching `reg_response` returns full `r12 = 0`, the row must show:

```text
Value      = 0x0
Status     = fresh
Confidence = exact_register_location
Storage    = r12d
Source EA  = 0x1406d3498
```

The exact microblock serials, use EA, and path counts are database-dependent
and must be taken from the live diagnostic lines. Do not treat this scenario
as passed until it is verified in the real IDA/WinDbg session.

## vvar Probe Manual Recovery Test

Build and use `samples/vvar_probe/` as described in its README. Its MASM
functions export instruction-accurate symbols for definitions, retained uses,
and register reuse. Hex-Rays may propagate a simple machine temporary away, so
identify test rows by function EA, lvar index, Source EA, and Storage rather
than assuming a generated name.

For the register path:

```text
bp vvar_probe!vvar_register_before_def
g
!dvs_pc
!dvs_step p 1
```

Expected:

- Before the `lea r8d, [rcx+2]`, no r8 value is copied into the local row.
- At `vvar_register_live`, a structurally mapped and live row may request full
  `r8`, mask it to 32 bits, and become
  `0x42/fresh/exact_register_location`.
- After `vvar_register_before_reuse` executes, the original value must never
  remain fresh; if preserved, it is `stale/stale_runtime_value`.

Repeat from `vvar_stack_before_def`. At `vvar_stack_live`, a supported row must
request `rsp`, resolve the concrete address using IDA SP/frame state, request
exactly 8 bytes, decode little-endian, and become
`0x8877665544332211/fresh/exact_stack_location`.

Repeat from `vvar_constant_before_def`. At `vvar_constant_live`, a retained
whole `m_mov mop_n -> mop_l` definition may produce
`0x2/fresh/exact_constant` without any debugger read for that candidate.

Negative checks:

- A row whose printed location says `r8` but lacks the proof remains
  unavailable.
- Scattered, ambiguous/undefined cross-block, cross-block stack, and
  unresolved-stack rows send no value read. A unique, storage-valid
  cross-block register candidate may send one full-register request.
- Trigger a newer PC update before an older v response arrives. IDA must log
  `stale pc_seq` and must not change the newer row to fresh.
- Temporarily force decompilation/microcode failure (or test a function Hex-Rays
  cannot decompile). PC mapping, arguments, stepping, socket processing, and
  the table must continue; affected local rows use `microcode_unavailable`.

Manual milestone sign-off is not complete until the same session also proves:

- Existing entry arguments still become `fresh/exact_entry` unchanged.
- Stepping away still makes captured arguments `stale/stale_entry_value`.
- At least one real non-argument row becomes fresh through the register, stack,
  or constant class.
- An ambiguous row remains unavailable even when its printed location names a
  register.
- An old-`pc_seq` response is rejected and never becomes fresh.

## Step Stale-State Test

Use a function with known Windows x64 arguments, for example:

```text
bp nt!NtCreateFile
g
!dvs_pc
```

Expected after `!dvs_pc` at entry:

- IDA jumps to the function entry.
- Supported arguments become `fresh/exact_entry`.
- Broker shows `pc_update`, `ida_pc_mapped`, `reg_request`, `reg_response`,
  and stack `mem_request`/`mem_response` when stack args exist.

Then run:

```text
!dvs_step p 1
```

Expected after stepping:

- `!dvs_step` initiates the step and returns without calling `WaitForEvent`.
- WinDbg sends `pc_update(auto_live=true, reason=dvs_step)` only after
  `DebugExtensionNotify(DEBUG_NOTIFY_SESSION_ACCESSIBLE)` reports that the
  session is accessible again.
- The `pc_update` PC must match the stopped post-step WinDbg PC, for example
  `nt!NtCreateFile+0x7` after stepping from function entry.
- IDA jumps to the new EA.
- If the new EA is inside the same function but not entry, old argument values
  remain visible as `stale/stale_entry_value`.
- No new entry-argument request is sent away from entry. Separate `v-reg-*` or
  `v-mem-*` requests are allowed only for currently proven local candidates.
- Unsupported locals remain unavailable, and prior successful locals may be
  visible only as `stale/stale_runtime_value` when proof disappears.

## WinDbg Smoke Tests

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

Unsupported `v*` temporaries must be shown as unavailable with a reason, or as
an explicitly stale prior success, never guessed from their printed location.
