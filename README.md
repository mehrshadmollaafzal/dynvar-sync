# dynvar-sync-version2

`dynvar-sync-version2` is the current DayVarSync research prototype: a
best-effort, confidence-aware synchronization system between IDA Pro 9.3 and
WinDbg Preview for Windows x64 targets. It synchronizes the debugger's runtime
PC with IDA and displays confidence-tagged runtime values for supported
Hex-Rays variables. It is not a source-level debugger and does not guarantee
recovery of every Hex-Rays lvar.

Current status: broker routing, WinDbg DbgEng-derived PC/register/memory
responses, and a real IDA-side plugin for the current auto-live flow. The IDA
plugin can connect to the broker, receive `pc_update`, map the runtime PC to an
IDA EA, jump there, enumerate Hex-Rays lvars, show them in a Live Variables
table, read supported Windows x64 arguments at exact function entry, and
conservatively recover a first subset of live non-argument locals while
stepping. The
IDA argument detector uses Hex-Rays argument indexes, `is_arg_var()` when it is
reliable, prototype names, and known Windows x64 entry locations such as
`rcx`, `rdx`/`edx`, `r8`, `r9`, and `^B0` stack notation. The WinDbg extension
also supports asynchronous `!dvs_step p|t [count]`: it initiates the step,
returns immediately, then sends a fresh `pc_update` and pumps immediate IDA
requests when WinDbg reports the session is accessible again.

The local recovery layer uses Hex-Rays ctree/final microcode plus IDA native
instruction, CFG, and SP/frame information. It supports unique whole-lvar
reaching definitions from the current or predecessor microblock and future
uses in reachable successor blocks. Register-backed recovery additionally
requires the physical x64 GPR to survive every native CFG path to the current
PC. Stack and constant support retain their narrower conservative constraints.
Printed `lvar.location` text alone never authorizes a read.

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
ida_plugin/  IDAPython plugin for arguments and conservative local recovery
windbg_ext/  C-first WinDbg extension skeleton
samples/     Fake clients, unit tests, and the deterministic vvar probe
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
Load ida_plugin/dayvar_plugin.py
DayVarSync -> Connect
Open/decompile a function near the synced PC
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
!dvs_step p 1
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

Then it jumps to the mapped EA, enumerates Hex-Rays variables, and refreshes
the `DayVarSync Live Variables` table. Supported entry arguments are read with:

```text
arg0 -> rcx
arg1 -> rdx
arg2 -> r8
arg3 -> r9
arg4+ -> [rsp + 0x28 + 8 * (arg_index - 4)]
```

The separate `v_variable_recovery.py` layer rebuilds proof at every mapped PC.
A supported local can become:

```text
fresh / exact_register_location
fresh / exact_stack_location
fresh / exact_constant
```

When proof disappears, its previous exact value can remain only
`stale/stale_runtime_value`. Other locals stay unavailable with reasons such as
`not_live_at_current_pc`, `ambiguous_register_location`,
`unresolved_stack_location`, or `no_reaching_definition`. Stale responses from
an older `pc_seq` or unknown `v-` request ID are ignored.

After `!dvs_step p 1` or `!dvs_step t 1`, WinDbg sends
`pc_update(auto_live=true, reason=dvs_step)` from the asynchronous session
accessible notification, after the target has stopped at the post-step PC. If
IDA maps the new PC inside the same function but not at entry, prior entry
argument values remain visible only as `stale/stale_entry_value`, and no
exact-entry arg request is sent.

Values are displayed as normalized hex. Register values are canonical `0x...`;
stack argument memory reads decode 1/2/4/8-byte values as little-endian numeric
hex and keep raw bytes in the row reason. Local stack reads always use the
proven 1/2/4/8-byte lvar width. The table appends `Source EA`, `Storage`, and
`Last Update PC`, plus `LvarIndex` and `Type`, to its existing columns.

## First Local/`v*` Recovery Boundary

At the exact pre-instruction `MMAT_LVARS` point, the current proof scans the
microcode CFG backward and requires one effective whole-lvar definition on all
paths. It separately scans successors for any use before redefinition. A use
may be in another block; later definitions that cannot reach the current point
do not invalidate it. Register storage must be structural `is_reg1()` and
survive a native FlowChart predecessor proof with no call, decode uncertainty,
or overlapping subregister write. A 32-bit GPR definition zero-extends the
physical register; runtime reads still request the full register and mask the
proven width.

Currently unsupported cases include ambiguous or undefined reaching paths,
partial/scattered/shared locations, storage-clobbered paths, unresolved loops
or native program points, cross-block stack definitions, address-taken or
aliased stack locals, XMM/vector/FPU values, fuzzy stack state, and
inlined/expression-only variables. These remain unavailable rather than
guessed.

Run outside-IDA regressions with:

```bash
python3 -m unittest -v \
  samples.test_dynvar_core \
  samples.test_v_variable_recovery \
  samples.test_v_variable_cfg
```

For the measured support matrix and closure baseline, see
`docs/07_research_prototype_status.md`.

For manual IDA/WinDbg transitions, build and follow
`samples/vvar_probe/README.md`.

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

Values must be tagged as fresh, stale, unavailable, or error. Responses
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
rather than stable storage locations. The current milestone recovers only the
proven subset above; broader CFG liveness and reaching-definition analysis are
future work.

## Correctness Rule

```text
Unavailable is better than wrong.
```

Unsupported variables must be marked unavailable or explicitly unsupported with
a clear confidence/reason field. Guessing a `v*` value would make the tool
misleading, so unsupported recovery must remain honest until the project can
prove an exact runtime location.
