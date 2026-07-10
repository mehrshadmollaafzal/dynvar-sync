# IDA Plugin

IDAPython plugin for the current DayVarSync auto-live flow.

Responsibilities:

- Connect to the Python broker.
- Receive `pc_update` messages from WinDbg through the broker.
- Map runtime PCs to IDA EAs.
- Jump IDA to the mapped EA.
- Enumerate Hex-Rays local variables and arguments.
- Build an exact-entry Windows x64 argument request plan.
- Request only low-level register and memory reads from WinDbg.
- Display variables and runtime values in the Live Variables table.
- Mark late or outdated values as stale or unavailable.

## Current Behavior

Load or run `dayvar_plugin.py` in IDA. The plugin registers these actions under
`Edit/DayVarSync`:

- `DayVarSync: Connect`
- `DayVarSync: Disconnect`
- `DayVarSync: Status`
- `DayVarSync: Show Live Variables`

`Connect` prompts for a broker `host:port` and defaults to:

```text
172.28.70.90:9100
```

The connection runs in a background socket thread so the IDA UI does not block
when the broker is unavailable. Incoming messages are marshalled back onto the
IDA UI thread before using IDA APIs.

For each `pc_update(auto_live=true)`, IDA maps:

```text
ida_ea = idaapi.get_imagebase() + (runtime_pc - runtime_module_base)
```

Then it jumps to `ida_ea`, sends `ida_pc_mapped`, finds the current IDA
function, and decompiles it with Hex-Rays. The plugin enumerates `cfunc.lvars`
and records:

```text
name, type string, size, is_arg, arg_index, Hex-Rays location metadata,
function start EA
```

Both argument-looking `a*` variables and generated `v*` variables are listed.
`v*` locals/temporaries are not guessed. They appear as:

```text
status = unavailable
confidence = unsupported_variable
```

At exact function entry only, the plugin maps Windows x64 arguments:

```text
arg0 -> rcx
arg1 -> rdx
arg2 -> r8
arg3 -> r9
arg4+ -> [rsp + 0x28 + 8 * (arg_index - 4)]
```

The register request is built from the arguments that exist in the current
Hex-Rays lvar list. `rsp` is requested only when stack arguments are present.
After a matching `reg_response`, the plugin sends one `mem_request` for each
needed stack argument.

If the mapped PC is not the function start EA, old entry values are preserved
only as `stale`; otherwise argument rows remain `unavailable`.

Responses are accepted only when they match the current `pc_seq` and an
outstanding `request_id`.

Value display is normalized in the Live Variables table:

- Register values are shown as canonical `0x...` hex.
- Stack argument memory reads decode 1, 2, 4, or 8 bytes as little-endian
  numeric hex.
- Raw memory bytes are kept in the row reason for stack reads.

## Manual Test

Start the broker in WSL:

```bash
python3 broker/dayvar_broker.py --host 172.28.70.90 --port 9100 --verbose
```

In IDA:

```text
Load ida_plugin/dayvar_plugin.py
DayVarSync -> Connect
Open/decompile a function near the synced PC
```

In WinDbg:

```text
.load C:\Users\Mehrshad\source\repos\dynvar-sync-version2\windbg_ext\build\dayvar.dll
!dvs_connect 172.28.70.90 9100
!dvs_pc
!dvs_step p 1
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

Expected IDA behavior:

- IDA jumps to the mapped EA.
- `DayVarSync Live Variables` lists Hex-Rays variables.
- Supported entry arguments show `fresh/exact_entry`.
- After stepping away from entry in the same function, preserved entry values
  become `stale/stale_entry_value`.
- Unsupported `v*` variables show `unavailable/unsupported_variable`.

## Limitations

The IDA plugin must not guess unsupported Hex-Rays temporaries. Arbitrary
`v*` variables are especially important long-term, but unsupported values must
remain unavailable instead of being invented.

Not implemented yet:

- Real `v*` runtime recovery.
- Microcode analysis.
- Complex register lifetime tracking.
- Pseudocode overlays.
