# IDA Plugin

IDAPython plugin for the current DayVarSync auto-live flow.

Responsibilities:

- Connect to the Python broker.
- Receive `pc_update` messages from WinDbg through the broker.
- Map runtime PCs to IDA EAs.
- Jump IDA to the mapped EA.
- Build the current fixed auto-live request plan.
- Request only low-level register and memory reads from WinDbg.
- Display mapping and live responses in the IDA output log.
- Mark late or outdated values as stale or unavailable.

## Current Behavior

Load or run `dayvar_plugin.py` in IDA. The plugin registers these actions under
`Edit/DayVarSync`:

- `DayVarSync: Connect`
- `DayVarSync: Disconnect`
- `DayVarSync: Status`

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

Then it jumps to `ida_ea`, sends `ida_pc_mapped`, sends a `reg_request` for:

```text
rcx rdx r8 r9 rsp
```

After a matching `reg_response`, the plugin sends one test `mem_request` using
the returned `rsp` value and size `8`. Matching `reg_response` and
`mem_response` messages are printed to the IDA output log.

Responses are accepted only when they match the current `pc_seq` and an
outstanding `request_id`.

## Manual Test

Start the broker in WSL:

```bash
python3 broker/dayvar_broker.py --host 172.28.70.90 --port 9100 --verbose
```

In IDA:

```text
Run/load ida_plugin/dayvar_plugin.py
Edit -> DayVarSync -> Connect
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
pc_update
ida_pc_mapped
reg_request
reg_response
mem_request
mem_response
```

## Limitations

The IDA plugin must not guess unsupported Hex-Rays temporaries. Arbitrary
`v*` variables are especially important long-term, but unsupported values must
remain unavailable instead of being invented.

Not implemented yet:

- Hex-Rays variable extraction.
- `v*` recovery.
- Argument mapping.
- Stack argument logic.
- Stepping.
- Pseudocode overlays.
