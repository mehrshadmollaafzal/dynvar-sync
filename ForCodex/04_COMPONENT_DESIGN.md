# Component Design

## 1. Broker

### Language

Python 3.

### Files

```text
broker/
├── dayvar_broker.py
├── protocol.py
├── sessions.py
└── README.md
```

### Responsibilities

- Listen on a TCP port.
- Accept IDA and WinDbg clients.
- Read JSONL messages.
- Validate minimal message structure.
- Route messages by type.
- Preserve partial input lines.
- Correlate request and response ids.
- Log all protocol messages in debug mode.
- Drop or flag stale messages when `pc_seq` / PC context mismatches.
- Route the full automatic PC-map-live-refresh cycle without understanding variable semantics.

### Broker should not

- Parse Hex-Rays variables.
- Read target memory itself.
- Know WinDbg internals.
- Perform static analysis.

### Suggested commands

```bash
python broker/dayvar_broker.py --host 0.0.0.0 --port 9100 --verbose
```

## 2. IDA plugin

### Language

Python / IDAPython.

### Files

```text
ida_plugin/
├── dayvar_plugin.py
├── dynvar_core.py
├── hexrays_variables.py
├── address_mapping.py
├── live_variables_view.py
├── protocol_client.py
└── README.md
```

### Responsibilities

- Connect to broker.
- Receive `pc_update` messages.
- Map runtime PC to IDA EA.
- Jump IDA view to mapped EA.
- Extract Hex-Rays local variables and arguments.
- Classify supported/unsupported variables.
- Build an internal live request plan after `pc_update(auto_live=true)`.
- Send `reg_request` / `mem_request` messages.
- Attach `pc_seq` and `request_id` to all runtime-dependent requests.
- Display values in the Live Variables table.
- Mark stale values after stepping.
- Ignore late responses from older `pc_seq` values.

### IDA plugin should not

- Execute debugger commands directly.
- Guess runtime values for unsupported variables.
- Modify pseudocode output in v1.

### Suggested UI actions

- `DayVarSync: Connect`
- `DayVarSync: Disconnect`
- `DayVarSync: Sync PC`
- `DayVarSync: Refresh Live Variables`
- `DayVarSync: Add Selected Hex-Rays Watch`
- `DayVarSync: Step Over`
- `DayVarSync: Trace Into`

## 3. WinDbg extension

### Language

C-first. C++ only if required by DbgEng integration.

### Files

```text
windbg_ext/
├── dayvar.c
├── socket_client.c
├── socket_client.h
├── json_writer.c
├── json_writer.h
├── dbgeng_ops.c
├── dbgeng_ops.h
├── dayvar.def
├── build.bat
└── README.md
```

### Responsibilities

- Implement WinDbg commands.
- Connect to broker using TCP.
- Send current PC/module/base.
- Read registers.
- Read memory.
- Step the debugger when requested.
- Poll broker for pending requests.
- After `!dvs_pc` or `!dvs_step`, run a short bounded command pump to answer immediate `reg_request` / `mem_request` messages.

### WinDbg extension should not

- Parse arbitrary JSON with heavy dependencies.
- Contain Hex-Rays logic.
- Keep large state.
- Block WinDbg forever while waiting for network data.

### Required WinDbg commands

```text
!dvs_connect <host> <port>
!dvs_disconnect
!dvs_pc
!dvs_poll [max_messages]
!dvs_step [p|t] [count]
!dvs_status
```

Expected command behavior:

```text
!dvs_pc
  - send pc_update(auto_live=true)
  - pump broker messages briefly
  - answer immediate reg_request/mem_request messages

!dvs_step p|t count
  - execute the step operation
  - send step_response
  - send pc_update(auto_live=true, reason=dvs_step)
  - pump broker messages briefly

!dvs_poll [max_messages]
  - manually process pending broker messages
  - useful when auto pump is disabled or timed out
```

The pump must be bounded. It must never hang WinDbg forever.

### Optional later commands

```text
!dvs_read_reg <reg>
!dvs_read_mem <address> <size>
!dvs_log on|off
```

## 4. Samples

Samples are mandatory because this project is hard to validate only by inspection.

Recommended initial samples:

```text
samples/
├── ntqsi_probe/
│   ├── ntqsi_probe.c
│   ├── build.bat
│   └── README.md
│
├── ntcreatefile_probe/
│   ├── ntcreatefile_probe.c
│   ├── build.bat
│   └── README.md
│
└── README.md
```

Samples should be tiny, reproducible, and designed to test:

- first four args
- 5th+ stack args
- entry snapshots
- stale values after stepping
- EA memory watches

