# Samples

Phase 1 includes fake clients for broker/protocol testing before real IDA or
WinDbg integration exists.

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

Expected flow:

```text
fake_windbg -> broker -> fake_ida: pc_update
fake_ida -> broker -> fake_windbg: ida_pc_mapped
fake_ida -> broker -> fake_windbg: reg_request
fake_windbg -> broker -> fake_ida: reg_response
```

These clients do not use real IDA APIs, Hex-Rays APIs, WinDbg APIs, or DbgEng.
They only test JSONL framing, registration, routing, and basic `pc_seq` field
preservation.

Future sample programs will validate Windows x64 arguments, entry snapshots,
stale values after stepping, explicit memory watches, and unsupported
Hex-Rays temporaries such as `v1`, `v2`, and `v160`.
