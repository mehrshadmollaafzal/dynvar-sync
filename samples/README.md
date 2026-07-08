# Samples

The sample clients provide broker/protocol testing before real IDA integration
exists. `fake_ida_client.py` is persistent by default and can handle repeated
`!dvs_pc` commands from the WinDbg extension.

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

Expected flow for each `!dvs_pc`:

```text
pc_update
ida_pc_mapped
reg_request
reg_response
mem_request
mem_response
```

After `reg_response`, the fake IDA client reads `rsp` and sends one
`mem_request` for 8 bytes at that address. Use `--once` to exit after one full
PC/register/memory flow.

The fake IDA client does not use real IDA APIs or Hex-Rays APIs. It tests JSONL
framing, registration, routing, and `pc_seq` / `request_id` preservation.

Future sample programs will validate Windows x64 arguments, entry snapshots,
stale values after stepping, explicit memory watches, and unsupported
Hex-Rays temporaries such as `v1`, `v2`, and `v160`.
