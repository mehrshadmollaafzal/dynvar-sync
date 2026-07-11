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

Additional sample programs can extend coverage for Windows x64 entry snapshots,
explicit memory watches, and more complex unsupported Hex-Rays temporaries.

`vvar_probe/` now provides deterministic x64 definition/live/reuse landmarks,
plus C `noinline` local probes, for manual register, stack, constant, and stale
runtime-recovery validation.
