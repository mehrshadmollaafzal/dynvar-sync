# Auto Live Refresh

The preferred default behavior is that one WinDbg command updates both IDA's
current address and the Live Variables view.

```text
!dvs_pc
```

or:

```text
!dvs_step p 1
```

## Sequence

1. WinDbg sends `pc_update` with `pc_seq` and `auto_live=true`.
2. Broker forwards `pc_update` to IDA.
3. IDA maps runtime PC to IDA EA.
4. IDA sends `ida_pc_mapped`.
5. IDA builds an internal live request plan.
6. IDA sends `reg_request` and/or `mem_request`.
7. Broker forwards requests to WinDbg.
8. WinDbg's bounded command pump answers immediate requests.
9. WinDbg sends `reg_response` and/or `mem_response`.
10. IDA applies only responses matching the current `pc_seq`.
11. IDA refreshes the Live Variables view.

## Bounded Pump Requirements

The WinDbg extension may briefly poll the broker after sending a PC update, but
it must:

- Never wait forever.
- Preserve partial JSONL lines.
- Avoid assuming one `recv` equals one message.
- Stop cleanly on timeout.
- Keep `!dvs_poll` available as a manual fallback.

IDA must accept a response only when it is `ok`, has the current `pc_seq`, has
the expected `runtime_pc` when present, and has a pending `request_id`.
