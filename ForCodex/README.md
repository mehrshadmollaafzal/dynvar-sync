# dayvar-sync-version2 architecture pack

These Markdown files are intended to be given to Codex before implementation.

Recommended reading order:

1. `00_PROJECT_BRIEF.md`
2. `01_ARCHITECTURE.md`
3. `02_PROTOCOL_JSONL.md`
4. `03_VARIABLE_MODEL.md`
5. `04_COMPONENT_DESIGN.md`
6. `05_IMPLEMENTATION_ROADMAP.md`
7. `06_CODEX_RULES.md`
8. `07_TESTING_STRATEGY.md`
9. `08_PERSONAL_OPINION_AND_RISKS.md`
10. `09_CODEX_START_PROMPT.md`
11. `10_AUTO_LIVE_REFRESH_FLOW.md`

The files intentionally keep v1 narrow and correctness-focused.


## Version 2 update

This pack includes the auto live refresh flow:

```text
WinDbg pc_update -> IDA map -> IDA reg/mem request -> WinDbg response -> IDA Live Variables refresh
```

Use `pc_seq`, `request_id`, and bounded WinDbg command pumping to keep it safe.
