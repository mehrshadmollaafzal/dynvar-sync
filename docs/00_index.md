# Documentation Index

## Getting Started

- [Installation](09_installation.md) - Windows localhost installation,
  permanent IDA plugin setup, broker startup, and WinDbg connection.
- [Quick Start](10_quick_start_validation.md) - Deterministic manual
  IDA/WinDbg smoke test using `samples\vvar_probe`.
- [Troubleshooting](11_troubleshooting.md) - Common Windows setup and runtime
  issues.

## Technical Reference

- [Architecture](01_architecture.md) - Component responsibilities and state
  ownership.
- [Protocol](02_protocol.md) - JSONL/TCP messages and correlation fields.
- [Variable Model](03_variable_model.md) - Exact, stale, unavailable, and
  unsupported value semantics.
- [Auto Live Refresh](04_auto_live_refresh.md) - One-command PC sync and live
  refresh sequence.
- [Research Prototype Status](07_research_prototype_status.md) - Support
  matrix, limitations, and current proof boundary.

## Development

- [Development Rules](05_development_rules.md) - Implementation constraints.
- [Testing](06_testing.md) - Developer regression commands and lower-level test
  design.
- [Release Checklist](08_release_checklist.md) - Maintainer release validation.

## Project Status

- [Release Notes](release_notes_v0.1.0_research.md) - Concise release summary.
- [Changelog](../CHANGELOG.md) - Versioned changes.
