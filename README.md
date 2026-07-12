# dynvar-sync v0.1.0-research

`dynvar-sync` is a best-effort, confidence-aware research prototype that
synchronizes stopped WinDbg runtime state with IDA Pro and recovers only
Hex-Rays variables whose runtime values can be structurally proven.

It is not a source-level debugger and does not guarantee recovery of every
Hex-Rays lvar.

## Current Scope

- Python JSONL/TCP broker for one active IDA client and one active WinDbg
  client.
- WinDbg extension commands for connection, PC/module/base reporting, bounded
  register/memory request pumping, and asynchronous stepping.
- IDA Pro 9.3 plugin that maps a WinDbg runtime PC to an IDA EA, jumps there,
  enumerates Hex-Rays lvars, and displays a Live Variables table.
- Exact-entry Windows x64 argument recovery for documented register and stack
  argument locations.
- Conservative scalar local recovery for a narrow supported subset:
  register-backed lvars, stack-backed lvars, and constants when proof exists.
- Stale / last observed handling for values that were exact at an earlier PC.
- Fail-closed behavior for unavailable, unsupported, ambiguous, and
  optimized-away rows.

The IDA UI still uses the established `DayVarSync` menu and Live Variables
view names. Those identifiers are implementation/UI names; the public project
name is `dynvar-sync`.

## Documentation

- [Documentation index](docs/00_index.md)
- [Installation guide](docs/09_installation.md)
- [Quick-start validation](docs/10_quick_start_validation.md)
- [Support matrix and limitations](docs/07_research_prototype_status.md)
- [Variable model](docs/03_variable_model.md)
- [Testing guide](docs/06_testing.md)
- [Release checklist](docs/08_release_checklist.md)
- [Release notes](docs/release_notes_v0.1.0_research.md)
- [Changelog](CHANGELOG.md)
- [Version](VERSION)

## Repository Layout

```text
broker/      Python broker and protocol helpers
ida_plugin/  IDAPython plugin for arguments and conservative local recovery
windbg_ext/  WinDbg extension source
samples/     Fake clients, tests, and deterministic vvar probe
docs/        Architecture, installation, testing, support, and release docs
tools/       Reserved helper-script area; no required release scripts yet
ForCodex/    Original planning pack
```

## Architecture

```text
IDA Plugin <-> Python Broker <-> WinDbg Extension DLL
```

- IDA owns Hex-Rays interpretation, variable proof, UI state, and stale
  response rejection.
- The broker owns JSONL/TCP routing, session registration, protocol envelope
  validation, and logs.
- WinDbg owns low-level runtime facts: PC, module base, registers, memory, and
  debugger stepping.

## Minimal Local Broker Check

Run this from the repository root for a non-IDA smoke test:

```bash
python3 broker/dayvar_broker.py --host 127.0.0.1 --port 9100 --verbose
```

In two other terminals:

```bash
python3 samples/fake_ida_client.py --host 127.0.0.1 --port 9100
```

```bash
python3 samples/fake_windbg_client.py --host 127.0.0.1 --port 9100
```

For real IDA/WinDbg setup, use the canonical
[installation guide](docs/09_installation.md). In WSL/Windows deployments, bind
the broker to the WSL address that Windows can reach and connect IDA/WinDbg to
`<WSL_IP>:9100`.

## Supported Value States

- `exact current value`: proven fresh for the current `pc_seq`.
- `stale / last observed`: exact at an earlier accepted PC, no longer proven
  for the current PC.
- `unavailable`: known row without enough evidence for a value.
- `ambiguous`: multiple possible definitions or storage states.
- `unsupported`: outside the implemented research subset.
- `not yet defined`: no reaching definition has executed at the current
  pre-instruction PC.
- `optimized away / not materialized`: Hex-Rays did not expose usable storage
  or definition information.

See [docs/03_variable_model.md](docs/03_variable_model.md) and
[docs/07_research_prototype_status.md](docs/07_research_prototype_status.md)
for the full model.

## Validation

Outside IDA, the current regression suite is:

```bash
python3 -m py_compile broker/*.py ida_plugin/*.py samples/*.py
python3 -m unittest discover -s samples -p "test_*.py" -v
git diff --check
```

The WinDbg extension build and live IDA/WinDbg behavior require the appropriate
Windows, IDA Pro 9.3, Hex-Rays, and DbgEng environment. Manual release
validation is documented in [docs/08_release_checklist.md](docs/08_release_checklist.md)
and [docs/10_quick_start_validation.md](docs/10_quick_start_validation.md).

## Release Boundary

`dynvar-sync v0.1.0-research` is complete when:

- transport and synchronization prototype behavior is validated;
- exact-entry argument recovery works for the documented Windows x64 scope;
- best-effort supported scalar lvar recovery works only when structurally
  proven;
- unsupported cases fail closed; and
- full Hex-Rays lvar recovery remains explicitly out of scope.
