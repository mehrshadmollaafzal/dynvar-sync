# Broker

The v0.1.0-research broker is a small JSONL-over-TCP router for one active IDA
client and one active WinDbg client. It validates protocol envelopes, registers
roles, and routes runtime messages. It does not interpret Hex-Rays variables or
debugger state.

Run it with:

```cmd
py -3 .\broker\dayvar_broker.py --host 127.0.0.1 --port 9100 --verbose
```

The broker:

- Accepts one active IDA client and one active WinDbg client.
- Requires clients to send `hello` before other messages.
- Sends `hello_ack` after registration.
- Replaces an existing client when another client registers the same role.
- Preserves partial JSONL lines and handles multiple messages in one receive.
- Logs malformed JSON and invalid protocol envelopes without crashing.
- Routes runtime messages between IDA and WinDbg clients.

Supported routes:

```text
pc_update        windbg -> ida
ida_pc_mapped    ida    -> windbg
reg_request      ida    -> windbg
reg_response     windbg -> ida
mem_request      ida    -> windbg
mem_response     windbg -> ida
error            either -> opposite side when connected
```

The broker still must not parse Hex-Rays variables, read target memory, perform
static analysis, or talk to real IDA/WinDbg APIs.
