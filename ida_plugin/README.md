# IDA Plugin

Future IDAPython plugin for IDA Pro 9.3.

Responsibilities:

- Connect to the Python broker.
- Receive `pc_update` messages from WinDbg through the broker.
- Map runtime PCs to IDA EAs.
- Extract and classify Hex-Rays variables.
- Build IDA-owned live request plans.
- Request only low-level register and memory reads from WinDbg.
- Display values in a separate Live Variables table.
- Mark late or outdated values as stale or unavailable.

The IDA plugin must not guess unsupported Hex-Rays temporaries. Arbitrary
`v*` variables are especially important long-term, but unsupported values must
remain unavailable instead of being invented.
