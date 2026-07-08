# Variable Model

Hex-Rays variables are not always real runtime storage locations. Function
arguments and explicit memory watches can often be read reliably, but many
temporaries named like `v1`, `v2`, or `v160` are analysis artifacts, optimized
values, or expressions.

Core rule:

```text
Unavailable is better than wrong.
```

The project must always distinguish:

- `fresh` - valid for the current PC and current `pc_seq`.
- `stale` - previously valid, but not guaranteed for the current PC.
- `unavailable` - no reliable value is currently available.
- `unsupported` - the variable kind or location is not supported by the
  current implementation.

In the UI, unsupported variables may be displayed as unavailable with
`confidence = unsupported_variable`, but the reason must make the unsupported
classification explicit.

## Initial Supported Variables

At exact Windows x64 function entry:

```text
arg0 -> rcx
arg1 -> rdx
arg2 -> r8
arg3 -> r9
arg4 -> [rsp + 0x28]
arg5 -> [rsp + 0x30]
arg6 -> [rsp + 0x38]
```

This mapping is exact only at function entry. After stepping, registers may be
overwritten and entry-derived values must become stale.

## Initial Unsupported Variables

Do not guess values for:

- Arbitrary Hex-Rays locals.
- Arbitrary `v*` temporaries.
- Expression-only variables.
- Register locations after unknown instruction flow.
- Variables from inlined functions.

Recommended display:

```text
status = unavailable
confidence = unsupported_variable
reason = variable does not have a reliable runtime location in v1
```

## Live Variables View

The first UI should be a table with:

```text
Name | Kind | Size | Location | Value | Status | Confidence | Reason | Last PC | Current PC
```

Pseudocode overlays are a later feature after the variable model is stable.
