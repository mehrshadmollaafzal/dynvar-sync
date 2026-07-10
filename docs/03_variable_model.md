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
- `error` - a supported read failed.

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

This mapping is exact only when the mapped IDA EA equals the function start EA.
After stepping or syncing inside the function body, entry-derived values must
become stale, and missing values remain unavailable.

The current plugin requests only the low-level runtime facts needed for the
arguments Hex-Rays actually enumerated:

- `rcx`, `rdx`, `r8`, and `r9` for arguments 0..3.
- `rsp` only when argument 4 or later exists.
- One `mem_request` per stack argument after `rsp` is known.

Stack arguments are read from:

```text
[rsp + 0x28 + 8 * (arg_index - 4)]
```

The memory bytes are shown as the debugger returned them. Later phases may add
typed formatting.

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

The Live Variables table still lists unsupported `v*` rows because the
long-term goal is to recover some of them later. Listing them now makes the
unsupported state explicit and prevents misleading blanks or guessed values.

## Hex-Rays Enumeration

When a `pc_update` maps to an IDA EA, the plugin:

1. Uses `ida_funcs.get_func(ida_ea)` to find the current function.
2. Uses `ida_hexrays.init_hexrays_plugin()` when available.
3. Uses `ida_hexrays.decompile(function_start_ea)`.
4. Iterates `cfunc.lvars`.
5. Reads lvar metadata such as name, `tif`, `width`, `is_arg_var()`,
   `cfunc.argidx`, prototype argument names, location, and function start EA.

Argument detection intentionally uses more than one signal because
`lvar.is_arg_var()` is not reliable for every IDA 9.3 decompilation. The
current fallback order is:

- `cfunc.argidx`, when Hex-Rays exposes argument lvar indexes.
- `lvar.is_arg_var()`, when it is set.
- Function prototype / decompiled prototype argument names.
- Known Windows x64 entry ABI locations such as `rcx`, `rdx`/`edx`, `r8`,
  `r9`, and stack locations like `^B0`, `^B8`, `^C0`.

Stack notation is used only to recover argument order. Runtime stack reads
still use the ABI formula:

```text
arg4 -> [rsp + 0x28]
arg5 -> [rsp + 0x30]
arg6 -> [rsp + 0x38]
```

Locals and generated `v*` temporaries are displayed but not used for runtime
requests.

If Hex-Rays is unavailable or decompilation fails, PC sync still works:
`ida_pc_mapped` is sent and IDA jumps to the mapped EA, but no variable rows are
updated from guessed data.

## Live Variables View

The first UI is a table with:

```text
Name | Kind | ArgIndex | Size | Location | Value | Status | Confidence | Reason
```

Pseudocode overlays are a later feature after the variable model is stable.
