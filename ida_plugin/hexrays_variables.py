"""Hex-Rays variable extraction and conservative classification.

This module enumerates lvars and records what IDA can prove. It does not try to
recover runtime values for arbitrary locals or `v*` temporaries.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

try:
    import ida_funcs  # type: ignore
    import ida_hexrays  # type: ignore
    import ida_typeinf  # type: ignore
except ImportError:  # pragma: no cover - outside IDA validation path.
    ida_funcs = None  # type: ignore
    ida_hexrays = None  # type: ignore
    ida_typeinf = None  # type: ignore


STATUS_UNAVAILABLE = "unavailable"
CONFIDENCE_UNSUPPORTED_VARIABLE = "unsupported_variable"
CONFIDENCE_UNKNOWN = "unknown"


@dataclass
class VariableRecord:
    """IDA-side description and display state for one Hex-Rays variable."""

    lvar_index: int
    name: str
    hexrays_kind: str
    type_string: str
    size: int
    is_arg: bool
    arg_index: int | None
    location: str
    function_ea: str
    function_start_ea: int
    value: str = ""
    status: str = STATUS_UNAVAILABLE
    confidence: str = CONFIDENCE_UNKNOWN
    reason: str = "not evaluated"
    last_pc: str = ""
    current_pc: str = ""
    printed_location: str = ""
    current_ea: str = ""
    source_ea: str = ""
    storage_kind: str = ""
    storage: str = ""
    current_pc_seq: int | None = None
    last_success_value: str = ""
    last_success_pc_seq: int | None = None
    lvar_defea: str = ""


@dataclass(frozen=True)
class ArgumentDetection:
    """Argument classification result for one lvar."""

    is_arg: bool
    arg_index: int | None
    reason: str


@dataclass(frozen=True)
class VariableEnumerationResult:
    """Result of a Hex-Rays lvar enumeration attempt."""

    ok: bool
    function_start_ea: int | None
    function_ea: str
    variables: list[VariableRecord]
    error: str = ""
    cfunc: object | None = None


def is_v_temporary_name(name: str) -> bool:
    """Return true for generated-looking Hex-Rays names such as v1 or v160."""
    return len(name) > 1 and name[0] == "v" and name[1:].isdigit()


def unsupported_variable(
    name: str,
    *,
    lvar_index: int = -1,
    size: int = 0,
    type_string: str = "",
    function_start_ea: int = 0,
    current_pc: str = "",
) -> VariableRecord:
    """Create an honest unsupported-variable record."""
    return VariableRecord(
        lvar_index=lvar_index,
        name=name,
        hexrays_kind="temporary" if is_v_temporary_name(name) else "unknown",
        type_string=type_string,
        size=size,
        is_arg=False,
        arg_index=None,
        location="unsupported",
        function_ea=_format_hex(function_start_ea),
        function_start_ea=function_start_ea,
        status=STATUS_UNAVAILABLE,
        confidence=CONFIDENCE_UNSUPPORTED_VARIABLE,
        reason="variable does not have a reliable runtime location in v1",
        current_pc=current_pc,
        printed_location="unsupported",
    )


def enumerate_hexrays_variables(ea: int, current_pc: str = "") -> VariableEnumerationResult:
    """Find the current function, decompile it, and enumerate Hex-Rays lvars."""
    if ida_funcs is None or ida_hexrays is None:
        return VariableEnumerationResult(
            ok=False,
            function_start_ea=None,
            function_ea="",
            variables=[],
            error="IDA/Hex-Rays APIs are unavailable outside IDA",
        )

    func = ida_funcs.get_func(ea)
    if func is None:
        return VariableEnumerationResult(
            ok=False,
            function_start_ea=None,
            function_ea="",
            variables=[],
            error=f"no IDA function contains ea={_format_hex(ea)}",
        )

    function_start = int(func.start_ea)
    try:
        if hasattr(ida_hexrays, "init_hexrays_plugin"):
            ida_hexrays.init_hexrays_plugin()
        cfunc = ida_hexrays.decompile(function_start)
    except Exception as exc:
        return VariableEnumerationResult(
            ok=False,
            function_start_ea=function_start,
            function_ea=_format_hex(function_start),
            variables=[],
            error=f"Hex-Rays decompilation failed: {exc}",
        )

    if cfunc is None:
        return VariableEnumerationResult(
            ok=False,
            function_start_ea=function_start,
            function_ea=_format_hex(function_start),
            variables=[],
            error="Hex-Rays decompilation returned no cfunc",
        )

    lvars = list(cfunc.lvars)
    arg_detections = _detect_arguments(cfunc, lvars)

    variables: list[VariableRecord] = []
    for lvar_index, lvar in enumerate(lvars):
        name = str(getattr(lvar, "name", "") or "<unnamed>")
        size = _safe_size(lvar)
        location = _safe_location_string(lvar, size)
        detection = arg_detections.get(
            lvar_index,
            ArgumentDetection(False, None, "not detected as function argument"),
        )
        record = VariableRecord(
            lvar_index=lvar_index,
            name=name,
            hexrays_kind=_classify_lvar(name, detection.is_arg),
            type_string=_safe_type_string(lvar),
            size=size,
            is_arg=detection.is_arg,
            arg_index=detection.arg_index,
            location=location,
            function_ea=_format_hex(function_start),
            function_start_ea=function_start,
            status=STATUS_UNAVAILABLE,
            confidence=CONFIDENCE_UNKNOWN if detection.is_arg else CONFIDENCE_UNSUPPORTED_VARIABLE,
            reason=(
                f"argument detected by {detection.reason}"
                if detection.is_arg
                else "variable does not have a reliable runtime location in v1"
            ),
            current_pc=current_pc,
            printed_location=location,
            lvar_defea=_safe_definition_ea(lvar),
        )
        variables.append(record)

    return VariableEnumerationResult(
        ok=True,
        function_start_ea=function_start,
        function_ea=_format_hex(function_start),
        variables=variables,
        cfunc=cfunc,
    )


def _classify_lvar(name: str, is_arg: bool) -> str:
    if is_arg:
        return "arg"
    if is_v_temporary_name(name):
        return "temporary"
    return "local"


def _detect_arguments(cfunc: object, lvars: list[object]) -> dict[int, ArgumentDetection]:
    """Detect function arguments using multiple Hex-Rays/prototype signals."""
    detections: dict[int, ArgumentDetection] = {}

    for arg_index, lvar_index in enumerate(_iter_cfunc_argidx(cfunc)):
        if 0 <= lvar_index < len(lvars):
            detections[lvar_index] = ArgumentDetection(True, arg_index, "cfunc.argidx")

    next_index = _next_arg_index(detections)
    for lvar_index, lvar in enumerate(lvars):
        if lvar_index in detections:
            continue
        if _safe_bool_call(lvar, "is_arg_var"):
            detections[lvar_index] = ArgumentDetection(True, next_index, "lvar.is_arg_var()")
            next_index += 1

    prototype_names = _prototype_arg_names(cfunc)
    if prototype_names:
        next_index = _next_arg_index(detections)
        name_to_lvar_index = {
            str(getattr(lvar, "name", "") or ""): lvar_index for lvar_index, lvar in enumerate(lvars)
        }
        for proto_index, name in enumerate(prototype_names):
            lvar_index = name_to_lvar_index.get(name)
            if lvar_index is not None and lvar_index not in detections:
                detections[lvar_index] = ArgumentDetection(True, proto_index, "function prototype")
                next_index = max(next_index, proto_index + 1)

    # Fallback for IDA 9.3 cases where visible parameters are not marked as
    # args: promote ABI-shaped leading lvars in Windows x64 argument order. It
    # can also fill stack args when the first four register args were found by
    # another signal but later args were not.
    fallback = _detect_abi_location_arguments(lvars)
    used_arg_indexes = {
        detection.arg_index for detection in detections.values() if detection.arg_index is not None
    }
    for lvar_index, detection in fallback.items():
        if lvar_index in detections or detection.arg_index in used_arg_indexes:
            continue
        detections[lvar_index] = detection

    return detections


def _iter_cfunc_argidx(cfunc: object) -> list[int]:
    argidx = getattr(cfunc, "argidx", None)
    if argidx is None:
        return []

    values: list[int] = []
    for accessor in (
        lambda idx: argidx[idx],
        lambda idx: argidx.at(idx),
    ):
        try:
            size = int(argidx.size()) if hasattr(argidx, "size") else len(argidx)
            values = [int(accessor(idx)) for idx in range(size)]
            if values:
                return values
        except Exception:
            pass

    try:
        return [int(value) for value in argidx]
    except Exception:
        return []


def _prototype_arg_names(cfunc: object) -> list[str]:
    names = _prototype_arg_names_from_tinfo(cfunc)
    if names:
        return names
    return _prototype_arg_names_from_pseudocode(cfunc)


def _prototype_arg_names_from_tinfo(cfunc: object) -> list[str]:
    if ida_typeinf is None:
        return []
    try:
        tif = ida_typeinf.tinfo_t()
        get_func_type = getattr(cfunc, "get_func_type", None)
        if not callable(get_func_type) or not get_func_type(tif):
            return []
        details = ida_typeinf.func_type_data_t()
        if not tif.get_func_details(details):
            return []
    except Exception:
        return []

    names: list[str] = []
    try:
        size = int(details.size()) if hasattr(details, "size") else len(details)
    except Exception:
        size = 0
    for index in range(size):
        try:
            arg = details.at(index) if hasattr(details, "at") else details[index]
            name = str(getattr(arg, "name", "") or "")
            if name:
                names.append(name)
        except Exception:
            continue
    return names


def _prototype_arg_names_from_pseudocode(cfunc: object) -> list[str]:
    try:
        pseudocode = cfunc.get_pseudocode()
    except Exception:
        return []

    header_parts: list[str] = []
    for line in pseudocode:
        text = _strip_ida_tags(str(getattr(line, "line", line)))
        header_parts.append(text.strip())
        if ")" in text:
            break
    header = " ".join(header_parts)
    match = re.search(r"\((.*)\)", header)
    if not match:
        return []

    args_text = match.group(1).strip()
    if not args_text or args_text == "void":
        return []

    names: list[str] = []
    for part in _split_args(args_text):
        name = _extract_decl_name(part)
        if name:
            names.append(name)
    return names


def _detect_abi_location_arguments(lvars: list[object]) -> dict[int, ArgumentDetection]:
    candidates: list[tuple[int, int, str]] = []
    for lvar_index, lvar in enumerate(lvars):
        name = str(getattr(lvar, "name", "") or "")
        if is_v_temporary_name(name):
            continue
        size = _safe_size(lvar)
        location = _safe_location_string(lvar, size)
        arg_index = abi_arg_index_from_location(location)
        if arg_index is None:
            continue
        candidates.append((arg_index, lvar_index, location))

    if not candidates:
        return {}

    by_arg_index: dict[int, tuple[int, str]] = {}
    for arg_index, lvar_index, location in sorted(candidates):
        by_arg_index.setdefault(arg_index, (lvar_index, location))

    detections: dict[int, ArgumentDetection] = {}
    expected = 0
    while expected in by_arg_index:
        lvar_index, location = by_arg_index[expected]
        detections[lvar_index] = ArgumentDetection(True, expected, f"ABI location {location}")
        expected += 1

    # Accept stack-only prototypes when the first four args were optimized away
    # only if we have at least one leading register argument. Otherwise it is
    # too easy to confuse stack locals with parameters.
    if 0 not in by_arg_index:
        return {}
    return detections


def abi_arg_index_from_location(location: str) -> int | None:
    """Map known Hex-Rays Windows x64 entry locations to argument indexes."""
    normalized = _normalize_location(location)
    register_map = {
        "rcx": 0,
        "ecx": 0,
        "cx": 0,
        "cl": 0,
        "rdx": 1,
        "edx": 1,
        "dx": 1,
        "dl": 1,
        "r8": 2,
        "r8d": 2,
        "r8w": 2,
        "r8b": 2,
        "r9": 3,
        "r9d": 3,
        "r9w": 3,
        "r9b": 3,
    }
    for register, arg_index in register_map.items():
        if re.search(rf"\b{register}\b", normalized):
            return arg_index

    match = re.search(r"\^([0-9a-f]+)", normalized)
    if match:
        offset = int(match.group(1), 16)
        if offset >= 0xB0 and (offset - 0xB0) % 8 == 0:
            return 4 + ((offset - 0xB0) // 8)
    return None


def _next_arg_index(detections: dict[int, ArgumentDetection]) -> int:
    indexes = [detection.arg_index for detection in detections.values() if detection.arg_index is not None]
    return max(indexes, default=-1) + 1


def _strip_ida_tags(text: str) -> str:
    # IDA color tags are control-byte sequences. Keeping only printable text is
    # sufficient for prototype-name fallback.
    return "".join(ch for ch in text if ch >= " " or ch in "\t")


def _split_args(args_text: str) -> list[str]:
    args: list[str] = []
    depth = 0
    start = 0
    for index, char in enumerate(args_text):
        if char in "([{<":
            depth += 1
        elif char in ")]}>":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            args.append(args_text[start:index].strip())
            start = index + 1
    tail = args_text[start:].strip()
    if tail:
        args.append(tail)
    return args


def _extract_decl_name(arg_decl: str) -> str:
    arg_decl = arg_decl.strip()
    if not arg_decl or arg_decl == "...":
        return ""
    arg_decl = re.sub(r"=.*$", "", arg_decl).strip()
    match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?\s*$", arg_decl)
    if not match:
        return ""
    name = match.group(1)
    if name in {
        "void",
        "char",
        "short",
        "int",
        "long",
        "float",
        "double",
        "signed",
        "unsigned",
        "const",
        "volatile",
        "struct",
        "union",
        "enum",
    }:
        return ""
    return name


def _normalize_location(location: str) -> str:
    return location.strip().lower().replace("`", "")


def _safe_bool_call(obj: object, method_name: str) -> bool:
    method = getattr(obj, method_name, None)
    if method is None:
        return False
    try:
        return bool(method())
    except Exception:
        return False


def _safe_size(lvar: object) -> int:
    try:
        if _safe_bool_call(lvar, "is_unknown_width"):
            return 0
        return int(getattr(lvar, "width", 0) or 0)
    except Exception:
        return 0


def _safe_type_string(lvar: object) -> str:
    tif = getattr(lvar, "tif", None)
    if tif is None:
        type_method = getattr(lvar, "type", None)
        if callable(type_method):
            try:
                tif = type_method()
            except Exception:
                tif = None

    if tif is None:
        return ""

    for method_name in ("dstr", "__str__"):
        method = getattr(tif, method_name, None)
        if callable(method):
            try:
                text = str(method())
                if text and text != "?":
                    return text
            except Exception:
                pass
    return str(tif)


def _safe_location_string(lvar: object, size: int) -> str:
    try:
        if ida_hexrays is not None and hasattr(ida_hexrays, "print_vdloc"):
            location = getattr(lvar, "location", None)
            if location is not None:
                text = ida_hexrays.print_vdloc(location, size)
                if text:
                    return str(text)
    except Exception:
        pass

    if _safe_bool_call(lvar, "is_reg_var"):
        return "hexrays_reg"
    if _safe_bool_call(lvar, "is_stk_var"):
        return "hexrays_stack"
    return "unknown"


def _safe_definition_ea(lvar: object) -> str:
    try:
        value = int(getattr(lvar, "defea"))
    except (AttributeError, TypeError, ValueError):
        return ""
    if value < 0 or value == ((1 << 64) - 1):
        return ""
    return _format_hex(value)


def _format_hex(value: int) -> str:
    return f"0x{value:x}"
