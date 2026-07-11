"""Outside-IDA unit tests for the conservative v-variable runtime layer."""

from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN_DIR = os.path.join(ROOT, "ida_plugin")
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)

from hexrays_variables import VariableRecord  # noqa: E402
from v_variable_recovery import (  # noqa: E402
    CONFIDENCE_EXACT_CONSTANT,
    CONFIDENCE_EXACT_REGISTER_LOCATION,
    CONFIDENCE_EXACT_STACK_LOCATION,
    CONFIDENCE_STALE_RUNTIME_VALUE,
    REASON_MICROCODE,
    REASON_NOT_LIVE,
    RecoveryAnalysis,
    RecoveryEvidence,
    STATUS_FRESH,
    STATUS_STALE,
    STATUS_UNAVAILABLE,
    VVariableRecovery,
    _RegisterWrite,
    _validate_straight_line_micro_range,
    decode_little_endian,
    extract_register_value,
    normalize_register_alias,
)


def _variable(
    index: int = 4,
    name: str = "v4",
    size: int = 4,
    defea: str = "0x140001010",
) -> VariableRecord:
    return VariableRecord(
        lvar_index=index,
        name=name,
        hexrays_kind="temporary",
        type_string="unsigned int",
        size=size,
        is_arg=False,
        arg_index=None,
        location="r8d",
        function_ea="0x140001000",
        function_start_ea=0x140001000,
        printed_location="r8d",
        lvar_defea=defea,
    )


def _envelope(message_type: str, payload: dict[str, object]) -> dict[str, object]:
    return {"protocol": 1, "type": message_type, "role": "ida", "payload": payload}


class _Provider:
    def __init__(self, analysis: RecoveryAnalysis) -> None:
        self.analysis = analysis

    def __call__(
        self,
        function_ea: int,
        current_ea: int,
        variables: list[VariableRecord],
        cfunc: object | None,
    ) -> RecoveryAnalysis:
        del function_ea, current_ea, variables, cfunc
        return self.analysis


class _RaisingProvider:
    def __call__(
        self,
        function_ea: int,
        current_ea: int,
        variables: list[VariableRecord],
        cfunc: object | None,
    ) -> RecoveryAnalysis:
        del function_ea, current_ea, variables, cfunc
        raise RuntimeError("synthetic provider failure")


class RegisterHelpersTest(unittest.TestCase):
    def test_aliases_project_to_full_registers_and_mask(self) -> None:
        cases = {
            "rax": ("rax", 8, 0),
            "eax": ("rax", 4, 0),
            "ax": ("rax", 2, 0),
            "al": ("rax", 1, 0),
            "ah": ("rax", 1, 8),
            "sil": ("rsi", 1, 0),
            "r8d": ("r8", 4, 0),
            "r15b": ("r15", 1, 0),
        }
        for alias, expected in cases.items():
            with self.subTest(alias=alias):
                spec = normalize_register_alias(alias)
                self.assertIsNotNone(spec)
                assert spec is not None
                self.assertEqual(
                    (spec.full_register, spec.width, spec.bit_offset),
                    expected,
                )

        ah = normalize_register_alias("ah")
        assert ah is not None
        self.assertEqual(extract_register_value("0x1234", ah, 1), "0x12")
        r8d = normalize_register_alias("r8d")
        assert r8d is not None
        self.assertEqual(extract_register_value("0x1122334455667788", r8d, 4), "0x55667788")

    def test_little_endian_decoder_requires_exact_width(self) -> None:
        self.assertEqual(decode_little_endian("78563412", 4), "0x12345678")
        with self.assertRaises(ValueError):
            decode_little_endian("7856", 4)

    def test_native_write_must_cover_exact_subregister_bits(self) -> None:
        ah = normalize_register_alias("ah")
        assert ah is not None
        self.assertFalse(_RegisterWrite("rax", 0, 8).covers(ah, 1))
        self.assertTrue(_RegisterWrite("rax", 8, 8).covers(ah, 1))
        self.assertFalse(_RegisterWrite("rax", 0, 8).overlaps(ah, 1))


class _FakeMicroInstruction:
    def __init__(self, ea: int) -> None:
        self.ea = ea

    def is_assert(self) -> bool:
        return False


class _FakeMba:
    @staticmethod
    def map_fict_ea(ea: int) -> int:
        return ea


class ProgramPointTest(unittest.TestCase):
    def test_definition_at_current_ea_has_not_executed(self) -> None:
        self.assertFalse(
            _validate_straight_line_micro_range(
                mba=_FakeMba(),
                instructions=[_FakeMicroInstruction(0x110), _FakeMicroInstruction(0x114)],
                start=0,
                end=1,
                native_bounds=(0x100, 0x120),
                current_ea=0x110,
            )
        )
        self.assertTrue(
            _validate_straight_line_micro_range(
                mba=_FakeMba(),
                instructions=[_FakeMicroInstruction(0x10C), _FakeMicroInstruction(0x110)],
                start=0,
                end=1,
                native_bounds=(0x100, 0x120),
                current_ea=0x110,
            )
        )

    def test_propagated_or_nonmonotone_micro_range_is_rejected(self) -> None:
        self.assertFalse(
            _validate_straight_line_micro_range(
                mba=_FakeMba(),
                instructions=[_FakeMicroInstruction(0x10C), _FakeMicroInstruction(0x108)],
                start=0,
                end=1,
                native_bounds=(0x100, 0x120),
                current_ea=0x110,
            )
        )


class RecoveryStateTest(unittest.TestCase):
    def test_register_fresh_then_stale_and_old_response_rejected(self) -> None:
        variable = _variable()
        spec = normalize_register_alias("r8d")
        assert spec is not None
        provider = _Provider(
            RecoveryAnalysis(
                ok=True,
                evidence_by_index={
                    4: RecoveryEvidence(
                        4,
                        storage_kind="register",
                        storage="register:r8d",
                        source_ea=0x140001010,
                        confidence=CONFIDENCE_EXACT_REGISTER_LOCATION,
                        reason="proven",
                        register=spec,
                    )
                },
            )
        )
        recovery = VVariableRecovery(provider)
        plan = recovery.begin_pc(
            variables=[variable],
            function_ea=variable.function_start_ea,
            current_ea=0x140001014,
            runtime_pc="0x7ff600001014",
            pc_seq=10,
            envelope=_envelope,
        )
        self.assertEqual(plan.register_request["payload"]["registers"], ["r8"])
        self.assertEqual(recovery.records[0].recovery_status, STATUS_UNAVAILABLE)

        accepted, reason, requests, _logs = recovery.apply_reg_response(
            {
                "pc_seq": 10,
                "request_id": "v-reg-10-runtime",
                "runtime_pc": "0x7ff600001014",
                "ok": True,
                "registers": {"r8": "0xffffffff00000002"},
            },
            envelope=_envelope,
        )
        self.assertTrue(accepted, reason)
        self.assertEqual(requests, [])
        record = recovery.records[0]
        self.assertEqual(record.value, "0x2")
        self.assertEqual(record.recovery_status, STATUS_FRESH)
        self.assertEqual(record.confidence, CONFIDENCE_EXACT_REGISTER_LOCATION)

        provider.analysis = RecoveryAnalysis(
            ok=True,
            evidence_by_index={4: RecoveryEvidence(4, reason=REASON_NOT_LIVE)},
        )
        recovery.begin_pc(
            variables=[variable],
            function_ea=variable.function_start_ea,
            current_ea=0x140001020,
            runtime_pc="0x7ff600001020",
            pc_seq=11,
            envelope=_envelope,
        )
        record = recovery.records[0]
        self.assertEqual(record.value, "0x2")
        self.assertEqual(record.recovery_status, STATUS_STALE)
        self.assertEqual(record.confidence, CONFIDENCE_STALE_RUNTIME_VALUE)
        self.assertEqual(record.last_successful_pc_seq, 10)

        accepted, reason, _requests, _logs = recovery.apply_reg_response(
            {
                "pc_seq": 10,
                "request_id": "v-reg-10-runtime",
                "runtime_pc": "0x7ff600001014",
                "ok": True,
                "registers": {"r8": "0x99"},
            },
            envelope=_envelope,
        )
        self.assertFalse(accepted)
        self.assertIn("stale pc_seq", reason)
        self.assertEqual(recovery.records[0].value, "0x2")
        self.assertEqual(recovery.records[0].recovery_status, STATUS_STALE)

    def test_stack_address_exact_width_and_little_endian_response(self) -> None:
        variable = _variable(index=7, name="v7", size=4)
        provider = _Provider(
            RecoveryAnalysis(
                ok=True,
                evidence_by_index={
                    7: RecoveryEvidence(
                        7,
                        storage_kind="stack",
                        storage="stack:rsp+0x20",
                        source_ea=0x140001030,
                        confidence=CONFIDENCE_EXACT_STACK_LOCATION,
                        reason="proven",
                        stack_pointer_offset=0x20,
                    )
                },
            )
        )
        recovery = VVariableRecovery(provider)
        plan = recovery.begin_pc(
            variables=[variable],
            function_ea=variable.function_start_ea,
            current_ea=0x140001034,
            runtime_pc="0x7ff600001034",
            pc_seq=20,
            envelope=_envelope,
        )
        self.assertEqual(plan.register_request["payload"]["registers"], ["rsp"])
        accepted, reason, requests, _logs = recovery.apply_reg_response(
            {
                "pc_seq": 20,
                "request_id": "v-reg-20-runtime",
                "runtime_pc": "0x7ff600001034",
                "ok": True,
                "registers": {"rsp": "0x1000"},
            },
            envelope=_envelope,
        )
        self.assertTrue(accepted, reason)
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]["payload"]["address"], "0x1020")
        self.assertEqual(requests[0]["payload"]["size"], 4)

        accepted, reason, _logs = recovery.apply_mem_response(
            {
                "pc_seq": 20,
                "request_id": "v-mem-20-7",
                "runtime_pc": "0x7ff600001034",
                "ok": True,
                "address": "0x1024",
                "size": 4,
                "bytes_hex": "78563412",
            }
        )
        self.assertFalse(accepted)
        self.assertIn("address", reason)

        accepted, reason, _logs = recovery.apply_mem_response(
            {
                "pc_seq": 20,
                "request_id": "v-mem-20-7",
                "runtime_pc": "0x7ff600001034",
                "ok": True,
                "address": "0x1020",
                "size": 4,
                "bytes_hex": "78563412",
            }
        )
        self.assertTrue(accepted, reason)
        record = recovery.records[0]
        self.assertEqual(record.value, "0x12345678")
        self.assertEqual(record.recovery_status, STATUS_FRESH)
        self.assertEqual(record.confidence, CONFIDENCE_EXACT_STACK_LOCATION)

    def test_constant_is_fresh_without_debugger_request(self) -> None:
        variable = _variable(index=6, name="v6", size=4)
        provider = _Provider(
            RecoveryAnalysis(
                ok=True,
                evidence_by_index={
                    6: RecoveryEvidence(
                        6,
                        storage_kind="constant",
                        storage="constant:0x2",
                        source_ea=0x140001040,
                        confidence=CONFIDENCE_EXACT_CONSTANT,
                        reason="proven",
                        constant_value=2,
                    )
                },
            )
        )
        recovery = VVariableRecovery(provider)
        plan = recovery.begin_pc(
            variables=[variable],
            function_ea=variable.function_start_ea,
            current_ea=0x140001044,
            runtime_pc="0x7ff600001044",
            pc_seq=30,
            envelope=_envelope,
        )
        self.assertIsNone(plan.register_request)
        record = recovery.records[0]
        self.assertEqual(record.value, "0x2")
        self.assertEqual(record.recovery_status, STATUS_FRESH)
        self.assertEqual(record.confidence, CONFIDENCE_EXACT_CONSTANT)

    def test_microcode_failure_is_unavailable_even_with_history(self) -> None:
        variable = _variable()
        provider = _Provider(
            RecoveryAnalysis(
                ok=True,
                evidence_by_index={
                    4: RecoveryEvidence(
                        4,
                        storage_kind="constant",
                        storage="constant:0x2",
                        confidence=CONFIDENCE_EXACT_CONSTANT,
                        reason="proven",
                        constant_value=2,
                    )
                },
            )
        )
        recovery = VVariableRecovery(provider)
        recovery.begin_pc(
            variables=[variable],
            function_ea=variable.function_start_ea,
            current_ea=0x140001014,
            runtime_pc="0x7ff600001014",
            pc_seq=40,
            envelope=_envelope,
        )
        provider.analysis = RecoveryAnalysis(
            ok=False,
            evidence_by_index={},
            error="synthetic microcode exception",
        )
        recovery.begin_pc(
            variables=[variable],
            function_ea=variable.function_start_ea,
            current_ea=0x140001018,
            runtime_pc="0x7ff600001018",
            pc_seq=41,
            envelope=_envelope,
        )
        record = recovery.records[0]
        self.assertEqual(record.recovery_status, STATUS_UNAVAILABLE)
        self.assertEqual(record.value, "")
        self.assertEqual(record.reason, REASON_MICROCODE)
        self.assertEqual(record.last_successful_pc_seq, 40)

    def test_analysis_exception_is_isolated(self) -> None:
        variable = _variable()
        recovery = VVariableRecovery(_RaisingProvider())
        plan = recovery.begin_pc(
            variables=[variable],
            function_ea=variable.function_start_ea,
            current_ea=0x140001014,
            runtime_pc="0x7ff600001014",
            pc_seq=45,
            envelope=_envelope,
        )
        self.assertIsNone(plan.register_request)
        self.assertEqual(recovery.records[0].recovery_status, STATUS_UNAVAILABLE)
        self.assertEqual(recovery.records[0].reason, REASON_MICROCODE)
        self.assertTrue(any("v-microcode failure" in line for line in plan.debug_lines))

    def test_printed_register_without_evidence_sends_no_request(self) -> None:
        variable = _variable()
        provider = _Provider(RecoveryAnalysis(ok=True, evidence_by_index={}))
        recovery = VVariableRecovery(provider)
        plan = recovery.begin_pc(
            variables=[variable],
            function_ea=variable.function_start_ea,
            current_ea=0x140001014,
            runtime_pc="0x7ff600001014",
            pc_seq=50,
            envelope=_envelope,
        )
        self.assertIsNone(plan.register_request)
        self.assertEqual(recovery.records[0].recovery_status, STATUS_UNAVAILABLE)

    def test_history_fingerprint_rejects_reused_lvar_index(self) -> None:
        original = _variable(size=4, defea="0x140001010")
        provider = _Provider(
            RecoveryAnalysis(
                ok=True,
                evidence_by_index={
                    4: RecoveryEvidence(
                        4,
                        storage_kind="constant",
                        storage="constant:0x2",
                        confidence=CONFIDENCE_EXACT_CONSTANT,
                        reason="proven",
                        constant_value=2,
                    )
                },
            )
        )
        recovery = VVariableRecovery(provider)
        recovery.begin_pc(
            variables=[original],
            function_ea=original.function_start_ea,
            current_ea=0x140001014,
            runtime_pc="0x7ff600001014",
            pc_seq=60,
            envelope=_envelope,
        )
        replacement = _variable(size=8, defea="0x140001080")
        replacement.type_string = "unsigned __int64"
        provider.analysis = RecoveryAnalysis(
            ok=True,
            evidence_by_index={4: RecoveryEvidence(4, reason=REASON_NOT_LIVE)},
        )
        recovery.begin_pc(
            variables=[replacement],
            function_ea=replacement.function_start_ea,
            current_ea=0x140001084,
            runtime_pc="0x7ff600001084",
            pc_seq=61,
            envelope=_envelope,
        )
        record = recovery.records[0]
        self.assertEqual(record.recovery_status, STATUS_UNAVAILABLE)
        self.assertEqual(record.value, "")
        self.assertIsNone(record.last_successful_pc_seq)


if __name__ == "__main__":
    unittest.main()
