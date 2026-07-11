"""Outside-IDA tests for CFG-aware lvar and register-storage proofs."""

from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN_DIR = os.path.join(ROOT, "ida_plugin")
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)

from hexrays_variables import VariableRecord  # noqa: E402
from dayvar_plugin import DayVarController  # noqa: E402
from dynvar_core import CONFIDENCE_EXACT_ENTRY, DayVarCore  # noqa: E402
from v_variable_recovery import (  # noqa: E402
    CONFIDENCE_EXACT_REGISTER_LOCATION,
    CONFIDENCE_STALE_RUNTIME_VALUE,
    REASON_AMBIGUOUS_REACHING_DEFINITION,
    REASON_CROSS_BLOCK_LIVENESS_UNPROVEN,
    REASON_NO_DEFINITION,
    REASON_STORAGE_CLOBBERED,
    RecoveryAnalysis,
    RecoveryEvidence,
    STATUS_FRESH,
    STATUS_STALE,
    VVariableRecovery,
    _CfgBlockFacts,
    _CfgInstructionFact,
    _NativeBlockFacts,
    _NativeInstructionFact,
    _RegisterWrite,
    _find_future_uses,
    _find_reaching_definitions,
    _future_use_rejection_reason,
    _reaching_definition_rejection_reason,
    _validate_cfg_reciprocity,
    _validate_register_storage_cfg,
    normalize_register_alias,
)


def _event(
    ea: int,
    *,
    definition: bool = False,
    overlap: bool = False,
    use: bool = False,
) -> _CfgInstructionFact:
    return _CfgInstructionFact(
        ea=ea,
        whole_definition=definition,
        overlapping_definition=overlap,
        use=use,
    )


def _block(
    block_id: int,
    *events: _CfgInstructionFact,
    predecessors: tuple[int, ...] = (),
    successors: tuple[int, ...] = (),
) -> _CfgBlockFacts:
    return _CfgBlockFacts(block_id, events, predecessors, successors)


class ReachingDefinitionCfgTest(unittest.TestCase):
    def test_nonreciprocal_cfg_is_rejected(self) -> None:
        blocks = {
            0: _block(0, _event(0x100), successors=(1,)),
            1: _block(1, _event(0x110)),
        }
        with self.assertRaises(RuntimeError):
            _validate_cfg_reciprocity(blocks, "synthetic")

    def test_definition_at_current_instruction_has_not_executed(self) -> None:
        blocks = {0: _block(0, _event(0x100, definition=True))}
        result = _find_reaching_definitions(blocks, 0, 0)
        self.assertEqual(result.count, 0)
        self.assertEqual(
            _reaching_definition_rejection_reason(result),
            REASON_NO_DEFINITION,
        )

    def test_one_definition_in_current_block(self) -> None:
        blocks = {
            0: _block(
                0,
                _event(0x100, definition=True),
                _event(0x104),
                _event(0x108, use=True),
            )
        }
        result = _find_reaching_definitions(blocks, 0, 1)
        self.assertEqual(result.count, 1)
        self.assertEqual(result.definitions[0].ea, 0x100)
        self.assertIsNone(_reaching_definition_rejection_reason(result))

    def test_one_definition_in_predecessor_block(self) -> None:
        blocks = {
            0: _block(0, _event(0x100, definition=True), successors=(1,)),
            1: _block(1, _event(0x110), predecessors=(0,)),
        }
        result = _find_reaching_definitions(blocks, 1, 0)
        self.assertEqual(result.count, 1)
        self.assertEqual(result.definitions[0].block_id, 0)
        self.assertEqual(result.definitions[0].ea, 0x100)

    def test_two_predecessor_definitions_are_ambiguous(self) -> None:
        blocks = {
            0: _block(0, _event(0x100, definition=True), successors=(2,)),
            1: _block(1, _event(0x104, definition=True), successors=(2,)),
            2: _block(2, _event(0x110), predecessors=(0, 1)),
        }
        result = _find_reaching_definitions(blocks, 2, 0)
        self.assertEqual(result.count, 2)
        self.assertEqual(
            _reaching_definition_rejection_reason(result),
            REASON_AMBIGUOUS_REACHING_DEFINITION,
        )

    def test_redefinition_before_current_pc_kills_older_definition(self) -> None:
        blocks = {
            0: _block(
                0,
                _event(0x100, definition=True),
                _event(0x104, definition=True),
                _event(0x108),
            )
        }
        result = _find_reaching_definitions(blocks, 0, 2)
        self.assertEqual(result.count, 1)
        self.assertEqual(result.definitions[0].ea, 0x104)

    def test_overlapping_definition_is_ambiguous(self) -> None:
        blocks = {
            0: _block(
                0,
                _event(0x100, definition=True),
                _event(0x104, overlap=True),
                _event(0x108),
            )
        }
        result = _find_reaching_definitions(blocks, 0, 2)
        self.assertTrue(result.overlapping_definition)
        self.assertEqual(
            _reaching_definition_rejection_reason(result),
            REASON_AMBIGUOUS_REACHING_DEFINITION,
        )

    def test_diamond_deduplicates_one_dominating_definition(self) -> None:
        blocks = {
            0: _block(0, _event(0x100, definition=True), successors=(1, 2)),
            1: _block(1, _event(0x108), predecessors=(0,), successors=(3,)),
            2: _block(2, _event(0x10C), predecessors=(0,), successors=(3,)),
            3: _block(3, _event(0x110), predecessors=(1, 2)),
        }
        result = _find_reaching_definitions(blocks, 3, 0)
        self.assertEqual(result.count, 1)
        self.assertEqual(result.definitions[0].ea, 0x100)

    def test_one_definition_plus_undefined_path_is_not_usable(self) -> None:
        blocks = {
            0: _block(0, _event(0x100, definition=True), successors=(2,)),
            1: _block(1, _event(0x104), successors=(2,)),
            2: _block(2, _event(0x110), predecessors=(0, 1)),
        }
        result = _find_reaching_definitions(blocks, 2, 0)
        self.assertEqual(result.count, 1)
        self.assertTrue(result.unresolved_path)
        self.assertEqual(
            _reaching_definition_rejection_reason(result),
            REASON_NO_DEFINITION,
        )

    def test_successor_definition_does_not_reach_current_pc(self) -> None:
        blocks = {
            0: _block(
                0,
                _event(0x100, definition=True),
                _event(0x104),
                successors=(1,),
            ),
            1: _block(
                1,
                _event(0x110),
                _event(0x114, definition=True),
                predecessors=(0,),
            ),
        }
        result = _find_reaching_definitions(blocks, 0, 1)
        self.assertEqual(result.count, 1)
        self.assertEqual(result.definitions[0].ea, 0x100)
        self.assertIsNone(_reaching_definition_rejection_reason(result))

    def test_backward_loop_terminates_conservatively(self) -> None:
        blocks = {
            0: _block(0, _event(0x100), predecessors=(1,), successors=(1,)),
            1: _block(1, _event(0x110), predecessors=(0,), successors=(0,)),
        }
        result = _find_reaching_definitions(blocks, 0, 0, max_states=8)
        self.assertEqual(result.count, 0)
        self.assertTrue(result.loop_detected)
        self.assertLessEqual(result.visited_states, 3)


class FutureUseCfgTest(unittest.TestCase):
    def test_use_at_current_instruction_is_live(self) -> None:
        blocks = {0: _block(0, _event(0x100, use=True))}
        result = _find_future_uses(blocks, 0, 0)
        self.assertTrue(result.has_use)
        self.assertFalse(result.use_sites[0].crossed_block)

    def test_future_use_in_successor_block(self) -> None:
        blocks = {
            0: _block(0, _event(0x100), successors=(1,)),
            1: _block(1, _event(0x110, use=True), predecessors=(0,)),
        }
        result = _find_future_uses(blocks, 0, 0)
        self.assertTrue(result.has_use)
        self.assertEqual(result.use_sites[0].block_id, 1)
        self.assertIsNone(_future_use_rejection_reason(result))

    def test_redefinition_ends_only_that_future_path(self) -> None:
        blocks = {
            0: _block(0, _event(0x100), successors=(1, 2)),
            1: _block(1, _event(0x110, definition=True), predecessors=(0,)),
            2: _block(2, _event(0x120, use=True), predecessors=(0,)),
        }
        result = _find_future_uses(blocks, 0, 0)
        self.assertTrue(result.has_use)
        self.assertEqual(result.redefinition_paths, 1)

    def test_forward_loop_without_use_terminates_unproven(self) -> None:
        blocks = {
            0: _block(0, _event(0x100), predecessors=(1,), successors=(1,)),
            1: _block(1, _event(0x110), predecessors=(0,), successors=(0,)),
        }
        result = _find_future_uses(blocks, 0, 0, max_states=8)
        self.assertFalse(result.has_use)
        self.assertTrue(result.loop_detected)
        self.assertEqual(
            _future_use_rejection_reason(result),
            REASON_CROSS_BLOCK_LIVENESS_UNPROVEN,
        )


class NativeRegisterStorageCfgTest(unittest.TestCase):
    def setUp(self) -> None:
        spec = normalize_register_alias("r12d")
        assert spec is not None
        self.spec = spec

    def test_register_clobber_before_current_pc_is_rejected(self) -> None:
        blocks = {
            0: _NativeBlockFacts(
                0,
                0x100,
                0x10C,
                (
                    _NativeInstructionFact(
                        0x100,
                        4,
                        writes=(_RegisterWrite("r12", 0, 64),),
                    ),
                    _NativeInstructionFact(
                        0x104,
                        4,
                        writes=(_RegisterWrite("r12", 0, 16),),
                    ),
                    _NativeInstructionFact(0x108, 4),
                ),
            )
        }
        result = _validate_register_storage_cfg(
            blocks,
            0x100,
            0x108,
            self.spec,
            4,
        )
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, REASON_STORAGE_CLOBBERED)
        self.assertEqual(result.clobber_ea, 0x104)

    def test_current_instruction_clobber_has_not_executed(self) -> None:
        blocks = {
            0: _NativeBlockFacts(
                0,
                0x100,
                0x108,
                (
                    _NativeInstructionFact(
                        0x100,
                        4,
                        writes=(_RegisterWrite("r12", 0, 64),),
                    ),
                    _NativeInstructionFact(
                        0x104,
                        4,
                        writes=(_RegisterWrite("r12", 0, 8),),
                    ),
                ),
            )
        }
        result = _validate_register_storage_cfg(
            blocks,
            0x100,
            0x104,
            self.spec,
            4,
        )
        self.assertTrue(result.valid, result.reason)

    def test_definition_in_native_predecessor_block_is_valid(self) -> None:
        blocks = {
            0: _NativeBlockFacts(
                0,
                0x100,
                0x108,
                (
                    _NativeInstructionFact(
                        0x100,
                        4,
                        writes=(_RegisterWrite("r12", 0, 64),),
                    ),
                    _NativeInstructionFact(0x104, 4),
                ),
                successors=(1,),
            ),
            1: _NativeBlockFacts(
                1,
                0x110,
                0x114,
                (_NativeInstructionFact(0x110, 4),),
                predecessors=(0,),
            ),
        }
        result = _validate_register_storage_cfg(
            blocks,
            0x100,
            0x110,
            self.spec,
            4,
        )
        self.assertTrue(result.valid, result.reason)

    def test_one_clobbered_predecessor_path_rejects_storage(self) -> None:
        blocks = {
            0: _NativeBlockFacts(
                0,
                0x100,
                0x104,
                (
                    _NativeInstructionFact(
                        0x100,
                        4,
                        writes=(_RegisterWrite("r12", 0, 64),),
                    ),
                ),
                successors=(1, 2),
            ),
            1: _NativeBlockFacts(
                1,
                0x110,
                0x114,
                (_NativeInstructionFact(0x110, 4),),
                predecessors=(0,),
                successors=(3,),
            ),
            2: _NativeBlockFacts(
                2,
                0x120,
                0x124,
                (
                    _NativeInstructionFact(
                        0x120,
                        4,
                        writes=(_RegisterWrite("r12", 0, 8),),
                    ),
                ),
                predecessors=(0,),
                successors=(3,),
            ),
            3: _NativeBlockFacts(
                3,
                0x130,
                0x134,
                (_NativeInstructionFact(0x130, 4),),
                predecessors=(1, 2),
            ),
        }
        result = _validate_register_storage_cfg(
            blocks,
            0x100,
            0x130,
            self.spec,
            4,
        )
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, REASON_STORAGE_CLOBBERED)
        self.assertEqual(result.clobber_ea, 0x120)


def _variable(index: int, name: str) -> VariableRecord:
    return VariableRecord(
        lvar_index=index,
        name=name,
        hexrays_kind="temporary",
        type_string="unsigned int",
        size=4,
        is_arg=False,
        arg_index=None,
        location="r12d",
        function_ea="0x1406d3400",
        function_start_ea=0x1406D3400,
        printed_location="r12d",
        lvar_defea="0x1406d3498",
    )


def _envelope(message_type: str, payload: dict[str, object]) -> dict[str, object]:
    return {"protocol": 1, "type": message_type, "role": "ida", "payload": payload}


class _MutableProvider:
    def __init__(self, analysis: RecoveryAnalysis) -> None:
        self.analysis = analysis

    def __call__(self, *_args: object, **_kwargs: object) -> RecoveryAnalysis:
        return self.analysis


class R12RuntimeStateTest(unittest.TestCase):
    def test_full_r12_request_masking_stale_history_and_old_response(self) -> None:
        v10 = _variable(10, "v10")
        v11 = _variable(11, "v11")
        spec = normalize_register_alias("r12d")
        assert spec is not None
        provider = _MutableProvider(
            RecoveryAnalysis(
                ok=True,
                evidence_by_index={
                    10: RecoveryEvidence(
                        10,
                        storage_kind="register",
                        storage="r12d",
                        source_ea=0x1406D3498,
                        confidence=CONFIDENCE_EXACT_REGISTER_LOCATION,
                        reason="proven",
                        register=spec,
                        width=4,
                    )
                },
            )
        )
        recovery = VVariableRecovery(provider)
        plan = recovery.begin_pc(
            variables=[v10],
            function_ea=v10.function_start_ea,
            current_ea=0x1406D349B,
            runtime_pc="0xfffff8001406d349b",
            pc_seq=70,
            envelope=_envelope,
        )
        assert plan.register_request is not None
        self.assertEqual(plan.register_request["payload"]["registers"], ["r12"])
        self.assertTrue(
            any(
                "v-recovery name=v10 result=pending source=register:r12d" in line
                for line in plan.debug_lines
            )
        )
        accepted, reason, _requests, _logs = recovery.apply_reg_response(
            {
                "pc_seq": 70,
                "request_id": "v-reg-70-runtime",
                "runtime_pc": "0xfffff8001406d349b",
                "ok": True,
                "registers": {"r12": "0xdeadbeef00000000"},
            },
            envelope=_envelope,
        )
        self.assertTrue(accepted, reason)
        self.assertEqual(recovery.records[0].value, "0x0")
        self.assertEqual(recovery.records[0].recovery_status, STATUS_FRESH)
        self.assertEqual(recovery.records[0].storage, "r12d")
        self.assertEqual(recovery.records[0].source_ea, 0x1406D3498)

        provider.analysis = RecoveryAnalysis(
            ok=True,
            evidence_by_index={
                10: RecoveryEvidence(10, reason=REASON_STORAGE_CLOBBERED),
                11: RecoveryEvidence(
                    11,
                    storage_kind="register",
                    storage="r12d",
                    source_ea=0x1406D3500,
                    confidence=CONFIDENCE_EXACT_REGISTER_LOCATION,
                    reason="proven replacement",
                    register=spec,
                    width=4,
                ),
            },
        )
        plan = recovery.begin_pc(
            variables=[v10, v11],
            function_ea=v10.function_start_ea,
            current_ea=0x1406D3504,
            runtime_pc="0xfffff8001406d3504",
            pc_seq=71,
            envelope=_envelope,
        )
        assert plan.register_request is not None
        self.assertEqual(recovery.records[0].recovery_status, STATUS_STALE)
        self.assertEqual(
            recovery.records[0].confidence,
            CONFIDENCE_STALE_RUNTIME_VALUE,
        )

        accepted, reason, _requests, _logs = recovery.apply_reg_response(
            {
                "pc_seq": 70,
                "request_id": "v-reg-71-runtime",
                "runtime_pc": "0xfffff8001406d3504",
                "ok": True,
                "registers": {"r12": "0x99"},
            },
            envelope=_envelope,
        )
        self.assertFalse(accepted)
        self.assertIn("stale pc_seq", reason)

        accepted, reason, _requests, _logs = recovery.apply_reg_response(
            {
                "pc_seq": 71,
                "request_id": "v-reg-71-runtime",
                "runtime_pc": "0xfffff8001406d3504",
                "ok": True,
                "registers": {"r12": "0x12345678"},
            },
            envelope=_envelope,
        )
        self.assertTrue(accepted, reason)
        records = {record.lvar_index: record for record in recovery.records}
        self.assertEqual(records[10].value, "0x0")
        self.assertEqual(records[10].recovery_status, STATUS_STALE)
        self.assertEqual(records[11].value, "0x12345678")
        self.assertEqual(records[11].recovery_status, STATUS_FRESH)

    def test_same_v10_updates_through_a_new_proven_definition(self) -> None:
        v10 = _variable(10, "v10")
        spec = normalize_register_alias("r12d")
        assert spec is not None
        provider = _MutableProvider(
            RecoveryAnalysis(
                ok=True,
                evidence_by_index={
                    10: RecoveryEvidence(
                        10,
                        storage_kind="register",
                        storage="r12d",
                        source_ea=0x1406D3498,
                        confidence=CONFIDENCE_EXACT_REGISTER_LOCATION,
                        reason="first definition",
                        register=spec,
                        width=4,
                    )
                },
            )
        )
        recovery = VVariableRecovery(provider)
        recovery.begin_pc(
            variables=[v10],
            function_ea=v10.function_start_ea,
            current_ea=0x1406D349B,
            runtime_pc="0xfffff8001406d349b",
            pc_seq=90,
            envelope=_envelope,
        )
        accepted, reason, _requests, _logs = recovery.apply_reg_response(
            {
                "pc_seq": 90,
                "request_id": "v-reg-90-runtime",
                "runtime_pc": "0xfffff8001406d349b",
                "ok": True,
                "registers": {"r12": "0x1"},
            },
            envelope=_envelope,
        )
        self.assertTrue(accepted, reason)

        provider.analysis = RecoveryAnalysis(
            ok=True,
            evidence_by_index={
                10: RecoveryEvidence(
                    10,
                    storage_kind="register",
                    storage="r12d",
                    source_ea=0x1406D3510,
                    confidence=CONFIDENCE_EXACT_REGISTER_LOCATION,
                    reason="second definition",
                    register=spec,
                    width=4,
                )
            },
        )
        recovery.begin_pc(
            variables=[v10],
            function_ea=v10.function_start_ea,
            current_ea=0x1406D3514,
            runtime_pc="0xfffff8001406d3514",
            pc_seq=91,
            envelope=_envelope,
        )
        accepted, reason, _requests, _logs = recovery.apply_reg_response(
            {
                "pc_seq": 91,
                "request_id": "v-reg-91-runtime",
                "runtime_pc": "0xfffff8001406d3514",
                "ok": True,
                "registers": {"r12": "0x2"},
            },
            envelope=_envelope,
        )
        self.assertTrue(accepted, reason)
        record = recovery.records[0]
        self.assertEqual(record.value, "0x2")
        self.assertEqual(record.source_ea, 0x1406D3510)
        self.assertEqual(record.last_successful_pc_seq, 91)


class MappingFailureCorrelationTest(unittest.TestCase):
    def test_new_unmapped_pc_invalidates_old_v_request(self) -> None:
        v10 = _variable(10, "v10")
        spec = normalize_register_alias("r12d")
        assert spec is not None
        provider = _MutableProvider(
            RecoveryAnalysis(
                ok=True,
                evidence_by_index={
                    10: RecoveryEvidence(
                        10,
                        storage_kind="register",
                        storage="r12d",
                        source_ea=0x1406D3498,
                        confidence=CONFIDENCE_EXACT_REGISTER_LOCATION,
                        reason="proven",
                        register=spec,
                        width=4,
                    )
                },
            )
        )
        controller = DayVarController()
        controller.v_recovery = VVariableRecovery(provider)
        controller.core.start_pc_context(
            pc_seq=80,
            runtime_pc="0xfffff8001406d349b",
            ida_ea="0x1406d349b",
        )
        controller.v_recovery.begin_pc(
            variables=[v10],
            function_ea=v10.function_start_ea,
            current_ea=0x1406D349B,
            runtime_pc="0xfffff8001406d349b",
            pc_seq=80,
            envelope=_envelope,
        )
        sent: list[dict[str, object]] = []
        controller._send = sent.append  # type: ignore[method-assign]
        controller._handle_pc_update(
            {
                "auto_live": True,
                "pc_seq": 81,
                "pc": "0xfffff8001406d3500",
                "module": "nt",
                # Deliberately omit runtime_module_base so mapping fails.
            }
        )
        self.assertEqual(controller.core.current_pc.pc_seq, 81)
        self.assertEqual(sent[0]["payload"]["pc_seq"], 81)
        self.assertFalse(sent[0]["payload"]["ok"])

        accepted, reason, _requests, _logs = controller.v_recovery.apply_reg_response(
            {
                "pc_seq": 80,
                "request_id": "v-reg-80-runtime",
                "runtime_pc": "0xfffff8001406d349b",
                "ok": True,
                "registers": {"r12": "0x99"},
            },
            envelope=_envelope,
        )
        self.assertFalse(accepted)
        self.assertIn("stale pc_seq", reason)


class ArgumentNamespaceIntegrationTest(unittest.TestCase):
    def test_entry_argument_and_v_requests_remain_independent(self) -> None:
        argument = VariableRecord(
            lvar_index=0,
            name="a1",
            hexrays_kind="arg",
            type_string="unsigned __int64",
            size=8,
            is_arg=True,
            arg_index=0,
            location="rcx",
            function_ea="0x1406d3400",
            function_start_ea=0x1406D3400,
        )
        v10 = _variable(10, "v10")
        spec = normalize_register_alias("r12d")
        assert spec is not None
        provider = _MutableProvider(
            RecoveryAnalysis(
                ok=True,
                evidence_by_index={
                    10: RecoveryEvidence(
                        10,
                        storage_kind="register",
                        storage="r12d",
                        source_ea=0x1406D3498,
                        confidence=CONFIDENCE_EXACT_REGISTER_LOCATION,
                        reason="proven",
                        register=spec,
                        width=4,
                    )
                },
            )
        )
        core = DayVarCore()
        recovery = VVariableRecovery(provider)
        argument_plan = core.build_entry_plan(
            variables=[argument, v10],
            pc_seq=100,
            runtime_pc="0xfffff8001406d3400",
            ida_ea="0x1406d3400",
            function_ea="0x1406d3400",
            at_function_entry=True,
        )
        v_plan = recovery.begin_pc(
            variables=[argument, v10],
            function_ea=0x1406D3400,
            current_ea=0x1406D3400,
            runtime_pc="0xfffff8001406d3400",
            pc_seq=100,
            envelope=core.envelope,
        )
        assert argument_plan.register_request is not None
        assert v_plan.register_request is not None
        self.assertEqual(
            argument_plan.register_request["payload"]["request_id"],
            "reg-100-entry",
        )
        self.assertEqual(
            v_plan.register_request["payload"]["request_id"],
            "v-reg-100-runtime",
        )

        accepted, reason, _mem_requests = core.apply_reg_response(
            {
                "pc_seq": 100,
                "request_id": "reg-100-entry",
                "runtime_pc": "0xfffff8001406d3400",
                "ok": True,
                "registers": {"rcx": "0x1122334455667788"},
            }
        )
        self.assertTrue(accepted, reason)
        accepted, reason, _requests, _logs = recovery.apply_reg_response(
            {
                "pc_seq": 100,
                "request_id": "v-reg-100-runtime",
                "runtime_pc": "0xfffff8001406d3400",
                "ok": True,
                "registers": {"r12": "0x2"},
            },
            envelope=core.envelope,
        )
        self.assertTrue(accepted, reason)

        rows = {row.lvar_index: row for row in recovery.overlay_rows(core.rows)}
        self.assertEqual(rows[0].value, "0x1122334455667788")
        self.assertEqual(rows[0].confidence, CONFIDENCE_EXACT_ENTRY)
        self.assertEqual(rows[10].value, "0x2")
        self.assertEqual(rows[10].confidence, CONFIDENCE_EXACT_REGISTER_LOCATION)


if __name__ == "__main__":
    unittest.main()
