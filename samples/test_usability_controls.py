"""Outside-IDA tests for logging, filters, and bounded analysis selection."""

from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN_DIR = os.path.join(ROOT, "ida_plugin")
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)

from dayvar_plugin import (  # noqa: E402
    AnalysisSelectionCache,
    DayVarController,
    diagnostic_line_level,
    select_recovery_candidate_indexes,
)
from hexrays_variables import VariableRecord  # noqa: E402
from live_variables_view import (  # noqa: E402
    FILTER_ARGUMENTS,
    FILTER_FRESH,
    FILTER_NAMED_LOCALS,
    FILTER_RECOVERABLE,
    FILTER_UNAVAILABLE,
    LiveVariablesView,
    presented_status,
    row_matches_filter,
)
from v_variable_recovery import (  # noqa: E402
    CONFIDENCE_EXACT_CONSTANT,
    CONFIDENCE_EXACT_REGISTER_LOCATION,
    RecoveryAnalysis,
    RecoveryEvidence,
    VVariableRecovery,
    normalize_register_alias,
)


def _row(
    index: int,
    name: str,
    *,
    is_arg: bool = False,
    status: str = "unavailable",
    confidence: str = "unknown",
    reason: str = "",
    value: str = "",
    last_success: str = "",
) -> VariableRecord:
    return VariableRecord(
        lvar_index=index,
        name=name,
        hexrays_kind="arg" if is_arg else "local",
        type_string="unsigned int",
        size=4,
        is_arg=is_arg,
        arg_index=index if is_arg else None,
        location="unknown",
        function_ea="0x140001000",
        function_start_ea=0x140001000,
        status=status,
        confidence=confidence,
        reason=reason,
        value=value,
        last_success_value=last_success,
        lvar_defea=f"0x1400010{index:02x}",
    )


def _envelope(message_type: str, payload: dict[str, object]) -> dict[str, object]:
    return {"protocol": 1, "type": message_type, "role": "ida", "payload": payload}


class _CaptureView(LiveVariablesView):
    def __init__(self) -> None:
        super().__init__()
        self.messages: list[str] = []

    def log(self, message: str) -> None:
        self.messages.append(message)


class LoggingLevelTest(unittest.TestCase):
    def test_normal_logging_suppresses_trace_lines(self) -> None:
        controller = DayVarController(diagnostic_level="normal")
        view = _CaptureView()
        controller.view = view
        controller._emit_diagnostic_lines(
            [
                "v-cfg-point name=v1 current_block=1 current_instruction=0 current_ea=0x1",
                "v-recovery name=v1 result=unavailable source=none reason=no_reaching_definition",
                "v-recovery name=v2 result=fresh source=constant:0x2 reason=ok",
            ]
        )
        self.assertEqual(
            view.messages,
            ["v-recovery name=v2 result=fresh source=constant:0x2 reason=ok"],
        )

    def test_trace_logging_preserves_full_analysis_lines(self) -> None:
        controller = DayVarController(diagnostic_level="trace")
        view = _CaptureView()
        controller.view = view
        lines = [
            "v-cfg-point name=v1 current_block=1 current_instruction=0 current_ea=0x1",
            "v-reaching-def name=v1 def_ea=none def_block=none count=0",
            "v-storage-valid name=v1 storage=r12d result=valid reason=ok",
        ]
        controller._emit_diagnostic_lines(lines)
        self.assertEqual(view.messages, lines)
        self.assertEqual(diagnostic_line_level(lines[0]), "trace")


class LiveVariableFilterTest(unittest.TestCase):
    def test_filter_predicates(self) -> None:
        fresh = _row(
            1,
            "v1",
            status="fresh",
            confidence=CONFIDENCE_EXACT_CONSTANT,
            value="0x2",
        )
        stale = _row(2, "v2", status="stale", value="0x1")
        unavailable = _row(3, "v3", status="unavailable", reason="no_reaching_definition")
        arg = _row(0, "a1", is_arg=True, status="fresh", value="0x9")
        named = _row(4, "named_local", status="unavailable")

        self.assertTrue(row_matches_filter(fresh, FILTER_FRESH))
        self.assertTrue(row_matches_filter(fresh, FILTER_RECOVERABLE))
        self.assertTrue(row_matches_filter(stale, FILTER_RECOVERABLE))
        self.assertFalse(row_matches_filter(unavailable, FILTER_RECOVERABLE))
        self.assertTrue(row_matches_filter(arg, FILTER_ARGUMENTS))
        self.assertTrue(row_matches_filter(named, FILTER_NAMED_LOCALS))
        self.assertFalse(row_matches_filter(fresh, FILTER_NAMED_LOCALS))
        self.assertTrue(row_matches_filter(unavailable, FILTER_UNAVAILABLE))

    def test_active_filter_preserves_underlying_state(self) -> None:
        view = _CaptureView()
        rows = [
            _row(1, "v1", status="fresh", confidence=CONFIDENCE_EXACT_CONSTANT, value="0x2"),
            _row(2, "v2", status="unavailable"),
        ]
        view.update_rows(rows)
        view.set_filter(FILTER_FRESH)
        self.assertEqual(len(view.all_rows), 2)
        self.assertEqual([row.name for row in view.rows], ["v1"])

        updated = [
            _row(1, "v1", status="unavailable"),
            _row(2, "v2", status="fresh", confidence=CONFIDENCE_EXACT_CONSTANT, value="0x3"),
        ]
        view.update_rows(updated)
        self.assertEqual(view.active_filter, FILTER_FRESH)
        self.assertEqual(len(view.all_rows), 2)
        self.assertEqual([row.name for row in view.rows], ["v2"])

    def test_presented_status_labels_are_conservative(self) -> None:
        self.assertEqual(
            presented_status(
                _row(1, "v1", status="fresh", confidence=CONFIDENCE_EXACT_CONSTANT)
            ),
            "exact",
        )
        self.assertEqual(presented_status(_row(2, "v2", status="stale")), "stale / last observed")
        self.assertEqual(
            presented_status(_row(3, "v3", reason="ambiguous_reaching_definition")),
            "ambiguous",
        )
        self.assertEqual(
            presented_status(_row(4, "v4", reason="unsupported_scattered_location")),
            "unsupported storage",
        )


class AnalysisSelectionTest(unittest.TestCase):
    def test_bounded_candidate_selection_rotates_for_discovery(self) -> None:
        variables = [_row(index, f"v{index}") for index in range(1, 6)]
        selected, cursor = select_recovery_candidate_indexes(
            variables=variables,
            previous_rows=[],
            active_filter="All",
            max_candidates=2,
            fallback_cursor=0,
        )
        self.assertEqual(selected, {1, 2})

        selected, _cursor = select_recovery_candidate_indexes(
            variables=variables,
            previous_rows=[],
            active_filter="All",
            max_candidates=2,
            fallback_cursor=cursor,
        )
        self.assertEqual(selected, {3, 4})

    def test_fresh_and_stale_variables_remain_prioritized(self) -> None:
        variables = [_row(index, f"v{index}") for index in range(1, 5)]
        previous = [
            _row(3, "v3", status="fresh", value="0x3"),
            _row(4, "v4", status="stale", value="0x4"),
        ]
        selected, _cursor = select_recovery_candidate_indexes(
            variables=variables,
            previous_rows=previous,
            active_filter=FILTER_NAMED_LOCALS,
            max_candidates=2,
            fallback_cursor=0,
        )
        self.assertEqual(selected, {3, 4})

    def test_cache_invalidation(self) -> None:
        cache = AnalysisSelectionCache()
        variables = [_row(index, f"v{index}") for index in range(1, 4)]
        selected = cache.select(
            pc_seq=1,
            function_ea=0x140001000,
            current_ea=0x140001010,
            variables=variables,
            previous_rows=[],
            active_filter="All",
            watched_lvar_indexes=set(),
            max_candidates=1,
        )
        self.assertEqual(selected, {1})
        self.assertIsNotNone(cache.key)
        self.assertTrue(cache.cursor_by_function)

        cache.invalidate(clear_cursors=True)
        self.assertIsNone(cache.key)
        self.assertEqual(cache.indexes, ())
        self.assertEqual(cache.cursor_by_function, {})


class StaleCorrelationRegressionTest(unittest.TestCase):
    def test_stale_response_rejection_remains_intact_with_bounded_selection(self) -> None:
        variable = _row(7, "v7")
        spec = normalize_register_alias("r8d")
        assert spec is not None
        recovery = VVariableRecovery(
            lambda *_args: RecoveryAnalysis(
                ok=True,
                evidence_by_index={
                    7: RecoveryEvidence(
                        7,
                        storage_kind="register",
                        storage="r8d",
                        confidence=CONFIDENCE_EXACT_REGISTER_LOCATION,
                        register=spec,
                        width=4,
                    )
                },
            )
        )
        recovery.begin_pc(
            variables=[variable],
            function_ea=variable.function_start_ea,
            current_ea=0x140001010,
            runtime_pc="0x7ff600001010",
            pc_seq=10,
            envelope=_envelope,
            analysis_lvar_indexes={7},
        )
        recovery.begin_pc(
            variables=[variable],
            function_ea=variable.function_start_ea,
            current_ea=0x140001014,
            runtime_pc="0x7ff600001014",
            pc_seq=11,
            envelope=_envelope,
            analysis_lvar_indexes=set(),
        )
        accepted, reason, _requests, _logs = recovery.apply_reg_response(
            {
                "pc_seq": 10,
                "request_id": "v-reg-10-runtime",
                "runtime_pc": "0x7ff600001010",
                "ok": True,
                "registers": {"r8": "0x2"},
            },
            envelope=_envelope,
        )
        self.assertFalse(accepted)
        self.assertIn("stale pc_seq", reason)


if __name__ == "__main__":
    unittest.main()
