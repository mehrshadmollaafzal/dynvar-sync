"""Regression tests for the unchanged exact-entry argument path."""

from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN_DIR = os.path.join(ROOT, "ida_plugin")
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)

from dynvar_core import (  # noqa: E402
    CONFIDENCE_EXACT_ENTRY,
    CONFIDENCE_STALE_ENTRY_VALUE,
    DayVarCore,
    STATUS_FRESH,
    STATUS_STALE,
)
from hexrays_variables import VariableRecord  # noqa: E402


def _arg(index: int, size: int = 8) -> VariableRecord:
    return VariableRecord(
        lvar_index=index,
        name=f"a{index + 1}",
        hexrays_kind="arg",
        type_string="unsigned __int64",
        size=size,
        is_arg=True,
        arg_index=index,
        location="unknown",
        function_ea="0x140001000",
        function_start_ea=0x140001000,
    )


class ArgumentRegressionTest(unittest.TestCase):
    def test_entry_register_stack_and_stale_transition(self) -> None:
        core = DayVarCore()
        variables = [_arg(0, 4), _arg(4, 4)]
        plan = core.build_entry_plan(
            variables=variables,
            pc_seq=1,
            runtime_pc="0x7ff600001000",
            ida_ea="0x140001000",
            function_ea="0x140001000",
            at_function_entry=True,
        )
        self.assertEqual(
            plan.register_request["payload"]["registers"],
            ["rcx", "rsp"],
        )
        accepted, reason, mem_requests = core.apply_reg_response(
            {
                "pc_seq": 1,
                "request_id": "reg-1-entry",
                "runtime_pc": "0x7ff600001000",
                "ok": True,
                "registers": {
                    "rcx": "0xffffffff12345678",
                    "rsp": "0x1000",
                },
            }
        )
        self.assertTrue(accepted, reason)
        self.assertEqual(core.rows[0].value, "0x12345678")
        self.assertEqual(core.rows[0].status, STATUS_FRESH)
        self.assertEqual(core.rows[0].confidence, CONFIDENCE_EXACT_ENTRY)
        self.assertEqual(mem_requests[0]["payload"]["address"], "0x1028")
        self.assertEqual(mem_requests[0]["payload"]["size"], 4)

        accepted, reason = core.apply_mem_response(
            {
                "pc_seq": 1,
                "request_id": "mem-1-a5",
                "runtime_pc": "0x7ff600001000",
                "ok": True,
                "bytes_hex": "78563412",
            }
        )
        self.assertTrue(accepted, reason)
        self.assertEqual(core.rows[1].value, "0x12345678")

        next_plan = core.build_entry_plan(
            variables=variables,
            pc_seq=2,
            runtime_pc="0x7ff600001004",
            ida_ea="0x140001004",
            function_ea="0x140001000",
            at_function_entry=False,
        )
        self.assertIsNone(next_plan.register_request)
        for row in core.rows:
            self.assertEqual(row.status, STATUS_STALE)
            self.assertEqual(row.confidence, CONFIDENCE_STALE_ENTRY_VALUE)

        accepted, reason, _requests = core.apply_reg_response(
            {
                "pc_seq": 1,
                "request_id": "reg-1-entry",
                "runtime_pc": "0x7ff600001000",
                "ok": True,
                "registers": {"rcx": "0x99", "rsp": "0x1000"},
            }
        )
        self.assertFalse(accepted)
        self.assertIn("stale pc_seq", reason)
        self.assertEqual(core.rows[0].value, "0x12345678")


if __name__ == "__main__":
    unittest.main()
