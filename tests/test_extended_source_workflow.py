"""Explicit opt-in real native-context, C# and Python defender MCP workflow."""
from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest

from antirea.defense_mcp import DefenseBridge


@unittest.skipUnless(os.environ.get("ANTIREA_RUN_EXTENDED_SOURCE_E2E") == "1",
                     "explicit owned-source compiler/execution opt-in required")
class ExtendedSourceWorkflowTests(unittest.TestCase):
    def exercise(self, fixture, backend):
        root = Path(__file__).resolve().parents[1]
        bridge = DefenseBridge(SimpleNamespace(root=root))
        response = bridge.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "owned-extended-source-e2e", "version": "1"}}})
        self.assertIn("result", response)
        bridge.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
        def call(name, **arguments):
            reply = bridge.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                   "params": {"name": name, "arguments": arguments}})
            self.assertNotIn("error", reply, reply)
            payload = json.loads(reply["result"]["content"][0]["text"])
            self.assertFalse(reply["result"]["isError"], payload)
            return payload
        plan = call("protection_source_plan", project_path=str(root / fixture / "project.json"))
        self.assertEqual(plan["status"], "planned")
        built = call("protection_source_build", plan_id=plan["plan_id"], fingerprint=plan["fingerprint"])
        self.assertEqual(built["status"], "artifact_created_unvalidated")
        if backend:
            self.assertEqual(built["backend"], backend)
        validated = call("protection_source_validate", plan_id=plan["plan_id"],
                         contract_path=str(root / fixture / "contract.json"), random_cases=8192,
                         timeout_seconds=180)
        self.assertEqual(validated["status"], "functional_samples_passed", validated)
        record = {"schema_version": 1, "status": "passed", "fixture": fixture, "backend": backend,
                  "plan_id": plan["plan_id"], "build_report": str(Path(plan["output_dir"]) / "report.json"),
                  "validation_id": validated["validation_id"],
                  "cases_per_function": validated["cases_per_function"],
                  "behavior_repeats": validated["behavior_repeats"],
                  "external_attack_evaluation": "not_evaluated"}
        output = Path(plan["output_dir"]).parent / "extended-e2e.json"
        with output.open("x", encoding="utf-8") as stream:
            json.dump(record, stream, indent=2)
        print(json.dumps(record))

    def test_context_public_entry_observes_four_internal_vm_functions(self):
        self.exercise("samples/multilang/native/context", None)

    def test_actual_csharp_source_via_il_to_native_vm(self):
        self.exercise("samples/multilang/dotnet", "dotnet_il_native")

    def test_actual_python_source_via_python_vm(self):
        self.exercise("samples/multilang/python", "python_vm")


if __name__ == "__main__":
    unittest.main()
