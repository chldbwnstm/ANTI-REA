"""Opt-in source MCP E2E on repository-owned arithmetic code, never an attack."""
from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest

from antirea.defense_mcp import DefenseBridge


@unittest.skipUnless(os.environ.get("ANTIREA_RUN_SOURCE_E2E") == "1", "explicit owned-source compiler/execution opt-in required")
class SourceMcpEndToEnd(unittest.TestCase):
    def test_plan_build_validate_and_generate_bindings(self):
        root = Path(__file__).resolve().parents[1]
        bridge = DefenseBridge(SimpleNamespace(root=root))
        initialize = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "owned-source-e2e", "version": "1"}}}
        self.assertIn("result", bridge.handle(initialize))
        bridge.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
        def call(name, **arguments):
            reply = bridge.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                   "params": {"name": name, "arguments": arguments}})
            self.assertNotIn("error", reply, reply)
            payload = json.loads(reply["result"]["content"][0]["text"])
            self.assertFalse(reply["result"]["isError"], payload)
            return payload
        plan = call("protection_source_plan", project_path=str(root / "samples/multilang/native/c/project.json"))
        self.assertEqual(plan["status"], "planned")
        built = call("protection_source_build", plan_id=plan["plan_id"], fingerprint=plan["fingerprint"])
        self.assertEqual(built["status"], "artifact_created_unvalidated")
        self.assertTrue(built["coverage"]["functions"]["native_transform"]["virtualized"])
        contract = str(root / "samples/multilang/native/contract.json")
        validated = call("protection_source_validate", plan_id=plan["plan_id"], contract_path=contract, random_cases=256)
        self.assertEqual(validated["status"], "functional_samples_passed")
        self.assertTrue(validated["functions"]["native_transform"]["sampled_output_match"])
        bindings = call("protection_bindings", contract_path=contract)
        self.assertEqual(bindings["status"], "bindings_generated_unvalidated")
        self.assertFalse(bindings["source_protection"])
        record = {"schema_version": 1, "status": "passed", "plan_id": plan["plan_id"],
                  "build_report": str(Path(plan["output_dir"]) / "report.json"),
                  "validation_id": validated["validation_id"], "bindings_job": bindings["job_id"],
                  "scope": "One owned C integer core through real MCP routing, not every language or input.",
                  "external_attack_evaluation": "not_evaluated"}
        output = Path(plan["output_dir"]).parent / "workflow-e2e.json"
        with output.open("x", encoding="utf-8") as stream:
            json.dump(record, stream, indent=2)
        print(json.dumps(record))


if __name__ == "__main__":
    unittest.main()
