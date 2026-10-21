"""Public ProjectService.validate / DefenseBridge validation tests for the owned
mixed-module JavaScript route.

These exercise the REAL public API end to end (no engine mocking, no stubbed
validator): plan -> build -> validate against the actual production engine and
per-arm runner, with the service binding its real trusted plan/engine/tool pins.

Covered: a real explicit mixed-contract validation succeeds; append-only
validation directories; a scalar contract cannot authorize application startup;
saved-plan fingerprint and build-report identity drift fail closed; STOP; and a
JavaScript contract cannot authorize a TypeScript build. The DefenseBridge wiring
(both direct call and a JSON-RPC round trip) reaches the same opt-in validator.

Run: C:/Python313/python.exe -I -S -B test_javascript_mixed_validate_service.py
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import js_mixed_validate_support as H  # noqa: E402  (inserts repo root; imports production engine)

from antirea.projects import ProjectService  # noqa: E402
from antirea.defense_mcp import DefenseBridge  # noqa: E402


def num_param(n, lo, hi):
    return {"name": n, "type": "number", "minimum": lo, "maximum": hi}


MIXED_ENTRYPOINTS = [
    {"name": "fadd", "parameters": [num_param("a", -1000, 1000), num_param("b", -1000, 1000)]},
    {"name": "isposz", "parameters": [num_param("x", -3, 3)]},
    {"name": "bigadd", "parameters": [{"name": "a", "type": "bigint", "minimum": -10 ** 6, "maximum": 10 ** 6},
                                      {"name": "b", "type": "bigint", "minimum": -10 ** 6, "maximum": 10 ** 6}]},
    {"name": "mix", "parameters": [num_param("a", -3, 3), {"name": "b", "type": "bigint", "minimum": -3, "maximum": 3}]},
]
MIXED_PRESERVED = [{"name": "describe", "parameters": [num_param("n", -150, 150)]}]


class _ServiceBase(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.root = Path(self._t.name)
        self.app = self.root / "owned_app"
        H.write_sample_app(self.app)
        self.project = self.app / "project.json"
        self.service = ProjectService(self.root)

    def plan_build(self, *, seed=71):
        plan = self.service.plan(self.project, seed=seed)
        self.assertEqual(plan["status"], "planned", plan.get("blockers"))
        result = self.service.build(plan["plan_id"], plan["fingerprint"])
        self.assertEqual(result["status"], "artifact_created_unvalidated", result)
        self.assertEqual(result["backend"], "javascript_mixed_module_vm")
        return plan, result

    def write_contract(self, *, name="samples.json", source="index.js",
                       entrypoints=None, preserved=None):
        # The application contract is a separate owned input; it must live OUTSIDE
        # the snapshotted project directory so it never perturbs the bound source plan.
        path = self.root / name
        H.write_contract(path, source=source,
                         entrypoints=entrypoints if entrypoints is not None else MIXED_ENTRYPOINTS,
                         preserved=preserved if preserved is not None else MIXED_PRESERVED)
        return path


class ProjectServiceValidateTests(_ServiceBase):
    def test_real_plan_build_validate_succeeds_and_is_append_only(self):
        plan, _ = self.plan_build()
        contract = self.write_contract()
        out = self.service.validate(plan["plan_id"], str(contract), random_cases=8, timeout_seconds=90)
        self.assertEqual(out["status"], "mixed_application_samples_passed", out.get("error"))
        self.assertEqual(out["plan_id"], plan["plan_id"])
        self.assertTrue(out["validation_id"].startswith("validation-"))
        self.assertTrue(out["module_origin"]["consistent"])
        self.assertTrue(out["inputs_unchanged"])
        self.assertEqual(out["baseline_source_kind"], "javascript_original_module")
        self.assertFalse(out["transpiled_typescript"])
        # The service binds its REAL plan/result/tool pins (not mocked away).
        self.assertTrue(out["service_plan_inputs_bound"])
        directory = Path(plan["output_dir"]).parent
        self.assertIn(str(directory / "plan.json"), out["service_input_pins"])
        self.assertTrue(all(f["sampled_output_match"] and f["deterministic"] for f in out["functions"].values()))
        self.assertEqual(out["functions"]["mix"]["baseline_throws"], out["functions"]["mix"]["cases"])

        # Append-only: a second validation gets its own fresh directory, never
        # overwriting the first.
        out2 = self.service.validate(plan["plan_id"], str(contract), random_cases=8, timeout_seconds=90)
        self.assertEqual(out2["status"], "mixed_application_samples_passed", out2.get("error"))
        self.assertNotEqual(out2["validation_id"], out["validation_id"])
        validation_dirs = sorted(directory.glob("validation-*"))
        self.assertEqual(len(validation_dirs), 2)
        for vd in validation_dirs:
            self.assertTrue((vd / "validation.json").is_file())

    def test_scalar_contract_cannot_authorize_application_startup(self):
        plan, _ = self.plan_build()
        scalar = self.root / "scalar.json"
        scalar.write_text(json.dumps({"kind": "javascript_scalar_samples", "functions": []}), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "mixed application contract requires"):
            self.service.validate(plan["plan_id"], str(scalar), random_cases=4, timeout_seconds=60)
        # A refused scalar contract never produces a validation directory.
        directory = Path(plan["output_dir"]).parent
        self.assertFalse(any(directory.glob("validation-*")))

    def test_build_report_mismatch_refused_before_validation(self):
        plan, _ = self.plan_build()
        contract = self.write_contract()
        report_path = Path(plan["output_dir"]) / "report.json"
        # Any drift of the saved build report away from its recorded digest must fail
        # closed before the validator is invoked (appended whitespace keeps it valid
        # JSON while changing its SHA-256).
        report_path.write_bytes(report_path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "build report no longer matches"):
            self.service.validate(plan["plan_id"], str(contract), random_cases=4, timeout_seconds=60)

    def test_saved_plan_fingerprint_identity_drift_refused(self):
        plan, _ = self.plan_build()
        contract = self.write_contract()
        directory = Path(plan["output_dir"]).parent
        plan_path = directory / "plan.json"
        saved_plan = json.loads(plan_path.read_text(encoding="utf-8"))
        saved_plan["seed"] = saved_plan["seed"] + 1          # changes canonical fingerprint
        plan_path.write_text(json.dumps(saved_plan), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "source plan does not bind this mixed build result"):
            self.service.validate(plan["plan_id"], str(contract), random_cases=4, timeout_seconds=60)

    def test_stop_cancels_validation(self):
        plan, _ = self.plan_build()
        contract = self.write_contract()
        stop = self.root / ".runs" / "defense-loop" / "STOP"
        stop.parent.mkdir(parents=True, exist_ok=True)
        stop.write_text("owned test STOP", encoding="utf-8")
        out = self.service.validate(plan["plan_id"], str(contract), random_cases=4, timeout_seconds=60)
        self.assertEqual(out["status"], "cancelled", out.get("error"))
        self.assertEqual(out.get("execution"), {})

    def test_javascript_contract_cannot_authorize_typescript_build(self):
        # TypeScript has a separate opt-in contract. A JavaScript contract must
        # not authorize TS startup, even when the same backend built both.
        ts = self.app / "ui.ts"
        ts.write_text('throw new Error("never executed");\n'
                      'export enum Colour { Red, Blue }\n'
                      'export function core(x: number): number { return x * 37 + 19; }\n'
                      'export function label(x: number): string { return Colour[x] + core(x); }\n',
                      encoding="utf-8")
        self.project.write_text(json.dumps(
            {"schema_version": 1, "name": "wave4-ts-app", "language": "typescript",
             "sources": ["ui.ts"], "functions": ["core"], "protection_mode": "mixed_module"}), encoding="utf-8")
        plan, result = self.plan_build()
        self.assertTrue(result["coverage"]["transpiled_typescript"])
        contract = self.write_contract(name="ts_samples.json", source="ui.js",
                                       entrypoints=[{"name": "core", "parameters": [num_param("x", -5, 5)]}],
                                       preserved=[])
        with self.assertRaisesRegex(ValueError, "contract kind must match"):
            self.service.validate(plan["plan_id"], str(contract), random_cases=4, timeout_seconds=60)


class DefenseBridgeValidateTests(_ServiceBase):
    def _bridge(self):
        return DefenseBridge(SimpleNamespace(root=self.root), self.service)

    def test_bridge_call_reaches_real_validator(self):
        bridge = self._bridge()
        plan = bridge.call("protection_source_plan", {"project_path": str(self.project), "seed": 73})
        result = bridge.call("protection_source_build",
                             {"plan_id": plan["plan_id"], "fingerprint": plan["fingerprint"]})
        self.assertEqual(result["status"], "artifact_created_unvalidated")
        contract = self.write_contract()
        out = bridge.call("protection_source_validate",
                          {"plan_id": plan["plan_id"], "contract_path": str(contract),
                           "random_cases": 6, "timeout_seconds": 90})
        self.assertEqual(out["status"], "mixed_application_samples_passed", out.get("error"))
        self.assertEqual(out["plan_id"], plan["plan_id"])
        self.assertTrue(out["service_plan_inputs_bound"])

    def test_bridge_jsonrpc_round_trip_maps_scalar_refusal(self):
        # Prove the full MCP envelope reaches validate and maps a refusal honestly as
        # isError, without paying for a second multi-arm run.
        bridge = self._bridge()
        plan, _ = self.plan_build()
        scalar = self.root / "scalar.json"
        scalar.write_text(json.dumps({"kind": "javascript_scalar_samples", "functions": []}), encoding="utf-8")
        self.assertEqual(bridge.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                                   "clientInfo": {"name": "t", "version": "1"}}})["result"]
                         ["serverInfo"]["name"], "anti-rea-defense")
        self.assertIsNone(bridge.handle({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}))
        response = bridge.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                  "params": {"name": "protection_source_validate",
                                             "arguments": {"plan_id": plan["plan_id"],
                                                           "contract_path": str(scalar),
                                                           "random_cases": 4, "timeout_seconds": 60}}})
        result = response["result"]
        self.assertTrue(result["isError"])
        body = json.loads(result["content"][0]["text"])
        self.assertEqual(body["status"], "error")
        self.assertIn("mixed application contract requires", body["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
