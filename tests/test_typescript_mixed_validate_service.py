"""Public ProjectService / DefenseBridge coverage for the owned TypeScript
mixed-module route.

Plan and build of the owned TypeScript sample run against the REAL production
service (no mocking): the plan is a javascript_source_build and the build
transpiles the whole module to CommonJS. Validation of a TypeScript build routes
through the same opt-in ``javascript_mixed_validate.validate_build``; a scalar
kind and a cross-language JavaScript contract are both refused, which needs no
reference helper. The end-to-end pass and the DefenseBridge wiring additionally
require the independent reference-compiler helper and gate themselves off until
its owning worker stages it.

Each test runs in its own fresh temp workspace; the real repository STOP is only
ever read, never written.

Run: C:/Python313/python.exe -I -S -B test_typescript_mixed_validate_service.py
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import typescript_mixed_validate_support as H  # noqa: E402

from antirea.projects import ProjectService  # noqa: E402
from antirea.defense_mcp import DefenseBridge  # noqa: E402


def num_param(name, lo, hi):
    return {"name": name, "type": "number", "minimum": lo, "maximum": hi}


class _ServiceBase(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.root = Path(self._t.name)
        self.app = self.root / "owned_ts_app"
        H.write_sample_ts(self.app)
        self.project = self.app / "project.json"
        self.service = ProjectService(self.root)

    def plan_build(self, *, seed=71):
        plan = self.service.plan(self.project, seed=seed)
        self.assertEqual(plan["status"], "planned", plan.get("blockers"))
        self.assertEqual(plan["kind"], "javascript_source_build")
        result = self.service.build(plan["plan_id"], plan["fingerprint"])
        self.assertEqual(result["status"], "artifact_created_unvalidated", result)
        self.assertEqual(result["backend"], "javascript_mixed_module_vm")
        self.assertTrue(result["coverage"]["transpiled_typescript"])
        return plan, result

    def write_contract(self, *, name="ts_samples.json", source="index.ts",
                       entrypoints=None, preserved=None):
        # The application contract is a separate owned input OUTSIDE the snapshotted
        # project directory so it never perturbs the bound source plan.
        path = self.root / name
        H.write_ts_contract(path, source=source,
                            entrypoints=entrypoints if entrypoints is not None else H.SAMPLE_ENTRYPOINTS,
                            preserved=preserved if preserved is not None else H.SAMPLE_PRESERVED)
        return path


class TypeScriptPlanBuildAndRefusalTests(_ServiceBase):
    """Plan/build and the pre-execution refusals: these run without the helper."""

    def test_plan_and_build_transpile_typescript(self):
        plan, result = self.plan_build()
        self.assertEqual(result["project"]["language"], "typescript")
        self.assertTrue(result["project"]["sources"][0].endswith("index.ts"))

    def test_scalar_contract_cannot_authorize_typescript_startup(self):
        plan, _ = self.plan_build()
        scalar = self.root / "scalar.json"
        scalar.write_text(json.dumps({"kind": "typescript_scalar_samples", "functions": []}), encoding="utf-8")
        with self.assertRaises(ValueError):
            self.service.validate(plan["plan_id"], str(scalar), random_cases=4, timeout_seconds=60)
        directory = Path(plan["output_dir"]).parent
        self.assertFalse(any(directory.glob("validation-*")))

    def test_javascript_contract_cannot_authorize_typescript_build(self):
        plan, _ = self.plan_build()
        js = self.root / "js_contract.json"
        js.write_text(json.dumps(
            {"schema_version": 1, "kind": H.JS_CONTRACT_KIND, "source": "index.js",
             "entrypoints": [{"name": "core", "parameters": [num_param("x", -5, 5)]}],
             "preserved_entrypoints": []}), encoding="utf-8")
        with self.assertRaises(ValueError):
            self.service.validate(plan["plan_id"], str(js), random_cases=4, timeout_seconds=60)
        directory = Path(plan["output_dir"]).parent
        self.assertFalse(any(directory.glob("validation-*")))


@unittest.skipUnless(H.ts_reference_ready(),
                     "independent TypeScript reference helper not yet staged by its owning worker")
class TypeScriptServiceValidateTests(_ServiceBase):
    def test_real_plan_build_validate_succeeds_and_is_append_only(self):
        plan, _ = self.plan_build()
        contract = self.write_contract()
        out = self.service.validate(plan["plan_id"], str(contract), random_cases=8, timeout_seconds=120)
        self.assertEqual(out["status"], "mixed_application_samples_passed", out.get("error"))
        self.assertEqual(out["plan_id"], plan["plan_id"])
        self.assertTrue(out["validation_id"].startswith("validation-"))
        self.assertEqual(out["language"], "typescript")
        self.assertEqual(out["baseline_source_kind"], "typescript_independent_transpile")
        self.assertEqual(out["runtime_module_relative"], "index.cjs")
        self.assertEqual(out["reference_compilation"]["status"], "reference_created")
        # The service binds its REAL plan/result/tool pins, including the pinned
        # TypeScript reference helper tool.
        self.assertTrue(out["service_plan_inputs_bound"])
        directory = Path(plan["output_dir"]).parent
        self.assertIn(str(directory / "plan.json"), out["service_input_pins"])

        out2 = self.service.validate(plan["plan_id"], str(contract), random_cases=8, timeout_seconds=120)
        self.assertEqual(out2["status"], "mixed_application_samples_passed", out2.get("error"))
        self.assertNotEqual(out2["validation_id"], out["validation_id"])
        self.assertEqual(len(sorted(directory.glob("validation-*"))), 2)

    def test_defense_bridge_route_reaches_typescript_validator(self):
        bridge = DefenseBridge(SimpleNamespace(root=self.root), self.service)
        plan = bridge.call("protection_source_plan", {"project_path": str(self.project), "seed": 73})
        result = bridge.call("protection_source_build",
                             {"plan_id": plan["plan_id"], "fingerprint": plan["fingerprint"]})
        self.assertEqual(result["status"], "artifact_created_unvalidated")
        contract = self.write_contract()
        out = bridge.call("protection_source_validate",
                          {"plan_id": plan["plan_id"], "contract_path": str(contract),
                           "random_cases": 6, "timeout_seconds": 120})
        self.assertEqual(out["status"], "mixed_application_samples_passed", out.get("error"))
        self.assertEqual(out["language"], "typescript")
        self.assertTrue(out["service_plan_inputs_bound"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
