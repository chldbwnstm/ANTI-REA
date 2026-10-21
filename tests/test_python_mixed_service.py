"""Owned parse/build/MCP integration; never execute mixed application code."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from antirea.defense_mcp import DefenseBridge
from antirea.projects import ProjectService
from antirea import python_frontend, python_mixed_module


class MixedSourceServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = self.root / "owned_app"
        self.app.mkdir()
        self.source = self.app / "ui.py"
        self.source.write_text(
            "from __future__ import annotations\n"
            "raise RuntimeError('application startup must never run in plan/build')\n"
            "from .display import render\n"
            "TITLE = 'ordinary UI'\n"
            "def helper(x: int) -> int:\n    return x * 37 + 19\n"
            "def core(x: int) -> int:\n    return helper(x) ^ 97153\n"
            "def ui(x):\n    return render(TITLE, core(x))\n", encoding="utf-8")
        (self.app / "display.py").write_text("def render(title, value):\n    return title + str(value)\n", encoding="utf-8")
        (self.app / "__init__.py").write_text("# owned package context\n", encoding="utf-8")
        self.project = self.app / "project.json"
        self.value = {"schema_version": 1, "name": "owned_mixed_app", "language": "python",
                      "sources": ["ui.py"], "functions": ["core"], "protection_mode": "mixed_module"}
        self.project.write_text(json.dumps(self.value), encoding="utf-8")
        self.service = ProjectService(self.root)

    def plan_build(self):
        plan = self.service.plan(self.project, seed=71)
        result = self.service.build(plan["plan_id"], plan["fingerprint"])
        self.assertEqual(plan["status"], "planned")
        self.assertEqual(result["status"], "artifact_created_unvalidated", result)
        return plan, result

    def test_real_plan_build_preserves_context_without_executing_application(self):
        original = self.source.read_bytes()
        with patch("subprocess.Popen", side_effect=AssertionError("no child execution")):
            plan, result = self.plan_build()
        self.assertFalse(plan["executes_compilers"])
        self.assertFalse(plan["executes_application"])
        self.assertEqual(plan["inspection"]["backend"], "python_mixed_module_vm")
        self.assertFalse(plan["toolchain"]["native_toolchain_required"])
        self.assertEqual(len(plan["inputs"]), 4)
        self.assertFalse(result["source_executed"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["published"])
        self.assertEqual(result["external_attack_evaluation"], "not_evaluated")
        self.assertEqual(result["coverage"]["helper_closure"], ["core", "helper"])
        self.assertEqual(Path(result["baseline"]).read_bytes(), original)
        protected = Path(result["protected"]).read_text(encoding="utf-8")
        self.assertIn("from .display import render", protected)
        self.assertIn("application startup must never run", protected)
        self.assertNotIn("return x * 37 + 19", protected)
        self.assertEqual(self.source.read_bytes(), original)
        report = Path(plan["output_dir"]) / "report.json"
        self.assertEqual(hashlib.sha256(report.read_bytes()).hexdigest(), result["build_report_sha256"])

    def test_pure_schema_and_unknown_modes_do_not_silently_choose_mixed(self):
        for mode in (None, "pure", "MIXED_MODULE", True, 1):
            value = dict(self.value)
            if mode is None:
                value.pop("protection_mode")
            else:
                value["protection_mode"] = mode
            self.project.write_text(json.dumps(value), encoding="utf-8")
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.service.plan(self.project)
        with self.assertRaises(python_frontend.PythonFrontendError):
            python_frontend.inspect_python_source(self.source.read_text(encoding="utf-8"), ["core"])
        self.assertFalse(self.service.output_root.exists())

    def test_both_frontend_implementations_are_bound_to_plan(self):
        plan = self.service.plan(self.project)
        tools = plan["toolchain"]["tools"]
        for name, module in (("python_frontend", python_frontend), ("python_mixed_module", python_mixed_module)):
            item = tools["engine_" + name]
            self.assertEqual(Path(item["path"]), Path(module.__file__).resolve())
            self.assertEqual(item["sha256"], hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest())
        original = self.service._toolchain
        def changed(inspection=None):
            value = original(inspection)
            value["tools"]["engine_python_mixed_module"]["sha256"] = "0" * 64
            return value
        with patch.object(self.service, "_toolchain", side_effect=changed), patch("antirea.projects._build") as build:
            with self.assertRaisesRegex(ValueError, "changed after planning"):
                self.service.build(plan["plan_id"], plan["fingerprint"])
            build.assert_not_called()
        self.assertFalse((Path(plan["output_dir"]).parent / "started.json").exists())

    def test_surrounding_package_change_invalidates_plan_without_build(self):
        plan = self.service.plan(self.project)
        (self.app / "display.py").write_text("raise RuntimeError('changed dependency')\n", encoding="utf-8")
        with patch("antirea.projects._build") as build:
            with self.assertRaisesRegex(ValueError, "changed after planning"):
                self.service.build(plan["plan_id"], plan["fingerprint"])
            build.assert_not_called()

    def test_scalar_validation_cannot_authorize_mixed_module_import(self):
        plan, _ = self.plan_build()
        contract = self.app / "samples.json"
        contract.write_text(json.dumps({"kind": "python_scalar_samples", "functions": []}), encoding="utf-8")
        with patch("antirea.python_validate.validate_build") as pure_validate, \
                patch("antirea.native_validate.validate_build") as native_validate, \
                patch("subprocess.Popen", side_effect=AssertionError("no application import")):
            with self.assertRaisesRegex(ValueError, "mixed application contract requires"):
                self.service.validate(plan["plan_id"], contract)
            pure_validate.assert_not_called()
            native_validate.assert_not_called()
        self.assertFalse(any(Path(plan["output_dir"]).parent.glob("validation-*")))

    def test_fingerprint_and_single_attempt_gates_remain(self):
        plan = self.service.plan(self.project)
        with patch("antirea.projects._build") as build:
            with self.assertRaisesRegex(ValueError, "fingerprint"):
                self.service.build(plan["plan_id"], "0" * 64)
            build.assert_not_called()
        result = self.service.build(plan["plan_id"], plan["fingerprint"])
        self.assertEqual(result["status"], "artifact_created_unvalidated")
        with self.assertRaisesRegex(ValueError, "already attempted"):
            self.service.build(plan["plan_id"], plan["fingerprint"])

    def test_stop_prevents_mixed_build(self):
        plan = self.service.plan(self.project)
        stop = self.root / ".runs" / "defense-loop" / "STOP"
        stop.parent.mkdir(parents=True)
        stop.write_text("owned fixture stop", encoding="utf-8")
        with patch("antirea.projects._build") as build:
            result = self.service.build(plan["plan_id"], plan["fingerprint"])
            self.assertEqual(result["status"], "cancelled")
            build.assert_not_called()

    def test_existing_mcp_tools_reach_real_opt_in_builder(self):
        bridge = DefenseBridge(SimpleNamespace(root=self.root), self.service)
        plan = bridge.call("protection_source_plan", {"project_path": str(self.project), "seed": 73})
        result = bridge.call("protection_source_build", {"plan_id": plan["plan_id"], "fingerprint": plan["fingerprint"]})
        self.assertEqual(result["status"], "artifact_created_unvalidated")
        self.assertEqual(result["backend"], "python_mixed_module_vm")
        self.assertFalse(result["source_executed"])


if __name__ == "__main__":
    unittest.main()
