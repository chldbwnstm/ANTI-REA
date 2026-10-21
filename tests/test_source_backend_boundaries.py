"""Implementation regressions only; all compiler/application launches mocked."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from antirea import native_validate as nv
from antirea import projects


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class BackendPlanBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "owned"
        self.source.mkdir()
        self.project = self.source / "project.json"
        self.project.write_text('{"schema_version":1,"language":"python"}', encoding="utf-8")
        (self.source / "core.py").write_text("def core(x):\n    return x + 1\n", encoding="utf-8")
        self.service = projects.ProjectService(self.root)
        self.engine = self.root / "test-engine"
        self.engine.mkdir()
        for name in ("projects", "scope", "python_frontend", "dotnet_frontend"):
            (self.engine / (name + ".py")).write_text("# test-only hashed engine input\n", encoding="utf-8")
        self.tools = self.root / ".tools"
        self.tools.mkdir()
        (self.tools / "kagura-toolchain.json").write_text("{}", encoding="utf-8")

    def test_non_object_top_level_project_json_is_rejected_without_build(self):
        for value in ([], None, True, 7, "python"):
            with self.subTest(value=value):
                self.project.write_text(json.dumps(value), encoding="utf-8")
                with patch.object(projects, "_build") as build:
                    with self.assertRaises(ValueError):
                        self.service.plan(self.project)
                    build.assert_not_called()
                self.assertFalse(self.service.output_root.exists())

    def test_build_dispatch_rejects_non_object_json_before_backend_execution(self):
        for value in ([], None, 5, "native"):
            with self.subTest(value=value):
                self.project.write_text(json.dumps(value), encoding="utf-8")
                with patch("antirea.native_build.build_project") as native_builder:
                    with self.assertRaises(ValueError):
                        projects._build(self.project, self.root / "unused", workspace_root=self.root, seed=1)
                    native_builder.assert_not_called()
                self.assertFalse((self.root / "unused").exists())

    def test_malformed_and_duplicate_json_are_rejected_before_plan_creation(self):
        for text in ('{"language":', '{"language":"python","language":"c"}'):
            with self.subTest(text=text):
                self.project.write_text(text, encoding="utf-8")
                with patch.object(projects, "_build") as build:
                    with self.assertRaises(ValueError):
                        self.service.plan(self.project)
                    build.assert_not_called()
                self.assertFalse(self.service.output_root.exists())

    def test_changed_engine_and_frontend_modules_invalidate_existing_plan(self):
        inspection = {"language": "python", "blockers": []}
        with patch.object(projects, "__file__", str(self.engine / "projects.py")), \
                patch.object(projects, "_inspect", return_value=inspection), \
                patch.object(projects.shutil, "which", return_value=None):
            for module in ("scope", "projects", "python_frontend", "dotnet_frontend"):
                with self.subTest(module=module):
                    path = self.engine / (module + ".py")
                    original = path.read_bytes()
                    plan = self.service.plan(self.project)
                    self.assertEqual(plan["toolchain"]["tools"]["engine_" + module]["sha256"], digest(path))
                    path.write_bytes(original + b"# changed after plan\n")
                    with patch.object(projects, "_build") as build:
                        with self.assertRaisesRegex(ValueError, "changed"):
                            self.service.build(plan["plan_id"], plan["fingerprint"])
                        build.assert_not_called()
                    self.assertFalse((Path(plan["output_dir"]).parent / "started.json").exists())
                    self.assertFalse(Path(plan["output_dir"]).exists())
                    path.write_bytes(original)

    def test_changed_frontend_compiler_input_invalidates_plan(self):
        compiler = self.tools / "frontend-compiler.dll"
        compiler.write_bytes(b"mock compiler input v1")
        inspection = {"language": "csharp", "blockers": [], "compiler_inputs": {str(compiler): digest(compiler)}}
        with patch.object(projects, "__file__", str(self.engine / "projects.py")), \
                patch.object(projects, "_inspect", return_value=inspection), \
                patch.object(projects.shutil, "which", return_value=None):
            plan = self.service.plan(self.project)
            self.assertTrue(any(item.get("path") == str(compiler) and item.get("sha256") == digest(compiler)
                                for item in plan["toolchain"]["tools"].values()))
            compiler.write_bytes(b"mock compiler input v2")
            with patch.object(projects, "_build") as build:
                with self.assertRaisesRegex(ValueError, "changed"):
                    self.service.build(plan["plan_id"], plan["fingerprint"])
                build.assert_not_called()

    def test_changed_inspection_compiler_hash_is_not_silently_replanned(self):
        compiler = self.tools / "frontend-compiler.dll"
        compiler.write_bytes(b"mock compiler input v1")
        inspection = {"language": "csharp", "blockers": [], "compiler_inputs": {str(compiler): digest(compiler)}}
        with patch.object(projects, "__file__", str(self.engine / "projects.py")), \
                patch.object(projects.shutil, "which", return_value=None), \
                patch.object(projects, "_inspect", return_value=inspection) as inspect:
            plan = self.service.plan(self.project)
            compiler.write_bytes(b"mock compiler input v2")
            inspect.return_value = {**inspection, "compiler_inputs": {str(compiler): digest(compiler)}}
            with patch.object(projects, "_build") as build:
                with self.assertRaisesRegex(ValueError, "changed"):
                    self.service.build(plan["plan_id"], plan["fingerprint"])
                build.assert_not_called()

    def test_compact_compiler_inventory_change_invalidates_plan(self):
        inspection = {"language": "go", "blockers": [], "compiler_inventory_sha256": "a" * 64}
        with patch.object(projects, "__file__", str(self.engine / "projects.py")), \
                patch.object(projects.shutil, "which", return_value=None), \
                patch.object(projects, "_inspect", return_value=inspection) as inspect:
            plan = self.service.plan(self.project)
            inspect.return_value = {**inspection, "compiler_inventory_sha256": "b" * 64}
            with patch.object(projects, "_build") as build:
                with self.assertRaisesRegex(ValueError, "changed"):
                    self.service.build(plan["plan_id"], plan["fingerprint"])
                build.assert_not_called()


class ExportCoverageBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.build = self.root / ".runs" / "build"
        self.build.mkdir(parents=True)
        source = self.root / "owned"
        source.mkdir()
        self.contract = {"schema_version": 1, "library_name": "fixture", "functions": [
            {"name": "public_entry", "return_type": "u64", "parameters": [{"name": "x", "type": "u32"}]}]}
        self.contract_path = source / "contract.json"
        self.contract_path.write_text(json.dumps(self.contract), encoding="utf-8")
        ir = self.build / "module.before.ll"
        ir.write_text("define i64 @public_entry(i32 %x) {\n %v = call i64 @private_core(i32 %x)\n ret i64 %v\n}\n"
                      "define internal i64 @private_core(i32 %x) {\n %v = zext i32 %x to i64\n ret i64 %v\n}\n",
                      encoding="utf-8")
        artifacts = {}
        for arm in ("baseline", "protected"):
            path = self.build / (arm + ".dll")
            path.write_bytes(("not executable; mocked " + arm).encode())
            artifacts[arm] = {"path": str(path), "sha256": digest(path)}
        self.report = {"status": "artifact_created_unvalidated", "artifacts": artifacts,
                       "artifact_hashes": {"module.before.ll": digest(ir)},
                       "coverage": {"exported_functions": ["public_entry"],
                                    "selected_functions": ["private_core", "private_helper"],
                                    "functions": {"private_core": {"virtualized": True}, "private_helper": {"virtualized": True}},
                                    "public_boundaries": {"public_entry": {"defined": True, "virtualized": False}}}}
        self.report_path = self.build / "report.json"
        self.save_report()

    def save_report(self):
        self.report_path.write_text(json.dumps(self.report), encoding="utf-8")

    def mocked_worker(self, command, *_args, **_kwargs):
        request_path = Path(command[-1])
        request = json.loads(request_path.read_text(encoding="utf-8"))
        self.assertEqual([item["name"] for item in request["contract"]["functions"]], ["public_entry"])
        cases = nv.make_cases(request["contract"], request["random_cases"], request["seed"])
        values = [int(args[0]) for args in cases["public_entry"]]
        reply = {"outputs": {"public_entry": values}, "deterministic": {"public_entry": True},
                 "timings": {"public_entry": {"median_ns": 100, "samples_ns": [100] * 7,
                                             "calls_per_batch": min(256, len(values)), "warmup_batches": 1}}}
        request_path.with_suffix(".reply.json").write_text(json.dumps(reply), encoding="utf-8")
        return {"returncode": 0, "cancelled": False, "timed_out": False,
                "cleanup": {"job_assigned": True, "active_after": 0,
                            "parent_exit_confirmed": True, "job_handle_closed": True}}

    def test_public_only_contract_observes_all_internal_vm_functions(self):
        with patch.object(nv, "run_logged", side_effect=self.mocked_worker) as runner, \
                patch.object(nv.ctypes, "CDLL", side_effect=AssertionError("no runtime apps in regression tests")):
            result = nv.validate_build(self.report_path, self.contract_path, self.root / ".runs/check",
                                       workspace_root=self.root, random_cases=2)
        self.assertEqual(result["status"], "functional_samples_passed")
        self.assertEqual(set(result["functions"]), {"public_entry"})
        self.assertEqual(runner.call_count, 2)

    def test_mock_timing_schema_matches_worker_without_loading_a_library(self):
        artifact = self.report["artifacts"]["baseline"]
        request = {"workspace_root": str(self.root), "build_directory": str(self.build),
                   "library_path": artifact["path"], "sha256": artifact["sha256"],
                   "contract": self.contract, "random_cases": 2, "seed": 17}
        request_path = self.build / "mock-contract.request.json"
        request_path.write_text(json.dumps(request), encoding="utf-8")
        self.mocked_worker(["not-a-command", str(request_path)])
        mocked = json.loads(request_path.with_suffix(".reply.json").read_text(encoding="utf-8"))
        # Exercise the actual reply producer with a Python callback in place of
        # CDLL. The fixture bytes are never loaded or executed.
        library = type("PythonOnlyLibrary", (), {})()
        library.public_entry = lambda x: int(x)
        with patch.object(nv.ctypes, "CDLL", return_value=library) as loader:
            actual = nv._worker_run(request)
        loader.assert_called_once()
        expected = actual["timings"]["public_entry"]
        observed = mocked["timings"]["public_entry"]
        self.assertEqual(set(observed), set(expected))
        self.assertEqual(observed["calls_per_batch"], expected["calls_per_batch"])
        self.assertEqual(observed["warmup_batches"], expected["warmup_batches"])
        self.assertEqual(len(observed["samples_ns"]), len(expected["samples_ns"]))

    def test_unvirtualized_internal_function_rejects_before_worker(self):
        self.report["coverage"]["functions"]["private_helper"]["virtualized"] = False
        self.save_report()
        with patch.object(nv, "run_logged") as runner:
            with self.assertRaises(ValueError):
                nv.validate_build(self.report_path, self.contract_path, self.root / ".runs/reject",
                                  workspace_root=self.root, random_cases=2)
            runner.assert_not_called()

    def test_selected_internal_function_missing_from_coverage_rejects(self):
        self.report["coverage"]["functions"].pop("private_helper")
        self.save_report()
        with patch.object(nv, "run_logged", side_effect=self.mocked_worker) as runner:
            with self.assertRaises(ValueError):
                nv.validate_build(self.report_path, self.contract_path, self.root / ".runs/reject",
                                  workspace_root=self.root, random_cases=2)
            runner.assert_not_called()

    def test_public_boundary_requires_defined_unvirtualized_evidence(self):
        for boundary in ({}, {"defined": False, "virtualized": False}, {"defined": True, "virtualized": True}):
            with self.subTest(boundary=boundary):
                self.report["coverage"]["public_boundaries"]["public_entry"] = boundary
                self.save_report()
                with patch.object(nv, "run_logged") as runner:
                    with self.assertRaises(ValueError):
                        nv.validate_build(self.report_path, self.contract_path, self.root / ".runs/reject",
                                          workspace_root=self.root, random_cases=2)
                    runner.assert_not_called()

    def test_export_contract_requires_exact_membership_without_duplicates(self):
        for exports in (["public_entry", "private_core"], ["private_core"], ["public_entry", "public_entry"], []):
            with self.subTest(exports=exports):
                self.report["coverage"]["exported_functions"] = exports
                self.save_report()
                with patch.object(nv, "run_logged") as runner:
                    with self.assertRaises(ValueError):
                        nv.validate_build(self.report_path, self.contract_path, self.root / ".runs/reject",
                                          workspace_root=self.root, random_cases=2)
                    runner.assert_not_called()

    def assert_rejected_before_worker(self, suffix):
        output = self.root / ".runs" / ("malformed-" + suffix)
        self.save_report()
        with patch.object(nv, "run_logged", side_effect=self.mocked_worker) as runner, \
                patch.object(nv.ctypes, "CDLL", side_effect=AssertionError("no runtime apps in regression tests")):
            with self.assertRaises(ValueError):
                nv.validate_build(self.report_path, self.contract_path, output,
                                  workspace_root=self.root, random_cases=2)
            runner.assert_not_called()
        self.assertFalse(output.exists(), "malformed coverage must fail before output/worker creation")

    def test_malformed_top_level_coverage_is_value_error(self):
        for index, value in enumerate((None, [], "coverage", True, 17)):
            with self.subTest(value=value):
                self.report["coverage"] = value
                self.assert_rejected_before_worker("coverage-" + str(index))

    def test_malformed_function_coverage_is_value_error(self):
        values = (None, [], ["private_core"], "private_core", True, {},
                  {"private_core": None, "private_helper": {"virtualized": True}},
                  {"private_core": [], "private_helper": {"virtualized": True}},
                  {"private_core": {"virtualized": 1}, "private_helper": {"virtualized": True}})
        for index, value in enumerate(values):
            with self.subTest(value=value):
                self.report["coverage"]["functions"] = value
                self.assert_rejected_before_worker("functions-" + str(index))

    def test_declared_internal_selection_is_exact_unique_string_list(self):
        values = (None, "private_core", {}, True, [],
                  ["private_core", "private_helper", "private_core"],
                  ["private_core"], ["private_core", "private_helper", "missing"],
                  ["private_core", 4], ["private_core", None],
                  ["private_core", ["private_helper"]])
        for index, value in enumerate(values):
            with self.subTest(value=value):
                self.report["coverage"]["selected_functions"] = value
                self.assert_rejected_before_worker("selection-" + str(index))

    def test_malformed_public_boundaries_are_value_error(self):
        valid = {"defined": True, "virtualized": False}
        values = (None, [], "public_entry", True,
                  {"public_entry": None}, {"public_entry": []}, {"public_entry": "reviewed"},
                  {"public_entry": True},
                  {"public_entry": {"defined": "true", "virtualized": False}},
                  {"public_entry": {"defined": True, "virtualized": 0}},
                  {"public_entry": valid, "unrelated": None})
        for index, value in enumerate(values):
            with self.subTest(value=value):
                self.report["coverage"]["public_boundaries"] = copy.deepcopy(value)
                self.assert_rejected_before_worker("boundaries-" + str(index))

    def test_public_boundary_report_without_selected_list_remains_compatible(self):
        self.report["coverage"].pop("selected_functions")
        self.save_report()
        with patch.object(nv, "run_logged", side_effect=self.mocked_worker) as runner:
            result = nv.validate_build(self.report_path, self.contract_path, self.root / ".runs/legacy-boundary",
                                       workspace_root=self.root, random_cases=2)
        self.assertEqual(result["status"], "functional_samples_passed")
        self.assertEqual(runner.call_count, 2)

    def test_legacy_coverage_without_export_list_still_supports_direct_export(self):
        self.report["coverage"] = {"functions": {"public_entry": {"virtualized": True}}}
        self.save_report()
        with patch.object(nv, "run_logged", side_effect=self.mocked_worker):
            result = nv.validate_build(self.report_path, self.contract_path, self.root / ".runs/legacy",
                                       workspace_root=self.root, random_cases=2)
        self.assertEqual(result["status"], "functional_samples_passed")


if __name__ == "__main__":
    unittest.main()
