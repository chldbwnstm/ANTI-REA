"""Owned, bounded tests for the mixed-module application validation contract (v2).

Production-shaped: the primary import is ``from antirea import python_mixed_validate``.
When run directly from the pre-adoption candidate directory under the isolated
interpreter, two explicit dev shims (guarded by import failure) make the antirea
package and this not-yet-adopted module importable; both become inert once root
copies the module to ``antirea/`` and this test to ``tests/``.

    C:/Python313/python.exe -I -S -B .runs/orca-wave1-python-v2/test_python_mixed_validate.py

Child processes import only this owned fixture code; no network, no received
artifact, no arbitrary shell/test command.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

# Dev shim 1 (pre-adoption only): make the antirea package importable. Under a
# normal repo-root test runner `import antirea` already works and this is skipped.
# The repository root is located by walking up to the directory that contains the
# antirea package, so this is independent of how deep this file is nested.
try:
    import antirea
except ModuleNotFoundError:
    for _parent in Path(__file__).resolve().parents:
        if (_parent / "antirea" / "__init__.py").is_file():
            sys.path.insert(0, str(_parent))
            break
    import antirea

from antirea import python_mixed_module as pmm
from antirea import python_validate as pv
from antirea.projects import ProjectService, _digest, _encoded

# Prefer the adopted module; fall back to the sibling candidate pre-adoption.
try:
    from antirea import python_mixed_validate as pmv
except ImportError:
    _candidate = Path(__file__).resolve().with_name("python_mixed_validate.py")
    _spec = importlib.util.spec_from_file_location("antirea.python_mixed_validate", str(_candidate))
    pmv = importlib.util.module_from_spec(_spec)
    sys.modules["antirea.python_mixed_validate"] = pmv
    setattr(antirea, "python_mixed_validate", pmv)
    _spec.loader.exec_module(pmv)


FIXTURE_CORE = (
    '"""Owned mixed module: virtualize the integer core, preserve imports and UI."""\n'
    "from __future__ import annotations\n"
    "\n"
    "from .labels import BANNER\n"
    "\n"
    "STARTUP_BANNER = BANNER.upper()  # ordinary module-level UI/startup state\n"
    "\n"
    "\n"
    "def _scale(value: int) -> int:\n"
    "    return value * 3 + 11\n"
    "\n"
    "\n"
    "def compute(x: int, y: int) -> int:\n"
    "    return _scale(x) // y\n"
    "\n"
    "\n"
    "def validated_total(x, y) -> int:\n"
    '    """Ordinary UI validation path that calls into the virtualized core."""\n'
    "    if type(x) is not int or type(y) is not int:\n"
    '        raise TypeError("inputs must be integers")\n'
    "    if y == 0:\n"
    '        raise ValueError("y must be nonzero")\n'
    "    return compute(x, y)\n"
)

DIVERGENT_PROTECTED = (
    "from .labels import BANNER\n"
    "STARTUP_BANNER = BANNER.upper()\n"
    "def _scale(value):\n    return value * 3 + 11\n"
    "def compute(x, y):\n    return _scale(x) // y + 1\n"
    "def validated_total(x, y):\n"
    "    if type(x) is not int or type(y) is not int:\n"
    '        raise TypeError("inputs must be integers")\n'
    "    if y == 0:\n"
    '        raise ValueError("y must be nonzero")\n'
    "    return compute(x, y)\n"
)

HANGING_PROTECTED = (
    "from .labels import BANNER\n"
    "import time\n"
    "time.sleep(30)\n"
    "STARTUP_BANNER = BANNER.upper()\n"
    "def compute(x, y):\n    return x\n"
    "def validated_total(x, y):\n    return x\n"
)


def _contract(module="widget.core"):
    return {
        "schema_version": 1,
        "kind": pmv.CONTRACT_KIND,
        "module": module,
        "entrypoints": [
            {"name": "compute", "parameters": [
                {"name": "x", "minimum": -10, "maximum": 10},
                {"name": "y", "minimum": -4, "maximum": 4}]}],
        "preserved_entrypoints": [
            {"name": "validated_total", "parameters": [
                {"name": "x", "minimum": -5, "maximum": 20},
                {"name": "y", "minimum": -4, "maximum": 4}]}],
    }


class MixedApplicationValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.proj = self.root / "proj"
        (self.proj / "widget").mkdir(parents=True)
        (self.proj / "widget" / "__init__.py").write_text("# owned widget package\n", encoding="utf-8")
        (self.proj / "widget" / "labels.py").write_text('BANNER = "widget"\nOFFSET = 7\n', encoding="utf-8")
        (self.proj / "widget" / "core.py").write_text(FIXTURE_CORE, encoding="utf-8")
        self.manifest = self.proj / "project.json"
        self.manifest.write_text(json.dumps({
            "schema_version": 1, "name": "widgetapp", "language": "python",
            "sources": ["widget/core.py"], "functions": ["compute"],
            "protection_mode": "mixed_module"}), encoding="utf-8")
        self.contract_path = self.root / "contract.json"
        self.contract_path.write_text(json.dumps(_contract()), encoding="utf-8")
        self.service = ProjectService(self.root)

    # -- helpers -----------------------------------------------------------
    def _plan_build(self):
        """Real source-plan + build; returns (report_path, plan_json, result)."""
        plan = self.service.plan(self.manifest, seed=71)
        self.assertEqual(plan["status"], "planned", plan)
        result = self.service.build(plan["plan_id"], plan["fingerprint"])
        self.assertEqual(result["status"], "artifact_created_unvalidated", result)
        self.assertEqual(result["backend"], "python_mixed_module_vm")
        self.assertFalse(result["source_executed"])
        directory = Path(plan["output_dir"]).parent
        plan_json = json.loads((directory / "plan.json").read_text(encoding="utf-8"))
        report_path = Path(plan["output_dir"]) / "report.json"
        return report_path, plan_json, result

    def _expected(self, plan_json):
        return plan_json["inputs"]

    def _patch_protected(self, report_path, content):
        build_dir = report_path.parent
        protected = build_dir / "protected.py"
        protected.write_text(content, encoding="utf-8")
        digest = hashlib.sha256(protected.read_bytes()).hexdigest()
        size = protected.stat().st_size
        report = json.loads(report_path.read_text(encoding="utf-8"))
        for container in (report["artifacts"], report["coverage"]["artifacts"]):
            container["protected"]["sha256"] = digest
            container["protected"]["bytes"] = size
        report["artifact_hashes"]["protected.py"] = digest
        report_path.write_text(json.dumps(report), encoding="utf-8")

    def _validate(self, report_path, expected, out_name="val", contract=None, **kw):
        return pmv.validate_build(report_path, contract or self.contract_path,
                                  self.root / ".runs" / out_name, workspace_root=self.root,
                                  expected_snapshot=expected, **kw)

    # -- (old 1) contract / cross-validator isolation ----------------------
    def test_scalar_and_mixed_contracts_do_not_cross_validate(self):
        with self.assertRaises(ValueError):
            pv.validate_contract(_contract())  # scalar validator rejects the mixed kind
        scalar = {"schema_version": 1, "kind": "python_integer_samples",
                  "functions": [{"name": "compute", "parameters": []}]}
        with self.assertRaises(ValueError):
            pmv.validate_application_contract(scalar)  # mixed validator rejects the scalar kind

    # -- (old 2) contract field/identifier/bound validation ----------------
    def test_contract_requires_exact_fields_and_identifiers(self):
        base = _contract()
        for mutate in (
            lambda c: c.pop("preserved_entrypoints"),
            lambda c: c.update(kind="python_integer_samples"),
            lambda c: c.update(module="widget.core.."),
            lambda c: c.update(module="1bad.core"),
            lambda c: c.update(entrypoints=[]),
            lambda c: c.update(extra=1),
            lambda c: c["entrypoints"][0]["parameters"].append(
                {"name": "x", "minimum": 0, "maximum": 2 ** 300}),
        ):
            value = json.loads(json.dumps(base))
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                pmv.validate_application_contract(value)

    # -- (old 3) happy path + item (4) loader evidence + item (3) binding --
    def test_independent_original_vs_protected_match_with_import_and_ui_preserved(self):
        report_path, plan_json, _ = self._plan_build()
        result = self._validate(report_path, self._expected(plan_json), random_cases=64, timeout_seconds=60)
        self.assertEqual(result["status"], "mixed_application_samples_passed", result.get("error") or result)
        self.assertTrue(result["inputs_unchanged"])
        self.assertTrue(result["source_plan_snapshot_bound"])
        self.assertEqual(result["source_plan_files"], 4)
        self.assertEqual(result["module"], "widget.core")
        for name in ("compute", "validated_total"):
            fn = result["functions"][name]
            self.assertTrue(fn["sampled_output_match"], (name, fn))
            self.assertTrue(fn["deterministic"], (name, fn))
            self.assertIs(fn["raw_repeat_arrays_compared"], True)
            self.assertGreater(fn["baseline_ordinary_returns"], 0, (name, fn))
            self.assertGreater(fn["baseline_exceptions"], 0, (name, fn))  # y==0 raises in both arms
        self.assertEqual(result["functions"]["compute"]["selected"], True)
        self.assertEqual(result["functions"]["validated_total"]["selected"], False)
        origin = result["module_origin"]
        self.assertTrue(origin["consistent"], origin)
        self.assertEqual(origin["baseline"]["public_surface"], origin["protected"]["public_surface"])
        self.assertIn("validated_total", origin["baseline"]["public_surface"])  # UI preserved
        self.assertIn("STARTUP_BANNER", origin["baseline"]["public_surface"])   # import-time UI state
        self.assertEqual(origin["baseline"]["name"], "widget.core")
        self.assertEqual(origin["baseline"]["package"], "widget")
        # item (4): both arms loaded by the standard source file loader.
        self.assertEqual(origin["baseline"]["loader"], "SourceFileLoader")
        self.assertEqual(origin["protected"]["loader"], "SourceFileLoader")
        self.assertNotEqual(origin["baseline"]["file"], origin["protected"]["file"])  # fresh separate arms
        self.assertEqual(origin["baseline"]["file_sha256"], result["artifacts"]["baseline"]["sha256"])
        self.assertEqual(origin["protected"]["file_sha256"], result["artifacts"]["protected"]["sha256"])
        for arm in ("baseline", "protected"):
            execution = result["execution"][arm]
            self.assertEqual(execution["returncode"], 0, execution)
            self.assertIn("TEMP", execution["child_env_keys"])
            self.assertGreater(result["staging"][arm]["files"], 0)
            if os.name == "nt":
                cleanup = execution["cleanup"]
                self.assertTrue(cleanup.get("job_assigned"))
                self.assertEqual(cleanup.get("active_after"), 0)
                self.assertTrue(cleanup.get("parent_exit_confirmed"))
                self.assertTrue(cleanup.get("job_handle_closed"))

    # -- (old 4) mismatch detection ----------------------------------------
    def test_detects_protected_divergence(self):
        report_path, plan_json, _ = self._plan_build()
        self._patch_protected(report_path, DIVERGENT_PROTECTED)
        result = self._validate(report_path, self._expected(plan_json), "val_mismatch", random_cases=64, timeout_seconds=60)
        self.assertEqual(result["status"], "failed", result)
        self.assertFalse(result["functions"]["compute"]["sampled_output_match"])
        self.assertEqual(result["execution"]["baseline"]["returncode"], 0)
        self.assertEqual(result["execution"]["protected"]["returncode"], 0)

    # -- (old 5) module-origin binding -------------------------------------
    def test_module_origin_binding_enforced(self):
        report_path, plan_json, _ = self._plan_build()
        wrong = self.root / "wrong_contract.json"
        wrong.write_text(json.dumps(_contract(module="widget.other")), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "contract module must equal"):
            self._validate(report_path, self._expected(plan_json), "val_bind", contract=wrong,
                           random_cases=8, timeout_seconds=30)
        self.assertFalse((self.root / ".runs" / "val_bind").exists())

    # -- (old 6) non-mixed backend refused ---------------------------------
    def test_non_mixed_backend_is_refused(self):
        report_path, plan_json, _ = self._plan_build()
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["backend"] = "python_vm"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "mixed-module VM build"):
            self._validate(report_path, self._expected(plan_json), "val_backend", random_cases=8, timeout_seconds=30)

    # -- (old 7) STOP cancels before execution -----------------------------
    def test_stop_marker_cancels_before_execution(self):
        report_path, plan_json, _ = self._plan_build()
        stop = self.root / ".runs" / "defense-loop" / "STOP"
        stop.parent.mkdir(parents=True, exist_ok=True)
        stop.write_text("owned fixture stop", encoding="utf-8")
        result = self._validate(report_path, self._expected(plan_json), "val_stop", random_cases=8, timeout_seconds=30)
        self.assertEqual(result["status"], "cancelled")
        self.assertFalse((self.root / ".runs" / "val_stop").exists())

    # -- (old 8) file budget fails closed ----------------------------------
    def test_package_file_budget_fails_closed_without_execution(self):
        report_path, plan_json, _ = self._plan_build()
        original = pmv.MAX_PACKAGE_FILES
        pmv.MAX_PACKAGE_FILES = 1
        try:
            with self.assertRaisesRegex(ValueError, "file budget"):
                self._validate(report_path, self._expected(plan_json), "val_filebound",
                               random_cases=8, timeout_seconds=30)
        finally:
            pmv.MAX_PACKAGE_FILES = original
        self.assertFalse((self.root / ".runs" / "val_filebound").exists())

    # -- (old 9) timeout + cleanup -----------------------------------------
    def test_timeout_and_cleanup_on_hanging_protected_import(self):
        report_path, plan_json, _ = self._plan_build()
        self._patch_protected(report_path, HANGING_PROTECTED)
        result = self._validate(report_path, self._expected(plan_json), "val_timeout", random_cases=8, timeout_seconds=2)
        self.assertEqual(result["status"], "timed_out", result)
        protected = result["execution"]["protected"]
        self.assertTrue(protected["timed_out"])
        if os.name == "nt":
            self.assertTrue(protected["cleanup"].get("job_assigned"))
            self.assertEqual(protected["cleanup"].get("active_after"), 0)
            self.assertTrue(protected["cleanup"].get("parent_exit_confirmed"))

    # ================= NEW negatives for the review items =================

    # -- (1) partially overlapping roots are refused before any child ------
    def test_coverage_subset_rejects_partially_overlapping_roots_unit(self):
        # {a,b} roots vs {b,c} export/closure: 'a' is outside the closure.
        coverage = {"schema_version": 1, "backend": "python_mixed_module_vm",
                    "protection_mode": "mixed_module", "original_module_source_sha256": "0" * 64,
                    "selected_functions": ["a", "b"], "exported_functions": ["b", "c"],
                    "helper_closure": ["b", "c"], "preserved_unprotected_functions": [],
                    "functions": {"b": {"virtualized": True, "parameters": []},
                                  "c": {"virtualized": True, "parameters": []}}}
        with self.assertRaisesRegex(ValueError, "within the exported helper closure"):
            pmv._verify_mixed_coverage(coverage, {"a", "b"}, set())

    def test_coverage_out_of_closure_root_refuses_before_child(self):
        report_path, plan_json, _ = self._plan_build()
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["coverage"]["selected_functions"] = ["compute", "ghost"]  # ghost not in closure
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "within the exported helper closure"):
            self._validate(report_path, self._expected(plan_json), "val_roots",
                           random_cases=8, timeout_seconds=30)
        self.assertFalse((self.root / ".runs" / "val_roots").exists())

    # -- (2) output nested in package_root refused before mkdir ------------
    def test_output_nested_in_package_root_refused_before_mkdir(self):
        report_path, plan_json, _ = self._plan_build()
        nested = self.proj / "inside_pkg_output"
        with self.assertRaisesRegex(ValueError, "must not overlap the owned package tree"):
            pmv.validate_build(report_path, self.contract_path, nested, workspace_root=self.root,
                               expected_snapshot=self._expected(plan_json), random_cases=8, timeout_seconds=30)
        self.assertFalse(nested.exists())  # nothing created under the source tree

    # -- (2) directory entry and depth budgets -----------------------------
    def test_directory_entry_budget_fails_closed(self):
        report_path, plan_json, _ = self._plan_build()
        original = pmv.MAX_PACKAGE_ENTRIES
        pmv.MAX_PACKAGE_ENTRIES = 1
        try:
            with self.assertRaisesRegex(ValueError, "directory entry budget"):
                self._validate(report_path, self._expected(plan_json), "val_entries",
                               random_cases=8, timeout_seconds=30)
        finally:
            pmv.MAX_PACKAGE_ENTRIES = original
        self.assertFalse((self.root / ".runs" / "val_entries").exists())

    def test_directory_depth_budget_fails_closed(self):
        report_path, plan_json, _ = self._plan_build()
        original = pmv.MAX_PACKAGE_DEPTH
        pmv.MAX_PACKAGE_DEPTH = 0  # the package has a nested 'widget' directory
        try:
            with self.assertRaisesRegex(ValueError, "directory depth budget"):
                self._validate(report_path, self._expected(plan_json), "val_depth",
                               random_cases=8, timeout_seconds=30)
        finally:
            pmv.MAX_PACKAGE_DEPTH = original
        self.assertFalse((self.root / ".runs" / "val_depth").exists())

    # -- (3) source-plan snapshot binding detects since-build changes ------
    def test_source_plan_binding_detects_sibling_modification(self):
        report_path, plan_json, _ = self._plan_build()
        (self.proj / "widget" / "labels.py").write_text('BANNER = "tampered"\nOFFSET = 7\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "changed since the bound source plan"):
            self._validate(report_path, self._expected(plan_json), "val_mod", random_cases=8, timeout_seconds=30)
        self.assertFalse((self.root / ".runs" / "val_mod").exists())

    def test_source_plan_binding_detects_sibling_addition(self):
        report_path, plan_json, _ = self._plan_build()
        (self.proj / "widget" / "extra.py").write_text("SENTINEL = 1\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "changed since the bound source plan"):
            self._validate(report_path, self._expected(plan_json), "val_add", random_cases=8, timeout_seconds=30)
        self.assertFalse((self.root / ".runs" / "val_add").exists())

    def test_source_plan_binding_detects_sibling_removal(self):
        report_path, plan_json, _ = self._plan_build()
        (self.proj / "widget" / "labels.py").unlink()
        with self.assertRaisesRegex(ValueError, "changed since the bound source plan"):
            self._validate(report_path, self._expected(plan_json), "val_rm", random_cases=8, timeout_seconds=30)
        self.assertFalse((self.root / ".runs" / "val_rm").exists())

    # -- (race) change between plan preflight and first staging: no child starts -
    def test_sibling_drift_between_preflight_and_staging_starts_no_child(self):
        report_path, plan_json, _ = self._plan_build()
        proj = self.proj

        def mutate():  # runs after preflight passes, before the first stage
            (proj / "widget" / "labels.py").write_text('BANNER = "raced"\nOFFSET = 7\n', encoding="utf-8")

        original = pmv._prestage_drift_hook
        pmv._prestage_drift_hook = mutate
        try:
            result = self._validate(report_path, self._expected(plan_json), "val_race",
                                    random_cases=64, timeout_seconds=60)
        finally:
            pmv._prestage_drift_hook = original
        self.assertEqual(result["status"], "failed", result)
        self.assertIn("before staging arm", result.get("error", ""))
        # The pre-launch per-arm snapshot check fired before any worker started.
        self.assertEqual(result["execution"], {})

    def test_empty_source_plan_snapshot_is_refused(self):
        report_path, _, _ = self._plan_build()
        with self.assertRaisesRegex(ValueError, "source-plan snapshot is required"):
            self._validate(report_path, [], "val_nosnap", random_cases=8, timeout_seconds=30)

    # -- (3) plan.json fingerprint binding round-trip (service-patch logic) -
    def test_plan_fingerprint_binds_result_and_inputs(self):
        report_path, plan_json, result = self._plan_build()
        # This is exactly the binding the ProjectService patch performs before it
        # trusts plan["inputs"] as the expected snapshot.
        self.assertEqual(_digest(_encoded(plan_json)), result["fingerprint"])
        self.assertEqual(plan_json["project_path"], json.loads(report_path.read_text(
            encoding="utf-8"))["project"]["project_path"])
        validated = self._validate(report_path, plan_json["inputs"], "val_fp",
                                   random_cases=32, timeout_seconds=60)
        self.assertEqual(validated["status"], "mixed_application_samples_passed",
                         validated.get("error") or validated)

    # Public service integration, distinct from direct candidate invocation.
    def _service_refused(self, plan, message):
        with patch("subprocess.Popen", side_effect=AssertionError("must refuse before launch")):
            with self.assertRaisesRegex(ValueError, message):
                self.service.validate(plan["plan_id"], self.contract_path, random_cases=8)
        self.assertFalse(any(Path(plan["output_dir"]).parent.glob("validation-*")))

    def test_service_application_contract_executes_separate_arms_and_keeps_history(self):
        _, plan, _ = self._plan_build()
        validator_pin = plan["toolchain"]["tools"]["engine_python_mixed_validate"]
        self.assertEqual(validator_pin["sha256"], hashlib.sha256(Path(pmv.__file__).read_bytes()).hexdigest())
        result = self.service.validate(plan["plan_id"], self.contract_path, random_cases=16, timeout_seconds=30)
        self.assertEqual(result["status"], "mixed_application_samples_passed", result)
        self.assertEqual(result["plan_id"], plan["plan_id"])
        self.assertNotEqual(result["execution"]["baseline"]["pid"], result["execution"]["protected"]["pid"])
        record = Path(plan["output_dir"]).parent / result["validation_id"] / "validation.json"
        original_record = record.read_bytes()
        again = self.service.validate(plan["plan_id"], self.contract_path, random_cases=8, timeout_seconds=30)
        self.assertEqual(again["status"], "mixed_application_samples_passed", again)
        self.assertNotEqual(result["validation_id"], again["validation_id"])
        self.assertEqual(record.read_bytes(), original_record)
        self.assertEqual(result["external_attack_evaluation"], "not_evaluated")

    def test_mcp_explicit_application_contract_reaches_service_validator(self):
        from types import SimpleNamespace
        from antirea.defense_mcp import DefenseBridge
        _, plan, _ = self._plan_build()
        bridge = DefenseBridge(SimpleNamespace(root=self.root), self.service)
        result = bridge.call("protection_source_validate", {
            "plan_id": plan["plan_id"], "contract_path": str(self.contract_path),
            "random_cases": 8, "timeout_seconds": 30})
        self.assertEqual(result["status"], "mixed_application_samples_passed", result)
        self.assertTrue(result["source_plan_snapshot_bound"])

    def test_service_rejects_changed_plan_fingerprint_before_execution(self):
        _, plan, _ = self._plan_build()
        changed = dict(plan, seed=999)
        (Path(plan["output_dir"]).parent / "plan.json").write_text(json.dumps(changed), encoding="utf-8")
        self._service_refused(plan, "source plan does not bind")

    def test_service_rejects_consistently_rehashed_wrong_plan_identity(self):
        mutations = {
            "plan_id": "source-20000101T000000Z-000000000000",
            "workspace_root": str(self.root / "other"),
            "kind": "native_source_build",
            "project_path": str(self.proj / "other.json"),
            "inspection": {"backend": "python_vm"},
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                _, plan, _ = self._plan_build()
                directory = Path(plan["output_dir"]).parent
                changed = dict(plan)
                changed[field] = value
                (directory / "plan.json").write_text(json.dumps(changed), encoding="utf-8")
                record = json.loads((directory / "result.json").read_bytes())
                record["fingerprint"] = _digest(_encoded(changed))
                (directory / "result.json").write_text(json.dumps(record), encoding="utf-8")
                self._service_refused(plan, "source plan does not bind")

    def test_service_rejects_result_identity_swap_before_execution(self):
        _, plan, _ = self._plan_build()
        path = Path(plan["output_dir"]).parent / "result.json"
        record = json.loads(path.read_bytes())
        record["plan_id"] = "source-20000101T000000Z-000000000000"
        path.write_text(json.dumps(record), encoding="utf-8")
        self._service_refused(plan, "source plan does not bind")

    def test_service_rejects_changed_validator_toolchain_before_execution(self):
        _, plan, _ = self._plan_build()
        altered = json.loads(json.dumps(plan["toolchain"]))
        altered["tools"]["engine_python_mixed_validate"]["sha256"] = "0" * 64
        with patch.object(self.service, "_toolchain", return_value=altered):
            self._service_refused(plan, "engine or toolchain changed")

    def test_service_rejects_changed_sibling_before_execution(self):
        _, plan, _ = self._plan_build()
        (self.proj / "widget" / "labels.py").write_text('BANNER = "changed"\n', encoding="utf-8")
        self._service_refused(plan, "changed since the bound source plan")

    def test_service_stop_preserves_no_launch_boundary(self):
        _, plan, _ = self._plan_build()
        stop = self.root / ".runs/defense-loop/STOP"
        stop.parent.mkdir(parents=True)
        stop.write_text("owned test stop", encoding="utf-8")
        with patch("subprocess.Popen", side_effect=AssertionError("must not launch")):
            result = self.service.validate(plan["plan_id"], self.contract_path, random_cases=8)
        self.assertEqual(result["status"], "cancelled")
        self.assertFalse(any(Path(plan["output_dir"]).parent.glob("validation-*")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
