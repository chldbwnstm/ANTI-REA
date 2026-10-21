"""Python validation transport and false-acceptance checks, not VM coverage proof."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from antirea.python_validate import (make_cases, validate_contract, validate_build,
                                     _observed_call, _verify_signature, _verify_coverage)


CONTRACT = {"schema_version": 1, "kind": "python_integer_samples", "functions": [
    {"name": "core", "parameters": [
        {"name": "x", "minimum": -(2**100), "maximum": 2**100},
        {"name": "y", "minimum": -3, "maximum": 3}]}]}


class PythonValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.build = self.root / ".runs" / "built"
        self.build.mkdir(parents=True)
        self.contract = self.source / "contract.json"
        self.contract.write_text(json.dumps(CONTRACT), encoding="utf-8")

    def prepare(self, baseline="def core(x, y):\n    return x * x + y\n", protected=None):
        report = {"status": "artifact_created_unvalidated", "backend": "python_vm", "artifacts": {},
                  "coverage": {"schema_version": 1, "backend": "python_vm",
                               "selected_functions": ["core"], "exported_functions": ["core"],
                               "validation_exports": ["core"], "helper_closure": ["core"],
                               "functions": {"core": {"parameters": ["x", "y"], "helpers": [],
                                                       "instruction_count": 9, "vm_function_id": 0,
                                                       "virtualized": True}}}}
        for arm, text in (("baseline", baseline), ("protected", baseline if protected is None else protected)):
            path = self.build / (arm + ".py")
            path.write_text(text, encoding="utf-8")
            report["artifacts"][arm] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        path = self.build / "report.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        return path

    def run_validation(self, report):
        return validate_build(report, self.contract, self.root / ".runs" / "validation",
                              workspace_root=self.root, random_cases=16, timeout_seconds=10)

    def test_bounds_are_not_machine_integer_truncations(self):
        cases = make_cases(CONTRACT, 20, 123)
        self.assertEqual(cases, make_cases(CONTRACT, 20, 123))
        self.assertIn([-(2**100), -3], cases["core"])
        self.assertIn([2**100, 3], cases["core"])
        narrow = copy.deepcopy(CONTRACT)
        narrow["functions"][0]["parameters"][0].update(minimum=5, maximum=9)
        self.assertTrue(all(5 <= row[0] <= 9 for row in make_cases(narrow, 4)["core"]))

    def test_contract_fields_duplicates_and_bounds_are_strict(self):
        variants = []
        value = copy.deepcopy(CONTRACT)
        value["schema_version"] = True
        variants.append(value)
        value = copy.deepcopy(CONTRACT)
        value["functions"].append(copy.deepcopy(value["functions"][0]))
        variants.append(value)
        for change in ({"minimum": True}, {"minimum": 4, "maximum": 3}, {"maximum": 2**257}):
            value = copy.deepcopy(CONTRACT)
            value["functions"][0]["parameters"][0].update(change)
            variants.append(value)
        value = copy.deepcopy(CONTRACT)
        value["functions"][0]["parameters"][0]["extra"] = "ignored?"
        variants.append(value)
        for invalid in variants:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_contract(invalid)

    def test_observation_preserves_types_big_integers_and_exception_classes(self):
        self.assertEqual(_observed_call(lambda x: x * x, [2**100])["value"], str(2**200))
        self.assertNotEqual(_observed_call(lambda: True, []), _observed_call(lambda: 1, []))
        self.assertEqual(_observed_call(lambda: 1 // 0, []), {"kind": "exception", "type": "builtins.ZeroDivisionError"})
        with self.assertRaisesRegex(ValueError, "int/bool"):
            _observed_call(lambda: "not supported", [])

    def test_signature_rejects_arity_names_defaults_and_variadics(self):
        parameters = CONTRACT["functions"][0]["parameters"]
        _verify_signature(lambda x, y: x + y, parameters)
        for callback in (lambda x: x, lambda x, z: x + z, lambda x, y=0: x + y, lambda *args: 1):
            with self.assertRaises(ValueError):
                _verify_signature(callback, parameters)

    def test_real_workers_preserve_unbounded_return_precision(self):
        result = self.run_validation(self.prepare())
        self.assertEqual(result["status"], "functional_samples_passed", result)
        reply = json.loads((self.root / ".runs/validation/protected.request.reply.json").read_text())
        outputs = reply["outputs"]["core"]
        self.assertEqual(outputs, reply["outputs_second"]["core"])
        self.assertIs(result["functions"]["core"]["raw_repeat_arrays_compared"], True)
        self.assertTrue(any(abs(int(item["value"])) > 2**64 for item in outputs))
        self.assertTrue(result["inputs_unchanged"])
        self.assertFalse((self.build / "__pycache__").exists())

    def test_equal_exceptions_only_are_not_a_functional_pass(self):
        result = self.run_validation(self.prepare("def core(x, y):\n    return 1 // 0\n"))
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["functions"]["core"]["sampled_output_match"])
        self.assertEqual(result["functions"]["core"]["baseline_ordinary_returns"], 0)

    def test_changed_behavior_cannot_pass(self):
        result = self.run_validation(self.prepare(protected="def core(x, y):\n    return x * x + y + 1\n"))
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["functions"]["core"]["sampled_output_match"])

    def test_wrong_contract_and_changed_artifact_never_launch_workers(self):
        report = self.prepare()
        bad = copy.deepcopy(CONTRACT)
        bad["functions"][0]["parameters"][0]["name"] = "wrong_name"
        self.contract.write_text(json.dumps(bad), encoding="utf-8")
        with patch("antirea.python_validate.run_logged") as runner:
            with self.assertRaisesRegex(ValueError, "parameters differ"):
                self.run_validation(report)
            runner.assert_not_called()
        self.contract.write_text(json.dumps(CONTRACT), encoding="utf-8")
        (self.build / "protected.py").write_text("changed", encoding="utf-8")
        with patch("antirea.python_validate.run_logged") as runner:
            with self.assertRaisesRegex(ValueError, "hash differs"):
                self.run_validation(report)
            runner.assert_not_called()

    def test_stop_prevents_execution(self):
        report = self.prepare()
        stop = self.root / ".runs/defense-loop/STOP"
        stop.parent.mkdir()
        stop.touch()
        with patch("antirea.python_validate.run_logged") as runner:
            result = self.run_validation(report)
            self.assertEqual(result["status"], "cancelled")
            runner.assert_not_called()

    def closure_coverage(self):
        """Current frontend-shaped scope, not an independent transformation proof."""
        report = json.loads(self.prepare().read_text(encoding="utf-8"))
        coverage = report["coverage"]
        coverage["helper_closure"].append("helper")
        coverage["functions"]["core"]["helpers"] = ["helper"]
        coverage["functions"]["helper"] = {"parameters": ["value"], "helpers": [],
                                           "instruction_count": 5, "vm_function_id": 1,
                                           "virtualized": True}
        return coverage

    def reject_coverage_before_execution(self, coverage):
        report_path = self.prepare()
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["coverage"] = coverage
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with patch("antirea.python_validate.run_logged") as runner:
            with self.assertRaises(ValueError):
                self.run_validation(report_path)
            runner.assert_not_called()
        self.assertFalse((self.root / ".runs" / "validation").exists())

    def test_complete_helper_closure_matches_current_frontend(self):
        # Parsing/generation is nonexecuting. This ties the checker to the actual
        # backend schema rather than permitting an invented minimal fixture.
        from antirea.python_frontend import protect_python_source
        source = "def helper(value):\n    return value + 7\ndef core(x, y):\n    return helper(x) + y\n"
        report = protect_python_source(source, ["core"], self.root / ".runs" / "actual-generated", seed=19)
        functions = _verify_coverage(report["coverage"], ["core"])
        self.assertEqual(set(functions), {"core", "helper"})
        self.assertEqual(functions["core"]["parameters"], ["x", "y"])

    def test_declared_helper_without_function_evidence_is_rejected(self):
        coverage = self.closure_coverage()
        del coverage["functions"]["helper"]
        self.reject_coverage_before_execution(coverage)

    def test_extra_function_missing_declared_closure_is_rejected(self):
        coverage = self.closure_coverage()
        coverage["helper_closure"] = ["core"]
        self.reject_coverage_before_execution(coverage)

    def test_every_function_must_be_virtualized_with_typed_evidence(self):
        initial = self.closure_coverage()
        changes = [{"virtualized": False}, {"virtualized": 1}, {"parameters": "value"},
                   {"parameters": ["value", "value"]}, {"helpers": "other"},
                   {"helpers": ["missing"]}, {"helpers": ["core"]},
                   {"instruction_count": True}, {"instruction_count": 0},
                   {"vm_function_id": True}, {"vm_function_id": 0}, {"vm_function_id": 2}]
        for change in changes:
            with self.subTest(change=change):
                coverage = copy.deepcopy(initial)
                coverage["functions"]["helper"].update(change)
                self.reject_coverage_before_execution(coverage)
        for value in (None, [], True):
            with self.subTest(evidence=value):
                coverage = copy.deepcopy(initial)
                coverage["functions"]["helper"] = value
                self.reject_coverage_before_execution(coverage)

    def test_roots_exports_and_validation_exports_must_be_identical(self):
        initial = self.closure_coverage()
        for field in ("selected_functions", "exported_functions", "validation_exports"):
            for value in (["core", "helper"], ["helper"], [], ["core", "core"], [None], [["core"]]):
                with self.subTest(field=field, value=value):
                    coverage = copy.deepcopy(initial)
                    coverage[field] = value
                    self.reject_coverage_before_execution(coverage)

    def test_unreachable_helper_or_root_missing_from_closure_is_rejected(self):
        coverage = self.closure_coverage()
        coverage["functions"]["core"]["helpers"] = []
        self.reject_coverage_before_execution(coverage)
        coverage = self.closure_coverage()
        coverage["helper_closure"] = ["helper"]
        del coverage["functions"]["core"]
        coverage["functions"]["helper"]["vm_function_id"] = 0
        self.reject_coverage_before_execution(coverage)

    def test_missing_legacy_scope_fields_and_malformed_collections_fail_closed(self):
        initial = self.closure_coverage()
        for field in ("schema_version", "backend", "selected_functions", "validation_exports", "helper_closure", "functions"):
            with self.subTest(missing=field):
                coverage = copy.deepcopy(initial)
                del coverage[field]
                self.reject_coverage_before_execution(coverage)
        for field, value in (("schema_version", True), ("backend", "native"), ("functions", []),
                             ("helper_closure", "core"), ("helper_closure", ["core", "helper", "helper"]),
                             ("helper_closure", ["core", ["helper"]])):
            with self.subTest(field=field, value=value):
                coverage = copy.deepcopy(initial)
                coverage[field] = value
                self.reject_coverage_before_execution(coverage)
        self.reject_coverage_before_execution(None)


if __name__ == "__main__":
    unittest.main()
