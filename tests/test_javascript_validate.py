"""Owned scalar transport/false-pass regressions, not arbitrary artifact VM proof."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from antirea.javascript_frontend import discover_toolchain
from antirea.javascript_validate import make_cases, validate_contract, validate_build, _verify_coverage


CONTRACT = {"schema_version": 1, "kind": "javascript_scalar_samples", "functions": [
    {"name": "core", "parameters": [{"name": "x", "type": "number", "minimum": -100, "maximum": 100},
                                     {"name": "y", "type": "number", "minimum": -5, "maximum": 5}]}]}


class JavaScriptValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try: cls.toolchain = discover_toolchain()
        except ValueError as exc: raise unittest.SkipTest(str(exc))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"; self.source.mkdir()
        self.contract = self.source / "contract.json"; self.contract.write_text(json.dumps(CONTRACT), encoding="utf-8")
        self.directory = self.root / ".runs/built"; self.directory.mkdir(parents=True)

    def prepare(self, baseline="module.exports.core = function(x,y) { return x / y; };", protected=None):
        evidence = {"parameters": ["x", "y"], "helpers": [], "instruction_count": 4, "vm_function_id": 0, "virtualized": True}
        report = {"schema_version": 1, "backend": "javascript_vm", "status": "artifact_created_unvalidated",
                  "toolchain": self.toolchain, "artifacts": {},
                  "coverage": {"schema_version": 1, "backend": "javascript_vm", "selected_functions": ["core"],
                               "exported_functions": ["core"], "validation_exports": ["core"], "helper_closure": ["core"],
                               "functions": {"core": evidence}}}
        for arm, source in (("baseline", baseline), ("protected", baseline if protected is None else protected)):
            path = self.directory / (arm + ".cjs"); path.write_text(source, encoding="utf-8")
            report["artifacts"][arm] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        path = self.directory / "report.json"; path.write_text(json.dumps(report), encoding="utf-8")
        return path

    def validate(self, report, timeout=10):
        return validate_build(report, self.contract, self.directory / "validation", workspace_root=self.root,
                              random_cases=16, timeout_seconds=timeout)

    def test_tags_preserve_minus_zero_and_special_edges_without_json_nan(self):
        cases = make_cases(CONTRACT, 16, 123)["core"]
        numbers = [tag["value"] for row in cases for tag in row]
        self.assertIn("8000000000000000", numbers)
        self.assertIn("0000000000000000", numbers)
        self.assertIn("7ff0000000000000", numbers)
        self.assertIn("fff0000000000000", numbers)
        self.assertTrue(any(struct.unpack(">d", bytes.fromhex(value))[0] != struct.unpack(">d", bytes.fromhex(value))[0] for value in numbers))
        json.dumps(cases, allow_nan=False)
        self.assertEqual(len(cases), len({json.dumps(row, sort_keys=True) for row in cases}))

    def test_bigint_bounds_remain_decimal_strings_and_boolean_domain_is_exhaustive(self):
        bigint = copy.deepcopy(CONTRACT)
        for p in bigint["functions"][0]["parameters"]:
            p.update(type="bigint", minimum=str(-(2 ** 100)), maximum=str(2 ** 100))
        cases = make_cases(bigint, 16)["core"]
        self.assertTrue(any(abs(int(p["value"])) > 2 ** 53 for row in cases for p in row))
        boolean = {"schema_version": 1, "kind": "javascript_scalar_samples", "functions": [
            {"name": "core", "parameters": [{"name": "x", "type": "boolean"}, {"name": "y", "type": "boolean"}]}]}
        self.assertEqual(len(make_cases(boolean, 8192)["core"]), 4)

    def test_contract_rejects_machine_precision_loss_and_malformed_types(self):
        variants = []
        for update in ({"maximum": 2 ** 53}, {"minimum": True}, {"type": "bigint"}, {"type": "boolean"}, {"extra": 1}):
            value = copy.deepcopy(CONTRACT); value["functions"][0]["parameters"][0].update(update); variants.append(value)
        value = copy.deepcopy(CONTRACT); value["schema_version"] = True; variants.append(value)
        value = copy.deepcopy(CONTRACT); value["functions"].append(value["functions"][0]); variants.append(value)
        for value in variants:
            with self.subTest(value=value), self.assertRaises(ValueError): validate_contract(value)

    def test_real_workers_return_nan_infinity_and_negative_zero_exactly(self):
        result = self.validate(self.prepare())
        self.assertEqual(result["status"], "functional_samples_passed", result)
        reply = json.loads((self.directory / "validation/baseline.reply.json").read_text())
        outputs = reply["outputs"]["core"]
        self.assertEqual(outputs, reply["outputs_second"]["core"])
        self.assertIs(result["functions"]["core"]["raw_repeat_arrays_compared"], True)
        values = {item["value"] for item in outputs}
        self.assertIn("NaN", values)
        self.assertIn("+Infinity", values)
        self.assertIn("-Infinity", values)
        self.assertIn("8000000000000000", values)

    def test_bool_and_number_or_negative_zero_changes_do_not_pass(self):
        result = self.validate(self.prepare("module.exports.core = function(x,y) { return true; };",
                                            "module.exports.core = function(x,y) { return 1; };"))
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["functions"]["core"]["sampled_output_match"])

    def test_all_exceptions_and_unsupported_returns_cannot_pass(self):
        result = self.validate(self.prepare("module.exports.core = function(x,y) { return 1n / 0n; };"))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["functions"]["core"]["baseline_ordinary_returns"], 0)

    def test_changed_hash_never_launches_worker(self):
        report = self.prepare(); (self.directory / "protected.cjs").write_text("changed", encoding="utf-8")
        with patch("antirea.javascript_validate.run_logged") as runner:
            with self.assertRaisesRegex(ValueError, "hash differs"): self.validate(report)
            runner.assert_not_called()

    def test_missing_helper_nonvirtualized_and_wrong_parameters_fail_before_execution(self):
        path = self.prepare(); original = json.loads(path.read_text())
        variants = []
        item = copy.deepcopy(original); item["coverage"]["helper_closure"].append("missing"); variants.append(item)
        item = copy.deepcopy(original); item["coverage"]["functions"]["core"]["virtualized"] = 1; variants.append(item)
        item = copy.deepcopy(original); item["coverage"]["functions"]["core"]["parameters"] = ["y", "x"]; variants.append(item)
        item = copy.deepcopy(original); del item["coverage"]["validation_exports"]; variants.append(item)
        for item in variants:
            path.write_text(json.dumps(item), encoding="utf-8")
            with patch("antirea.javascript_validate.run_logged") as runner:
                with self.assertRaises(ValueError): self.validate(path)
                runner.assert_not_called()

    def test_stdout_is_not_the_result_protocol(self):
        result = self.validate(self.prepare("console.log('owned diagnostic'); module.exports.core = function(x,y) { return x+y; };"))
        self.assertEqual(result["status"], "functional_samples_passed", result)
        self.assertIn("owned diagnostic", (self.directory / "validation/baseline.stdout.log").read_text())

    def test_timeout_is_not_a_functional_pass_and_owned_tree_is_cleaned(self):
        report = self.prepare(protected="module.exports.core = function(x,y) { while(true) {} };")
        result = self.validate(report, timeout=1)
        self.assertEqual(result["status"], "timed_out", result)
        self.assertTrue(result["execution"]["protected"]["timed_out"])
        self.assertTrue(result["execution"]["protected"]["cleanup"]["parent_exit_confirmed"])

    def test_stop_cancels_without_execution(self):
        report = self.prepare(); stop = self.root / ".runs/defense-loop/STOP"; stop.parent.mkdir(); stop.touch()
        with patch("antirea.javascript_validate.run_logged") as runner:
            result = self.validate(report); self.assertEqual(result["status"], "cancelled"); runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
