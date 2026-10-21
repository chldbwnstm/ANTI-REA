"""Composite validation contracts; runtime launches are mocked here."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from antirea import source_validate as sv


class LoweredSourceValidationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.build = self.root / ".runs/build"
        self.build.mkdir(parents=True)
        self.report = self.build / "report.json"
        self.source_report = {"backend": "dotnet_il_native", "status": "artifact_created_unvalidated",
                              "frontend": {"methods": [{"selector": {"export": "core"},
                                  "metadata": {"return_type": "Int32", "parameters": ["Int32", "Int64"]}}]}}
        self.report.write_text(json.dumps(self.source_report), encoding="utf-8")
        self.contract = self.root / "contract.json"
        self.contract_data = {"schema_version": 1, "library_name": "sample", "functions": [
            {"name": "core", "return_type": "i32", "parameters": [
                {"name": "x", "type": "i32"}, {"name": "y", "type": "i64"}]}]}
        self.contract.write_text(json.dumps(self.contract_data), encoding="utf-8")
        self.output = self.root / ".runs/validation"
        self.reference = {"status": "passed", "methods": [{"export": "core", "total": 9,
            "comparisons": {arm: {"status": "passed", "matched": 9, "total": 9}
                            for arm in ("baseline", "protected")}}]}

    def native(self, report, contract, output, **kwargs):
        output.mkdir(parents=True)
        result = {"status": "functional_samples_passed", "functions": {"core": {}},
                  "cases_per_function": {"core": 9}, "behavior_repeats": 2}
        sv.native_validate._save(output / "validation.json", result)
        return result

    def run_validation(self):
        return sv.validate_lowered_build(self.report, self.contract, self.output,
                                        workspace_root=self.root, random_cases=7, timeout_seconds=40)

    def test_both_native_and_original_reference_are_required(self):
        with patch.object(sv.native_validate, "validate_build", side_effect=self.native) as native, \
                patch.object(sv, "_reference", return_value=self.reference) as reference:
            result = self.run_validation()
        self.assertEqual(result["status"], "functional_samples_passed")
        self.assertTrue(result["source_reference_required"])
        self.assertEqual(result["source_signature_evidence"]["signedness"], "original_source_metadata")
        self.assertEqual(reference.call_args.args[0], "dotnet_il_native")
        self.assertEqual(reference.call_args.kwargs["random_cases"], 7)
        self.assertEqual(reference.call_args.kwargs["timeout_seconds"], 40)
        self.assertEqual(native.call_args.args[2], self.output / "native")
        self.assertEqual(json.loads((self.output / "validation.json").read_text()), result)
        self.assertTrue((self.output / "native/validation.json").exists())

    def test_native_failure_does_not_run_reference(self):
        def fail(*args, **kwargs):
            result = self.native(*args, **kwargs)
            return {**result, "status": "failed"}
        with patch.object(sv.native_validate, "validate_build", side_effect=fail), \
                patch.object(sv, "_reference") as reference:
            self.assertEqual(self.run_validation()["status"], "failed")
            reference.assert_not_called()

    def test_reference_failure_cannot_be_hidden_by_matching_native_outputs(self):
        with patch.object(sv.native_validate, "validate_build", side_effect=self.native), \
                patch.object(sv, "_reference", return_value={"status": "failed"}):
            result = self.run_validation()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["source_reference"]["status"], "failed")

    def test_malformed_partial_or_duplicate_reference_is_not_passed(self):
        examples = [None, {"status": "passed"}, {"status": "passed", "methods": []}]
        for transform in (lambda m: m["comparisons"].pop("protected"),
                          lambda m: m.update(export="other"), lambda m: m.update(total=0),
                          lambda m: m["comparisons"]["baseline"].update(matched=8),
                          lambda m: m["comparisons"]["protected"].update(total=True)):
            example = copy.deepcopy(self.reference)
            transform(example["methods"][0])
            examples.append(example)
        examples.append({"status": "passed", "methods": self.reference["methods"] * 2})
        for example in examples:
            with self.subTest(example=example):
                self.assertFalse(sv._reference_passed(example, {"core"}))

    def test_reference_error_is_recorded_without_success(self):
        with patch.object(sv.native_validate, "validate_build", side_effect=self.native), \
                patch.object(sv, "_reference", side_effect=ValueError("original VM unavailable")):
            result = self.run_validation()
        self.assertEqual(result["status"], "failed")
        self.assertIn("original VM unavailable", result["error"])
        self.assertTrue((self.output / "validation.json").exists())

    def test_changed_build_report_is_failure(self):
        def reference(*args, **kwargs):
            self.report.write_text(self.report.read_text() + " ", encoding="utf-8")
            return self.reference
        with patch.object(sv.native_validate, "validate_build", side_effect=self.native), \
                patch.object(sv, "_reference", side_effect=reference):
            self.assertEqual(self.run_validation()["status"], "failed")

    def test_timeout_and_stop_remain_non_success(self):
        with patch.object(sv.native_validate, "validate_build", side_effect=self.native), \
                patch.object(sv, "_reference", return_value={"status": "timed_out"}):
            self.assertEqual(self.run_validation()["status"], "timed_out")

    def test_contract_changed_during_original_reference_is_failure(self):
        def reference(*args, **kwargs):
            self.contract.write_text("{\"changed\":true}", encoding="utf-8")
            return self.reference
        with patch.object(sv.native_validate, "validate_build", side_effect=self.native), \
                patch.object(sv, "_reference", side_effect=reference):
            result = self.run_validation()
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["inputs_unchanged"])

    def test_stop_prevents_any_execution_or_output(self):
        stop = self.root / ".runs/defense-loop/STOP"
        stop.parent.mkdir()
        stop.touch()
        with patch.object(sv.native_validate, "validate_build") as native, patch.object(sv, "_reference") as reference:
            self.assertEqual(self.run_validation()["status"], "cancelled")
            native.assert_not_called()
            reference.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_jvm_uses_its_original_runtime_backend(self):
        self.report.write_text(json.dumps(self.jvm_report()))
        with patch.object(sv.native_validate, "validate_build", side_effect=self.native), \
                patch.object(sv, "_reference", return_value=self.reference) as reference:
            self.assertEqual(self.run_validation()["status"], "functional_samples_passed")
        self.assertEqual(reference.call_args.args[0], "jvm_bytecode_native")

    @staticmethod
    def go_report():
        return {"backend": "go_typed_native", "status": "artifact_created_unvalidated",
                "project": {"selectors": [{"name": "Core", "export": "core"}]},
                "methods": [{"name": "helper", "export": "go_owned_helper", "parameters": ["int32"],
                             "return_type": "int32", "is_root": False},
                            {"name": "Core", "export": "core", "parameters": ["int32", "int64"],
                             "return_type": "int32", "is_root": True}]}

    @staticmethod
    def swift_report():
        return {"backend": "swift_llvm_native", "status": "artifact_created_unvalidated",
                "project": {"functions": ["core"]},
                "source_functions": [{"name": "core", "swift_name": "coreBody", "return_type": "i32",
                                      "parameters": [{"name": "x", "type": "i32"}, {"name": "y", "type": "i64"}]}]}

    def test_go_and_swift_require_original_execution_not_only_native_equality(self):
        for report in (self.go_report(), self.swift_report()):
            self.report.write_text(json.dumps(report))
            with self.subTest(backend=report["backend"]), patch.object(sv.native_validate, "validate_build", return_value={
                    "status": "functional_samples_passed", "functions": {"core": {}}}), \
                    patch.object(sv, "_reference", return_value={"status": "failed"}) as reference:
                self.assertEqual(self.run_validation()["status"], "failed")
                self.assertEqual(reference.call_args.args[0], report["backend"])

    def test_go_and_swift_metadata_reject_unsigned_contract_mismatch(self):
        for report in (self.go_report(), self.swift_report()):
            contract = copy.deepcopy(self.contract_data)
            self.assertEqual(sv.verify_source_contract(report, contract)["status"], "matched")
            contract["functions"][0]["parameters"][0]["type"] = "u32"
            with self.subTest(backend=report["backend"]):
                self.assert_preflight_rejected(report, contract)

    def test_go_selector_or_root_marker_mismatch_is_rejected(self):
        for change in (lambda r: r["project"]["selectors"][0].update(name="Wrong"),
                       lambda r: r["methods"][-1].update(is_root="true"),
                       lambda r: r["methods"][-1].update(return_type="uint")):
            report = self.go_report()
            change(report)
            self.assert_preflight_rejected(report, self.contract_data)

    def test_swift_metadata_must_cover_declared_exports(self):
        report = self.swift_report()
        report["project"]["functions"].append("missing")
        self.assert_preflight_rejected(report, self.contract_data)

    @staticmethod
    def jvm_report():
        return {"backend": "jvm_bytecode_native", "status": "artifact_created_unvalidated",
                "project": {"methods": [{"export": "core", "descriptor": "(IJ)I"}]},
                "methods": [{"export": "owned_helper", "descriptor": "(I)I", "is_root": False},
                            {"export": "core", "descriptor": "(IJ)I", "is_root": True}]}

    def assert_preflight_rejected(self, report, contract):
        self.report.write_text(json.dumps(report), encoding="utf-8")
        self.contract.write_text(json.dumps(contract), encoding="utf-8")
        with patch.object(sv.native_validate, "validate_build") as native, patch.object(sv, "_reference") as reference:
            with self.assertRaises(ValueError):
                self.run_validation()
            native.assert_not_called()
            reference.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_same_width_unsigned_return_or_argument_cannot_pass_either_backend(self):
        for report in (self.source_report, self.jvm_report()):
            for field in ("return", "arg0", "arg1"):
                contract = copy.deepcopy(self.contract_data)
                function = contract["functions"][0]
                if field == "return":
                    function["return_type"] = "u32"
                else:
                    parameter = function["parameters"][int(field[-1])]
                    parameter["type"] = parameter["type"].replace("i", "u")
                with self.subTest(backend=report["backend"], field=field):
                    self.assert_preflight_rejected(report, contract)

    def test_argument_order_arity_and_export_set_must_match(self):
        for report in (self.source_report, self.jvm_report()):
            for change in (lambda f: f["parameters"].reverse(), lambda f: f["parameters"].pop(),
                           lambda f: f.update(name="renamed"), lambda f: f.update(return_type="i64")):
                contract = copy.deepcopy(self.contract_data)
                change(contract["functions"][0])
                with self.subTest(backend=report["backend"], function=contract):
                    self.assert_preflight_rejected(report, contract)
            extra = copy.deepcopy(self.contract_data)
            extra["functions"].append({"name": "other", "return_type": "i32", "parameters": []})
            self.assert_preflight_rejected(report, extra)

    def test_parameter_names_do_not_override_abi_and_jvm_private_helpers_are_not_exports(self):
        for report in (self.source_report, self.jvm_report()):
            contract = copy.deepcopy(self.contract_data)
            contract["functions"][0]["parameters"][0]["name"] = "caller_chosen"
            evidence = sv.verify_source_contract(report, contract)
            self.assertEqual(set(evidence["functions"]), {"core"})
            self.assertFalse(evidence["parameter_names_compared"])

    def test_csharp_exact_unsigned_and_zero_argument_metadata_supported(self):
        for scalar, abi in (("Int32", "i32"), ("UInt32", "u32"), ("Int64", "i64"), ("UInt64", "u64")):
            for parameters in ([], [scalar]):
                report = copy.deepcopy(self.source_report)
                report["frontend"]["methods"][0]["metadata"] = {"return_type": scalar, "parameters": parameters}
                contract = copy.deepcopy(self.contract_data)
                contract["functions"][0].update(return_type=abi, parameters=[{"name": "argument", "type": abi}] if parameters else [])
                with self.subTest(scalar=scalar, parameters=parameters):
                    self.assertEqual(sv.verify_source_contract(report, contract)["status"], "matched")

    def test_invalid_or_duplicate_csharp_metadata_rejected_before_execution(self):
        for bad_methods in (None, [], [None], [{"selector": None, "metadata": {}}],
                            self.source_report["frontend"]["methods"] * 2):
            report = copy.deepcopy(self.source_report)
            report["frontend"]["methods"] = bad_methods
            with self.subTest(methods=bad_methods):
                self.assert_preflight_rejected(report, self.contract_data)
        for result, parameters in (("Boolean", []), ([], []), ("Int32", "Int32"), ("Int32", [None]),
                                   ("Int32", ["Int32"] * 9)):
            report = copy.deepcopy(self.source_report)
            report["frontend"]["methods"][0]["metadata"] = {"return_type": result, "parameters": parameters}
            with self.subTest(result=result, parameters=parameters):
                self.assert_preflight_rejected(report, self.contract_data)

    def test_invalid_duplicate_or_selector_mismatched_jvm_metadata_rejected(self):
        changes = [lambda r: r["methods"].append(copy.deepcopy(r["methods"][-1])),
                   lambda r: r["methods"][-1].update(is_root="true"),
                   lambda r: r["methods"][-1].update(is_root=False),
                   lambda r: r["methods"][-1].update(descriptor="(ID)I"),
                   lambda r: r["methods"][-1].update(descriptor="(IJ)V"),
                   lambda r: r["methods"][-1].update(descriptor=None),
                   lambda r: r["project"]["methods"][0].update(descriptor="(JI)I"),
                   lambda r: r["project"]["methods"][0].update(export="other")]
        for change in changes:
            report = self.jvm_report()
            change(report)
            with self.subTest(report=report):
                self.assert_preflight_rejected(report, self.contract_data)

    def test_malformed_incoming_contract_still_uses_normalized_boundary(self):
        for contract in (None, [], {}, True, {**self.contract_data, "unexpected": True}):
            with self.subTest(contract=contract):
                self.assert_preflight_rejected(self.source_report, contract)

    def test_export_order_is_not_part_of_abi_signature(self):
        report = copy.deepcopy(self.source_report)
        second = copy.deepcopy(report["frontend"]["methods"][0])
        second["selector"]["export"] = "other"
        report["frontend"]["methods"].append(second)
        contract = copy.deepcopy(self.contract_data)
        second_function = copy.deepcopy(contract["functions"][0])
        second_function["name"] = "other"
        contract["functions"].insert(0, second_function)
        self.assertEqual(set(sv.verify_source_contract(report, contract)["functions"]), {"core", "other"})

    def test_unsupported_or_received_report_is_rejected_before_runtime(self):
        for backend in ("python_vm", "javascript_vm", "unknown"):
            self.report.write_text(json.dumps({"backend": backend, "status": "artifact_created_unvalidated"}))
            with self.subTest(backend=backend), patch.object(sv.native_validate, "validate_build") as native:
                with self.assertRaises(ValueError):
                    self.run_validation()
                native.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_existing_output_and_bad_sampling_are_rejected(self):
        for name, value in (("random_cases", True), ("random_cases", 0), ("random_cases", 8193),
                            ("timeout_seconds", 0), ("timeout_seconds", True), ("timeout_seconds", 601)):
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                sv.validate_lowered_build(self.report, self.contract, self.output,
                                         workspace_root=self.root, **{name: value})
        self.output.mkdir()
        with self.assertRaisesRegex(ValueError, "fresh"):
            self.run_validation()


if __name__ == "__main__":
    unittest.main()
