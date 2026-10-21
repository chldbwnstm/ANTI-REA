"""Boundary evidence regressions; target libraries are never executed here."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from antirea import native_build, native_validate as nv, scope


ORIGINAL = '''define i64 @core(i64 %a, i64 %b) {
  %r = call i64 @secret(i64 %a, i64 %b)
  ret i64 %r
}
define i64 @secret(i64 %a, i64 %b) {
  %r = add i64 %a, %b
  ret i64 %r
}
'''
CONTRACT = {"schema_version": 1, "library_name": "fixture", "functions": [
    {"name": "core", "return_type": "u64", "parameters": [
        {"name": "a", "type": "u64"}, {"name": "b", "type": "u64"}]}]}
BOUNDARY_CONTRACT = {"schema_version": 1, "functions": {"core": {
    "signature": "i64 (i64, i64)", "abi_attributes": [[], [], []],
    "callee": "secret", "argument_indices": [0, 1],
    "callee_signature": "i64 (i64, i64)", "callee_calling_convention": 0,
    "callee_abi_attributes": [[], [], []],
    "call_abi_attributes": [[], [], []], "return": {"kind": "call_result"}}}}
QUALIFICATION = "Parsed final call/parameter/return relation matches the reviewed boundary; not an all-input call-frequency or resistance claim."
EVIDENCE = {"status": "verified", "functions": {"core": {
    "callee": "secret", "ordered_arguments": True, "return_preserved": True,
    "signature_preserved": True}}, "qualification": QUALIFICATION}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class BoundaryValidationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="antirea-boundary-validation-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.build = self.root / ".runs/build"
        self.build.mkdir(parents=True)
        self.original = self.build / "module.before.ll"
        self.business = self.build / "module.protection-business.ll"
        self.boundary = self.build / "module.public-boundaries.ll"
        self.final = self.build / "protected.codegen.ll"
        for path in (self.original, self.business, self.boundary, self.final):
            path.write_text(ORIGINAL, encoding="utf-8")
        self.config = self.root / ".tools/kagura-toolchain.json"
        self.library = self.root / ".tools/llvm/bin/LLVM-C.dll"
        self.library.parent.mkdir(parents=True)
        self.library.write_bytes(b"NONEXECUTABLE MOCK PARSER; MUST NEVER BE LOADED")
        self.config.write_text(json.dumps({"llvm_root": str(self.library.parent.parent)}), encoding="utf-8")
        source = self.root / "source"
        source.mkdir()
        self.contract_path = source / "contract.json"
        self.contract_path.write_text(json.dumps(CONTRACT), encoding="utf-8")
        policy = {"core_roots": ["secret"], "public_presentation": {"core": "reviewed pure forwarder"},
                  "entry_points": ["core"]}
        plan = scope.analyze_scope([self.original], policy)
        self.assertEqual(plan["status"], "ready")
        transit = {"schema_version": 1, "status": "verified", "contract": copy.deepcopy(BOUNDARY_CONTRACT),
                   "evidence": copy.deepcopy(EVIDENCE), "original_ir": self.descriptor(self.original),
                   "business_ir": self.descriptor(self.business), "boundary_ir": self.descriptor(self.boundary),
                   "final_ir": self.descriptor(self.final)}
        self.report = {"status": "artifact_created_unvalidated", "coverage_schema_version": 2,
            "boundary_transit": transit, "signature_ir": self.descriptor(self.original),
            "coverage": {"schema_version": 2, "functions": {"secret": {"virtualized": True}},
                         "selected_functions": ["secret"], "exported_functions": ["core"],
                         "public_boundaries": {"core": {"defined": True, "virtualized": False}},
                         "scope_plan": plan, "boundary_transit": copy.deepcopy(transit)},
            "tool_hashes": {str(self.config): digest(self.config), str(self.library): digest(self.library)},
            "artifacts": {}, "artifact_hashes": {}}
        for arm in ("baseline", "protected"):
            path = self.build / (arm + ".dll")
            path.write_bytes(b"NONEXECUTABLE MOCK TARGET; NEVER EXECUTED")
            self.report["artifacts"][arm] = self.descriptor(path)
        self.report_path = self.build / "report.json"
        self.save()
        self.calls = []
        self.mutation = None
        self.parser_contract = self.enterContext(patch("antirea.native_build._boundary_contract", return_value=copy.deepcopy(BOUNDARY_CONTRACT)))
        self.parser_evidence = self.enterContext(patch("antirea.native_build._boundary_transit_evidence", return_value=copy.deepcopy(EVIDENCE)))
        self.runner = self.enterContext(patch("antirea.native_validate.run_logged", side_effect=self.fake_worker))

    @staticmethod
    def descriptor(path):
        return {"path": str(path), "sha256": digest(path)}

    def save(self):
        coverage_path = self.build / "coverage.json"
        coverage_path.write_text(json.dumps(self.report["coverage"]), encoding="utf-8")
        self.report["artifact_hashes"] = {str(p.relative_to(self.build)): digest(p)
            for p in self.build.rglob("*") if p.is_file() and p != self.report_path}
        self.report_path.write_text(json.dumps(self.report), encoding="utf-8")

    def both(self, key, value):
        self.report["boundary_transit"][key] = copy.deepcopy(value)
        self.report["coverage"]["boundary_transit"][key] = copy.deepcopy(value)

    def fake_worker(self, argv, cwd, prefix, timeout, **kwargs):
        request = Path(argv[-1])
        data = json.loads(request.read_text(encoding="utf-8"))
        cases = nv.make_cases(data["contract"], data["random_cases"], data["seed"])
        reply = {"outputs": {name: [0] * len(rows) for name, rows in cases.items()},
                 "deterministic": {name: True for name in cases},
                 "timings": {name: {"samples_ns": [10] * 7, "median_ns": 10,
                    "calls_per_batch": min(256, len(rows)), "warmup_batches": 1} for name, rows in cases.items()}}
        request.with_suffix(".reply.json").write_text(json.dumps(reply), encoding="utf-8")
        self.calls.append(data)
        if self.mutation:
            self.mutation()
        return {"returncode": 0, "timed_out": False, "cancelled": False,
                "cleanup": {"job_assigned": True, "active_after": 0,
                            "parent_exit_confirmed": True, "job_handle_closed": True}}

    def validate(self, name="validation"):
        return nv.validate_build(self.report_path, self.contract_path, self.root / ".runs" / name,
                                 workspace_root=self.root, random_cases=2)

    def wrap_native_report(self):
        """Model the actual frontend descriptor without rewriting a native build."""
        wrapper = self.root / ".runs/composed"
        native = wrapper / "native"
        native.mkdir(parents=True)
        old = self.build
        for path in old.iterdir():
            if path.is_file():
                (native / path.name).write_bytes(path.read_bytes())
        # JSON paths must be rebound, but IR bytes are identical.
        encoded = json.dumps(self.report).replace(json.dumps(str(old))[1:-1], json.dumps(str(native))[1:-1])
        self.report = json.loads(encoded)
        self.build = native
        self.original, self.business, self.boundary, self.final = (
            native / p.name for p in (self.original, self.business, self.boundary, self.final))
        self.report_path = native / "report.json"
        self.save()
        inner_path = self.report_path
        outer = {"status": "artifact_created_unvalidated", "backend": "test_composed_native",
            "native_report": str(inner_path), "native_report_sha256": digest(inner_path),
            "coverage": copy.deepcopy(self.report["coverage"]),
            "artifacts": copy.deepcopy(self.report["artifacts"]),
            "signature_ir": copy.deepcopy(self.report["signature_ir"])}
        self.report_path = wrapper / "report.json"
        self.report_path.write_text(json.dumps(outer), encoding="utf-8")
        return outer, inner_path

    def reject(self, text):
        self.save()
        with self.assertRaisesRegex((ValueError, native_build.NativeBuildError), text):
            self.validate()
        self.runner.assert_not_called()

    def test_verified_contract_is_recomputed_before_workers(self):
        result = self.validate()
        self.assertEqual(result["status"], "functional_samples_passed")
        self.assertEqual(result["boundary_transit"]["status"], "verified")
        self.assertTrue(result["boundary_transit_inputs_unchanged"])
        self.parser_contract.assert_called_once_with(self.original, ["core"], self.library,
            expected_calls=self.report["coverage"]["scope_plan"]["graph"]["calls"])
        self.parser_evidence.assert_called_once_with(self.final, BOUNDARY_CONTRACT, self.library)
        self.assertEqual(len(self.calls), 2)

    def test_schema_two_missing_descriptor_cannot_fall_back(self):
        self.report.pop("boundary_transit")
        self.reject("identical")

    def test_report_and_coverage_must_match(self):
        self.report["boundary_transit"]["status"] = "no_boundaries"
        self.reject("identical")

    def test_marker_prevents_schema_downgrade(self):
        self.report["coverage"]["schema_version"] = 1
        self.reject("inconsistent")

    def test_wrong_ir_hash_fails_before_parser_or_worker(self):
        self.both("final_ir", {"path": str(self.final), "sha256": "0" * 64})
        self.reject("artifact hash")
        self.parser_contract.assert_not_called()

    def test_artifact_hash_inventory_is_required(self):
        self.report["artifact_hashes"].pop("module.public-boundaries.ll")
        self.report_path.write_text(json.dumps(self.report), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "artifact hash"):
            self.validate()
        self.runner.assert_not_called()

    def test_fake_contract_fails_against_original_parser(self):
        bad = copy.deepcopy(BOUNDARY_CONTRACT)
        bad["functions"]["core"]["callee"] = "unrelated"
        self.both("contract", bad)
        self.reject("contract differs")

    def test_contract_preserves_json_scalar_types(self):
        bad = copy.deepcopy(BOUNDARY_CONTRACT)
        bad["functions"]["core"]["argument_indices"] = [False, True]
        self.both("contract", bad)
        self.reject("contract differs")

    def test_forged_scope_calls_fail_before_parser(self):
        self.report["coverage"]["scope_plan"]["graph"]["calls"]["core"] = []
        self.reject("scope differs")
        self.parser_contract.assert_not_called()

    def test_fake_final_evidence_fails(self):
        bad = copy.deepcopy(EVIDENCE)
        bad["functions"]["core"]["return_preserved"] = False
        self.both("evidence", bad)
        self.reject("evidence differs")

    def test_missing_scope_is_not_an_explicit_boundary_waiver(self):
        self.report["coverage"]["scope_plan"] = None
        self.reject("reviewed scope")

    def test_decoy_final_filename_is_not_accepted(self):
        decoy = self.build / "nice-looking.ll"
        decoy.write_text(ORIGINAL, encoding="utf-8")
        self.both("final_ir", self.descriptor(decoy))
        self.reject("artifact name")

    def test_missing_or_changed_parser_pin_prevents_loading(self):
        self.report["tool_hashes"][str(self.library)] = "0" * 64
        self.reject("tool pins")
        self.parser_contract.assert_not_called()

    def test_persisted_coverage_is_watched(self):
        coverage_file = self.build / "coverage.json"
        saved = json.loads(coverage_file.read_text())
        saved["boundary_transit"]["status"] = "no_boundaries"
        coverage_file.write_text(json.dumps(saved), encoding="utf-8")
        self.report["artifact_hashes"]["coverage.json"] = digest(coverage_file)
        self.report_path.write_text(json.dumps(self.report), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "persisted native coverage"):
            self.validate()
        self.runner.assert_not_called()

    def test_sidecar_change_stops_before_second_worker(self):
        self.mutation = lambda: self.final.write_text("changed while worker ran", encoding="utf-8")
        result = self.validate()
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["inputs_unchanged"])
        self.assertFalse(result["boundary_transit_inputs_unchanged"])
        self.assertEqual(len(self.calls), 1)

    def test_parser_config_change_during_worker_is_not_ignored(self):
        self.mutation = lambda: self.config.write_text("{}", encoding="utf-8")
        result = self.validate()
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["boundary_transit_inputs_unchanged"])

    def test_every_sidecar_is_checked_after_last_worker(self):
        paths = [self.original, self.business, self.boundary, self.final,
                 self.build / "coverage.json", self.config, self.library]
        for index, path in enumerate(paths):
            with self.subTest(path=path.name):
                before = path.read_bytes()
                self.calls.clear()
                self.mutation = lambda: path.write_bytes(b"changed in final worker") if len(self.calls) == 2 else None
                try:
                    result = self.validate("changed-last-" + str(index))
                    self.assertEqual(len(self.calls), 2)
                    self.assertEqual(result["status"], "failed")
                    self.assertFalse(result["boundary_transit_inputs_unchanged"])
                    self.assertFalse(result["inputs_unchanged"])
                finally:
                    path.write_bytes(before)

    def test_timeout_is_not_reclassified_as_success_or_an_ordinary_failure(self):
        def timeout(*args, **kwargs):
            self.final.write_text("changed before timeout", encoding="utf-8")
            return {"returncode": -1, "timed_out": True, "cancelled": False}
        self.runner.side_effect = timeout
        result = self.validate()
        self.assertEqual(result["status"], "timed_out")
        self.assertFalse(result["boundary_transit_inputs_unchanged"])

    def test_no_boundaries_is_explicit_and_does_not_claim_forwarding(self):
        self.report["coverage"].update(functions={"core": {"virtualized": True}},
            selected_functions=["core"], public_boundaries={}, scope_plan=None)
        empty = {"schema_version": 1, "functions": {}}
        evidence = {"status": "no_boundaries", "functions": {}, "qualification": QUALIFICATION}
        for key, value in {"contract": empty, "evidence": evidence, "status": "no_boundaries",
                           "boundary_ir": None, "business_ir": self.descriptor(self.original)}.items():
            self.both(key, value)
        self.parser_contract.return_value = empty
        self.parser_evidence.return_value = evidence
        self.save()
        result = self.validate()
        self.assertEqual(result["status"], "functional_samples_passed")
        self.assertEqual(result["boundary_transit"]["status"], "no_boundaries")

    def test_legacy_coverage_remains_unverified(self):
        self.report.pop("coverage_schema_version")
        self.report.pop("boundary_transit")
        self.report["coverage"].pop("boundary_transit")
        self.report["coverage"]["schema_version"] = 1
        self.save()
        result = self.validate()
        self.assertEqual(result["status"], "functional_samples_passed")
        self.assertEqual(result["boundary_transit"]["status"], "legacy_unverified")
        self.parser_contract.assert_not_called()

    def test_composed_frontend_uses_bound_native_report(self):
        outer, inner = self.wrap_native_report()
        self.assertNotIn("tool_hashes", outer)
        self.assertNotIn("boundary_transit", outer)
        result = self.validate()
        self.assertEqual(result["status"], "functional_samples_passed")
        self.assertEqual(result["boundary_transit"]["native_report"], self.descriptor(inner))

    def test_composed_frontend_mismatched_coverage_rejected(self):
        outer, inner = self.wrap_native_report()
        outer["coverage"]["boundary_transit"]["status"] = "no_boundaries"
        self.report_path.write_text(json.dumps(outer), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "coverage/artifacts differ"):
            self.validate()
        self.runner.assert_not_called()

    def test_composed_frontend_canonical_inventory_key(self):
        outer, inner = self.wrap_native_report()
        outer["artifact_hashes"] = {"native/report.json": digest(inner)}
        self.report_path.write_text(json.dumps(outer), encoding="utf-8")
        self.assertEqual(self.validate()["status"], "functional_samples_passed")

    def test_composed_frontend_legacy_windows_inventory_key(self):
        outer, inner = self.wrap_native_report()
        outer["artifact_hashes"] = {"native\\report.json": digest(inner)}
        self.report_path.write_text(json.dumps(outer), encoding="utf-8")
        self.assertEqual(self.validate()["status"], "functional_samples_passed")

    def test_composed_frontend_duplicate_separator_aliases_rejected(self):
        outer, inner = self.wrap_native_report()
        outer["artifact_hashes"] = {"native/report.json": digest(inner),
                                    "native\\report.json": digest(inner)}
        self.report_path.write_text(json.dumps(outer), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "artifact hashes"):
            self.validate()
        self.runner.assert_not_called()

    def test_composed_frontend_canonical_inventory_wrong_hash_rejected(self):
        outer, inner = self.wrap_native_report()
        outer["artifact_hashes"] = {"native/report.json": "0" * 64}
        self.report_path.write_text(json.dumps(outer), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "artifact hashes"):
            self.validate()
        self.runner.assert_not_called()

    def test_composed_frontend_wrong_native_report_hash_rejected(self):
        outer, inner = self.wrap_native_report()
        outer["native_report_sha256"] = "0" * 64
        self.report_path.write_text(json.dumps(outer), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "native report hash"):
            self.validate()
        self.runner.assert_not_called()

    def test_composed_frontend_cannot_choose_other_native_report_path(self):
        outer, inner = self.wrap_native_report()
        decoy = inner.with_name("decoy.json")
        decoy.write_bytes(inner.read_bytes())
        outer["native_report"] = str(decoy)
        self.report_path.write_text(json.dumps(outer), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "fixed private"):
            self.validate()
        self.runner.assert_not_called()

    def test_composed_native_report_change_during_worker_fails(self):
        outer, inner = self.wrap_native_report()
        self.mutation = lambda: inner.write_text("{}", encoding="utf-8")
        result = self.validate()
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["boundary_transit_inputs_unchanged"])
        self.assertEqual(len(self.calls), 1)


class ActualBoundaryParserTests(unittest.TestCase):
    """Parse synthetic owned IR using the installed LLVM; no target executes."""
    @classmethod
    def setUpClass(cls):
        config = Path(__file__).resolve().parents[1] / ".tools/kagura-toolchain.json"
        if not config.is_file():
            raise unittest.SkipTest("pinned local LLVM configuration unavailable")
        value = json.loads(config.read_text(encoding="utf-8-sig"))
        cls.library = Path(value["llvm_root"]) / "bin/LLVM-C.dll"
        if not cls.library.is_file():
            raise unittest.SkipTest("pinned local LLVM parser unavailable")

    def test_actual_forwarding_relation_and_abi_are_checked(self):
        with tempfile.TemporaryDirectory(prefix="antirea-boundary-ir-") as folder:
            original, final = Path(folder) / "original.ll", Path(folder) / "final.ll"
            original.write_text(ORIGINAL, encoding="utf-8")
            contract = native_build._boundary_contract(original, ["core"], self.library,
                expected_calls={"core": ["secret"]})
            self.assertEqual(contract, BOUNDARY_CONTRACT)
            for text, valid in ((ORIGINAL, True),
                    (ORIGINAL.replace("%r = call i64 @secret(i64 %a, i64 %b)", "%r = add i64 %a, %b"), False),
                    (ORIGINAL.replace("call i64 @secret(i64 %a, i64 %b)", "call i64 @secret(i64 %b, i64 %a)"), False),
                    (ORIGINAL.replace("ret i64 %r", "ret i64 %a", 1), False),
                    (ORIGINAL.replace("i64 @core", "signext i64 @core"), False)):
                with self.subTest(valid=valid, ir=text):
                    final.write_text(text, encoding="utf-8")
                    if valid:
                        self.assertEqual(native_build._boundary_transit_evidence(final, contract, self.library), EVIDENCE)
                    else:
                        with self.assertRaises(native_build.NativeBuildError):
                            native_build._boundary_transit_evidence(final, contract, self.library)

    def test_empty_contract_does_not_load_any_library(self):
        missing = Path("absent-library-that-must-not-load.dll")
        contract = native_build._boundary_contract(Path("absent.ll"), [], missing)
        self.assertEqual(native_build._boundary_transit_evidence(Path("absent.ll"), contract, missing)["status"], "no_boundaries")


if __name__ == "__main__":
    unittest.main()
