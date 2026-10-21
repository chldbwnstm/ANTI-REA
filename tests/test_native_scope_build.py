"""Reviewed scope integration. Real fixture build is explicitly opt-in."""
import ctypes
import json
import os
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch

from antirea import native_build as nb

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "samples/multilang/native/context"
SELECTED = ["context_adjust", "context_mix", "context_prepare", "context_score"]


def expected(x, y):
    mask = (1 << 64) - 1
    prepared = x * 37 + y + 101
    prepared = (prepared ^ (y << 21)) if x & 1 else prepared + (x << 17)
    prepared &= mask
    a, b = prepared & 0xFFFFFFFF, y ^ (prepared >> 32)
    value = (a * 1000003 + b) & mask
    for index in range(3):
        value ^= value >> 13
        value = (value + (b + index + 17) * 65537) & mask
        value = (value * 257) & mask
    value ^= value >> 29
    delta = y * 97 + 23
    return (((value ^ (delta << 9)) + delta) if y & 2 else ((value + delta) ^ (value >> 11))) & mask


class ScopeSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.policy = self.root / "policy.json"
        self.ir = self.root / "before.ll"
        self.ir.write_text("""define i64 @entry(i32 %x) {
  %v = call i64 @core(i32 %x)
  ret i64 %v
}
define i64 @core(i32 %x) {
  %v = call i64 @helper(i32 %x)
  ret i64 %v
}
define internal i64 @helper(i32 %x) {
  %v = zext i32 %x to i64
  ret i64 %v
}
""", encoding="utf-8")
        self.policy.write_text(json.dumps({"core_roots": ["core"], "public_presentation": {"entry": "Reviewed unchanged forwarding."}}))
        self.project = {"functions": ["entry"], "scope_policy": str(self.policy),
                        "scope_policy_sha256": nb._hash(self.policy)}

    def tearDown(self):
        self.temp.cleanup()

    def test_expansion_and_exports_are_separate(self):
        result = nb._select_scope(self.project, self.ir, self.ir)
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["selected_functions"], ["core", "helper"])
        self.assertEqual(result["exported_functions"], ["entry"])
        self.assertEqual(result["public_boundaries"], ["entry"])
        self.assertEqual(result["global_data_protection"], "not_applied")
        self.assertIn("callee_of:core", result["scope_plan"]["reasons"]["helper"])

    def test_legacy_explicit_route_unchanged(self):
        result = nb._select_scope({"functions": ["core"]}, self.ir, self.ir)
        self.assertEqual(result["selected_functions"], ["core"])
        self.assertIsNone(result["scope_plan"])

    def test_policy_changed_after_inspection_rejected(self):
        self.policy.write_text('{"core_roots":["entry"]}')
        with self.assertRaisesRegex(nb.NativeBuildError, "changed"):
            nb._select_scope(self.project, self.ir, self.ir)

    def test_unrelated_export_is_not_claimed_protected(self):
        self.ir.write_text(self.ir.read_text() + "define i64 @unrelated(i32 %x) {\n  ret i64 7\n}\n")
        self.project["functions"] = ["unrelated"]
        result = nb._select_scope(self.project, self.ir, self.ir)
        self.assertEqual(result["status"], "needs_review")
        self.assertTrue(any(item["kind"] == "uncovered_export" for item in result["scope_plan"]["unresolved"]))

    def test_unreviewed_global_blocks_instead_of_claiming_encryption(self):
        text = self.ir.read_text().replace("  %v = zext i32 %x to i64", "  %v = load i64, ptr @secret")
        self.ir.write_text('@secret = global i64 7\n' + text)
        result = nb._select_scope(self.project, self.ir, self.ir)
        self.assertEqual(result["status"], "needs_review")
        self.assertTrue(result["scope_plan"]["data_risks"])

    def test_indirect_call_requires_review(self):
        self.ir.write_text(self.ir.read_text().replace("call i64 @helper(i32 %x)", "call i64 %callback(i32 %x)"))
        result = nb._select_scope(self.project, self.ir, self.ir)
        self.assertEqual(result["status"], "needs_review")
        self.assertTrue(any(item["kind"] == "indirect_call" for item in result["scope_plan"]["unresolved"]))

    def test_unsafe_selected_allowlist_name_requires_review(self):
        self.ir.write_text(self.ir.read_text().replace("@helper", '@"helper*"'))
        result = nb._select_scope(self.project, self.ir, self.ir)
        self.assertEqual(result["status"], "needs_review")
        self.assertTrue(any(item["kind"] == "unsupported_native_scope_symbol" for item in result["scope_plan"]["unresolved"]))

    def test_internal_function_body_supported_without_export_claim(self):
        self.assertIn("zext", nb._body(self.ir.read_text(), "helper", allow_internal=True))
        with self.assertRaises(nb.NativeBuildError):
            nb._body(self.ir.read_text(), "helper")

    def test_public_boundary_must_not_contain_vm_call(self):
        evidence = nb._boundary_evidence(self.ir.read_text(), ["entry"], "dispatch")
        self.assertFalse(evidence["entry"]["virtualized"])
        with self.assertRaisesRegex(nb.NativeBuildError, "virtualized"):
            nb._boundary_evidence(self.ir.read_text().replace("@core(", "@dispatch("), ["entry"], "dispatch")

    def test_fixture_inspection_does_not_compile_and_pins_policy(self):
        with patch.object(nb, "run_logged", side_effect=AssertionError("no compilation")):
            info = nb.inspect_project(FIXTURE / "project.json")
        self.assertEqual(info["scope_analysis_status"], "requires_compilation")
        self.assertEqual(info["exported_functions"], ["context_public"])
        self.assertEqual(info["scope_policy_sha256"], info["input_hashes"][str(FIXTURE / "protection-policy.json")])


@unittest.skipUnless(os.environ.get("ANTIREA_CONTEXT_REAL") == "1", "explicit owned-source build opt-in")
class ActualContextBuildTests(unittest.TestCase):
    def test_multifile_context_scope_and_expected_behavior(self):
        output = Path(os.environ["ANTIREA_CONTEXT_OUTPUT"]).resolve()
        report = nb.build_project(FIXTURE / "project.json", output, workspace_root=ROOT, seed=1739)
        self.assertEqual(report["status"], "artifact_created_unvalidated", report.get("error"))
        coverage = report["coverage"]
        self.assertEqual(coverage["selected_functions"], SELECTED)
        self.assertEqual(coverage["exported_functions"], ["context_public"])
        self.assertEqual(set(coverage["functions"]), set(SELECTED))
        self.assertFalse(coverage["public_boundaries"]["context_public"]["virtualized"])
        self.assertTrue(all(item["virtualized"] for item in coverage["final_vm"].values()))
        rng = random.Random(20261020)
        edges = [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]
        cases = [(x, y) for x in edges for y in edges]
        cases += [(rng.getrandbits(32), rng.getrandbits(32)) for _ in range(8192)]
        results = {}
        for arm in ("baseline", "protected"):
            library_path = Path(report["artifacts"][arm]["path"])
            before = nb._hash(library_path)
            library = ctypes.CDLL(str(library_path))
            try:
                fn = library.context_public
                fn.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
                fn.restype = ctypes.c_uint64
                matches = []
                for _ in range(2):
                    matched = sum(fn(x, y) == expected(x, y) for x, y in cases)
                    matches.append(matched)
                    self.assertEqual(matched, len(cases), arm)
                results[arm] = {"matched_each_repeat": matches, "sha256": before}
            finally:
                import _ctypes
                _ctypes.FreeLibrary(library._handle)
            self.assertEqual(nb._hash(library_path), before)
        nb._write(output / "fixture-check.json", {"schema_version": 1, "status": "passed", "cases": len(cases),
                  "repeats": 2, "functional": results, "selected_functions": SELECTED,
                  "exported_functions": ["context_public"], "external_attack_evaluation": "not_performed"})
