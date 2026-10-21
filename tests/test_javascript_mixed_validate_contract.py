"""Contract, case-generation, coverage-binding, source-plan and bounded-read unit
tests for the production engine ``antirea.javascript_mixed_validate`` (no child
process). Promoted from the phase17 candidate suite and extended for the stricter
duplicate-source-pin rejection and bounded ``_read`` byte budget.

Run: C:/Python313/python.exe -I -S -B test_javascript_mixed_validate_contract.py
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import js_mixed_validate_support as H

V = H.load_validate()


def ep(name, params):
    return {"name": name, "parameters": params}


def pnum(n, lo, hi):
    return {"name": n, "type": "number", "minimum": lo, "maximum": hi}


def pbig(n, lo, hi):
    return {"name": n, "type": "bigint", "minimum": lo, "maximum": hi}


def pbool(n):
    return {"name": n, "type": "boolean"}


def base_contract(**over):
    c = {"schema_version": 1, "kind": "javascript_mixed_module_application_samples", "source": "index.js",
         "entrypoints": [ep("fadd", [pnum("a", -10, 10), pnum("b", -10, 10)])], "preserved_entrypoints": []}
    c.update(over)
    return c


class ContractTests(unittest.TestCase):
    def test_accepts_valid(self):
        c = V.validate_application_contract(base_contract())
        self.assertEqual(c["kind"], "javascript_mixed_module_application_samples")
        self.assertEqual(c["source"], "index.js")

    def test_accepts_bigint_and_boolean_and_preserved(self):
        c = base_contract(entrypoints=[ep("bigmul", [pbig("a", -5, 5), pbig("b", -5, 5)]), ep("flag", [pbool("p")])],
                          preserved_entrypoints=[ep("describe", [pnum("n", 0, 9)])])
        self.assertEqual(len(V.validate_application_contract(c)["entrypoints"]), 2)

    def _reject(self, contract, needle=None):
        with self.assertRaises(V.MixedValidateError) as cm:
            V.validate_application_contract(contract)
        if needle:
            self.assertIn(needle, str(cm.exception))

    def test_rejects_extra_and_missing_keys(self):
        c = base_contract(); c["extra"] = 1
        self._reject(c)
        c = base_contract(); del c["preserved_entrypoints"]
        self._reject(c)

    def test_rejects_bad_schema_and_kind(self):
        self._reject(base_contract(schema_version=2))
        self._reject(base_contract(kind="python_integer_samples"))

    def test_rejects_bad_source(self):
        self._reject(base_contract(source="/abs/index.js"))
        self._reject(base_contract(source="../escape.js"))
        self._reject(base_contract(source="C:\\x\\index.js"))
        self._reject(base_contract(source="index.ts"), "source language must match")

    def test_rejects_empty_entrypoints(self):
        self._reject(base_contract(entrypoints=[]))

    def test_rejects_selected_preserved_overlap_and_dupes(self):
        self._reject(base_contract(entrypoints=[ep("f", [pnum("a", 0, 1)])],
                                   preserved_entrypoints=[ep("f", [pnum("a", 0, 1)])]))

    def test_rejects_bad_parameter_types_and_bounds(self):
        self._reject(base_contract(entrypoints=[ep("f", [{"name": "a", "type": "string", "minimum": 0, "maximum": 1}])]))
        self._reject(base_contract(entrypoints=[ep("f", [pnum("a", 5, 1)])]), "minimum")
        self._reject(base_contract(entrypoints=[ep("f", [pnum("a", 0, 2 ** 53)])]), "exact-integer")
        self._reject(base_contract(entrypoints=[ep("f", [pbig("a", 0, 2 ** 300)])]), "256 bits")
        self._reject(base_contract(entrypoints=[ep("f", [{"name": "p", "type": "boolean", "minimum": 0, "maximum": 1}])]))

    def test_rejects_bad_names_and_arm_prefix(self):
        self._reject(base_contract(entrypoints=[ep("1bad", [])]))
        self._reject(base_contract(entrypoints=[ep("_arm_enter", [])]))
        self._reject(base_contract(entrypoints=[ep("f", [pnum("a", 0, 1), pnum("a", 0, 1)])]), "unique")

    def test_rejects_too_many_entrypoints(self):
        self._reject(base_contract(entrypoints=[ep("f%d" % i, []) for i in range(33)]))


class CaseTests(unittest.TestCase):
    def test_deterministic_for_same_seed(self):
        c = base_contract()
        self.assertEqual(V.make_cases(c, random_cases=16, seed=7), V.make_cases(c, random_cases=16, seed=7))

    def test_number_specials_present(self):
        cases = V.make_cases(base_contract(), random_cases=4, seed=3)
        bits = {arg["bits"] for vector in cases["fadd"] for arg in vector}
        for key in ("nan", "neg_zero", "pos_zero", "pos_inf", "neg_inf"):
            self.assertIn(V._NUMBER_SPECIAL_BITS[key], bits, key)
        self.assertNotEqual(V._NUMBER_SPECIAL_BITS["neg_zero"], V._NUMBER_SPECIAL_BITS["pos_zero"])

    def test_bigint_and_boolean_wire_forms(self):
        c = base_contract(entrypoints=[ep("b", [pbig("a", -3, 3)]), ep("fl", [pbool("p")])])
        cases = V.make_cases(c, random_cases=4, seed=1)
        self.assertTrue(all(arg["t"] == "bigint" and isinstance(arg["v"], str) for v in cases["b"] for arg in v))
        flags = {arg["v"] for v in cases["fl"] for arg in v}
        self.assertEqual(flags, {True, False})

    def test_rejects_bad_random_cases_and_seed(self):
        with self.assertRaises(V.MixedValidateError):
            V.make_cases(base_contract(), random_cases=0)
        with self.assertRaises(V.MixedValidateError):
            V.make_cases(base_contract(), random_cases=99999)
        with self.assertRaises(V.MixedValidateError):
            V.make_cases(base_contract(), seed=-1)


class CoverageTests(unittest.TestCase):
    def cov(self, **over):
        base = H.synth_coverage(["fadd"], ["fadd", "sq"], ["describe"])
        base.update(over)
        return base

    def test_accepts_valid(self):
        functions = V._verify_mixed_coverage(self.cov(), {"fadd"}, {"describe"})
        self.assertEqual(set(functions), {"fadd", "sq"})

    def _reject(self, coverage, selected={"fadd"}, preserved={"describe"}, needle=None):
        with self.assertRaises(V.MixedValidateError) as cm:
            V._verify_mixed_coverage(coverage, selected, preserved)
        if needle:
            self.assertIn(needle, str(cm.exception))

    def test_rejects_wrong_backend_or_mode(self):
        self._reject(self.cov(backend="python_mixed_module_vm"))
        self._reject(self.cov(protection_mode="full"))

    def test_rejects_missing_source_hashes_and_nonbool_transpiled(self):
        self._reject(self.cov(original_module_source_sha256="xyz"))
        self._reject(self.cov(working_source_sha256=""))
        self._reject(self.cov(transpiled_typescript="no"))

    def test_rejects_roots_not_in_closure(self):
        self._reject(self.cov(selected_functions=["ghost"]))

    def test_rejects_exported_not_equal_closure(self):
        self._reject(self.cov(exported_functions=["fadd", "sq", "extra"]))

    def test_rejects_functions_not_matching_closure(self):
        self._reject(self.cov(functions={"fadd": {"virtualized": True}}))

    def test_rejects_non_virtualized(self):
        self._reject(self.cov(functions={"fadd": {"virtualized": False}, "sq": {"virtualized": True}}))

    def test_rejects_preserved_overlap(self):
        self._reject(self.cov(preserved_unprotected_functions=["fadd"]))

    def test_rejects_entrypoint_not_root_or_not_preserved(self):
        self._reject(self.cov(), selected={"sq"})          # sq is a helper, not a selected root
        self._reject(self.cov(), preserved={"ghost"})      # not a declared preserved function


class SourcePlanBindingTests(unittest.TestCase):
    """The stricter source-plan snapshot binding: non-empty, well-formed and with
    no duplicate package input (root's duplicate-source-pin rejection)."""

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.pkg = Path(self._t.name) / "pkg"
        self.pkg.mkdir()
        (self.pkg / "index.js").write_text("module.exports={};\n", encoding="utf-8")

    def tearDown(self):
        self._t.cleanup()

    def _snapshot(self):
        return V.snapshot_source_tree(self.pkg)

    def test_accepts_real_snapshot(self):
        expected = V._expected_source_files(self._snapshot(), self.pkg)
        self.assertEqual(set(expected), {"index.js"})

    def test_rejects_empty_snapshot(self):
        with self.assertRaises(V.MixedValidateError) as cm:
            V._expected_source_files([], self.pkg)
        self.assertIn("non-empty source-plan snapshot", str(cm.exception))

    def test_rejects_duplicate_source_pin(self):
        snap = self._snapshot()
        # Two entries that resolve to the SAME relative package input must be rejected,
        # not silently de-duplicated into one accepted pin.
        dup = list(snap) + [dict(snap[0])]
        with self.assertRaises(V.MixedValidateError) as cm:
            V._expected_source_files(dup, self.pkg)
        self.assertIn("duplicate package input", str(cm.exception))

    def test_rejects_malformed_snapshot_entry(self):
        with self.assertRaises(V.MixedValidateError) as cm:
            V._expected_source_files([{"path": "index.js", "sha256": "nothex", "bytes": 1}], self.pkg)
        self.assertIn("path, sha256 and bytes", str(cm.exception))

    def test_rejects_snapshot_not_covering_tree(self):
        # An out-of-tree-only snapshot covers nothing inside the package root.
        outside = {"path": "../outside.js", "sha256": "0" * 64, "bytes": 1}
        with self.assertRaises(V.MixedValidateError) as cm:
            V._expected_source_files([outside], self.pkg)
        self.assertIn("does not cover", str(cm.exception))


class BoundedReadTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.tmp = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()

    def test_read_accepts_within_budget_and_rejects_oversize(self):
        path = self.tmp / "f.bin"
        path.write_bytes(b"x" * 8)
        self.assertEqual(V._read(path, 8), b"x" * 8)
        with self.assertRaises(V.MixedValidateError) as cm:
            V._read(path, 7)
        self.assertIn("byte budget", str(cm.exception))

    def test_walk_tree_rejects_oversize_before_read(self):
        pkg = self.tmp / "pkg"
        pkg.mkdir()
        (pkg / "big.js").write_bytes(b"x" * 9)
        saved = V.MAX_FILE_BYTES
        V.MAX_FILE_BYTES = 8
        try:
            with self.assertRaises(V.MixedValidateError) as cm:
                V.snapshot_source_tree(pkg)
            self.assertIn("per-file byte budget", str(cm.exception))
        finally:
            V.MAX_FILE_BYTES = saved


if __name__ == "__main__":
    unittest.main(verbosity=2)
