"""First-class TypeScript mixed-module application contract validation.

Exercises the PRODUCTION ``validate_application_contract`` directly (no engine
mocking) for the new ``typescript_mixed_module_application_samples`` kind: the
kind is accepted with a ``.ts`` source; the TypeScript kind cannot carry a
JavaScript source and the JavaScript kind cannot carry a TypeScript source; an
unknown kind is refused; and the normalisation/limits are the same bounded,
command-free selected-entrypoint shape as the JavaScript contract.

These are pure-function checks that start no process and need no reference
helper. Semantics (acceptance / refusal class), not exact message strings, are
asserted; where a substring is checked it names a documented concept.

Run: C:/Python313/python.exe -I -S -B test_typescript_mixed_validate_contract.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import typescript_mixed_validate_support as H  # noqa: E402  (inserts repo root; imports production engine)

V = H.load_validate()


def num_param(name, lo, hi):
    return {"name": name, "type": "number", "minimum": lo, "maximum": hi}


def ts_contract(*, source="index.ts", kind=H.TS_CONTRACT_KIND, schema_version=1,
                entrypoints=None, preserved=None, extra=None):
    contract = {"schema_version": schema_version, "kind": kind, "source": source,
                "entrypoints": entrypoints if entrypoints is not None
                else [{"name": "core", "parameters": [num_param("x", -5, 5)]}],
                "preserved_entrypoints": preserved if preserved is not None else []}
    if extra:
        contract.update(extra)
    return contract


class TypeScriptContractTests(unittest.TestCase):
    def test_valid_ts_contract_is_accepted_and_normalised(self):
        resolved = V.validate_application_contract(ts_contract(
            source="pkg\\mod.ts",
            entrypoints=[{"name": "core", "parameters": [num_param("x", -5, 5)]}],
            preserved=[{"name": "combo", "parameters": [num_param("x", -5, 5)]}]))
        self.assertEqual(resolved["kind"], H.TS_CONTRACT_KIND)
        self.assertEqual(resolved["source"], "pkg/mod.ts")               # POSIX-normalised
        self.assertEqual([e["name"] for e in resolved["entrypoints"]], ["core"])
        self.assertEqual([e["name"] for e in resolved["preserved_entrypoints"]], ["combo"])

    def test_ts_kind_requires_ts_source_not_js(self):
        # A TypeScript contract cannot authorize a JavaScript source module.
        with self.assertRaises(V.MixedValidateError) as cm:
            V.validate_application_contract(ts_contract(source="index.js"))
        self.assertIn("typescript", str(cm.exception).lower())

    def test_ts_kind_rejects_emitted_cjs_source(self):
        # The .cjs runtime entry is engine-internal; the contract binds the .ts source.
        with self.assertRaises(V.MixedValidateError):
            V.validate_application_contract(ts_contract(source="index.cjs"))

    def test_js_kind_cannot_carry_ts_source(self):
        # Symmetric: a JavaScript contract cannot authorize a TypeScript source.
        with self.assertRaises(V.MixedValidateError) as cm:
            V.validate_application_contract(ts_contract(kind=H.JS_CONTRACT_KIND, source="index.ts"))
        self.assertIn("javascript", str(cm.exception).lower())

    def test_unknown_kind_refused(self):
        with self.assertRaises(V.MixedValidateError):
            V.validate_application_contract(ts_contract(kind="typescript_scalar_samples"))

    def test_schema_version_must_be_one(self):
        with self.assertRaises(V.MixedValidateError):
            V.validate_application_contract(ts_contract(schema_version=2))

    def test_extra_top_level_key_refused(self):
        with self.assertRaises(V.MixedValidateError):
            V.validate_application_contract(ts_contract(extra={"deployment": "manual"}))

    def test_at_least_one_selected_entrypoint_required(self):
        with self.assertRaises(V.MixedValidateError):
            V.validate_application_contract(ts_contract(entrypoints=[]))

    def test_selected_and_preserved_cannot_overlap(self):
        with self.assertRaises(V.MixedValidateError):
            V.validate_application_contract(ts_contract(
                entrypoints=[{"name": "core", "parameters": [num_param("x", -5, 5)]}],
                preserved=[{"name": "core", "parameters": [num_param("x", -5, 5)]}]))

    def test_number_bounds_and_types_enforced_like_javascript(self):
        # The TS kind reuses the same bounded scalar parameter grammar.
        with self.assertRaises(V.MixedValidateError):
            V.validate_application_contract(ts_contract(
                entrypoints=[{"name": "core",
                              "parameters": [{"name": "x", "type": "number",
                                              "minimum": 5, "maximum": -5}]}]))
        resolved = V.validate_application_contract(ts_contract(
            entrypoints=[{"name": "core",
                          "parameters": [{"name": "b", "type": "bigint",
                                          "minimum": -10 ** 6, "maximum": 10 ** 6}]}]))
        self.assertEqual(resolved["entrypoints"][0]["parameters"][0]["type"], "bigint")

    def test_make_cases_accepts_ts_contract(self):
        cases = V.make_cases(ts_contract(
            entrypoints=[{"name": "core", "parameters": [num_param("x", -3, 3)]}],
            preserved=[{"name": "combo", "parameters": [num_param("x", -3, 3)]}]),
            random_cases=4, seed=11)
        self.assertEqual(set(cases), {"core", "combo"})
        self.assertTrue(all(len(v) >= 1 for v in cases.values()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
