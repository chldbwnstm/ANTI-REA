"""TypeScript mixed-module validation boundaries that are decided BEFORE any
child process or the independent reference compiler runs.

Every refusal here is reached inside ``validate_build`` ahead of the
``typescript_reference`` import and ahead of ``output.mkdir`` / ``run_logged``,
so these tests need no reference helper and start no process. They drive the
engine with owned synthetic TypeScript (and one minimal JavaScript) build whose
report/coverage/artifacts are honestly hash-bound owned fixtures.

Covered: the TypeScript contract cannot authorize a JavaScript build and the
JavaScript contract cannot authorize a TypeScript build; the contract source
must equal the inspected ``.ts`` module; the coverage transpiled flag must match
the language; the bound original ``.ts`` source identity must match; the derived
runtime ``.cjs`` entry must not collide with an owned package file; any
additional TypeScript (.ts/.tsx/.cts/.mts) source is refused; plain JS/JSON
siblings alone do not trip the additional-TypeScript boundary.

Semantics (refusal class + no output/process) are asserted, not exact messages.

Run: C:/Python313/python.exe -I -S -B test_typescript_mixed_validate_boundary.py
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import typescript_mixed_validate_support as H  # noqa: E402

V = H.load_validate()


def num_param(name, lo, hi):
    return {"name": name, "type": "number", "minimum": lo, "maximum": hi}


class _Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.ws = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()

    def _ts_contract(self, *, source="index.ts",
                     entrypoints=None, preserved=None, name="contract.json"):
        path = self.ws / name
        H.write_ts_contract(path, source=source,
                            entrypoints=entrypoints if entrypoints is not None
                            else [{"name": "core", "parameters": [num_param("x", -5, 5)]}],
                            preserved=preserved if preserved is not None else [])
        return path

    def _js_contract(self, *, source="index.js", entrypoints=None, name="js_contract.json"):
        path = self.ws / name
        path.write_text(json.dumps(
            {"schema_version": 1, "kind": H.JS_CONTRACT_KIND, "source": source,
             "entrypoints": entrypoints if entrypoints is not None
             else [{"name": "f", "parameters": [num_param("x", -5, 5)]}],
             "preserved_entrypoints": []}), encoding="utf-8")
        return path

    def _run(self, report_path, contract_path, app):
        return V.validate_build(str(report_path), str(contract_path),
                                str(self.ws / "validate"), workspace_root=str(self.ws),
                                expected_snapshot=V.snapshot_source_tree(app),
                                random_cases=4, timeout_seconds=60)

    def _assert_no_output_no_process(self):
        # A refusal reached before output.mkdir leaves no validation directory.
        self.assertFalse((self.ws / "validate").exists())


class CrossLanguageContractTests(_Base):
    def test_typescript_contract_cannot_authorize_javascript_build(self):
        # JavaScript build (coverage roots {f}); a TypeScript-kind contract whose
        # selected entrypoint matches that coverage still cannot authorize it.
        synth = H.make_synthetic_js_min(self.ws)
        contract = self._ts_contract(source="index.ts",
                                     entrypoints=[{"name": "f", "parameters": [num_param("x", -5, 5)]}])
        with self.assertRaises(V.MixedValidateError) as cm:
            self._run(synth["report_path"], contract, synth["app"])
        self.assertIn("language", str(cm.exception).lower())
        self._assert_no_output_no_process()

    def test_javascript_contract_cannot_authorize_typescript_build(self):
        # TypeScript build (coverage roots {core, sq}); a JavaScript-kind contract
        # whose selected entrypoint matches that coverage still cannot authorize it.
        synth = H.make_synthetic_ts(self.ws)
        contract = self._js_contract(source="index.js",
                                     entrypoints=[{"name": "core", "parameters": [num_param("x", -5, 5)]}])
        with self.assertRaises(V.MixedValidateError) as cm:
            self._run(synth["report_path"], contract, synth["app"])
        self.assertIn("language", str(cm.exception).lower())
        self._assert_no_output_no_process()


class TypeScriptBindingBoundaryTests(_Base):
    def test_contract_source_must_equal_inspected_ts_module(self):
        synth = H.make_synthetic_ts(self.ws, module_relative="index.ts")
        contract = self._ts_contract(source="other.ts")
        with self.assertRaises(V.MixedValidateError) as cm:
            self._run(synth["report_path"], contract, synth["app"])
        self.assertIn("source", str(cm.exception).lower())
        self._assert_no_output_no_process()

    def test_coverage_transpiled_flag_must_match_typescript(self):
        synth = H.make_synthetic_ts(self.ws, transpiled=False)
        contract = self._ts_contract()
        with self.assertRaises(V.MixedValidateError):
            self._run(synth["report_path"], contract, synth["app"])
        self._assert_no_output_no_process()

    def test_bound_original_ts_identity_mismatch_refused(self):
        synth = H.make_synthetic_ts(self.ws, original_sha="1" * 64)  # valid hex64, wrong value
        contract = self._ts_contract()
        with self.assertRaises(V.MixedValidateError):
            self._run(synth["report_path"], contract, synth["app"])
        self._assert_no_output_no_process()


class RuntimeEntryAndGraphBoundaryTests(_Base):
    def test_runtime_cjs_collision_with_owned_file_refused(self):
        # A preexisting index.cjs beside index.ts collides with the derived runtime
        # entry (same stem) and must be refused (casefold-aware).
        synth = H.make_synthetic_ts(
            self.ws, extra_files={"index.cjs": "'use strict';\nmodule.exports={};\n"})
        contract = self._ts_contract()
        with self.assertRaises(V.MixedValidateError) as cm:
            self._run(synth["report_path"], contract, synth["app"])
        self.assertIn("collide", str(cm.exception).lower())
        self._assert_no_output_no_process()

    def test_runtime_cjs_collision_is_casefold(self):
        synth = H.make_synthetic_ts(
            self.ws, extra_files={"INDEX.CJS": "'use strict';\nmodule.exports={};\n"})
        contract = self._ts_contract()
        with self.assertRaises(V.MixedValidateError) as cm:
            self._run(synth["report_path"], contract, synth["app"])
        self.assertIn("collide", str(cm.exception).lower())

    def test_additional_typescript_sibling_refused(self):
        for sibling in ("helper.ts", "helper.tsx", "helper.cts", "helper.mts"):
            with self.subTest(sibling=sibling):
                t = tempfile.TemporaryDirectory()
                self.addCleanup(t.cleanup)
                ws = Path(t.name)
                synth = H.make_synthetic_ts(ws, extra_files={sibling: "export const y = 1;\n"})
                contract = ws / "contract.json"
                H.write_ts_contract(contract, source="index.ts",
                                    entrypoints=[{"name": "core", "parameters": [num_param("x", -5, 5)]}])
                with self.assertRaises(V.MixedValidateError):
                    V.validate_build(str(synth["report_path"]), str(contract),
                                     str(ws / "validate"), workspace_root=str(ws),
                                     expected_snapshot=V.snapshot_source_tree(synth["app"]),
                                     random_cases=4, timeout_seconds=60)
                self.assertFalse((ws / "validate").exists())

    def test_plain_js_and_json_siblings_do_not_trip_graph_boundary(self):
        # Plain JS/JSON siblings are preserved; they alone must NOT raise the
        # additional-TypeScript refusal. With the helper absent, a clean TS build
        # instead fails at the reference import -- but it must NOT be the TS-graph
        # or collision refusal, which is what this test pins.
        synth = H.make_synthetic_ts(
            self.ws, extra_files={"lib/util.js": H.SAMPLE_UTIL_JS, "data.json": '{"ok":true}\n'})
        contract = self._ts_contract()
        try:
            res = self._run(synth["report_path"], contract, synth["app"])
        except V.MixedValidateError as exc:
            msg = str(exc).lower()
            self.assertNotIn("collide", msg)
            self.assertNotIn("additional typescript", msg)
        except ImportError:
            pass  # reference helper not yet staged: reached PAST the graph boundary
        else:
            # If the helper is present, the run proceeds past these boundaries.
            self.assertIn(res.get("status"),
                          {"mixed_application_samples_passed", "failed", "cancelled", "timed_out"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
