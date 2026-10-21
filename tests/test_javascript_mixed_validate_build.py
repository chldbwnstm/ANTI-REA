"""Full production validate_build orchestration: real pass (with verified process
cleanup + repeat arrays), mismatch, missing export, timeout, STOP cancellation,
toolchain drift, source-plan drift, the stricter original-source baseline-equality
check, and the service trusted-input pins (pass / conflict / malformed / drift).

Every test runs in its own fresh temp workspace, so the STOP test writes only a
fake defense-loop/STOP inside that temp root and never touches the real project
controller.

Run: C:/Python313/python.exe -I -S -B test_javascript_mixed_validate_build.py
"""
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import js_mixed_validate_support as H

V = H.load_validate()


def num_param(n, lo, hi):
    return {"name": n, "type": "number", "minimum": lo, "maximum": hi}


class _Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.ws = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()


class ValidateBuildTests(_Base):
    # -- real end-to-end pass -------------------------------------------------
    def test_real_sample_passes_with_isolation(self):
        built = H.build_sample(self.ws)
        self.assertEqual(built["report"]["status"], "artifact_created_unvalidated")
        H.write_contract(self.ws / "contract.json", source="index.js",
                         entrypoints=[
                             {"name": "fadd", "parameters": [num_param("a", -1000, 1000), num_param("b", -1000, 1000)]},
                             {"name": "frecip", "parameters": [num_param("x", -8, 8)]},
                             {"name": "quad", "parameters": [num_param("x", -50, 50)]},
                             {"name": "bigadd", "parameters": [{"name": "a", "type": "bigint", "minimum": -10 ** 9, "maximum": 10 ** 9},
                                                               {"name": "b", "type": "bigint", "minimum": -10 ** 9, "maximum": 10 ** 9}]},
                             {"name": "isposz", "parameters": [num_param("x", -3, 3)]},
                             {"name": "mix", "parameters": [num_param("a", -3, 3), {"name": "b", "type": "bigint", "minimum": -3, "maximum": 3}]},
                         ],
                         preserved=[{"name": "describe", "parameters": [num_param("n", -150, 150)]}])
        snap = V.snapshot_source_tree(built["app"])
        os.environ["WAVE4_VB_SENTINEL"] = "nope"
        try:
            res = V.validate_build(str(built["report_path"]), str(self.ws / "contract.json"),
                                   str(self.ws / ".runs" / "validate"), workspace_root=str(self.ws),
                                   expected_snapshot=snap, random_cases=64, timeout_seconds=90)
        finally:
            del os.environ["WAVE4_VB_SENTINEL"]
        self.assertEqual(res["status"], "mixed_application_samples_passed", res.get("error"))
        self.assertTrue(res["module_origin"]["consistent"])
        self.assertTrue(res["inputs_unchanged"])
        self.assertEqual(res["baseline_source_kind"], "javascript_original_module")
        self.assertFalse(res["transpiled_typescript"])
        self.assertTrue(res["source_plan_snapshot_bound"])
        self.assertFalse(res["service_plan_inputs_bound"])     # no trusted_inputs supplied directly
        self.assertEqual(res["behavior_repeats"], 2)
        self.assertNotIn("WAVE4_VB_SENTINEL", res["module_origin"]["baseline"]["env_keys"])
        self.assertTrue(all(f["sampled_output_match"] and f["deterministic"] for f in res["functions"].values()))
        self.assertEqual(res["functions"]["mix"]["baseline_throws"], res["functions"]["mix"]["cases"])
        self.assertGreater(res["functions"]["fadd"]["baseline_ordinary_returns"], 0)
        # Raw per-arm receipts (reply + retained second-pass arrays) exist for both arms,
        # and each arm's bounded process-tree cleanup was positively verified.
        for arm in ("baseline", "protected"):
            reply = json.loads((self.ws / ".runs" / "validate" / arm / (arm + ".reply.json")).read_text(encoding="utf-8"))
            self.assertEqual(reply["status"], "ok")
            self.assertIn("outputs_second", reply)
            cleanup = res["execution"][arm]["cleanup"]
            self.assertTrue(cleanup.get("job_assigned"))
            self.assertEqual(cleanup.get("active_after"), 0)
            self.assertTrue(cleanup.get("parent_exit_confirmed"))
            self.assertTrue(cleanup.get("job_handle_closed"))
        self.assertTrue((self.ws / ".runs" / "validate" / "validation.json").is_file())

    # -- mismatch -------------------------------------------------------------
    def test_output_mismatch_fails(self):
        base = "'use strict';\nfunction f(a,b){return a+b;}\nmodule.exports={f};\n"
        prot = "'use strict';\nfunction f(a,b){return a+b+1;}\nmodule.exports={f};\n"  # off by one
        synth = H.make_synthetic(self.ws, module_relative="index.js", baseline_text=base, protected_text=prot,
                                 selected=["f"], closure=["f"], preserved=[])
        H.write_contract(self.ws / "contract.json", source="index.js",
                         entrypoints=[{"name": "f", "parameters": [num_param("a", -5, 5), num_param("b", -5, 5)]}])
        snap = V.snapshot_source_tree(synth["app"])
        res = V.validate_build(str(synth["report_path"]), str(self.ws / "contract.json"),
                               str(self.ws / "validate"), workspace_root=str(self.ws),
                               expected_snapshot=snap, random_cases=16, timeout_seconds=60)
        self.assertEqual(res["status"], "failed")
        self.assertFalse(res["functions"]["f"]["sampled_output_match"])

    # -- missing export -------------------------------------------------------
    def test_missing_export_fails(self):
        base = "'use strict';\nfunction f(x){return x;}\nmodule.exports={f};\n"
        prot = "'use strict';\nmodule.exports={};\n"  # protected arm drops the export
        synth = H.make_synthetic(self.ws, module_relative="index.js", baseline_text=base, protected_text=prot,
                                 selected=["f"], closure=["f"], preserved=[])
        H.write_contract(self.ws / "contract.json", source="index.js",
                         entrypoints=[{"name": "f", "parameters": [num_param("x", -5, 5)]}])
        snap = V.snapshot_source_tree(synth["app"])
        res = V.validate_build(str(synth["report_path"]), str(self.ws / "contract.json"),
                               str(self.ws / "validate"), workspace_root=str(self.ws),
                               expected_snapshot=snap, random_cases=8, timeout_seconds=60)
        self.assertEqual(res["status"], "failed")
        self.assertIn("missing or not a function", str(res.get("error")))

    # -- timeout --------------------------------------------------------------
    def test_timeout(self):
        busy = ("'use strict';\nconst end=Date.now()+20000;\nwhile(Date.now()<end){}\n"
                "function f(x){return x;}\nmodule.exports={f};\n")
        synth = H.make_synthetic(self.ws, module_relative="index.js", baseline_text=busy, protected_text=busy,
                                 selected=["f"], closure=["f"], preserved=[])
        H.write_contract(self.ws / "contract.json", source="index.js",
                         entrypoints=[{"name": "f", "parameters": [num_param("x", 0, 1)]}])
        snap = V.snapshot_source_tree(synth["app"])
        res = V.validate_build(str(synth["report_path"]), str(self.ws / "contract.json"),
                               str(self.ws / "validate"), workspace_root=str(self.ws),
                               expected_snapshot=snap, random_cases=2, timeout_seconds=2)
        self.assertEqual(res["status"], "timed_out", res.get("error"))

    # -- STOP (fake, isolated workspace only) --------------------------------
    def test_stop_cancels(self):
        base = "'use strict';\nfunction f(x){return x;}\nmodule.exports={f};\n"
        synth = H.make_synthetic(self.ws, module_relative="index.js", baseline_text=base, protected_text=base,
                                 selected=["f"], closure=["f"], preserved=[])
        H.write_contract(self.ws / "contract.json", source="index.js",
                         entrypoints=[{"name": "f", "parameters": [num_param("x", 0, 1)]}])
        stop = self.ws / ".runs" / "defense-loop" / "STOP"
        stop.parent.mkdir(parents=True, exist_ok=True)
        stop.write_text("stop", encoding="utf-8")
        snap = V.snapshot_source_tree(synth["app"])
        res = V.validate_build(str(synth["report_path"]), str(self.ws / "contract.json"),
                               str(self.ws / "validate"), workspace_root=str(self.ws),
                               expected_snapshot=snap, random_cases=4, timeout_seconds=60)
        self.assertEqual(res["status"], "cancelled")
        self.assertEqual(res["execution"], {})

    # -- toolchain drift ------------------------------------------------------
    def test_toolchain_drift_fails_closed(self):
        base = "'use strict';\nfunction f(x){return x;}\nmodule.exports={f};\n"
        synth = H.make_synthetic(self.ws, module_relative="index.js", baseline_text=base, protected_text=base,
                                 selected=["f"], closure=["f"], preserved=[])
        report = json.loads(synth["report_path"].read_text(encoding="utf-8"))
        report["toolchain"]["files"]["node"]["sha256"] = "0" * 64  # stale pin
        synth["report_path"].write_text(json.dumps(report), encoding="utf-8")
        H.write_contract(self.ws / "contract.json", source="index.js",
                         entrypoints=[{"name": "f", "parameters": [num_param("x", 0, 1)]}])
        snap = V.snapshot_source_tree(synth["app"])
        res = V.validate_build(str(synth["report_path"]), str(self.ws / "contract.json"),
                               str(self.ws / "validate"), workspace_root=str(self.ws),
                               expected_snapshot=snap, random_cases=4, timeout_seconds=60)
        self.assertEqual(res["status"], "failed")
        self.assertIn("toolchain changed", str(res.get("error")))
        self.assertEqual(res["execution"], {})

    # -- source-plan drift (pre-flight) --------------------------------------
    def test_plan_preflight_drift_raises(self):
        built = H.build_sample(self.ws)
        snap = V.snapshot_source_tree(built["app"])
        (built["app"] / "lib" / "util.js").write_text(
            "'use strict';\nfunction isSmall(n){return n<101;}\nmodule.exports={isSmall};\n", encoding="utf-8")
        H.write_contract(self.ws / "contract.json", source="index.js",
                         entrypoints=[{"name": "fadd", "parameters": [num_param("a", -5, 5), num_param("b", -5, 5)]}])
        with self.assertRaises(V.MixedValidateError) as cm:
            V.validate_build(str(built["report_path"]), str(self.ws / "contract.json"),
                             str(self.ws / ".runs" / "validate"), workspace_root=str(self.ws),
                             expected_snapshot=snap, random_cases=4, timeout_seconds=60)
        self.assertIn("changed since the bound source plan", str(cm.exception))

    # -- source-plan drift between preflight and staging ---------------------
    def test_prestage_drift_detected(self):
        built = H.build_sample(self.ws)
        snap = V.snapshot_source_tree(built["app"])
        H.write_contract(self.ws / "contract.json", source="index.js",
                         entrypoints=[{"name": "fadd", "parameters": [num_param("a", -5, 5), num_param("b", -5, 5)]}])
        util = built["app"] / "lib" / "util.js"
        original = util.read_text(encoding="utf-8")
        saved_hook = V._prestage_drift_hook

        def mutate():
            util.write_text(original + "\n// drift\n", encoding="utf-8")

        V._prestage_drift_hook = mutate
        try:
            res = V.validate_build(str(built["report_path"]), str(self.ws / "contract.json"),
                                   str(self.ws / ".runs" / "validate"), workspace_root=str(self.ws),
                                   expected_snapshot=snap, random_cases=4, timeout_seconds=60)
        finally:
            V._prestage_drift_hook = saved_hook
        self.assertEqual(res["status"], "failed")
        self.assertIn("before staging arm baseline", str(res.get("error")))


class BaselineEqualityTests(_Base):
    """The stricter JavaScript baseline-equality guarantee: the baseline arm artifact
    must equal the bound owned original module (UTF-8 BOM removed)."""

    def _synth_contract(self):
        H.write_contract(self.ws / "contract.json", source="index.js",
                         entrypoints=[{"name": "f", "parameters": [num_param("x", -3, 3)]}])

    def test_baseline_artifact_differing_from_original_is_refused(self):
        base = "'use strict';\nfunction f(x){return x;}\nmodule.exports={f};\n"
        synth = H.make_synthetic(self.ws, module_relative="index.js", baseline_text=base, protected_text=base,
                                 selected=["f"], closure=["f"], preserved=[])
        # Tamper the baseline ARTIFACT so it no longer equals the owned original module,
        # and honestly re-pin its hash/size so the artifact-hash check still passes --
        # only the baseline-equality guarantee should fail.
        report = json.loads(synth["report_path"].read_text(encoding="utf-8"))
        baseline_cjs = Path(report["artifacts"]["baseline"]["path"])
        baseline_cjs.write_text(base + "// not the original\n", encoding="utf-8")
        report["artifacts"]["baseline"]["sha256"] = hashlib.sha256(baseline_cjs.read_bytes()).hexdigest()
        report["artifacts"]["baseline"]["bytes"] = baseline_cjs.stat().st_size
        synth["report_path"].write_text(json.dumps(report), encoding="utf-8")
        self._synth_contract()
        snap = V.snapshot_source_tree(synth["app"])
        with self.assertRaises(V.MixedValidateError) as cm:
            V.validate_build(str(synth["report_path"]), str(self.ws / "contract.json"),
                             str(self.ws / "validate"), workspace_root=str(self.ws),
                             expected_snapshot=snap, random_cases=4, timeout_seconds=60)
        self.assertIn("baseline must equal the bound original module", str(cm.exception))

    def test_coverage_original_hash_mismatch_is_refused(self):
        base = "'use strict';\nfunction f(x){return x;}\nmodule.exports={f};\n"
        synth = H.make_synthetic(self.ws, module_relative="index.js", baseline_text=base, protected_text=base,
                                 selected=["f"], closure=["f"], preserved=[])
        report = json.loads(synth["report_path"].read_text(encoding="utf-8"))
        report["coverage"]["original_module_source_sha256"] = "1" * 64  # valid hex64, wrong value
        synth["report_path"].write_text(json.dumps(report), encoding="utf-8")
        self._synth_contract()
        snap = V.snapshot_source_tree(synth["app"])
        with self.assertRaises(V.MixedValidateError) as cm:
            V.validate_build(str(synth["report_path"]), str(self.ws / "contract.json"),
                             str(self.ws / "validate"), workspace_root=str(self.ws),
                             expected_snapshot=snap, random_cases=4, timeout_seconds=60)
        self.assertIn("baseline must equal the bound original module", str(cm.exception))


    def test_coverage_working_hash_mismatch_is_refused(self):
        base = "function f(x){return x;}\nmodule.exports={f};\n"
        synth = H.make_synthetic(self.ws, module_relative="index.js", baseline_text=base,
                                 protected_text=base, selected=["f"], closure=["f"], preserved=[])
        report = json.loads(synth["report_path"].read_bytes())
        report["coverage"]["working_source_sha256"] = "1" * 64
        synth["report_path"].write_text(json.dumps(report), encoding="utf-8")
        self._synth_contract()
        with self.assertRaisesRegex(V.MixedValidateError, "working source hash must match"):
            V.validate_build(str(synth["report_path"]), str(self.ws / "contract.json"),
                             str(self.ws / "validate"), workspace_root=str(self.ws),
                             expected_snapshot=V.snapshot_source_tree(synth["app"]),
                             random_cases=4, timeout_seconds=60)
        self.assertFalse((self.ws / "validate").exists())

    def test_real_bom_and_shebang_working_source_binding(self):
        app = self.ws / "app"
        H.write_sample_app(app)
        source = app / "index.js"
        source.write_bytes(b"\xef\xbb\xbf#!/usr/bin/env node\r\n" + source.read_bytes())
        out = self.ws / ".runs" / "build"
        builder = H.load_builder()
        report = builder.build_project(str(app / "project.json"), str(out),
                                       workspace_root=str(self.ws), seed=20261020)
        original = source.read_bytes().decode("utf-8-sig")
        self.assertEqual(report["coverage"]["working_source_sha256"], H.working_source_sha(original))
        self.assertNotEqual(report["coverage"]["working_source_sha256"],
                            report["coverage"]["original_module_source_sha256"])
        H.write_contract(self.ws / "contract.json", source="index.js",
                         entrypoints=[{"name": "fadd", "parameters": [num_param("a", -3, 3),
                                                                        num_param("b", -3, 3)]}])
        result = V.validate_build(str(out / "report.json"), str(self.ws / "contract.json"),
                                  str(self.ws / "validate"), workspace_root=str(self.ws),
                                  expected_snapshot=V.snapshot_source_tree(app), random_cases=4,
                                  timeout_seconds=60)
        self.assertEqual(result["status"], "mixed_application_samples_passed", result.get("error"))


class TrustedInputPinTests(_Base):
    """Root's service plan/engine/tool pins, exercised through validate_build's public
    trusted_inputs parameter (bound and re-checked before/after every arm)."""

    def _synth(self):
        ident = "'use strict';\nfunction f(x){return x;}\nmodule.exports={f};\n"
        synth = H.make_synthetic(self.ws, module_relative="index.js", baseline_text=ident,
                                 protected_text=ident, selected=["f"], closure=["f"], preserved=[])
        H.write_contract(self.ws / "contract.json", source="index.js",
                         entrypoints=[{"name": "f", "parameters": [num_param("x", -3, 3)]}])
        return synth

    def _pin_file(self, name, text):
        path = self.ws / name
        path.write_text(text, encoding="utf-8")
        return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}, path

    def _run(self, synth, trusted_inputs):
        snap = V.snapshot_source_tree(synth["app"])
        return V.validate_build(str(synth["report_path"]), str(self.ws / "contract.json"),
                                str(self.ws / "validate"), workspace_root=str(self.ws),
                                expected_snapshot=snap, trusted_inputs=trusted_inputs,
                                random_cases=4, timeout_seconds=60)

    def test_matching_trusted_inputs_pass_and_are_bound(self):
        synth = self._synth()
        pin, _ = self._pin_file("service_plan.json", '{"owned":"plan"}')
        res = self._run(synth, [pin])
        self.assertEqual(res["status"], "mixed_application_samples_passed", res.get("error"))
        self.assertTrue(res["service_plan_inputs_bound"])
        self.assertIn(pin["path"], res["service_input_pins"])
        self.assertEqual(res["service_input_pins"][pin["path"]], pin["sha256"])

    def test_trusted_input_drift_between_arms_fails_closed(self):
        synth = self._synth()
        pin, path = self._pin_file("service_plan.json", '{"owned":"plan"}')
        saved = V._postchild_drift_hook

        def mutate(arm, stage_root):
            if arm == "baseline":
                path.write_text('{"owned":"plan","drifted":true}', encoding="utf-8")

        V._postchild_drift_hook = mutate
        try:
            res = self._run(synth, [pin])
        finally:
            V._postchild_drift_hook = saved
        self.assertEqual(res["status"], "failed")
        self.assertIn("trusted service plan/engine input changed after child arm baseline", str(res.get("error")))
        self.assertIn("baseline", res["execution"])      # drift caught post-child, not pre-launch

    def test_conflicting_trusted_input_pins_refused(self):
        synth = self._synth()
        pin, _ = self._pin_file("service_plan.json", '{"owned":"plan"}')
        conflict = {"path": pin["path"], "sha256": "0" * 64}
        with self.assertRaises(V.MixedValidateError) as cm:
            self._run(synth, [pin, conflict])
        self.assertIn("conflicting trusted service input pins", str(cm.exception))

    def test_malformed_and_empty_trusted_inputs_refused(self):
        synth = self._synth()
        with self.assertRaises(V.MixedValidateError) as cm:
            self._run(synth, [{"path": "x"}])
        self.assertIn("trusted service input must carry path and sha256", str(cm.exception))
        # An empty pin list is likewise refused (fresh output dir; the first call
        # raised before any output directory was created).
        with self.assertRaises(V.MixedValidateError) as cm:
            V.validate_build(str(synth["report_path"]), str(self.ws / "contract.json"),
                             str(self.ws / "validate_empty"), workspace_root=str(self.ws),
                             expected_snapshot=V.snapshot_source_tree(synth["app"]),
                             trusted_inputs=[], random_cases=4, timeout_seconds=60)
        self.assertIn("non-empty pin list", str(cm.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
