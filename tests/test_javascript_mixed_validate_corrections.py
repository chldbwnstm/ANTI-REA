"""Focused regressions for the review corrections now carried by the production
engine. Each test proves one guarantee:

  * pinned artifact/tool re-hash immediately before launch (prelaunch drift);
  * pinned tool re-hash after each child (post-child tool drift);
  * complete overlaid staged-tree inventory before/after each arm, catching an
    injected, removed OR modified staged sibling (not only the target module);
  * the Module._load staged-tree require bound staying active through sampled
    calls, so a LAZY (and even a caught) require escaping the stage fails the arm;
  * strict parent validation of the per-arm reply schema/types/lengths/wire
    values, and parent recomputation of determinism from the retained second
    observation arrays (no truthy-flag coercion from an unsigned child field);
  * refusal of the CLI expected-snapshot=derive qualification bypass;
  * _walk_tree statting and rejecting an oversize file BEFORE reading it.

Every test runs in its own fresh temp workspace, so no real controller/STOP is
touched.

Run: C:/Python313/python.exe -I -S -B test_javascript_mixed_validate_corrections.py
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


def obs_num(value):
    return {"kind": "return", "type": "number", "bits": H.num_bits(value)}


IDENT = "'use strict';\nfunction f(x){return x;}\nmodule.exports={f};\n"


class DriftTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.ws = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()
        V._prelaunch_drift_hook = _ORIG_PRELAUNCH
        V._postchild_drift_hook = _ORIG_POSTCHILD

    def _synth(self):
        synth = H.make_synthetic(self.ws, module_relative="index.js", baseline_text=IDENT,
                                 protected_text=IDENT, selected=["f"], closure=["f"], preserved=[])
        H.write_contract(self.ws / "contract.json", source="index.js",
                         entrypoints=[{"name": "f", "parameters": [num_param("x", -3, 3)]}])
        snap = V.snapshot_source_tree(synth["app"])
        return synth, snap

    def _run(self, synth, snap):
        return V.validate_build(str(synth["report_path"]), str(self.ws / "contract.json"),
                                str(self.ws / "validate"), workspace_root=str(self.ws),
                                expected_snapshot=snap, random_cases=4, timeout_seconds=60)

    def test_artifact_prelaunch_drift_caught_before_launch(self):
        synth, snap = self._synth()
        report = json.loads(synth["report_path"].read_text(encoding="utf-8"))
        baseline_artifact = Path(report["artifacts"]["baseline"]["path"])

        def mutate(arm):
            if arm == "baseline":
                baseline_artifact.write_text(IDENT + "// drifted after staging\n", encoding="utf-8")

        V._prelaunch_drift_hook = mutate
        res = self._run(synth, snap)
        self.assertEqual(res["status"], "failed")
        self.assertIn("before launching arm baseline", str(res.get("error")))
        self.assertIn("artifact:baseline", str(res.get("error")))
        self.assertNotIn("baseline", res["execution"])      # child never launched

    def test_postchild_tool_drift_caught_after_child(self):
        synth, snap = self._synth()
        # Pin an OWNED extra build tool inside the temp workspace so we can mutate it
        # (production Node is never touched).
        tool = self.ws / "owned_tool.js"
        tool.write_text("module.exports=1;\n", encoding="utf-8")
        report = json.loads(synth["report_path"].read_text(encoding="utf-8"))
        report["toolchain"]["files"]["owned_tool"] = {
            "path": str(tool), "sha256": hashlib.sha256(tool.read_bytes()).hexdigest()}
        synth["report_path"].write_text(json.dumps(report), encoding="utf-8")

        def mutate(arm, stage_root):
            if arm == "baseline":
                tool.write_text("module.exports=2;// drifted\n", encoding="utf-8")

        V._postchild_drift_hook = mutate
        res = self._run(synth, snap)
        self.assertEqual(res["status"], "failed")
        self.assertIn("after child arm baseline", str(res.get("error")))
        self.assertIn("tool:owned_tool", str(res.get("error")))
        self.assertIn("baseline", res["execution"])          # child ran; drift caught post-child

    def _postchild_overlay_case(self, mutate_stage, needle):
        synth, snap = self._synth()

        def hook(arm, stage_root):
            if arm == "baseline":
                mutate_stage(Path(stage_root))

        V._postchild_drift_hook = hook
        res = self._run(synth, snap)
        self.assertEqual(res["status"], "failed")
        self.assertIn("does not match the trusted source/artifact map", str(res.get("error")))
        self.assertIn(needle, str(res.get("error")))

    def test_postchild_staged_sibling_injection(self):
        self._postchild_overlay_case(
            lambda stage: (stage / "injected.js").write_text("module.exports={};\n", encoding="utf-8"),
            "injected.js")

    def test_postchild_staged_sibling_removal(self):
        self._postchild_overlay_case(
            lambda stage: (stage / "package.json").unlink(),
            "package.json")

    def test_postchild_staged_sibling_modification(self):
        self._postchild_overlay_case(
            lambda stage: (stage / "package.json").write_text('{"type":"commonjs","x":1}', encoding="utf-8"),
            "package.json")

    def test_prelaunch_staged_sibling_modification_caught_against_trusted_map(self):
        # A staged sibling changed AFTER the initial capture but BEFORE launch must be
        # caught against the trusted source/artifact map (re-checked after the prelaunch
        # seam), not silently accepted as the baseline. The child must not launch.
        synth, snap = self._synth()

        def mutate(arm):
            if arm == "baseline":
                (self.ws / "validate" / "baseline" / "stage" / "package.json").write_text(
                    '{"type":"commonjs","injected":true}', encoding="utf-8")

        V._prelaunch_drift_hook = mutate
        res = self._run(synth, snap)
        self.assertEqual(res["status"], "failed")
        self.assertIn("before launch (post-hook)", str(res.get("error")))
        self.assertIn("package.json", str(res.get("error")))
        self.assertNotIn("baseline", res["execution"])


_ORIG_PRELAUNCH = V._prelaunch_drift_hook
_ORIG_POSTCHILD = V._postchild_drift_hook


class LazyRequireTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.tmp = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()

    def test_lazy_outside_require_during_sampled_call_fails_arm(self):
        # The owned module requires an outside module only on the first call, after
        # top-level load already succeeded. The guard must still be installed during
        # sampling and fail the arm (not record an ordinary throw observation).
        (self.tmp / "outside.js").write_text("module.exports={};\n", encoding="utf-8")
        stage = self.tmp / "stage"
        stage.mkdir(parents=True, exist_ok=True)
        (stage / "package.json").write_text('{"type":"commonjs"}', encoding="utf-8")
        module = ("'use strict';\n"
                  "let cached;\n"
                  "function f(x){ if(!cached){ cached = require('../outside.js'); } return x; }\n"
                  "module.exports={f};\n")
        (stage / "index.js").write_text(module, encoding="utf-8")
        result = H.run_runner(stage, stage / "index.js",
                              [{"name": "f", "parameters": [{"name": "x"}]}],
                              {"f": [[H.arg_num(1)], [H.arg_num(2)]]}, self.tmp / "work")
        self.assertNotEqual(result["returncode"], 0, result["stdout"])
        self.assertEqual(result["reply"]["status"], "error")
        self.assertIn("outside the staged tree", result["reply"]["error"])

    def test_caught_lazy_outside_require_still_fails_arm(self):
        # Owned app code that CATCHES its own escaping-require error and returns
        # normally must still fail the arm: the loader hook records a sticky violation
        # re-checked after sampling, so the escape is not laundered into a success.
        (self.tmp / "outside.js").write_text("module.exports={};\n", encoding="utf-8")
        stage = self.tmp / "stage"
        stage.mkdir(parents=True, exist_ok=True)
        (stage / "package.json").write_text('{"type":"commonjs"}', encoding="utf-8")
        module = ("'use strict';\n"
                  "function f(x){ try { require('../outside.js'); } catch (e) {} return x; }\n"
                  "module.exports={f};\n")
        (stage / "index.js").write_text(module, encoding="utf-8")
        result = H.run_runner(stage, stage / "index.js",
                              [{"name": "f", "parameters": [{"name": "x"}]}],
                              {"f": [[H.arg_num(1)], [H.arg_num(2)]]}, self.tmp / "work")
        self.assertNotEqual(result["returncode"], 0, result["stdout"])
        self.assertEqual(result["reply"]["status"], "error")
        self.assertIn("outside the staged tree (sticky)", result["reply"]["error"])


def make_reply(names, outputs, *, outputs_second=None, deterministic=None):
    names = list(names)
    second = outputs_second if outputs_second is not None else {n: list(outputs[n]) for n in names}
    return {
        "status": "ok",
        "module_origin": {"resolved": "/staged/index.js", "require_executed": True,
                          "file_sha256_before": "0" * 64, "file_sha256_after": "0" * 64,
                          "loaded_files": [], "public_surface": {n: "function" for n in names},
                          "env_keys": []},
        "signatures": {n: {"length": 1, "kind": "function", "source_prefix": "function " + n} for n in names},
        "outputs": outputs,
        "outputs_second": second,
        "deterministic": deterministic if deterministic is not None else {n: True for n in names},
        "timings": {n: {"samples_ns": [1], "median_ns": 1, "calls_per_batch": 1, "warmup_batches": 1}
                    for n in names},
    }


class ReplyValidationTests(unittest.TestCase):
    def valid(self):
        return make_reply(["f"], {"f": [obs_num(1), obs_num(2)]})

    def test_accepts_well_formed_reply(self):
        V._validate_reply(self.valid(), {"f"}, {"f": 2})  # no raise

    def _reject(self, reply, needle=None):
        with self.assertRaises(V.MixedValidateError) as cm:
            V._validate_reply(reply, {"f"}, {"f": 2})
        if needle:
            self.assertIn(needle, str(cm.exception))

    def test_rejects_wrong_output_length(self):
        r = self.valid(); r["outputs"]["f"] = [obs_num(1)]
        self._reject(r, "one observation per sampled vector")

    def test_rejects_bad_number_bits(self):
        r = self.valid(); r["outputs"]["f"][0] = {"kind": "return", "type": "number", "bits": "zz"}
        self._reject(r, "16 lowercase hex bits")

    def test_rejects_non_bool_boolean_value(self):
        r = self.valid(); r["outputs"]["f"][0] = {"kind": "return", "type": "boolean", "value": 1}
        self._reject(r, "JSON boolean")

    def test_rejects_require_executed_not_true(self):
        r = self.valid(); r["module_origin"]["require_executed"] = "yes"
        self._reject(r, "require_executed must be exactly true")

    def test_rejects_missing_outputs_second(self):
        r = self.valid(); del r["outputs_second"]
        self._reject(r, "outputs_second")

    def test_rejects_extra_output_entrypoint(self):
        r = self.valid(); r["outputs"]["g"] = [obs_num(1), obs_num(2)]
        self._reject(r, "exactly the sampled entrypoints")

    def test_recomputes_determinism_ignoring_truthy_flag(self):
        names = {"f"}
        # Baseline's SECOND observation pass differs at index 1: truly nondeterministic,
        # yet the child falsely claims deterministic=True.
        baseline = make_reply(names, {"f": [obs_num(1), obs_num(2)]},
                              outputs_second={"f": [obs_num(1), obs_num(999)]},
                              deterministic={"f": True})
        protected = make_reply(names, {"f": [obs_num(1), obs_num(2)]})
        V._validate_reply(baseline, names, {"f": 2})
        V._validate_reply(protected, names, {"f": 2})
        functions = V._compare_functions(baseline, protected, {"f": [None, None]}, names)
        self.assertFalse(functions["f"]["deterministic"])    # recomputed a==a2 and b==b2
        self.assertTrue(functions["f"]["sampled_output_match"])

    def test_determinism_true_when_second_arrays_match(self):
        names = {"f"}
        baseline = make_reply(names, {"f": [obs_num(1), obs_num(2)]})
        protected = make_reply(names, {"f": [obs_num(1), obs_num(2)]})
        functions = V._compare_functions(baseline, protected, {"f": [None, None]}, names)
        self.assertTrue(functions["f"]["deterministic"])


class CliAndWalkTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.tmp = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()

    def test_cli_refuses_derive(self):
        with self.assertRaises(V.MixedValidateError) as cm:
            V.main(["--report", "r.json", "--contract", "c.json", "--output", "o",
                    "--workspace", str(self.tmp), "--expected-snapshot", "derive"])
        self.assertIn("derive is refused", str(cm.exception))

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
