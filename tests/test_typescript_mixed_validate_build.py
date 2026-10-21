"""Full production ``validate_build`` orchestration for an owned TypeScript mixed
build: the real pass (independent reference provenance, verified per-arm process
cleanup, retained second-pass arrays, append-only output), the independent
reference catching a repinned baseline tamper, STOP cancellation, toolchain
drift, and source / artifact / staged-sibling / reference-input drift caught by
the before/after integrity and overlay re-checks.

TypeScript actual execution requires the independent reference-compiler helper
(``antirea.typescript_reference`` + ``tools/typescript_frontend/mixed_reference.cjs``).
Until its owning worker stages it, this whole module skips (``ts_reference_ready``);
the refusals reached before that helper live in test_typescript_mixed_validate_boundary.

Each test runs in its own fresh temp workspace, so the STOP test writes only a
fake defense-loop/STOP inside that temp root; the real repository STOP is never
written. Tests assert semantics and documented result fields, not exact message
strings.

Run: C:/Python313/python.exe -I -S -B test_typescript_mixed_validate_build.py
"""
import hashlib
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


@unittest.skipUnless(H.ts_reference_ready(),
                     "independent TypeScript reference helper not yet staged by its owning worker")
class TypeScriptValidateBuildTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.ws = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()

    def _built(self, *, seed=20261020):
        built = H.build_sample_ts(self.ws, seed=seed)
        self.assertEqual(built["report"]["status"], "artifact_created_unvalidated", built["report"])
        self.assertTrue(built["report"]["coverage"]["transpiled_typescript"])
        return built

    def _contract(self, name="contract.json"):
        path = self.ws / name
        H.write_ts_contract(path, source="index.ts",
                            entrypoints=H.SAMPLE_ENTRYPOINTS, preserved=H.SAMPLE_PRESERVED)
        return path

    def _validate(self, built, contract, out="validate", *, random_cases=16, timeout=120):
        # TypeScript validation emits its independent reference under the output
        # directory, which the reference helper requires to live under
        # <workspace>/.runs (as the real ProjectService output does).
        return V.validate_build(str(built["report_path"]), str(contract),
                                str(self.ws / ".runs" / out), workspace_root=str(self.ws),
                                expected_snapshot=V.snapshot_source_tree(built["app"]),
                                random_cases=random_cases, timeout_seconds=timeout)

    # -- real end-to-end pass -------------------------------------------------
    def test_real_typescript_sample_passes(self):
        built = self._built()
        contract = self._contract()
        res = self._validate(built, contract)
        self.assertEqual(res["status"], "mixed_application_samples_passed", res.get("error"))

        # First-class TypeScript result identity.
        self.assertEqual(res["language"], "typescript")
        self.assertEqual(res["baseline_source_kind"], "typescript_independent_transpile")
        self.assertTrue(res["transpiled_typescript"])
        self.assertEqual(res["module_relative"], "index.ts")
        self.assertEqual(res["runtime_module_relative"], "index.cjs")
        self.assertEqual(res["behavior_repeats"], 2)
        self.assertTrue(res["inputs_unchanged"])
        self.assertTrue(res["module_origin"]["consistent"])

        # Independent reference provenance: a successfully built reference whose
        # source identity and working-source hash bind the SAME original .ts.
        ref = res["reference_compilation"]
        self.assertEqual(ref["status"], "reference_created")
        self.assertEqual(ref["normalized_source_sha256"], res["original_module_source_sha256"])
        self.assertEqual(ref["working_source_sha256"], res["working_source_sha256"])
        self.assertTrue(res["reference_evidence_pins"])
        self.assertTrue(res["reference_tool_pins"])

        # Sampled functional preservation on both the selected root and the
        # preserved caller that invokes the virtualized root.
        self.assertTrue(all(f["sampled_output_match"] and f["deterministic"]
                            for f in res["functions"].values()))
        self.assertTrue(res["functions"]["core"]["selected"])
        self.assertFalse(res["functions"]["combo"]["selected"])
        self.assertGreater(res["functions"]["core"]["baseline_ordinary_returns"], 0)

        # Raw per-arm receipts with the retained SECOND-pass arrays, and verified
        # bounded process-tree cleanup, for each arm.
        for arm in ("baseline", "protected"):
            reply = json.loads((self.ws / ".runs" / "validate" / arm / (arm + ".reply.json")).read_text(encoding="utf-8"))
            self.assertEqual(reply["status"], "ok")
            self.assertIn("outputs", reply)
            self.assertIn("outputs_second", reply)
            cleanup = res["execution"][arm]["cleanup"]
            self.assertTrue(cleanup.get("job_assigned"))
            self.assertEqual(cleanup.get("active_after"), 0)
            self.assertTrue(cleanup.get("parent_exit_confirmed"))
            self.assertTrue(cleanup.get("job_handle_closed"))
            # The staged runtime entry is the emitted .cjs; the .ts entry is gone.
            stage = self.ws / ".runs" / "validate" / arm / "stage"
            self.assertTrue((stage / "index.cjs").is_file())
            self.assertFalse((stage / "index.ts").exists())
        self.assertTrue((self.ws / ".runs" / "validate" / "validation.json").is_file())

    # -- append-only validation directories ----------------------------------
    def test_validation_output_is_append_only(self):
        built = self._built()
        contract = self._contract()
        res1 = self._validate(built, contract, out="validate")
        self.assertEqual(res1["status"], "mixed_application_samples_passed", res1.get("error"))
        res2 = self._validate(built, contract, out="validate2")
        self.assertEqual(res2["status"], "mixed_application_samples_passed", res2.get("error"))
        # A re-validation never overwrites an earlier run's receipts.
        self.assertTrue((self.ws / ".runs" / "validate" / "validation.json").is_file())
        self.assertTrue((self.ws / ".runs" / "validate2" / "validation.json").is_file())
        with self.assertRaises(V.MixedValidateError):
            self._validate(built, contract, out="validate")  # existing dir refused

    # -- independent reference catches a repinned baseline tamper -------------
    def test_repinned_baseline_tamper_fails_against_independent_emit(self):
        built = self._built()
        contract = self._contract()
        report = json.loads(built["report_path"].read_text(encoding="utf-8"))
        baseline_cjs = Path(report["artifacts"]["baseline"]["path"])
        # Tamper the baseline runtime so it no longer equals the independently
        # emitted reference, and HONESTLY re-pin its hash/size so the ordinary
        # artifact-hash check still passes -- only the independent-emit comparison
        # should fail.
        baseline_cjs.write_bytes(baseline_cjs.read_bytes() + b"\n// tampered runtime\n")
        report["artifacts"]["baseline"]["sha256"] = hashlib.sha256(baseline_cjs.read_bytes()).hexdigest()
        report["artifacts"]["baseline"]["bytes"] = baseline_cjs.stat().st_size
        built["report_path"].write_text(json.dumps(report), encoding="utf-8")
        res = self._validate(built, contract)
        self.assertEqual(res["status"], "failed", res.get("error"))
        # The reference itself built cleanly; the tamper was caught by COMPARISON
        # to the true independent emit, not by a reference-build failure.
        self.assertEqual(res["reference_compilation"]["status"], "reference_created")
        self.assertIn("independent", str(res.get("error")).lower())

    # -- STOP -----------------------------------------------------------------
    def test_stop_cancels_before_execution(self):
        built = self._built()
        contract = self._contract()
        stop = self.ws / ".runs" / "defense-loop" / "STOP"
        stop.parent.mkdir(parents=True, exist_ok=True)
        stop.write_text("owned test STOP", encoding="utf-8")
        res = self._validate(built, contract)
        self.assertEqual(res["status"], "cancelled", res.get("error"))
        self.assertEqual(res["execution"], {})

    # -- toolchain drift ------------------------------------------------------
    def test_toolchain_drift_fails_closed(self):
        built = self._built()
        contract = self._contract()
        report = json.loads(built["report_path"].read_text(encoding="utf-8"))
        report["toolchain"]["files"]["node"]["sha256"] = "0" * 64  # stale pin
        built["report_path"].write_text(json.dumps(report), encoding="utf-8")
        res = self._validate(built, contract)
        self.assertEqual(res["status"], "failed")
        self.assertIn("toolchain changed", str(res.get("error")))
        self.assertEqual(res["execution"], {})

    # -- owned source drift between plan preflight and staging ----------------
    def test_prestage_source_drift_detected(self):
        built = self._built()
        contract = self._contract()
        util = built["app"] / "lib" / "util.js"
        original = util.read_text(encoding="utf-8")
        saved = V._prestage_drift_hook
        V._prestage_drift_hook = lambda: util.write_text(original + "\n// drift\n", encoding="utf-8")
        try:
            res = self._validate(built, contract)
        finally:
            V._prestage_drift_hook = saved
        self.assertEqual(res["status"], "failed")
        self.assertIn("source plan", str(res.get("error")).lower())

    # -- a staged sibling injected after a child fails closed -----------------
    def test_staged_sibling_drift_after_child_fails_closed(self):
        built = self._built()
        contract = self._contract()
        saved = V._postchild_drift_hook

        def inject(arm, stage_root):
            if arm == "baseline":
                (Path(stage_root) / "injected.js").write_text("// injected\n", encoding="utf-8")

        V._postchild_drift_hook = inject
        try:
            res = self._validate(built, contract)
        finally:
            V._postchild_drift_hook = saved
        self.assertEqual(res["status"], "failed")
        self.assertIn("baseline", res["execution"])  # caught post-child, after the arm ran

    # -- a pinned arm artifact mutated before launch fails closed -------------
    def test_artifact_drift_before_launch_fails_closed(self):
        built = self._built()
        contract = self._contract()
        report = json.loads(built["report_path"].read_text(encoding="utf-8"))
        protected_cjs = Path(report["artifacts"]["protected"]["path"])
        saved = V._prelaunch_drift_hook

        def mutate(arm):
            if arm == "protected":
                protected_cjs.write_bytes(protected_cjs.read_bytes() + b"\n// drift\n")

        V._prelaunch_drift_hook = mutate
        try:
            res = self._validate(built, contract)
        finally:
            V._prelaunch_drift_hook = saved
        self.assertEqual(res["status"], "failed")
        self.assertIn("integrity", str(res.get("error")).lower())

    # -- a reference evidence input mutated after a child fails closed --------
    def test_reference_evidence_drift_after_child_fails_closed(self):
        built = self._built()
        contract = self._contract()
        reference_report = self.ws / ".runs" / "validate" / "reference" / "reference.json"
        saved = V._postchild_drift_hook

        def mutate(arm, stage_root):
            if arm == "baseline" and reference_report.is_file():
                reference_report.write_bytes(reference_report.read_bytes() + b"\n")

        V._postchild_drift_hook = mutate
        try:
            res = self._validate(built, contract)
        finally:
            V._postchild_drift_hook = saved
        self.assertEqual(res["status"], "failed")
        self.assertIn("reference", str(res.get("error")).lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
