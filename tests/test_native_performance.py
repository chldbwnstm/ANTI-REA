"""Private comparison control-flow tests; dummy artifacts are never executed."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from antirea import native_performance as perf


class MeasurementTests(unittest.TestCase):
    def test_seven_rounds_rotate_and_one_warmup_is_excluded(self):
        calls = []
        callbacks = {name: (lambda *args, name=name: calls.append((name, args))) for name in perf.ARMS}
        times = iter(range(0, 420, 10))
        result = perf._measure(callbacks, [(1, 2), (3, 4)], clock=lambda: next(times))
        self.assertEqual(len(calls), 3 * 2 * 8)
        self.assertEqual([name for name, _ in calls[:6]], ["baseline"] * 2 + ["current"] * 2 + ["candidate"] * 2)
        self.assertEqual(result["round_order"][:3], [["baseline", "current", "candidate"],
                                                    ["current", "candidate", "baseline"],
                                                    ["candidate", "baseline", "current"]])
        for arm in perf.ARMS:
            self.assertEqual(result["arms"][arm]["samples_ns"], [10] * 7)
            self.assertEqual(result["arms"][arm]["ratio_to_current"], 1)


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.contract = self.root / "contract.json"
        self.write(self.contract, {"schema_version": 1, "library_name": "sample", "calling_convention": "cdecl",
                                  "functions": [{"name": "score", "return_type": "u64", "parameters": [{"name": "x", "type": "u32"}]}]})
        self.paths = {}
        for name in ("current", "candidate"):
            folder = self.root / ".runs" / name
            folder.mkdir(parents=True)
            (folder / "module.before.ll").write_text("define i64 @score(i32 %x) {\n  ret i64 0\n}\n")
            manifest = {"parameters": {"key": 19}, "blobs": [{"encoded_sha256": "fixed"}],
                        "used_handlers": ["F_CONST"], "format_version": 2, "requested_hardening_layers": ["anti_tamper"]}
            self.write(folder / "diversification.json", manifest)
            artifacts = {}
            for arm in ("baseline", "protected"):
                file = folder / (arm + ".dll")
                file.write_bytes(b"inert test fixture, not an executable" + arm.encode())
                artifacts[arm] = {"path": str(file), "sha256": perf._hash(file)}
            coverage = {"functions": {"score": {"virtualized": True}}, "requested_core_passes": ["fla", "sub", "co", "vm"],
                        "runtime_evidence": {"fla_dispatcher": True, "substitution_instructions": 1, "constant_obfuscation_instructions": 1},
                        "hardening_evidence": {"verified_retained_components": ["encoded_bytecode_length_checksum_check"]}}
            report = {"status": "artifact_created_unvalidated", "seed": 19, "project": {"input_hashes": {"owned.c": "same"}},
                      "coverage": coverage, "artifacts": artifacts,
                      "artifact_hashes": {p: perf._hash(folder / p) for p in ("module.before.ll", "diversification.json")}}
            self.paths[name] = folder / "report.json"
            self.write(self.paths[name], report)

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def write(path, value):
        path.write_text(json.dumps(value), encoding="utf-8")

    def prepare(self):
        return perf.prepare(self.paths["current"], self.paths["candidate"], self.contract, self.root)

    def alter(self, mutate):
        report = json.loads(self.paths["candidate"].read_text())
        mutate(report)
        self.write(self.paths["candidate"], report)

    def test_preflight_pins_all_three_artifacts_without_loading(self):
        with patch.object(perf.ctypes, "CDLL", side_effect=AssertionError("preflight must not execute")):
            request = self.prepare()
        self.assertEqual(set(request["artifacts"]), set(perf.ARMS))
        self.assertEqual(len(request["protection_identity_sha256"]), 64)
        self.assertIn("ctypes", request["qualification"])

    def test_changed_source_or_seed_rejected(self):
        for field in ("seed", "inputs"):
            with self.subTest(field=field):
                original = self.paths["candidate"].read_text()
                if field == "seed":
                    self.alter(lambda r: r.update(seed=20))
                else:
                    self.alter(lambda r: r["project"]["input_hashes"].update({"owned.c": "changed"}))
                with self.assertRaisesRegex(ValueError, "identical"):
                    self.prepare()
                self.paths["candidate"].write_text(original)

    def test_changed_artifact_rejected(self):
        (self.paths["candidate"].parent / "protected.dll").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "artifact hash"):
            self.prepare()

    def test_contract_cannot_omit_public_exports(self):
        for key in self.paths:
            report = json.loads(self.paths[key].read_text())
            report["coverage"]["exported_functions"] = ["score", "unobserved"]
            self.write(self.paths[key], report)
        with self.assertRaisesRegex(ValueError, "every exported"):
            self.prepare()

    def test_changed_manifest_and_signature_ir_rejected(self):
        for filename in ("diversification.json", "module.before.ll"):
            with self.subTest(filename=filename):
                path = self.paths["candidate"].parent / filename
                original = path.read_bytes()
                path.write_bytes(original + b" ")
                with self.assertRaisesRegex(ValueError, "hash differs"):
                    self.prepare()
                path.write_bytes(original)

    def test_disabled_protection_is_not_a_performance_win(self):
        for field in ("fla_dispatcher", "substitution_instructions", "constant_obfuscation_instructions"):
            with self.subTest(field=field):
                original = self.paths["candidate"].read_text()
                self.alter(lambda r: r["coverage"]["runtime_evidence"].update({field: False}))
                with self.assertRaisesRegex(ValueError, "retained VM"):
                    self.prepare()
                self.paths["candidate"].write_text(original)

    def test_different_codec_is_not_a_same_protection_comparison(self):
        path = self.paths["candidate"].parent / "diversification.json"
        manifest = json.loads(path.read_text())
        manifest["parameters"]["key"] = 20
        self.write(path, manifest)
        self.alter(lambda r: r["artifact_hashes"].update({"diversification.json": perf._hash(path)}))
        with self.assertRaisesRegex(ValueError, "VM bytecode"):
            self.prepare()

    def test_secondary_engine_changes_are_not_hidden_by_first_engine_alias(self):
        for key in self.paths:
            path = self.paths[key].parent / "diversification.json"
            manifest = json.loads(path.read_text())
            manifest.update(engine_mode="per_function_indirect", dispatcher_symbols=["first", "second"],
                            engines=[{"parameters": {"key": 19}}, {"parameters": {"key": 23}}])
            self.write(path, manifest)
            report = json.loads(self.paths[key].read_text())
            report["artifact_hashes"]["diversification.json"] = perf._hash(path)
            self.write(self.paths[key], report)
        self.prepare()  # Equal mock identities, without loading inert DLLs.
        path = self.paths["candidate"].parent / "diversification.json"
        manifest = json.loads(path.read_text())
        manifest["engines"][1]["parameters"]["key"] = 29
        self.write(path, manifest)
        self.alter(lambda r: r["artifact_hashes"].update({"diversification.json": perf._hash(path)}))
        with self.assertRaisesRegex(ValueError, "VM bytecode"):
            self.prepare()

    def test_stop_or_existing_output_prevents_worker_launch(self):
        output = self.root / ".runs/comparison"
        with patch.object(perf, "run_logged", side_effect=AssertionError("must not launch")):
            output.mkdir()
            with self.assertRaisesRegex(ValueError, "fresh"):
                perf.compare(self.paths["current"], self.paths["candidate"], self.contract, output, workspace_root=self.root)
            stop = self.root / ".runs/defense-loop/STOP"
            stop.parent.mkdir()
            stop.touch()
            with self.assertRaisesRegex(ValueError, "STOP"):
                perf.compare(self.paths["current"], self.paths["candidate"], self.contract, self.root / ".runs/new", workspace_root=self.root)

    def test_worker_compares_every_arm_twice_and_never_times_mismatch(self):
        request = self.prepare()
        def library(path, **kwargs):
            bump = 1 if Path(path) == Path(request["artifacts"]["candidate"]["path"]) else 0
            return SimpleNamespace(score=lambda x: x + bump)
        with patch.object(perf.ctypes, "CDLL", side_effect=library), \
             patch.object(perf, "make_cases", return_value={"score": [[0], [1], [2]]}), \
             patch.object(perf, "_measure", side_effect=AssertionError("mismatch must not be benchmarked")):
            result = perf._worker_run(request)
        self.assertEqual(result["status"], "functional_mismatch")
        self.assertEqual(result["functional"]["score"]["matches"], {"baseline": [3, 3], "current": [3, 3], "candidate": [0, 0]})
        self.assertEqual(result["timings"], {})

    def test_unverified_cleanup_cannot_report_a_measurement(self):
        output = self.root / ".runs/comparison"
        def run(*args, **kwargs):
            self.write(output / "worker-reply.json", {"status": "measured", "timings": {"fabricated": True}})
            return {"returncode": 0, "cleanup": {"parent_exit_confirmed": True, "status": "unverified", "job_handle_closed": True}}
        with patch.object(perf, "run_logged", side_effect=run):
            result = perf.compare(self.paths["current"], self.paths["candidate"], self.contract, output, workspace_root=self.root)
        self.assertEqual(result["status"], "failed")
        self.assertNotIn("timings", result)


if __name__ == "__main__":
    unittest.main()
