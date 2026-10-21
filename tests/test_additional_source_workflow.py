"""Explicit opt-in real Java/Kotlin/JS/TS defender MCP source workflows.

These tests compile and execute only repository-owned fixtures. They do not run
attacks, install dependencies, publish artifacts, or alter the external loop.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest

from antirea.defense_mcp import DefenseBridge


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@unittest.skipUnless(os.environ.get("ANTIREA_RUN_LANGUAGE_E2E") == "1",
                     "explicit owned Java/Kotlin/JavaScript/TypeScript compiler/execution opt-in required")
class AdditionalSourceWorkflowTests(unittest.TestCase):
    def exercise(self, language, backend):
        root = Path(__file__).resolve().parents[1]
        fixture = root / "samples/multilang" / language
        contract_path = fixture / "contract.json"
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        exports = {entry["name"] for entry in contract["functions"]}
        bridge = DefenseBridge(SimpleNamespace(root=root))
        request_id = 1
        record = {"schema_version": 1, "status": "failed", "language": language, "backend": backend,
                  "started_utc": datetime.now(timezone.utc).isoformat(),
                  "fixture": str(fixture.relative_to(root)), "random_cases_requested": 8192,
                  "timeout_seconds_per_process": 180, "external_attack_evaluation": "not_evaluated",
                  "published": False}
        evidence_path = None

        def call(name, **arguments):
            nonlocal request_id
            request_id += 1
            reply = bridge.handle({"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
                                   "params": {"name": name, "arguments": arguments}})
            self.assertIsInstance(reply, dict)
            self.assertEqual(reply.get("id"), request_id)
            self.assertNotIn("error", reply, reply)
            result = reply["result"]
            payload = json.loads(result["content"][0]["text"])
            self.assertFalse(result["isError"], payload)
            return payload

        try:
            initialized = bridge.handle({"jsonrpc": "2.0", "id": request_id, "method": "initialize", "params": {
                "protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "owned-additional-language-e2e", "version": "1"}}})
            self.assertIn("result", initialized)
            self.assertIsNone(bridge.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))

            plan = call("protection_source_plan", project_path=str(fixture / "project.json"))
            self.assertEqual(plan["status"], "planned")
            plan_dir = Path(plan["output_dir"]).parent
            self.assertTrue(plan_dir.is_relative_to(root / ".runs/source-protection"))
            evidence_path = plan_dir / "language-e2e.json"
            record.update(plan_id=plan["plan_id"], fingerprint=plan["fingerprint"],
                          build_report=str(Path(plan["output_dir"]) / "report.json"))

            built = call("protection_source_build", plan_id=plan["plan_id"], fingerprint=plan["fingerprint"])
            self.assertEqual(built["status"], "artifact_created_unvalidated", built)
            self.assertEqual(built["backend"], backend)
            self.assertEqual(built["project"]["language"], language)
            self.assertEqual(set(built["coverage"]["exported_functions"]), exports)
            self.assertNotEqual(built["artifacts"]["baseline"]["sha256"], built["artifacts"]["protected"]["sha256"])
            build_report = Path(record["build_report"])
            self.assertTrue(build_report.is_file())
            record.update(build_report_sha256=_sha256(build_report), artifacts=built["artifacts"],
                          exported_functions=sorted(exports))
            if backend in {"jvm_bytecode_native", "go_typed_native", "swift_llvm_native"}:
                self.assertFalse(built["target_executed"])
                self.assertTrue(set(built["coverage"]["functions"]).issuperset(exports))
                self.assertTrue(all(entry["virtualized"] is True for entry in built["coverage"]["functions"].values()))
                signature = built["signature_ir"]
                self.assertTrue(Path(signature["path"]).is_relative_to(build_report.parent))
                self.assertEqual(_sha256(signature["path"]), signature["sha256"])

            validated = call("protection_source_validate", plan_id=plan["plan_id"],
                             contract_path=str(contract_path), random_cases=8192, timeout_seconds=180)
            self.assertEqual(validated["status"], "functional_samples_passed", validated)
            self.assertEqual(set(validated["functions"]), exports)
            self.assertEqual(set(validated["cases_per_function"]), exports)
            self.assertEqual(validated["behavior_repeats"], 2)
            self.assertTrue(validated["inputs_unchanged"])
            minimum_cases = {}
            for function in contract["functions"]:
                domain = 1  # A zero-argument function has one input tuple.
                for parameter in function["parameters"]:
                    if parameter["type"] == "boolean":
                        domain *= 2
                    elif backend == "javascript_vm":
                        domain *= int(parameter["maximum"]) - int(parameter["minimum"]) + 1
                    else:
                        domain *= 2 ** int(parameter["type"][1:])
                minimum_cases[function["name"]] = min(8192, domain)
            for name in exports:
                self.assertGreaterEqual(validated["cases_per_function"][name], minimum_cases[name])
                self.assertTrue(validated["functions"][name]["sampled_output_match"])
                self.assertTrue(validated["functions"][name]["deterministic"])
            validation_path = plan_dir / validated["validation_id"] / "validation.json"
            self.assertTrue(validation_path.is_file())
            record.update(validation_id=validated["validation_id"], validation_report=str(validation_path),
                          validation_report_sha256=_sha256(validation_path),
                          cases_per_function=validated["cases_per_function"],
                          behavior_repeats=validated["behavior_repeats"])
            if backend in {"jvm_bytecode_native", "go_typed_native", "swift_llvm_native"}:
                self.assertIs(validated["source_reference_required"], True)
                reference = validated["source_reference"]
                self.assertEqual(reference["status"], "passed", reference)
                self.assertEqual(set(reference["arms"]), {"baseline", "protected"})
                self.assertTrue(reference["target_executed"])
                self.assertEqual(reference["changed_inputs"], [])
                self.assertEqual({entry["export"] for entry in reference["methods"]}, exports)
                self.assertEqual(len(reference["methods"]), len(exports))
                for method in reference["methods"]:
                    expected_random = 0 if minimum_cases[method["export"]] == 1 else 8192
                    self.assertEqual(method["random_unique_cases"], expected_random)
                    self.assertGreater(method["edge_cases"], 0)
                    self.assertEqual(method["total"], method["random_unique_cases"] + method["edge_cases"])
                    self.assertEqual(set(method["comparisons"]), {"baseline", "protected"})
                    for arm, comparison in method["comparisons"].items():
                        self.assertEqual(comparison["status"], "passed")
                        self.assertEqual(comparison["matched"], method["total"])
                        self.assertEqual(comparison["total"], method["total"])
                        self.assertEqual(comparison["library_sha256"], built["artifacts"][arm]["sha256"])
                reference_path = validation_path.parent / "reference/report.json"
                self.assertTrue(reference_path.is_file())
                record["source_reference"] = {"required": True, "status": reference["status"],
                    "report": str(reference_path), "sha256": _sha256(reference_path),
                    "methods": reference["methods"], "repeats_per_runtime": reference.get("behavior_repeats", 1)}
            else:
                # Script baselines are the original owned-language execution;
                # no CLR/JVM source-to-native reference stage is involved.
                self.assertFalse(validated.get("source_reference_required", False))
                record["source_reference"] = {"required": False, "status": "original_script_baseline_compared"}
            self.assertEqual(_sha256(build_report), record["build_report_sha256"])
            record["status"] = "passed"
        except BaseException as exc:
            record["error"] = type(exc).__name__ + ": " + str(exc)[:4096]
            raise
        finally:
            if evidence_path is not None:
                record["finished_utc"] = datetime.now(timezone.utc).isoformat()
                # Each plan owns a fresh directory. Never overwrite a prior run,
                # including failed E2E assertions after a successful compilation.
                with evidence_path.open("x", encoding="utf-8", newline="\n") as stream:
                    json.dump(record, stream, indent=2)
                    stream.write("\n")
                print(json.dumps(record))

    def test_actual_java_source_via_jvm_to_native_vm(self):
        self.exercise("java", "jvm_bytecode_native")

    def test_actual_kotlin_source_via_jvm_to_native_vm(self):
        self.exercise("kotlin", "jvm_bytecode_native")

    def test_actual_javascript_source_via_script_vm(self):
        self.exercise("javascript", "javascript_vm")

    def test_actual_typescript_source_via_script_vm(self):
        self.exercise("typescript", "javascript_vm")

    @unittest.skipUnless(os.environ.get("ANTIREA_RUN_GO_SWIFT_E2E") == "1", "explicit Go/Swift toolchain execution opt-in required")
    def test_actual_go_source_via_typed_native_vm(self):
        self.exercise("go", "go_typed_native")

    @unittest.skipUnless(os.environ.get("ANTIREA_RUN_GO_SWIFT_E2E") == "1", "explicit Go/Swift toolchain execution opt-in required")
    def test_actual_swift_source_via_llvm_native_vm(self):
        self.exercise("swift", "swift_llvm_native")


if __name__ == "__main__":
    unittest.main()
