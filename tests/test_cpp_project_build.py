"""Real owned C++ overload/namespace integration, opt-in and append-only.

The original compiler build, LLVM baseline and protected DLL are three distinct
arms. Test definitions alone are not a passing execution result.
"""
import hashlib
import json
import os
from pathlib import Path
import unittest
import uuid

from antirea.projects import ProjectService


ROOT = next(parent for parent in Path(__file__).resolve().parents
            if (parent / "antirea/projects.py").is_file())


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@unittest.skipUnless(os.name == "nt" and os.environ.get("ANTIREA_RUN_CPP_PROJECT_E2E") == "1",
                     "explicit owned C++ compiler/VM/three-arm execution opt-in")
class ActualCppProjectTests(unittest.TestCase):
    def assert_clean(self, record):
        self.assertEqual(record["returncode"], 0)
        self.assertIs(record["timed_out"], False)
        self.assertIs(record["cancelled"], False)
        cleanup = record["cleanup"]
        self.assertEqual(cleanup["method"], "windows_job")
        self.assertEqual(cleanup["status"], "assigned_job_empty")
        self.assertIs(cleanup["job_assigned"], True)
        self.assertEqual(cleanup["active_after"], 0)
        self.assertIs(cleanup["parent_exit_confirmed"], True)
        self.assertIs(cleanup["job_handle_closed"], True)

    def exercise(self, optimization, *, dialect="gnu", public_boundary=False):
        self.assertFalse((ROOT / ".runs/defense-loop/STOP").exists())
        # Only trusted, versioned fixture bytes may be copied. No received code.
        fixture = ROOT / "samples/multilang/cpp_namespace"
        self.assertTrue(fixture.is_dir(), "Production fixture has not been integrated yet")
        base = Path(os.environ.get("ANTIREA_CPP_PROJECT_OUTPUT", str(ROOT / ".runs"))).resolve()
        self.assertTrue(base.is_relative_to(ROOT / ".runs"))
        directory = base / ("cpp-project-" + dialect + "-" + optimization.lower()
                            + "-" + uuid.uuid4().hex[:12])
        source = directory / "source"
        source.mkdir(parents=True, exist_ok=False)
        files = ("core.hpp", "wide.cpp", "narrow.cpp", "entry.cpp",
                 "contract.json", "protection-policy.json")
        for name in files:
            with (source / name).open("xb") as stream:
                stream.write((fixture / name).read_bytes())
        exports = ["public_score"]
        if public_boundary:
            exports.append("public_forward")
            policy = read(source / "protection-policy.json")
            policy["public_presentation"] = {"public_forward": "Reviewed public scalar forwarding ABI only."}
            contract = read(source / "contract.json")
            contract["functions"].append({**contract["functions"][0], "name": "public_forward"})
            for name, value in (("protection-policy.json", policy), ("contract.json", contract)):
                (source / name).write_text(json.dumps(value, indent=2), encoding="utf-8")
        source_hashes = {name: digest(source / name) for name in files}
        config = read(ROOT / ".tools/kagura-toolchain.json")
        entries = []
        for filename in ("wide.cpp", "narrow.cpp", "entry.cpp"):
            if dialect == "clangcl":
                compiler = Path(config["clang"]).with_name("clang-cl.exe")
                self.assertTrue(compiler.is_file())
                argv = [str(compiler), "/TP", "/std:c++17", "/MD", "/" + optimization,
                        "/Zc:__cplusplus", "/Fo" + filename + ".obj", "-c", "--", filename]
            else:
                argv = [config["clangxx"], "-std=c++17", "-" + optimization,
                        "-fno-exceptions", "-fno-rtti", "-c", filename, "-o", filename + ".obj"]
            if public_boundary:
                argv.insert(1, ("/D" if dialect == "clangcl" else "-D") + "ANTIREA_PUBLIC_FORWARDER=1")
            entries.append({"directory": str(source), "file": filename, "arguments": argv})
        manifest = {"schema_version": 1, "name": "cpp-namespace-overloads", "language": "cpp",
                    "compile_commands": {"path": "compile_commands.json", "selections": [
                        {"file": name} for name in ("wide.cpp", "narrow.cpp", "entry.cpp")]},
                    "functions": exports, "scope_policy": "protection-policy.json"}
        for name, value in (("compile_commands.json", entries), ("project.json", manifest)):
            with (source / name).open("x", encoding="utf-8") as stream:
                json.dump(value, stream, indent=2)
        service = ProjectService(ROOT)
        plan = service.plan(source / "project.json", seed=2071)
        self.assertEqual(plan["status"], "planned", plan.get("blockers"))
        with (directory / "plan.json").open("x", encoding="utf-8") as stream:
            json.dump(plan, stream, indent=2)
        report = service.build(plan["plan_id"], plan["fingerprint"])
        self.assertEqual(report["status"], "artifact_created_unvalidated", report.get("error"))
        self.assertEqual(report["changed_inputs"], [])
        self.assertEqual(set(report["artifacts"]), {"original_reference", "baseline", "protected"})
        self.assertIs(report["original_reference_provenance"]["uses_protection_normalized_ir"], False)
        mapping, coverage = report["cpp_symbol_mapping"], report["coverage"]
        self.assertEqual(report["coverage_schema_version"], 2)
        self.assertEqual(coverage["schema_version"], 2)
        rows = mapping["functions"]
        self.assertEqual(len(rows), 5)
        self.assertEqual(set(rows), set(coverage["scope_plan"]["selected_functions"]))
        self.assertEqual(set(rows), set(coverage["by_source_symbol"]))
        for source_symbol, row in rows.items():
            actual = coverage["by_source_symbol"][source_symbol]
            self.assertEqual(actual["protected_symbol"], row["protected_symbol"])
            self.assertEqual(actual["stages"], {
                stage: coverage[key][row["protected_symbol"]]
                for stage, key in (("post_vm", "original_vm"), ("diversified", "functions"),
                                   ("final_codegen", "final_vm"))})
        self.assertEqual(rows["public_score"]["protected_symbol"], "public_score")
        helpers = [row for name, row in rows.items() if name != "public_score"]
        # Four actual C++ helpers, not replacements with extern-C fixtures.
        self.assertTrue(all(row["renamed"] is True for row in helpers))
        self.assertEqual(sum(row["signature"]["linkage"] == 0 for row in helpers), 3)
        self.assertEqual(sum(row["signature"]["linkage"] in (8, 9) for row in helpers), 1)
        self.assertEqual(sorted((row["signature"]["return_bits"], row["signature"]["parameter_bits"])
                                for row in helpers),
                         [(32, [32, 32]), (32, [32, 32]), (64, [64, 64]), (64, [64, 64])])
        self.assertTrue(all(row["signature"]["calling_convention"] == 0 for row in helpers))
        targets = {row["protected_symbol"] for row in rows.values()}
        self.assertEqual(len(targets), len(rows))
        for stage in ("original_vm", "functions", "final_vm"):
            self.assertEqual(set(coverage[stage]), targets)
            self.assertTrue(all(row["virtualized"] is True for row in coverage[stage].values()))
        self.assertEqual(report["cpp_symbol_link_evidence"]["status"], "fixed_link_and_exports_verified")
        self.assertEqual(report["cpp_symbol_export_sets"], {
            arm: sorted(exports) for arm in ("original_reference", "baseline", "protected")})
        for command in report["commands"]:
            self.assert_clean(command)
        validation = service.validate(plan["plan_id"], source / "contract.json",
                                      random_cases=8192, timeout_seconds=240)
        self.assertEqual(validation["status"], "functional_samples_passed", validation.get("error"))
        self.assertIs(validation["original_reference_required"], True)
        self.assertEqual(validation["original_reference_provenance"]["link_verification"]["status"],
                         "fixed_recipe_and_trusted_tools_verified")
        self.assertEqual(set(validation["execution"]), {"original_reference", "baseline", "protected"})
        self.assertEqual(validation["behavior_repeats"], 2)
        self.assertIs(validation["inputs_unchanged"], True)
        self.assertIs(validation["boundary_transit_inputs_unchanged"], True)
        transit = validation["boundary_transit"]
        self.assertEqual(transit["coverage_schema_version"], 2)
        self.assertEqual(transit["status"], "verified" if public_boundary else "no_boundaries")
        mapping_check = transit["cpp_symbol_mapping"]
        self.assertEqual(mapping_check["status"], "replayed_and_vm_stages_verified")
        self.assertEqual(mapping_check["source_to_protected"], {
            name: row["protected_symbol"] for name, row in rows.items()})
        watched = transit["evidence_hashes"]
        self.assertTrue(watched)
        for artifact in ("original_ir", "protection_ir", "final_ir", "symbol_mapping"):
            descriptor = report["boundary_transit"][artifact]
            self.assertEqual(watched[descriptor["path"]], descriptor["sha256"])
        self.assertEqual(sorted(coverage["public_boundaries"]), ["public_forward"] if public_boundary else [])
        for boundary in coverage["public_boundaries"].values():
            self.assertIs(boundary["defined"], True)
            self.assertIs(boundary["virtualized"], False)
        if public_boundary:
            self.assertEqual(set(transit["contract"]["functions"]), {"public_forward"})
            source_callee = transit["contract"]["functions"]["public_forward"]["callee"]
            self.assertIn(source_callee, rows)
            self.assertIs(rows[source_callee]["renamed"], True)
        self.assertEqual(set(validation["functions"]), set(exports))
        for export, function in validation["functions"].items():
            self.assertIs(function["deterministic"], True)
            self.assertIs(function["original_reference_match"], True)
            self.assertGreater(validation["cases_per_function"][export], 8192)
            for arm in ("baseline", "protected"):
                comparison = function["original_reference_comparisons"][arm]
                self.assertEqual(comparison["matched"], comparison["total"])
                self.assertEqual(comparison["total"], validation["cases_per_function"][export])
        for command in validation["execution"].values():
            self.assert_clean(command)
        self.assertEqual(source_hashes, {name: digest(source / name) for name in files})
        result = {"status": "passed", "plan_id": plan["plan_id"], "dialect": dialect,
                  "optimization": optimization, "source_hashes": source_hashes,
                  "public_boundary": public_boundary,
                  "build_report": str(ROOT / ".runs/source-protection" / plan["plan_id"] / "build/report.json"),
                  "build_report_sha256": digest(ROOT / ".runs/source-protection" / plan["plan_id"] / "build/report.json"),
                  "validation_id": validation["validation_id"], "cases": validation["cases_per_function"],
                  "behavior_repeats": 2, "whole_cpp_application_support": False,
                  "external_attack_evaluation": "not_evaluated", "published": False}
        with (directory / "cpp-project-e2e.json").open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2)

    def test_gnu_o0_namespace_overloads_and_internal_helper(self):
        self.exercise("O0")

    def test_gnu_o2_namespace_overloads_and_internal_helper(self):
        self.exercise("O2")

    def test_clangcl_o2_namespace_overloads_and_internal_helper(self):
        self.exercise("O2", dialect="clangcl")

    def test_gnu_o2_public_forwarder_calls_mapped_helper(self):
        self.exercise("O2", public_boundary=True)


if __name__ == "__main__":
    unittest.main()
