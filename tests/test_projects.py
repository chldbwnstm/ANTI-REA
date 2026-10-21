"""Source workflow boundaries. Mock compiler calls never execute a target."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from antirea.projects import ProjectService
from antirea.languages import LANGUAGE_IDS, language_catalog
from antirea.defense_mcp import DefenseBridge, TOOLS, validate_arguments


class ProjectWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "owned"
        self.source.mkdir()
        self.project = self.source / "project.json"
        self.project.write_text('{"schema_version":1}', encoding="utf-8")
        self.code = self.source / "core.c"
        self.code.write_text("int core(int x) { return x + 1; }", encoding="utf-8")
        self.tools = self.root / ".tools"
        self.tools.mkdir()
        (self.tools / "kagura-toolchain.json").write_text('{"llvm_version":"22.1.0"}', encoding="utf-8")
        self.service = ProjectService(self.root)
        self.inspect = patch("antirea.projects._inspect", return_value={"language": "c", "blockers": []})
        self.inspect.start()
        self.addCleanup(self.inspect.stop)
        # Tool discovery is not relevant to mocked build-plan invariants.
        self.discovery = patch("antirea.projects.shutil.which", return_value=None)
        self.discovery.start()
        self.addCleanup(self.discovery.stop)

    def successful_builder(self, source, output, **kwargs):
        output.mkdir(parents=True)
        result = {"status": "artifact_created_unvalidated", "artifacts": {}, "coverage": {}}
        (output / "report.json").write_text(json.dumps(result), encoding="utf-8")
        return result

    def test_plan_does_not_run_compiler_and_pins_header_tree(self):
        header = self.source / "headers" / "empty.h"
        header.parent.mkdir()
        header.write_bytes(b"")
        with patch("antirea.projects._build") as build:
            plan = self.service.plan(self.project)
        build.assert_not_called()
        self.assertEqual(plan["status"], "planned")
        self.assertEqual(len(plan["fingerprint"]), 64)
        self.assertIn(str(header), {item["path"] for item in plan["inputs"]})
        self.assertFalse(plan["executes_application"])

    def test_success_requires_fingerprint_and_never_reuses_attempt(self):
        plan = self.service.plan(self.project)
        with patch("antirea.projects._build", side_effect=self.successful_builder) as build:
            result = self.service.build(plan["plan_id"], plan["fingerprint"])
            self.assertEqual(result["status"], "artifact_created_unvalidated")
            self.assertFalse(result["published"])
            self.assertEqual(len(result["build_report_sha256"]), 64)
            self.assertEqual(result["external_attack_evaluation"], "not_evaluated")
            build.assert_called_once()
            with self.assertRaisesRegex(ValueError, "already attempted"):
                self.service.build(plan["plan_id"], plan["fingerprint"])

    def test_replaced_build_report_is_not_revalidated_under_original_plan(self):
        plan = self.service.plan(self.project)
        with patch("antirea.projects._build", side_effect=self.successful_builder):
            self.service.build(plan["plan_id"], plan["fingerprint"])
        report = Path(plan["output_dir"]) / "report.json"
        data = json.loads(report.read_text())
        data["artifacts"] = {"protected": {"path": "replacement.dll"}}
        report.write_text(json.dumps(data), encoding="utf-8")
        with patch("antirea.native_validate.validate_build") as validate:
            with self.assertRaisesRegex(ValueError, "no longer matches"):
                self.service.validate(plan["plan_id"], self.project)
            validate.assert_not_called()

    def test_wrong_fingerprint_and_path_injection_never_compile(self):
        plan = self.service.plan(self.project)
        with patch("antirea.projects._build") as build:
            for plan_id, fingerprint in ((plan["plan_id"], "0" * 64), ("../escape", plan["fingerprint"]),
                                         (plan["plan_id"], "g" * 64)):
                with self.subTest(plan_id=plan_id, fingerprint=fingerprint):
                    with self.assertRaises(ValueError):
                        self.service.build(plan_id, fingerprint)
            build.assert_not_called()

    def test_changed_project_source_or_toolchain_is_rejected(self):
        for path in (self.project, self.code, self.tools / "kagura-toolchain.json"):
            with self.subTest(path=path):
                original = path.read_bytes()
                plan = self.service.plan(self.project)
                path.write_bytes(original + b" ")
                with patch("antirea.projects._build") as build:
                    with self.assertRaisesRegex(ValueError, "changed"):
                        self.service.build(plan["plan_id"], plan["fingerprint"])
                    build.assert_not_called()
                path.write_bytes(original)

    def test_changed_compiler_executable_is_rejected(self):
        compiler = self.tools / "compiler.exe"
        compiler.write_bytes(b"fake compiler fixture")
        (self.tools / "kagura-toolchain.json").write_text(json.dumps({"clang": str(compiler)}), encoding="utf-8")
        plan = self.service.plan(self.project)
        compiler.write_bytes(b"replacement compiler fixture")
        with patch("antirea.projects._build") as build:
            with self.assertRaisesRegex(ValueError, "changed"):
                self.service.build(plan["plan_id"], plan["fingerprint"])
            build.assert_not_called()

    def test_changed_kagura_generator_source_is_rejected_before_build(self):
        upstream = self.tools / "kagura"
        runtime = upstream / "runtime/core/vm_interpreter.c"
        opcodes = upstream / "include/kagura/VMOpcodes.def"
        for path in (runtime, opcodes):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"owned mock upstream source")
        (self.tools / "kagura-toolchain.json").write_text(
            json.dumps({"kagura_source": str(upstream)}), encoding="utf-8")
        for name, path in (("runtime_source", runtime), ("opcode_source", opcodes)):
            with self.subTest(name=name):
                original = path.read_bytes()
                plan = self.service.plan(self.project)
                self.assertEqual(plan["toolchain"]["tools"][name]["path"], str(path))
                self.assertEqual(len(plan["toolchain"]["tools"][name]["sha256"]), 64)
                path.write_bytes(original + b" changed after planning")
                with patch("antirea.projects._build") as build:
                    with self.assertRaisesRegex(ValueError, "changed"):
                        self.service.build(plan["plan_id"], plan["fingerprint"])
                    build.assert_not_called()
                path.write_bytes(original)

    def test_llvm_c_parser_is_pinned_before_native_build(self):
        llvm_root = self.tools / "llvm"
        binary = llvm_root / "bin"
        binary.mkdir(parents=True)
        for name in ("llvm-link.exe", "opt.exe", "LLVM-C.dll", "lld-link.exe"):
            (binary / name).write_bytes(b"owned inert LLVM tool fixture")
        (self.tools / "kagura-toolchain.json").write_text(
            json.dumps({"llvm_root": str(llvm_root)}), encoding="utf-8")
        plan = self.service.plan(self.project)
        parser = binary / "LLVM-C.dll"
        self.assertEqual(plan["toolchain"]["tools"]["llvm_c"]["path"], str(parser))
        parser.write_bytes(b"changed inert parser fixture")
        with patch("antirea.projects._build") as build:
            with self.assertRaisesRegex(ValueError, "changed"):
                self.service.build(plan["plan_id"], plan["fingerprint"])
            build.assert_not_called()

    def test_lld_link_is_pinned_before_native_build(self):
        llvm_root = self.tools / "llvm"
        binary = llvm_root / "bin"
        binary.mkdir(parents=True)
        for name in ("llvm-link.exe", "opt.exe", "LLVM-C.dll", "lld-link.exe"):
            (binary / name).write_bytes(b"owned inert LLVM tool fixture")
        (self.tools / "kagura-toolchain.json").write_text(
            json.dumps({"llvm_root": str(llvm_root)}), encoding="utf-8")
        plan = self.service.plan(self.project)
        linker = binary / "lld-link.exe"
        self.assertEqual(plan["toolchain"]["tools"]["lld_link"]["path"], str(linker))
        linker.write_bytes(b"changed inert linker fixture")
        with patch("antirea.projects._build") as build:
            with self.assertRaisesRegex(ValueError, "changed"):
                self.service.build(plan["plan_id"], plan["fingerprint"])
            build.assert_not_called()

    def test_new_header_after_plan_invalidates_snapshot(self):
        plan = self.service.plan(self.project)
        (self.source / "new.h").write_text("#define X 42", encoding="utf-8")
        with patch("antirea.projects._build") as build:
            with self.assertRaisesRegex(ValueError, "changed"):
                self.service.build(plan["plan_id"], plan["fingerprint"])
            build.assert_not_called()

    def test_trusted_tool_hardlink_is_hashed_but_source_hardlink_rejected(self):
        compiler = self.tools / "compiler.exe"
        compiler.write_bytes(b"fake installed tool")
        alias = self.tools / "tool-alias.exe"
        os.link(compiler, alias)
        (self.tools / "kagura-toolchain.json").write_text(json.dumps({"clang": str(alias)}), encoding="utf-8")
        plan = self.service.plan(self.project)
        self.assertEqual(plan["toolchain"]["tools"]["clang"]["hardlink_count"], 2)
        os.link(self.code, self.source / "source-alias.c")
        with self.assertRaisesRegex(ValueError, "hard-linked"):
            self.service.plan(self.project)

    def test_input_changed_during_compiler_is_not_success(self):
        plan = self.service.plan(self.project)
        def mutate(*args, **kwargs):
            self.code.write_text("changed during build", encoding="utf-8")
            return {"status": "artifact_created_unvalidated"}
        with patch("antirea.projects._build", side_effect=mutate):
            result = self.service.build(plan["plan_id"], plan["fingerprint"])
        self.assertEqual(result["status"], "original_input_changed")

    def test_stop_prevents_compiler_execution(self):
        plan = self.service.plan(self.project)
        stop = self.root / ".runs" / "defense-loop" / "STOP"
        stop.parent.mkdir(parents=True)
        stop.touch()
        with patch("antirea.projects._build") as build:
            result = self.service.build(plan["plan_id"], plan["fingerprint"])
        build.assert_not_called()
        self.assertEqual(result["status"], "cancelled")

    def test_failed_build_is_audited_and_not_retried(self):
        plan = self.service.plan(self.project)
        with patch("antirea.projects._build", side_effect=RuntimeError("compiler failed")):
            result = self.service.build(plan["plan_id"], plan["fingerprint"])
        self.assertEqual(result["status"], "failed")
        self.assertIn("compiler failed", result["error"])
        with self.assertRaisesRegex(ValueError, "already attempted"):
            self.service.build(plan["plan_id"], plan["fingerprint"])

    def test_unavailable_toolchain_creates_blocked_plan(self):
        (self.tools / "kagura-toolchain.json").unlink()
        plan = self.service.plan(self.project)
        self.assertEqual(plan["status"], "blocked")
        self.assertIn("native_toolchain_not_configured", plan["blockers"])
        with self.assertRaisesRegex(ValueError, "blockers"):
            self.service.build(plan["plan_id"], plan["fingerprint"])

    def test_python_plan_does_not_require_a_native_toolchain(self):
        (self.tools / "kagura-toolchain.json").unlink()
        with patch("antirea.projects._inspect", return_value={"language": "python", "blockers": []}):
            plan = self.service.plan(self.project)
        self.assertEqual(plan["status"], "planned")
        self.assertEqual(plan["kind"], "python_source_build")
        self.assertFalse(plan["executes_compilers"])
        self.assertFalse(plan["toolchain"]["native_toolchain_required"])
        self.assertIn("python_executable", plan["toolchain"]["tools"])

    def test_javascript_and_typescript_plan_do_not_require_kagura(self):
        (self.tools / "kagura-toolchain.json").unlink()
        for language in ("javascript", "typescript"):
            with self.subTest(language=language), patch("antirea.projects._inspect",
                    return_value={"language": language, "blockers": []}):
                plan = self.service.plan(self.project)
            self.assertEqual(plan["status"], "planned")
            self.assertEqual(plan["kind"], "javascript_source_build")
            self.assertFalse(plan["toolchain"]["native_toolchain_required"])

    def test_lowered_backends_require_original_reference_validator(self):
        for backend in ("dotnet_il_native", "jvm_bytecode_native"):
            with self.subTest(backend=backend):
                plan = self.service.plan(self.project)
                def builder(source, output, **kwargs):
                    result = self.successful_builder(source, output, **kwargs)
                    result["backend"] = backend
                    (output / "report.json").write_text(json.dumps(result), encoding="utf-8")
                    return result
                with patch("antirea.projects._build", side_effect=builder):
                    self.service.build(plan["plan_id"], plan["fingerprint"])
                with patch("antirea.source_validate.validate_lowered_build",
                           return_value={"status": "functional_samples_passed"}) as validator:
                    result = self.service.validate(plan["plan_id"], self.project, random_cases=9)
                self.assertEqual(result["status"], "functional_samples_passed")
                self.assertEqual(validator.call_args.kwargs["random_cases"], 9)

    def test_frontend_compiler_input_hash_is_part_of_plan(self):
        import hashlib
        compiler = self.tools / "csc.dll"
        compiler.write_bytes(b"owned compiler fixture")
        inspection = {"language": "csharp", "blockers": [],
                      "compiler_inputs": {str(compiler): hashlib.sha256(compiler.read_bytes()).hexdigest()}}
        with patch("antirea.projects._inspect", return_value=inspection):
            plan = self.service.plan(self.project)
            compiler.write_bytes(b"changed compiler fixture")
            with patch("antirea.projects._build") as build:
                with self.assertRaisesRegex(ValueError, "changed"):
                    self.service.build(plan["plan_id"], plan["fingerprint"])
                build.assert_not_called()

    def test_changed_inspection_route_is_rejected_before_build(self):
        plan = self.service.plan(self.project)
        with patch("antirea.projects._inspect", return_value={"language": "python", "blockers": []}), \
                patch("antirea.projects._build") as build:
            with self.assertRaisesRegex(ValueError, "changed"):
                self.service.build(plan["plan_id"], plan["fingerprint"])
            build.assert_not_called()

    def test_python_result_routes_to_separate_sampling_validator(self):
        plan = self.service.plan(self.project)
        def builder(source, output, **kwargs):
            result = self.successful_builder(source, output, **kwargs)
            result["backend"] = "python_vm"
            (output / "report.json").write_text(json.dumps(result), encoding="utf-8")
            return result
        with patch("antirea.projects._build", side_effect=builder):
            self.service.build(plan["plan_id"], plan["fingerprint"])
        with patch("antirea.python_validate.validate_build", return_value={"status": "functional_samples_passed"}) as validate:
            result = self.service.validate(plan["plan_id"], self.project, random_cases=7)
            self.assertEqual(result["status"], "functional_samples_passed")
            self.assertEqual(validate.call_args.kwargs["random_cases"], 7)

    def test_unimplemented_language_never_becomes_ready(self):
        with patch("antirea.projects._inspect", return_value={"language": "swift", "blockers": ["route_not_implemented"]}):
            plan = self.service.plan(self.project)
        self.assertEqual(plan["status"], "blocked")

    def test_untrusted_and_outside_and_root_manifests_are_rejected(self):
        paths = [self.root / "rea-analysis-reports" / "project.json",
                 self.root / ".runs" / "defense-loop" / "inbox" / "project.json",
                 self.root / ".runs" / "source-protection" / "project.json",
                 self.root / "attackerfolder" / "project.json",
                 self.root.parent / "outside.json", self.root / "project.json"]
        for path in paths:
            with self.subTest(path=path):
                if path == self.root / "project.json":
                    path.write_text("{}", encoding="utf-8")
                with self.assertRaises((ValueError, OSError)):
                    self.service.plan(path)

    def test_invalid_seeds_rejected(self):
        for seed in (True, 0, -1, 2**31, 1.0, "1"):
            with self.subTest(seed=seed), self.assertRaises(ValueError):
                self.service.plan(self.project, seed=seed)

    def test_output_json_cannot_be_overwritten(self):
        from antirea.projects import _create_json
        path = self.source / "audit.json"
        _create_json(path, {"first": True})
        with self.assertRaises(FileExistsError):
            _create_json(path, {"first": False})
        self.assertTrue(json.loads(path.read_text())["first"])

    def test_tree_entry_budget_includes_directories(self):
        (self.source / "one").mkdir()
        (self.source / "two").mkdir()
        with patch("antirea.projects.MAX_PROJECT_FILES", 2):
            with self.assertRaisesRegex(ValueError, "entry limit"):
                self.service.plan(self.project)

    def test_symlink_inside_project_is_not_followed(self):
        path = self.source / "alias.c"
        try:
            path.symlink_to(self.code)
        except OSError:
            self.skipTest("symlink creation unavailable")
        with self.assertRaisesRegex(ValueError, "symlink|reparse"):
            self.service.plan(self.project)


class LanguageCatalogTests(unittest.TestCase):
    def test_all_requested_languages_are_distinct_and_honest(self):
        result = language_catalog()
        self.assertEqual([item["id"] for item in result["languages"]], list(LANGUAGE_IDS))
        for item in result["languages"]:
            self.assertFalse(item["source_protection"]["whole_language_verified"])
            self.assertFalse(item["tool_discovery"]["executed"])
        for language, route in (("python", "python_vm"), ("csharp", "dotnet_il_native"),
                                ("java", "jvm_bytecode_native"), ("kotlin", "jvm_bytecode_native"),
                                ("go", "go_typed_native"), ("swift", "swift_llvm_native"),
                                ("javascript", "javascript_vm"), ("typescript", "javascript_vm")):
            protection = language_catalog(language)["languages"][0]["source_protection"]
            self.assertEqual(protection["status"], "experimental")
            self.assertEqual(protection["route"], route)
            self.assertFalse(protection["whole_language_verified"])
        self.assertEqual(result["macos_validation"], "not_performed")

    def test_unknown_language_rejected(self):
        with self.assertRaises(ValueError):
            language_catalog("pretend_supported")

    def test_mcp_routes_source_tools_without_commercial_provider(self):
        class SourceService:
            def plan(self, path, *, seed):
                return {"kind": "plan", "path": path, "seed": seed}
            def build(self, plan_id, fingerprint):
                return {"kind": "build", "plan_id": plan_id}
            def bindings(self, path):
                return {"kind": "bindings", "path": path}
        bridge = DefenseBridge(object(), SourceService())
        self.assertEqual(bridge.call("protection_source_plan", {"project_path": "owned/project.json"})["seed"], 1729)
        self.assertEqual(bridge.call("protection_source_build", {"plan_id": "id", "fingerprint": "a" * 64})["kind"], "build")
        self.assertEqual(bridge.call("protection_bindings", {"contract_path": "contract.json"})["kind"], "bindings")
        self.assertEqual(len(bridge.call("protection_languages", {})["languages"]), 11)

    def test_mcp_source_arguments_are_closed(self):
        for name, args in (("protection_source_plan", {"project_path": "x", "seed": True}),
                           ("protection_source_build", {"plan_id": "x", "fingerprint": "bad"}),
                           ("protection_bindings", {"contract_path": "x", "execute": True}),
                           ("protection_languages", {"language": "unknown"})):
            tool = next(item for item in TOOLS if item["name"] == name)
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_arguments(tool, args)


if __name__ == "__main__":
    unittest.main()
