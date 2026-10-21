"""Root-authored regressions for inspected direct-project reference binding.

Reuse inert fixtures only. No compiler, LLVM library or target is executed.
"""
import copy
import json
import unittest

import test_native_direct_reference as fixtures
import test_native_validate as database_fixtures


class DirectReferenceBindingTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.DirectCReferenceTests("test_honest_three_arm_direct_reference_passes")
        self.addCleanup(self.f.doCleanups)
        self.f.setUp()

    def test_missing_manifest_or_manifest_pin_is_rejected(self):
        good = copy.deepcopy(self.f.report)
        for field in ("project_path", "manifest_pin"):
            with self.subTest(field=field):
                self.f.report = copy.deepcopy(good)
                project = self.f.report["project"]
                if field == "project_path":
                    project.pop(field)
                else:
                    project["input_hashes"].pop(project["project_path"])
                self.f.assert_preflight_rejects("original reference")

    def test_recorded_project_settings_must_match_manifest(self):
        good = copy.deepcopy(self.f.report)
        for key, value in (("sources", []), ("defines", {"ALTERED": 1}),
                           ("include_dirs", [str(self.f.source_file.parent)])):
            with self.subTest(key=key):
                self.f.report = copy.deepcopy(good)
                self.f.report["project"][key] = value
                self.f.assert_preflight_rejects("original reference")

    def test_manifest_change_during_validation_is_detected(self):
        manifest = self.f.source_file.parent / "project.json"
        def mutate(arm, process):
            if arm == "protected":
                manifest.write_text(manifest.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        self.f.process_mutation = mutate
        result = self.f.validate()
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["inputs_unchanged"])

    def test_forged_report_language_cannot_bypass_bound_native_manifest(self):
        for key in ("original_reference_signature_ir", "original_reference_provenance"):
            self.f.report.pop(key)
        self.f.report["artifacts"].pop("original_reference")
        self.f.report["project"]["language"] = "llvm_ir"
        self.f.assert_preflight_rejects("original reference|project|route")

    def test_consistently_replaced_frontend_is_not_the_trusted_compiler(self):
        replacement = self.f.root / "alternate-clang.exe"
        replacement.write_bytes(b"NONEXECUTABLE ALTERNATE FRONTEND")
        descriptor = self.f.descriptor(replacement)
        provenance = self.f.report["original_reference_provenance"]
        provenance["compiler_inputs"] = {str(replacement): descriptor["sha256"]}
        provenance["translation_units"][0].update(
            compiler=str(replacement), compiler_sha256=descriptor["sha256"])
        self.f.report["tool_hashes"][str(replacement)] = descriptor["sha256"]
        for index in (self.f.object_index, self.f.signature_index):
            self.f.report["commands"][index]["argv"][0] = str(replacement)
        self.f.assert_preflight_rejects("original reference")

    def test_unrelated_abi_matching_signature_is_not_source_compilation_evidence(self):
        unrelated = self.f.build / "unrelated-signature.ll"
        unrelated.write_text(fixtures.IR, encoding="utf-8")
        self.f.report["original_reference_signature_ir"] = self.f.descriptor(unrelated)
        self.f.report["artifact_hashes"][unrelated.name] = self.f.descriptor(unrelated)["sha256"]
        self.f.assert_preflight_rejects("original reference")

    def install_recorded_signature_merge(self):
        merged = self.f.build / "merged-reference.ll"
        merged.write_text(fixtures.IR, encoding="utf-8")
        signature = self.f.report["original_reference_provenance"]["translation_units"][0]["signature_ir_path"]
        tool = str(self.f.root / ".tools/llvm/bin/llvm-link.exe")
        self.f.report["original_reference_signature_ir"] = self.f.descriptor(merged)
        self.f.report["artifact_hashes"][merged.name] = self.f.descriptor(merged)["sha256"]
        self.f.report["commands"].append(self.f.successful_command(
            [tool, "-S", signature, "-o", str(merged)], str(self.f.build)))
        return tool

    def test_recorded_trusted_signature_merge_is_accepted(self):
        self.install_recorded_signature_merge()
        self.f.save_report()
        result = self.f.validate()
        self.assertEqual(result["status"], "functional_samples_passed", result.get("error"))

    def test_signature_merge_requires_exact_inputs_trusted_tool_and_clean_command(self):
        tool = self.install_recorded_signature_merge()
        good = copy.deepcopy(self.f.report)
        for mode in ("extra_input", "missing_tool_pin", "duplicate", "wrong_cwd", "unclean"):
            with self.subTest(mode=mode):
                self.f.report = copy.deepcopy(good)
                record = self.f.report["commands"][-1]
                if mode == "extra_input":
                    record["argv"].insert(2, str(self.f.build / "unrelated.ll"))
                elif mode == "missing_tool_pin":
                    self.f.report["tool_hashes"].pop(tool)
                elif mode == "duplicate":
                    self.f.report["commands"].append(copy.deepcopy(record))
                elif mode == "wrong_cwd":
                    record["cwd"] = str(self.f.root)
                else:
                    record["cleanup"]["active_after"] = 1
                self.f.assert_preflight_rejects("original reference")

    def test_missing_translation_unit_from_manifest_is_rejected(self):
        extra = self.f.source_file.parent / "extra.c"
        extra.write_text("int extra(void){return 1;}\n", encoding="utf-8")
        manifest = self.f.source_file.parent / "project.json"
        value = json.loads(manifest.read_text(encoding="utf-8"))
        value["sources"].append(extra.name)
        manifest.write_text(json.dumps(value), encoding="utf-8")
        project = self.f.report["project"]
        project["sources"].append(str(extra))
        project["source_files"].append(str(extra))
        project["input_hashes"].update({str(extra): self.f.descriptor(extra)["sha256"],
            str(manifest): self.f.descriptor(manifest)["sha256"]})
        self.f.assert_preflight_rejects("original reference")


class DatabaseSignatureBindingTests(unittest.TestCase):
    def test_unrelated_abi_matching_signature_is_not_source_compilation_evidence(self):
        fixture = database_fixtures.CompileDatabaseThreeArmTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        unrelated = fixture.build / "unrelated-signature.ll"
        unrelated.write_text(fixture.ir, encoding="utf-8")
        fixture.report["original_reference_signature_ir"] = fixture.descriptor(unrelated)
        fixture.report["artifact_hashes"][unrelated.name] = fixture.descriptor(unrelated)["sha256"]
        fixture.save_report()
        with self.assertRaisesRegex(ValueError, "original reference"):
            fixture.validate()


class MixedSourceReferenceTests(unittest.TestCase):
    def test_c_translation_unit_inside_cpp_project_preserves_c_recipe(self):
        fixture = fixtures.DirectCppReferenceTests("test_honest_three_arm_direct_reference_passes")
        fixture.source_name = "core.c"
        fixture.compiler_name = "clang.exe"
        fixture.source_text = fixtures.DirectCReferenceTests.source_text
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        result = fixture.validate()
        self.assertEqual(result["status"], "functional_samples_passed", result.get("error"))
        self.assertEqual(result["required_arms"], ["original_reference", "baseline", "protected"])


class ComposedReferenceRouteTests(unittest.TestCase):
    def test_composed_native_half_does_not_require_direct_source_reference(self):
        fixture = fixtures.DirectCReferenceTests("test_honest_three_arm_direct_reference_passes")
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        manifest = fixture.source_file.parent / "project.json"
        manifest.write_text(json.dumps({"schema_version": 1, "name": "jvm-core", "language": "java",
            "sources": ["Core.java"], "methods": []}), encoding="utf-8")
        fixture.report["project"] = {"language": "java", "project_path": str(manifest)}
        fixture.report["backend"] = "jvm_bytecode_native"
        fixture.report.pop("original_reference_signature_ir")
        fixture.report.pop("original_reference_provenance")
        fixture.report["artifacts"].pop("original_reference")
        fixture.save_report()
        # source_validate checks the original JVM separately; this is its native half.
        try:
            result = fixture.validate()
        except ValueError as exc:
            self.fail("legitimate composed native half was rejected: " + str(exc))
        self.assertEqual(result["status"], "functional_samples_passed", result.get("error"))
        self.assertEqual(result["required_arms"], ["baseline", "protected"])
