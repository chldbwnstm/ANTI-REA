"""Validator transport/replay regressions; mock targets and compilers never run.

The real mapper's path/tool/record checks and VM-evidence parsers are exercised;
LLVM renaming itself is a controlled mock here, covered by test_cpp_symbols.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from antirea import cpp_symbols, native_build, native_validate as nv, scope, swift_frontend
import test_native_boundary_validation as boundary_tests
from test_native_boundary_validation import BOUNDARY_CONTRACT, EVIDENCE, digest


SOURCE_A = "?mix@math@@YA_K_K0@Z"
SOURCE_B = "?mix@math@@YA_J_J0@Z"
TARGET_A, TARGET_B = "antirea_cpp_fn_first", "antirea_cpp_fn_second"
ORIGINAL = f'''target triple = "x86_64-pc-windows-msvc"
define i64 @core(i64 %a, i64 %b) {{
  %r = call i64 @"{SOURCE_A}"(i64 %a, i64 %b)
  ret i64 %r
}}
define i64 @"{SOURCE_A}"(i64 %a, i64 %b) {{
  %r = call i64 @"{SOURCE_B}"(i64 %a, i64 %b)
  ret i64 %r
}}
define i64 @"{SOURCE_B}"(i64 %a, i64 %b) {{
  %r = add i64 %a, %b
  ret i64 %r
}}
'''


class CppSymbolValidationTests(unittest.TestCase):
    descriptor = staticmethod(boundary_tests.BoundaryValidationTests.descriptor)
    save_base = boundary_tests.BoundaryValidationTests.save
    fake_worker = boundary_tests.BoundaryValidationTests.fake_worker
    validate = boundary_tests.BoundaryValidationTests.validate

    def save(self):
        # The bootstrap base fixture has no C++ mapping yet.
        if hasattr(self, "mapping_path"):
            self.mapping_path.write_text(json.dumps(self.mapping), encoding="utf-8")
            descriptor = self.descriptor(self.mapping_path)
            self.report["cpp_symbol_mapping_descriptor"] = descriptor
            self.report["coverage"]["symbol_mapping"] = copy.deepcopy(descriptor)
            for transit in (self.report["boundary_transit"], self.report["coverage"]["boundary_transit"]):
                transit["symbol_mapping"] = copy.deepcopy(descriptor)
        self.save_base()

    def setUp(self):
        boundary_tests.BoundaryValidationTests.setUp(self)
        for name in ("llvm-link.exe", "opt.exe", "clang++.exe", "lld-link.exe"):
            (self.library.parent / name).write_bytes(("NONEXECUTABLE TOOL " + name).encode())
        self.config.write_text(json.dumps({"schema_version": 1, "target": cpp_symbols.TARGET,
            "llvm_root": str(self.library.parent.parent), "clangxx": str(self.library.parent / "clang++.exe")}), encoding="utf-8")
        self.original.write_text(ORIGINAL, encoding="utf-8")
        self.protection = self.build / "module.symbol-mapped.ll"
        self.expected_mapped = ORIGINAL.replace('"' + SOURCE_A + '"', TARGET_A).replace('"' + SOURCE_B + '"', TARGET_B).encode()
        self.protection.write_bytes(self.expected_mapped)
        self.raw, self.tu = self.build / "module.raw.ll", self.build / "source-000.ll"
        for path in (self.raw, self.tu):
            path.write_text(ORIGINAL, encoding="utf-8")
        database = {"schema_version": 1, "workspace_root": str(self.root), "status": "normalized_not_built",
                    "translation_units": [{"source": str(self.root / "source/core.cpp"), "entry_sha256": "a" * 64}]}
        database["fingerprint"] = nv._reference_digest(database)
        self.report.update(backend="compile_database_native", compilation_database=database)
        (self.build / "compile-database-plan.json").write_text(json.dumps(database), encoding="utf-8")
        trusted = cpp_symbols._trusted_link_tools(self.root)
        self.trusted = trusted
        self.report["tool_hashes"] = {row["path"]: row["sha256"] for row in [trusted["config"], *trusted["tools"].values()]}
        for module in (cpp_symbols, swift_frontend):
            self.report["tool_hashes"][str(Path(module.__file__).resolve())] = digest(Path(module.__file__))
        linked = self.completed([trusted["tools"]["llvm_link"]["path"], "-S", str(self.tu), "-o", str(self.raw)])
        canonical = self.completed([trusted["tools"]["scope_optimizer"]["path"], "-passes=mem2reg", "-S", str(self.raw), "-o", str(self.original)])
        self.closed = cpp_symbols.make_link_boundary(workspace=self.root, build_dir=self.build, database=database,
            module_paths=[self.tu], raw_ir=self.raw, input_ir=self.original, module_link_record=linked,
            canonicalize_record=canonical, toolchain={key: row["path"] for key, row in trusted["tools"].items()}, exports=["core"])
        self.report["commands"] = [linked, canonical, self.completed(self.closed["protected_link_argv"])]
        self.mapping = {"schema_version": 1, "status": "mapped_not_protected",
            "source_selected_functions": sorted([SOURCE_A, SOURCE_B]),
            "protected_selected_functions": sorted([TARGET_A, TARGET_B]),
            "functions": {SOURCE_A: {"source_symbol": SOURCE_A, "protected_symbol": TARGET_A},
                          SOURCE_B: {"source_symbol": SOURCE_B, "protected_symbol": TARGET_B}},
            "input_sha256": digest(self.original), "output_sha256": digest(self.protection), "link_boundary": self.closed}
        self.mapping_path = self.build / "cpp-symbol-mapping.json"
        self.report["cpp_symbol_mapping"] = self.mapping
        self.vm_ir, self.diversified = self.build / "module.after.ll", self.build / "core.diversified.ll"
        self.vm_ir.write_text(self.vm_text("kagura_vm_execute"), encoding="utf-8", newline="\n")
        self.diversified.write_text(self.vm_text("test_dispatch"), encoding="utf-8", newline="\n")
        self.final.write_bytes(self.diversified.read_bytes())
        (self.build / "diversification.json").write_text(json.dumps({"dispatcher_symbol": "test_dispatch"}), encoding="utf-8")
        (self.build / "exports.def").write_bytes(b"EXPORTS\ncore\n")
        self.expected_contract = copy.deepcopy(BOUNDARY_CONTRACT)
        self.expected_contract["functions"]["core"]["callee"] = SOURCE_A
        self.expected_evidence = copy.deepcopy(EVIDENCE)
        self.expected_evidence["functions"]["core"]["callee"] = TARGET_A
        self.parser_contract.return_value = self.expected_contract
        self.parser_evidence.return_value = self.expected_evidence
        policy = {"core_roots": [SOURCE_A], "public_presentation": {"core": "reviewed forwarder"}}
        self.report["coverage"]["scope_plan"] = scope.analyze_scope([self.original], policy)
        self.assertEqual(self.report["coverage"]["scope_plan"]["status"], "ready")
        self.install_stages()
        self.report["coverage"]["source_selected_functions"] = sorted([SOURCE_A, SOURCE_B])
        transit = {"schema_version": 1, "status": "verified", "contract": self.expected_contract,
            "evidence": self.expected_evidence, "original_ir": self.descriptor(self.original),
            "protection_ir": self.descriptor(self.protection), "business_ir": self.descriptor(self.business),
            "boundary_ir": self.descriptor(self.boundary), "final_ir": self.descriptor(self.final)}
        self.report["boundary_transit"] = transit
        self.report["coverage"]["boundary_transit"] = copy.deepcopy(transit)
        self.report["signature_ir"] = self.descriptor(self.original)
        self.report["cpp_symbol_link_evidence"] = {"status": "fixed_link_and_exports_verified",
            "binary_sha256": self.report["artifacts"]["protected"]["sha256"], "exported_functions": ["core"],
            "complete_application_link": False}
        reference = self.build / "original-reference.dll"
        reference.write_bytes(b"NONEXECUTABLE ORIGINAL REFERENCE")
        self.report["artifacts"]["original_reference"] = self.descriptor(reference)
        reference_ir = self.build / "original-reference-signature.ll"
        reference_ir.write_text(ORIGINAL, encoding="utf-8")
        self.report["original_reference_signature_ir"] = self.descriptor(reference_ir)
        self.remapper = self.enterContext(patch("antirea.cpp_symbols.remap_protection_symbols", side_effect=self.fake_remap))
        self.enterContext(patch("antirea.cpp_symbols.pe_exports", return_value=["core"]))
        self.save()
        self.expected_mapping = copy.deepcopy(self.mapping)

    def completed(self, argv):
        return {"argv": argv, "cwd": str(self.build), "pid": 123, "returncode": 0,
            "timed_out": False, "cancelled": False, "cleanup": {"method": "windows_job",
            "status": "assigned_job_empty", "assignment_timing": "immediately_after_launch", "parent_pid": 123,
            "job_assigned": True, "active_after": 0, "parent_exit_confirmed": True, "job_handle_closed": True}}

    @staticmethod
    def vm_text(dispatcher, targets=(TARGET_A, TARGET_B)):
        return "\n".join(f'''@kagura_vm_bc_{index} = private constant [1 x i8] c"\\01"
define i64 @{name}(i64 %a, i64 %b) {{
  %r = call i64 @{dispatcher}(ptr @kagura_vm_bc_{index}, i32 1)
  ret i64 %r
}}''' for index, name in enumerate(targets))

    def install_stages(self):
        targets = self.mapping["protected_selected_functions"]
        stages = {"post_vm": native_build._vm_evidence(self.vm_ir.read_text(), targets, "kagura_vm_execute"),
                  "diversified": native_build._vm_evidence(self.diversified.read_text(), targets, "test_dispatch"),
                  "final_codegen": native_build._vm_evidence(self.final.read_text(), targets, "test_dispatch")}
        by_source = cpp_symbols.bind_coverage(self.mapping, **stages)
        self.report["coverage"].update(functions=stages["diversified"], original_vm=stages["post_vm"],
            final_vm=stages["final_codegen"], selected_functions=targets, by_source_symbol=by_source)
        self.report["cpp_symbol_coverage"] = copy.deepcopy(by_source)

    def fake_remap(self, data, **kwargs):
        self.assertEqual(kwargs["workspace_root"], self.root)
        self.assertEqual(kwargs["llvm_library"], self.library)
        cpp_symbols._verify_boundary_files(kwargs["link_boundary"], cpp_symbols.digest(data),
            set(kwargs["exported_symbols"]), workspace_root=kwargs["workspace_root"])
        return self.expected_mapped, copy.deepcopy(self.expected_mapping)

    def preflight(self):
        self.watched = {}
        return nv._verify_boundary_transit(self.report, self.report["coverage"], self.root,
            self.build, self.original, self.watched)

    def reject(self, text):
        self.save()
        with self.assertRaisesRegex(ValueError, text):
            self.preflight()
        self.runner.assert_not_called()

    def test_exact_replay_and_all_vm_stages_are_required(self):
        result = self.preflight()
        self.assertEqual(result["cpp_symbol_mapping"]["status"], "replayed_and_vm_stages_verified")
        self.assertEqual(self.remapper.call_args.kwargs["selected_symbols"], sorted([SOURCE_A, SOURCE_B]))
        self.assertEqual(self.parser_evidence.call_args.kwargs["symbol_map"], {SOURCE_A: TARGET_A, SOURCE_B: TARGET_B})
        for name in ("compile-database-plan.json", "cpp-symbol-mapping.json", "source-000.ll", "module.raw.ll",
                     "module.symbol-mapped.ll", "module.after.ll", "core.diversified.ll", "diversification.json", "exports.def"):
            self.assertIn(str(self.build / name), self.watched)

    def test_mapping_markers_cannot_downgrade_to_legacy(self):
        self.report["coverage"]["schema_version"] = 1
        self.report["coverage_schema_version"] = 1
        self.reject("requires native coverage schema 2")

    def test_partial_null_legacy_mapping_marker_is_rejected(self):
        legacy = {"cpp_symbol_mapping": None}
        with self.assertRaisesRegex(ValueError, "schema 2"):
            nv._verify_boundary_transit(legacy, {"schema_version": 1}, self.root, self.build, self.original, {})

    def test_mapping_is_not_accepted_for_another_backend(self):
        self.report["backend"] = "dotnet_il_native"
        self.reject("native compile-database")

    def test_composed_frontend_cannot_hide_mapping(self):
        self.report["native_report"] = str(self.build / "native/report.json")
        self.reject("not a composed")

    def test_two_sources_cannot_merge_into_one_vm(self):
        self.mapping["functions"][SOURCE_B]["protected_symbol"] = TARGET_A
        self.reject("bijection")

    def test_source_scope_cannot_be_silently_reduced(self):
        self.mapping["source_selected_functions"].remove(SOURCE_B)
        self.reject("source mapping set")

    def test_public_names_remain_identity(self):
        self.mapping["functions"]["core"] = {"source_symbol": "core", "protected_symbol": "renamed_public"}
        self.mapping["source_selected_functions"].append("core")
        self.reject("bijection")

    def test_mapping_descriptor_and_sidecar_must_agree(self):
        self.mapping_path.write_text("{}", encoding="utf-8")
        self.report["artifact_hashes"][self.mapping_path.name] = digest(self.mapping_path)
        with self.assertRaisesRegex(ValueError, "artifact hash"):
            self.preflight()

    def test_closed_build_directory_cannot_choose_nested_copy(self):
        self.closed["build_directory"] = str(self.build / "other")
        self.reject("closed-link plan differs")

    def test_same_basename_nested_input_is_rejected(self):
        nested = self.build / "other/module.before.ll"
        nested.parent.mkdir()
        nested.write_bytes(self.original.read_bytes())
        self.closed["input_ir"] = self.descriptor(nested)
        self.reject("not the reviewed original")

    def test_missing_duplicate_or_changed_link_record_is_rejected(self):
        original = copy.deepcopy(self.report["commands"])
        for mode in ("missing", "duplicate", "changed"):
            with self.subTest(mode=mode):
                self.report["commands"] = copy.deepcopy(original)
                if mode == "missing": self.report["commands"].pop(0)
                elif mode == "duplicate": self.report["commands"].append(copy.deepcopy(original[0]))
                else: self.report["commands"][0]["pid"] = 456
                self.reject("unique exact build record")

    def test_unpinned_command_executable_is_rejected(self):
        self.closed["module_link_record"]["argv"][0] = str(self.root / "other.exe")
        self.reject("authored action")

    def test_unverified_cleanup_is_rejected(self):
        self.closed["canonicalize_record"]["cleanup"]["method"] = "taskkill"
        self.reject("cleanup is unverified")

    def test_linker_pin_is_required(self):
        self.report["tool_hashes"].pop(str(self.library.parent / "lld-link.exe"))
        self.reject("original build pins")

    def test_mapping_source_pin_is_required(self):
        self.report["tool_hashes"][str(Path(cpp_symbols.__file__).resolve())] = "0" * 64
        self.reject("mapping/binding source changed")

    def test_rehashed_changed_mapped_ir_is_not_a_valid_replay(self):
        self.protection.write_bytes(self.expected_mapped + b"\n; changed\n")
        self.mapping["output_sha256"] = digest(self.protection)
        for item in (self.report["boundary_transit"], self.report["coverage"]["boundary_transit"]):
            item["protection_ir"] = self.descriptor(self.protection)
        self.reject("cannot be reproduced")

    def test_rehashed_fake_mapping_manifest_is_not_a_valid_replay(self):
        self.mapping["extra_unproven_claim"] = True
        self.reject("cannot be reproduced")

    def test_missing_actual_vm_is_not_hidden_by_coverage_claim(self):
        self.vm_ir.write_text(self.vm_text("kagura_vm_execute", (TARGET_A,)), encoding="utf-8", newline="\n")
        self.reject("missing|definition|exactly one")

    def test_by_source_claim_must_equal_actual_vm_stages(self):
        self.report["coverage"]["by_source_symbol"][SOURCE_A]["protected_symbol"] = TARGET_B
        self.reject("actual recorded VM stages")

    def test_protected_link_record_must_be_unique(self):
        self.report["commands"].append(copy.deepcopy(self.report["commands"][-1]))
        self.reject("exactly one fixed")

    def test_cpp_route_still_requires_original_reference_before_any_worker(self):
        self.report.pop("original_reference_signature_ir")
        self.save()
        with self.assertRaisesRegex(ValueError, "original reference signature"):
            self.validate()
        self.runner.assert_not_called()

    def test_mapping_sidecars_are_watched_during_workers(self):
        # Only the already-tested original-reference provenance gate is mocked;
        # all new mapping consistency checks execute against owned fake files.
        with patch("antirea.native_validate._verify_reference_provenance", return_value={"test_transport": True}):
            self.mutation = lambda: self.tu.write_text("changed in worker", encoding="utf-8")
            result = self.validate()
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["boundary_transit_inputs_unchanged"])
        self.assertEqual(len(self.calls), 1)


if __name__ == "__main__":
    unittest.main()
