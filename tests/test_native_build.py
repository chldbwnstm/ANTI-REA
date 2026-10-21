import json
import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from antirea import native_build as nb


class NativeProjectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.project = self.root / "project.json"
        (self.root / "core.c").write_text("int f(int x) { return x + 1; }", encoding="utf-8")
        self.value = {"schema_version": 1, "name": "native-example", "language": "c",
                      "sources": ["core.c"], "functions": ["f"]}
        self.save()

    def tearDown(self):
        self.temp.cleanup()

    def save(self):
        self.project.write_text(json.dumps(self.value), encoding="utf-8")

    def test_inspect_normalizes_and_hashes_without_execution(self):
        with patch.object(nb, "run_logged", side_effect=AssertionError("must not run")):
            info = nb.inspect_project(self.project)
        self.assertEqual(info["route_status"], "available")
        self.assertEqual(info["sources"], [str(self.root / "core.c")])
        self.assertEqual(set(info["input_hashes"]), {str(self.project), str(self.root / "core.c")})
        self.assertEqual(info["target"], nb.TARGET)

    def test_unknown_fields_rejected(self):
        self.value["pre_build"] = "echo unsafe"
        self.save()
        with self.assertRaisesRegex(nb.NativeBuildError, "Unknown"):
            nb.inspect_project(self.project)

    def test_duplicate_json_rejected(self):
        self.project.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaisesRegex(nb.NativeBuildError, "Duplicate JSON"):
            nb.inspect_project(self.project)

    def test_path_escapes_rejected(self):
        for value in ("../core.c", "C:/elsewhere/core.c", "/core.c", "core.c:stream"):
            with self.subTest(value=value):
                self.value["sources"] = [value]
                self.save()
                with self.assertRaises(nb.NativeBuildError):
                    nb.inspect_project(self.project)

    def test_function_patterns_and_duplicates_rejected(self):
        for functions in (["f*"], ["f", "f"], ["kagura_f"], ["f,g"], []):
            with self.subTest(functions=functions):
                self.value["functions"] = functions
                self.save()
                with self.assertRaises(nb.NativeBuildError):
                    nb.inspect_project(self.project)

    def test_bad_defines_rejected(self):
        for defines in ({"OK": "bad\nline"}, {"BAD-NAME": 1}, {"OK": True}, ["-DOK"]):
            self.value["defines"] = defines
            self.save()
            with self.assertRaises(nb.NativeBuildError):
                nb.inspect_project(self.project)

    def test_target_and_artifact_explicit_blockers(self):
        self.value.update(target="aarch64-apple-darwin", artifact="executable")
        self.save()
        info = nb.inspect_project(self.project)
        self.assertEqual(info["route_status"], "unsupported")
        self.assertEqual(len(info["blockers"]), 2)

    def test_swift_is_not_claimed_supported(self):
        (self.root / "core.swift").write_text("// source")
        self.value.update(language="swift", sources=["core.swift"])
        self.save()
        info = nb.inspect_project(self.project)
        self.assertEqual(info["route_status"], "unsupported")

    def test_rust_is_experimental_and_no_cargo_hook(self):
        (self.root / "core.rs").write_text("#![no_std]")
        self.value.update(language="rust", sources=["core.rs"])
        self.save()
        self.assertTrue(nb.inspect_project(self.project)["experimental"])
        self.value["cargo"] = ["build"]
        self.save()
        with self.assertRaises(nb.NativeBuildError):
            nb.inspect_project(self.project)

    def test_snapshot_includes_headers(self):
        (self.root / "value.h").write_text("#define VALUE 2")
        self.assertIn(str(self.root / "value.h"), nb.inspect_project(self.project)["input_hashes"])

    def test_scope_policy_is_owned_hashed_and_not_analyzed_during_inspection(self):
        policy = self.root / "policy.json"
        policy.write_text('{"core_roots":["f"]}')
        self.value["scope_policy"] = "policy.json"
        self.save()
        with patch.object(nb.scope, "analyze_scope", side_effect=AssertionError("IR requires explicit compilation")):
            info = nb.inspect_project(self.project)
        self.assertEqual(info["scope_mode"], "expanded")
        self.assertEqual(info["scope_policy_sha256"], info["input_hashes"][str(policy)])
        self.assertEqual(info["functions"], info["exported_functions"])

    def test_scope_policy_escape_and_missing_file_are_rejected(self):
        for value in ("../policy.json", "C:/elsewhere/policy.json", "missing.json", None):
            self.value["scope_policy"] = value
            self.save()
            with self.subTest(value=value), self.assertRaises(nb.NativeBuildError):
                nb.inspect_project(self.project)

    def test_scope_policy_duplicate_json_is_rejected(self):
        (self.root / "policy.json").write_text('{"core_roots":["f"],"core_roots":[]}')
        self.value["scope_policy"] = "policy.json"
        self.save()
        with self.assertRaisesRegex(nb.NativeBuildError, "Duplicate"):
            nb.inspect_project(self.project)

    def test_scope_policy_hardlink_is_rejected(self):
        original = self.root / "original.json"
        original.write_text('{"core_roots":["f"]}')
        os.link(original, self.root / "policy.json")
        self.value["scope_policy"] = "policy.json"
        self.save()
        with self.assertRaisesRegex(nb.NativeBuildError, "hard-linked"):
            nb.inspect_project(self.project)

    def test_symlink_rejected_if_supported(self):
        try:
            (self.root / "link.c").symlink_to(self.root / "core.c")
        except OSError:
            self.skipTest("symlink privilege unavailable")
        with self.assertRaisesRegex(nb.NativeBuildError, "Links"):
            nb.inspect_project(self.project)

    def test_no_source_rewrite(self):
        original = (self.root / "core.c").read_bytes()
        nb.inspect_project(self.project)
        self.assertEqual((self.root / "core.c").read_bytes(), original)

    def test_wrong_schema_and_types_rejected(self):
        for key, value in (("schema_version", True), ("language", []), ("target", {}),
                           ("artifact", 7), ("sources", "core.c"), ("include_dirs", "include")):
            original = self.value.copy()
            with self.subTest(key=key):
                self.value[key] = value
                self.save()
                with self.assertRaises(nb.NativeBuildError):
                    nb.inspect_project(self.project)
            self.value = original

    def test_mismatched_extension_rejected(self):
        self.value["language"] = "rust"
        self.save()
        with self.assertRaisesRegex(nb.NativeBuildError, "extension"):
            nb.inspect_project(self.project)

    def test_input_caps_fail_closed(self):
        with patch.object(nb, "MAX_INPUT_BYTES", 2):
            with self.assertRaisesRegex(nb.NativeBuildError, "64 MiB"):
                nb.inspect_project(self.project)

    def test_cli_inspect_outputs_json(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = nb.main(["inspect", "--project", str(self.project)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["functions"], ["f"])

    @unittest.skipUnless(os.name == "nt", "Windows build preflight")
    def test_build_refuses_existing_output_without_tools(self):
        with tempfile.TemporaryDirectory() as workspace_value:
            workspace = Path(workspace_value)
            output = workspace / ".runs" / "existing"
            output.mkdir(parents=True)
            with patch.object(nb, "_toolchain", side_effect=AssertionError("must not inspect tools")):
                with self.assertRaisesRegex(nb.NativeBuildError, "fresh"):
                    nb.build_project(self.project, output, workspace_root=workspace)

    @unittest.skipUnless(os.name == "nt", "Windows build preflight")
    def test_build_refuses_output_outside_runs(self):
        with tempfile.TemporaryDirectory() as workspace_value:
            workspace = Path(workspace_value)
            with self.assertRaisesRegex(nb.NativeBuildError, "descendant"):
                nb.build_project(self.project, workspace / "output", workspace_root=workspace)

    @unittest.skipUnless(os.name == "nt", "Windows build preflight")
    def test_stop_marker_blocks_without_creating_output(self):
        with tempfile.TemporaryDirectory() as workspace_value:
            workspace = Path(workspace_value)
            marker = workspace / ".runs/defense-loop/STOP"
            marker.parent.mkdir(parents=True)
            marker.write_text("stop")
            output = workspace / ".runs/new"
            with patch.object(nb, "_toolchain", return_value=({}, {})):
                with self.assertRaisesRegex(nb.NativeBuildError, "STOP"):
                    nb.build_project(self.project, output, workspace_root=workspace)
            self.assertFalse(output.exists())

    @unittest.skipUnless(os.name == "nt", "Windows build failure record")
    def test_post_creation_failure_is_recorded_without_stdout(self):
        with tempfile.TemporaryDirectory() as workspace_value:
            workspace = Path(workspace_value)
            output = workspace / ".runs/failed"
            stream = io.StringIO()
            with patch.object(nb, "_toolchain", return_value=({}, {})), \
                    patch.object(nb.shutil, "which", return_value=None), \
                    contextlib.redirect_stdout(stream):
                report = nb.build_project(self.project, output, workspace_root=workspace)
            self.assertEqual(stream.getvalue(), "")
            self.assertEqual(report["status"], "failed")
            self.assertEqual(json.loads((output / "report.json").read_text())["status"], "failed")
            self.assertEqual(report["functional_evaluation"], "not_performed")


class CoverageTests(unittest.TestCase):
    def ir(self, call="kagura_vm_execute", size=2):
        return ('@kagura_vm_bc_7 = private constant [2 x i8] c"\\01\\02"\n'
                'define i64 @f(i32 %x) {\n'
                f'  %v = call i64 @{call}(ptr @kagura_vm_bc_7, i32 {size}, ptr null)\n'
                '  ret i64 %v\n}\n')

    def test_actual_vm_call_and_blob_required(self):
        evidence = nb._vm_evidence(self.ir(), ["f"], "kagura_vm_execute")
        self.assertTrue(evidence["f"]["virtualized"])
        self.assertEqual(evidence["f"]["bytecode_size"], 2)

    def test_final_codegen_nonnull_blob_attribute_is_supported(self):
        ir = self.ir().replace("(ptr @kagura_vm_bc_7", "(ptr nonnull @kagura_vm_bc_7")
        self.assertTrue(nb._vm_evidence(ir, ["f"], "kagura_vm_execute")["f"]["virtualized"])

    def test_unvirtualized_and_wrong_blob_fail_closed(self):
        for ir in (self.ir(call="other"), self.ir(size=3), self.ir().replace('\\01\\02', '\\01')):
            with self.assertRaises(nb.NativeBuildError):
                nb._vm_evidence(ir, ["f"], "kagura_vm_execute")

    def test_extra_vm_protection_outside_selection_rejected(self):
        ir = self.ir() + '@kagura_vm_bc_8 = private constant [1 x i8] c"\\01"\n'
        with self.assertRaisesRegex(nb.NativeBuildError, "outside"):
            nb._vm_evidence(ir, ["f"], "kagura_vm_execute")

    def test_private_or_missing_symbol_rejected(self):
        with self.assertRaises(nb.NativeBuildError):
            nb._body(self.ir().replace("define i64", "define internal i64"), "f")
        with self.assertRaises(nb.NativeBuildError):
            nb._body(self.ir(), "missing")

    def test_simple_function_pass_noop_is_not_faked(self):
        evidence = nb._layer_evidence(self.ir(), "f")
        self.assertFalse(evidence["fla_dispatcher"])
        self.assertEqual(evidence["substitution_instructions"], 0)

    def test_multi_binding_requires_complete_selected_scope(self):
        manifest = {"engine_mode": "per_function_indirect"}
        with patch.object(nb.diversify, "inspect_vm_bindings", return_value={"f": {"virtualized": True}}):
            self.assertEqual(set(nb._manifest_vm_evidence("ir", ["f"], manifest)), {"f"})
            with self.assertRaisesRegex(nb.NativeBuildError, "complete selected scope"):
                nb._manifest_vm_evidence("ir", ["f", "helper"], manifest)
        with patch.object(nb.diversify, "inspect_vm_bindings", side_effect=ValueError("slot changed")):
            with self.assertRaisesRegex(nb.NativeBuildError, "slot changed"):
                nb._manifest_vm_evidence("ir", ["f"], manifest)

    def test_every_runtime_requires_all_three_transformations(self):
        names = ["antirea_dispatch_0000000000000001", "antirea_dispatch_0000000000000002"]
        passed = {"fla_dispatcher": True, "substitution_instructions": 2, "constant_obfuscation_instructions": 3}
        with patch.object(nb, "_layer_evidence", return_value=passed):
            result = nb._runtime_evidence("ir", names)
        self.assertEqual(result["engine_count"], 2)
        self.assertEqual(result["substitution_instructions"], 4)
        self.assertEqual(set(result["engines"]), set(names))
        for key in passed:
            with self.subTest(key=key), patch.object(nb, "_layer_evidence", side_effect=[passed, {**passed, key: 0}]):
                with self.assertRaisesRegex(nb.NativeBuildError, "runtime lacks"):
                    nb._runtime_evidence("ir", names)
        with self.assertRaisesRegex(nb.NativeBuildError, "duplicate"):
            nb._runtime_evidence("ir", [names[0], names[0]])

    def test_public_boundary_cannot_load_secondary_vm_slot(self):
        ir = 'define i64 @public(i32 %x) {\n  %p = load volatile ptr, ptr @secondary_slot\n  ret i64 0\n}\n'
        with self.assertRaisesRegex(nb.NativeBuildError, "boundary unexpectedly"):
            nb._boundary_evidence(ir, ["public"], ["first", "second"], ["secondary_slot"])


class PrivateLLVMHandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.ir = self.root / ".runs/frontend/module.ll"
        self.ir.parent.mkdir(parents=True)
        self.ir.write_text('define i32 @f(i32 %x) {\n ret i32 %x\n}\n')
        self.inputs = {str(self.ir): nb._hash(self.ir)}

    def tearDown(self):
        self.temp.cleanup()

    def handoff(self, **kwargs):
        args = {"workspace_root": self.root, "name": "swift-owned", "selected_functions": ["f", "helper"],
                "exported_functions": ["f"], "input_hashes": self.inputs}
        args.update(kwargs)
        return nb.build_llvm_project(self.ir, self.root / ".runs/native", **args)

    def test_owned_hashed_handoff_preserves_full_selection(self):
        with patch.object(nb, "_build_project", return_value={"status": "mock"}) as build:
            self.handoff()
        project = build.call_args.args[0]
        self.assertEqual(project["language"], "llvm_ir")
        selected = nb._select_scope(project, self.ir, self.ir)
        self.assertEqual(selected["selected_functions"], ["f", "helper"])
        self.assertEqual(selected["exported_functions"], ["f"])

    def test_changed_or_missing_ir_hash_rejected_before_build(self):
        for hashes in ({}, {str(self.ir): "0" * 64}):
            with self.subTest(hashes=hashes), patch.object(nb, "_build_project", side_effect=AssertionError("must not build")):
                with self.assertRaises(nb.NativeBuildError):
                    self.handoff(input_hashes=hashes)

    def test_unselected_exports_and_reserved_symbols_rejected(self):
        for selection, exports in ((["f"], ["other"]), (["f", "f"], ["f"]), (["kagura_f"], ["kagura_f"])):
            with self.subTest(selection=selection), self.assertRaises(nb.NativeBuildError):
                self.handoff(selected_functions=selection, exported_functions=exports)

    def test_public_source_manifest_cannot_select_private_ir_backend(self):
        project = self.ir.parent / "project.json"
        project.write_text(json.dumps({"schema_version": 1, "name": "private", "language": "llvm_ir",
                                       "sources": ["module.ll"], "functions": ["f"]}))
        with self.assertRaisesRegex(nb.NativeBuildError, "language"):
            nb.inspect_project(project)


if __name__ == "__main__":
    unittest.main()
