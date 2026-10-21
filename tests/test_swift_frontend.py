"""Swift source route unit tests; native parser availability is explicit."""
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch

from antirea.swift_frontend import SwiftFrontendError, build_project, inspect_project, normalize_llvm, parse_public_interface, verify_build, _hash, _read_report


ROOT = Path(__file__).resolve().parents[1]
LLVM = ROOT / ".tools/clang+llvm-22.1.0-x86_64-pc-windows-msvc/bin/LLVM-C.dll"
HEADER = 'target triple = "x86_64-pc-windows-msvc"\n'
PURE = HEADER + '''
define dllexport i64 @swift_score(i64 %x, i64 %y) {
entry:
  %a = call swiftcc i64 @"$s8Original3mixys6UInt64VAD_ADtF"(i64 %x, i64 %y)
  %b = xor i64 %a, 23
  ret i64 %b
}
define swiftcc i64 @"$s8Original3mixys6UInt64VAD_ADtF"(i64 %x, i64 %y) {
entry:
  %a = add i64 %x, %y
  %b = mul i64 %a, 33
  ret i64 %b
}
define dllexport swiftcc i64 @unused_plaintext_copy(i64 %x) {
entry:
  %b = xor i64 %x, 31337
  ret i64 %b
}
'''


@unittest.skipUnless(LLVM.is_file(), "pinned LLVM-C parser unavailable")
class LLVMNormalizationTests(unittest.TestCase):
    def normalize(self, text=PURE):
        return normalize_llvm(text, ["swift_score"], llvm_library=LLVM)

    def test_real_parser_normalizes_entire_helper_graph(self):
        result, evidence = self.normalize()
        self.assertEqual(evidence["status"], "normalized_closed_integer_graph")
        self.assertEqual(len(evidence["selected_functions"]), 2)
        self.assertIn("swift_score", evidence["selected_functions"])
        self.assertNotIn("swiftcc", result)
        self.assertNotIn("unused_plaintext_copy", result)
        self.assertNotIn("31337", result)
        self.assertFalse(evidence["arithmetic_rewritten"])
        self.assertIn("add i64 %x, %y", result)
        self.assertIn("define hidden i64 @antirea_swift_helper_", result)
        self.assertEqual(evidence["functions"]["swift_score"]["parameter_bits"], [64, 64])

    def test_removes_compiler_retention_of_unselected_duplicates(self):
        source = PURE + '@llvm.used = appending global [2 x ptr] [ptr @swift_score, ptr @unused_plaintext_copy], section "llvm.metadata"\n'
        result, evidence = self.normalize(source)
        self.assertNotIn("@llvm.used", result)
        self.assertNotIn("unused_plaintext_copy", result)

    def test_parser_rejects_malformed_ir(self):
        with self.assertRaisesRegex(SwiftFrontendError, "parser rejected"):
            self.normalize(HEADER + "define i64 @swift_score( { nonsense")

    def test_rejects_wrong_target_and_missing_export(self):
        with self.assertRaisesRegex(SwiftFrontendError, "target"):
            self.normalize(PURE.replace("x86_64-pc-windows-msvc", "aarch64-apple-macosx"))
        with self.assertRaisesRegex(SwiftFrontendError, "missing"):
            self.normalize(PURE.replace("@swift_score", "@other_score"))

    def test_rejects_swiftcc_public_entry(self):
        with self.assertRaisesRegex(SwiftFrontendError, "C ABI"):
            self.normalize(PURE.replace("define dllexport i64 @swift_score", "define dllexport swiftcc i64 @swift_score"))

    def test_rejects_recursive_helpers(self):
        text = HEADER + '''
define i64 @swift_score(i64 %x) {
  %a = call i64 @swift_score(i64 %x)
  ret i64 %a
}
'''
        with self.assertRaisesRegex(SwiftFrontendError, "Recursive"):
            self.normalize(text)

    def test_rejects_checked_overflow_without_rewriting_to_wrap(self):
        text = HEADER + '''
declare {i64, i1} @llvm.sadd.with.overflow.i64(i64, i64)
define i64 @swift_score(i64 %x, i64 %y) {
  %r = call {i64,i1} @llvm.sadd.with.overflow.i64(i64 %x, i64 %y)
  %a = extractvalue {i64,i1} %r, 0
  ret i64 %a
}
'''
        with self.assertRaisesRegex(SwiftFrontendError, "aggregate|opcode"):
            self.normalize(text)

    def test_rejects_trap_and_runtime_calls(self):
        for declaration, call, message in [
            ("declare void @llvm.trap()", "call void @llvm.trap()", "intrinsic"),
            ("declare i64 @swift_unknown(i64)", "%a = call i64 @swift_unknown(i64 %x)", "runtime/external"),
        ]:
            with self.subTest(message=message), self.assertRaisesRegex(SwiftFrontendError, message):
                self.normalize(HEADER + declaration + "\ndefine i64 @swift_score(i64 %x) {\n" + call + "\nret i64 %x\n}\n")

    def test_rejects_indirect_call_and_operand_bundle(self):
        text = HEADER + '''
define i64 @swift_score(i64 %x) {
  %a = call i64 @helper(i64 %x) [ "deopt"(i32 3) ]
  ret i64 %a
}
define i64 @helper(i64 %x) {
  ret i64 %x
}
'''
        with self.assertRaisesRegex(SwiftFrontendError, "operand bundles"):
            self.normalize(text)

    def test_rejects_memory_globals_and_poison(self):
        for body in ("%a = load i64, ptr @value\nret i64 %a", "ret i64 poison", "ret i64 undef",
                     "ret i64 ptrtoint (ptr @value to i64)"):
            with self.subTest(body=body), self.assertRaises(SwiftFrontendError):
                self.normalize(HEADER + "@value = global i64 3\ndefine i64 @swift_score(i64 %x) {\n" + body + "\n}\n")

    def test_rejects_module_assembly_initializers_and_special_types(self):
        with self.assertRaisesRegex(SwiftFrontendError, "assembly"):
            self.normalize(PURE + 'module asm "nop"\n')
        with self.assertRaisesRegex(SwiftFrontendError, "initializers"):
            self.normalize(PURE + '@llvm.global_ctors = appending global [1 x {i32, ptr, ptr}] [{i32, ptr, ptr} {i32 65535, ptr @init, ptr null}]\ndefine void @init() {\nret void\n}\n')
        with self.assertRaisesRegex(SwiftFrontendError, "i32/i64"):
            self.normalize(HEADER + 'define i64 @swift_score(ptr %x) {\nret i64 3\n}\n')

    def test_supported_integer_intrinsic_remains_native_ir(self):
        text = HEADER + '''
declare i64 @llvm.smax.i64(i64, i64)
define i64 @swift_score(i64 %x, i64 %y) {
  %a = call i64 @llvm.smax.i64(i64 %x, i64 %y)
  ret i64 %a
}
'''
        result, evidence = self.normalize(text)
        self.assertIn("@llvm.smax.i64", result)
        self.assertEqual(evidence["selected_functions"], ["swift_score"])

    def test_unknown_vendor_target_is_canonicalized_without_arithmetic_change(self):
        result, evidence = self.normalize(PURE.replace("x86_64-pc-windows-msvc", "x86_64-unknown-windows-msvc"))
        self.assertIn('target triple = "x86_64-pc-windows-msvc"', result)
        self.assertEqual(evidence["source_target"], "x86_64-unknown-windows-msvc")

    def test_only_unused_swift_autolink_is_removed_after_closed_graph(self):
        text = PURE + '''
!llvm.linker.options = !{!0, !1, !2}
!0 = !{!"/DEFAULTLIB:swiftCore.lib"}
!1 = !{!"/DEFAULTLIB:oldnames.lib"}
!2 = !{!"/DEFAULTLIB:msvcrt.lib"}
'''
        result, evidence = self.normalize(text)
        self.assertEqual(evidence["removed_unused_swift_autolink_options"], ["/DEFAULTLIB:swiftCore.lib"])
        self.assertNotIn("swiftCore.lib", result)
        self.assertIn("oldnames.lib", result)
        self.assertIn("msvcrt.lib", result)
        with self.assertRaisesRegex(SwiftFrontendError, "Unsupported compiler linker option"):
            self.normalize(text.replace("/DEFAULTLIB:swiftCore.lib", "/INCLUDE:unreviewed"))


class PublicInterfaceTests(unittest.TestCase):
    def test_exact_compiler_signatures_include_signedness(self):
        text = '''// swift-interface-format-version: 1.0
import Swift
@_cdecl("public_unsigned")
public func score(_ x: Swift.UInt32, _ y: Swift.UInt64) -> Swift.UInt64
@_cdecl("public_signed")
@inline(never)
public func signed(_ x: Swift.Int32, _ y: Swift.Int64) -> Swift.Int64
'''
        result = parse_public_interface(text, ["public_unsigned", "public_signed"])
        self.assertEqual(result[0]["swift_name"], "score")
        self.assertEqual(result[0]["return_type"], "u64")
        self.assertEqual([p["type"] for p in result[0]["parameters"]], ["u32", "u64"])
        self.assertEqual([p["type"] for p in result[1]["parameters"]], ["i32", "i64"])
        self.assertEqual(parse_public_interface(text.replace("Swift.", "Swift::"), ["public_unsigned", "public_signed"]), result)

    def test_missing_unsupported_and_duplicate_exports_rejected(self):
        for text in ("public func score(_ x: Swift.UInt64) -> Swift.UInt64",
                     '@_cdecl("score")\npublic func score(_ x: Swift.Double) -> Swift.UInt64',
                     '@_cdecl("score")\npublic func score(_ x: Swift.UInt64) -> Swift.UInt64\n' * 2):
            with self.subTest(text=text), self.assertRaises(SwiftFrontendError):
                parse_public_interface(text, ["score"])

    def test_default_optional_inout_and_generic_signatures_fail_closed(self):
        for parameter in ("_ x: Swift.UInt64 = 1", "_ x: Swift.UInt64?", "_ x: inout Swift.UInt64", "_ x: T"):
            with self.subTest(parameter=parameter), self.assertRaises(SwiftFrontendError):
                parse_public_interface('@_cdecl("score")\npublic func score(' + parameter + ') -> Swift.UInt64', ["score"])

    def test_ordinary_public_labels_and_explicit_external_labels(self):
        for spelling in ("x: Swift::UInt32, y: Swift::Int32", "left x: Swift::UInt32, right y: Swift::Int32",
                         "_ x: Swift.UInt32, _ y: Swift.Int32"):
            with self.subTest(spelling=spelling):
                result = parse_public_interface('@_cdecl("score")\npublic func score(' + spelling + ') -> Swift::UInt32', ["score"])
                self.assertEqual(result[0]["parameters"], [{"name": "x", "type": "u32"}, {"name": "y", "type": "i32"}])
        for spelling in ("x: Swift::UInt32, x: Swift::UInt32", "first middle x: Swift::UInt32",
                         "x: Swift::UInt32 = 0", "x: Swift::UInt32...", "x: inout Swift::UInt32"):
            with self.subTest(spelling=spelling), self.assertRaises(SwiftFrontendError):
                parse_public_interface('@_cdecl("score")\npublic func score(' + spelling + ') -> Swift::UInt32', ["score"])


class ProjectTests(unittest.TestCase):
    def project(self, directory, **changes):
        root = Path(directory)
        (root / "core.swift").write_text('fatalError("must not run during inspection")', encoding="utf-8")
        data = {"schema_version": 1, "name": "fixture", "language": "swift", "sources": ["core.swift"], "functions": ["score"]}
        data.update(changes)
        path = root / "project.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_inspection_never_runs_compiler_or_target(self):
        with tempfile.TemporaryDirectory() as directory, patch("antirea.swift_frontend._compiler", return_value={"input_hashes": {}, "blockers": []}), patch("antirea.swift_frontend.run_logged") as run:
            path = self.project(directory)
            result = inspect_project(path)
            self.assertEqual(result["route_status"], "available")
            self.assertEqual(result["backend"], "swift_llvm_native")
            self.assertFalse(result["source_executed"])
            run.assert_not_called()
            self.assertEqual({p.name for p in Path(directory).iterdir()}, {"core.swift", "project.json"})

    def test_missing_compiler_is_unsupported_not_validated(self):
        with tempfile.TemporaryDirectory() as directory, patch("antirea.swift_frontend._compiler", return_value={"input_hashes": {}, "blockers": ["swift_portable_compiler_not_configured"]}):
            result = inspect_project(self.project(directory))
            self.assertEqual(result["route_status"], "unsupported")
            self.assertTrue(result["blockers"])

    def test_project_rejects_hooks_paths_extra_fields_and_duplicates(self):
        for changes in ({"commands": ["cmd"]}, {"sources": ["../other.swift"]}, {"functions": ["score", "score"]},
                        {"sources": []}, {"functions": ["antirea_internal"]}, {"schema_version": True}):
            with tempfile.TemporaryDirectory() as directory, self.subTest(changes=changes), self.assertRaises(ValueError):
                inspect_project(self.project(directory, **changes))


class ArtifactPathSerializationTests(unittest.TestCase):
    def test_build_finalizer_uses_canonical_slash_artifact_keys(self):
        """Exercise the real report finalizer without any compiler execution."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / "app"
            app.mkdir()
            source = app / "project.json"
            source.write_text("{}", encoding="utf-8")
            output = root / ".runs/build"
            project = {"blockers": [], "project_root": str(app),
                       "project_path": str(source), "input_hashes": {},
                       "compiler": {"input_hashes": {}}}

            def stop_before_compiler(_root):
                (output / "frontend/contract.json").write_bytes(b'{"fixture":true}\n')
                raise SwiftFrontendError("intentional mock before compiler")

            with patch("antirea.swift_frontend.inspect_project", return_value=project), \
                    patch("antirea.swift_frontend.native_build._toolchain",
                          side_effect=stop_before_compiler), \
                    patch("antirea.swift_frontend.run_logged") as run:
                result = build_project(source, output, workspace_root=root)
            run.assert_not_called()
            self.assertEqual(result["status"], "failed")
            self.assertIn("intentional mock before compiler", result["error"])
            self.assertEqual(result["artifact_hashes"],
                             {"frontend/contract.json": _hash(output / "frontend/contract.json")})
            self.assertEqual(_read_report(output / "report.json"), result)


class ReferenceGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.directory = self.root / ".runs/build"
        self.directory.mkdir(parents=True)
        self.output = self.root / ".runs/reference"
        self.interface = self.directory / "api.swiftinterface"
        self.interface.write_text('@_cdecl("score")\npublic func score(_ x: Swift.UInt64) -> Swift.UInt64\n')
        self.ir = self.directory / "original.ll"
        self.ir.write_text(HEADER + 'define i64 @score(i64 %x) {\nret i64 %x\n}\n')
        for name in ("original", "baseline", "protected"):
            (self.directory / (name + ".dll")).write_bytes(("mock " + name).encode())
        artifacts = {arm: {"path": str(self.directory / (arm + ".dll")), "sha256": _hash(self.directory / (arm + ".dll"))}
                     for arm in ("baseline", "protected")}
        self.native = self.directory / "native.json"
        self.native.write_text(json.dumps({"status": "artifact_created_unvalidated", "artifacts": artifacts, "coverage": {"functions": {"score": {"virtualized": True}}}}))
        self.build = {"status": "artifact_created_unvalidated", "backend": "swift_llvm_native", "exported_functions": ["score"],
            "source_functions": parse_public_interface(self.interface.read_text(), ["score"]),
            "public_interface": {"path": str(self.interface), "sha256": _hash(self.interface)},
            "original_ir": {"path": str(self.ir), "sha256": _hash(self.ir)},
            "original_reference": {"path": str(self.directory / "original.dll"), "sha256": _hash(self.directory / "original.dll"), "runtime_files": {}},
            "artifacts": artifacts, "coverage": {"functions": {"score": {"virtualized": True}}},
            "native_report": str(self.native), "native_report_sha256": _hash(self.native)}
        self.report = self.directory / "report.json"
        self.report.write_text(json.dumps(self.build))

    def tearDown(self):
        self.temporary.cleanup()

    def run_mock(self, command, cwd, prefix, **kwargs):
        request = json.loads(Path(command[-1]).read_text())
        values = [row[0] for row in request["cases"]]
        Path(request["reply"]).write_text(json.dumps({"values": [values, values], "behavior_repeats": 2}))
        return {"returncode": 0, "timed_out": False, "stderr": "mock stderr",
                "cleanup": {"status": "assigned_job_empty", "parent_exit_confirmed": True, "job_handle_closed": True}}

    def verify(self):
        return verify_build(self.report, self.output, workspace_root=self.root, random_cases=8, include_protected=True)

    def test_two_repeats_original_and_both_native_arms(self):
        with patch("antirea.swift_frontend.run_logged", side_effect=self.run_mock) as run:
            result = self.verify()
        self.assertEqual(result["status"], "passed")
        self.assertEqual(run.call_count, 3)
        self.assertEqual(result["behavior_repeats"], 2)
        self.assertEqual(result["changed_inputs"], [])
        self.assertEqual(set(result["methods"][0]["comparisons"]), {"baseline", "protected"})
        self.assertEqual(result["methods"][0]["random_unique_cases"], 8)
        self.assertGreater(result["methods"][0]["edge_cases"], 0)

    def test_reference_finalizer_uses_canonical_slash_artifact_keys(self):
        def run_with_nested_evidence(command, cwd, prefix, **kwargs):
            nested = self.output / "logs/canonical.txt"
            nested.parent.mkdir(exist_ok=True)
            nested.write_bytes(b"mock evidence only\n")
            return self.run_mock(command, cwd, prefix, **kwargs)
        with patch("antirea.swift_frontend.run_logged", side_effect=run_with_nested_evidence):
            result = self.verify()
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["artifact_hashes"].get("logs/canonical.txt"),
                         _hash(self.output / "logs/canonical.txt"))
        self.assertFalse(any("\\" in key for key in result["artifact_hashes"]))

    def test_timeout_is_failure_not_sample_success(self):
        with patch("antirea.swift_frontend.run_logged", return_value={"returncode": None, "timed_out": True, "stderr": "timeout"}):
            result = self.verify()
        self.assertEqual(result["status"], "failed")
        self.assertIn("process failed", result["error"])

    def test_second_repeat_disagreement_is_failure(self):
        def changed(command, cwd, prefix, **kwargs):
            result = self.run_mock(command, cwd, prefix, **kwargs)
            request = json.loads(Path(command[-1]).read_text())
            if "protected" in request["library"]:
                reply = Path(request["reply"])
                values = json.loads(reply.read_text())
                values["values"][1][0] ^= 1
                reply.write_text(json.dumps(values))
            return result
        with patch("antirea.swift_frontend.run_logged", side_effect=changed):
            result = self.verify()
        self.assertEqual(result["status"], "failed")
        comparison = result["methods"][0]["comparisons"]["protected"]
        self.assertFalse(comparison["deterministic"])
        self.assertEqual(comparison["matched"], comparison["total"] - 1)

    def test_signature_change_rejected_before_workers(self):
        self.build["source_functions"][0]["return_type"] = "i64"
        self.report.write_text(json.dumps(self.build))
        with patch("antirea.swift_frontend.run_logged", side_effect=AssertionError("must not execute")), self.assertRaisesRegex(SwiftFrontendError, "signatures"):
            self.verify()
        self.assertFalse(self.output.exists())

    def test_artifact_change_and_stop_rejected_before_workers(self):
        (self.directory / "protected.dll").write_bytes(b"changed")
        with patch("antirea.swift_frontend.run_logged", side_effect=AssertionError("must not execute")), self.assertRaisesRegex(SwiftFrontendError, "hash mismatch"):
            self.verify()
        stop = self.root / ".runs/defense-loop/STOP"
        stop.parent.mkdir()
        stop.write_text("stop")
        with self.assertRaisesRegex(SwiftFrontendError, "STOP"):
            self.verify()

    def test_pinned_compiler_inventory_report_larger_than_one_mib_is_supported(self):
        value = {"status": "fixture", "inventory": "x" * (1024 * 1024 + 1)}
        self.report.write_text(json.dumps(value))
        self.assertEqual(_read_report(self.report), value)
        self.report.write_text('{"status":"one","status":"two"}')
        with self.assertRaisesRegex(ValueError, "Duplicate JSON"):
            _read_report(self.report)


if __name__ == "__main__":
    unittest.main()
