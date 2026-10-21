"""Draft-only fake-input tests; no compiler, DevShell or target execution."""
import ctypes
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
import uuid

from antirea import native_build as guards


class SelectionInputsTests(unittest.TestCase):
    def test_preserves_order_and_spelling_without_publishing_values(self):
        first = guards._environment_selection_inputs({"Include": "owned-a;owned-b", "WindowsSDKVersion": "10.0.1\\"})
        same = guards._environment_selection_inputs({"INCLUDE": "owned-a;owned-b", "WINDOWSSDKVERSION": "10.0.1\\"})
        other = guards._environment_selection_inputs({"INCLUDE": "owned-b;owned-a", "WINDOWSSDKVERSION": "10.0.1\\"})
        self.assertEqual(first, same)
        self.assertNotEqual(first, other)
        self.assertNotIn("owned-a", repr(first))

    def test_absent_empty_and_new_selector_are_distinct(self):
        empty = guards._environment_selection_inputs({"INCLUDE": ""})
        absent = guards._environment_selection_inputs({})
        custom = guards._environment_selection_inputs({"__VCVARS_CUSTOM_OVERRIDE": "changed"})
        self.assertNotEqual(empty, absent)
        self.assertNotEqual(custom, absent)

    def test_sdk_versions_and_script_referenced_selectors_are_pinned(self):
        a = guards._environment_selection_inputs({"CUSTOM_SDK": "one"}, referenced_names=["CUSTOM_SDK"])
        b = guards._environment_selection_inputs({"CUSTOM_SDK": "two"}, referenced_names=["CUSTOM_SDK"])
        self.assertNotEqual(a, b)
        for key in ("VCToolsVersion", "WindowsSDKVersion", "VSCMD_ARG_WINSDK", "PATH", "LIBPATH", "SOURCE_DATE_EPOCH"):
            with self.subTest(key=key):
                self.assertNotEqual(guards._environment_selection_inputs({key: "a"}),
                                    guards._environment_selection_inputs({key: "b"}))

    def test_unrelated_secret_is_neither_captured_nor_a_build_selector(self):
        a = guards._environment_selection_inputs({"API_TOKEN": "private-one"})
        b = guards._environment_selection_inputs({"API_TOKEN": "private-two"})
        self.assertEqual(a, b)
        self.assertNotIn("API_TOKEN", repr(a))

    def test_conflicting_windows_case_variants_rejected(self):
        with self.assertRaisesRegex(guards.NativeBuildError, "Conflicting"):
            guards._environment_selection_inputs({"PATH": "one", "Path": "two"})


class MetadataTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.install = self.root / "installation"
        self.shell = self.install / "Common7/Tools/Launch-VsDevShell.ps1"
        self.paths = [self.shell, self.install / "Common7/Tools/VsDevCmd.bat",
                      self.install / "Common7/Tools/Microsoft.VisualStudio.DevShell.dll",
                      self.install / "Common7/Tools/vsdevcmd/core/winsdk.bat",
                      self.install / "VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt",
                      self.install / "VC/Auxiliary/Build/Microsoft.VCToolsVersion.v145.default.props",
                      self.install / "VC/Auxiliary/Build/v145/Microsoft.VCToolsVersion.VC.14.50.18.0.txt",
                      self.root / "pf86/Microsoft Visual Studio/Installer/vswhere.exe",
                      self.root / "program-data/Microsoft/VisualStudio/Packages/_Instances/owned/state.json"]
        for path in self.paths:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"fake owned selector metadata, never executed")
        self.paths[3].write_text('if "%CUSTOM_SDK%" NEQ "" echo selected\n', encoding="utf-8")
        self.env = {"PROGRAMFILES(X86)": str(self.root / "pf86"), "PROGRAMDATA": str(self.root / "program-data")}

    def inspect(self):
        return guards._devshell_selection_metadata(self.install, self.shell, self.env)

    def test_transitive_selector_metadata_is_hashed_without_execution(self):
        with patch("subprocess.Popen", side_effect=AssertionError("must not execute")):
            result = self.inspect()
        self.assertTrue(all(str(path) in result["files"] for path in self.paths))
        self.assertIn("CUSTOM_SDK", result["referenced_environment_names"])

    def test_default_props_dll_vswhere_and_setup_state_changes_invalidate(self):
        for path in (self.paths[2], self.paths[5], self.paths[6], self.paths[7], self.paths[8]):
            before = self.inspect()
            raw = path.read_bytes()
            path.write_bytes(raw + b"changed")
            with self.subTest(path=path):
                self.assertNotEqual(before, self.inspect())
            path.write_bytes(raw)

    def test_optional_module_or_default_selector_addition_changes_inventory(self):
        before = self.inspect()
        added = self.install / "Common7/Tools/vsdevshell/Microsoft.VisualStudio.DevShell.dll"
        added.parent.mkdir()
        added.write_bytes(b"fake alternative module")
        self.assertNotEqual(before, self.inspect())


class FakeCallback:
    def __call__(self, value):
        return value if value == 99 else None


class FakeLLVM:
    def __init__(self, *, module_asm=False, inline_asm=False, parse_error=False):
        self.module_asm, self.inline_asm, self.parse_error = module_asm, inline_asm, parse_error
        self.dll = types.SimpleNamespace(LLVMIsAInlineAsm=FakeCallback())
        self.closed = False
        self.disposed = False

    def LLVMContextCreate(self): return 1
    def LLVMCreateMemoryBufferWithMemoryRangeCopy(self, *args): return 2
    def LLVMParseIRInContext(self, context, buffer, module, error):
        module._obj.value = 3
        return 1 if self.parse_error else 0
    def LLVMVerifyModule(self, *args): return 0
    def LLVMGetModuleInlineAsm(self, module, length): length._obj.value = int(self.module_asm)
    def functions(self, module): return [4, 5]
    def instructions(self, function): return [function]
    def LLVMGetNumOperands(self, instruction): return 1
    def LLVMGetOperand(self, instruction, index): return 99 if self.inline_asm and instruction == 5 else 10
    def name(self, function): return "unselected_helper" if function == 5 else "core"
    def string(self, value): return "fake parse error"
    def LLVMDisposeModule(self, module): self.disposed = True
    def LLVMContextDispose(self, context): pass
    def close(self): self.closed = True


class AssemblyGateTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.source = Path(temp.name) / "raw.ll"
        self.source.write_text('; owned raw IR stand-in; fake parser only\n', encoding="utf-8")

    def check(self, llvm):
        with patch("antirea.swift_frontend._LLVM", return_value=llvm), \
             patch("subprocess.Popen", side_effect=AssertionError("no compiler/assembler")):
            return guards._reject_assembly_before_original_codegen(self.source, "fake-LLVM-C.dll")

    def test_no_assembly_passes_and_disposes_parser(self):
        llvm = FakeLLVM()
        evidence = self.check(llvm)
        self.assertEqual(evidence["status"], "no_module_or_function_inline_assembly")
        self.assertEqual(evidence["instructions_inspected"], 2)
        self.assertTrue(llvm.closed and llvm.disposed)

    def test_module_assembly_rejected_before_any_assembler_execution(self):
        llvm = FakeLLVM(module_asm=True)
        with self.assertRaisesRegex(guards.NativeBuildError, "module assembly"):
            self.check(llvm)
        self.assertTrue(llvm.closed and llvm.disposed)

    def test_inline_assembly_in_unselected_function_rejected(self):
        llvm = FakeLLVM(inline_asm=True)
        with self.assertRaisesRegex(guards.NativeBuildError, "unselected_helper"):
            self.check(llvm)
        self.assertTrue(llvm.closed and llvm.disposed)

    def test_parser_failure_never_marks_assembly_absent(self):
        with self.assertRaisesRegex(guards.NativeBuildError, "parse failed"):
            self.check(FakeLLVM(parse_error=True))


@unittest.skipUnless(os.environ.get("ANTIREA_RUN_COMPDB_IR_GATE_TESTS") == "1" and os.name == "nt",
                     "explicit opt-in pinned LLVM-C parsing only; no assembler or target")
class ActualAssemblyGateTests(unittest.TestCase):
    def test_handwritten_ir_assembly_gate_without_code_generation(self):
        repo = Path(__file__).resolve().parents[1]
        config = json.loads((repo / ".tools/kagura-toolchain.json").read_text(encoding="utf-8-sig"))
        library = Path(config["llvm_root"]) / "bin/LLVM-C.dll"
        identity = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:10]
        directory = repo / ".runs" / ("compile-db-llvm-assembly-gate-" + identity)
        directory.mkdir(parents=True, exist_ok=False)
        stop = repo / ".runs/defense-loop/STOP"
        self.assertFalse(stop.exists())
        target = 'target triple = "x86_64-pc-windows-msvc"\n'
        cases = {
            "ordinary": (target + '@words = private constant [4 x i8] c"asm\\00"\n'
                         + 'define i32 @core() {\n ret i32 7\n}\n', None),
            "module": (target + 'module asm ".incbin \\22missing-owned.bin\\22"\n'
                       + 'define i32 @core() {\n ret i32 7\n}\n', "module assembly"),
            "unselected_inline": (target + 'define i32 @core() {\n ret i32 7\n}\n'
                       + 'define void @unselected_helper() {\n call void asm sideeffect ".incbin \\22missing-owned.bin\\22", ""()\n ret void\n}\n',
                       "inline assembly"),
            "malformed": ('not llvm IR', "parse failed"),
        }
        evidence = {"LLVM_C": {"path": str(library), "sha256": guards._hash(library)},
                    "target_executed": False, "assembler_executed": False, "cases": {}}
        with patch("subprocess.Popen", side_effect=AssertionError("parser gate must not launch a compiler")):
            for name, (text, error) in cases.items():
                self.assertFalse(stop.exists())
                source = directory / (name + ".ll")
                source.write_text(text, encoding="utf-8")
                if error:
                    with self.assertRaisesRegex(guards.NativeBuildError, error) as failure:
                        guards._reject_assembly_before_original_codegen(source, library)
                    evidence["cases"][name] = {"status": "rejected", "error": str(failure.exception),
                                               "input_sha256": guards._hash(source)}
                else:
                    evidence["cases"][name] = guards._reject_assembly_before_original_codegen(source, library)
        self.assertFalse((directory / "missing-owned.bin").exists())
        self.assertFalse(stop.exists())
        (directory / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        print("COMPDB_LLVM_ASSEMBLY_GATE_EVIDENCE=" + str(directory / "evidence.json"))


if __name__ == "__main__":
    unittest.main()
