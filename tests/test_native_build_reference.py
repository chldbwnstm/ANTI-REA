"""RED-first builder tests for the direct-source original-reference producer.

Task 3 of docs/superpowers/plans/2026-10-21-supported-languages.md, builder half.
The validator-side contract lives in tests/test_native_direct_reference.py; these
tests pin the *builder* side: native_build must compile a separate source-only
original object and signature IR for the direct C / C++ / single-crate Rust
routes, using the normal direct recipe (O1 / -Copt-level=1, never the
scope-analysis O0 downgrade), and the existing raw-IR assembly rejection must run
BEFORE that original object codegen.

Status when written: RED. native_build has no direct-source original-reference
producer -- the original object/signature/DLL/provenance exist only inside the
``compile_database_native`` branch (native_build.py:1452-1474). The helpers under
test (``_direct_reference_commands`` and ``_emit_direct_original_reference``) do
not exist yet, so every test here fails until the builder half is implemented.

Execution boundary: the worker (defender) does NOT run these. Root executes every
test/build/compiler/target. The process boundary (``run``) and the LLVM assembly
gate are mocked with inert callables -- no compiler, object, DLL or LLVM library
is ever produced; the tests exercise the real recipe/ordering logic only.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from antirea import native_build as nb


class DirectReferenceRecipeTests(unittest.TestCase):
    """The pure normal-direct-recipe argv the validator gate will enforce."""

    def setUp(self):
        self.assertTrue(callable(getattr(nb, "_direct_reference_commands", None)),
                        "direct-source original-reference recipe is not implemented")
        self.source = Path("project") / "core.c"
        self.obj = Path("build") / "original-000.obj"
        self.sig = Path("build") / "original-signature-000.ll"

    def test_c_uses_o1_object_c_and_separate_emit_llvm_signature(self):
        source = Path("project") / "core.c"
        object_argv, signature_argv = nb._direct_reference_commands(
            "c", source, "clang.exe", self.obj, self.sig, include_dirs=[], defines={})
        self.assertEqual(object_argv, [
            "clang.exe", "-std=c11", "-O1", "-fno-inline", "-fno-exceptions",
            "-target", nb.TARGET, "-c", str(source), "-o", str(self.obj)])
        self.assertEqual(signature_argv, [
            "clang.exe", "-std=c11", "-O1", "-fno-inline", "-fno-exceptions",
            "-target", nb.TARGET, "-S", "-emit-llvm", str(source), "-o", str(self.sig)])

    def test_cpp_adds_fno_rtti_then_includes_then_sorted_defines(self):
        source = Path("project") / "core.cpp"
        object_argv, signature_argv = nb._direct_reference_commands(
            "cpp", source, "clang++.exe", self.obj, self.sig,
            include_dirs=["incdir"], defines={"B": 2, "A": "x"})
        prefix = ["clang++.exe", "-std=c++17", "-O1", "-fno-inline", "-fno-exceptions",
                  "-fno-rtti", "-I", "incdir", "-DA=x", "-DB=2", "-target", nb.TARGET]
        self.assertEqual(object_argv, [*prefix, "-c", str(source), "-o", str(self.obj)])
        self.assertEqual(signature_argv,
                         [*prefix, "-S", "-emit-llvm", str(source), "-o", str(self.sig)])

    def test_cpp_project_preserves_c_translation_unit_frontend_recipe(self):
        source = Path("project") / "helper.c"
        object_argv, signature_argv = nb._direct_reference_commands(
            "cpp", source, "clang.exe", self.obj, self.sig, include_dirs=[], defines={})
        for argv in (object_argv, signature_argv):
            self.assertIn("-std=c11", argv)
            self.assertNotIn("-std=c++17", argv)
            self.assertNotIn("-fno-rtti", argv)

    def test_rust_uses_emit_obj_for_object_and_emit_llvm_ir_for_signature_at_opt1(self):
        source = Path("project") / "core.rs"
        object_argv, signature_argv = nb._direct_reference_commands(
            "rust", source, "rustc.exe", self.obj, self.sig, include_dirs=[], defines={})
        base = ["rustc.exe", "--crate-name", "antirea_native_module", "--crate-type=lib",
                "--edition=2021"]
        tail = ["-Copt-level=1", "-Cpanic=abort", "-Ccodegen-units=1", "--target", nb.TARGET,
                str(source)]
        self.assertEqual(object_argv, [*base, "--emit=obj", *tail, "-o", str(self.obj)])
        self.assertEqual(signature_argv, [*base, "--emit=llvm-ir", *tail, "-o", str(self.sig)])

    def test_recipe_never_uses_scope_analysis_o0_downgrade(self):
        for language, compiler in (("c", "clang.exe"), ("cpp", "clang++.exe"), ("rust", "rustc.exe")):
            with self.subTest(language=language):
                source = Path("project") / "core"
                object_argv, signature_argv = nb._direct_reference_commands(
                    language, source, compiler, self.obj, self.sig, include_dirs=[], defines={})
                for argv in (object_argv, signature_argv):
                    self.assertNotIn("-O0", argv)
                    self.assertNotIn("-Copt-level=0", argv)
                    self.assertIn("-O1" if language != "rust" else "-Copt-level=1", argv)


class DirectReferenceEmissionTests(unittest.TestCase):
    """Guard-before-codegen ordering and the per-translation-unit provenance,
    exercised against an inert (mocked) process boundary and assembly gate."""

    def setUp(self):
        self.assertTrue(callable(getattr(nb, "_emit_direct_original_reference", None)),
                        "direct-source original-reference emission is not implemented")
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.output = self.root / "out"
        self.output.mkdir()
        self.source = self.root / "core.c"
        self.source.write_text("int f(void){return 0;}", encoding="utf-8")
        self.module = self.output / "source-000.ll"
        self.module.write_text("; raw ir fixture\n", encoding="utf-8")
        self.project = {"language": "c", "include_dirs": [], "defines": {}}
        self.calls = []
        self.commands = []

    def tearDown(self):
        self.temp.cleanup()

    def _run(self, program, *args):
        self.calls.append(("run", program, *args))
        self.commands.append({"argv": [program, *args]})
        return ""

    def _guard(self, module, library):
        self.calls.append(("guard", str(module)))
        return {"path": str(module), "status": "no_module_or_function_inline_assembly"}

    def _emit(self, **overrides):
        kwargs = {"compiler": "clang.exe", "compiler_sha256": "a" * 64,
                  "llvm_library": "LLVM-C.dll", "run": self._run, "commands": self.commands}
        kwargs.update(overrides)
        with patch.object(nb, "_reject_assembly_before_original_codegen", side_effect=self._guard):
            return nb._emit_direct_original_reference(
                self.project, 0, self.source, self.module, self.output, **kwargs)

    def test_assembly_gate_runs_before_the_original_object_command(self):
        self._emit()
        self.assertEqual(self.calls[0], ("guard", str(self.module)))
        self.assertEqual(self.calls[1][0], "run")
        self.assertIn("-c", self.calls[1])
        self.assertNotIn("-emit-llvm", self.calls[1])
        self.assertEqual(self.calls[2][0], "run")
        self.assertIn("-emit-llvm", self.calls[2])

    def test_assembly_rejection_prevents_any_original_codegen(self):
        with patch.object(self, "_guard", side_effect=nb.NativeBuildError("assembly rejected")):
            with self.assertRaisesRegex(nb.NativeBuildError, "assembly rejected"):
                self._emit()
        self.assertEqual(self.calls, [])
        self.assertEqual(self.commands, [])

    def test_records_distinct_object_and_signature_paths_with_command_indices(self):
        assembly_check, unit, object_path, signature_path = self._emit()
        self.assertEqual(object_path, self.output / "original-000.obj")
        self.assertEqual(signature_path, self.output / "original-signature-000.ll")
        self.assertNotEqual(str(object_path), str(signature_path))
        self.assertEqual(unit["source"], str(self.source))
        self.assertEqual(unit["source_operand"], str(self.source))
        self.assertEqual(unit["entry_sha256"],
                         hashlib.sha256(self.source.read_bytes()).hexdigest())
        self.assertEqual(unit["compiler"], "clang.exe")
        self.assertEqual(unit["compiler_sha256"], "a" * 64)
        self.assertEqual(unit["cwd"], str(self.output))
        self.assertEqual(unit["object_path"], str(object_path))
        self.assertEqual(unit["signature_ir_path"], str(signature_path))
        self.assertEqual(unit["object_command_index"], 0)
        self.assertEqual(unit["signature_ir_command_index"], 1)
        self.assertEqual(assembly_check["status"], "no_module_or_function_inline_assembly")

    def test_source_operand_is_the_exact_inspected_source_path(self):
        _, unit, _, _ = self._emit()
        object_argv = self.commands[unit["object_command_index"]]["argv"]
        self.assertIn(str(self.source), object_argv)
        self.assertEqual(unit["source_operand"], str(self.source))


if __name__ == "__main__":
    unittest.main()
