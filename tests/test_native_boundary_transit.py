"""Parsed public-boundary preservation; LLVM parser use is explicitly opt-in."""
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid

from antirea import native_build as nb
from antirea.process import run_logged

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / ".tools/kagura-toolchain.json"
IR = '''target triple = "x86_64-pc-windows-msvc"
define i64 @secret(i64 %x, i64 %y) {
entry:
  %r = add i64 %x, %y
  ret i64 %r
}
define i64 @entry(i64 %x, i64 %y) {
entry:
  %r = call i64 @secret(i64 %x, i64 %y) #0
  ret i64 %r
}
attributes #0 = { alwaysinline }
'''


class EmptyBoundaryContractTests(unittest.TestCase):
    def test_no_boundaries_explicit_without_loading_library(self):
        contract = nb._boundary_contract(Path("missing.ll"), [], Path("missing.dll"))
        self.assertEqual(contract, {"schema_version": 1, "functions": {}})
        evidence = nb._boundary_transit_evidence(Path("missing.ll"), contract, Path("missing.dll"))
        self.assertEqual(evidence["status"], "no_boundaries")
        self.assertEqual(evidence["functions"], {})


@unittest.skipUnless(os.environ.get("ANTIREA_RUN_COMPDB_IR_GATE_TESTS") == "1" and CONFIG.is_file(),
                     "explicit owned LLVM parser opt-in")
class ParsedBoundaryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        config = json.loads(CONFIG.read_text(encoding="utf-8-sig"))
        cls.library = Path(config["llvm_root"]) / "bin/LLVM-C.dll"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "before.ll"
        self.source.write_text(IR, encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def contract(self):
        return nb._boundary_contract(self.source, ["entry"], self.library,
                                     expected_calls={"entry": ["secret"]})

    def changed(self, text):
        path = self.root / "changed.ll"
        path.write_text(text, encoding="utf-8")
        return path

    def test_contract_records_ordered_parameter_and_result_relation(self):
        result = self.contract()["functions"]["entry"]
        self.assertEqual(result["callee"], "secret")
        self.assertEqual(result["argument_indices"], [0, 1])
        self.assertEqual(result["return"], {"kind": "call_result"})
        self.assertEqual(result["signature"], "i64 (i64, i64)")

    def test_contract_records_callee_signature_and_abi(self):
        result = self.contract()["functions"]["entry"]
        self.assertEqual(result["callee_signature"], "i64 (i64, i64)")
        self.assertEqual(result["callee_calling_convention"], 0)
        self.assertEqual(result["callee_abi_attributes"], [[], [], []])

    def test_callee_fastcc_change_rejected(self):
        final = self.changed(IR.replace("define i64 @secret", "define fastcc i64 @secret"))
        with self.assertRaises(nb.NativeBuildError):
            nb._boundary_transit_evidence(final, self.contract(), self.library)

    def test_callee_return_abi_change_rejected(self):
        final = self.changed(IR.replace("define i64 @secret", "define signext i64 @secret"))
        with self.assertRaises(nb.NativeBuildError):
            nb._boundary_transit_evidence(final, self.contract(), self.library)

    def test_callee_parameter_abi_change_rejected(self):
        final = self.changed(IR.replace("define i64 @secret(i64 %x", "define i64 @secret(i64 signext %x"))
        with self.assertRaises(nb.NativeBuildError):
            nb._boundary_transit_evidence(final, self.contract(), self.library)

    def test_called_function_type_differs_from_callee_rejected(self):
        original_definition = "define i64 @secret(i64 %x, i64 %y) {\nentry:\n  %r = add i64 %x, %y\n  ret i64 %r\n}"
        final = self.changed(IR.replace(original_definition, "define i32 @secret(i64 %x, i64 %y) {\n  ret i32 42\n}"))
        with self.assertRaises(nb.NativeBuildError):
            nb._boundary_transit_evidence(final, self.contract(), self.library)

    def test_callee_declaration_and_definition_same_signature_allowed(self):
        original_definition = "define i64 @secret(i64 %x, i64 %y) {\nentry:\n  %r = add i64 %x, %y\n  ret i64 %r\n}"
        final = self.changed(IR.replace(original_definition, "declare i64 @secret(i64, i64)"))
        result = nb._boundary_transit_evidence(final, self.contract(), self.library)
        self.assertEqual(result["status"], "verified")

    def test_unchanged_tailcall_verified(self):
        final = self.changed(IR.replace("%r = call", "%r = tail call"))
        evidence = nb._boundary_transit_evidence(final, self.contract(), self.library)
        self.assertEqual(evidence["status"], "verified")
        self.assertTrue(evidence["functions"]["entry"]["ordered_arguments"])

    def test_constant_folded_boundary_rejected(self):
        final = self.changed(IR.replace("  %r = call i64 @secret(i64 %x, i64 %y) #0\n  ret i64 %r", "  ret i64 42"))
        with self.assertRaisesRegex(nb.NativeBuildError, "transit"):
            nb._boundary_transit_evidence(final, self.contract(), self.library)

    def test_returned_parameter_instead_of_call_result_rejected(self):
        final = self.changed(IR.replace("  ret i64 %r\n}\nattributes", "  ret i64 %x\n}\nattributes"))
        with self.assertRaises(nb.NativeBuildError):
            nb._boundary_transit_evidence(final, self.contract(), self.library)

    def test_plaintext_substitution_rejected(self):
        final = self.changed(IR.replace("  %r = call i64 @secret(i64 %x, i64 %y) #0", "  %r = add i64 %x, %y"))
        with self.assertRaises(nb.NativeBuildError):
            nb._boundary_transit_evidence(final, self.contract(), self.library)

    def test_reordered_args_rejected(self):
        final = self.changed(IR.replace("call i64 @secret(i64 %x, i64 %y)", "call i64 @secret(i64 %y, i64 %x)"))
        with self.assertRaises(nb.NativeBuildError):
            nb._boundary_transit_evidence(final, self.contract(), self.library)

    def test_poison_arg_rejected(self):
        final = self.changed(IR.replace("call i64 @secret(i64 %x, i64 %y)", "call i64 @secret(i64 %x, i64 poison)"))
        with self.assertRaises(nb.NativeBuildError):
            nb._boundary_transit_evidence(final, self.contract(), self.library)

    def test_graph_target_mismatch_rejected(self):
        with self.assertRaisesRegex(nb.NativeBuildError, "graph"):
            nb._boundary_contract(self.source, ["entry"], self.library, expected_calls={"entry": ["other"]})

    def test_symbol_remap_changes_only_expected_target(self):
        final = self.changed(IR.replace("@secret", "@mapped"))
        result = nb._boundary_transit_evidence(final, self.contract(), self.library, symbol_map={"secret": "mapped"})
        self.assertEqual(result["functions"]["entry"]["callee"], "mapped")

    def test_operand_bundle_rejected(self):
        self.source.write_text(IR.replace(" #0\n", ' #0 [ "deopt"(i64 7) ]\n'), encoding="utf-8")
        with self.assertRaises(nb.NativeBuildError):
            self.contract()

    def test_split_has_only_needed_declarations_not_globals_or_ctors(self):
        suffix = '''
@g = global i64 7
@alias = alias i64, ptr @g
@llvm.global_ctors = appending global [1 x { i32, ptr, ptr }] [{ i32, ptr, ptr } { i32 65535, ptr @init, ptr null }]
define internal void @init() {
  store i64 9, ptr @g
  ret void
}
'''
        self.source.write_text(IR + suffix, encoding="utf-8")
        core, boundary = self.root / "core.ll", self.root / "boundary.ll"
        descriptor = nb._isolate_public_boundaries(self.source, core, boundary, ["entry"], self.library,
                                                   expected_calls={"entry": ["secret"]})
        public_text = boundary.read_text(encoding="utf-8")
        core_text = core.read_text(encoding="utf-8")
        for name in ("@g", "@alias", "@llvm.global_ctors", "@init"):
            self.assertNotIn(name, public_text)
            self.assertIn(name, core_text)
        self.assertIn("define i64 @entry", public_text)
        self.assertIn("declare i64 @secret", public_text)
        self.assertIn("declare i64 @entry", core_text)
        self.assertNotIn("alwaysinline", public_text)
        self.assertIn("optnone", public_text)
        self.assertEqual(descriptor["contract"], self.contract())
        self.assertEqual(nb._boundary_transit_evidence(boundary, self.contract(), self.library)["status"], "verified")

    def test_zero_call_public_leaf_preserved(self):
        text = IR.replace("  %r = call i64 @secret(i64 %x, i64 %y) #0\n  ret i64 %r", "  ret i64 19")
        self.source.write_text(text, encoding="utf-8")
        contract = nb._boundary_contract(self.source, ["entry"], self.library, expected_calls={"entry": []})
        self.assertIsNone(contract["functions"]["entry"]["callee"])
        self.assertEqual(contract["functions"]["entry"]["return"], {"kind": "constant", "llvm": "i64 19"})

    def test_protection_retention_removes_callsite_alwaysinline(self):
        retained = self.root / "retained.ll"
        result = nb._retain_database_scope(self.source, retained, ["secret"], self.library)
        self.assertNotIn("alwaysinline", retained.read_text(encoding="utf-8"))
        self.assertEqual(result["callsite_adjustments"][0]["callee"], "secret")

    def test_mandatory_tailcall_preserved(self):
        self.source.write_text(IR.replace("%r = call", "%r = musttail call"), encoding="utf-8")
        core, boundary = self.root / "core.ll", self.root / "boundary.ll"
        result = nb._isolate_public_boundaries(self.source, core, boundary, ["entry"], self.library)
        self.assertEqual(result["contract"]["functions"]["entry"]["tail_requirement"], "musttail")
        self.assertIn("musttail call", boundary.read_text(encoding="utf-8"))
        self.assertEqual(nb._boundary_transit_evidence(boundary, result["contract"], self.library)["status"], "verified")

    def test_signed_extension_abi_attributes_preserved(self):
        text = IR.replace("define i64 @", "define signext i64 @").replace("(i64 %x, i64 %y)", "(i64 signext %x, i64 signext %y)")
        text = text.replace("call i64 @", "call signext i64 @")
        self.source.write_text(text, encoding="utf-8")
        core, boundary = self.root / "core.ll", self.root / "boundary.ll"
        result = nb._isolate_public_boundaries(self.source, core, boundary, ["entry"], self.library)
        record = result["contract"]["functions"]["entry"]
        self.assertTrue(all(row == [{"name": "signext", "value": 0}] for row in record["abi_attributes"]))
        self.assertEqual(nb._boundary_transit_evidence(boundary, result["contract"], self.library)["status"], "verified")

    def test_public_chain_uses_single_public_definition(self):
        extra = '''define i64 @outer(i64 %x, i64 %y) {
entry:
  %r = call i64 @entry(i64 %x, i64 %y)
  ret i64 %r
}
'''
        self.source.write_text(IR + extra, encoding="utf-8")
        core, boundary = self.root / "core.ll", self.root / "boundary.ll"
        result = nb._isolate_public_boundaries(self.source, core, boundary, ["entry", "outer"], self.library)
        self.assertEqual(nb._boundary_transit_evidence(boundary, result["contract"], self.library)["status"], "verified")
        self.assertEqual(boundary.read_text().count("define i64 @entry"), 1)

    def test_void_result_forwarder_preserved(self):
        self.source.write_text('''define void @secret(i32 %x) { ret void }
define void @entry(i32 %x) {
  call void @secret(i32 %x)
  ret void
}
''', encoding="utf-8")
        core, boundary = self.root / "core.ll", self.root / "boundary.ll"
        result = nb._isolate_public_boundaries(self.source, core, boundary, ["entry"], self.library)
        self.assertEqual(result["contract"]["functions"]["entry"]["return"], {"kind": "void"})
        self.assertEqual(nb._boundary_transit_evidence(boundary, result["contract"], self.library)["status"], "verified")

    def test_actual_optimizer_preserves_all_four_boundary_cases(self):
        """No target execution: catch module IPO that defeats noinline/optnone."""
        stop = ROOT / ".runs/defense-loop/STOP"
        self.assertFalse(stop.exists(), "STOP marker prevents compiler-only regression")
        output = ROOT / ".runs" / ("native-boundary-regression-" + uuid.uuid4().hex[:12])
        output.mkdir(exist_ok=False)
        toolchain, hashes = nb._toolchain(ROOT)
        hashes[str(Path(nb.__file__).resolve())] = nb._hash(Path(nb.__file__))
        selected, boundaries, pieces = [], [], ['target triple = "x86_64-pc-windows-msvc"']
        bodies = {
            "callsite": "  %a = xor i64 %x, 8191\n  %b = mul i64 %a, %y\n  %r = add i64 %b, 17\n  ret i64 %r",
            "constant": "  ret i64 42",
            "argument": "  ret i64 %x",
            "control": "  %a = xor i64 %x, 8191\n  %b = mul i64 %a, %y\n  %r = add i64 %b, 17\n  ret i64 %r",
        }
        for kind, body in bodies.items():
            target, name = "sensitive_" + kind, "public_" + kind
            selected.append(target)
            boundaries.append(name)
            pieces.append(f"define i64 @{target}(i64 %x, i64 %y) #0 {{\n{body}\n}}")
            attribute = " #1" if kind == "callsite" else ""
            pieces.append(f"define i64 @{name}(i64 %x, i64 %y) {{\n  %r = call i64 @{target}(i64 %x, i64 %y){attribute}\n  ret i64 %r\n}}")
        pieces.extend(["attributes #0 = { nounwind willreturn memory(none) }", "attributes #1 = { alwaysinline }"])
        source = output / "original.ll"
        source.write_text("\n\n".join(pieces) + "\n", encoding="utf-8")
        core, boundary = output / "business.ll", output / "boundaries.ll"
        split = nb._isolate_public_boundaries(source, core, boundary, boundaries, self.library,
                                              expected_calls=dict(zip(boundaries, ([name] for name in selected))))
        retained = output / "retained.ll"
        nb._retain_database_scope(core, retained, selected, self.library)
        vm, joined, final = (output / name for name in ("vm.ll", "joined.ll", "final.ll"))
        commands = [
            [toolchain["optimizer"], "-O1", "-kagura-fla", "-kagura-sub", "-kagura-co", "-kagura-vm",
             "-kagura-allow=" + ",".join(selected), "-kagura-seed=1729", "-S", retained, "-o", vm],
            [toolchain["llvm_link"], "-S", vm, boundary, "-o", joined],
            [toolchain["clangxx"], "-target", nb.TARGET, "-O1", "-S", "-emit-llvm", joined, "-o", final],
        ]
        results = []
        for index, argv in enumerate(commands):
            self.assertFalse(stop.exists())
            result = run_logged(list(map(str, argv)), output, output / f"command-{index}", timeout=15, cancel_file=stop)
            results.append(result)
            self.assertEqual(result["returncode"], 0, result)
            self.assertFalse(result["cancelled"] or result["timed_out"])
            self.assertEqual(result["cleanup"]["status"], "assigned_job_empty")
            self.assertEqual(result["cleanup"]["active_after"], 0)
            self.assertTrue(result["cleanup"]["parent_exit_confirmed"] and result["cleanup"]["job_handle_closed"])
        evidence = nb._boundary_transit_evidence(final, split["contract"], self.library)
        self.assertEqual(evidence["status"], "verified")
        virtualized = nb._vm_evidence(final.read_text(encoding="utf-8"), selected, "kagura_vm_execute")
        self.assertEqual(set(virtualized), set(selected))
        self.assertFalse(stop.exists())
        self.assertEqual({path: nb._hash(Path(path)) for path in hashes}, hashes)
        nb._write(output / "evidence.json", {"status": "passed", "target_execution": False,
                  "tool_and_source_hashes": hashes, "commands": results, "boundary_transit": evidence,
                  "contract": split["contract"], "selected_vm": virtualized,
                  "ir_sha256": {path.name: nb._hash(path) for path in (source, core, boundary, retained, vm, joined, final)}})


if __name__ == "__main__":
    unittest.main()
