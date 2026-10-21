import base64
import copy
import json
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch

from antirea.dotnet_frontend import (DotnetFrontendError, analyze_method, decode_il, emit_method,
                                     inspect_project, build_project, reference_cases)


def method(return_type="Int32", parameters=None, locals_=None):
    return {"name": "DifferentAlgorithm", "type": "Demo.Core", "is_static": True, "is_public": True,
            "generic_count": 0, "exception_regions": 0, "calling_convention": "Default",
            "return_type": return_type, "parameters": parameters or ["Int32", "Int32"],
            "locals": locals_ or [], "init_locals": True, "max_stack": 8}


def instructions(*names):
    return [{"offset": i, "next": i + 1, "name": name, "operand": operand}
            for i, (name, operand) in enumerate(names)]


class IlLoweringTests(unittest.TestCase):
    def test_arbitrary_method_arithmetic_is_generated_from_il(self):
        il = instructions(("ldarg.0", None), ("ldarg.1", None), ("mul", None), ("ret", None))
        code, evidence = emit_method(method(), "not_a_fixture_name", il)
        self.assertIn("int32_t not_a_fixture_name", code)
        self.assertIn("s0 * s1", code)
        self.assertIn("0xffffffff", code)
        self.assertEqual(evidence["instruction_count"], 4)

    def test_shift_counts_masked_and_signed_shift_defined(self):
        il = instructions(("ldarg.0", None), ("ldarg.1", None), ("shr", None), ("ret", None))
        code, _ = emit_method(method(), "shifted", il)
        self.assertIn("s1 & 31u", code)
        self.assertIn("s0 ^ UINT64_C(2147483648)", code)
        self.assertIn("- (UINT64_C(2147483648) >>", code)

    def test_signed_comparison_uses_sign_bit_bias(self):
        il = instructions(("ldarg.0", None), ("ldarg.1", None), ("clt", None), ("ret", None))
        code, _ = emit_method(method(), "compare", il)
        self.assertIn("s0 ^ UINT64_C(2147483648)", code)

    def test_unsigned_comparison_has_no_signed_bias(self):
        il = instructions(("ldarg.0", None), ("ldarg.1", None), ("clt.un", None), ("ret", None))
        code, _ = emit_method(method(), "compare", il)
        self.assertIn("s0 < s1", code)

    def test_conversion_sign_extends_i4_to_i8(self):
        il = instructions(("ldarg.0", None), ("conv.i8", None), ("ret", None))
        code, _ = emit_method(method("Int64"), "converted", il)
        self.assertIn("^ UINT64_C(0x80000000)", code)

    def test_conversion_unsigned_extension_and_truncation(self):
        for op, result_type, must, absent in (("conv.u8", "UInt64", "s0 = s0;", "0x80000000"),
                    ("conv.i4", "Int32", "s0 & UINT64_C(0xffffffff)", "0x80000000")):
            with self.subTest(op=op):
                candidate = method(result_type, ["Int64" if op == "conv.i4" else "UInt32"])
                code, _ = emit_method(candidate, "converted", instructions(("ldarg.0", None), (op, None), ("ret", None)))
                self.assertIn(must, code)
                self.assertNotIn(absent, code)

    def test_wrapping_operators_never_emit_signed_arithmetic(self):
        for op in ("add", "sub", "mul", "and", "or", "xor"):
            with self.subTest(op=op):
                code, _ = emit_method(method(), "wrapped", instructions(("ldarg.0", None), ("ldarg.1", None), (op, None), ("ret", None)))
                self.assertIn("uint64_t s0", code)
                self.assertIn("& UINT64_C(0xffffffff)", code)

    def test_shift_bias_formula_covers_negative_values_and_masked_counts(self):
        rng = random.Random(92)
        for width in (32, 64):
            mask, sign = (1 << width) - 1, 1 << (width - 1)
            for bits in [0, 1, mask, sign, sign - 1, sign + 1, *[rng.getrandbits(width) for _ in range(100)]]:
                signed = bits - (1 << width) if bits & sign else bits
                for raw in (0, 1, width-1, width, width+1, -1, -width, 2**31-1, -2**31):
                    count = raw & (width - 1)
                    emitted = (((bits ^ sign) >> count) - (sign >> count)) & mask
                    self.assertEqual(emitted, (signed >> count) & mask)

    def test_same_width_branch_stack_join_supported(self):
        il = instructions(("ldarg.0", None), ("brtrue.s", 4), ("ldc.i4.1", None),
                          ("br.s", 5), ("ldc.i4.2", None), ("ret", None))
        code, evidence = emit_method(method(), "joined", il)
        self.assertIn("goto IL_5", code)
        self.assertEqual(evidence["typed_cfg_nodes"], 6)

    def test_switch_and_loop_cfg_supported(self):
        il = instructions(("ldarg.0", None), ("switch", [4, 6]), ("ldc.i4.0", None), ("ret", None),
                          ("ldc.i4.1", None), ("ret", None), ("ldc.i4.2", None), ("ret", None))
        code, _ = emit_method(method(), "switched", il)
        self.assertIn("if (s0 == 1u) goto IL_6", code)
        loop = instructions(("ldarg.0", None), ("ldc.i4.1", None), ("sub", None), ("starg.s", 0),
                            ("ldarg.0", None), ("brtrue.s", 0), ("ldarg.0", None), ("ret", None))
        self.assertEqual(len(analyze_method(method(), loop)), 8)

    def test_control_flow_merge_requires_identical_stack_types(self):
        il = instructions(("ldarg.0", None), ("brtrue.s", 4), ("ldc.i4.1", None),
                          ("br.s", 5), ("ldc.i8", 1), ("ret", None))
        with self.assertRaisesRegex(DotnetFrontendError, "stack|Return"):
            analyze_method(method(), il)

    def test_unsupported_instructions_fail_without_fallback(self):
        for opcode in ("call", "callvirt", "ldsfld", "add.ovf", "div", "rem.un", "newobj", "localloc", "conv.ovf.i4"):
            with self.subTest(opcode=opcode):
                il = instructions(("ldarg.0", None), ("ldarg.1", None), (opcode, 123), ("ret", None))
                with self.assertRaisesRegex(DotnetFrontendError, "Unsupported IL"):
                    analyze_method(method(), il)

    def test_instance_generic_exception_and_object_signatures_rejected(self):
        il = instructions(("ldarg.0", None), ("ret", None))
        for key, value in (("is_static", False), ("generic_count", 1), ("exception_regions", 1),
                           ("return_type", "Object"), ("parameters", ["Double"])):
            candidate = method()
            candidate[key] = value
            with self.subTest(key=key), self.assertRaises(DotnetFrontendError):
                analyze_method(candidate, il)

    def test_bad_branch_and_underflow_rejected(self):
        for il in (instructions(("br", 9)), instructions(("ret", None))):
            with self.assertRaises(DotnetFrontendError):
                analyze_method(method(), il)

    def test_decode_signed_constants_and_relative_branch(self):
        table = {"31": {"name": "ldc.i4.s", "operand": "ShortInlineI"},
                 "43": {"name": "br.s", "operand": "ShortInlineBrTarget"}}
        il = decode_il(base64.b64encode(bytes([31, 255, 43, 252])).decode(), table)
        self.assertEqual(il[0]["operand"], -1)
        self.assertEqual(il[1]["operand"], 0)

    def test_truncated_and_unknown_opcode_rejected(self):
        with self.assertRaises(DotnetFrontendError):
            decode_il(base64.b64encode(b"\xfe").decode(), {})
        with self.assertRaises(DotnetFrontendError):
            decode_il(base64.b64encode(b"\x00").decode(), {})


class ProjectAndReferenceTests(unittest.TestCase):
    def project(self, directory, **updates):
        source = directory / "Core.cs"
        source.write_text("public static class Core { public static int F(int x) => x+1; }", encoding="utf-8")
        value = {"schema_version": 1, "name": "example", "language": "csharp", "sources": ["Core.cs"],
                 "methods": [{"type": "Core", "name": "F", "export": "exported"}], **updates}
        path = directory / "project.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_inspection_arbitrary_selectors_no_compilation(self):
        with tempfile.TemporaryDirectory() as tmp, patch("antirea.dotnet_frontend._compiler", return_value={"input_hashes": {}}):
            path = self.project(Path(tmp))
            result = inspect_project(path)
            self.assertEqual(result["functions"], ["exported"])
            self.assertEqual(result["methods"][0]["name"], "F")
            self.assertEqual(len(result["input_hashes"]), 2)

    def test_unknown_project_fields_and_external_sources_rejected(self):
        for update in ({"hooks": ["cmd"]}, {"sources": ["../Core.cs"]}, {"sources": ["Other.dll"]},
                       {"methods": [{"type": "Core", "name": "F", "export": "antirea_private"}]}):
            with self.subTest(update=update), tempfile.TemporaryDirectory() as tmp:
                path = self.project(Path(tmp), **update)
                with self.assertRaises(ValueError):
                    inspect_project(path)

    def test_build_rejects_source_outside_workspace_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            path = self.project(root)
            output = workspace / ".runs/new"
            with self.assertRaisesRegex(DotnetFrontendError, "inside"):
                build_project(path, output, workspace_root=workspace)
            self.assertFalse(output.exists())

    def test_random_and_edge_cases_are_unique_and_within_abi(self):
        cases, counts = reference_cases(["Int32", "UInt64"], 8192)
        self.assertEqual(counts["random_unique_cases"], 8192)
        self.assertGreater(counts["edge_cases"], 0)
        self.assertEqual(len(cases), len(set(map(tuple, cases))))
        self.assertIn([-2**31, 2**64-1], cases)
        self.assertTrue(all(-2**31 <= row[0] < 2**31 and 0 <= row[1] < 2**64 for row in cases))
        self.assertEqual(cases, reference_cases(["Int32", "UInt64"], 8192)[0])


if __name__ == "__main__":
    unittest.main()
