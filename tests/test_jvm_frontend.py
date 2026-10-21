import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from antirea.jvm_frontend import (JvmFrontendError, _run, analyze_method, build_project, decode_code,
    decode_modified_utf8, descriptor, emit_method, inspect_project, parse_class, resolve_closure,
    stack_permutation, verify_build)


def method(code=b"\x1a\x1b\x60\xac", desc="(II)I", *, locals_=2, stack=4, name="sum", flags=9):
    return {"class": "Demo", "name": name, "descriptor": desc, "access": flags,
            "code": code.hex(), "max_stack": stack, "max_locals": locals_, "exception_regions": 0}


def classfile(*, code=b"\x1a\x1b\x60\xac", method_name="sum", fields=0, major=65):
    entries = [b"\x01\x00\x04Demo", b"\x07\x00\x01", b"\x01\x00\x10java/lang/Object",
               b"\x07\x00\x03", b"\x01"+struct.pack(">H",len(method_name))+method_name.encode(),
               b"\x01\x00\x05(II)I", b"\x01\x00\x04Code"]
    data = struct.pack(">IHHH", 0xcafebabe, 0, major, 8)+b"".join(entries)
    data += struct.pack(">HHHHHH", 0x21, 2, 4, 0, fields, 1)
    body = struct.pack(">HHI", 4, 2, len(code))+code+struct.pack(">HH", 0, 0)
    data += struct.pack(">HHHHHI", 9, 5, 6, 1, 7, len(body))+body+struct.pack(">H", 0)
    return data


class ClassfileTests(unittest.TestCase):
    def test_binary_classfile_parsed_without_target_execution(self):
        parsed = parse_class(classfile())
        self.assertEqual(parsed["class"], "Demo")
        self.assertEqual(parsed["methods"][0]["descriptor"], "(II)I")
        self.assertEqual(parsed["methods"][0]["max_locals"], 2)

    def test_malformed_magic_length_and_trailing_bytes_rejected(self):
        for data in (b"bad", classfile()[:-1], classfile()+b"extra", classfile(major=66)):
            with self.subTest(length=len(data)), self.assertRaises(JvmFrontendError):
                parse_class(data)

    def test_fields_and_initializers_fail_closed(self):
        for data in (classfile(fields=1), classfile(method_name="<clinit>")):
            with self.assertRaises(JvmFrontendError):
                parse_class(data)

    def test_modified_utf8_nul_unicode_and_supplementary_pair(self):
        self.assertEqual(decode_modified_utf8(b"A\xc0\x80B"), "A\0B")
        self.assertEqual(decode_modified_utf8("한글".encode()), "한글")
        self.assertEqual(decode_modified_utf8(b"\xed\xa0\xbd\xed\xb8\x80"), "😀")
        self.assertEqual(decode_modified_utf8(b"\xed\xa0\x80"), "\ud800")

    def test_modified_utf8_rejects_standard_nul_fourbyte_and_overlong(self):
        for value in (b"\0", b"\xf0\x9f\x98\x80", b"\xc0\x81", b"\xe0\x80\x80", b"\xc2", b"\xc2A"):
            with self.subTest(value=value), self.assertRaises(JvmFrontendError):
                decode_modified_utf8(value)

    def test_descriptor_int_long_only(self):
        self.assertEqual(descriptor("(JIJ)J"), (["J", "I", "J"], "J"))
        for value in ("(Z)I", "(F)I", "(Ljava/lang/Object;)I", "([I)I", "()V", "(IIIIIIIII)I"):
            with self.subTest(value=value), self.assertRaises(JvmFrontendError):
                descriptor(value)


class BytecodeTests(unittest.TestCase):
    def emit(self, m):
        return emit_method(m, decode_code(m, [None]), "arbitrary_export", {})[1]

    def test_arbitrary_integer_bytecode_generates_wrapping_unsigned_math(self):
        code = self.emit(method())
        self.assertIn("int32_t arbitrary_export", code)
        self.assertIn("uint64_t s0", code)
        self.assertIn("s0 + s1", code)
        self.assertIn("0xffffffff", code)

    def test_long_arguments_use_two_local_slots(self):
        m = method(b"\x1e\x20\x61\xad", "(JJ)J", locals_=4)
        code = self.emit(m)
        self.assertIn("l2 = (uint64_t)(uint64_t)p1", code)
        self.assertIn("s1 = l2", code)
        self.assertNotIn("int32_t arbitrary_export", code)

    def test_category2_tail_slot_cannot_be_loaded(self):
        m = method(b"\x1f\xad", "(J)J", locals_=2)
        with self.assertRaises(JvmFrontendError):
            analyze_method(m, decode_code(m, [None]))

    def test_store_into_long_tail_invalidates_long_head(self):
        m = method(b"\x03\x3c\x1e\xad", "(J)J", locals_=2)
        with self.assertRaisesRegex(JvmFrontendError, "local load"):
            analyze_method(m, decode_code(m, [None]))

    def test_long_stack_slot_budget_not_value_count(self):
        m = method(b"\x1e\xad", "(J)J", locals_=2, stack=1)
        with self.assertRaisesRegex(JvmFrontendError, "category-slot"):
            analyze_method(m, decode_code(m, [None]))

    def test_iinc_signed_constant_and_wide_local_index(self):
        m = method(b"\xc4\x84\x00\x00\xff\x80\x1a\xac")
        code = decode_code(m, [None])
        self.assertEqual(code[0]["operand"], (0, -128))
        self.assertIn("4294967168", emit_method(m, code, "incremented", {})[1])

    def test_signed_and_unsigned_shifts_are_distinct_and_masked(self):
        signed = self.emit(method(b"\x1a\x1b\x7a\xac"))
        unsigned = self.emit(method(b"\x1a\x1b\x7c\xac"))
        self.assertIn("s1 & 31u", signed)
        self.assertIn("^ UINT64_C(2147483648)", signed)
        self.assertNotIn("^ UINT64_C(2147483648)", unsigned)
        wide = self.emit(method(b"\x1e\x1c\x7b\xad", "(JI)J", locals_=3))
        self.assertIn("s1 & 63u", wide)

    def test_int_to_long_sign_extension_and_long_to_int_truncation(self):
        self.assertIn("0x80000000", self.emit(method(b"\x1a\x85\xad", "(I)J", locals_=1)))
        self.assertIn("0xffffffff", self.emit(method(b"\x1e\x88\xac", "(J)I", locals_=2)))

    def test_byte_short_and_char_narrowing(self):
        for opcode, fragment in ((145, "255u"), (147, "65535u"), (146, "s0 & 65535u")):
            with self.subTest(opcode=opcode):
                self.assertIn(fragment, self.emit(method(bytes([26, opcode, 172]))))

    def test_long_comparison_produces_signed_int_result(self):
        code = self.emit(method(b"\x1e\x20\x94\xac", "(JJ)I", locals_=4))
        self.assertIn("UINT64_C(0xffffffff)", code)
        self.assertIn("UINT64_C(9223372036854775808)", code)

    def test_category_stack_operations_all_forms(self):
        cases = [
            ("dup", [32], [0, 0]), ("dup2", [64], [0, 0]), ("dup2", [32,32], [0,1,0,1]),
            ("dup_x1", [32,32], [1,0,1]), ("dup_x2", [64,32], [1,0,1]),
            ("dup_x2", [32,32,32], [2,0,1,2]), ("dup2_x1", [32,64], [1,0,1]),
            ("dup2_x1", [32,32,32], [1,2,0,1,2]), ("dup2_x2", [64,64], [1,0,1]),
            ("dup2_x2", [32,32,64], [2,0,1,2]), ("dup2_x2", [64,32,32], [1,2,0,1,2]),
            ("dup2_x2", [32,32,32,32], [2,3,0,1,2,3]), ("swap", [32,32], [1,0]),
            ("pop2", [32,64], [0]), ("pop2", [64,32,32], [0]),
        ]
        for name, stack, expected in cases:
            with self.subTest(name=name, stack=stack):
                self.assertEqual(stack_permutation(name, stack), expected)

    def test_invalid_category_stack_operations_rejected(self):
        for name, stack in (("dup", [64]), ("pop", [64]), ("swap", [32,64]), ("dup2", [64,32]), ("dup_x1", [32])):
            with self.subTest(name=name), self.assertRaises(JvmFrontendError):
                stack_permutation(name, stack)

    def test_signed_relative_branch_offsets(self):
        m = method(b"\x1a\x99\x00\x05\x04\xac\x03\xac")
        code = decode_code(m, [None])
        self.assertEqual(code[1]["operand"], 6)
        self.assertEqual(len(analyze_method(m, code)), 6)
        self.assertIn("BC_6", emit_method(m, code, "branch", {})[1])

    def test_branch_into_instruction_and_uninitialized_local_rejected(self):
        for m in (method(b"\x10\x05\xa7\xff\xff"), method(b"\x1c\xac", locals_=3)):
            with self.assertRaises(JvmFrontendError):
                analyze_method(m, decode_code(m, [None]))

    def test_tableswitch_alignment_and_default(self):
        code = bytes([26,170,0,0])+struct.pack(">iiii", 23, 0, 0, 23)+bytes([0,0,0,0,3,172])
        m = method(code)
        decoded = decode_code(m, [None])
        self.assertEqual(decoded[1]["operand"], {"default":24, "pairs":[(0,24)]})
        malformed = bytearray(code); malformed[2] = 1
        with self.assertRaises(JvmFrontendError):
            decode_code(method(bytes(malformed)), [None])

    def test_unsupported_external_object_exception_and_division_bytecodes(self):
        for opcode in (108,109,112,113,178,180,181,182,183,185,186,187,188,191,194,195):
            with self.subTest(opcode=opcode), self.assertRaises(JvmFrontendError):
                decode_code(method(bytes([opcode])), [None])

    def test_synchronized_native_instance_handlers_rejected(self):
        for flag in (1, 9|0x20, 9|0x100, 9|0x400):
            m = method(flags=flag)
            with self.subTest(flag=flag), self.assertRaises(JvmFrontendError):
                analyze_method(m, decode_code(m, [None]))
        m = method(); m["exception_regions"] = 1
        with self.assertRaises(JvmFrontendError):
            analyze_method(m, decode_code(m, [None]))


class ClosureTests(unittest.TestCase):
    def graph(self, target_class="Demo", recursive=False):
        cp = [None,(1,target_class),(7,1),(1,"sum" if recursive else "helper"),(1,"(II)I"),(12,3,4),(10,2,5)]
        root = method(b"\x1a\x1b\xb8\x00\x06\xac")
        helper = method(name="helper", flags=10)
        return [{"class":"Demo","constant_pool":cp,"methods":[root,helper]}], [{"class":"Demo","name":"sum","descriptor":"(II)I","export":"public_sum"}]

    def test_owned_private_helper_included_and_C_calling_convention_preserved(self):
        selected, symbols, roots = resolve_closure(*self.graph())
        self.assertEqual(len(selected), 2)
        key = ("Demo","helper","(II)I")
        self.assertTrue(symbols[key].startswith("jvm_owned_"))
        self.assertNotIn(key, roots)
        m, code = selected[key]
        proto = emit_method(m,code,symbols[key],symbols,internal=True)[0]
        self.assertNotIn("static ", proto)
        self.assertIn("__declspec(noinline)",proto)

    def test_external_and_recursive_helpers_fail_closed(self):
        for graph in (self.graph(target_class="External"), self.graph(recursive=True)):
            with self.assertRaises(JvmFrontendError):
                resolve_closure(*graph)

    def test_private_roots_rejected(self):
        classes, roots = self.graph()
        classes[0]["methods"][0]["access"] = 10
        with self.assertRaises(JvmFrontendError):
            resolve_closure(classes,roots)


class ProjectTests(unittest.TestCase):
    def fixture(self, directory, **changes):
        data = {"schema_version":1,"name":"owned-test","language":"java","sources":["Core.java"],
                "methods":[{"class":"Demo","name":"sum","descriptor":"(II)I","export":"public_sum"}], **changes}
        path = directory / "project.json"
        path.write_text(json.dumps(data),encoding="utf-8")
        (directory / "Core.java").write_text("public class Core {}",encoding="utf-8")
        return path

    def test_inspection_does_not_run_compiler(self):
        with tempfile.TemporaryDirectory() as tmp, patch("antirea.jvm_frontend._compiler",return_value={"input_hashes":{},"blockers":[]}):
            path = self.fixture(Path(tmp))
            result = inspect_project(path)
            self.assertEqual(result["functions"],["public_sum"])
            self.assertEqual(result["route_status"],"available")

    def test_unknown_fields_hooks_duplicate_exports_and_escape_rejected(self):
        changes = [{"hooks":["cmd"]},{"sources":["../Core.java"]},
                   {"methods":[{"class":"Demo","name":"sum","descriptor":"(II)I","export":"jvm_owned_secret"}]}]
        for change in changes:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(ValueError):
                    inspect_project(self.fixture(Path(tmp),**change))

    def test_kotlin_missing_toolchain_is_explicit_blocker(self):
        with tempfile.TemporaryDirectory() as tmp, patch("antirea.jvm_frontend._compiler",return_value={"input_hashes":{},"blockers":["kotlin_portable_compiler_not_configured"]}):
            root = Path(tmp)
            (root / "Core.kt").write_text("fun sum(x:Int,y:Int)=x+y",encoding="utf-8")
            result = inspect_project(self.fixture(root,language="kotlin",sources=["Core.kt"]))
            self.assertEqual(result["route_status"],"unsupported")
            self.assertTrue(result["blockers"])

    def test_workspace_boundary_checked_before_writing_or_compiling(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); workspace = root / "workspace"; workspace.mkdir()
            path = self.fixture(root)
            output = workspace / ".runs/build"
            with self.assertRaisesRegex(JvmFrontendError,"explicit workspace"):
                build_project(path,output,workspace_root=workspace)
            self.assertFalse(output.exists())

    def test_verification_bounds_reject_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for kwargs in ({"random_cases":0},{"random_cases":True},{"timeout_seconds":0},{"timeout_seconds":601}):
                with self.subTest(kwargs=kwargs), self.assertRaises(JvmFrontendError):
                    verify_build(root/".runs/report.json",root/".runs/output",workspace_root=root,**kwargs)

    def test_ambient_java_injection_options_are_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); stdout=root/"stdout"; stdout.write_text("metadata",encoding="utf-8")
            result={"returncode":0,"stdout":str(stdout),"stderr":"none",
                    "cleanup":{"status":"assigned_job_empty","job_handle_closed":True}}
            ambient={key:"malicious-options" for key in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH")}
            with patch.dict(os.environ,ambient), patch("antirea.jvm_frontend.run_logged",return_value=result) as run:
                self.assertEqual(_run(["java"],root,{"commands":[]},root/"STOP"),"metadata")
                self.assertFalse(set(ambient)&set(run.call_args.kwargs["env"]))


if __name__ == "__main__":
    unittest.main()
