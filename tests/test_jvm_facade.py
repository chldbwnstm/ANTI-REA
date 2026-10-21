"""Pure, offline tests for antirea.jvm_facade.

No compiler, target or subprocess runs here: classfiles are assembled in memory
with a tiny fixed-layout writer, so these exercise parsing/generation/checking
logic only. The on-disk core classfiles use a private temporary directory and
are read back exactly as the facade module's bounded authorized reader does.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest

from antirea import jvm_facade as f

BOOT = "antirea/runtime/ProtectedBootstrap"
NC = "antirea/runtime/NativeCore"
OBJECT = "java/lang/Object"
_LOAD_SHORT = {"iload": 26, "lload": 30}  # _0 base opcodes; slot 0..3 adds offset
SAMPLES = Path(__file__).resolve().parents[1] / "samples/multilang"


# --------------------------------------------------------------------------
# Minimal, fixed-layout classfile writer (Java 8 / major 52). Only the tags and
# attributes these tests need; names are ASCII (modified UTF-8 == UTF-8).
# --------------------------------------------------------------------------
class _CP:
    def __init__(self):
        self.pool = []
        self.index = {}

    def _add(self, key, encoded):
        if key in self.index:
            return self.index[key]
        self.pool.append(encoded)
        self.index[key] = len(self.pool)
        return self.index[key]

    def utf8(self, s):
        b = s.encode("utf-8")
        return self._add(("u", s), struct.pack(">BH", 1, len(b)) + b)

    def cls(self, internal):
        return self._add(("c", internal), struct.pack(">BH", 7, self.utf8(internal)))

    def nat(self, name, desc):
        return self._add(("n", name, desc), struct.pack(">BHH", 12, self.utf8(name), self.utf8(desc)))

    def methodref(self, owner, name, desc):
        return self._add(("m", owner, name, desc),
                         struct.pack(">BHH", 10, self.cls(owner), self.nat(name, desc)))

    def fieldref(self, owner, name, desc):
        return self._add(("f", owner, name, desc),
                         struct.pack(">BHH", 9, self.cls(owner), self.nat(name, desc)))


def _assemble(this_internal, access, methods, super_internal=OBJECT, interfaces=(), fields=()):
    """methods: list of (access, name, desc, code_fn(cp)->bytes, max_stack, max_locals)."""
    cp = _CP()
    this_i = cp.cls(this_internal)
    super_i = cp.cls(super_internal) if super_internal else 0
    iface = [cp.cls(x) for x in interfaces]
    field_blobs = [struct.pack(">HHHH", fa, cp.utf8(fn), cp.utf8(fd), 0) for (fa, fn, fd) in fields]
    method_blobs = []
    for (ma, mn, md, code_fn, ms, ml) in methods:
        code = code_fn(cp)
        payload = struct.pack(">HHI", ms, ml, len(code)) + code + struct.pack(">HH", 0, 0)
        attr = struct.pack(">HI", cp.utf8("Code"), len(payload)) + payload
        method_blobs.append(struct.pack(">HHHH", ma, cp.utf8(mn), cp.utf8(md), 1) + attr)
    out = struct.pack(">IHHH", 0xCAFEBABE, 0, 52, len(cp.pool) + 1) + b"".join(cp.pool)
    out += struct.pack(">HHH", access, this_i, super_i)
    out += struct.pack(">H", len(iface)) + b"".join(struct.pack(">H", x) for x in iface)
    out += struct.pack(">H", len(field_blobs)) + b"".join(field_blobs)
    out += struct.pack(">H", len(method_blobs)) + b"".join(method_blobs)
    out += struct.pack(">H", 0)
    return out


def _ctor_code(cp):
    return bytes([0x2a, 0xB7]) + struct.pack(">H", cp.methodref(OBJECT, "<init>", "()V")) + bytes([0xB1])


def _int_leaf(cp):
    return bytes([0x03, 0xAC])  # iconst_0; ireturn


def _long_leaf(cp):
    return bytes([0x09, 0xAD])  # lconst_0; lreturn


def _facade_body(export, loads, native_desc, ret_op):
    def code(cp):
        b = bytes([0xB8]) + struct.pack(">H", cp.methodref(BOOT, "ensureReady", "()V"))
        for (op, slot) in loads:
            b += bytes([_LOAD_SHORT[op] + slot])
        b += bytes([0xB8]) + struct.pack(">H", cp.methodref(NC, "call_" + export, native_desc))
        b += bytes([0xAC if ret_op == "ireturn" else 0xAD])
        return b
    return code


# Root shape shared by the Java/Kotlin sample cores.
ROOTS = [
    ("scramble", "(II)I", "scramble", [("iload", 0), ("iload", 1)], "ireturn"),
    ("blend", "(JJ)J", "blend", [("lload", 0), ("lload", 2)], "lreturn"),
    ("narrow", "(JI)I", "narrow", [("lload", 0), ("iload", 2)], "ireturn"),
]


def _core_bytes():
    methods = [(0x0001, "<init>", "()V", _ctor_code, 1, 1),
               (0x0009, "scramble", "(II)I", _int_leaf, 1, 2),
               (0x0009, "blend", "(JJ)J", _long_leaf, 2, 4),
               (0x0009, "narrow", "(JI)I", _int_leaf, 1, 3),
               (0x000A, "step", "(II)I", _int_leaf, 1, 2)]
    return _assemble("sample/Core", 0x0011, methods)


def _facade_bytes(roots=ROOTS, prefix="java", include_ctor=True, access=0x0011,
                  extra_methods=(), fields=()):
    methods = []
    if include_ctor:
        methods.append((0x0002, "<init>", "()V", _ctor_code, 1, 1))
    for (name, desc, exp, loads, ret) in roots:
        methods.append((0x0009, name, desc, _facade_body(prefix + "_" + exp, loads, desc, ret),
                        4, 4))
    methods.extend(extra_methods)
    return _assemble("sample/Core", access, methods, fields=fields)


def _bootstrap_bytes():
    ret = lambda cp: bytes([0xB1])  # noqa: E731 - trivial `return`
    methods = [(0x0002, "<init>", "()V", _ctor_code, 1, 1),
               (0x0009, "ensureReady", "()V", ret, 0, 0),
               (0x0008, "<clinit>", "()V", ret, 0, 0)]
    return _assemble(BOOT, 0x0011, methods)


def _nativecore_bytes(prefix="java"):
    ret_i = lambda cp: bytes([0x03, 0xAC])  # noqa: E731
    ret_v = lambda cp: bytes([0xB1])        # noqa: E731
    methods = [(0x0002, "<init>", "()V", _ctor_code, 1, 1),
               (0x0009, "nativeLoad", "(Ljava/lang/String;)V", ret_v, 0, 1)]
    for (_n, _d, e, _l, _r) in ROOTS:
        methods.append((0x0009, "call_" + prefix + "_" + e, "()I", ret_i, 1, 0))
    return _assemble(NC, 0x0011, methods)


def _k(internal):
    """Dict key the inspectors require: the class internal name + '.class'."""
    return internal + ".class"


def _deploy_set(facade=None, prefix="java", extra=None):
    out = {_k("sample/Core"): facade if facade is not None else _facade_bytes(prefix=prefix),
           _k(BOOT): _bootstrap_bytes(),
           _k(NC): _nativecore_bytes(prefix)}
    if extra:
        out.update(extra)
    return out


def _app_bytes(refs, this="sample/App", super_internal=OBJECT):
    def main_code(cp):
        for (kind, owner, name, desc) in refs:
            (cp.fieldref if kind == "field" else cp.methodref)(owner, name, desc)
        return bytes([0xB1])
    methods = [(0x0001, "<init>", "()V", _ctor_code, 1, 1),
               (0x0009, "main", "([Ljava/lang/String;)V", main_code, 1, 1)]
    return _assemble(this, 0x0011, methods, super_internal=super_internal)


def _app_entry(refs, this="sample/App", super_internal=OBJECT):
    """One-class app input correctly keyed by internal name + '.class'."""
    return {_k(this): _app_bytes(refs, this=this, super_internal=super_internal)}


def _producer(core_path, core_bytes, language="java", prefix="java"):
    sha = hashlib.sha256(core_bytes).hexdigest()
    selectors = [{"class": "sample.Core", "name": n, "descriptor": d, "export": prefix + "_" + e}
                 for (n, d, e, _l, _r) in ROOTS]
    methods = [{"class": "sample/Core", "name": n, "descriptor": d,
                "export": prefix + "_" + e, "is_root": True} for (n, d, e, _l, _r) in ROOTS]
    methods.append({"class": "sample/Core", "name": "step", "descriptor": "(II)I",
                    "export": "jvm_owned_0123456789abcdef", "is_root": False})
    types = {"scramble": ("i32", ["i32", "i32"]), "blend": ("i64", ["i64", "i64"]),
             "narrow": ("i32", ["i64", "i32"])}
    functions = []
    for (n, _d, e, _l, _r) in ROOTS:
        ret, params = types[n]
        functions.append({"name": prefix + "_" + e, "return_type": ret,
                          "parameters": [{"name": "a%d" % i, "type": t} for i, t in enumerate(params)]})
    contract = {"schema_version": 1, "library_name": prefix + "_app_core",
                "calling_convention": "cdecl", "functions": functions}
    return {"schema_version": 1, "status": "artifact_created_unvalidated",
            "backend": "jvm_bytecode_native", "language": language,
            "project": {"name": prefix + "-app-core", "methods": selectors},
            "methods": methods, "contract": contract,
            "original_classes": {str(core_path): sha}}


class _Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.core = _core_bytes()
        self.core_path = self.tmp / "Core.class"
        self.core_path.write_bytes(self.core)
        self.producer = _producer(self.core_path, self.core)

    def tearDown(self):
        self._tmp.cleanup()


class ReaderTests(_Base):
    def test_reads_identity_super_and_member_refs(self):
        meta = f._read_class(_app_bytes([("method", "sample/Core", "scramble", "(II)I")]))
        self.assertEqual(meta["class_internal"], "sample/App")
        self.assertEqual(meta["super_internal"], OBJECT)
        owners = {(r["owner"], r["name"], r["descriptor"]) for r in meta["member_refs"]}
        self.assertIn(("sample/Core", "scramble", "(II)I"), owners)

    def test_rejects_bad_magic(self):
        with self.assertRaises(f.JvmFacadeError):
            f._read_class(b"\x00\x00\x00\x00nope")


class PlanTests(_Base):
    def test_inventory_and_roots(self):
        plan = f._facade_plan(self.producer)
        self.assertEqual(set(plan["inventory"]), {"sample/Core"})
        self.assertEqual({r["name"] for r in plan["roots"]}, {"scramble", "blend", "narrow"})
        self.assertEqual(len(plan["helpers"]), 1)

    def test_reject_hash_mismatch(self):
        bad = dict(self.producer)
        bad["original_classes"] = {str(self.core_path): "0" * 64}
        with self.assertRaises(f.JvmFacadeError):
            f._facade_plan(bad)

    def test_reject_missing_file(self):
        bad = dict(self.producer)
        bad["original_classes"] = {str(self.tmp / "absent.class"): "a" * 64}
        with self.assertRaises(f.JvmFacadeError):
            f._facade_plan(bad)

    def test_reject_reserved_path(self):
        reserved = self.tmp / "attackerfolder" / "Core.class"
        reserved.parent.mkdir(parents=True)
        reserved.write_bytes(self.core)
        bad = dict(self.producer)
        bad["original_classes"] = {str(reserved): hashlib.sha256(self.core).hexdigest()}
        with self.assertRaises(f.JvmFacadeError):
            f._facade_plan(bad)

    def test_reject_wrong_status_and_backend(self):
        for key, value in (("status", "failed"), ("backend", "other"), ("language", "ruby")):
            bad = dict(self.producer)
            bad[key] = value
            with self.assertRaises(f.JvmFacadeError):
                f._facade_plan(bad)

    def test_reject_contract_abi_mismatch(self):
        bad = json.loads(json.dumps(self.producer))
        bad["contract"]["functions"][0]["return_type"] = "i64"  # scramble must be i32
        with self.assertRaises(f.JvmFacadeError):
            f._facade_plan(bad)

    def test_reject_supplied_core_classes_disagreement(self):
        bad = dict(self.producer)
        bad["core_classes"] = ["sample/Core", "sample/Extra"]
        with self.assertRaises(f.JvmFacadeError):
            f._facade_plan(bad)

    def test_reject_root_not_public_static(self):
        # A core whose "scramble" is private instance would not satisfy a root.
        methods = [(0x0001, "<init>", "()V", _ctor_code, 1, 1),
                   (0x0002, "scramble", "(II)I", _int_leaf, 1, 2),
                   (0x0009, "blend", "(JJ)J", _long_leaf, 2, 4),
                   (0x0009, "narrow", "(JI)I", _int_leaf, 1, 3),
                   (0x000A, "step", "(II)I", _int_leaf, 1, 2)]
        core = _assemble("sample/Core", 0x0011, methods)
        path = self.tmp / "Core2.class"
        path.write_bytes(core)
        with self.assertRaises(f.JvmFacadeError):
            f._facade_plan(_producer(path, core))

    def test_reject_duplicate_report_row(self):
        bad = json.loads(json.dumps(self.producer))
        bad["methods"].append(dict(bad["methods"][0]))  # duplicate the scramble root row
        with self.assertRaises(f.JvmFacadeError):
            f._facade_plan(bad)

    def test_reject_root_export_mismatch(self):
        bad = json.loads(json.dumps(self.producer))
        bad["methods"][0]["export"] = "java_blend"  # root row export != selector export
        with self.assertRaises(f.JvmFacadeError):
            f._facade_plan(bad)

    def test_reject_duplicate_selector_export(self):
        bad = json.loads(json.dumps(self.producer))
        bad["project"]["methods"][2]["export"] = bad["project"]["methods"][0]["export"]
        with self.assertRaises(f.JvmFacadeError):
            f._facade_plan(bad)

    def test_reject_non_bool_is_root(self):
        bad = json.loads(json.dumps(self.producer))
        bad["methods"][0]["is_root"] = 1  # truthy int, not a real bool
        with self.assertRaises(f.JvmFacadeError):
            f._facade_plan(bad)

    def test_reject_unaccounted_core_method(self):
        # A core with an extra public static method not in the closure is rejected.
        methods = [(0x0001, "<init>", "()V", _ctor_code, 1, 1),
                   (0x0009, "scramble", "(II)I", _int_leaf, 1, 2),
                   (0x0009, "blend", "(JJ)J", _long_leaf, 2, 4),
                   (0x0009, "narrow", "(JI)I", _int_leaf, 1, 3),
                   (0x0009, "orphan", "(I)I", _int_leaf, 1, 1),
                   (0x000A, "step", "(II)I", _int_leaf, 1, 2)]
        core = _assemble("sample/Core", 0x0011, methods)
        path = self.tmp / "Core3.class"
        path.write_bytes(core)
        with self.assertRaises(f.JvmFacadeError):
            f._facade_plan(_producer(path, core))

    def test_reject_helper_not_private(self):
        # Core's step is private static; a public step breaks the helper requirement.
        with self.assertRaises(f.JvmFacadeError):
            methods = [(0x0001, "<init>", "()V", _ctor_code, 1, 1),
                       (0x0009, "scramble", "(II)I", _int_leaf, 1, 2),
                       (0x0009, "blend", "(JJ)J", _long_leaf, 2, 4),
                       (0x0009, "narrow", "(JI)I", _int_leaf, 1, 3),
                       (0x0009, "step", "(II)I", _int_leaf, 1, 2)]  # step public
            core = _assemble("sample/Core", 0x0011, methods)
            path = self.tmp / "Core4.class"
            path.write_bytes(core)
            f._facade_plan(_producer(path, core))

    def test_reject_oversized_classfile(self):
        big = self.tmp / "Big.class"
        big.write_bytes(b"\x00" * (f.MAX_CLASS_BYTES + 1))
        bad = dict(self.producer)
        bad["original_classes"] = {str(big): hashlib.sha256(b"x").hexdigest()}
        with self.assertRaises(f.JvmFacadeError):
            f._facade_plan(bad)


class GenerateTests(_Base):
    def test_generate_report_and_files(self):
        out = self.tmp / "out"
        report = f.generate_facades(self.producer, out)
        self.assertEqual(report["status"], f.STATUS_GENERATED)
        self.assertEqual(report["package"], "antirea.runtime")
        self.assertFalse(report["executed"])
        self.assertEqual(report["native_exports"], ["java_scramble", "java_blend", "java_narrow"])
        self.assertEqual(report["replaced_core_classes"], ["sample/Core"])
        inv = {c["internal_name"]: c for c in report["class_inventory"]}
        self.assertTrue(inv["sample/Core"]["same_relative_class_path"])
        self.assertTrue(inv["sample/Core"]["original_bytes_must_be_absent"])
        self.assertEqual(inv["sample/Core"]["original_sha256"], hashlib.sha256(self.core).hexdigest())
        # The persisted facades.json equals the returned report.
        saved = json.loads((out / "facades.json").read_text(encoding="utf-8"))
        self.assertEqual(saved, report)
        self.assertEqual(sorted(report["expected_deploy_classes"]),
                         ["antirea.runtime.NativeCore", "antirea.runtime.ProtectedBootstrap", "sample.Core"])
        facade = (out / "java/sample/Core.java").read_text(encoding="utf-8")
        self.assertIn("public final class Core {", facade)
        self.assertIn("antirea.runtime.ProtectedBootstrap.ensureReady();", facade)
        self.assertIn("antirea.runtime.NativeCore.call_java_narrow(p0, p1)", facade)
        self.assertIn("public static int narrow(long p0, int p1)", facade)
        self.assertTrue((out / "java/antirea/runtime/ProtectedBootstrap.java").is_file())
        self.assertTrue((out / "java/antirea/runtime/NativeCore.java").is_file())
        self.assertTrue((out / "jni/adapter.c").is_file())
        self.assertTrue((out / "facades.json").is_file())
        adapter = (out / "jni/adapter.c").read_text(encoding="utf-8")
        self.assertIn("Java_antirea_runtime_NativeCore_nativeLoad", adapter)
        self.assertNotIn("Java_NativeCore_", adapter)
        bootstrap = (out / "java/antirea/runtime/ProtectedBootstrap.java").read_text(encoding="utf-8")
        self.assertIn("ANTIREA_JNI_ADAPTER", bootstrap)
        self.assertIn("ANTIREA_NATIVE_CORE", bootstrap)

    def test_reject_existing_output_dir(self):
        out = self.tmp / "exists"
        out.mkdir()
        with self.assertRaises(f.JvmFacadeError):
            f.generate_facades(self.producer, out)

    def test_reject_reserved_output_dir(self):
        with self.assertRaises(f.JvmFacadeError):
            f.generate_facades(self.producer, self.tmp / "rea-analysis-reports" / "out")

    def test_generated_facade_passes_its_own_validation(self):
        # Independent deploy set with the exact expected shape validates clean.
        result = f.validate_facade_classes(_deploy_set(), self.producer)
        self.assertEqual(result["status"], f.STATUS_FACADE_VALID, result["violations"])


class InspectTests(_Base):
    def test_accept_app_that_only_calls_roots(self):
        app = _app_entry([("method", "sample/Core", "scramble", "(II)I"),
                          ("method", "sample/Core", "blend", "(JJ)J"),
                          ("method", "sample/Core", "narrow", "(JI)I")])
        result = f.inspect_application_classes(app, self.producer)
        self.assertEqual(result["status"], f.STATUS_APP_OK, result["violations"])
        self.assertEqual(result["status"], "accepted")

    def test_reject_constructor_reference(self):
        result = f.inspect_application_classes(
            _app_entry([("method", "sample/Core", "<init>", "()V")]), self.producer)
        self.assertEqual(result["status"], "rejected")
        self.assertTrue(any(v["kind"] == "member_reference" for v in result["violations"]))

    def test_reject_private_helper_reference(self):
        result = f.inspect_application_classes(
            _app_entry([("method", "sample/Core", "step", "(II)I")]), self.producer)
        self.assertEqual(result["status"], "rejected")

    def test_reject_field_reference(self):
        result = f.inspect_application_classes(
            _app_entry([("field", "sample/Core", "SECRET", "I")]), self.producer)
        self.assertEqual(result["status"], "rejected")
        self.assertTrue(any(v["kind"] == "field_reference" for v in result["violations"]))

    def test_reject_inheritance_from_core(self):
        result = f.inspect_application_classes(
            _app_entry([("method", "sample/Core", "scramble", "(II)I")], super_internal="sample/Core"),
            self.producer)
        self.assertEqual(result["status"], "rejected")
        self.assertTrue(any(v["kind"] == "inheritance" for v in result["violations"]))

    def test_reject_core_identity_collision(self):
        result = f.inspect_application_classes(
            _app_entry([("method", OBJECT, "<init>", "()V")], this="sample/Core"), self.producer)
        self.assertEqual(result["status"], "rejected")
        self.assertTrue(any(v["kind"] == "identity" for v in result["violations"]))

    def test_reject_reference_into_runtime_namespace(self):
        result = f.inspect_application_classes(
            _app_entry([("method", "antirea/runtime/ProtectedBootstrap", "ensureReady", "()V")]),
            self.producer)
        self.assertEqual(result["status"], "rejected")
        self.assertTrue(any(v["kind"] == "reserved_namespace" for v in result["violations"]))

    def test_reject_app_declared_in_runtime_namespace(self):
        result = f.inspect_application_classes(
            _app_entry([("method", OBJECT, "<init>", "()V")], this="antirea/runtime/Sneaky"), self.producer)
        self.assertEqual(result["status"], "rejected")
        self.assertTrue(any(v["kind"] == "reserved_namespace" for v in result["violations"]))

    def test_reject_wrong_dictionary_key(self):
        # Correct bytes under an alias key (not internal name + .class) is rejected.
        app = _app_bytes([("method", "sample/Core", "scramble", "(II)I")])
        result = f.inspect_application_classes({"wrong/Alias.class": app}, self.producer)
        self.assertEqual(result["status"], "rejected")
        self.assertTrue(any(v["kind"] == "key_identity" for v in result["violations"]))

    def test_reject_duplicate_app_identity(self):
        app = _app_bytes([("method", OBJECT, "<init>", "()V")])  # internal sample/App
        result = f.inspect_application_classes(
            {"sample/App.class": app, "alias/App.class": app}, self.producer)
        self.assertEqual(result["status"], "rejected")
        self.assertTrue(any(v["kind"] == "duplicate_identity" for v in result["violations"]))


class ValidateTests(_Base):
    def test_accept_exact_deploy_set(self):
        result = f.validate_facade_classes(_deploy_set(), self.producer)
        self.assertEqual(result["status"], f.STATUS_FACADE_VALID, result["violations"])
        self.assertEqual(result["status"], "accepted")

    def test_reject_missing_facade_class(self):
        # Runtime classes present but the facade class absent.
        result = f.validate_facade_classes(
            {_k(BOOT): _bootstrap_bytes(), _k(NC): _nativecore_bytes()}, self.producer)
        self.assertEqual(result["status"], "rejected")
        self.assertTrue(any(v["kind"] == "missing_class" and v["class"] == "sample/Core"
                            for v in result["violations"]))

    def test_reject_missing_runtime_classes(self):
        result = f.validate_facade_classes({_k("sample/Core"): _facade_bytes()}, self.producer)
        self.assertEqual(result["status"], "rejected")
        kinds = {(v["kind"], v.get("class")) for v in result["violations"]}
        self.assertIn(("missing_class", BOOT), kinds)
        self.assertIn(("missing_class", NC), kinds)

    def test_reject_unexpected_extra_class(self):
        extra = {_k("sample/Extra"): _app_bytes([("method", OBJECT, "<init>", "()V")], this="sample/Extra")}
        result = f.validate_facade_classes(_deploy_set(extra=extra), self.producer)
        self.assertEqual(result["status"], "rejected")
        self.assertTrue(any(v["kind"] == "unexpected_class" for v in result["violations"]))

    def test_reject_wrong_dictionary_key(self):
        # Exact facade bytes under an alias key (not internal + .class) is rejected.
        bad = _deploy_set()
        bad["sample/Alias.class"] = bad.pop(_k("sample/Core"))
        result = f.validate_facade_classes(bad, self.producer)
        self.assertEqual(result["status"], "rejected")
        self.assertTrue(any(v["kind"] == "key_identity" for v in result["violations"]))

    def test_reject_non_final_class(self):
        result = f.validate_facade_classes(_deploy_set(facade=_facade_bytes(access=0x0001)), self.producer)
        self.assertEqual(result["status"], f.STATUS_FACADE_INVALID)
        self.assertTrue(any(v["kind"] == "class_flags" for v in result["violations"]))

    def test_reject_field_present(self):
        result = f.validate_facade_classes(
            _deploy_set(facade=_facade_bytes(fields=[(0x000A, "cache", "I")])), self.producer)
        self.assertEqual(result["status"], f.STATUS_FACADE_INVALID)
        self.assertTrue(any(v["kind"] == "fields" for v in result["violations"]))

    def test_reject_missing_constructor(self):
        result = f.validate_facade_classes(_deploy_set(facade=_facade_bytes(include_ctor=False)), self.producer)
        self.assertEqual(result["status"], f.STATUS_FACADE_INVALID)
        self.assertTrue(any(v["kind"] == "constructor" for v in result["violations"]))

    def test_reject_unexpected_method(self):
        extra = [(0x0009, "backdoor", "()I", _int_leaf, 1, 0)]
        result = f.validate_facade_classes(
            _deploy_set(facade=_facade_bytes(extra_methods=extra)), self.producer)
        self.assertEqual(result["status"], f.STATUS_FACADE_INVALID)
        self.assertTrue(any(v["kind"] == "unexpected_method" for v in result["violations"]))

    def test_reject_static_initializer(self):
        clinit = [(0x0008, "<clinit>", "()V", lambda cp: bytes([0xB1]), 0, 0)]
        result = f.validate_facade_classes(
            _deploy_set(facade=_facade_bytes(extra_methods=clinit)), self.producer)
        self.assertEqual(result["status"], f.STATUS_FACADE_INVALID)
        self.assertTrue(any(v["kind"] == "static_initializer" for v in result["violations"]))

    def test_reject_non_forwarding_body(self):
        # scramble body is a constant return, not bootstrap+native forwarding.
        methods = [(0x0002, "<init>", "()V", _ctor_code, 1, 1),
                   (0x0009, "scramble", "(II)I", _int_leaf, 1, 2),
                   (0x0009, "blend", "(JJ)J", _facade_body("java_blend", [("lload", 0), ("lload", 2)], "(JJ)J", "lreturn"), 4, 4),
                   (0x0009, "narrow", "(JI)I", _facade_body("java_narrow", [("lload", 0), ("iload", 2)], "(JI)I", "ireturn"), 4, 4)]
        core = _assemble("sample/Core", 0x0011, methods)
        result = f.validate_facade_classes(_deploy_set(facade=core), self.producer)
        self.assertEqual(result["status"], f.STATUS_FACADE_INVALID)
        self.assertTrue(any(v["kind"] == "method_body" for v in result["violations"]))

    def test_reject_missing_root_method(self):
        result = f.validate_facade_classes(_deploy_set(facade=_facade_bytes(roots=ROOTS[:2])), self.producer)
        self.assertEqual(result["status"], f.STATUS_FACADE_INVALID)
        self.assertTrue(any(v["kind"] == "missing_method" for v in result["violations"]))

    def test_reject_wrong_native_target(self):
        # Forward to a different native call name than the plan expects.
        wrong = [("scramble", "(II)I", "WRONG", [("iload", 0), ("iload", 1)], "ireturn"),
                 ("blend", "(JJ)J", "blend", [("lload", 0), ("lload", 2)], "lreturn"),
                 ("narrow", "(JI)I", "narrow", [("lload", 0), ("iload", 2)], "ireturn")]
        result = f.validate_facade_classes(_deploy_set(facade=_facade_bytes(roots=wrong)), self.producer)
        self.assertEqual(result["status"], f.STATUS_FACADE_INVALID)
        self.assertTrue(any(v["kind"] == "method_body" for v in result["violations"]))


class SampleFixtureTests(unittest.TestCase):
    """Fixture-shape regression guards ONLY (not functional coverage): the sample
    cores must bound scramble's loop so full-width int32 scalar validation is
    finite, and the app contracts must list a protected-reaching case first."""

    def test_java_core_bounds_scramble_loop(self):
        src = (SAMPLES / "java_application/Core.java").read_text(encoding="utf-8")
        self.assertIn("rounds & 7", src)
        self.assertIn("i <= limit", src)

    def test_kotlin_core_bounds_scramble_loop(self):
        src = (SAMPLES / "kotlin_application/Core.kt").read_text(encoding="utf-8")
        self.assertIn("rounds and 7", src)
        self.assertIn("i <= limit", src)

    def test_contracts_start_with_one_round_then_zero_rounds(self):
        for lang in ("java_application", "kotlin_application"):
            cases = json.loads((SAMPLES / lang / "application-contract.json")
                               .read_text(encoding="utf-8"))["cases"]
            self.assertEqual([c["label"] for c in cases[:2]], ["one-round", "zero-rounds"])


if __name__ == "__main__":
    unittest.main()
