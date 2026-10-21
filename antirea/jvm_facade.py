"""Pure Java/Kotlin facade generation and classfile inspection for owned-app integration.

This module never executes: it parses classfile bytes, generates Java/JNI *source*,
and checks bytes. It is not a JVM, not a whole-language promise, and it preserves
neither Kotlin @Metadata nor reflection. A protected deployment substitutes
same-name Java facade classes that forward each original public static int/long
root to the packaged protected native core via JNI; the ordinary application
bytecode is preserved unchanged and keeps calling the same binary identities.

Boundaries (see docs and the phase brief):
  * Only separated pure-scalar cores already accepted by ``jvm_frontend`` are
    supported, plus ordinary application classes that reference nothing of the
    core except its selected public static roots.
  * Generation reuses the fixed ``bindings`` pure generator; the generated
    ``NativeCore`` is pinned to the trusted package ``antirea.runtime`` and its
    JNI entry-point symbols are renamed consistently.  No user-controlled JNI
    paths, runtime jars, link flags or build hooks are produced here.
  * The original core classfiles are read only as a bounded, authorized,
    read-only inventory: a lexical reserved-path guard, a no-links resolve and an
    exact SHA-256 match against the producer report, then a strict parse.  No
    class is loaded or executed.  Missing or inconsistent evidence is rejected.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re

from . import bindings
from . import jvm_frontend
from . import native_build


class JvmFacadeError(ValueError):
    """Raised for malformed input or missing/inconsistent build evidence.

    Policy violations found while *inspecting* application classes or
    *validating* compiled facades are reported as ``status == "rejected"`` with a
    ``violations`` list, not raised; this exception is reserved for input that
    cannot be trusted enough to continue (bad producer report, hash mismatch,
    reserved path, truncated constant pool, ...).
    """


PACKAGE = "antirea.runtime"
PACKAGE_INTERNAL = "antirea/runtime"
BOOTSTRAP_CLASS = PACKAGE + ".ProtectedBootstrap"
BOOTSTRAP_INTERNAL = PACKAGE_INTERNAL + "/ProtectedBootstrap"
NATIVECORE_CLASS = PACKAGE + ".NativeCore"
NATIVECORE_INTERNAL = PACKAGE_INTERNAL + "/NativeCore"
ENV_ADAPTER = "ANTIREA_JNI_ADAPTER"
ENV_CORE = "ANTIREA_NATIVE_CORE"

# Attacker-supplied / forbidden directory names that must never be read here.
RESERVED_PARTS = {"rea-analysis-reports", "attackerfolder", "env.setting", "linkrepro"}

MAX_CLASS_BYTES = 4 * 1024 * 1024
MAX_CORE_CLASSES = 128
MAX_APP_CLASSES = 128
MAX_METHOD_BYTES = 65535

# Descriptor letters are restricted to the frontend's int/long subset.
DESC_TO_ABI = {"I": "i32", "J": "i64"}
JAVA_TYPE = {"i32": "int", "i64": "long"}
RET_OPCODE = {"I": "ireturn", "J": "lreturn"}
LOAD_OPCODE = {"I": "iload", "J": "lload"}

ACC_PUBLIC, ACC_PRIVATE, ACC_STATIC, ACC_FINAL = 0x0001, 0x0002, 0x0008, 0x0010

# Supported class identities: dotted/slashed ASCII segments, no nested/dollar
# names (initially rejected), and never inside the reserved runtime package.
SAFE_CLASS = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:/[A-Za-z_][A-Za-z0-9_]*)*\Z")

# Fixed status strings per .runs/phase21-root/decisions.md (07:34 UTC): the
# single engine contract is the facade's implemented shape - generator
# `generated_not_validated`; both validators `accepted`/`rejected` with
# `violations`. Non-negotiable; the engine adapts to exactly this.
STATUS_GENERATED = "generated_not_validated"
STATUS_APP_OK = "accepted"
STATUS_APP_REJECTED = "rejected"
STATUS_FACADE_VALID = "accepted"
STATUS_FACADE_INVALID = "rejected"

GENERATION_LIMITATIONS = [
    "Experimental: same-name Java facades for public static int/long roots only; "
    "no objects, arrays, fields, inheritance, interfaces, exceptions or dynamic calls.",
    "Facades forward to the packaged protected native core; they are not the original algorithm "
    "and carry no original or helper bytecode, constants or classfiles.",
    "Kotlin cores are substituted at the same binary method identities only; @Metadata, "
    "reflection and downstream Kotlin recompilation of the bundle are NOT preserved or claimed.",
    "Reflection or dynamic name construction in the application cannot be proven absent and is "
    "outside this contract; this is not general JVM API equivalence.",
    "Generation does not compile, execute, download or publish; actual toolchain, load and "
    "behavior results belong to separate harnessed verification, not inferred from source.",
    "Windows x64 only, matching the pinned native builder and JNI adapter.",
]
INSPECTION_LIMITATIONS = [
    "Static reference check only: the application constant pool must reference nothing of the "
    "core except its selected public static roots (no constructors, helpers, non-root members or fields).",
    "Reflection and dynamically constructed names are not detected and are outside the contract.",
    "Acceptance is a bounded structural check, not functional equivalence or attack resistance.",
]
VALIDATION_LIMITATIONS = [
    "Validates that every facade body is exactly bootstrap+native-forwarding for the expected "
    "descriptor, by decoded opcode sequence and resolved call targets, not by method name.",
    "A facade class may contain only its roots and a trivial private constructor; any other "
    "member, field, interface, non-Object superclass or static initializer is rejected.",
    "This checks the compiled facade shape only; it is not functional equivalence or attack resistance.",
]

__all__ = [
    "JvmFacadeError", "generate_facades", "inspect_application_classes",
    "validate_facade_classes", "PACKAGE", "ENV_ADAPTER", "ENV_CORE",
]


def _self_hash() -> str:
    return native_build._hash(Path(__file__).resolve())


# --------------------------------------------------------------------------
# Bounded, read-only classfile metadata reader (independent of the strict
# jvm_frontend parser, which it must not weaken).  It reads ordinary
# application classes and compiled facades; it never loads or executes a class.
# The constant-pool layout mirrors jvm_frontend's so the shared read-only
# helpers (``method_ref``) resolve call targets against it.
# --------------------------------------------------------------------------
def _collect_attrs(reader, text):
    result = {}
    for _ in range(reader.number("H")):
        name = text(reader.number("H"))
        payload = reader.take(reader.number("I"))
        result.setdefault(name, payload)
    return result


def _skip_attrs(reader, text):
    for _ in range(reader.number("H")):
        reader.number("H")
        reader.take(reader.number("I"))


def _read_class(data) -> dict:
    if not isinstance(data, (bytes, bytearray)):
        raise JvmFacadeError("classfile data must be bytes")
    data = bytes(data)
    if not 1 <= len(data) <= MAX_CLASS_BYTES:
        raise JvmFacadeError("classfile is empty or exceeds 4 MiB")
    r = jvm_frontend.Reader(data)
    if r.number("I") != 0xCAFEBABE:
        raise JvmFacadeError("invalid classfile magic")
    minor, major = r.number("H"), r.number("H")
    if not 45 <= major <= 65:
        raise JvmFacadeError("unsupported classfile major version")
    count = r.number("H")
    if not 1 <= count <= 65535:
        raise JvmFacadeError("invalid constant pool count")
    cp, index = [None] * count, 1
    while index < count:
        tag = r.number("B")
        if tag == 1:
            entry = (tag, jvm_frontend.decode_modified_utf8(r.take(r.number("H"))))
        elif tag in (3, 4):
            entry = (tag, r.number("i") if tag == 3 else r.take(4).hex())
        elif tag in (5, 6):
            entry = (tag, r.number("q") if tag == 5 else r.take(8).hex())
        elif tag in (7, 8, 16, 19, 20):
            entry = (tag, r.number("H"))
        elif tag in (9, 10, 11, 12, 17, 18):
            entry = (tag, r.number("H"), r.number("H"))
        elif tag == 15:
            entry = (tag, r.number("B"), r.number("H"))
        else:
            raise JvmFacadeError("unsupported constant pool tag %d" % tag)
        cp[index] = entry
        index += 2 if tag in (5, 6) else 1
        if index > count:
            raise JvmFacadeError("category-2 constant exceeds constant pool")

    def at(i, kind):
        if not 0 < i < len(cp) or cp[i] is None or cp[i][0] != kind:
            raise JvmFacadeError("invalid constant pool reference/type")
        return cp[i]

    def text(i):
        return at(i, 1)[1]

    def classname(i):
        return text(at(i, 7)[1])

    access = r.number("H")
    this_class = classname(r.number("H"))
    super_index = r.number("H")
    super_name = classname(super_index) if super_index else None
    interfaces = [classname(r.number("H")) for _ in range(r.number("H"))]
    fields = []
    for _ in range(r.number("H")):
        f_access, f_name, f_desc = r.number("H"), text(r.number("H")), text(r.number("H"))
        _skip_attrs(r, text)
        fields.append({"name": f_name, "descriptor": f_desc, "access": f_access})
    methods = []
    for _ in range(r.number("H")):
        m_access, m_name, m_desc = r.number("H"), text(r.number("H")), text(r.number("H"))
        attrs = _collect_attrs(r, text)
        code, max_locals = None, 0
        if "Code" in attrs:
            body = jvm_frontend.Reader(attrs["Code"])
            body.number("H")  # max_stack
            max_locals = body.number("H")
            code = body.take(body.number("I"))
        methods.append({"name": m_name, "descriptor": m_desc, "access": m_access,
                        "code": code, "max_locals": max_locals})
    member_refs = []
    for entry in cp:
        if entry and entry[0] in (9, 10, 11):
            owner = classname(entry[1])
            nt = at(entry[2], 12)
            member_refs.append({"kind": {9: "field", 10: "method", 11: "interface_method"}[entry[0]],
                                "owner": owner, "name": text(nt[1]), "descriptor": text(nt[2])})
    class_refs = sorted({text(e[1]) for e in cp if e and e[0] == 7})
    return {"class_internal": this_class, "super_internal": super_name,
            "interfaces": interfaces, "access": access, "fields": fields,
            "methods": methods, "member_refs": member_refs, "class_refs": class_refs,
            "cp": cp, "major": major, "minor": minor}


def _linear_ops(code, cp) -> list:
    """Decode the small straight-line opcode subset a facade/constructor may use.

    Any other opcode raises; callers treat that as a rejected facade body.
    """
    if not code or len(code) > MAX_METHOD_BYTES:
        raise JvmFacadeError("empty or oversized method body")
    r = jvm_frontend.Reader(code)
    ops = []
    while r.position < len(code):
        opcode = r.number("B")
        if opcode == 0:
            ops.append(("nop", None))
        elif opcode == 42:
            ops.append(("aload", 0))
        elif opcode == 25:
            ops.append(("aload", r.number("B")))
        elif opcode == 21:
            ops.append(("iload", r.number("B")))
        elif opcode == 22:
            ops.append(("lload", r.number("B")))
        elif 26 <= opcode <= 29:
            ops.append(("iload", opcode - 26))
        elif 30 <= opcode <= 33:
            ops.append(("lload", opcode - 30))
        elif opcode in (183, 184):
            ref = jvm_frontend.method_ref(cp, r.number("H"))
            ops.append(("invokespecial" if opcode == 183 else "invokestatic", tuple(ref)))
        elif opcode == 172:
            ops.append(("ireturn", None))
        elif opcode == 173:
            ops.append(("lreturn", None))
        elif opcode == 177:
            ops.append(("return", None))
        elif opcode == 196:
            wide = r.number("B")
            if wide == 21:
                ops.append(("iload", r.number("H")))
            elif wide == 22:
                ops.append(("lload", r.number("H")))
            else:
                raise JvmFacadeError("unsupported wide opcode 0x%02x in facade body" % wide)
        else:
            raise JvmFacadeError("unexpected opcode 0x%02x in facade body" % opcode)
        if len(ops) > 512:
            raise JvmFacadeError("facade body exceeds bounded length")
    return ops


# --------------------------------------------------------------------------
# Producer validation + authoritative core inventory (bounded authorized read)
# --------------------------------------------------------------------------
def _validate_producer(producer):
    if not isinstance(producer, dict):
        raise JvmFacadeError("producer must be the full jvm_frontend build report dict")
    if producer.get("schema_version") != 1:
        raise JvmFacadeError("producer.schema_version must be 1")
    if producer.get("status") != "artifact_created_unvalidated":
        raise JvmFacadeError("producer must be a successful JVM source build "
                             "(status artifact_created_unvalidated)")
    if producer.get("backend") != "jvm_bytecode_native":
        raise JvmFacadeError("producer.backend must be jvm_bytecode_native")
    if producer.get("language") not in ("java", "kotlin"):
        raise JvmFacadeError("producer.language must be java or kotlin")
    project = producer.get("project")
    if not isinstance(project, dict) or not isinstance(project.get("methods"), list) or not project["methods"]:
        raise JvmFacadeError("producer.project.methods must be a non-empty selector list")
    for sel in project["methods"]:
        if not isinstance(sel, dict) or not {"class", "name", "descriptor", "export"} <= set(sel):
            raise JvmFacadeError("each selector needs class, name, descriptor and export")
    if not isinstance(producer.get("methods"), list) or not producer["methods"]:
        raise JvmFacadeError("producer.methods must be the non-empty method report list")
    for m in producer["methods"]:
        if not isinstance(m, dict) or not {"class", "name", "descriptor", "export", "is_root"} <= set(m):
            raise JvmFacadeError("each method report needs class, name, descriptor, export, is_root")
    if not isinstance(producer.get("contract"), dict):
        raise JvmFacadeError("producer.contract must be the cdecl ABI contract")
    if not isinstance(producer.get("original_classes"), dict) or not producer["original_classes"]:
        raise JvmFacadeError("producer.original_classes must map classfile paths to sha256")


def _read_authorized_classfile(raw_path, sha):
    """Return ``(resolved_path, bytes)`` for one declared original core classfile.

    Lexical reserved-path guard first, then a no-links resolve, then a single
    bounded read of a regular, non-hard-linked file whose SHA-256 must equal the
    declared hash; the SAME bytes are returned for parsing (never re-read)."""
    if not isinstance(raw_path, str) or not raw_path:
        raise JvmFacadeError("original_classes keys must be non-empty path strings")
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
        raise JvmFacadeError("original_classes values must be lowercase sha256 hex")
    raw = Path(raw_path)
    if {p.casefold() for p in raw.parts} & RESERVED_PARTS:  # lexical guard precedes any FS access
        raise JvmFacadeError("refusing to read reserved/untrusted path: " + raw_path)
    path = native_build._no_links(raw)  # rejects symlinks/reparse points in the path
    info = path.lstat() if path.exists() else None
    if info is None or not path.is_file():
        raise JvmFacadeError("missing or non-regular original core classfile: " + raw_path)
    if getattr(info, "st_nlink", 1) not in (0, 1):
        raise JvmFacadeError("original core classfile must not be hard-linked: " + raw_path)
    # Single bounded content read: read at most MAX+1 bytes, length-check, then
    # hash and parse THOSE SAME bytes (no second read, no stat-size gating).
    with open(path, "rb") as stream:
        data = stream.read(MAX_CLASS_BYTES + 1)
    if len(data) > MAX_CLASS_BYTES:
        raise JvmFacadeError("original core classfile exceeds 4 MiB: " + raw_path)
    if hashlib.sha256(data).hexdigest() != sha:
        raise JvmFacadeError("original core classfile hash mismatch: " + raw_path)
    return path, data


def _core_inventory(producer) -> dict:
    """Independently parse every declared original core classfile.

    Returns ``{internal_name: {"methods": {(name, descriptor): access}, "path", "sha"}}``.
    Each file passes the reserved-path guard, no-links resolve and exact SHA
    match before a strict ``jvm_frontend.parse_class`` (which rejects any class
    that is not a pure static-only Object subclass with no fields).
    """
    original = producer["original_classes"]
    if len(original) > MAX_CORE_CLASSES:
        raise JvmFacadeError("original_classes exceeds %d entries" % MAX_CORE_CLASSES)
    inventory = {}
    for raw_path, sha in sorted(original.items()):
        path, data = _read_authorized_classfile(raw_path, sha)
        parsed = jvm_frontend.parse_class(data)  # strict: raises on non-core shape, SAME bytes
        name = parsed["class"]
        if not SAFE_CLASS.fullmatch(name) or "$" in name:
            raise JvmFacadeError("unsupported core class identity (nested/dollar names rejected): " + name)
        if name == NATIVECORE_INTERNAL or name == BOOTSTRAP_INTERNAL or (name + "/").startswith(PACKAGE_INTERNAL + "/"):
            raise JvmFacadeError("core class may not occupy the reserved runtime package: " + name)
        if name in inventory:
            raise JvmFacadeError("duplicate original core class identity: " + name)
        methods = {}
        for m in parsed["methods"]:
            key = (m["name"], m["descriptor"])
            if key in methods:
                raise JvmFacadeError("duplicate method in core class " + name)
            methods[key] = m["access"]
        inventory[name] = {"methods": methods, "path": str(path), "sha": sha}
    return inventory


def _facade_plan(producer) -> dict:
    """Validate the producer, build the authoritative core inventory and derive
    the exact facade plan.  Pure: reads classfiles, writes nothing."""
    _validate_producer(producer)
    inventory = _core_inventory(producer)
    contract = bindings.validate_contract(producer["contract"])
    by_export = {f["name"]: f for f in contract["functions"]}

    roots, grouped = [], {}
    selector_keys = set()
    selector_export = {}          # (internal, name, descriptor) -> export, one-to-one
    selector_exports = set()
    for sel in producer["project"]["methods"]:
        internal = sel["class"].replace(".", "/")
        try:
            params, ret = jvm_frontend.descriptor(sel["descriptor"])
        except ValueError as exc:
            raise JvmFacadeError("unsupported root descriptor: " + str(exc))
        export = sel["export"]
        key = (internal, sel["name"], sel["descriptor"])
        # Structural duplicate checks first: a duplicate selector key or export is
        # a selector-set error regardless of ABI/inventory.
        if key in selector_keys:
            raise JvmFacadeError("duplicate root selector: " + str(key))
        if export in selector_exports:
            raise JvmFacadeError("duplicate selector export: " + str(export))
        if export not in by_export:
            raise JvmFacadeError("root export missing from contract: " + str(export))
        func = by_export[export]
        if ([p["type"] for p in func["parameters"]] != [DESC_TO_ABI[p] for p in params]
                or func["return_type"] != DESC_TO_ABI[ret]):
            raise JvmFacadeError("contract ABI does not match descriptor for export " + export)
        if internal not in inventory:
            raise JvmFacadeError("root class not present in original core inventory: " + internal)
        access = inventory[internal]["methods"].get((sel["name"], sel["descriptor"]))
        if access is None:
            raise JvmFacadeError("root method absent from core classfile: %s.%s%s"
                                 % (internal, sel["name"], sel["descriptor"]))
        if not (access & ACC_PUBLIC) or not (access & ACC_STATIC):
            raise JvmFacadeError("root must be public static in the original core: " + sel["name"])
        selector_keys.add(key)
        selector_exports.add(export)
        selector_export[key] = export
        pkg_internal, _, simple = internal.rpartition("/")
        slot, param_slots = 0, []
        for p in params:
            param_slots.append([LOAD_OPCODE[p], slot])
            slot += 2 if p == "J" else 1
        root = {"internal_class": internal, "package": pkg_internal.replace("/", "."),
                "simple_name": simple, "name": sel["name"], "descriptor": sel["descriptor"],
                "export": export, "params": list(params), "ret": ret,
                "return_java_type": JAVA_TYPE[DESC_TO_ABI[ret]],
                "native_call": "call_" + export, "native_descriptor": sel["descriptor"],
                "param_slots": param_slots, "ret_opcode": RET_OPCODE[ret]}
        roots.append(root)
        grouped.setdefault(internal, []).append(root)

    # Cross-check the method report against selectors; validate the whole closure.
    # Require an exact bool is_root, no duplicate report rows, and a one-to-one
    # (key AND export) correspondence between is_root rows and selectors.
    helpers, closure_keys = [], set(selector_keys)
    all_exports = set(selector_exports)
    seen_rows, matched_roots = set(), set()
    for m in producer["methods"]:
        if m["is_root"] is not True and m["is_root"] is not False:
            raise JvmFacadeError("method report is_root must be a bool: " + str(m.get("is_root")))
        key = (m["class"], m["name"], m["descriptor"])
        if key in seen_rows:
            raise JvmFacadeError("duplicate method report row: " + str(key))
        seen_rows.add(key)
        if m["is_root"]:
            if key not in selector_export:
                raise JvmFacadeError("is_root report row is not a project selector: " + str(key))
            if m["export"] != selector_export[key]:
                raise JvmFacadeError("root report export does not match selector export: "
                                     "%s vs %s" % (m["export"], selector_export[key]))
            matched_roots.add(key)
            continue
        # Helper: must exist in the parsed core, be static and private (it is not selected).
        internal = m["class"]
        if internal not in inventory:
            raise JvmFacadeError("closure helper class absent from core inventory: " + internal)
        access = inventory[internal]["methods"].get((m["name"], m["descriptor"]))
        if access is None:
            raise JvmFacadeError("closure helper absent from core classfile: %s.%s%s"
                                 % (internal, m["name"], m["descriptor"]))
        if not (access & ACC_STATIC) or not (access & ACC_PRIVATE):
            raise JvmFacadeError("unselected closure helper must be private static: "
                                 "%s.%s%s" % (internal, m["name"], m["descriptor"]))
        if m["export"] in all_exports:
            raise JvmFacadeError("duplicate export identity: " + str(m["export"]))
        all_exports.add(m["export"])
        closure_keys.add(key)
        helpers.append({"class": internal, "name": m["name"],
                        "descriptor": m["descriptor"], "export": m["export"]})
    if matched_roots != selector_keys:
        missing = selector_keys - matched_roots
        raise JvmFacadeError("selectors without a matching is_root report row: " + str(sorted(missing)))

    # Every original non-constructor method must be accounted for in the closure;
    # no stray/unselected member may remain in a replaced core class.
    for internal, meta in inventory.items():
        for (name, descriptor) in meta["methods"]:
            if name in ("<init>", "<clinit>"):
                continue
            if (internal, name, descriptor) not in closure_keys:
                raise JvmFacadeError("original core method not in the protected closure: "
                                     "%s.%s%s" % (internal, name, descriptor))

    if "core_classes" in producer:
        supplied = producer["core_classes"]
        if not isinstance(supplied, (list, tuple, set)) or set(supplied) != set(inventory):
            raise JvmFacadeError("supplied core_classes disagree with independently parsed inventory")

    return {"inventory": inventory, "roots": roots, "grouped": grouped,
            "contract": contract, "helpers": helpers, "language": producer["language"]}


# --------------------------------------------------------------------------
# Source generation (reuses the fixed bindings generator, pinned package)
# --------------------------------------------------------------------------
def _facade_method_source(root) -> str:
    params = ", ".join("%s p%d" % (JAVA_TYPE[DESC_TO_ABI[p]], i) for i, p in enumerate(root["params"]))
    args = ", ".join("p%d" % i for i in range(len(root["params"])))
    return ("    public static %s %s(%s) {\n"
            "        %s.ProtectedBootstrap.ensureReady();\n"
            "        return %s.NativeCore.%s(%s);\n"
            "    }\n") % (root["return_java_type"], root["name"], params,
                         PACKAGE, PACKAGE, root["native_call"], args)


def _facade_class_source(package, simple, roots) -> str:
    lines = []
    if package:
        lines.append("package %s;" % package)
        lines.append("")
    lines.append("// Generated ANTI-REA facade. Same binary class/method identities as the")
    lines.append("// original owned core, but each public static root forwards to the packaged")
    lines.append("// protected native core via JNI. This is not the original algorithm and")
    lines.append("// carries no original or helper bytecode, constants or classfiles.")
    lines.append("public final class %s {" % simple)
    lines.append("    private %s() {}" % simple)
    lines.append("")
    lines.append("\n".join(_facade_method_source(r) for r in roots).rstrip("\n"))
    lines.append("}")
    return "\n".join(lines) + "\n"


def _bootstrap_source() -> str:
    return (
        "package %s;\n\n"
        "// Loads the pinned JNI adapter and protected native core exactly once from the\n"
        "// explicit absolute paths in %s and %s. Fail closed: if either is unset or empty\n"
        "// the class never initializes and there is NO original-algorithm fallback.\n"
        "public final class ProtectedBootstrap {\n"
        "    private ProtectedBootstrap() {}\n"
        "    static {\n"
        "        String adapter = System.getenv(\"%s\");\n"
        "        String core = System.getenv(\"%s\");\n"
        "        if (adapter == null || adapter.isEmpty() || core == null || core.isEmpty()) {\n"
        "            throw new IllegalStateException(\n"
        "                \"%s and %s must be set to absolute paths\");\n"
        "        }\n"
        "        NativeCore.initialize(adapter, core);\n"
        "    }\n"
        "    public static void ensureReady() { }\n"
        "}\n"
    ) % (PACKAGE, ENV_ADAPTER, ENV_CORE, ENV_ADAPTER, ENV_CORE, ENV_ADAPTER, ENV_CORE)


def _packaged_bindings(contract):
    """Return the fixed bindings Java/JNI, pinned to package ``antirea.runtime``.

    The generated ``NativeCore`` is moved into the trusted package and the JNI
    entry-point symbols are renamed consistently; nothing else is rewritten.
    """
    java, jni, _kotlin = bindings._java(contract)
    header, bridge = bindings._bridge(contract)
    packaged_java = "package %s;\n\n%s" % (PACKAGE, java)
    adapter = jni.replace('#include "../common/antirea_bridge.h"', '#include "antirea_bridge.h"')
    adapter = adapter.replace("Java_NativeCore_", "Java_" + PACKAGE.replace(".", "_") + "_NativeCore_")
    symbols = ["Java_%s_NativeCore_nativeLoad" % PACKAGE.replace(".", "_")]
    for f in contract["functions"]:
        mangled = ("native_" + f["name"]).replace("_", "_1")
        symbols.append("Java_%s_NativeCore_%s" % (PACKAGE.replace(".", "_"), mangled))
    return packaged_java, adapter, header, bridge, symbols


def _hash_text(text) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def generate_facades(producer: dict, output_dir: Path) -> dict:
    """Generate the facade, bootstrap, packaged NativeCore and JNI adapter sources.

    Pure: all producer and classfile preflight runs *before* any file is created,
    and nothing is compiled, executed, downloaded or published.  Returns the
    report that is also persisted as ``output_dir/facades.json``.
    """
    directory = Path(os.path.abspath(output_dir))
    # Lexical reserved-path guard FIRST, before any filesystem access.
    parts = [p.casefold() for p in directory.parts]
    if set(parts) & RESERVED_PARTS:
        raise JvmFacadeError("facades are private build inputs, not transfer/intake artifacts")
    if any(parts[i:i + 2] == ["defense-loop", "inbox"] for i in range(len(parts) - 1)):
        raise JvmFacadeError("facades cannot be written into the untrusted intake inbox")
    native_build._no_links(directory)
    if directory.exists():
        raise JvmFacadeError("output_dir must be new; facades never overwrite existing files")

    # Preflight everything first.
    plan = _facade_plan(producer)
    packaged_java, adapter, header, bridge, symbols = _packaged_bindings(plan["contract"])

    files = {}
    facade_classes = []
    for internal, roots in sorted(plan["grouped"].items()):
        package = roots[0]["package"]
        simple = roots[0]["simple_name"]
        rel = "java/" + (package.replace(".", "/") + "/" if package else "") + simple + ".java"
        files[rel] = _facade_class_source(package, simple, roots)
        facade_classes.append({
            "internal_name": internal, "class": internal.replace("/", "."),
            "source_file": rel,
            "methods": [{"name": r["name"], "descriptor": r["descriptor"], "export": r["export"],
                         "native_call": r["native_call"], "native_descriptor": r["native_descriptor"],
                         "return_opcode": r["ret_opcode"], "param_loads": r["param_slots"]}
                        for r in roots]})

    files["java/antirea/runtime/ProtectedBootstrap.java"] = _bootstrap_source()
    files["java/antirea/runtime/NativeCore.java"] = packaged_java
    files["jni/antirea_bridge.h"] = header
    files["jni/antirea_bridge.c"] = bridge
    files["jni/adapter.c"] = adapter

    # Same-class-path replacement: the original core class and the generated
    # facade deliberately share the same relative .class path, so this is NOT a
    # blanket path ban. The deploy check is that the original class BYTES (by
    # SHA) and private helper bodies are absent, and the same identity is
    # occupied by the generated forwarding class whose exact methods and compiled
    # SHA are established by validate_facade_classes after compilation.
    class_inventory = []
    facade_file = {c["internal_name"]: c for c in facade_classes}
    for internal in sorted(plan["inventory"]):
        entry = facade_file.get(internal)
        src = entry["source_file"] if entry else None
        class_inventory.append({
            "internal_name": internal, "class": internal.replace("/", "."),
            "original_sha256": plan["inventory"][internal]["sha"],
            "original_classfile": plan["inventory"][internal]["path"],
            "facade_source_file": src,
            "facade_source_sha256": _hash_text(files[src]) if src else None,
            "same_relative_class_path": True,
            "original_bytes_must_be_absent": True,
            "methods": entry["methods"] if entry else []})

    report = {
        "schema_version": 1, "kind": "jvm_facade_generation",
        "status": STATUS_GENERATED, "language": plan["language"],
        "package": PACKAGE, "executed": False,
        "output_dir": str(directory),
        "contract": plan["contract"],
        "facade_classes": facade_classes,
        "runtime_classes": [
            {"class": BOOTSTRAP_CLASS, "source_file": "java/antirea/runtime/ProtectedBootstrap.java",
             "entry": "ensureReady", "environment": [ENV_ADAPTER, ENV_CORE], "fail_closed": True},
            {"class": NATIVECORE_CLASS, "source_file": "java/antirea/runtime/NativeCore.java"}],
        "jni": {"header": "jni/antirea_bridge.h",
                "adapter_sources": ["jni/adapter.c", "jni/antirea_bridge.c"],
                "exported_symbols": symbols},
        "native_exports": [f["name"] for f in plan["contract"]["functions"]],
        "helpers_internal_to_native_not_exposed": plan["helpers"],
        "expected_deploy_classes": sorted(
            [c["class"] for c in facade_classes] + [BOOTSTRAP_CLASS, NATIVECORE_CLASS]),
        "replaced_core_classes": sorted(plan["inventory"]),
        "class_inventory": class_inventory,
        "closure": {
            "roots": [{"class": r["internal_class"], "name": r["name"],
                       "descriptor": r["descriptor"], "export": r["export"]} for r in plan["roots"]],
            "helpers": plan["helpers"]},
        "bindings_source_sha256": native_build._hash(Path(bindings.__file__).resolve()),
        "facade_source_sha256": _self_hash(),
        "limitations": list(GENERATION_LIMITATIONS),
    }
    report["files"] = {rel: _hash_text(content) for rel, content in sorted(files.items())}

    # All preflight passed: write a fresh bundle, then persist the EXACT report
    # that is returned (so the saved facades.json and the return value match).
    directory.mkdir(parents=True, exist_ok=False)
    for rel, content in files.items():
        target = directory / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
    serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
    with (directory / "facades.json").open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(serialized)
    return report


# --------------------------------------------------------------------------
# Application class inspection
# --------------------------------------------------------------------------
def inspect_application_classes(class_files: dict, producer: dict) -> dict:
    """Check that ordinary application classes reference nothing of the core
    except its selected public static roots.  Each ``class_files`` key must be the
    class's internal name plus ``.class`` (slash form); wrong/alias keys are
    rejected.  Returns ``status`` ``accepted`` or ``rejected`` with a
    ``violations`` list; raises only on malformed producer input."""
    plan = _facade_plan(producer)
    core_classes = set(plan["inventory"])
    roots_set = {(r["internal_class"], r["name"], r["descriptor"]) for r in plan["roots"]}
    if not isinstance(class_files, dict) or not class_files or len(class_files) > MAX_APP_CLASSES:
        raise JvmFacadeError("class_files must map 1..%d identifiers to classfile bytes" % MAX_APP_CLASSES)

    def in_runtime(name):
        return isinstance(name, str) and (name == NATIVECORE_INTERNAL or name == BOOTSTRAP_INTERNAL
                                          or (name + "/").startswith(PACKAGE_INTERNAL + "/"))

    classes_report, violations, seen_identities = [], [], set()
    for key, data in sorted(class_files.items()):
        try:
            meta = _read_class(data)
        except JvmFacadeError as exc:
            violations.append({"source": str(key), "kind": "parse", "detail": str(exc)})
            continue
        app_name = meta["class_internal"]
        expected_key = app_name + ".class"
        if key != expected_key:
            violations.append({"source": str(key), "class": app_name, "kind": "key_identity",
                               "detail": "class_files key must be '%s' (internal name + .class)" % expected_key})
        if app_name in seen_identities:
            violations.append({"class": app_name, "kind": "duplicate_identity",
                               "detail": "duplicate application class identity in the input set"})
        seen_identities.add(app_name)
        if in_runtime(app_name):
            violations.append({"class": app_name, "kind": "reserved_namespace",
                               "detail": "application must not declare a class in antirea.runtime"})
        if app_name in core_classes:
            violations.append({"class": app_name, "kind": "identity",
                               "detail": "application class reuses an original core class identity"})
        if meta["super_internal"] in core_classes:
            violations.append({"class": app_name, "kind": "inheritance",
                               "detail": "extends protected core class " + str(meta["super_internal"])})
        for itf in meta["interfaces"]:
            if itf in core_classes:
                violations.append({"class": app_name, "kind": "inheritance",
                                   "detail": "implements protected core class " + itf})
        refs = []
        for ref in meta["member_refs"]:
            if in_runtime(ref["owner"]):
                violations.append({"class": app_name, "kind": "reserved_namespace",
                                   "owner": ref["owner"], "member": ref["name"] + ref["descriptor"],
                                   "detail": "unexpected reference into antirea.runtime"})
                refs.append({**ref, "allowed": False, "reason": "reserved runtime reference"})
                continue
            if ref["owner"] not in core_classes:
                continue
            member = ref["name"] + ref["descriptor"]
            if ref["kind"] == "field":
                violations.append({"class": app_name, "kind": "field_reference", "owner": ref["owner"],
                                   "member": member, "detail": "references a protected core field"})
                refs.append({**ref, "allowed": False, "reason": "field reference"})
            elif (ref["owner"], ref["name"], ref["descriptor"]) in roots_set:
                refs.append({**ref, "allowed": True, "reason": "public static root"})
            else:
                reason = ("constructor" if ref["name"] in ("<init>", "<clinit>")
                          else "helper or non-root member")
                violations.append({"class": app_name, "kind": "member_reference", "owner": ref["owner"],
                                   "member": member, "detail": "references protected " + reason})
                refs.append({**ref, "allowed": False, "reason": reason})
        classes_report.append({"class": app_name, "super": meta["super_internal"],
                               "interfaces": meta["interfaces"], "core_references": refs})

    return {"schema_version": 1, "kind": "jvm_application_inspection",
            "status": STATUS_APP_REJECTED if violations else STATUS_APP_OK,
            "language": plan["language"], "core_classes": sorted(core_classes),
            "roots": [{"class": r["internal_class"], "name": r["name"],
                       "descriptor": r["descriptor"], "export": r["export"]} for r in plan["roots"]],
            "classes": classes_report, "violations": violations,
            "facade_source_sha256": _self_hash(), "limitations": list(INSPECTION_LIMITATIONS)}


# --------------------------------------------------------------------------
# Compiled facade validation
# --------------------------------------------------------------------------
def _expected_root_ops(root):
    ops = [("invokestatic", (BOOTSTRAP_INTERNAL, "ensureReady", "()V"))]
    ops.extend((load, slot) for load, slot in root["param_slots"])
    ops.append(("invokestatic", (NATIVECORE_INTERNAL, root["native_call"], root["native_descriptor"])))
    ops.append((root["ret_opcode"], None))
    return ops


_EXPECTED_CTOR_OPS = [("aload", 0), ("invokespecial", ("java/lang/Object", "<init>", "()V")), ("return", None)]


def _validate_one_facade(internal, roots, meta, violations):
    report = {"class": internal, "methods": [], "has_constructor": False}
    if not (meta["access"] & ACC_PUBLIC) or not (meta["access"] & ACC_FINAL):
        violations.append({"class": internal, "kind": "class_flags",
                           "detail": "facade class must be public final"})
    if meta["super_internal"] != "java/lang/Object":
        violations.append({"class": internal, "kind": "superclass",
                           "detail": "facade must extend java/lang/Object, not " + str(meta["super_internal"])})
    if meta["interfaces"]:
        violations.append({"class": internal, "kind": "interfaces",
                           "detail": "facade must implement no interfaces"})
    if meta["fields"]:
        violations.append({"class": internal, "kind": "fields", "detail": "facade must declare no fields"})

    expected = {(r["name"], r["descriptor"]): r for r in roots}
    seen = set()
    for m in meta["methods"]:
        mkey = (m["name"], m["descriptor"])
        if m["name"] == "<clinit>":
            violations.append({"class": internal, "kind": "static_initializer",
                               "detail": "facade must have no static initializer"})
            continue
        if m["name"] == "<init>" and m["descriptor"] == "()V":
            report["has_constructor"] = True
            if m["access"] & ACC_STATIC or not (m["access"] & ACC_PRIVATE):
                violations.append({"class": internal, "kind": "constructor",
                                   "detail": "facade constructor must be a private instance method"})
            try:
                ops = _linear_ops(m["code"], meta["cp"])
            except JvmFacadeError as exc:
                violations.append({"class": internal, "kind": "constructor_body", "detail": str(exc)})
                continue
            if ops != _EXPECTED_CTOR_OPS:
                violations.append({"class": internal, "kind": "constructor_body",
                                   "detail": "constructor is not the trivial Object super-call"})
            continue
        if mkey not in expected:
            violations.append({"class": internal, "kind": "unexpected_method",
                               "detail": "unexpected method %s%s" % mkey})
            continue
        seen.add(mkey)
        root = expected[mkey]
        method_report = {"name": m["name"], "descriptor": m["descriptor"],
                         "export": root["export"], "body_ok": False}
        if not (m["access"] & ACC_PUBLIC) or not (m["access"] & ACC_STATIC):
            violations.append({"class": internal, "kind": "method_flags",
                               "detail": "facade root %s%s must be public static" % mkey})
        try:
            ops = _linear_ops(m["code"], meta["cp"])
        except JvmFacadeError as exc:
            violations.append({"class": internal, "kind": "method_body",
                               "detail": "root %s%s body rejected: %s" % (m["name"], m["descriptor"], exc)})
            report["methods"].append(method_report)
            continue
        if ops == _expected_root_ops(root):
            method_report["body_ok"] = True
        else:
            violations.append({"class": internal, "kind": "method_body",
                               "detail": "root %s%s body is not exact bootstrap+native forwarding"
                                         % (m["name"], m["descriptor"])})
        report["methods"].append(method_report)

    for mkey in expected:
        if mkey not in seen:
            violations.append({"class": internal, "kind": "missing_method",
                               "detail": "expected facade root %s%s is absent" % mkey})
    if not report["has_constructor"]:
        violations.append({"class": internal, "kind": "constructor",
                           "detail": "facade must declare a trivial private constructor"})
    return report


def validate_facade_classes(class_files: dict, producer: dict) -> dict:
    """Validate compiled facade classfiles against the exact expected shape.

    Each facade body must be exactly ``ProtectedBootstrap.ensureReady()`` then a
    single forwarding call into the packaged ``NativeCore`` for the matching
    export, with the correct parameter loads and return opcode; the class may
    carry only its roots and a trivial private constructor.  Each ``class_files``
    key must be the class's internal name plus ``.class`` (slash form); wrong or
    alias keys are rejected.  The provided set must be exactly the facades plus
    both packaged runtime classes.  Returns ``status`` ``accepted`` or
    ``rejected``; raises only on malformed producer input."""
    plan = _facade_plan(producer)
    grouped = plan["grouped"]
    if not isinstance(class_files, dict) or not class_files or len(class_files) > MAX_APP_CLASSES:
        raise JvmFacadeError("class_files must map 1..%d identifiers to classfile bytes" % MAX_APP_CLASSES)

    violations = []
    by_name = {}
    for key, data in sorted(class_files.items()):
        try:
            meta = _read_class(data)
        except JvmFacadeError as exc:
            violations.append({"source": str(key), "kind": "parse", "detail": str(exc)})
            continue
        internal = meta["class_internal"]
        if key != internal + ".class":
            violations.append({"source": str(key), "class": internal, "kind": "key_identity",
                               "detail": "class_files key must be '%s' (internal name + .class)"
                                         % (internal + ".class")})
        if internal in by_name:
            violations.append({"class": internal, "kind": "duplicate",
                               "detail": "duplicate class identity in facade set"})
            continue
        by_name[internal] = meta

    classes_report = []
    for internal, roots in sorted(grouped.items()):
        meta = by_name.get(internal)
        if meta is None:
            violations.append({"class": internal, "kind": "missing_class",
                               "detail": "expected facade class not provided"})
            continue
        classes_report.append(_validate_one_facade(internal, roots, meta, violations))

    # The provided class set must be EXACTLY the facades plus both packaged
    # runtime classes - no extras, none missing.
    expected_classes = set(grouped) | {BOOTSTRAP_INTERNAL, NATIVECORE_INTERNAL}
    for name in sorted(by_name):
        if name not in expected_classes:
            violations.append({"class": name, "kind": "unexpected_class",
                               "detail": "class is not an expected facade or runtime class"})

    runtime = {"bootstrap_present": BOOTSTRAP_INTERNAL in by_name,
               "nativecore_present": NATIVECORE_INTERNAL in by_name}
    if not runtime["bootstrap_present"]:
        violations.append({"class": BOOTSTRAP_INTERNAL, "kind": "missing_class",
                           "detail": "packaged ProtectedBootstrap class not provided"})
    else:
        names = {(m["name"], m["descriptor"]) for m in by_name[BOOTSTRAP_INTERNAL]["methods"]}
        if ("ensureReady", "()V") not in names:
            violations.append({"class": BOOTSTRAP_INTERNAL, "kind": "bootstrap",
                               "detail": "ProtectedBootstrap.ensureReady()V absent"})
        if ("<clinit>", "()V") not in names:
            violations.append({"class": BOOTSTRAP_INTERNAL, "kind": "bootstrap",
                               "detail": "ProtectedBootstrap static initializer absent"})
    if not runtime["nativecore_present"]:
        violations.append({"class": NATIVECORE_INTERNAL, "kind": "missing_class",
                           "detail": "packaged NativeCore class not provided"})
    else:
        names = {m["name"] for m in by_name[NATIVECORE_INTERNAL]["methods"]}
        for export in [c["export"] for c in plan["roots"]]:
            if ("call_" + export) not in names:
                violations.append({"class": NATIVECORE_INTERNAL, "kind": "nativecore",
                                   "detail": "NativeCore.call_%s absent" % export})
        if "nativeLoad" not in names:
            violations.append({"class": NATIVECORE_INTERNAL, "kind": "nativecore",
                               "detail": "NativeCore.nativeLoad absent"})

    return {"schema_version": 1, "kind": "jvm_facade_validation",
            "status": STATUS_FACADE_INVALID if violations else STATUS_FACADE_VALID,
            "language": plan["language"], "package": PACKAGE,
            "expected_facade_classes": sorted(grouped),
            "expected_deploy_classes": sorted(c.replace("/", ".") for c in expected_classes),
            "classes": classes_report, "runtime_classes": runtime,
            "violations": violations, "facade_source_sha256": _self_hash(),
            "limitations": list(VALIDATION_LIMITATIONS)}
