"""Owned Java/Kotlin sources -> inspected classfile integers -> C -> native VM.

Compilation/inspection do not load target classes. Explicit verification does.
This bounded frontend is not a JVM implementation or a whole-language promise.
"""
from __future__ import annotations

import argparse
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import sys

from . import native_build
from .dotnet_frontend import _write, _hash, _mask, _comparison, reference_cases
from .process import run_logged


class JvmFrontendError(ValueError):
    pass


CLASS_NAME = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*\Z")
TYPES = {"I": (32, "int32_t", "i32", "Int32"), "J": (64, "int64_t", "i64", "Int64")}
LIMITATIONS = [
    "Experimental Java/Kotlin public static int/long roots and acyclic owned static helper closure only.",
    "No objects, arrays, fields, inheritance, interfaces, synchronization, exceptions, division/remainder, floating point or dynamic calls.",
    "All compiled classes must have no fields or class initializers and extend only java.lang.Object.",
    "No class/JAR rewriting or automatic caller replacement; only the protected native DLL is a deployment candidate.",
    "Original classes, generated C and LLVM IR are private build evidence, not deployment files.",
    "Windows x64 only; each language needs its own source/runtime evidence, not another language's fixtures.",
    "Coverage and sampled equivalence do not establish performance acceptance or attack resistance.",
]
SPEC = "https://docs.oracle.com/javase/specs/jvms/se21/html/jvms-6.html"


def descriptor(text):
    if not isinstance(text, str) or not re.fullmatch(r"\([IJ]{0,8}\)[IJ]", text):
        raise JvmFrontendError("Only int/long signatures with up to eight arguments are supported")
    return list(text[1:text.index(")")]), text[-1]


def _compiler(language="java"):
    value = shutil.which("javac")
    if not value:
        raise JvmFrontendError("Installed javac required; no tool downloads are performed")
    javac = native_build._no_links(Path(value))
    jdk = javac.parent.parent
    java = native_build._no_links(javac.parent / ("java.exe" if os.name == "nt" else "java"))
    helper = Path(__file__).resolve().parents[1] / "tools/jvm_frontend/ReferenceRunner.java"
    inputs = [javac, java, jdk / "release", jdk / "lib/modules", helper, Path(__file__).resolve(),
              Path(__file__).with_name("dotnet_frontend.py"), *sorted((jdk / "bin").rglob("*.dll"))]
    if any(not p.is_file() for p in inputs):
        raise JvmFrontendError("Installed JDK or trusted reference helper is incomplete")
    compiler = {"javac": str(javac), "java": str(java), "jdk_root": str(jdk), "release": (jdk / "release").read_text(),
                "helper": str(helper), "blockers": []}
    if language == "kotlin":
        repo = Path(__file__).resolve().parents[1]
        config_path = repo / ".tools/kotlin-toolchain.json"
        if not config_path.is_file():
            compiler["blockers"].append("kotlin_portable_compiler_not_configured")
        else:
            native_build._no_links(config_path)
            config = native_build._read_json(config_path)
            if type(config.get("schema_version")) is not int or config["schema_version"] != 1:
                raise JvmFrontendError("Kotlin toolchain schema_version must be 1")
            home = native_build._no_links(Path(config["kotlin_home"]))
            if not home.is_relative_to(repo / ".tools"):
                raise JvmFrontendError("Portable Kotlin compiler must be within repository/.tools")
            jars = sorted((home / "lib").glob("*.jar"))
            if len(jars) > 128 or sum(p.stat().st_size for p in jars) > 512 * 1024 * 1024:
                raise JvmFrontendError("Kotlin compiler library inventory exceeds limits")
            for name in ("kotlin-compiler.jar", "kotlin-stdlib.jar", "annotations-13.0.jar"):
                if not (home / "lib" / name).is_file():
                    raise JvmFrontendError("Portable Kotlin distribution incomplete: " + name)
            inputs.extend([config_path, *jars])
            compiler.update(kotlin_home=str(home), kotlin_version=config.get("version"),
                kotlin_compiler=str(home / "lib/kotlin-compiler.jar"), kotlin_config=str(config_path),
                kotlin_stdlib=str(home / "lib/kotlin-stdlib.jar"), kotlin_annotations=str(home / "lib/annotations-13.0.jar"))
    compiler["input_hashes"] = {str(native_build._no_links(p)): _hash(p) for p in inputs}
    return compiler


def inspect_project(project_path: Path) -> dict:
    path = native_build._no_links(Path(project_path))
    if "rea-analysis-reports" in {p.casefold() for p in path.parts}:
        raise JvmFrontendError("Incoming reports cannot be source projects")
    data = native_build._read_json(path)
    if set(data) != {"schema_version", "name", "language", "sources", "methods"}:
        raise JvmFrontendError("Expected exactly schema_version, name, language, sources and methods")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1 or data["language"] not in ("java", "kotlin"):
        raise JvmFrontendError("Expected schema_version 1 and language java or kotlin")
    if not isinstance(data["name"], str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", data["name"]):
        raise JvmFrontendError("Invalid project name")
    if not isinstance(data["sources"], list) or not 1 <= len(data["sources"]) <= 32:
        raise JvmFrontendError("sources must contain 1..32 source files")
    sources = [native_build._relative(path.parent, p) for p in data["sources"]]
    extension = ".java" if data["language"] == "java" else ".kt"
    if len(set(sources)) != len(sources) or any(p.suffix != extension for p in sources):
        raise JvmFrontendError("Only unique " + extension + " source files are accepted; no scripts/build hooks")
    if not isinstance(data["methods"], list) or not 1 <= len(data["methods"]) <= 16:
        raise JvmFrontendError("methods must contain 1..16 explicit roots")
    identities, exports = set(), set()
    for m in data["methods"]:
        if not isinstance(m, dict) or set(m) != {"class", "name", "descriptor", "export"}:
            raise JvmFrontendError("Each method needs class, name, descriptor and export")
        if not isinstance(m["class"], str) or not CLASS_NAME.fullmatch(m["class"]):
            raise JvmFrontendError("Unsupported declaring class name")
        if any(not isinstance(m[k], str) or not native_build.SYMBOL.fullmatch(m[k]) for k in ("name", "export")):
            raise JvmFrontendError("Method/export names must be ordinary identifiers")
        if m["export"].startswith(("antirea_", "kagura_", "jvm_owned_")):
            raise JvmFrontendError("Reserved export prefix")
        descriptor(m["descriptor"])
        key = (m["class"].replace(".", "/"), m["name"], m["descriptor"])
        if key in identities or m["export"] in exports:
            raise JvmFrontendError("Duplicate root method/export")
        identities.add(key)
        exports.add(m["export"])
    compiler = _compiler(data["language"])
    return {"schema_version": 1, "project_path": str(path), "project_root": str(path.parent),
            "name": data["name"], "language": data["language"], "sources": list(map(str, sources)),
            "source_files": list(map(str, sources)), "methods": data["methods"],
            "functions": [m["export"] for m in data["methods"]], "exported_functions": [m["export"] for m in data["methods"]],
            "input_hashes": native_build._snapshot([path.parent], [path]), "compiler_inputs": compiler["input_hashes"],
            "compiler": compiler, "route_status": "unsupported" if compiler["blockers"] else "available",
            "blockers": compiler["blockers"], "experimental": True,
            "target": native_build.TARGET, "artifact": "shared_library", "limitations": list(LIMITATIONS)}


class Reader:
    def __init__(self, data):
        self.data, self.position = data, 0

    def take(self, count):
        if count < 0 or self.position + count > len(self.data):
            raise JvmFrontendError("Truncated classfile/bytecode")
        result = self.data[self.position:self.position+count]
        self.position += count
        return result

    def number(self, fmt):
        return struct.unpack(">" + fmt, self.take(struct.calcsize(">" + fmt)))[0]

    def end(self):
        if self.position != len(self.data):
            raise JvmFrontendError("Trailing classfile/attribute bytes")


def decode_modified_utf8(raw):
    """JVMS 4.4.7: UTF-16 code units, encoded NUL and surrogate pairs."""
    units, index = [], 0
    while index < len(raw):
        first = raw[index]
        index += 1
        if 1 <= first <= 0x7f:
            units.append(first)
            continue
        count = 1 if first & 0xe0 == 0xc0 else 2 if first & 0xf0 == 0xe0 else -1
        if count == -1 or index + count > len(raw):
            raise JvmFrontendError("Invalid modified UTF-8 leading/truncated sequence")
        value = first & (0x1f if count == 1 else 0x0f)
        for byte in raw[index:index+count]:
            if byte & 0xc0 != 0x80:
                raise JvmFrontendError("Invalid modified UTF-8 continuation")
            value = (value << 6) | (byte & 0x3f)
        index += count
        if count == 1 and value < 0x80 and value != 0 or count == 2 and value < 0x800:
            raise JvmFrontendError("Noncanonical modified UTF-8 sequence")
        units.append(value)
    return b"".join(struct.pack(">H", value) for value in units).decode("utf-16-be", "surrogatepass")


def parse_class(data):
    if len(data) > 4 * 1024 * 1024:
        raise JvmFrontendError("Classfile exceeds 4 MiB")
    r = Reader(data)
    if r.number("I") != 0xCAFEBABE:
        raise JvmFrontendError("Invalid classfile magic")
    minor, major = r.number("H"), r.number("H")
    if minor != 0 or not 52 <= major <= 65:
        raise JvmFrontendError("Only non-preview Java 8..21 classfile versions are accepted")
    count = r.number("H")
    cp, index = [None] * count, 1
    while index < count:
        tag = r.number("B")
        if tag == 1:
            raw = r.take(r.number("H"))
            entry = (tag, decode_modified_utf8(raw))
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
            raise JvmFrontendError("Unsupported constant pool tag")
        cp[index] = entry
        index += 2 if tag in (5, 6) else 1
        if index > count:
            raise JvmFrontendError("Category-2 constant exceeds constant pool")

    def at(i, kind):
        if not 0 < i < len(cp) or cp[i] is None or cp[i][0] != kind:
            raise JvmFrontendError("Invalid constant pool reference/type")
        return cp[i]

    def text(i):
        return at(i, 1)[1]

    def classname(i):
        return text(at(i, 7)[1])

    def attributes(reader):
        result = {}
        for _ in range(reader.number("H")):
            name, payload = text(reader.number("H")), reader.take(reader.number("I"))
            if name in result:
                raise JvmFrontendError("Duplicate attribute")
            result[name] = payload
        return result

    access, name, super_index = r.number("H"), classname(r.number("H")), r.number("H")
    superclass = classname(super_index) if super_index else None
    if access & (0x0200 | 0x0400 | 0x2000 | 0x4000 | 0x8000) or superclass != "java/lang/Object" or r.number("H"):
        raise JvmFrontendError("Interfaces, inheritance, abstract classes, enums and modules are unsupported")
    if r.number("H"):
        raise JvmFrontendError("Fields are unsupported, including class state/constant fields")
    methods = []
    for _ in range(r.number("H")):
        flags, method_name, desc = r.number("H"), text(r.number("H")), text(r.number("H"))
        attrs = attributes(r)
        if method_name == "<clinit>":
            raise JvmFrontendError("Class initializers are unsupported")
        m = {"class": name, "name": method_name, "descriptor": desc, "access": flags,
             "code": None, "max_stack": 0, "max_locals": 0, "exception_regions": 0}
        if "Code" in attrs:
            body = Reader(attrs["Code"])
            m.update(max_stack=body.number("H"), max_locals=body.number("H"))
            m["code"] = body.take(body.number("I")).hex()
            m["exception_regions"] = body.number("H")
            body.take(m["exception_regions"] * 8)
            attributes(body)
            body.end()
        if any((old["name"], old["descriptor"]) == (method_name, desc) for old in methods):
            raise JvmFrontendError("Duplicate method signature")
        methods.append(m)
    attributes(r)
    r.end()
    return {"class": name, "major": major, "minor": minor, "constant_pool": cp, "methods": methods}


def cp_value(cp, index, tag):
    if not 0 < index < len(cp) or cp[index] is None or cp[index][0] != tag:
        raise JvmFrontendError("Invalid bytecode constant pool operand")
    return cp[index]


def method_ref(cp, index):
    ref = cp_value(cp, index, 10)
    owner = cp_value(cp, cp_value(cp, ref[1], 7)[1], 1)[1]
    pair = cp_value(cp, ref[2], 12)
    return owner, cp_value(cp, pair[1], 1)[1], cp_value(cp, pair[2], 1)[1]


_SIMPLE = {0: "nop", 87: "pop", 88: "pop2", 89: "dup", 90: "dup_x1", 91: "dup_x2",
           92: "dup2", 93: "dup2_x1", 94: "dup2_x2", 95: "swap", 133: "i2l", 136: "l2i",
           145: "i2b", 146: "i2c", 147: "i2s", 148: "lcmp", 172: "ireturn", 173: "lreturn"}
for _start, _suffix in ((96, "add"), (100, "sub"), (104, "mul"), (116, "neg")):
    _SIMPLE[_start], _SIMPLE[_start+1] = "i" + _suffix, "l" + _suffix
for _start, _suffix in ((120, "shl"), (122, "shr"), (124, "ushr"), (126, "and"), (128, "or"), (130, "xor")):
    _SIMPLE[_start], _SIMPLE[_start+1] = "i" + _suffix, "l" + _suffix
_BRANCHES = dict(zip(range(153, 165), ("ifeq", "ifne", "iflt", "ifge", "ifgt", "ifle",
                                    "if_icmpeq", "if_icmpne", "if_icmplt", "if_icmpge", "if_icmpgt", "if_icmple")))


def decode_code(method, cp):
    data = bytes.fromhex(method["code"] or "")
    if not 1 <= len(data) <= 65535:
        raise JvmFrontendError("Missing or oversized bytecode body")
    r, result = Reader(data), []
    while r.position < len(data):
        offset, opcode = r.position, r.number("B")
        name, operand = _SIMPLE.get(opcode), None
        if opcode in range(2, 9):
            name, operand = "iconst", opcode - 3
        elif opcode in (9, 10):
            name, operand = "lconst", opcode - 9
        elif opcode in (16, 17):
            name, operand = "iconst", r.number("b" if opcode == 16 else "h")
        elif opcode in (18, 19, 20):
            value = cp_value(cp, r.number("B" if opcode == 18 else "H"), 5 if opcode == 20 else 3)
            name, operand = ("lconst" if opcode == 20 else "iconst"), value[1]
        elif opcode in (21, 22, 54, 55):
            name, operand = {21: "iload", 22: "lload", 54: "istore", 55: "lstore"}[opcode], r.number("B")
        elif 26 <= opcode <= 33 or 59 <= opcode <= 66:
            start = 26 if opcode <= 33 else 59
            name = ("i" if opcode - start < 4 else "l") + ("load" if start == 26 else "store")
            operand = (opcode - start) % 4
        elif opcode == 132:
            name, operand = "iinc", (r.number("B"), r.number("b"))
        elif opcode in _BRANCHES or opcode in (167, 200):
            name = _BRANCHES.get(opcode, "goto")
            operand = offset + r.number("i" if opcode == 200 else "h")
        elif opcode in (170, 171):
            name = "switch"
            while r.position % 4:
                if r.number("B") != 0:
                    raise JvmFrontendError("Nonzero switch padding")
            default = offset + r.number("i")
            if opcode == 170:
                low, high = r.number("i"), r.number("i")
                if not 0 <= high - low < 4096:
                    raise JvmFrontendError("Invalid or oversized tableswitch")
                pairs = [(i, offset + r.number("i")) for i in range(low, high+1)]
            else:
                count = r.number("i")
                if not 0 <= count <= 4096:
                    raise JvmFrontendError("Invalid or oversized lookupswitch")
                pairs = [(r.number("i"), offset + r.number("i")) for _ in range(count)]
                if [x for x, _ in pairs] != sorted({x for x, _ in pairs}):
                    raise JvmFrontendError("Unsorted/duplicate lookupswitch keys")
            operand = {"default": default, "pairs": pairs}
        elif opcode == 184:
            name, operand = "invokestatic", method_ref(cp, r.number("H"))
            descriptor(operand[2])
        elif opcode == 196:
            wide = r.number("B")
            if wide in (21, 22, 54, 55):
                name, operand = {21: "iload", 22: "lload", 54: "istore", 55: "lstore"}[wide], r.number("H")
            elif wide == 132:
                name, operand = "iinc", (r.number("H"), r.number("h"))
            else:
                raise JvmFrontendError("Unsupported wide instruction")
        if name is None:
            raise JvmFrontendError(f"Unsupported JVM opcode 0x{opcode:02x} at {offset}; no fallback")
        result.append({"offset": offset, "next": r.position, "name": name, "operand": operand})
        if len(result) > 4096:
            raise JvmFrontendError("Method exceeds 4096 instructions")
    return result


def stack_permutation(name, stack):
    """JVMS category-1/category-2 stack transforms as source-index permutation."""
    indexes = list(range(len(stack)))
    def group(slots):
        values, used = [], 0
        while used < slots:
            if not indexes:
                raise JvmFrontendError("Stack operation underflow")
            i = indexes.pop()
            used += stack[i] // 32
            values.insert(0, i)
        if used != slots:
            raise JvmFrontendError("Illegal category-2 stack operation")
        return values
    if name == "swap":
        top, below = group(1), group(1)
        return indexes + top + below
    if name in ("pop", "pop2"):
        group(1 if name == "pop" else 2)
        return indexes
    top = group(2 if name.startswith("dup2") else 1)
    below = group(int(name[-1])) if "_x" in name else []
    return indexes + top + below + top if below else indexes + top + top


def analyze_method(method, code):
    params, returns = descriptor(method["descriptor"])
    flags = method["access"]
    if not flags & 8 or flags & (0x0020 | 0x0100 | 0x0400) or method["exception_regions"]:
        raise JvmFrontendError("Only static non-native/non-synchronized methods without handlers are supported")
    if not 0 <= method["max_locals"] <= 128 or not 1 <= method["max_stack"] <= 128:
        raise JvmFrontendError("Method exceeds bounded stack/local support")
    locals_ = [0] * method["max_locals"]
    slot = 0
    for kind in params:
        width = TYPES[kind][0]
        if slot + width // 32 > len(locals_):
            raise JvmFrontendError("Arguments exceed local slots")
        locals_[slot] = width
        if width == 64:
            locals_[slot+1] = -1
        slot += width // 32
    by_offset = {i["offset"]: i for i in code}
    states = {code[0]["offset"]: ((), tuple(locals_))}
    pending = deque(states)
    while pending:
        offset = pending.popleft()
        inst = by_offset[offset]
        stack, local = list(states[offset][0]), list(states[offset][1])
        name, operand = inst["name"], inst["operand"]
        successors = [inst["next"]]
        width = 64 if name.startswith("l") else 32
        def pop(expected):
            if not stack or stack.pop() != expected:
                raise JvmFrontendError("Stack underflow/type mismatch")
        def local_index(i, bits):
            if type(i) is not int or not 0 <= i <= len(local) - bits // 32:
                raise JvmFrontendError("Invalid local slot")
        if name == "nop":
            pass
        elif name in ("iconst", "lconst"):
            stack.append(width)
        elif name in ("iload", "lload"):
            local_index(operand, width)
            if local[operand] != width or width == 64 and local[operand+1] != -1:
                raise JvmFrontendError("Uninitialized or mismatched local load")
            stack.append(width)
        elif name in ("istore", "lstore"):
            local_index(operand, width)
            pop(width)
            for i in range(operand, operand + width // 32):
                if local[i] == -1 and i:
                    local[i-1] = 0
                if local[i] == 64:
                    local[i+1] = 0
                local[i] = 0
            local[operand] = width
            if width == 64:
                local[operand+1] = -1
        elif name == "iinc":
            local_index(operand[0], 32)
            if local[operand[0]] != 32:
                raise JvmFrontendError("iinc needs initialized int local")
        elif name in ("pop", "pop2", "dup", "dup2", "dup_x1", "dup_x2", "dup2_x1", "dup2_x2", "swap"):
            stack = [stack[i] for i in stack_permutation(name, stack)]
        elif name[1:] in ("add", "sub", "mul", "and", "or", "xor"):
            pop(width); pop(width); stack.append(width)
        elif name in ("ineg", "lneg"):
            pop(width); stack.append(width)
        elif name[1:] in ("shl", "shr", "ushr"):
            pop(32); pop(width); stack.append(width)
        elif name in ("i2l", "l2i", "i2b", "i2s", "i2c"):
            pop(64 if name == "l2i" else 32)
            stack.append(64 if name == "i2l" else 32)
        elif name == "lcmp":
            pop(64); pop(64); stack.append(32)
        elif name.startswith("if"):
            pop(32)
            if name.startswith("if_icmp"):
                pop(32)
            successors.append(operand)
        elif name == "goto":
            successors = [operand]
        elif name == "switch":
            pop(32)
            successors = [operand["default"], *[target for _, target in operand["pairs"]]]
        elif name == "invokestatic":
            args, ret = descriptor(operand[2])
            for kind in reversed(args):
                pop(TYPES[kind][0])
            stack.append(TYPES[ret][0])
        elif name in ("ireturn", "lreturn"):
            if width != TYPES[returns][0]:
                raise JvmFrontendError("Return opcode/signature mismatch")
            pop(width)
            if stack:
                raise JvmFrontendError("Nonempty return stack outside supported subset")
            successors = []
        else:
            raise JvmFrontendError("Unsupported typed instruction " + name)
        if sum(w // 32 for w in stack) > method["max_stack"]:
            raise JvmFrontendError("Stack exceeds declared category-slot maximum")
        for target in successors:
            if target not in by_offset:
                raise JvmFrontendError("Branch is not an instruction boundary")
            state = (tuple(stack), tuple(local))
            if target in states:
                old_stack, old_local = states[target]
                if old_stack != state[0]:
                    raise JvmFrontendError("Stack type mismatch at branch join")
                state = (old_stack, tuple(a if a == b else 0 for a, b in zip(old_local, state[1])))
                if state == states[target]:
                    continue
            states[target] = state
            pending.append(target)
    if len(states) != len(code):
        raise JvmFrontendError("Unreachable bytecode is outside supported subset")
    return states


def emit_method(method, code, export, symbols, *, internal=False):
    states = analyze_method(method, code)
    params, ret = descriptor(method["descriptor"])
    # Preserve the C calling convention for helper calls. Internal C linkage can
    # be rewritten to LLVM fastcc, which the pinned VM does not accept. The DLL
    # export list still contains only the reviewed public roots.
    signature = "__declspec(noinline) " + TYPES[ret][1] + " " + export + "(" + (
        ", ".join(TYPES[k][1] + f" p{i}" for i, k in enumerate(params)) or "void") + ")"
    lines = [signature + " {"]
    slot = 0
    for i in range(method["max_locals"]):
        lines.append(f"  uint64_t l{i} = 0;")
    for i, kind in enumerate(params):
        lines.append(f"  l{slot} = (uint64_t)({'uint32_t' if kind == 'I' else 'uint64_t'})p{i};")
        slot += TYPES[kind][0] // 32
    for i in range(method["max_stack"]):
        lines.append(f"  uint64_t s{i} = 0, t{i} = 0;")
    for inst in code:
        name, operand, offset = inst["name"], inst["operand"], inst["offset"]
        stack = states[offset][0]
        n = len(stack)
        top, lhs, rhs = f"s{n-1}", f"s{n-2}", f"s{n-1}"
        width = 64 if name.startswith("l") else 32
        body = []
        if name == "nop":
            pass
        elif name in ("iconst", "lconst"):
            body.append(f"s{n} = UINT64_C({operand & ((1 << width)-1)});")
        elif name in ("iload", "lload"):
            body.append(f"s{n} = l{operand};")
        elif name in ("istore", "lstore"):
            body.append(f"l{operand} = {top};")
        elif name == "iinc":
            index, value = operand
            body.append(f"l{index} = (l{index} + UINT64_C({value & 0xffffffff})) & {_mask(32)};")
        elif name in ("pop", "pop2", "dup", "dup2", "dup_x1", "dup_x2", "dup2_x1", "dup2_x2", "swap"):
            permutation = stack_permutation(name, stack)
            body.extend(f"t{i} = s{i};" for i in range(n))
            body.extend(f"s{i} = t{old};" for i, old in enumerate(permutation))
        elif name[1:] in ("add", "sub", "mul", "and", "or", "xor"):
            op = {"add": "+", "sub": "-", "mul": "*", "and": "&", "or": "|", "xor": "^"}[name[1:]]
            body.append(f"{lhs} = ({lhs} {op} {rhs}) & {_mask(width)};")
        elif name in ("ineg", "lneg"):
            body.append(f"{top} = (UINT64_C(0) - {top}) & {_mask(width)};")
        elif name[1:] in ("shl", "shr", "ushr"):
            count = f"({rhs} & {width-1}u)"
            if name[1:] == "shr":
                sign = f"UINT64_C({1 << (width-1)})"
                expression = f"((({lhs} ^ {sign}) >> {count}) - ({sign} >> {count}))"
            else:
                expression = f"({lhs} {'<<' if name[1:] == 'shl' else '>>'} {count})"
            body.append(f"{lhs} = {expression} & {_mask(width)};")
        elif name in ("i2l", "l2i", "i2b", "i2s", "i2c"):
            if name == "i2l":
                expression = f"(({top} ^ UINT64_C(0x80000000)) - UINT64_C(0x80000000))"
            elif name == "l2i":
                expression = f"({top} & {_mask(32)})"
            elif name == "i2c":
                expression = f"({top} & 65535u)"
            else:
                bits = 8 if name == "i2b" else 16
                expression = f"((({top} & {(1 << bits)-1}u) ^ {1 << (bits-1)}u) - UINT64_C({1 << (bits-1)})) & {_mask(32)}"
            body.append(f"{top} = {expression};")
        elif name == "lcmp":
            greater = _comparison("cgt", lhs, rhs, 64)
            less = _comparison("clt", lhs, rhs, 64)
            body.append(f"{lhs} = {greater} ? 1u : ({less} ? UINT64_C(0xffffffff) : 0u);")
        elif name.startswith("if"):
            suffix = name[-2:]
            operation = {"eq": "beq", "ne": "bne.un", "lt": "blt", "ge": "bge", "gt": "bgt", "le": "ble"}[suffix]
            condition = _comparison(operation, lhs, rhs, 32) if name.startswith("if_icmp") else _comparison(operation, top, "UINT64_C(0)", 32)
            body.append(f"if {condition} goto BC_{operand};")
        elif name == "goto":
            body.append(f"goto BC_{operand};")
        elif name == "switch":
            body.extend(f"if ({top} == UINT64_C({key & 0xffffffff})) goto BC_{target};" for key, target in operand["pairs"])
            body.append(f"goto BC_{operand['default']};")
        elif name == "invokestatic":
            args, result = descriptor(operand[2])
            if tuple(operand) not in symbols:
                raise JvmFrontendError("Static call is not in the owned closure")
            start = n - len(args)
            call = symbols[tuple(operand)] + "(" + ", ".join(f"({TYPES[k][1]})s{start+i}" for i, k in enumerate(args)) + ")"
            body.append(f"s{start} = (uint64_t)({'uint32_t' if result == 'I' else 'uint64_t'}){call};")
        elif name in ("ireturn", "lreturn"):
            body.append(f"return ({TYPES[ret][1]}){top};")
        else:
            raise JvmFrontendError("Emission missing for " + name)
        if name not in ("ireturn", "lreturn", "goto", "switch"):
            body.append(f"goto BC_{inst['next']};")
        lines.append(f"BC_{offset}: ; /* {name} */")
        lines.extend("  " + line for line in body)
    lines.append("}\n")
    return signature + ";", "\n".join(lines), {"instruction_count": len(code), "typed_cfg_nodes": len(states),
        "jvm_opcodes": sorted({i["name"] for i in code}), "category2_local_slots_checked": True}


def resolve_closure(classes, selectors):
    methods, cp_by_class = {}, {}
    for cls in classes:
        if cls["class"] in cp_by_class:
            raise JvmFrontendError("Duplicate compiled class")
        cp_by_class[cls["class"]] = cls["constant_pool"]
        for method in cls["methods"]:
            methods[(cls["class"], method["name"], method["descriptor"])] = method
    symbols = {(s["class"].replace(".", "/"), s["name"], s["descriptor"]): s["export"] for s in selectors}
    roots = set(symbols)
    selected, active = {}, set()
    def visit(key):
        if key in active:
            raise JvmFrontendError("Recursive helper closure is unsupported")
        if key in selected:
            return
        if key not in methods or key[1].startswith("<"):
            raise JvmFrontendError("External/missing static helper: " + str(key))
        if len(selected) + len(active) >= 64:
            raise JvmFrontendError("Owned closure exceeds 64 methods")
        method = methods[key]
        if key in roots and not method["access"] & 1:
            raise JvmFrontendError("Selected roots must be public static")
        code = decode_code(method, cp_by_class[key[0]])
        analyze_method(method, code)
        active.add(key)
        for inst in code:
            if inst["name"] == "invokestatic":
                visit(tuple(inst["operand"]))
        active.remove(key)
        symbols.setdefault(key, "jvm_owned_" + hashlib.sha256(repr(key).encode()).hexdigest()[:16])
        selected[key] = (method, code)
    for key in list(symbols):
        visit(key)
    return selected, symbols, roots


def _run(argv, output, report, stop, *, stdin=None, timeout=120):
    env = os.environ.copy()
    # Ignore ambient Java startup injection/options/classpaths; only explicit
    # arguments select our compiler and reference classpaths.
    for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH"):
        env.pop(key, None)
    result = run_logged(list(map(str, argv)), output, output / "logs" / f"{len(report['commands'])+1:03d}",
                        env=env, timeout=timeout, stdin=stdin, cancel_file=stop)
    report["commands"].append(result)
    cleanup = result.get("cleanup", {})
    if result.get("returncode") != 0 or result.get("timed_out") or result.get("cancelled"):
        raise JvmFrontendError("Owned process failed: " + result["stderr"])
    if os.name == "nt" and (cleanup.get("status") != "assigned_job_empty" or not cleanup.get("job_handle_closed")):
        raise JvmFrontendError("Owned process cleanup unverified")
    return Path(result["stdout"]).read_text(encoding="utf-8-sig")


def build_project(project_path: Path, output_dir: Path, *, workspace_root: Path, seed: int = 1729) -> dict:
    root = native_build._no_links(Path(workspace_root))
    source = native_build._no_links(Path(project_path))
    output = native_build._no_links(Path(output_dir))
    if not source.is_relative_to(root):
        raise JvmFrontendError("Source must stay inside the explicit workspace")
    if output.exists() or not output.is_relative_to(root / ".runs") or output.is_relative_to(source.parent):
        raise JvmFrontendError("Output must be fresh inside workspace/.runs and outside the source project")
    inspection = inspect_project(source)
    if inspection["blockers"]:
        raise JvmFrontendError("; ".join(inspection["blockers"]))
    stop = root / ".runs/defense-loop/STOP"
    if stop.exists():
        raise JvmFrontendError("Defense STOP exists")
    output.mkdir(parents=True)
    frontend = output / "frontend"
    frontend.mkdir()
    classes_dir, helper_dir, generated = frontend / "classes", frontend / "helper", frontend / "generated"
    for directory in (classes_dir, helper_dir, generated):
        directory.mkdir()
    report = {"schema_version": 1, "status": "failed", "backend": "jvm_bytecode_native", "language": inspection["language"],
              "project": inspection, "source_hashes": inspection["input_hashes"], "compiler_inputs": inspection["compiler_inputs"],
              "target_executed": False, "commands": [], "published": False, "functional_evaluation": "not_performed",
              "external_attack_evaluation": "not_performed", "limitations": list(LIMITATIONS), "semantic_reference": SPEC}
    try:
        compiler = inspection["compiler"]
        flags = [compiler["javac"], "-proc:none", "-implicit:none", "-encoding", "UTF-8", "-g:none", "--release", "21",
                 "-classpath", str(classes_dir), "-sourcepath", str(classes_dir)]
        if inspection["language"] == "java":
            _run([*flags, "-d", classes_dir, *inspection["sources"]], output, report, stop)
        else:
            _run([compiler["java"], "-cp", compiler["kotlin_compiler"], "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler",
                  "-kotlin-home", compiler["kotlin_home"], "-jdk-home", compiler["jdk_root"], "-jvm-target", "21",
                  "-no-stdlib", "-no-reflect", "-classpath", os.pathsep.join([compiler["kotlin_stdlib"], compiler["kotlin_annotations"]]),
                  "-d", classes_dir, *inspection["sources"]], output, report, stop)
        _run([*flags, "-d", helper_dir, compiler["helper"]], output, report, stop)
        classfiles = sorted(classes_dir.rglob("*.class"))
        if not classfiles or len(classfiles) > 128:
            raise JvmFrontendError("Compilation produced no classes or more than 128")
        classes = [parse_class(path.read_bytes()) for path in classfiles]
        selected, symbols, roots = resolve_closure(classes, inspection["methods"])
        prototypes, bodies, method_reports = [], [], []
        for key, (method, code) in selected.items():
            proto, body, evidence = emit_method(method, code, symbols[key], symbols, internal=key not in roots)
            prototypes.append(proto)
            bodies.append(body)
            method_reports.append({"class": key[0], "name": key[1], "descriptor": key[2], "export": symbols[key],
                                   "is_root": key in roots, "lowering": evidence})
        _write(generated / "core.c", "#include <stdint.h>\n/* Generated from JVM bytecode; private evidence. */\n" + "\n".join(prototypes + bodies))
        _write(generated / "scope.json", {"schema_version": 1, "core_roots": inspection["functions"],
                "sensitive_functions": list(symbols.values()), "public_presentation": {}, "max_functions": 64})
        _write(generated / "project.json", {"schema_version": 1, "name": inspection["name"], "language": "c",
                "sources": ["core.c"], "functions": inspection["functions"], "scope_policy": "scope.json"})
        contract = {"schema_version": 1, "library_name": inspection["name"].replace("-", "_"), "calling_convention": "cdecl", "functions": []}
        for selector in inspection["methods"]:
            args, result = descriptor(selector["descriptor"])
            contract["functions"].append({"name": selector["export"], "return_type": TYPES[result][2],
                "parameters": [{"name": f"a{i}", "type": TYPES[kind][2]} for i, kind in enumerate(args)]})
        _write(frontend / "metadata.json", classes)
        _write(frontend / "contract.json", contract)
        report.update(methods=method_reports, contract_path=str(frontend / "contract.json"), contract=contract,
                      original_classes={str(p): _hash(p) for p in classfiles}, reference_runner=str(helper_dir),
                      reference_runner_hashes={str(p): _hash(p) for p in helper_dir.rglob("*.class")},
                      frontend_artifact_hashes={str(p.relative_to(frontend)): _hash(p) for p in frontend.rglob("*") if p.is_file()})
        native = native_build.build_project(generated / "project.json", output / "native", workspace_root=root, seed=seed)
        report.update(status=native["status"], native_report=str(output / "native/report.json"),
            native_report_sha256=_hash(output / "native/report.json"), artifacts=native.get("artifacts"),
            coverage={**(native.get("coverage") or {}), "exported_functions": inspection["functions"]},
            signature_ir={"path": str(output / "native/module.before.ll"), "sha256": native.get("artifact_hashes", {}).get("module.before.ll")})
        if native.get("error"):
            report["error"] = native["error"]
    except Exception as exc:
        report.update(status="cancelled" if stop.exists() else "failed", error=type(exc).__name__ + ": " + str(exc))
    report["changed_inputs"] = [file for file, digest in {**inspection["input_hashes"], **inspection["compiler_inputs"]}.items()
                                if not Path(file).is_file() or _hash(file) != digest]
    if report["changed_inputs"]:
        report.update(status="failed", error="Source/compiler inputs changed during build")
    _write(output / "report.json", report)
    return report


def verify_build(report_path: Path, output_dir: Path, *, workspace_root: Path,
                 random_cases: int = 8192, include_protected: bool = True, timeout_seconds: int = 120) -> dict:
    root = native_build._no_links(Path(workspace_root))
    path = native_build._no_links(Path(report_path))
    output = native_build._no_links(Path(output_dir))
    if not path.is_relative_to(root / ".runs") or not output.is_relative_to(root / ".runs") or output.exists():
        raise JvmFrontendError("Use a private build report and fresh verification directory under workspace/.runs")
    if type(random_cases) is not int or not 1 <= random_cases <= 65536:
        raise JvmFrontendError("random_cases must be 1..65536; full default is 8192")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
        raise JvmFrontendError("timeout_seconds must be 1..600")
    stop = root / ".runs/defense-loop/STOP"
    if stop.exists():
        raise JvmFrontendError("Defense STOP exists")
    build = native_build._read_json(path)
    if build.get("status") != "artifact_created_unvalidated" or build.get("backend") != "jvm_bytecode_native":
        raise JvmFrontendError("A successful JVM source build is required")
    watched = {str(path): _hash(path)}
    for file, digest in {**build["original_classes"], **build["reference_runner_hashes"]}.items():
        current = native_build._no_links(Path(file))
        if not current.is_relative_to(path.parent) or _hash(current) != digest:
            raise JvmFrontendError("Class/helper input path or hash mismatch")
        watched[str(current)] = digest
    for file, digest in build["compiler_inputs"].items():
        if not Path(file).is_file() or _hash(native_build._no_links(Path(file))) != digest:
            raise JvmFrontendError("Compiler/runtime/validator source changed since build; build again")
        watched[file] = digest
    arms = ["baseline", "protected"] if include_protected else ["baseline"]
    for arm in arms:
        artifact = build["artifacts"][arm]
        library = native_build._no_links(Path(artifact["path"]))
        if not library.is_relative_to(path.parent) or _hash(library) != artifact["sha256"]:
            raise JvmFrontendError("Native library path/hash mismatch")
        watched[str(library)] = artifact["sha256"]
    output.mkdir(parents=True)
    report = {"schema_version": 1, "status": "failed", "build_report": str(path), "build_report_sha256": _hash(path),
              "target_executed": True, "arms": arms, "commands": [], "methods": [], "validator_sha256": _hash(Path(__file__)),
              "random_cases_requested": random_cases, "timeout_seconds_per_process": timeout_seconds,
              "limitations": ["Sampled JVM equivalence only, not full semantic proof.", "No performance gate or attack evaluation.",
                              "Trusted source executes in owned processes, not a security sandbox."]}
    try:
        for index, selector in enumerate(build["project"]["methods"]):
            export = selector["export"]
            args, result = descriptor(selector["descriptor"])
            cases, counts = reference_cases([TYPES[k][3] for k in args], random_cases, 2729 + index)
            _write(output / (export + ".cases.json"), cases)
            classpath = os.pathsep.join([build["reference_runner"], str(path.parent / "frontend/classes")])
            stdout = _run([build["project"]["compiler"]["java"], "-cp", classpath, "ReferenceRunner", selector["class"],
                           selector["name"], selector["descriptor"]], output, report, stop,
                          stdin="".join(" ".join(map(str, row)) + "\n" for row in cases), timeout=timeout_seconds)
            expected = [int(line) for line in stdout.splitlines()]
            if len(expected) != len(cases):
                raise JvmFrontendError("Original JVM returned wrong result count")
            entry = {"export": export, "total": len(cases), **counts, "comparisons": {}}
            report["methods"].append(entry)
            for arm in arms:
                artifact = build["artifacts"][arm]
                request, reply = output / f"{export}-{arm}.request.json", output / f"{export}-{arm}.reply.json"
                _write(request, {"library": artifact["path"], "sha256": artifact["sha256"], "export": export,
                    "parameters": [TYPES[k][3] for k in args], "return_type": TYPES[result][3], "cases": cases, "reply": str(reply)})
                bootstrap = "import sys;sys.path.insert(0,sys.argv[1]);from antirea.dotnet_frontend import _reference_native_worker;_reference_native_worker(sys.argv[2])"
                _run([sys.executable, "-I", "-S", "-c", bootstrap, str(Path(__file__).resolve().parents[1]), request], output, report, stop, timeout=timeout_seconds)
                actual = json.loads(reply.read_text(encoding="utf-8"))["values"]
                if len(actual) != len(expected) or any(type(v) is not int for v in actual):
                    raise JvmFrontendError("Native worker returned malformed values")
                differences = [i for i, (a, b) in enumerate(zip(expected, actual)) if a != b]
                entry["comparisons"][arm] = {"status": "failed" if differences else "passed", "total": len(cases),
                    "matched": len(cases)-len(differences), "library_sha256": artifact["sha256"],
                    "mismatches": [{"case": cases[i], "jvm": expected[i], "native": actual[i]} for i in differences[:10]]}
        if report["methods"] and all(c["status"] == "passed" for m in report["methods"] for c in m["comparisons"].values()):
            report["status"] = "passed"
    except Exception as exc:
        status = "cancelled" if stop.exists() else "timed_out" if report["commands"] and report["commands"][-1].get("timed_out") else "failed"
        report.update(status=status, error=type(exc).__name__ + ": " + str(exc))
    report["changed_inputs"] = [file for file, digest in watched.items() if not Path(file).is_file() or _hash(file) != digest]
    if report["changed_inputs"]:
        report.update(status="failed", error="Verification inputs changed")
    report["artifact_hashes"] = {str(p.relative_to(output)): _hash(p) for p in output.rglob("*") if p.is_file()}
    _write(output / "report.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("inspect", "build", "verify"))
    parser.add_argument("--project", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    if args.action != "inspect" and args.output_dir is None:
        parser.error("--output-dir required")
    if args.action == "verify" and args.report is None or args.action != "verify" and args.project is None:
        parser.error("--report or --project required for selected action")
    try:
        result = inspect_project(args.project) if args.action == "inspect" else (
            build_project(args.project, args.output_dir, workspace_root=args.workspace) if args.action == "build" else
            verify_build(args.report, args.output_dir, workspace_root=args.workspace))
    except (ValueError, OSError) as exc:
        result = {"status": "rejected", "error": str(exc)}
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") in ("artifact_created_unvalidated", "passed") or result.get("route_status") == "available" else 2


if __name__ == "__main__":
    raise SystemExit(main())
