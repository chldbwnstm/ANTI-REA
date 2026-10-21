"""Owned Swift integer cores -> real LLVM graph -> native VM protection.

This experimental route operates on Swift compiler output, not a C wrapper
around an unprotected Swift implementation.  It is deliberately not a Swift
runtime implementation or a whole-application compatibility promise.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time

from . import native_build
from .process import run_logged


class SwiftFrontendError(ValueError):
    pass


LIMITATIONS = [
    "Experimental Windows x64 owned Swift scalar C-ABI exports and closed acyclic integer helpers only.",
    "Checked-overflow/trap intrinsics, exceptions, pointers, objects, floating point, indirect calls and runtime calls are rejected in the selected LLVM graph.",
    "Swift source may use wrapping arithmetic; actual compiler IR, not source spelling, determines eligibility.",
    "LLVM normalization changes only closed scalar function calling conventions and private names; original Swift compilation requires separate behavior comparison.",
    "Only explicitly selected exports are retained in the deployment library; whole modules/apps and macOS are not supported.",
    "Build coverage is not functional equivalence, performance acceptance or attack resistance.",
]


def _hash(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _changed_inputs(watched):
    changed = []
    for value, expected in watched.items():
        try:
            path = native_build._no_links(Path(value))
            if not path.is_file() or _hash(path) != expected:
                changed.append(value)
        except (OSError, ValueError):
            changed.append(value)
    return changed


def _write(path, value):
    native_build._no_links(Path(path))
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def _read_report(path):
    path = native_build._no_links(Path(path))
    if not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
        raise SwiftFrontendError("Owned Swift build report must be a regular file of at most 16 MiB")
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=native_build._pairs)
    if not isinstance(value, dict):
        raise SwiftFrontendError("Owned Swift report must be a JSON object")
    return value


def _compiler():
    repo = Path(__file__).resolve().parents[1]
    config_path = repo / ".tools/swift-toolchain.json"
    if not config_path.is_file():
        return {"blockers": ["swift_portable_compiler_not_configured"], "input_hashes": {}}
    native_build._no_links(config_path)
    config = native_build._read_json(config_path)
    if type(config.get("schema_version")) is not int or config["schema_version"] != 1:
        raise SwiftFrontendError("Swift toolchain schema_version must be 1")
    swiftc = native_build._no_links(Path(config["swiftc"]))
    if not swiftc.is_file() or not swiftc.is_relative_to(repo / ".tools"):
        raise SwiftFrontendError("Portable Swift compiler must be an existing file in repository/.tools")
    sdk = native_build._no_links(Path(config["sdk"])) if config.get("sdk") else None
    if sdk is not None and (not sdk.is_dir() or not sdk.is_relative_to(repo / ".tools")):
        raise SwiftFrontendError("Portable Swift SDK must be an existing directory in repository/.tools")
    runtime_dirs = config.get("runtime_dirs", [])
    if not isinstance(runtime_dirs, list) or len(runtime_dirs) > 8:
        raise SwiftFrontendError("Swift runtime_dirs must be a bounded list")
    runtime = {}
    for value in runtime_dirs:
        directory = native_build._no_links(Path(value))
        if not directory.is_dir() or not directory.is_relative_to(repo / ".tools"):
            raise SwiftFrontendError("Swift runtime DLL roots must be under repository/.tools")
        for file in sorted(directory.glob("*.dll")):
            native_build._no_links(file)
            if file.name.casefold() in runtime:
                previous = Path(runtime[file.name.casefold()])
                if _hash(previous) != _hash(file):
                    raise SwiftFrontendError("Conflicting portable runtime DLL names")
            runtime[file.name.casefold()] = str(file)
    if len(runtime) > 128 or sum(Path(file).stat().st_size for file in runtime.values()) > 512 * 1024 * 1024:
        raise SwiftFrontendError("Swift runtime inventory exceeds limits")
    pinned = config.get("input_hashes", {})
    if not isinstance(pinned, dict) or not pinned:
        raise SwiftFrontendError("Swift compiler configuration requires explicit input_hashes")
    for value, expected in pinned.items():
        path = native_build._no_links(Path(value))
        if (not path.is_relative_to(repo / ".tools") or not path.is_file()
                or not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected)
                or _hash(path) != expected):
            raise SwiftFrontendError("Swift pinned toolchain input mismatch: " + str(path))
    if str(swiftc) not in pinned:
        raise SwiftFrontendError("Swift compiler executable requires a configured hash pin")
    native_config = native_build._read_json(repo / ".tools/kagura-toolchain.json")
    llvm_library = native_build._no_links(Path(native_config["llvm_root"]) / "bin/LLVM-C.dll")
    if not llvm_library.is_file():
        raise SwiftFrontendError("Pinned LLVM-C parser is missing")
    inputs = {**pinned, str(config_path): _hash(config_path), str(llvm_library): _hash(llvm_library),
              str(Path(__file__).resolve()): _hash(Path(__file__).resolve())}
    inputs.update({file: _hash(file) for file in runtime.values()})
    return {"swiftc": str(swiftc), "sdk": str(sdk) if sdk else None,
            "version": config.get("version"), "runtime_files": runtime,
            "search_dirs": [str(swiftc.parent), *runtime_dirs],
            "llvm_library": str(llvm_library), "input_hashes": inputs, "blockers": []}


def inspect_project(project_path: Path) -> dict:
    """Validate/pin a Swift project without running its compiler or source."""
    path = native_build._no_links(Path(project_path))
    if any(part.casefold() in {"rea-analysis-reports", "attackerfolder"} for part in path.parts):
        raise SwiftFrontendError("Received/shared data cannot be a Swift source project")
    data = native_build._read_json(path)
    if set(data) != {"schema_version", "name", "language", "sources", "functions"}:
        raise SwiftFrontendError("Expected schema_version, name, language, sources and functions only")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1 or data["language"] != "swift":
        raise SwiftFrontendError("Expected schema_version 1 and language swift")
    if not isinstance(data["name"], str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", data["name"]):
        raise SwiftFrontendError("Invalid Swift project name")
    if not isinstance(data["sources"], list) or len(data["sources"]) != 1:
        raise SwiftFrontendError("Initial Swift route requires one owned .swift compilation unit")
    source = native_build._relative(path.parent, data["sources"][0])
    if source.suffix != ".swift" or source.stat().st_size > 512 * 1024:
        raise SwiftFrontendError("Swift source must be a .swift file of at most 512 KiB")
    functions = data["functions"]
    if (not isinstance(functions, list) or not 1 <= len(functions) <= 16
            or any(not isinstance(value, str) or not native_build.SYMBOL.fullmatch(value)
                   or value.startswith(("antirea_", "kagura_")) for value in functions)
            or len(set(functions)) != len(functions)):
        raise SwiftFrontendError("functions must be 1..16 unique ordinary exported C ABI names")
    compiler = _compiler()
    return {"schema_version": 1, "project_path": str(path), "project_root": str(path.parent),
        "name": data["name"], "language": "swift", "sources": [str(source)], "source_files": [str(source)],
        "functions": list(functions), "exported_functions": list(functions),
        "target": native_build.TARGET, "artifact": "shared_library", "backend": "swift_llvm_native",
        "compiler": compiler, "compiler_inputs": compiler["input_hashes"],
        "input_hashes": native_build._snapshot([path.parent], [path]),
        "route_status": "unsupported" if compiler["blockers"] else "available",
        "blockers": compiler["blockers"], "experimental": True, "limitations": list(LIMITATIONS),
        "source_executed": False, "scope_status": "requires_swift_compilation_and_ir_inspection"}


def parse_public_interface(text, exports):
    """Read signatures from compiler-produced .swiftinterface, not source regexes."""
    scalar = {"UInt32": "u32", "Int32": "i32", "UInt64": "u64", "Int64": "i64"}
    result, pending = {}, None
    for raw in text.splitlines():
        line = raw.strip()
        attribute = re.fullmatch(r'@_cdecl\("([A-Za-z_][A-Za-z0-9_]*)"\)', line)
        if attribute:
            pending = attribute[1]
            continue
        if not pending or not line or line.startswith("//"):
            continue
        if line.startswith("@"):
            continue
        export, pending = pending, None
        if export not in exports:
            continue
        signature = re.fullmatch(r'public func ([A-Za-z_][A-Za-z0-9_]*)\((.*)\) -> (?:Swift(?:\.|::))?(UInt32|Int32|UInt64|Int64)', line)
        if signature is None:
            raise SwiftFrontendError("Unsupported Swift public signature for " + export)
        parameters = []
        for item in signature[2].split(",") if signature[2].strip() else []:
            parameter = re.fullmatch(r'\s*(?:(?:_|[A-Za-z_][A-Za-z0-9_]*)\s+)?([A-Za-z_][A-Za-z0-9_]*):\s*(?:Swift(?:\.|::))?(UInt32|Int32|UInt64|Int64)\s*', item)
            if parameter is None:
                raise SwiftFrontendError("Swift exports require explicit scalar named parameters")
            parameters.append({"name": parameter[1], "type": scalar[parameter[2]]})
        if len(parameters) > 8 or len({item["name"] for item in parameters}) != len(parameters) or export in result:
            raise SwiftFrontendError("Duplicate/oversized Swift public signature")
        result[export] = {"name": export, "swift_name": signature[1], "return_type": scalar[signature[3]], "parameters": parameters}
    if set(result) != set(exports):
        raise SwiftFrontendError("Every selected C export needs an exact compiler-emitted public Swift scalar signature")
    return [result[name] for name in exports]


class _LLVM:
    """Small pinned LLVM-C API surface; target code is parsed, never executed."""

    def __init__(self, library):
        library = native_build._no_links(Path(library))
        if not library.is_file():
            raise SwiftFrontendError("Pinned LLVM-C parser library is missing")
        self.search = os.add_dll_directory(str(library.parent)) if os.name == "nt" else None
        self.dll = ctypes.CDLL(str(library))
        p, u, s, z = ctypes.c_void_p, ctypes.c_uint, ctypes.c_char_p, ctypes.c_size_t
        definitions = {
            "LLVMContextCreate": (p, []), "LLVMContextDispose": (None, [p]),
            "LLVMCreateMemoryBufferWithMemoryRangeCopy": (p, [s, z, s]),
            "LLVMParseIRInContext": (ctypes.c_int, [p, p, ctypes.POINTER(p), ctypes.POINTER(p)]),
            "LLVMDisposeModule": (None, [p]), "LLVMDisposeMessage": (None, [p]),
            "LLVMPrintModuleToString": (p, [p]), "LLVMPrintValueToString": (p, [p]),
            "LLVMVerifyModule": (ctypes.c_int, [p, ctypes.c_int, ctypes.POINTER(p)]),
            "LLVMGetTarget": (s, [p]), "LLVMSetTarget": (None, [p, s]),
            "LLVMGetModuleInlineAsm": (s, [p, ctypes.POINTER(z)]),
            "LLVMGetFirstFunction": (p, [p]), "LLVMGetNextFunction": (p, [p]),
            "LLVMGetValueName2": (p, [p, ctypes.POINTER(z)]), "LLVMSetValueName2": (None, [p, s, z]),
            "LLVMIsDeclaration": (ctypes.c_int, [p]), "LLVMGetFunctionCallConv": (u, [p]),
            "LLVMSetFunctionCallConv": (None, [p, u]), "LLVMGlobalGetValueType": (p, [p]),
            "LLVMGetReturnType": (p, [p]), "LLVMCountParamTypes": (u, [p]),
            "LLVMGetParamTypes": (None, [p, ctypes.POINTER(p)]), "LLVMIsFunctionVarArg": (ctypes.c_int, [p]),
            "LLVMGetTypeKind": (u, [p]), "LLVMGetIntTypeWidth": (u, [p]), "LLVMTypeOf": (p, [p]),
            "LLVMGetFirstBasicBlock": (p, [p]), "LLVMGetNextBasicBlock": (p, [p]),
            "LLVMGetFirstInstruction": (p, [p]), "LLVMGetNextInstruction": (p, [p]),
            "LLVMGetInstructionOpcode": (u, [p]), "LLVMGetNumOperands": (ctypes.c_int, [p]),
            "LLVMGetOperand": (p, [p, u]), "LLVMGetValueKind": (u, [p]),
            "LLVMGetFirstUse": (p, [p]),
            "LLVMGetCalledValue": (p, [p]), "LLVMGetCalledFunctionType": (p, [p]),
            "LLVMGetInstructionCallConv": (u, [p]), "LLVMSetInstructionCallConv": (None, [p, u]),
            "LLVMGetNumOperandBundles": (u, [p]), "LLVMGetIntrinsicID": (u, [p]),
            "LLVMGetFirstGlobal": (p, [p]), "LLVMGetNextGlobal": (p, [p]),
            "LLVMGetFirstGlobalAlias": (p, [p]), "LLVMGetNextGlobalAlias": (p, [p]),
            "LLVMGetFirstGlobalIFunc": (p, [p]), "LLVMDeleteGlobal": (None, [p]),
            "LLVMGetNamedMetadataNumOperands": (u, [p, s]),
            "LLVMGetNamedMetadataOperands": (None, [p, s, ctypes.POINTER(p)]),
            "LLVMGetMDNodeNumOperands": (u, [p]), "LLVMGetMDNodeOperands": (None, [p, ctypes.POINTER(p)]),
            "LLVMGetMDString": (p, [p, ctypes.POINTER(u)]),
            "LLVMSetLinkage": (None, [p, u]), "LLVMSetDLLStorageClass": (None, [p, u]),
            "LLVMSetVisibility": (None, [p, u]),
            "LLVMGetEnumAttributeKindForName": (u, [s, z]),
            "LLVMRemoveEnumAttributeAtIndex": (None, [p, u, u]),
            "LLVMCreateEnumAttribute": (p, [p, u, ctypes.c_ulonglong]),
            "LLVMAddAttributeAtIndex": (None, [p, u, p]),
            "LLVMCreatePassBuilderOptions": (p, []), "LLVMDisposePassBuilderOptions": (None, [p]),
            "LLVMRunPasses": (p, [p, s, p, p]), "LLVMGetErrorMessage": (p, [p]),
            "LLVMDisposeErrorMessage": (None, [p]),
        }
        for name, (result, arguments) in definitions.items():
            try:
                callback = getattr(self.dll, name)
            except AttributeError as exc:
                raise SwiftFrontendError("Pinned LLVM parser API is incomplete: " + name) from exc
            callback.restype, callback.argtypes = result, arguments
            setattr(self, name, callback)

    def close(self):
        if self.search:
            self.search.close()

    def name(self, value):
        size = ctypes.c_size_t()
        pointer = self.LLVMGetValueName2(value, ctypes.byref(size))
        return ctypes.string_at(pointer, size.value).decode("utf-8") if pointer else ""

    def string(self, pointer):
        try:
            return ctypes.string_at(pointer).decode("utf-8") if pointer else ""
        finally:
            if pointer:
                self.LLVMDisposeMessage(pointer)

    def values(self, first, following, owner):
        value = first(owner)
        while value:
            yield value
            value = following(value)

    def functions(self, module):
        return list(self.values(self.LLVMGetFirstFunction, self.LLVMGetNextFunction, module))

    def instructions(self, function):
        for block in self.values(self.LLVMGetFirstBasicBlock, self.LLVMGetNextBasicBlock, function):
            yield from self.values(self.LLVMGetFirstInstruction, self.LLVMGetNextInstruction, block)

    def signature(self, function):
        signature = self.LLVMGlobalGetValueType(function)
        count = self.LLVMCountParamTypes(signature)
        values = (ctypes.c_void_p * count)()
        self.LLVMGetParamTypes(signature, values)
        types = [self.LLVMGetReturnType(signature), *values]
        if self.LLVMIsFunctionVarArg(signature) or count > 8:
            raise SwiftFrontendError("Swift core signatures require up to eight nonvariadic integer arguments")
        if any(self.LLVMGetTypeKind(value) != 8 or self.LLVMGetIntTypeWidth(value) not in (32, 64) for value in types):
            raise SwiftFrontendError("Swift core signatures require scalar i32/i64 return and arguments")
        rendered = self.string(self.LLVMPrintValueToString(function)).split("{", 1)[0]
        if re.search(r"\b(?:swiftself|swifterror|swiftasync|sret|byval|byref|inalloca|preallocated|nest|inreg)\b", rendered):
            raise SwiftFrontendError("Special Swift/C ABI parameter attributes are unsupported")
        return {"return_bits": self.LLVMGetIntTypeWidth(types[0]),
                "parameter_bits": [self.LLVMGetIntTypeWidth(value) for value in types[1:]]}


def normalize_llvm(ir: str, exports: list[str], *, llvm_library: Path) -> tuple[str, dict]:
    """Validate/normalize a closed scalar graph using LLVM's actual IR parser.

    Unselected module code is removed using LLVM global DCE, not by executing
    source, rewriting arithmetic, or extracting source with regular expressions.
    Unsupported traps are rejected rather than silently changed into wrapping.
    """
    if not isinstance(ir, str) or len(ir.encode("utf-8")) > 16 * 1024 * 1024:
        raise SwiftFrontendError("Swift LLVM input must be text of at most 16 MiB")
    if (not isinstance(exports, list) or not 1 <= len(exports) <= 16
            or len(set(exports)) != len(exports)
            or any(not isinstance(name, str) or not native_build.SYMBOL.fullmatch(name)
                   or name.startswith(("antirea_", "kagura_")) for name in exports)):
        raise SwiftFrontendError("Expected 1..16 unique ordinary C export names")
    llvm, context, module = _LLVM(llvm_library), None, ctypes.c_void_p()
    try:
        context = llvm.LLVMContextCreate()
        data = ir.encode("utf-8")
        buffer = llvm.LLVMCreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"owned-swift.ll")
        error = ctypes.c_void_p()
        if llvm.LLVMParseIRInContext(context, buffer, ctypes.byref(module), ctypes.byref(error)):
            raise SwiftFrontendError("Swift LLVM parser rejected input: " + llvm.string(error.value))
        if llvm.LLVMVerifyModule(module, 2, ctypes.byref(error)):
            raise SwiftFrontendError("Invalid Swift LLVM module: " + llvm.string(error.value))
        target = llvm.LLVMGetTarget(module).decode("ascii")
        if not re.fullmatch(r"x86_64-(?:pc|unknown)-windows-msvc(?:[0-9]+(?:\.[0-9]+)*)?", target):
            raise SwiftFrontendError("Swift LLVM target must be Windows x86-64 MSVC")
        llvm.LLVMSetTarget(module, native_build.TARGET.encode("ascii"))
        length = ctypes.c_size_t()
        llvm.LLVMGetModuleInlineAsm(module, ctypes.byref(length))
        if length.value or llvm.LLVMGetFirstGlobalIFunc(module):
            raise SwiftFrontendError("Module assembly/indirect functions are unsupported")
        definitions = {llvm.name(value): value for value in llvm.functions(module) if not llvm.LLVMIsDeclaration(value)}
        if not set(exports).issubset(definitions):
            raise SwiftFrontendError("Selected C export definition is missing")
        globals_ = list(llvm.values(llvm.LLVMGetFirstGlobal, llvm.LLVMGetNextGlobal, module))
        if any(llvm.name(value) in {"llvm.global_ctors", "llvm.global_dtors"} for value in globals_):
            raise SwiftFrontendError("Module initializers/finalizers are unsupported")
        graph, calls, signatures, conventions = {}, [], {}, {}
        pending = list(exports)
        # Pure integer SSA instructions only. In particular no memory, pointers,
        # aggregate overflow results, poison-producing freeze fallback or EH.
        allowed = {1, 2, 3, 8, 10, 12, 14, 15, 17, 18, 20, 21, 22, 23, 24, 25, 30, 31, 32, 42, 44, 45, 46}
        intrinsic = re.compile(r"llvm\.(?:[su]min|[su]max|abs)\.i(?:8|16|32|64)\Z")
        while pending:
            name = pending.pop()
            if name in graph:
                continue
            if len(graph) >= 64:
                raise SwiftFrontendError("Swift helper closure exceeds 64 functions")
            function = definitions[name]
            signatures[name] = llvm.signature(function)
            convention = llvm.LLVMGetFunctionCallConv(function)
            conventions[name] = convention
            if convention not in (0, 16) or (name in exports and convention != 0):
                raise SwiftFrontendError("Export must use C ABI; helpers may use scalar C or Swift calling convention")
            graph[name] = set()
            for instruction in llvm.instructions(function):
                opcode = llvm.LLVMGetInstructionOpcode(instruction)
                if opcode not in allowed:
                    raise SwiftFrontendError(f"Unsupported Swift LLVM opcode {opcode} in {name}")
                result = llvm.LLVMTypeOf(instruction)
                kind = llvm.LLVMGetTypeKind(result)
                if kind != 0 and (kind != 8 or llvm.LLVMGetIntTypeWidth(result) > 64):
                    raise SwiftFrontendError("Noninteger/aggregate instruction result is unsupported in " + name)
                callee = None
                if opcode == 45:
                    callee = llvm.LLVMGetCalledValue(instruction)
                    if not callee or llvm.LLVMGetValueKind(callee) != 5 or llvm.LLVMGetNumOperandBundles(instruction):
                        raise SwiftFrontendError("Only ordinary direct calls without operand bundles are supported")
                    target_name = llvm.name(callee)
                    if llvm.LLVMGetIntrinsicID(callee):
                        if not intrinsic.fullmatch(target_name):
                            raise SwiftFrontendError("Unsupported Swift intrinsic (including traps/checked overflow): " + target_name)
                    else:
                        if target_name not in definitions:
                            raise SwiftFrontendError("Swift runtime/external call is unsupported: " + target_name)
                        if (llvm.LLVMGetCalledFunctionType(instruction) != llvm.LLVMGlobalGetValueType(callee)
                                or llvm.LLVMGetInstructionCallConv(instruction) != llvm.LLVMGetFunctionCallConv(callee)):
                            raise SwiftFrontendError("Swift helper call signature/convention mismatch")
                        graph[name].add(target_name)
                        pending.append(target_name)
                        calls.append(instruction)
                for index in range(llvm.LLVMGetNumOperands(instruction)):
                    operand = llvm.LLVMGetOperand(instruction, index)
                    operand_type = llvm.LLVMTypeOf(operand)
                    operand_kind = llvm.LLVMGetTypeKind(operand_type)
                    if operand == callee or operand_kind == 7:  # direct callee / branch target
                        continue
                    if operand_kind != 8 or llvm.LLVMGetIntTypeWidth(operand_type) > 64:
                        raise SwiftFrontendError("Pointer/global/aggregate operands are unsupported in " + name)
                    # Poison/undef are not source values our runtime can preserve.
                    if llvm.LLVMGetValueKind(operand) in (14, 25):
                        raise SwiftFrontendError("Undefined/poison Swift LLVM operands are unsupported")
                    if llvm.LLVMGetValueKind(operand) not in (0, 18, 24):
                        raise SwiftFrontendError("Only direct scalar SSA values and literal integers are supported")
        visiting, visited = set(), set()

        def visit(name):
            if name in visiting:
                raise SwiftFrontendError("Recursive Swift helper closure is unsupported")
            if name in visited:
                return
            visiting.add(name)
            for child in graph[name]:
                visit(child)
            visiting.remove(name)
            visited.add(name)

        for name in exports:
            visit(name)
        renamed = {name: name if name in exports else f"antirea_swift_helper_{index:03d}"
                   for index, name in enumerate(sorted(graph))}
        # Both sides of every selected call are changed together; noninteger
        # conventions and references have already been rejected above.
        for name in sorted(graph):
            function = definitions[name]
            encoded = renamed[name].encode("ascii")
            llvm.LLVMSetValueName2(function, encoded, len(encoded))
            llvm.LLVMSetFunctionCallConv(function, 0)
            # Preserve the selected helper as its own protectable body through
            # the later native optimizer; this changes optimization, not math.
            for attribute in (b"alwaysinline", b"inlinehint"):
                kind = llvm.LLVMGetEnumAttributeKindForName(attribute, len(attribute))
                llvm.LLVMRemoveEnumAttributeAtIndex(function, 0xffffffff, kind)
            kind = llvm.LLVMGetEnumAttributeKindForName(b"noinline", 8)
            llvm.LLVMAddAttributeAtIndex(function, 0xffffffff, llvm.LLVMCreateEnumAttribute(context, kind, 0))
        for call in calls:
            llvm.LLVMSetInstructionCallConv(call, 0)
        for function in llvm.functions(module):
            if llvm.LLVMIsDeclaration(function):
                continue
            public = llvm.name(function) in exports
            llvm.LLVMSetDLLStorageClass(function, 2 if public else 0)
            llvm.LLVMSetVisibility(function, 0)
            llvm.LLVMSetLinkage(function, 0 if public else 8)
        for value in globals_:
            if llvm.name(value) in {"llvm.used", "llvm.compiler.used"}:
                if llvm.LLVMGetFirstUse(value):
                    raise SwiftFrontendError("Unexpected referenced compiler retention global")
                llvm.LLVMDeleteGlobal(value)
            elif not llvm.LLVMIsDeclaration(value):
                llvm.LLVMSetDLLStorageClass(value, 0)
                llvm.LLVMSetVisibility(value, 0)
                llvm.LLVMSetLinkage(value, 8)
        for alias in llvm.values(llvm.LLVMGetFirstGlobalAlias, llvm.LLVMGetNextGlobalAlias, module):
            llvm.LLVMSetDLLStorageClass(alias, 0)
            llvm.LLVMSetVisibility(alias, 0)
            llvm.LLVMSetLinkage(alias, 8)
        options = llvm.LLVMCreatePassBuilderOptions()
        try:
            failure = llvm.LLVMRunPasses(module, b"globaldce,strip-dead-prototypes", None, options)
            if failure:
                message = llvm.LLVMGetErrorMessage(failure)
                try:
                    raise SwiftFrontendError("Swift LLVM cleanup failed: " + ctypes.string_at(message).decode("utf-8"))
                finally:
                    llvm.LLVMDisposeErrorMessage(message)
        finally:
            llvm.LLVMDisposePassBuilderOptions(options)
        surviving = {llvm.name(value) for value in llvm.functions(module) if not llvm.LLVMIsDeclaration(value)}
        if surviving != set(renamed.values()):
            raise SwiftFrontendError("Normalized Swift definitions differ from the complete protected closure")
        if llvm.LLVMGetFirstGlobal(module) or llvm.LLVMGetFirstGlobalAlias(module):
            raise SwiftFrontendError("Selected Swift graph retained unsupported global data or aliases")
        # Internal functions are eligible for GlobalOpt's C->fastcc rewrite.
        # Keep selected helpers externally linked but hidden/not dllexport so
        # the later optimizer preserves the C call ABI the interpreter needs.
        # The native builder's .def still exports only the public roots.
        for function in llvm.functions(module):
            if not llvm.LLVMIsDeclaration(function) and llvm.name(function) not in exports:
                llvm.LLVMSetLinkage(function, 0)
                llvm.LLVMSetVisibility(function, 1)
        if llvm.LLVMVerifyModule(module, 2, ctypes.byref(error)):
            raise SwiftFrontendError("Normalized Swift LLVM verification failed: " + llvm.string(error.value))
        result = llvm.string(llvm.LLVMPrintModuleToString(module))
        autolink_count = llvm.LLVMGetNamedMetadataNumOperands(module, b"llvm.linker.options")
        removed_autolinks = []
        if autolink_count:
            nodes = (ctypes.c_void_p * autolink_count)()
            llvm.LLVMGetNamedMetadataOperands(module, b"llvm.linker.options", nodes)
            options = []
            for node in nodes:
                if llvm.LLVMGetMDNodeNumOperands(node) != 1:
                    raise SwiftFrontendError("Unsupported Swift autolink metadata shape")
                operand = (ctypes.c_void_p * 1)()
                llvm.LLVMGetMDNodeOperands(node, operand)
                size = ctypes.c_uint()
                pointer = llvm.LLVMGetMDString(operand[0], ctypes.byref(size))
                if not pointer:
                    raise SwiftFrontendError("Swift autolink option must be a literal metadata string")
                option = ctypes.string_at(pointer, size.value).decode("ascii")
                if not (re.fullmatch(r"/DEFAULTLIB:swift[A-Za-z0-9_]*\.lib", option)
                        or option in ("/DEFAULTLIB:oldnames.lib", "/DEFAULTLIB:msvcrt.lib")):
                    raise SwiftFrontendError("Unsupported compiler linker option: " + option)
                options.append(option)
            line = re.search(r"^!llvm\.linker\.options = !\{([^\n]*)\}$", result, re.M)
            ids = re.findall(r"!\d+", line[1]) if line else []
            if not line or len(ids) != len(options):
                raise SwiftFrontendError("Canonical LLVM autolink metadata did not match parsed nodes")
            keep = [value for value, option in zip(ids, options) if not option.startswith("/DEFAULTLIB:swift")]
            removed_autolinks = [option for option in options if option.startswith("/DEFAULTLIB:swift")]
            result = result[:line.start()] + ("!llvm.linker.options = !{" + ", ".join(keep) + "}" if keep else "") + result[line.end():]
            # Metadata-only serialization change is checked with the same real
            # LLVM parser/verifier, not accepted merely because text matched.
            checked = ctypes.c_void_p()
            encoded = result.encode("utf-8")
            buffer = llvm.LLVMCreateMemoryBufferWithMemoryRangeCopy(encoded, len(encoded), b"normalized-swift.ll")
            try:
                if llvm.LLVMParseIRInContext(context, buffer, ctypes.byref(checked), ctypes.byref(error)):
                    raise SwiftFrontendError("Normalized autolink metadata failed parsing: " + llvm.string(error.value))
                if llvm.LLVMVerifyModule(checked, 2, ctypes.byref(error)):
                    raise SwiftFrontendError("Normalized autolink metadata failed verification: " + llvm.string(error.value))
                result = llvm.string(llvm.LLVMPrintModuleToString(checked))
            finally:
                if checked.value:
                    llvm.LLVMDisposeModule(checked)
        return result, {"schema_version": 1, "status": "normalized_closed_integer_graph",
            "source_target": target, "selected_functions": sorted(renamed.values()), "exported_functions": list(exports),
            "functions": {renamed[name]: {"original_symbol": name, **signatures[name],
                "original_calling_convention": "swift" if conventions[name] == 16 else "c",
                "calling_convention": "c", "calls": sorted(renamed[child] for child in graph[name]),
                "is_root": name in exports} for name in sorted(graph)},
            "unselected_definitions_removed": sorted(set(definitions) - set(graph)),
            "arithmetic_rewritten": False, "target_executed": False,
            "selected_function_inlining": "disabled_to_preserve_per_function_coverage",
            "helper_linkage": "external_hidden_not_dll_exported_to_preserve_c_calling_convention",
            "removed_unused_swift_autolink_options": removed_autolinks,
            "qualification": "Compiler-IR graph/ABI normalization only; original Swift equivalence remains unvalidated."}
    finally:
        if module.value:
            llvm.LLVMDisposeModule(module)
        if context:
            llvm.LLVMContextDispose(context)
        llvm.close()


def _process_env():
    # Do not inherit driver replacement, compiler flags, import preload or
    # project-specific SDK overrides. The fixed installed VS initializer below
    # supplies only its normal compiler/linker search variables.
    denied = {"SDKROOT", "DEVELOPER_DIR", "CL", "_CL_", "LINK", "CPATH", "C_INCLUDE_PATH",
              "CPLUS_INCLUDE_PATH", "LIBRARY_PATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES"}
    return {key: value for key, value in os.environ.items()
            if key.upper() not in denied and not key.upper().startswith("SWIFT_")}


def build_project(project_path: Path, output_dir: Path, *, workspace_root: Path, seed: int = 1729) -> dict:
    """Compile owned Swift and create protected artifacts, never execute them."""
    project = inspect_project(project_path)
    if project["blockers"]:
        raise SwiftFrontendError("; ".join(project["blockers"]))
    root = native_build._no_links(Path(workspace_root))
    output = native_build._no_links(Path(output_dir))
    if (os.name != "nt" or not output.is_relative_to(root / ".runs") or output == root / ".runs"
            or output.exists() or output.is_relative_to(Path(project["project_root"]))
            or not Path(project["project_path"]).is_relative_to(root)
            or any(part.casefold() in {"rea-analysis-reports", "attackerfolder", "defense-loop"} for part in output.parts)):
        raise SwiftFrontendError("Swift builds require owned source and fresh private Windows workspace/.runs output")
    if type(seed) is not int or not 1 <= seed <= 2147483647:
        raise SwiftFrontendError("seed must be a positive 31-bit integer")
    stop = root / ".runs/defense-loop/STOP"
    if stop.exists():
        raise SwiftFrontendError("Defense STOP exists")
    output.mkdir(parents=True)
    frontend = output / "frontend"
    frontend.mkdir()
    reference_dir = frontend / "reference"
    reference_dir.mkdir()
    compiler = project["compiler"]
    watched = {**project["input_hashes"], **compiler["input_hashes"]}
    report = {"schema_version": 1, "status": "building", "backend": "swift_llvm_native",
              "language": "swift", "project": project, "seed": seed, "commands": [],
              "functional_evaluation": "not_performed", "performance_evaluation": "not_performed",
              "external_attack_evaluation": "not_performed", "published": False,
              "target_executed": False, "limitations": list(LIMITATIONS)}
    started, env = time.monotonic(), _process_env()

    def run(argv, timeout=180):
        result = run_logged(list(map(str, argv)), output, output / "logs" / f"{len(report['commands']) + 1:03d}",
                            timeout=timeout, cancel_file=stop, env=env)
        report["commands"].append(result)
        if result.get("returncode") != 0 or result.get("timed_out") or result.get("cancelled") or result.get("error"):
            raise SwiftFrontendError("Swift compiler command failed: " + str(result.get("stderr")))
        cleanup = result.get("cleanup", {})
        if (cleanup.get("status") != "assigned_job_empty" or not cleanup.get("parent_exit_confirmed")
                or not cleanup.get("job_handle_closed")):
            raise SwiftFrontendError("Swift compiler process cleanup is unverified")
        stdout = Path(result["stdout"])
        if stdout.stat().st_size > 1024 * 1024:
            raise SwiftFrontendError("Swift compiler control output exceeds 1 MiB")
        return stdout.read_text(encoding="utf-8-sig")

    try:
        native_tools, native_pins = native_build._toolchain(root)
        watched.update(native_pins)
        powershell = shutil.which("powershell.exe")
        if not powershell:
            raise SwiftFrontendError("Installed Windows PowerShell/Visual Studio SDK initializer required")
        env["ANTIREA_SWIFT_DEVSHELL"] = native_tools["developer_shell"]
        names = ("INCLUDE", "LIB", "LIBPATH", "PATH", "VCINSTALLDIR", "VCToolsInstallDir",
                 "WindowsSdkDir", "WindowsSDKVersion", "UniversalCRTSdkDir", "UCRTVersion")
        script = ("$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); "
                  "& $env:ANTIREA_SWIFT_DEVSHELL -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null; "
                  "$swiftSdk=@{}; foreach($swiftKey in @('" + "','".join(names) + "')) { "
                  "$swiftValue=[Environment]::GetEnvironmentVariable($swiftKey); "
                  "if($swiftValue) { $swiftSdk[$swiftKey]=$swiftValue } }; $swiftSdk | ConvertTo-Json -Compress")
        sdk_env = json.loads(run([powershell, "-NoProfile", "-NonInteractive", "-Command", script], 60))
        env.pop("ANTIREA_SWIFT_DEVSHELL", None)
        if not isinstance(sdk_env, dict) or set(sdk_env) - set(names) or not sdk_env.get("INCLUDE") or not sdk_env.get("LIB"):
            raise SwiftFrontendError("Visual Studio SDK environment is incomplete")
        for key, value in sdk_env.items():
            for previous in list(env):
                if previous.upper() == key.upper():
                    del env[previous]
            env[key] = value
        path_key = next((key for key in env if key.upper() == "PATH"), "PATH")
        env[path_key] = os.pathsep.join(compiler["search_dirs"] + [env.get(path_key, "")])
        report["sdk_environment"] = sdk_env
        version = run([compiler["swiftc"], "--version"], 30)
        report["swift_version"] = version
        if compiler.get("version") and str(compiler["version"]) not in version:
            raise SwiftFrontendError("Swift compiler version differs from configured version")
        source = frontend / "source.swift"
        with source.open("xb") as stream:
            stream.write(Path(project["sources"][0]).read_bytes())
        base = [compiler["swiftc"], "-parse-as-library", "-module-name", "AntireaOwned", "-language-mode", "6", "-O"]
        if compiler["sdk"]:
            base.extend(["-sdk", compiler["sdk"]])
        interface = frontend / "AntireaOwned.swiftinterface"
        run([*base, "-enable-library-evolution", "-emit-module", "-emit-module-path", frontend / "AntireaOwned.swiftmodule",
             "-emit-module-interface-path", interface, source])
        if interface.stat().st_size > 1024 * 1024:
            raise SwiftFrontendError("Compiler-produced Swift interface exceeds 1 MiB")
        signatures = parse_public_interface(interface.read_text(encoding="utf-8"), project["functions"])
        raw_ir = frontend / "swift.original.ll"
        run([*base, "-emit-ir", source, "-o", raw_ir])
        if raw_ir.stat().st_size > 16 * 1024 * 1024:
            raise SwiftFrontendError("Compiler-produced Swift LLVM exceeds 16 MiB")
        normalized, closure = normalize_llvm(raw_ir.read_text(encoding="utf-8"), project["functions"],
                                              llvm_library=Path(compiler["llvm_library"]))
        for entry in signatures:
            actual = closure["functions"][entry["name"]]
            if (int(entry["return_type"][1:]) != actual["return_bits"]
                    or [int(p["type"][1:]) for p in entry["parameters"]] != actual["parameter_bits"]):
                raise SwiftFrontendError("Compiler public Swift signature disagrees with actual C ABI LLVM")
        normalized_path = frontend / "swift.normalized.ll"
        with normalized_path.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(normalized)
        _write(frontend / "normalization.json", closure)
        contract = {"schema_version": 1, "library_name": "protected", "functions": [
            {key: entry[key] for key in ("name", "return_type", "parameters")} for entry in signatures]}
        _write(frontend / "contract.json", contract)
        # Independent, unnormalized Swift driver compilation is the original
        # language reference. It is never loaded by the build operation.
        original = reference_dir / "original.dll"
        run([*base, "-emit-library", source, "-o", original])
        runtime_files = {}
        for value in compiler["runtime_files"].values():
            source_runtime = Path(value)
            destination = reference_dir / source_runtime.name
            if destination.exists():
                raise SwiftFrontendError("Original Swift runtime destination collision")
            with destination.open("xb") as stream:
                stream.write(source_runtime.read_bytes())
            runtime_files[str(destination)] = _hash(destination)
        provenance = {**project["input_hashes"], str(source): _hash(source), str(interface): _hash(interface),
                      str(raw_ir): _hash(raw_ir), str(normalized_path): _hash(normalized_path)}
        report.update(source_functions=signatures, normalization=closure, source_hashes=project["input_hashes"],
            original_reference={"path": str(original), "sha256": _hash(original), "runtime_files": runtime_files,
                                "kind": "unmodified_swift_source_compiled_by_original_swift_driver"},
            original_ir={"path": str(raw_ir), "sha256": _hash(raw_ir)},
            public_interface={"path": str(interface), "sha256": _hash(interface)},
            contract_path=str(frontend / "contract.json"), exported_functions=list(project["functions"]))
        native = native_build.build_llvm_project(normalized_path, output / "native", workspace_root=root,
            name=project["name"], selected_functions=closure["selected_functions"],
            exported_functions=project["functions"], seed=seed, input_hashes=provenance)
        report.update(status=native["status"], native_report=str(output / "native/report.json"),
            native_report_sha256=_hash(output / "native/report.json"), artifacts=native.get("artifacts"),
            coverage=native.get("coverage"), signature_ir={"path": str(output / "native/module.before.ll"),
                "sha256": native["artifact_hashes"].get("module.before.ll")})
        if native.get("error"):
            report["error"] = native["error"]
    except Exception as exc:
        report.update(status="cancelled" if stop.exists() else "failed", error=f"{type(exc).__name__}: {exc}")
    finally:
        report["changed_inputs"] = _changed_inputs(watched)
        if report["changed_inputs"]:
            report.update(status="failed", error="Pinned Swift/source/native inputs changed during build")
        report["input_hashes"] = watched
        report["seconds"] = time.monotonic() - started
        # Report keys are portable slash paths, independent of the host OS.
        report["artifact_hashes"] = {path.relative_to(output).as_posix(): _hash(path)
                                     for path in output.rglob("*") if path.is_file()}
        _write(output / "report.json", report)
    return report


def _reference_worker(request_path):
    """Execute only an explicitly requested owned DLL in a bounded child."""
    from .bindings import validate_contract
    request = json.loads(Path(request_path).read_text(encoding="utf-8"))
    root = native_build._no_links(Path(request["workspace_root"]))
    directory = native_build._no_links(Path(request["build_directory"]))
    library = native_build._no_links(Path(request["library"]))
    if (not directory.is_relative_to(root / ".runs") or not library.is_relative_to(directory)
            or any(part.casefold() in {"rea-analysis-reports", "attackerfolder", "defense-loop"} for part in library.parts)
            or _hash(library) != request["sha256"]):
        raise SwiftFrontendError("Original/native Swift reference path or hash mismatch")
    for value, digest in request["runtime_files"].items():
        path = native_build._no_links(Path(value))
        if path.parent != library.parent or _hash(path) != digest:
            raise SwiftFrontendError("Original Swift runtime DLL path/hash mismatch")
    contract = validate_contract({"schema_version": 1, "library_name": "reference", "functions": [request["function"]]})
    function = contract["functions"][0]
    types = {"u32": ctypes.c_uint32, "i32": ctypes.c_int32, "u64": ctypes.c_uint64, "i64": ctypes.c_int64}
    cases = request["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= 65536:
        raise SwiftFrontendError("Invalid reference case count")
    for row in cases:
        if not isinstance(row, list) or len(row) != len(function["parameters"]):
            raise SwiftFrontendError("Reference case arity mismatch")
        for value, parameter in zip(row, function["parameters"]):
            kind = parameter["type"]
            bits = int(kind[1:])
            low, high = (0, 2**bits - 1) if kind[0] == "u" else (-2**(bits - 1), 2**(bits - 1) - 1)
            if type(value) is not int or not low <= value <= high:
                raise SwiftFrontendError("Reference input is outside its exact scalar range")
    handle = ctypes.CDLL(str(library), **({"winmode": 0x1100} if os.name == "nt" else {}))
    callback = getattr(handle, function["name"])
    callback.argtypes = [types[item["type"]] for item in function["parameters"]]
    callback.restype = types[function["return_type"]]
    values = [[int(callback(*row)) for row in cases] for _ in range(2)]
    if _hash(library) != request["sha256"] or any(_hash(path) != digest for path, digest in request["runtime_files"].items()):
        raise SwiftFrontendError("Swift reference artifacts changed during execution")
    _write(Path(request["reply"]), {"values": values, "behavior_repeats": 2})


def verify_build(report_path: Path, output_dir: Path, *, workspace_root: Path,
                 random_cases: int = 8192, timeout_seconds: int = 120,
                 include_protected: bool = False) -> dict:
    """Compare original Swift driver output against normalized native artifacts.

    This operation explicitly executes owned code in worker processes. Process
    ownership/timeouts are not an OS sandbox; crashes/timeouts never pass.
    """
    from .bindings import validate_contract
    from .dotnet_frontend import reference_cases
    from .native_validate import verify_integer_abi
    root = native_build._no_links(Path(workspace_root))
    path = native_build._no_links(Path(report_path))
    output = native_build._no_links(Path(output_dir))
    if (not path.is_relative_to(root / ".runs") or not output.is_relative_to(root / ".runs")
            or output.exists() or output == root / ".runs"
            or any(part.casefold() in {"rea-analysis-reports", "attackerfolder", "defense-loop"}
                   for item in (path, output) for part in item.parts)):
        raise SwiftFrontendError("Swift reference validation requires private owned report/fresh output in workspace/.runs")
    if type(random_cases) is not int or not 1 <= random_cases <= 8192:
        raise SwiftFrontendError("random_cases must be 1..8192; full checks require 8192 plus edges")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
        raise SwiftFrontendError("timeout_seconds must be 1..600")
    stop = root / ".runs/defense-loop/STOP"
    if stop.exists():
        raise SwiftFrontendError("Defense STOP exists")
    build = _read_report(path)
    if build.get("status") != "artifact_created_unvalidated" or build.get("backend") != "swift_llvm_native":
        raise SwiftFrontendError("A successful owned Swift LLVM native build is required")
    watched = {str(path): _hash(path)}

    def bound(value, digest):
        candidate = native_build._no_links(Path(value))
        if not candidate.is_relative_to(path.parent) or not candidate.is_file() or _hash(candidate) != digest:
            raise SwiftFrontendError("Swift build artifact path/hash mismatch: " + str(candidate))
        watched[str(candidate)] = digest
        return candidate

    original = bound(build["original_reference"]["path"], build["original_reference"]["sha256"])
    runtime_files = build["original_reference"]["runtime_files"]
    if not isinstance(runtime_files, dict) or len(runtime_files) > 128:
        raise SwiftFrontendError("Invalid Swift reference runtime inventory")
    for value, digest in runtime_files.items():
        if bound(value, digest).parent != original.parent:
            raise SwiftFrontendError("Original Swift runtime must be local to the reference DLL")
    interface = bound(build["public_interface"]["path"], build["public_interface"]["sha256"])
    source_functions = parse_public_interface(interface.read_text(encoding="utf-8"), build["exported_functions"])
    if source_functions != build["source_functions"]:
        raise SwiftFrontendError("Swift source signatures differ from original compiler-produced interface")
    contract = validate_contract({"schema_version": 1, "library_name": "protected", "functions": [
        {key: entry[key] for key in ("name", "return_type", "parameters")} for entry in source_functions]})
    original_ir = bound(build["original_ir"]["path"], build["original_ir"]["sha256"])
    abi = verify_integer_abi(original_ir.read_text(encoding="utf-8"), contract)
    arms = ["baseline", "protected"] if include_protected else ["baseline"]
    libraries = {arm: bound(build["artifacts"][arm]["path"], build["artifacts"][arm]["sha256"]) for arm in arms}
    native_report = bound(build["native_report"], build["native_report_sha256"])
    native = _read_report(native_report)
    if native.get("status") != "artifact_created_unvalidated" or native.get("artifacts") != build["artifacts"] or native.get("coverage") != build["coverage"]:
        raise SwiftFrontendError("Swift report differs from actual native engine evidence")
    output.mkdir(parents=True)
    report = {"schema_version": 1, "status": "failed", "build_report": str(path), "build_report_sha256": _hash(path),
              "original_sha256": _hash(original), "target_executed": True, "arms": arms,
              "methods": [], "commands": [], "behavior_repeats": 2, "original_abi": abi,
              "reference_kind": "original_swift_driver_compilation_not_normalized_ir",
              "validator_sha256": _hash(Path(__file__)), "limitations": [
                  "Sampled equivalence of explicitly owned scalar Swift cores, not whole-language correctness.",
                  "Owned DLL code is executed in bounded workers; these are not OS security sandboxes.",
                  "No external attack or performance acceptance is performed by this reference gate."]}
    scalar = {"u32": "UInt32", "i32": "Int32", "u64": "UInt64", "i64": "Int64"}

    def evaluate(library, function, cases, label, runtime):
        reply, request = output / (label + ".reply.json"), output / (label + ".request.json")
        _write(request, {"workspace_root": str(root), "build_directory": str(path.parent),
            "library": str(library), "sha256": _hash(library), "runtime_files": runtime,
            "function": function, "cases": cases, "reply": str(reply)})
        bootstrap = ("import sys;sys.path.insert(0,sys.argv[1]);"
                     "from antirea.swift_frontend import _reference_worker;_reference_worker(sys.argv[2])")
        process = run_logged([sys.executable, "-I", "-S", "-c", bootstrap,
            str(Path(__file__).resolve().parents[1]), str(request)], output, output / "logs" / label,
            timeout=timeout_seconds, cancel_file=stop, env=_process_env())
        report["commands"].append(process)
        cleanup = process.get("cleanup", {})
        if (process.get("returncode") != 0 or process.get("timed_out") or process.get("cancelled") or process.get("error")
                or cleanup.get("status") != "assigned_job_empty" or not cleanup.get("parent_exit_confirmed")
                or not cleanup.get("job_handle_closed")):
            raise SwiftFrontendError("Swift reference process failed or cleanup unverified: " + str(process.get("stderr")))
        if not reply.is_file() or reply.stat().st_size > 16 * 1024 * 1024:
            raise SwiftFrontendError("Swift reference reply missing/oversized")
        result = json.loads(reply.read_text(encoding="utf-8"))
        values = result.get("values")
        if (result.get("behavior_repeats") != 2 or not isinstance(values, list) or len(values) != 2
                or any(not isinstance(row, list) or len(row) != len(cases) or any(type(v) is not int for v in row) for row in values)):
            raise SwiftFrontendError("Swift reference reply schema/count mismatch")
        return values

    try:
        for index, function in enumerate(contract["functions"]):
            cases, counts = reference_cases([scalar[p["type"]] for p in function["parameters"]], random_cases, 1729 + index)
            export = function["name"]
            _write(output / (export + ".cases.json"), cases)
            expected = evaluate(original, function, cases, export + "-swift", runtime_files)
            result = {"export": export, "total": len(cases), **counts, "behavior_repeats": 2,
                      "original_deterministic": expected[0] == expected[1], "comparisons": {}}
            report["methods"].append(result)
            for arm, library in libraries.items():
                actual = evaluate(library, function, cases, export + "-" + arm, {})
                differences = [i for i in range(len(cases)) if any(actual[j][i] != expected[j][i] for j in (0, 1))]
                deterministic = actual[0] == actual[1]
                result["comparisons"][arm] = {"status": "passed" if not differences and deterministic and result["original_deterministic"] else "failed",
                    "matched": len(cases) - len(differences), "total": len(cases), "behavior_repeats": 2,
                    "deterministic": deterministic, "library_sha256": _hash(library),
                    "mismatches": [{"case": cases[i], "original": [row[i] for row in expected],
                                    "native": [row[i] for row in actual]} for i in differences[:10]]}
        if all(entry["status"] == "passed" for method in report["methods"] for entry in method["comparisons"].values()):
            report["status"] = "passed"
    except Exception as exc:
        report.update(status="cancelled" if stop.exists() else "failed", error=f"{type(exc).__name__}: {exc}")
    report["changed_artifacts"] = _changed_inputs(watched)
    report["changed_inputs"] = list(report["changed_artifacts"])
    if report["changed_artifacts"]:
        report.update(status="failed", error="Swift reference inputs changed during validation")
    report["artifact_hashes"] = {value.relative_to(output).as_posix(): _hash(value) for value in output.rglob("*") if value.is_file()}
    _write(output / "report.json", report)
    return report
