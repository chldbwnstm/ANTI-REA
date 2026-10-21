"""Package-ready Rust IR normalization draft; not a VM backend.

Only a caller-approved, hash-pinned LLVM library is loaded. No subprocess,
target code, Cargo, network, or filesystem write is performed by this module.
The caller must provide a bounded worker/Job and independently validate results.
"""
from __future__ import annotations

import ctypes
import hashlib
import importlib
import importlib.machinery
import json
import ntpath
from pathlib import Path
import re
import stat
import sys

TARGET = "x86_64-pc-windows-msvc"
MAX_IR_BYTES = 16 * 1024 * 1024
MAX_FUNCTIONS = 64
MAX_INSTRUCTIONS = 50000
MAX_INLINE_INSTRUCTIONS = 4096
INTEGER_WIDTHS = {1, 8, 16, 32, 64}
INTRINSIC_WIDTHS = {8, 16, 32, 64}
MATH_INTRINSICS = {
    "llvm.fshl": 3, "llvm.fshr": 3,
    "llvm.smin": 2, "llvm.smax": 2, "llvm.umin": 2, "llvm.umax": 2,
}
LIFETIMES = {"llvm.lifetime.start", "llvm.lifetime.end"}
EH_OPCODES = {5, 58, 59, 61, 62, 63, 64, 65}
SCALAR_OPCODES = {1, 2, 3, 8, 10, 12, 14, 15, 17, 18, 20, 21, 22,
                  23, 24, 25, 30, 31, 32, 42, 44, 45, 46}
RAW_OPCODES = SCALAR_OPCODES | {7, 26, 27, 28, 29, 53, 54, 68} | EH_OPCODES
SPECIAL_ABI = (b"inreg", b"nest", b"swiftself", b"swifterror", b"swiftasync",
               b"sret", b"byval", b"byref", b"inalloca", b"preallocated")
PHASE_PASSES = "function(sroa,mem2reg,simplifycfg,instcombine),strip-dead-prototypes"


class NormalizationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise NormalizationError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def _hash_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _json_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate toolchain configuration key")
        result[key] = value
    return result


def _no_links(path):
    # Keep the prior protectors policy available before loading package code.
    for part in reversed((path, *path.parents)):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
                "Symlink/reparse input is not allowed")
        require(not stat.S_ISREG(info.st_mode) or info.st_nlink == 1, "Hard-linked input is not allowed")


def _file(path):
    require(isinstance(path, Path) and path.is_absolute() and ".." not in path.parts,
            "Canonical absolute Path required")
    require(not str(path).startswith(("\\\\", "//")) and ":" not in str(path)[len(path.drive):]
            and not any(ord(ch) < 32 for ch in str(path))
            and not any(part.casefold() in {"rea-analysis-reports", "attackerfolder", "env.setting", "linkrepro", "shared"} for part in path.parts),
            "Received/published files are not normalization inputs")
    _no_links(path)
    require(path.is_file() and path == path.resolve(strict=True), "Regular canonical input file required")
    return path


class _MapperBootstrapImporter:
    """Minimal source-only bootstrap before the shared mapper API is available.

    Keep this namespace-limited loader aligned with rust_ir's shared loader.
    Both use reviewed source bytes, never Python's bytecode-cache loaders.
    """

    def __init__(self, root, watched):
        self.root = root
        self.indexed = {ntpath.normcase(ntpath.normpath(path)): (Path(path), sha)
                        for path, sha in watched.items()}
        self.executed = []

    def _source(self, name):
        require(re.fullmatch(r"antirea(?:\.[A-Za-z_][A-Za-z0-9_]*)*", name),
                "Unsupported production module identity")
        relative = self.root / Path(*name.split("."))
        candidates = [(relative / "__init__.py", True), (Path(str(relative) + ".py"), False)]
        found = [(self.indexed[ntpath.normcase(ntpath.normpath(str(path)))], package)
                 for path, package in candidates if ntpath.normcase(ntpath.normpath(str(path))) in self.indexed]
        require(len(found) == 1 and (name != "antirea" or found[0][1]),
                "Unknown/ambiguous production source module: " + name)
        (path, expected), package = found[0]
        require(path.stat().st_size <= 512 * 1024 * 1024, "Bounded production source required")
        return _file(path), expected, package

    def find_spec(self, fullname, path=None, target=None):
        if fullname != "antirea" and not fullname.startswith("antirea."):
            return None
        source, _, package = self._source(fullname)
        spec = importlib.machinery.ModuleSpec(fullname, self, origin=str(source), is_package=package)
        spec.has_location = True
        if package:
            spec.submodule_search_locations = [str(source.parent)]
        return spec

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        source, expected, _ = self._source(module.__name__)
        raw = source.read_bytes()
        require(sha256(raw) == expected, "Production source changed immediately before import")
        module.__cached__ = None
        exec(compile(raw, str(source), "exec", dont_inherit=True), module.__dict__)
        self.executed.append({"module": module.__name__, "path": str(source), "sha256": expected,
                              "loader": "verified_source_bytes_no_bytecode_cache"})


def _package_mapper(root, trusted_engine_pins):
    """Check caller pins before importing one fixed package-local module.

    This small stdlib precheck cannot call the mapper's stronger verifier until
    that mapper's own source and existing module identity have been verified.
    The full verifier then checks every loaded production module before LLVM.
    """
    require(isinstance(root, Path) and root.is_absolute() and ".." not in root.parts
            and root.is_dir() and root == root.resolve(strict=True), "Canonical trusted workspace required")
    _no_links(root)
    require(type(trusted_engine_pins) is dict and trusted_engine_pins, "Caller-reviewed engine snapshot required")
    key = lambda path: ntpath.normcase(ntpath.normpath(str(path)))
    indexed, watched = {}, {}
    for value, expected in trusted_engine_pins.items():
        require(type(value) is str and type(expected) is str and re.fullmatch(r"[0-9a-f]{64}", expected),
                "Malformed caller-reviewed engine pin")
        path = _file(Path(value))
        require(0 <= path.stat().st_size <= 512 * 1024 * 1024 and key(path) not in indexed
                and _hash_file(path) == expected, "Duplicate/changed reviewed engine input")
        indexed[key(path)], watched[str(path)] = str(path), expected
    mapper_path = root / "antirea/rust_ir.py"
    package_path = root / "antirea/__init__.py"
    required = [*sorted((root / "antirea").rglob("*.py")), Path(__file__).resolve(), mapper_path,
                package_path, root / "antirea/swift_frontend.py", root / ".tools/kagura-toolchain.json"]
    require(all(key(path) in indexed for path in required), "Complete engine/helper/configuration snapshot required")
    for name, module in sorted(list(sys.modules.items())):
        if name != "antirea" and not name.startswith("antirea."):
            continue
        relative = Path(*name.split("."))
        package_paths = getattr(module, "__path__", None)
        expected = root / relative / "__init__.py" if package_paths is not None else root / (str(relative) + ".py")
        spec = getattr(module, "__spec__", None)
        origin = getattr(spec, "origin", None)
        location = getattr(module, "__file__", None)
        require(location and origin and getattr(spec, "_initializing", False) is False
                and key(location) == key(expected) == key(origin) and key(expected) in indexed,
                "Incompatible preloaded production module: " + name)
        if name == "antirea" or package_paths is not None:
            require(package_paths is not None and list(package_paths) == [str(root / relative)],
                    "Production package search path differs")
    importer = _MapperBootstrapImporter(root, watched)
    old_path, old_meta = list(sys.path), list(sys.meta_path)
    old_modules = {name for name in sys.modules if name == "antirea" or name.startswith("antirea.")}
    try:
        sys.path.insert(0, str(root))
        sys.meta_path.insert(0, importer)
        mapper = importlib.import_module("antirea.rust_ir")
        require(key(getattr(mapper, "__file__", "")) == key(mapper_path), "Fixed package mapper origin differs")
        verified = mapper.verify_engine_snapshot(root, trusted_engine_pins,
                                                 additional_paths=(Path(__file__).resolve(),))
        require(verified == watched, "Engine snapshot changed across mapper import")
        mapper._recheck_engine(watched, root)
        return mapper, watched, list(importer.executed)
    except BaseException:
        for name in sorted(set(sys.modules) - old_modules, key=len, reverse=True):
            if name != "antirea" and not name.startswith("antirea."):
                continue
            removed = sys.modules.pop(name, None)
            parent_name, _, child = name.rpartition(".")
            parent = sys.modules.get(parent_name)
            if parent is not None and child in vars(parent) and vars(parent)[child] is removed:
                delattr(parent, child)
        raise
    finally:
        sys.meta_path[:] = old_meta
        sys.path[:] = old_path


def _inputs(raw, root, library, library_sha, config_sha, expected_raw_sha, exports):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_IR_BYTES, "Bounded nonempty raw bytes required")
    for value in (library_sha, config_sha, expected_raw_sha):
        require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "Exact SHA-256 pin required")
    require(sha256(raw) == expected_raw_sha, "Raw IR digest differs from supplied pin")
    require(isinstance(root, Path) and root.is_absolute() and ".." not in root.parts
            and root.is_dir() and root == root.resolve(strict=True), "Explicit canonical workspace required")
    _no_links(root)
    require(isinstance(exports, tuple) and 1 <= len(exports) <= MAX_FUNCTIONS
            and all(isinstance(name, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) for name in exports)
            and len(set(exports)) == len(exports),
            "Unique public C export names required")
    config = _file(root / ".tools/kagura-toolchain.json")
    require(config.stat().st_size <= 1024 * 1024 and _hash_file(config) == config_sha,
            "Trusted local toolchain configuration pin mismatch")
    settings = json.loads(config.read_text(encoding="utf-8-sig"), object_pairs_hook=_json_pairs)
    require(type(settings) is dict and type(settings.get("schema_version")) is int
            and settings["schema_version"] == 1 and settings.get("target") == TARGET
            and isinstance(settings.get("llvm_root"), str), "Unsupported local toolchain configuration")
    wanted = _file(Path(settings["llvm_root"]) / "bin/LLVM-C.dll")
    require(library == wanted and _hash_file(wanted) == library_sha,
            "LLVM library must match current trusted config and reviewed digest")
    # Rechecked before returning; the caller must additionally pin its full driver.
    watched = {str(config): config_sha, str(wanted): library_sha}
    for path in (Path(__file__).resolve(), root / "antirea/swift_frontend.py", root / "antirea/protectors.py"):
        watched[str(_file(path))] = _hash_file(path)
    return watched


def _api(library, *, workspace_root, trusted_engine_pins):
    mapper, engine, bootstrap_imports = _package_mapper(workspace_root, trusted_engine_pins)
    llvm = mapper.open_llvm(workspace_root=workspace_root, llvm_library=library,
                            trusted_engine_pins=trusted_engine_pins)
    p, u, z, s = ctypes.c_void_p, ctypes.c_uint, ctypes.c_size_t, ctypes.c_char_p
    extra = {
        "LLVMGetLinkage": (u, [p]), "LLVMGetVisibility": (u, [p]), "LLVMGetDLLStorageClass": (u, [p]),
        "LLVMGetComdat": (p, [p]), "LLVMGetGC": (s, [p]),
        "LLVMHasPersonalityFn": (ctypes.c_int, [p]), "LLVMGetPersonalityFn": (p, [p]),
        "LLVMSetPersonalityFn": (None, [p, p]), "LLVMDeleteFunction": (None, [p]),
        "LLVMGetNextUse": (p, [p]), "LLVMGetUser": (p, [p]),
        "LLVMGetInstructionParent": (p, [p]), "LLVMGetBasicBlockParent": (p, [p]),
        "LLVMGetBasicBlockTerminator": (p, [p]), "LLVMGetEntryBasicBlock": (p, [p]),
        "LLVMGetNumSuccessors": (u, [p]), "LLVMGetSuccessor": (p, [p, u]),
        "LLVMBasicBlockAsValue": (p, [p]), "LLVMGetDataLayoutStr": (s, [p]),
        "LLVMPrintTypeToString": (p, [p]), "LLVMGetNumArgOperands": (u, [p]),
        "LLVMGetTailCallKind": (u, [p]), "LLVMGetPointerAddressSpace": (u, [p]),
        "LLVMCountStructElementTypes": (u, [p]), "LLVMGetStructElementTypes": (None, [p, ctypes.POINTER(p)]),
        "LLVMIsOpaqueStruct": (ctypes.c_int, [p]), "LLVMLookupIntrinsicID": (u, [s, z]),
        "LLVMGetAttributeCountAtIndex": (u, [p, u]), "LLVMGetAttributesAtIndex": (None, [p, u, ctypes.POINTER(p)]),
        "LLVMGetCallSiteAttributeCount": (u, [p, u]), "LLVMGetCallSiteAttributes": (None, [p, u, ctypes.POINTER(p)]),
        "LLVMGetEnumAttributeAtIndex": (p, [p, u, u]), "LLVMGetCallSiteEnumAttribute": (p, [p, u, u]),
        "LLVMIsEnumAttribute": (ctypes.c_int, [p]), "LLVMIsStringAttribute": (ctypes.c_int, [p]),
        "LLVMIsTypeAttribute": (ctypes.c_int, [p]), "LLVMGetEnumAttributeKind": (u, [p]),
        "LLVMGetEnumAttributeValue": (ctypes.c_ulonglong, [p]), "LLVMGetTypeAttributeValue": (p, [p]),
        "LLVMGetStringAttributeKind": (p, [p, ctypes.POINTER(u)]),
        "LLVMGetStringAttributeValue": (p, [p, ctypes.POINTER(u)]),
        "LLVMGetVolatile": (ctypes.c_int, [p]), "LLVMGetOrdering": (u, [p]),
        "LLVMPassBuilderOptionsSetVerifyEach": (None, [p, ctypes.c_int]),
        "LLVMRunPassesOnFunction": (p, [p, s, p, p]),
    }
    try:
        for name, (result, args) in extra.items():
            callback = getattr(llvm.dll, name)
            callback.restype, callback.argtypes = result, args
            setattr(llvm, name, callback)
        require(llvm.trusted_engine_inputs == engine, "Engine snapshot changed before normalizer LLVM use")
        llvm.verified_source_imports = bootstrap_imports + llvm.verified_source_imports
        return llvm
    except BaseException:
        llvm.close()
        raise


def open_llvm(*, workspace_root, llvm_library, trusted_engine_pins):
    """Pinned normalizer parser/pass API; caller owns disposal and time bounds."""
    return _api(llvm_library, workspace_root=workspace_root, trusted_engine_pins=trusted_engine_pins)


def _verify(llvm, module):
    error = ctypes.c_void_p()
    if llvm.LLVMVerifyModule(module, 2, ctypes.byref(error)):
        raise NormalizationError("LLVM verification failed: " + llvm.string(error.value))


def _parse(llvm, context, raw):
    module, error = ctypes.c_void_p(), ctypes.c_void_p()
    memory = llvm.LLVMCreateMemoryBufferWithMemoryRangeCopy(raw, len(raw), b"owned-rust-normalization-copy")
    if llvm.LLVMParseIRInContext(context, memory, ctypes.byref(module), ctypes.byref(error)):
        raise NormalizationError("LLVM rejected raw IR: " + llvm.string(error.value))
    try:
        _verify(llvm, module)
        return module.value
    except BaseException:
        llvm.LLVMDisposeModule(module)
        raise


def _text(llvm, value):
    return llvm.string(llvm.LLVMPrintValueToString(value))


def _type(llvm, value):
    return llvm.string(llvm.LLVMPrintTypeToString(value))


def _attr_id(llvm, name):
    result = llvm.LLVMGetEnumAttributeKindForName(name, len(name))
    require(result != 0, "Pinned LLVM lacks requested attribute")
    return result


def _has(llvm, value, name, *, call=False):
    get = llvm.LLVMGetCallSiteEnumAttribute if call else llvm.LLVMGetEnumAttributeAtIndex
    return bool(get(value, 0xffffffff, _attr_id(llvm, name)))


def _attributes(llvm, value, count, *, call=False):
    result = {}
    count_fn = llvm.LLVMGetCallSiteAttributeCount if call else llvm.LLVMGetAttributeCountAtIndex
    get_fn = llvm.LLVMGetCallSiteAttributes if call else llvm.LLVMGetAttributesAtIndex
    for index in (0xffffffff, *range(count + 1)):
        size = count_fn(value, index)
        values = (ctypes.c_void_p * size)()
        get_fn(value, index, values)
        rows = []
        for attribute in values:
            if llvm.LLVMIsEnumAttribute(attribute):
                row = {"kind": "enum", "id": llvm.LLVMGetEnumAttributeKind(attribute),
                       "value": llvm.LLVMGetEnumAttributeValue(attribute)}
            elif llvm.LLVMIsTypeAttribute(attribute):
                row = {"kind": "type", "id": llvm.LLVMGetEnumAttributeKind(attribute),
                       "type": _type(llvm, llvm.LLVMGetTypeAttributeValue(attribute))}
            elif llvm.LLVMIsStringAttribute(attribute):
                kl, vl = ctypes.c_uint(), ctypes.c_uint()
                key = llvm.LLVMGetStringAttributeKind(attribute, ctypes.byref(kl))
                val = llvm.LLVMGetStringAttributeValue(attribute, ctypes.byref(vl))
                row = {"kind": "string", "key": ctypes.string_at(key, kl.value).hex(),
                       "value": ctypes.string_at(val, vl.value).hex()}
            else:
                raise NormalizationError("Unsupported attribute category")
            rows.append(row)
        result[str(index)] = sorted(rows, key=lambda item: json.dumps(item, sort_keys=True))
    return result


def _attribute_group_references(text):
    """Locate LLVM attribute-group tokens, never quoted names/string contents.

    This is not a general LLVM parser. The text is produced by the already
    verified LLVM value, and only a call instruction can authorize one token.
    All non-group text remains byte-exact in the comparison representation.
    """
    result, index, quoted = [], 0, False
    while index < len(text):
        char = text[index]
        if quoted:
            if char == "\\":
                require(index + 1 < len(text), "Malformed LLVM quoted operand")
                index += 2
                continue
            if char == '"':
                quoted = False
            index += 1
            continue
        if char == '"':
            quoted = True
        elif char == "#":
            match = re.match(r"#[0-9]+", text[index:])
            require(match is not None and index > 0 and text[index - 1].isspace(),
                    "Unsupported LLVM operand attribute-group syntax")
            end = index + len(match.group())
            require(end == len(text) or text[end].isspace() or text[end] == ",",
                    "Ambiguous LLVM operand attribute-group token")
            result.append((index, end))
            index = end
            continue
        index += 1
    require(not quoted, "Unterminated LLVM operand quote")
    return result


def _resolve_argument_ir(text, *, is_call, attributes):
    """Resolve a call value's printed group through that value's LLVM-C attrs.

    The group number itself is a printer-local label, not an attribute meaning.
    A reference is accepted only for an actual LLVM call value, with exactly one
    printed reference iff that same value has function-index call attributes.
    Real attributes (including their values/types) replace the reference; they
    are not erased. Parameter/return attrs are retained both in IR and the full
    structural attribute record. Any other text or SSA operand change differs.
    """
    references = _attribute_group_references(text)
    if not is_call:
        require(attributes is None and not references, "Non-call operand has an attribute-group reference")
        return text
    require(type(attributes) is dict and type(attributes.get("4294967295")) is list,
            "Actual call operand requires structured LLVM attributes")
    function_attributes = attributes["4294967295"]
    require(len(references) == (1 if function_attributes else 0),
            "Printed call group and actual LLVM function attributes disagree")
    if not references:
        return text
    start, end = references[0]
    resolved = json.dumps(function_attributes, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return text[:start] + "<LLVM_CALL_FUNCTION_ATTRIBUTES:" + resolved + ">" + text[end:]


def _argument_contract(llvm, value):
    kind = llvm.LLVMGetValueKind(value)
    is_call = kind == 24 and llvm.LLVMGetInstructionOpcode(value) == 45
    attributes = _attributes(llvm, value, llvm.LLVMGetNumArgOperands(value), call=True) if is_call else None
    return {"type": _type(llvm, llvm.LLVMTypeOf(value)), "value_kind": kind,
            "ir": _resolve_argument_ir(_text(llvm, value), is_call=is_call, attributes=attributes),
            "call_attributes": attributes}


def _shape(llvm, ty, *, aggregate=True):
    kind = llvm.LLVMGetTypeKind(ty)
    if kind == 8:
        bits = llvm.LLVMGetIntTypeWidth(ty)
        require(bits in INTEGER_WIDTHS, "Unsupported integer width")
        return {"kind": "integer", "bits": bits}
    if kind == 12:
        require(llvm.LLVMGetPointerAddressSpace(ty) == 0, "Nonzero pointer address space unsupported")
        return {"kind": "pointer", "address_space": 0}
    if kind == 10 and aggregate:
        require(not llvm.LLVMIsOpaqueStruct(ty), "Opaque aggregate unsupported")
        count = llvm.LLVMCountStructElementTypes(ty)
        require(1 <= count <= 8, "Aggregate field count exceeds first normalization scope")
        elements = (ctypes.c_void_p * count)()
        llvm.LLVMGetStructElementTypes(ty, elements)
        fields = [_shape(llvm, item, aggregate=False) for item in elements]
        require(all(item["kind"] == "integer" for item in fields), "Aggregate pointer/noninteger field unsupported")
        return {"kind": "struct", "fields": fields, "llvm": _type(llvm, ty)}
    raise NormalizationError("Unsupported helper signature type: " + _type(llvm, ty))


def _signature(llvm, function):
    signature = llvm.LLVMGlobalGetValueType(function)
    count = llvm.LLVMCountParamTypes(signature)
    params = (ctypes.c_void_p * count)()
    llvm.LLVMGetParamTypes(signature, params)
    return signature, llvm.LLVMGetReturnType(signature), list(params)


def _intrinsic(llvm, function):
    name, actual = llvm.name(function), llvm.LLVMGetIntrinsicID(function)
    require(actual != 0 and llvm.LLVMIsDeclaration(function) and llvm.LLVMGetFunctionCallConv(function) == 0,
            "Intrinsic must be an exact declared LLVM intrinsic with C CC")
    signature, result, params = _signature(llvm, function)
    require(not llvm.LLVMIsFunctionVarArg(signature), "Variadic intrinsic unsupported")
    for base in (*MATH_INTRINSICS, *sorted(LIFETIMES)):
        encoded = base.encode()
        expected = llvm.LLVMLookupIntrinsicID(encoded, len(encoded))
        if actual != expected or expected == 0:
            continue
        if base in LIFETIMES:
            require(name == base + ".p0" and llvm.LLVMGetTypeKind(result) == 0 and len(params) == 1
                    and llvm.LLVMGetTypeKind(params[0]) == 12 and llvm.LLVMGetPointerAddressSpace(params[0]) == 0,
                    "Unsupported pinned LLVM lifetime signature")
            return {"name": name, "base": base, "intrinsic_id": actual, "type": _type(llvm, signature),
                    "backend_support": "must_disappear_after_scalarization"}
        require(llvm.LLVMGetTypeKind(result) == 8, "Vector/noninteger intrinsic unsupported")
        width = llvm.LLVMGetIntTypeWidth(result)
        require(width in INTRINSIC_WIDTHS and name == base + ".i" + str(width)
                and len(params) == MATH_INTRINSICS[base] and all(ty == result for ty in params),
                "Intrinsic requires exact same-width scalar signature")
        return {"name": name, "base": base, "intrinsic_id": actual, "type": _type(llvm, signature),
                "width": width, "backend_support": "pending" if base in {"llvm.fshl", "llvm.fshr"} else "existing_kagura_lowering"}
    raise NormalizationError("Unsupported LLVM intrinsic: " + name)


def _blocks(llvm, function):
    blocks = list(llvm.values(llvm.LLVMGetFirstBasicBlock, llvm.LLVMGetNextBasicBlock, function))
    indices = {block: index for index, block in enumerate(blocks)}
    reachable, pending = set(), [llvm.LLVMGetEntryBasicBlock(function)]
    while pending:
        block = pending.pop()
        require(block in indices, "CFG edge leaves its function")
        if block in reachable:
            continue
        reachable.add(block)
        term = llvm.LLVMGetBasicBlockTerminator(block)
        require(term, "Missing basic-block terminator")
        pending.extend(llvm.LLVMGetSuccessor(term, index) for index in range(llvm.LLVMGetNumSuccessors(term)))
    return blocks, indices, reachable


def _snapshot(llvm, module, exports):
    length = ctypes.c_size_t()
    llvm.LLVMGetModuleInlineAsm(module, ctypes.byref(length))
    require(not length.value and not llvm.LLVMGetFirstGlobal(module)
            and not llvm.LLVMGetFirstGlobalAlias(module) and not llvm.LLVMGetFirstGlobalIFunc(module)
            and not llvm.LLVMGetNamedMetadataNumOperands(module, b"llvm.linker.options"),
            "Global data/alias/ifunc/module assembly/linker options remain unsupported")
    functions = {llvm.name(value): value for value in llvm.functions(module)}
    definitions = {name: value for name, value in functions.items() if not llvm.LLVMIsDeclaration(value)}
    require(1 <= len(definitions) <= MAX_FUNCTIONS and set(exports) <= set(definitions),
            "Public exports missing or definition bound exceeded")
    personalities = {}
    for name, function in definitions.items():
        if llvm.LLVMHasPersonalityFn(function):
            value = llvm.LLVMGetPersonalityFn(function)
            require(value in functions.values() and llvm.LLVMIsDeclaration(value), "Personality must be an exact declaration")
            personalities[name] = llvm.name(value)
    intrinsics, declarations = {}, {}
    for name, function in functions.items():
        if not llvm.LLVMIsDeclaration(function):
            continue
        if llvm.LLVMGetIntrinsicID(function):
            intrinsics[name] = _intrinsic(llvm, function)
        else:
            require(name in personalities.values(), "Unresolved external/runtime declaration: " + name)
            use = llvm.LLVMGetFirstUse(function)
            while use:
                owner = llvm.LLVMGetUser(use)
                require(owner in definitions.values() and llvm.LLVMHasPersonalityFn(owner)
                        and llvm.LLVMGetPersonalityFn(owner) == function, "Personality declaration has another use")
                use = llvm.LLVMGetNextUse(use)
        declarations[name] = {"type": _type(llvm, llvm.LLVMGlobalGetValueType(function)),
                              "intrinsic": intrinsics.get(name)}
    result = {"target": llvm.LLVMGetTarget(module).decode(), "data_layout": llvm.LLVMGetDataLayoutStr(module).decode(),
              "definitions": {}, "declarations": declarations, "intrinsics": intrinsics, "calls": {}, "graph": {}}
    require(result["target"] == TARGET and result["data_layout"], "Exact Windows target and explicit data layout required")
    special = {_attr_id(llvm, value) for value in SPECIAL_ABI}
    extension = {_attr_id(llvm, value) for value in (b"zeroext", b"signext")}
    instructions_total = 0
    for name, function in definitions.items():
        signature, ret, params = _signature(llvm, function)
        require(not llvm.LLVMGetComdat(function) and not llvm.LLVMGetGC(function)
                and llvm.LLVMGetLinkage(function) in (0, 8, 9) and llvm.LLVMGetFunctionCallConv(function) == 0
                and not llvm.LLVMGetDLLStorageClass(function) and not llvm.LLVMIsFunctionVarArg(signature)
                and len(params) <= 8, "Unsupported definition linkage/GC/COMDAT/CC/ABI: " + name)
        shapes = [_shape(llvm, ret), *(_shape(llvm, ty) for ty in params)]
        if name in exports:
            require(llvm.LLVMGetLinkage(function) == 0
                    and all(row["kind"] == "integer" and row["bits"] in {32, 64} for row in shapes),
                    "Public C ABI must remain externally defined scalar i32/i64")
        attrs = _attributes(llvm, function, len(params))
        require(not any(row.get("id") in special for key, rows in attrs.items() if key != "4294967295" for row in rows),
                "Special helper parameter ABI unsupported")
        blocks, indices, reachable = _blocks(llvm, function)
        row = {"type": _type(llvm, signature), "shapes": shapes, "calling_convention": 0,
               "linkage": llvm.LLVMGetLinkage(function), "visibility": llvm.LLVMGetVisibility(function),
               "dll_storage": 0, "attributes": attrs, "personality": personalities.get(name),
               "blocks": [], "instruction_count": 0, "alwaysinline": _has(llvm, function, b"alwaysinline"),
               "noinline": _has(llvm, function, b"noinline"), "nounwind": _has(llvm, function, b"nounwind")}
        calls, graph = [], set()
        for block in blocks:
            body = list(llvm.values(llvm.LLVMGetFirstInstruction, llvm.LLVMGetNextInstruction, block))
            opcodes = [llvm.LLVMGetInstructionOpcode(value) for value in body]
            require(set(opcodes) <= RAW_OPCODES, "Unsupported raw instruction in " + name)
            require(not (set(opcodes) & EH_OPCODES) or block not in reachable,
                    "Reachable exception-handling operation is unsupported: " + name)
            row["blocks"].append({"index": indices[block], "name": llvm.name(llvm.LLVMBasicBlockAsValue(block)),
                                  "reachable": block in reachable, "opcodes": opcodes,
                                  "sha256": sha256("\n".join(_text(llvm, value) for value in body).encode())})
            for position, instruction in enumerate(body):
                opcode = llvm.LLVMGetInstructionOpcode(instruction)
                if opcode in (27, 28):
                    require(not llvm.LLVMGetVolatile(instruction) and llvm.LLVMGetOrdering(instruction) == 0,
                            "Volatile/atomic memory is unsupported")
                if opcode != 45:
                    continue
                callee = llvm.LLVMGetCalledValue(instruction)
                target = llvm.name(callee) if callee else ""
                require(functions.get(target) == callee and llvm.LLVMGetValueKind(callee) == 5
                        and not llvm.LLVMGetNumOperandBundles(instruction)
                        and llvm.LLVMGetTailCallKind(instruction) != 2
                        and llvm.LLVMGetInstructionCallConv(instruction) == 0
                        and llvm.LLVMGetCalledFunctionType(instruction) == llvm.LLVMGlobalGetValueType(callee),
                        "Only exact direct matching C calls without bundles/musttail are supported")
                require(target in definitions or target in intrinsics, "Personality/runtime cannot be directly called")
                count = llvm.LLVMGetNumArgOperands(instruction)
                call_attrs = _attributes(llvm, instruction, count, call=True)
                definition_attrs = _attributes(llvm, callee, count)
                for index in range(count + 1):
                    require([a for a in call_attrs[str(index)] if a.get("id") in extension]
                            == [a for a in definition_attrs[str(index)] if a.get("id") in extension],
                            "Call/callee integer extension attributes differ")
                if name in personalities:
                    require(row["nounwind"] and (_has(llvm, instruction, b"nounwind", call=True)
                            or _has(llvm, callee, b"nounwind")), "Personality cleanup requires nounwind calls")
                record = {"caller": name, "block_index": indices[block], "instruction_index": row["instruction_count"] + position,
                          "reachable": block in reachable, "callee": target, "type": _type(llvm, llvm.LLVMGetCalledFunctionType(instruction)),
                          "attributes": call_attrs, "noinline": _has(llvm, instruction, b"noinline", call=True),
                          "argument_ir": [_text(llvm, llvm.LLVMGetOperand(instruction, n)) for n in range(count)],
                          "argument_contracts": [_argument_contract(llvm, llvm.LLVMGetOperand(instruction, n)) for n in range(count)],
                          "instruction_sha256": sha256(_text(llvm, instruction).encode())}
                calls.append(record)
                if target in definitions:
                    graph.add(target)
            row["instruction_count"] += len(body)
        instructions_total += row["instruction_count"]
        result["definitions"][name], result["calls"][name], result["graph"][name] = row, calls, sorted(graph)
        use = llvm.LLVMGetFirstUse(function)
        while use:
            user = llvm.LLVMGetUser(use)
            require(llvm.LLVMGetValueKind(user) == 24 and llvm.LLVMGetInstructionOpcode(user) == 45
                    and llvm.LLVMGetCalledValue(user) == function
                    and sum(llvm.LLVMGetOperand(user, n) == function for n in range(llvm.LLVMGetNumOperands(user))) == 1,
                    "Address-taken/non-direct helper use is unsupported")
            owner = llvm.LLVMGetBasicBlockParent(llvm.LLVMGetInstructionParent(user))
            require(owner in definitions.values(), "Helper caller leaves closed graph")
            use = llvm.LLVMGetNextUse(use)
    require(instructions_total <= MAX_INSTRUCTIONS, "Module instruction bound exceeded")
    _acyclic(result["graph"])
    return result


def _acyclic(graph):
    visiting, visited = set(), set()
    def visit(name):
        require(name not in visiting, "Recursive helper graph is unsupported")
        if name in visited:
            return
        visiting.add(name)
        for child in graph[name]:
            require(child in graph, "Unclosed helper graph")
            visit(child)
        visiting.remove(name)
        visited.add(name)
    for name in graph:
        visit(name)


def select_inline_candidates(contract, exports):
    """Pure selection policy; no symbol-name patterns or source parsing."""
    selected = {}
    calls = [row for rows in contract["calls"].values() for row in rows]
    for name, row in contract["definitions"].items():
        nonscalar = any(shape["kind"] != "integer" for shape in row["shapes"])
        if not nonscalar and not row["alwaysinline"]:
            continue
        if name in exports:
            require(not nonscalar, "Public aggregate/pointer ABI is unsupported")
            continue
        require(row["linkage"] in (8, 9), "Noninternal helper requiring ABI adaptation is unsupported")
        require(not row["noinline"], "Noinline helper needs separate aggregate/pointer ABI adaptation")
        uses = [call for call in calls if call["callee"] == name]
        require(uses and all(call["reachable"] and not call["noinline"] for call in uses),
                "Inlining requires reachable non-noinline direct callsites")
        require(row["instruction_count"] <= MAX_INLINE_INSTRUCTIONS, "Selected helper exceeds inline-size bound")
        # Pointer parameters only enter through a compiler-designated alwaysinline helper.
        require(not any(shape["kind"] == "pointer" for shape in row["shapes"])
                or row["alwaysinline"], "Pointer helper lacks compiler alwaysinline contract")
        selected[name] = {"reason": "internal_aggregate_abi" if any(shape["kind"] == "struct" for shape in row["shapes"]) else "compiler_alwaysinline",
                          "original_signature": {key: row[key] for key in ("type", "shapes", "calling_convention", "attributes")},
                          "call_occurrences": uses}
    _expansion_bound(contract, selected)
    return selected


def _expansion_bound(contract, selected):
    """Conservative acyclic instruction expansion bound before LLVM inlining."""
    _acyclic(contract["graph"])
    cache = {}
    def cost(name):
        if name not in cache:
            total = contract["definitions"][name]["instruction_count"]
            for call in contract["calls"][name]:
                if call["callee"] in selected:
                    total += cost(call["callee"])
                    require(total <= MAX_INSTRUCTIONS, "Predicted inline expansion exceeds instruction bound")
            cache[name] = total
        return cache[name]
    total = sum(cost(name) for name in contract["definitions"] if name not in selected)
    require(total <= MAX_INSTRUCTIONS, "Predicted module expansion exceeds instruction bound")
    return total


def _pass(llvm, module, pipeline, *, function=None):
    options = llvm.LLVMCreatePassBuilderOptions()
    try:
        llvm.LLVMPassBuilderOptionsSetVerifyEach(options, 1)
        callback = llvm.LLVMRunPassesOnFunction if function is not None else llvm.LLVMRunPasses
        error = callback(function if function is not None else module, pipeline.encode(), None, options)
        if error:
            message = llvm.LLVMGetErrorMessage(error)
            try:
                raise NormalizationError("LLVM pass failed: " + ctypes.string_at(message).decode())
            finally:
                llvm.LLVMDisposeErrorMessage(message)
    finally:
        llvm.LLVMDisposePassBuilderOptions(options)
    _verify(llvm, module)


def _function_values(llvm, module):
    return {llvm.name(value): value for value in llvm.functions(module) if not llvm.LLVMIsDeclaration(value)}


def _abi(row):
    return {key: row[key] for key in ("type", "shapes", "calling_convention", "linkage", "visibility", "dll_storage", "attributes")}


def _call_semantics(row):
    require(type(row.get("argument_ir")) is list and type(row.get("argument_contracts")) is list
            and len(row["argument_ir"]) == len(row["argument_contracts"]),
            "Typed argument contract is missing or changes operand count")
    for text, contract in zip(row["argument_ir"], row["argument_contracts"]):
        require(type(text) is str and type(contract) is dict
                and set(contract) == {"type", "value_kind", "ir", "call_attributes"}
                and type(contract["type"]) is str and bool(contract["type"])
                and type(contract["value_kind"]) is int and type(contract["ir"]) is str,
                "Malformed typed operand provenance")
        attributes = contract["call_attributes"]
        require(attributes is None or contract["value_kind"] == 24,
                "Call operand attributes on a noninstruction value")
        require(_resolve_argument_ir(text, is_call=attributes is not None, attributes=attributes) == contract["ir"],
                "Typed operand contract disagrees with original printed operand")
    return {key: row[key] for key in ("caller", "callee", "type", "attributes", "argument_contracts", "noinline")}


def _bind_call_provenance(raw_calls, post_eh_calls):
    """Ordered exact comparison after resolving actual LLVM call attributes."""
    require(type(raw_calls) is list and type(post_eh_calls) is list
            and len(raw_calls) == len(post_eh_calls), "EH cleanup changed helper call count")
    before = [_call_semantics(row) for row in raw_calls]
    after = [_call_semantics(row) for row in post_eh_calls]
    require(before == after, "EH cleanup changed typed helper call provenance")
    return {"schema_version": 1, "comparison": "llvm_typed_attribute_resolved_call_operands",
            "raw_count": len(raw_calls), "post_eh_count": len(post_eh_calls),
            "raw_semantics": before, "post_eh_semantics": after,
            "call_order_and_multiplicity_preserved": True, "typed_semantics_equal": True,
            "argument_ir_text_changed": any(left["argument_ir"] != right["argument_ir"]
                                            for left, right in zip(raw_calls, post_eh_calls))}


def _eh_cleanup(llvm, module, raw, exports):
    changes = []
    for name, row in raw["definitions"].items():
        dead_eh = [block for block in row["blocks"] if set(block["opcodes"]) & EH_OPCODES]
        if not row["personality"] and not dead_eh:
            continue
        require(row["personality"] and row["nounwind"], "EH cleanup requires an explicit nounwind personality-bearing function")
        value = _function_values(llvm, module)[name]
        if dead_eh:
            _pass(llvm, module, "simplifycfg", function=value)
        remaining = list(llvm.instructions(value))
        require(not any(llvm.LLVMGetInstructionOpcode(item) in EH_OPCODES for item in remaining),
                "EH instructions remain after unreachable-block cleanup")
        # _snapshot checked every call, including the disconnected component.
        interim = _snapshot(llvm, module, exports)
        require(_abi(interim["definitions"][name]) == _abi(row), "EH cleanup changed function ABI/attributes")
        expected_calls = [_call_semantics(call) for call in raw["calls"][name] if call["reachable"]]
        require([_call_semantics(call) for call in interim["calls"][name]] == expected_calls,
                "EH simplification changed reachable calls beyond this normalization contract")
        personality = llvm.LLVMGetPersonalityFn(value)
        require(personality and llvm.name(personality) == row["personality"], "Personality identity drift")
        llvm.LLVMSetPersonalityFn(value, None)
        # A later function may use another personality. Do not let the next
        # strict snapshot mistake this now-unused declaration for a runtime call.
        if not llvm.LLVMGetFirstUse(personality):
            llvm.LLVMDeleteFunction(personality)
        _verify(llvm, module)
        changes.append({"function": name, "personality": row["personality"],
                        "removed_unreachable_eh_blocks": dead_eh, "remaining_eh_instructions": 0,
                        "reachable_calls_preserved": True, "nounwind_function_and_calls_checked": True})
    # Only declarations proven to have had exclusively personality uses are removed.
    old_personalities = {row["personality"] for row in raw["definitions"].values() if row["personality"]}
    for value in list(llvm.functions(module)):
        if llvm.name(value) in old_personalities:
            require(llvm.LLVMIsDeclaration(value) and not llvm.LLVMGetFirstUse(value), "Personality still has a use")
            llvm.LLVMDeleteFunction(value)
    _verify(llvm, module)
    return changes


def _consumers(helper, selected, calls):
    direct = sorted({row["caller"] for rows in calls.values() for row in rows if row["callee"] == helper})
    surviving = set()
    for caller in direct:
        surviving.update(_consumers(caller, selected, calls) if caller in selected else [caller])
    return sorted(surviving)


def _inline(llvm, context, module, before, exports):
    selected = select_inline_candidates(before, exports)
    values = _function_values(llvm, module)
    always = _attr_id(llvm, b"alwaysinline")
    suppressed = {}
    for name, value in values.items():
        if name in selected:
            llvm.LLVMAddAttributeAtIndex(value, 0xffffffff, llvm.LLVMCreateEnumAttribute(context, always, 0))
        elif _has(llvm, value, b"alwaysinline"):
            suppressed[name] = llvm.LLVMGetEnumAttributeAtIndex(value, 0xffffffff, always)
            llvm.LLVMRemoveEnumAttributeAtIndex(value, 0xffffffff, always)
    if selected:
        _pass(llvm, module, "always-inline")
    after_values = _function_values(llvm, module)
    require(set(after_values) <= set(values) and set(values) - set(after_values) <= set(selected),
            "Inliner unexpectedly created or removed a nonselected definition")
    for name, record in selected.items():
        if name in after_values:
            value = after_values[name]
            require(not llvm.LLVMGetFirstUse(value), "Selected helper has residual calls/uses after always-inline: " + name)
            llvm.LLVMDeleteFunction(value)
        record["surviving_callers"] = _consumers(name, selected, before["calls"])
        record["definition_removed_after_no_uses"] = True
    remaining = _function_values(llvm, module)
    require(set(remaining) == set(values) - set(selected), "Post-inline definition set mismatch")
    for name, attribute in suppressed.items():
        llvm.LLVMAddAttributeAtIndex(remaining[name], 0xffffffff, attribute)
    _verify(llvm, module)
    return selected


def _strict_final(llvm, module, contract):
    functions = _function_values(llvm, module)
    require(not any(row["personality"] for row in contract["definitions"].values()), "Residual personality unsupported")
    require(set(contract["declarations"]) == set(contract["intrinsics"]), "Residual runtime declaration unsupported")
    require(not any(row["base"] in LIFETIMES for row in contract["intrinsics"].values()),
            "Lifetime/pointer operations did not disappear after scalarization")
    for name, function in functions.items():
        require(all(shape["kind"] == "integer" for shape in contract["definitions"][name]["shapes"]),
                "Remaining non-scalar signature needs explicit ABI adaptation")
        for item in llvm.instructions(function):
            opcode = llvm.LLVMGetInstructionOpcode(item)
            require(opcode in SCALAR_OPCODES, "Remaining memory/aggregate/unsupported operation: " + str(opcode))
            result = llvm.LLVMTypeOf(item)
            require(llvm.LLVMGetTypeKind(result) == 0 or (llvm.LLVMGetTypeKind(result) == 8
                    and llvm.LLVMGetIntTypeWidth(result) in INTEGER_WIDTHS), "Remaining noninteger instruction result")
            callee = llvm.LLVMGetCalledValue(item) if opcode == 45 else None
            for index in range(llvm.LLVMGetNumOperands(item)):
                operand = llvm.LLVMGetOperand(item, index)
                kind = llvm.LLVMTypeOf(operand)
                if operand == callee or llvm.LLVMGetTypeKind(kind) == 7:
                    continue
                require(llvm.LLVMGetTypeKind(kind) == 8 and llvm.LLVMGetIntTypeWidth(kind) in INTEGER_WIDTHS,
                        "Remaining pointer/aggregate instruction operand")
                require(llvm.LLVMGetValueKind(operand) not in (14, 25), "Residual undef/poison is not accepted as a source value")


def normalize_ir(raw: bytes, *, workspace_root: Path, llvm_library: Path,
                 llvm_sha256: str, toolchain_config_sha256: str,
                 public_exports: tuple[str, ...], expected_raw_sha256: str,
                 trusted_engine_pins: dict[str, str]):
    """Return (normalized bytes, JSON report), without writing or launching tools.

    This executes reviewed LLVM optimization passes in the caller's process.
    Use a bounded isolated worker. It does not attest rustc provenance, prove
    arbitrary semantic equivalence, apply VM protection, or resolve native links.
    """
    mapper, engine, bootstrap_imports = _package_mapper(workspace_root, trusted_engine_pins)
    watched = _inputs(raw, workspace_root, llvm_library, llvm_sha256,
                      toolchain_config_sha256, expected_raw_sha256, public_exports)
    indexed = {mapper._engine_key(path): sha for path, sha in engine.items()}
    require(all(indexed.get(mapper._engine_key(path)) == sha for path, sha in watched.items()),
            "Explicit normalizer pins and reviewed engine snapshot disagree")
    watched.update(engine)
    llvm, context, module, reparsed = None, None, None, None
    try:
        llvm = open_llvm(workspace_root=workspace_root, llvm_library=llvm_library,
                         trusted_engine_pins=trusted_engine_pins)
        require(llvm.trusted_engine_inputs == engine, "Engine snapshot changed before normalization")
        context = llvm.LLVMContextCreate()
        module = _parse(llvm, context, raw)
        original = _snapshot(llvm, module, public_exports)
        # Reject noinline/escaping ABI adaptation before any optimization pass.
        select_inline_candidates(original, public_exports)
        eh = _eh_cleanup(llvm, module, original, public_exports)
        before_inline = _snapshot(llvm, module, public_exports)
        inline = _inline(llvm, context, module, before_inline, public_exports)
        for name, record in inline.items():
            raw_calls = [call for rows in original["calls"].values() for call in rows if call["callee"] == name]
            record["call_provenance"] = _bind_call_provenance(raw_calls, record["call_occurrences"])
            record["raw_call_occurrences"] = raw_calls
            record["post_eh_call_occurrences"] = record["call_occurrences"]
        _pass(llvm, module, PHASE_PASSES)
        normalized = _snapshot(llvm, module, public_exports)
        require(set(normalized["definitions"]) == set(original["definitions"]) - set(inline),
                "Canonicalization changed definitions outside explicit inlining set")
        require(normalized["target"] == original["target"] and normalized["data_layout"] == original["data_layout"],
                "Target or data layout changed")
        for name, row in normalized["definitions"].items():
            require(_abi(row) == _abi(original["definitions"][name]), "Surviving function ABI/attributes changed: " + name)
        _strict_final(llvm, module, normalized)
        output = llvm.string(llvm.LLVMPrintModuleToString(module)).encode("utf-8")
        require(0 < len(output) <= MAX_IR_BYTES, "Normalized IR output exceeds bound")
        reparsed = _parse(llvm, context, output)
        require(_snapshot(llvm, reparsed, public_exports) == normalized, "Serialization changed parsed contract")
        for path, wanted in watched.items():
            require(_hash_file(_file(Path(path))) == wanted, "Normalization input changed during LLVM processing")
        mapper._recheck_engine(engine, workspace_root)
        origins = mapper._loaded_engine(workspace_root, engine)
        pending = sorted(name for name, row in normalized["intrinsics"].items() if row["backend_support"] == "pending")
        report = {
            "schema_version": 1, "status": "normalized_ir_unlinked_unvalidated",
            "raw_sha256": expected_raw_sha256, "normalized_sha256": sha256(output),
            "raw_bytes": len(raw), "normalized_bytes": len(output), "inputs_before": watched,
            "inputs_after": dict(watched), "changed_inputs": [], "public_exports": list(public_exports),
            "engine_snapshot_revision": 1, "reviewed_engine_inputs": engine,
            "loaded_production_modules": origins, "engine_inputs_unchanged": True,
            "source_import_policy": "fixed_antirea_namespace_reviewed_source_bytes",
            "verified_source_imports": bootstrap_imports + llvm.verified_source_imports,
            "raw_contract": original, "pre_inline_contract": before_inline, "normalized_contract": normalized,
            "eh_cleanup": eh, "inlining": inline, "inlined_functions": sorted(inline),
            "call_provenance_revision": 2,
            "argument_comparison": "llvm_typed_attribute_resolved_call_operands",
            "defined_graph": normalized["graph"],
            "intrinsics": [{**row, "signature": row["type"]} for name, row in sorted(normalized["intrinsics"].items())],
            "passes": {"dead_eh_functions": "simplifycfg", "selective_inline": "always-inline",
                       "scalar_canonicalization": PHASE_PASSES},
            "public_abi_preserved": True, "surviving_helper_abi_preserved": True,
            "calling_convention_rewritten": False, "noinline_helpers_removed": False,
            "backend_support": {"status": "pending_funnel_shift_lowering" if pending else "not_exercised",
                                "pending_intrinsics": pending},
            "vm_applied": False, "native_link_verified": False, "target_executed": False,
            "functional_validation": "required_original_vs_normalized_vs_protected",
            "qualification": [
                "Trusted hash-bound IR normalization; not independent rustc generation attestation.",
                "Exact public/surviving ABI and transformation receipts are not a general semantic equivalence proof.",
                "Inlined helpers have caller provenance, not separate VM-wrapper coverage.",
                "Native link/archive replacement and original Cargo behavior remain independent mandatory gates.",
                "The caller supplies a bounded worker; this API has no in-process hard timeout or OS sandbox.",
            ],
        }
        return output, report
    finally:
        if llvm is not None:
            if reparsed:
                llvm.LLVMDisposeModule(reparsed)
            if module:
                llvm.LLVMDisposeModule(module)
            if context:
                llvm.LLVMContextDispose(context)
            llvm.close()
