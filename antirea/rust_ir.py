"""Package-ready draft: protection identities for a closed scalar Rust graph.

No compiler, Cargo, linker, protector or target executes here. Hash-bound input
provenance is supplied by a trusted frontend, not independent rustc attestation.
"""
from __future__ import annotations

import ctypes
from dataclasses import asdict, dataclass
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
MAX_IR = 16 * 1024 * 1024
RETENTION = (b"alwaysinline", b"inlinehint", b"optnone", b"noinline")
ALLOWED_OPCODES = {1, 2, 3, 8, 10, 12, 14, 15, 17, 18, 20, 21, 22, 23, 24, 25, 30, 31, 32, 42, 44, 45, 46}
INTRINSICS = {"llvm.fshl": 3, "llvm.fshr": 3, "llvm.smin": 2, "llvm.smax": 2,
              "llvm.umin": 2, "llvm.umax": 2}
INTRINSIC_WIDTHS = frozenset({8, 16, 32, 64})


class RustIRError(ValueError):
    pass


@dataclass(frozen=True)
class PinnedFile:
    path: Path
    sha256: str


@dataclass(frozen=True)
class RustSourceProvenance:
    compiler_inputs: tuple[PinnedFile, ...]
    source_inputs: tuple[PinnedFile, ...]
    evidence_files: tuple[PinnedFile, ...]
    frontend_flags: tuple[str, ...]
    target: str = TARGET
    kind: str = "trusted_frontend_rust_ir"


@dataclass(frozen=True)
class RustIRRequest:
    input_ir: Path
    input_sha256: str
    selected_functions: tuple[str, ...]
    public_exports: tuple[str, ...]
    expected_calls: dict[str, tuple[str, ...]]
    provenance: RustSourceProvenance


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_hash(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _no_links(path):
    # Same no-link policy as the prior protectors helper, usable before any
    # package import. Do not resolve a link before inspecting its parents.
    for part in reversed((path, *path.parents)):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise RustIRError("Symlink/reparse input is not allowed")
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise RustIRError("Hard-linked input is not allowed")


def _engine_key(path):
    return ntpath.normcase(ntpath.normpath(str(path)))


def _engine_file(path):
    if (not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts
            or str(path).startswith(("\\\\", "//")) or ":" in str(path)[len(path.drive):]
            or any(ord(ch) < 32 for ch in str(path))
            or any(part.casefold() in {"rea-analysis-reports", "attackerfolder", "env.setting", "linkrepro", "shared"}
                   for part in path.parts)):
        raise RustIRError("Ordinary trusted engine path required")
    _no_links(path)
    if not path.is_file() or path != path.resolve(strict=True) or not 0 <= path.stat().st_size <= 512 * 1024 * 1024:
        raise RustIRError("Bounded regular canonical engine file required")
    return path


def _loaded_engine(root, watched):
    """Reject a same-name preloaded package whose origin is outside this root.

    This binds recorded origins/current bytes, not arbitrary in-memory monkey
    patches. The caller still supplies a fresh bounded trusted worker.
    """
    indexed = {_engine_key(path): (path, sha) for path, sha in watched.items()}
    origins = []
    for name, module in sorted(list(sys.modules.items())):
        if name != "antirea" and not name.startswith("antirea."):
            continue
        relative = Path(*name.split("."))
        package_paths = getattr(module, "__path__", None)
        expected = root / relative / "__init__.py" if package_paths is not None else root / (str(relative) + ".py")
        location = getattr(module, "__file__", None)
        spec = getattr(module, "__spec__", None)
        origin = getattr(spec, "origin", None)
        if (not location or not origin or getattr(spec, "_initializing", False) is not False
                or _engine_key(location) != _engine_key(expected) or _engine_key(origin) != _engine_key(expected)):
            raise RustIRError("Incompatible preloaded production module: " + name)
        found = indexed.get(_engine_key(expected))
        if found is None or file_hash(_engine_file(Path(found[0]))) != found[1]:
            raise RustIRError("Preloaded production module is not in the reviewed snapshot: " + name)
        if name == "antirea" or package_paths is not None:
            if package_paths is None or list(package_paths) != [str(root / relative)]:
                raise RustIRError("Production package search path differs")
        origins.append({"module": name, "path": found[0], "sha256": found[1]})
    return origins


def verify_engine_snapshot(workspace_root, trusted_engine_pins, *, additional_paths=()):
    """Stdlib-only verification; no helper, LLVM library or target is loaded."""
    root = Path(workspace_root)
    _no_links(root)
    if not root.is_absolute() or ".." in root.parts or not root.is_dir() or root != root.resolve(strict=True):
        raise RustIRError("Explicit canonical trusted workspace required")
    if type(trusted_engine_pins) is not dict or not trusted_engine_pins:
        raise RustIRError("Caller-reviewed engine snapshot required")
    watched, indexed = {}, {}
    for value, expected in trusted_engine_pins.items():
        if type(value) is not str or type(expected) is not str or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise RustIRError("Malformed caller-reviewed engine pin")
        path = _engine_file(Path(value))
        key = _engine_key(path)
        if key in indexed or file_hash(path) != expected:
            raise RustIRError("Duplicate/changed caller-reviewed engine input")
        indexed[key] = str(path)
        watched[str(path)] = expected
    required = [*sorted((root / "antirea").rglob("*.py")), Path(__file__).resolve(),
                root / "antirea/__init__.py", root / "antirea/swift_frontend.py",
                root / ".tools/kagura-toolchain.json", *additional_paths]
    if any(_engine_key(path) not in indexed for path in required):
        raise RustIRError("Complete engine/helper/configuration snapshot required")
    _loaded_engine(root, watched)
    return watched


def _recheck_engine(watched, workspace_root):
    package = Path(workspace_root) / "antirea"
    current = {_engine_key(path) for path in package.rglob("*.py")}
    recorded = {_engine_key(path) for path in watched if Path(path).is_relative_to(package) and Path(path).suffix == ".py"}
    if current != recorded:
        raise RustIRError("Production package file inventory changed")
    for name, expected in watched.items():
        if file_hash(_engine_file(Path(name))) != expected:
            raise RustIRError("Reviewed engine input changed")


class _SourceSnapshotImporter:
    """Only antirea source bytes; never a SourceFileLoader or bytecode cache.

    This finder is installed only for the duration of a verified import. Its
    snapshot is caller-reviewed, not a manifest supplied by the imported file.
    Other namespaces keep their ordinary, trusted-worker import behavior.
    """

    def __init__(self, root, watched):
        self.root = root
        self.indexed = {_engine_key(path): (Path(path), sha) for path, sha in watched.items()}
        self.executed = []

    def _source(self, name):
        if not re.fullmatch(r"antirea(?:\.[A-Za-z_][A-Za-z0-9_]*)*", name):
            raise RustIRError("Unsupported production module identity")
        relative = self.root / Path(*name.split("."))
        candidates = [(relative / "__init__.py", True), (Path(str(relative) + ".py"), False)]
        found = [(self.indexed[_engine_key(path)], package) for path, package in candidates
                 if _engine_key(path) in self.indexed]
        if len(found) != 1 or (name == "antirea" and not found[0][1]):
            raise RustIRError("Unknown/ambiguous production source module: " + name)
        (path, expected), package = found[0]
        return _engine_file(path), expected, package

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
        if digest(raw) != expected:
            raise RustIRError("Production source changed immediately before import")
        module.__cached__ = None
        # compile(bytes) preserves Python's source-encoding semantics. It cannot
        # consult a timestamp/hash-based .pyc and does not write one.
        code = compile(raw, str(source), "exec", dont_inherit=True)
        exec(code, module.__dict__)
        self.executed.append({"module": module.__name__, "path": str(source), "sha256": expected,
                              "loader": "verified_source_bytes_no_bytecode_cache"})


def import_verified_module(module_name, *, workspace_root, trusted_engine_pins, additional_paths=()):
    """Import a fixed helper with a scoped, source-only antirea dependency path.

    The entry module defining this function must itself have been loaded by a
    reviewed source-only bootstrap. A preloaded module's origin/current file
    bytes are checked; this does not attest its arbitrary live Python objects.
    Run in a fresh, single-threaded trusted worker, not a shared plugin host.
    """
    if module_name not in {"antirea.rust_ir", "antirea.swift_frontend"}:
        raise RustIRError("Only fixed package-local helper imports are supported")
    root = Path(workspace_root)
    watched = verify_engine_snapshot(root, trusted_engine_pins, additional_paths=additional_paths)
    importer = _SourceSnapshotImporter(root, watched)
    old_path, old_meta = list(sys.path), list(sys.meta_path)
    old_modules = {name for name in sys.modules if name == "antirea" or name.startswith("antirea.")}
    try:
        sys.path.insert(0, str(root))
        sys.meta_path.insert(0, importer)
        module = importlib.import_module(module_name)
        origins = _loaded_engine(root, watched)
        _recheck_engine(watched, root)
        return module, watched, origins, list(importer.executed)
    except BaseException:
        # Do not leave partially imported new package dependencies available to
        # a subsequent attempt after an import/post-import validation failure.
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


def _llvm_backend(workspace_root, library, trusted_engine_pins):
    root = Path(workspace_root)
    watched = verify_engine_snapshot(root, trusted_engine_pins)
    index = {_engine_key(path): sha for path, sha in watched.items()}
    config = _engine_file(root / ".tools/kagura-toolchain.json")
    if config.stat().st_size > 1024 * 1024:
        raise RustIRError("Bounded trusted configuration required")
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise RustIRError("Duplicate toolchain configuration key")
            result[key] = value
        return result
    settings = json.loads(config.read_text(encoding="utf-8-sig"), object_pairs_hook=pairs)
    if (type(settings) is not dict or type(settings.get("schema_version")) is not int
            or settings["schema_version"] != 1 or settings.get("target") != TARGET
            or type(settings.get("llvm_root")) is not str):
        raise RustIRError("Unsupported pinned LLVM configuration")
    wanted = _engine_file(Path(settings["llvm_root"]) / "bin/LLVM-C.dll")
    if library != wanted or index.get(_engine_key(wanted)) != file_hash(wanted):
        raise RustIRError("Requested LLVM library lacks exact configuration/snapshot binding")
    module, imported_pins, origins, source_imports = import_verified_module(
        "antirea.swift_frontend", workspace_root=root, trusted_engine_pins=trusted_engine_pins)
    if imported_pins != watched:
        raise RustIRError("Engine snapshot changed across backend import")
    return module._LLVM, watched, origins, source_imports


def _path(value, root, *, owned):
    if not isinstance(value, Path) or not value.is_absolute() or ".." in value.parts:
        raise RustIRError("A canonical absolute Path is required")
    if any(part.casefold() in {"rea-analysis-reports", "attackerfolder", "env.setting", "linkrepro", "shared"}
           for part in value.parts):
        raise RustIRError("Received/shared/sensitive files are not provenance inputs")
    _no_links(value)
    if (not value.is_file() or value != value.resolve(strict=True)
            or (owned and not value.is_relative_to(root))):
        raise RustIRError("Input must be a regular pinned file in its approved ownership boundary")
    return value


def _request(request, workspace_root, llvm_library):
    root = Path(workspace_root)
    if not root.is_absolute() or ".." in root.parts or not root.is_dir() or root != root.resolve(strict=True):
        raise RustIRError("Trusted workspace root must be explicit and canonical")
    _no_links(root)
    if not isinstance(request, RustIRRequest) or not isinstance(request.provenance, RustSourceProvenance):
        raise RustIRError("Expected a typed internal Rust IR request")
    provenance = request.provenance
    if provenance.kind != "trusted_frontend_rust_ir" or provenance.target != TARGET:
        raise RustIRError("Unsupported Rust provenance kind or target")
    if (not isinstance(provenance.frontend_flags, tuple) or not provenance.frontend_flags
            or any(not isinstance(v, str) or not v or "\x00" in v for v in provenance.frontend_flags)):
        raise RustIRError("Recorded frontend flags are required, never executed by this adapter")
    watched = {}
    for field, owned in (("compiler_inputs", False), ("source_inputs", True), ("evidence_files", True)):
        records = getattr(provenance, field)
        if not isinstance(records, tuple) or not 1 <= len(records) <= 256:
            raise RustIRError("Nonempty bounded provenance pins are required: " + field)
        for record in records:
            if (not isinstance(record, PinnedFile) or not isinstance(record.sha256, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", record.sha256)):
                raise RustIRError("Malformed provenance pin")
            path = _path(record.path, root, owned=owned)
            if file_hash(path) != record.sha256 or (str(path) in watched and watched[str(path)] != record.sha256):
                raise RustIRError("Provenance file hash changed")
            watched[str(path)] = record.sha256
    config_path = _path(root / ".tools/kagura-toolchain.json", root, owned=True)
    if config_path.stat().st_size > 1024 * 1024:
        raise RustIRError("Local LLVM configuration exceeds bound")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise RustIRError("Duplicate local toolchain configuration key")
            result[key] = value
        return result
    config = json.loads(config_path.read_text(encoding="utf-8-sig"), object_pairs_hook=pairs)
    if (not isinstance(config, dict) or type(config.get("schema_version")) is not int or config["schema_version"] != 1
            or config.get("target") != TARGET or not isinstance(config.get("llvm_root"), str)):
        raise RustIRError("Unsupported trusted local LLVM configuration")
    library = _path(Path(config["llvm_root"]) / "bin/LLVM-C.dll", root, owned=False)
    if llvm_library != library:
        raise RustIRError("Requested LLVM parser differs from the trusted local configuration")
    for path in (config_path, library):
        if watched.get(str(path)) != file_hash(path):
            raise RustIRError("Local LLVM parser/config must be pinned in provenance")
    input_path = _path(request.input_ir, root, owned=True)
    if not input_path.is_relative_to(root / ".runs") or input_path.stat().st_size > MAX_IR:
        raise RustIRError("Protection IR must be a bounded private owned artifact")
    data = input_path.read_bytes()
    if not data or digest(data) != request.input_sha256:
        raise RustIRError("Input IR hash changed")
    watched[str(input_path)] = request.input_sha256
    selected, exports = request.selected_functions, request.public_exports
    for values in (selected, exports):
        if (not isinstance(values, tuple) or not 1 <= len(values) <= 64
                or any(not isinstance(v, str) or not 1 <= len(v) <= 512
                       or any(ord(c) < 33 or ord(c) > 126 for c in v) for v in values)
                or len(set(values)) != len(values)):
            raise RustIRError("Expected unique bounded exact ASCII LLVM identities")
    if (not set(exports) <= set(selected) or any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", v) for v in exports)
            or not isinstance(request.expected_calls, dict) or set(request.expected_calls) != set(selected)):
        raise RustIRError("Selected/exported graph identities are inconsistent")
    for values in request.expected_calls.values():
        if (not isinstance(values, tuple) or any(not isinstance(v, str) for v in values)
                or len(set(values)) != len(values) or not set(values) <= set(selected)):
            raise RustIRError("Expected graph must contain exact closed direct-call edges")
    return data, library, watched


def _api(library, *, workspace_root, trusted_engine_pins):
    factory, watched, origins, source_imports = _llvm_backend(workspace_root, library, trusted_engine_pins)
    llvm = factory(library)
    p, u = ctypes.c_void_p, ctypes.c_uint
    definitions = {
        "LLVMLookupIntrinsicID": (u, [ctypes.c_char_p, ctypes.c_size_t]),
        "LLVMGetLinkage": (u, [p]), "LLVMGetVisibility": (u, [p]), "LLVMGetDLLStorageClass": (u, [p]),
        "LLVMGetComdat": (p, [p]), "LLVMHasPersonalityFn": (ctypes.c_int, [p]),
        "LLVMGetNextUse": (p, [p]), "LLVMGetUser": (p, [p]),
        "LLVMGetInstructionParent": (p, [p]), "LLVMGetBasicBlockParent": (p, [p]),
        "LLVMPrintTypeToString": (p, [p]), "LLVMGetNumArgOperands": (u, [p]),
        "LLVMGetAttributeCountAtIndex": (u, [p, u]), "LLVMGetAttributesAtIndex": (None, [p, u, ctypes.POINTER(p)]),
        "LLVMGetCallSiteAttributeCount": (u, [p, u]), "LLVMGetCallSiteAttributes": (None, [p, u, ctypes.POINTER(p)]),
        "LLVMGetEnumAttributeAtIndex": (p, [p, u, u]), "LLVMGetCallSiteEnumAttribute": (p, [p, u, u]),
        "LLVMRemoveCallSiteEnumAttribute": (None, [p, u, u]), "LLVMAddCallSiteAttribute": (None, [p, u, p]),
        "LLVMIsEnumAttribute": (ctypes.c_int, [p]), "LLVMIsStringAttribute": (ctypes.c_int, [p]),
        "LLVMIsTypeAttribute": (ctypes.c_int, [p]), "LLVMGetEnumAttributeKind": (u, [p]),
        "LLVMGetEnumAttributeValue": (ctypes.c_ulonglong, [p]), "LLVMGetTypeAttributeValue": (p, [p]),
        "LLVMGetStringAttributeKind": (p, [p, ctypes.POINTER(u)]), "LLVMGetStringAttributeValue": (p, [p, ctypes.POINTER(u)]),
    }
    try:
        for name, (result, arguments) in definitions.items():
            callback = getattr(llvm.dll, name)
            callback.restype, callback.argtypes = result, arguments
            setattr(llvm, name, callback)
        _recheck_engine(watched, workspace_root)
        llvm.trusted_engine_inputs = watched
        llvm.trusted_module_origins = origins
        llvm.verified_source_imports = source_imports
        return llvm
    except BaseException:
        llvm.close()
        raise


def open_llvm(*, workspace_root, llvm_library, trusted_engine_pins):
    """Pinned parser entry for prepare/qualifier; caller must close the result."""
    return _api(llvm_library, workspace_root=workspace_root, trusted_engine_pins=trusted_engine_pins)


def _parse(llvm, context, data):
    module, error = ctypes.c_void_p(), ctypes.c_void_p()
    buffer = llvm.LLVMCreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"owned-rust-protection-copy")
    if llvm.LLVMParseIRInContext(context, buffer, ctypes.byref(module), ctypes.byref(error)):
        raise RustIRError("LLVM parser rejected IR: " + llvm.string(error.value))
    if llvm.LLVMVerifyModule(module, 2, ctypes.byref(error)):
        message = llvm.string(error.value)
        llvm.LLVMDisposeModule(module)
        raise RustIRError("LLVM verifier rejected IR: " + message)
    return module


def _attrs(llvm, value, count, *, call=False):
    result = {}
    count_fn = llvm.LLVMGetCallSiteAttributeCount if call else llvm.LLVMGetAttributeCountAtIndex
    get_fn = llvm.LLVMGetCallSiteAttributes if call else llvm.LLVMGetAttributesAtIndex
    for index in (0xFFFFFFFF, *range(count + 1)):
        n = count_fn(value, index)
        values = (ctypes.c_void_p * n)()
        get_fn(value, index, values)
        rows = []
        for item in values:
            if llvm.LLVMIsEnumAttribute(item):
                rows.append({"kind": "enum", "id": llvm.LLVMGetEnumAttributeKind(item), "value": llvm.LLVMGetEnumAttributeValue(item)})
            elif llvm.LLVMIsStringAttribute(item):
                kl, vl = ctypes.c_uint(), ctypes.c_uint()
                k = llvm.LLVMGetStringAttributeKind(item, ctypes.byref(kl))
                v = llvm.LLVMGetStringAttributeValue(item, ctypes.byref(vl))
                rows.append({"kind": "string", "key": ctypes.string_at(k, kl.value).hex(), "value": ctypes.string_at(v, vl.value).hex()})
            elif llvm.LLVMIsTypeAttribute(item):
                rows.append({"kind": "type", "id": llvm.LLVMGetEnumAttributeKind(item),
                    "type": llvm.string(llvm.LLVMPrintTypeToString(llvm.LLVMGetTypeAttributeValue(item)))})
            else:
                raise RustIRError("Unsupported LLVM attribute category")
        result[str(index)] = rows
    return result


def validate_intrinsic_shape(name, intrinsic_id, expected_id, *, declared, return_kind,
                             return_bits, parameter_shapes, vararg, calling_convention):
    """Pure exact-shape gate; actual IDs must come from the pinned LLVM-C API."""
    if not isinstance(name, str) or len(name) > 64:
        raise RustIRError("External/runtime or unallowlisted intrinsic name")
    match = re.fullmatch(r"(llvm\.(?:fshl|fshr|smin|smax|umin|umax))\.i(8|16|32|64)", name)
    if not match:
        raise RustIRError("External/runtime or unallowlisted intrinsic name")
    base, width = match.group(1), int(match.group(2))
    if (type(intrinsic_id) is not int or type(expected_id) is not int or expected_id <= 0
            or intrinsic_id != expected_id):
        raise RustIRError("Intrinsic ID differs from the pinned exact base lookup")
    if declared is not True or vararg is not False or type(calling_convention) is not int or calling_convention != 0:
        raise RustIRError("Intrinsic must be a nonvariadic C-convention declaration")
    expected_shape = {"kind": 8, "bits": width}
    if (type(return_kind) is not int or return_kind != 8 or type(return_bits) is not int or return_bits != width
            or not isinstance(parameter_shapes, list) or len(parameter_shapes) != INTRINSICS[base]
            or any(not isinstance(row, dict) or set(row) != {"kind", "bits"}
                   or type(row["kind"]) is not int or type(row["bits"]) is not int
                   or row != expected_shape for row in parameter_shapes)):
        raise RustIRError("Intrinsic requires exact same-width scalar integer return/arguments")
    return {"name": name, "base": base, "intrinsic_id": intrinsic_id, "return_bits": width,
            "parameter_bits": [width] * INTRINSICS[base], "calling_convention": 0,
            "backend_gate": ("funnel_vm_lowering_required_unverified" if base in ("llvm.fshl", "llvm.fshr")
                             else "existing_vm_minmax_lowering_unvalidated_here")}


def intrinsic_inventory(llvm, module):
    """Exact typed declarations/calls; intrinsic names are not selected nodes."""
    all_functions = {llvm.name(value): value for value in llvm.functions(module)}
    definitions = {name: value for name, value in all_functions.items() if not llvm.LLVMIsDeclaration(value)}
    declarations, calls = {}, {name: [] for name in definitions}
    special = {llvm.LLVMGetEnumAttributeKindForName(name, len(name)) for name in
               (b"inreg", b"nest", b"swiftself", b"swifterror", b"swiftasync", b"sret", b"byval", b"inalloca", b"preallocated")}
    extension = {llvm.LLVMGetEnumAttributeKindForName(name, len(name)) for name in (b"zeroext", b"signext")}
    for name, function in all_functions.items():
        intrinsic_id = int(llvm.LLVMGetIntrinsicID(function))
        if not llvm.LLVMIsDeclaration(function):
            if intrinsic_id or name.startswith("llvm."):
                raise RustIRError("Intrinsic definition/spoof is unsupported")
            continue
        base = name.rsplit(".i", 1)[0]
        expected = int(llvm.LLVMLookupIntrinsicID(base.encode(), len(base))) if base in INTRINSICS else 0
        signature = llvm.LLVMGlobalGetValueType(function)
        count = llvm.LLVMCountParamTypes(signature)
        if count > 3:
            raise RustIRError("External/runtime or intrinsic parameter count unsupported")
        parameters = (ctypes.c_void_p * count)()
        llvm.LLVMGetParamTypes(signature, parameters)
        returned = llvm.LLVMGetReturnType(signature)
        def shape(kind):
            category = int(llvm.LLVMGetTypeKind(kind))
            return {"kind": category, "bits": int(llvm.LLVMGetIntTypeWidth(kind)) if category == 8 else 0}
        row = validate_intrinsic_shape(name, intrinsic_id, expected,
            declared=bool(llvm.LLVMIsDeclaration(function)), return_kind=shape(returned)["kind"],
            return_bits=shape(returned)["bits"], parameter_shapes=[shape(kind) for kind in parameters],
            vararg=bool(llvm.LLVMIsFunctionVarArg(signature)),
            calling_convention=int(llvm.LLVMGetFunctionCallConv(function)))
        if (llvm.LLVMGetLinkage(function) != 0 or llvm.LLVMGetDLLStorageClass(function)
                or llvm.LLVMGetComdat(function) or llvm.LLVMHasPersonalityFn(function)):
            raise RustIRError("Intrinsic declaration linkage/storage/personality is unsupported")
        attrs = _attrs(llvm, function, count)
        if any(item.get("id") in special for key, rows in attrs.items() if key != "4294967295" for item in rows):
            raise RustIRError("Special intrinsic parameter ABI attributes are unsupported")
        declarations[name] = {**row, "type": llvm.string(llvm.LLVMPrintTypeToString(signature)),
                              "linkage": 0, "visibility": int(llvm.LLVMGetVisibility(function)),
                              "dll_storage": 0, "attributes": attrs}
    if len(declarations) > 24:
        raise RustIRError("Intrinsic declaration count exceeds explicit allowlist")
    for owner, function in definitions.items():
        for index, instruction in enumerate(llvm.instructions(function)):
            if llvm.LLVMGetInstructionOpcode(instruction) != 45:
                continue
            callee = llvm.LLVMGetCalledValue(instruction)
            name = llvm.name(callee) if callee else ""
            if name not in declarations:
                continue
            if (callee != all_functions[name] or llvm.LLVMGetValueKind(callee) != 5
                    or llvm.LLVMGetNumOperandBundles(instruction)
                    or llvm.LLVMGetInstructionCallConv(instruction) != 0
                    or llvm.LLVMGetCalledFunctionType(instruction) != llvm.LLVMGlobalGetValueType(callee)
                    or llvm.LLVMGetNumArgOperands(instruction) != len(declarations[name]["parameter_bits"])):
                raise RustIRError("Intrinsic call must use the exact declared Value/type/CC without bundles")
            attrs = _attrs(llvm, instruction, llvm.LLVMGetNumArgOperands(instruction), call=True)
            for key, rows in attrs.items():
                if key != "4294967295":
                    if any(row.get("id") in special for row in rows):
                        raise RustIRError("Special intrinsic call ABI attributes are unsupported")
                    if [row for row in rows if row.get("id") in extension] != [
                            row for row in declarations[name]["attributes"][key] if row.get("id") in extension]:
                        raise RustIRError("Intrinsic call and declaration extension ABI attributes differ")
            calls[owner].append({"instruction_index": index, "callee": name,
                "intrinsic_id": declarations[name]["intrinsic_id"], "type": declarations[name]["type"],
                "calling_convention": 0, "attributes": attrs})
    for name in declarations:
        function, use = all_functions[name], llvm.LLVMGetFirstUse(all_functions[name])
        while use:
            user = llvm.LLVMGetUser(use)
            if (llvm.LLVMGetValueKind(user) != 24 or llvm.LLVMGetInstructionOpcode(user) != 45
                    or llvm.LLVMGetCalledValue(user) != function
                    or sum(llvm.LLVMGetOperand(user, n) == function for n in range(llvm.LLVMGetNumOperands(user))) != 1
                    or llvm.name(llvm.LLVMGetBasicBlockParent(llvm.LLVMGetInstructionParent(user))) not in definitions):
                raise RustIRError("Intrinsic has a non-direct/address-taken/outside-graph use")
            use = llvm.LLVMGetNextUse(use)
    return {"declarations": declarations, "calls": calls}


def _inspect(llvm, module, exported):
    length = ctypes.c_size_t()
    llvm.LLVMGetModuleInlineAsm(module, ctypes.byref(length))
    if (length.value or llvm.LLVMGetFirstGlobalAlias(module) or llvm.LLVMGetFirstGlobalIFunc(module)
            or llvm.LLVMGetFirstGlobal(module) or llvm.LLVMGetNamedMetadataNumOperands(module, b"llvm.linker.options")):
        raise RustIRError("Module assembly/aliases/globals/ifuncs/linker metadata are unsupported")
    if llvm.LLVMGetTarget(module).decode() != TARGET:
        raise RustIRError("Rust IR target differs from the supported target")
    all_functions = {llvm.name(value): value for value in llvm.functions(module)}
    intrinsic = intrinsic_inventory(llvm, module)
    functions = {name: value for name, value in all_functions.items() if not llvm.LLVMIsDeclaration(value)}
    if not 1 <= len(functions) <= 64:
        raise RustIRError("Closed Rust graph exceeds bounded function count")
    special = {llvm.LLVMGetEnumAttributeKindForName(name, len(name)) for name in
               (b"inreg", b"nest", b"swiftself", b"swifterror", b"swiftasync", b"sret", b"byval", b"inalloca", b"preallocated")}
    extension = {llvm.LLVMGetEnumAttributeKindForName(name, len(name)) for name in (b"zeroext", b"signext")}
    signatures, graph, calls, uses = {}, {}, {}, {}
    for name, function in functions.items():
        if (llvm.LLVMIsDeclaration(function) or llvm.LLVMHasPersonalityFn(function)
                or llvm.LLVMGetComdat(function) or llvm.LLVMGetLinkage(function) not in (0, 8, 9)):
            raise RustIRError("External/runtime, personality, COMDAT or weak definitions are unsupported")
        if llvm.LLVMGetFunctionCallConv(function) != 0:
            raise RustIRError("Non-C calling convention is rejected, never rewritten")
        if llvm.LLVMGetDLLStorageClass(function) or (name in exported and llvm.LLVMGetLinkage(function) != 0):
            raise RustIRError("DLL-storage or nonexternal public definition is unsupported")
        signature = llvm.LLVMGlobalGetValueType(function)
        count = llvm.LLVMCountParamTypes(signature)
        parameters = (ctypes.c_void_p * count)()
        llvm.LLVMGetParamTypes(signature, parameters)
        types = [llvm.LLVMGetReturnType(signature), *parameters]
        widths = {32, 64} if name in exported else {1, 8, 16, 32, 64}
        if (llvm.LLVMIsFunctionVarArg(signature) or count > 8 or any(
                llvm.LLVMGetTypeKind(kind) != 8 or llvm.LLVMGetIntTypeWidth(kind) not in widths for kind in types)):
            raise RustIRError("Only supported scalar integer signatures are accepted; public ABI is i32/i64")
        attrs = _attrs(llvm, function, count)
        if any(item.get("id") in special for key, rows in attrs.items() if key != "4294967295" for item in rows):
            raise RustIRError("Special parameter ABI attributes are unsupported")
        signatures[name] = {"type": llvm.string(llvm.LLVMPrintTypeToString(signature)),
            "return_bits": llvm.LLVMGetIntTypeWidth(types[0]), "parameter_bits": [llvm.LLVMGetIntTypeWidth(v) for v in parameters],
            "calling_convention": 0, "linkage": llvm.LLVMGetLinkage(function), "visibility": llvm.LLVMGetVisibility(function),
            "dll_storage": 0, "attributes": attrs}
        graph[name], calls[name], uses[name] = set(), [], []
    for name, function in functions.items():
        for index, instruction in enumerate(llvm.instructions(function)):
            opcode = llvm.LLVMGetInstructionOpcode(instruction)
            if opcode not in ALLOWED_OPCODES:
                raise RustIRError("Unsupported non-scalar/memory/exception instruction: " + str(opcode))
            result_type = llvm.LLVMTypeOf(instruction)
            if llvm.LLVMGetTypeKind(result_type) != 0 and (llvm.LLVMGetTypeKind(result_type) != 8 or llvm.LLVMGetIntTypeWidth(result_type) not in {1, 8, 16, 32, 64}):
                raise RustIRError("Aggregate/pointer/noninteger instruction result is unsupported")
            callee = None
            if opcode == 45:
                callee = llvm.LLVMGetCalledValue(instruction)
                callee_name = llvm.name(callee) if callee else ""
                if (callee_name not in all_functions or callee != all_functions[callee_name]
                        or llvm.LLVMGetValueKind(callee) != 5 or llvm.LLVMGetNumOperandBundles(instruction)
                        or llvm.LLVMGetInstructionCallConv(instruction) != 0
                        or llvm.LLVMGetCalledFunctionType(instruction) != llvm.LLVMGlobalGetValueType(callee)):
                    raise RustIRError("Call must target an exact defined Value or allowed intrinsic with matching C CC/type and no bundles")
                attrs = _attrs(llvm, instruction, llvm.LLVMGetNumArgOperands(instruction), call=True)
                target_signature = signatures.get(callee_name, intrinsic["declarations"].get(callee_name))
                for key, values in attrs.items():
                    if key == "4294967295":
                        continue
                    wanted = [a for a in target_signature["attributes"][key] if a.get("id") in extension]
                    if [a for a in values if a.get("id") in extension] != wanted:
                        raise RustIRError("Call and callee integer-extension ABI attributes differ")
                if callee_name in functions:
                    graph[name].add(callee_name)
                    calls[name].append({"instruction_index": index, "callee": callee_name, "attributes": attrs})
            for n in range(llvm.LLVMGetNumOperands(instruction)):
                operand = llvm.LLVMGetOperand(instruction, n)
                if operand == callee or llvm.LLVMGetTypeKind(llvm.LLVMTypeOf(operand)) == 7:
                    continue
                kind = llvm.LLVMTypeOf(operand)
                if llvm.LLVMGetTypeKind(kind) != 8 or llvm.LLVMGetIntTypeWidth(kind) not in {1, 8, 16, 32, 64}:
                    raise RustIRError("Pointer/callback/aggregate instruction operands are unsupported")
        use = llvm.LLVMGetFirstUse(function)
        while use:
            user = llvm.LLVMGetUser(use)
            if (llvm.LLVMGetValueKind(user) != 24 or llvm.LLVMGetInstructionOpcode(user) != 45
                    or llvm.LLVMGetCalledValue(user) != function
                    or sum(llvm.LLVMGetOperand(user, i) == function for i in range(llvm.LLVMGetNumOperands(user))) != 1):
                raise RustIRError("Non-direct or address-taken function use is unsupported")
            caller = llvm.LLVMGetBasicBlockParent(llvm.LLVMGetInstructionParent(user))
            if llvm.name(caller) not in functions:
                raise RustIRError("Function has a caller outside the closed graph")
            uses[name].append(llvm.name(caller))
            use = llvm.LLVMGetNextUse(use)
    return functions, signatures, {name: sorted(edges) for name, edges in graph.items()}, calls, uses


def _mapped_name(name, input_hash):
    return "antirea_rust_fn_" + digest(bytes.fromhex(input_hash) + b"\0" + name.encode())[:32]


def normalize_protection_ir(request: RustIRRequest, *, workspace_root: Path, llvm_library: Path,
                            trusted_engine_pins: dict[str, str]):
    engine = verify_engine_snapshot(workspace_root, trusted_engine_pins)
    data, library, watched = _request(request, workspace_root, llvm_library)
    indexed = {_engine_key(path): sha for path, sha in engine.items()}
    if any(_engine_key(path) in indexed and indexed[_engine_key(path)] != sha for path, sha in watched.items()):
        raise RustIRError("Original provenance and reviewed engine snapshot disagree")
    llvm, context, original, checked = None, None, None, None
    try:
        llvm = open_llvm(workspace_root=workspace_root, llvm_library=library, trusted_engine_pins=trusted_engine_pins)
        if llvm.trusted_engine_inputs != engine:
            raise RustIRError("Engine snapshot changed before LLVM use")
        context = llvm.LLVMContextCreate()
        original = _parse(llvm, context, data)
        functions, signatures, graph, calls, uses = _inspect(llvm, original, set(request.public_exports))
        before_intrinsic = intrinsic_inventory(llvm, original)
        selected = set(request.selected_functions)
        if set(functions) != selected or graph != {name: sorted(edges) for name, edges in request.expected_calls.items()}:
            raise RustIRError("Actual complete function/use graph differs from the selected scope")
        canonical_before = llvm.string(llvm.LLVMPrintModuleToString(original))
        names = {name: name if name in request.public_exports else _mapped_name(name, request.input_sha256) for name in functions}
        if (len(set(names.values())) != len(names)
                or any(mapped in functions and mapped != name for name, mapped in names.items())
                or set(names.values()) & set(before_intrinsic["declarations"])):
            raise RustIRError("Generated Rust symbol collision")
        retention_ids = {value: llvm.LLVMGetEnumAttributeKindForName(value, len(value)) for value in RETENTION}
        saved = {}
        def edit_retention(value, key, *, call=False, restore=False):
            get = llvm.LLVMGetCallSiteEnumAttribute if call else llvm.LLVMGetEnumAttributeAtIndex
            remove = llvm.LLVMRemoveCallSiteEnumAttribute if call else llvm.LLVMRemoveEnumAttributeAtIndex
            add = llvm.LLVMAddCallSiteAttribute if call else llvm.LLVMAddAttributeAtIndex
            if not restore:
                saved[key] = [get(value, 0xFFFFFFFF, kind) for kind in retention_ids.values()]
            for kind in retention_ids.values():
                remove(value, 0xFFFFFFFF, kind)
            if restore:
                for attribute in saved[key]:
                    if attribute:
                        add(value, 0xFFFFFFFF, attribute)
            else:
                add(value, 0xFFFFFFFF, llvm.LLVMCreateEnumAttribute(context, retention_ids[b"noinline"], 0))
        for name, function in functions.items():
            llvm.LLVMSetValueName2(function, names[name].encode(), len(names[name]))
            if llvm.name(function) != names[name]:
                raise RustIRError("LLVM changed a requested exact symbol name")
            # Protection-copy retention only. Internal/private functions may
            # otherwise be promoted to fastcc by later GlobalOpt. This does NOT
            # rewrite their current calling convention. Exact closed uses were
            # checked above; final exports/closed linking remain a separate gate.
            if name not in request.public_exports and signatures[name]["linkage"] in (8, 9):
                llvm.LLVMSetLinkage(function, 0)
                llvm.LLVMSetVisibility(function, 1)
            edit_retention(function, (name, "function"))
            for index, instruction in enumerate(llvm.instructions(function)):
                if (llvm.LLVMGetInstructionOpcode(instruction) == 45
                        and not llvm.LLVMGetIntrinsicID(llvm.LLVMGetCalledValue(instruction))):
                    edit_retention(instruction, (name, index), call=True)
        serialized = llvm.string(llvm.LLVMPrintModuleToString(original)).encode()
        checked = _parse(llvm, context, serialized)
        mapped, after_signatures, after_graph, after_calls, after_uses = _inspect(llvm, checked, set(request.public_exports))
        after_intrinsic = intrinsic_inventory(llvm, checked)
        if (before_intrinsic["declarations"] != after_intrinsic["declarations"]
                or {names[name]: rows for name, rows in before_intrinsic["calls"].items()} != after_intrinsic["calls"]):
            raise RustIRError("Typed intrinsic declarations/calls changed during protection mapping")
        if set(mapped) != set(names.values()) or after_graph != {names[n]: sorted(names[e] for e in edges) for n, edges in graph.items()}:
            raise RustIRError("Protection-copy graph changed after rename/reparse")
        records = {}
        for name, target in names.items():
            before, after = signatures[name], after_signatures[target]
            promoted = name not in request.public_exports and before["linkage"] in (8, 9)
            expected_linkage = 0 if promoted else before["linkage"]
            expected_visibility = 1 if promoted else before["visibility"]
            if after["linkage"] != expected_linkage or after["visibility"] != expected_visibility:
                raise RustIRError("Unauthorized protection-copy linkage/visibility transition")
            for key in set(before) - {"attributes", "linkage", "visibility"}:
                if before[key] != after[key]:
                    raise RustIRError("Signature changed beyond protection-only names")
            if {k: v for k, v in before["attributes"].items() if k != "4294967295"} != {k: v for k, v in after["attributes"].items() if k != "4294967295"}:
                raise RustIRError("Return/parameter ABI attributes changed")
            if sorted(after_uses[target]) != sorted(names[n] for n in uses[name]):
                raise RustIRError("Direct-use inventory changed")
            records[name] = {"source_symbol": name, "protected_symbol": target, "renamed": name != target,
                "source_symbol_bytes_hex": name.encode().hex(), "signature": before,
                "source_callers": sorted(uses[name]), "protected_callers": sorted(after_uses[target]),
                "direct_use_count": len(uses[name]), "all_uses_checked": True,
                "linkage_transition": {"promoted_private_to_external_hidden": promoted,
                    "source_linkage": before["linkage"], "protected_linkage": after["linkage"],
                    "source_visibility": before["visibility"], "protected_visibility": after["visibility"],
                    "all_direct_callers_in_selected_graph": True},
                "retention_before": before["attributes"]["4294967295"],
                "retention_after": after["attributes"]["4294967295"]}
        # Strong reversible check: restore names, linkage, visibility and retention
        # AttributeRefs on the parsed output. Its entire canonical LLVM module
        # must equal the original canonical module, including numbered groups.
        # Nothing is hidden with regex attribute-number stripping.
        for name, target in names.items():
            function = mapped[target]
            llvm.LLVMSetValueName2(function, name.encode(), len(name))
            llvm.LLVMSetLinkage(function, signatures[name]["linkage"])
            llvm.LLVMSetVisibility(function, signatures[name]["visibility"])
            edit_retention(function, (name, "function"), restore=True)
            for index, instruction in enumerate(llvm.instructions(function)):
                if (llvm.LLVMGetInstructionOpcode(instruction) == 45
                        and not llvm.LLVMGetIntrinsicID(llvm.LLVMGetCalledValue(instruction))):
                    edit_retention(instruction, (name, index), call=True, restore=True)
        restored = llvm.string(llvm.LLVMPrintModuleToString(checked))
        if restored != canonical_before:
            raise RustIRError("Exact restoration failed: more than names/retention/authorized linkage changed")
        for name, expected in watched.items():
            if file_hash(Path(name)) != expected:
                raise RustIRError("A pinned input changed during normalization")
        _recheck_engine(engine, workspace_root)
        origins = _loaded_engine(Path(workspace_root), engine)
        provenance = asdict(request.provenance)
        for field in ("compiler_inputs", "source_inputs", "evidence_files"):
            provenance[field] = [{"path": str(row["path"]), "sha256": row["sha256"]} for row in provenance[field]]
        return serialized, {"schema_version": 1, "normalization_revision": 3, "backend": "rust_ir_protection_copy",
            "status": "mapped_ir_unlinked_unvalidated", "input_sha256": digest(data), "output_sha256": digest(serialized),
            "source_selected_functions": sorted(selected), "protected_selected_functions": sorted(names.values()),
            "exported_functions": sorted(request.public_exports), "functions": records,
            "source_graph": graph, "protected_graph": after_graph,
            "source_calls": calls, "protected_calls": after_calls,
            "intrinsic_declarations": before_intrinsic["declarations"],
            "source_intrinsic_calls": before_intrinsic["calls"],
            "protected_intrinsic_calls": after_intrinsic["calls"],
            "intrinsic_contract_preserved": True,
            "intrinsic_backend_validated": False,
            "exact_restore_roundtrip": True, "calling_convention_rewritten": False,
            "retention_changes": ["remove only alwaysinline/inlinehint/optnone/noinline function and defined-call hints",
                                  "set noinline on every selected function and defined-function direct call",
                                  "leave allowlisted intrinsic declarations and callsites unchanged"],
            "linkage_policy": "closed_private_to_external_hidden",
            "closed_final_link": {"status": "required_unverified", "exported_functions": sorted(request.public_exports),
                "helper_exports_forbidden": True, "dependency_link_closure_verified": False},
            "provenance": provenance, "input_hashes": watched, "source_or_baseline_modified": False,
            "engine_snapshot_revision": 1, "reviewed_engine_inputs": engine,
            "loaded_production_modules": origins, "engine_inputs_unchanged": True,
            "source_import_policy": "fixed_antirea_namespace_reviewed_source_bytes",
            "verified_source_imports": llvm.verified_source_imports,
            "vm_applied": False, "target_executed": False, "complete_application_link": False,
            "limitations": ["Trusted-frontend hash binding, not independent compiler execution attestation.",
                "Closed scalar integer graph only; no aggregate/pointer/runtime/callback/alias/COMDAT/assembly support.",
                "Public ABI remains i32/i64; helper i1/i8/i16/i32/i64 support here does not prove Kagura compatibility.",
                "Exact fshl/fshr and integer min/max declarations are preserved, not lowered here; funnel VM support remains required/unverified.",
                "Internal/private nonpublic definitions are external-hidden only in the protection copy; final link/export isolation is required and not yet verified.",
                "Cargo crate recipe, dependencies/dep-info, final Rust link, original-reference comparison and actual VM stage evidence remain required."]}
    finally:
        if checked:
            llvm.LLVMDisposeModule(checked)
        if original:
            llvm.LLVMDisposeModule(original)
        if context:
            llvm.LLVMContextDispose(context)
        if llvm is not None:
            llvm.close()
