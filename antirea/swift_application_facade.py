"""Pure same-name Swift application facade generation for owned-app integration.

This module never executes: it parses the pinned compiler-produced
``.swiftinterface`` and the authenticated producer report, generates Swift
*source*, and reuses the fixed :mod:`antirea.bindings` generator.  It is not a
Swift compiler, not a whole-language promise, and it preserves neither Swift
reflection nor the module ABI beyond the selected integer roots.

A protected deployment substitutes same-name top-level Swift facade functions
that forward each selected public scalar root to the packaged protected native
core through the generated ``NativeCore`` bridge.  The ordinary application
source is preserved byte-for-byte and keeps calling the same Swift function
names *and external argument labels*; the original core source is NEVER part of
the protected compiler inputs or deployment.

Boundaries (see ``.runs/phase22-root/brief.md`` and AGENTS.md):
  * Only separated pure-scalar Swift cores already accepted by the Swift source
    frontend (``backend == "swift_llvm_native"``) are supported, plus ordinary
    application sources that reference nothing of the core except its selected
    public roots.
  * Generation reuses :func:`antirea.bindings.generate_bindings` in a private
    subdirectory; only the common C bridge implementation and the generated
    ``NativeCore`` Swift source plus its module map are exposed as trusted
    compile inputs.  ``bindings`` is never modified here.
  * External argument labels (named labels, ``_`` and the implicit
    label == internal-name form) are derived ONLY from the pinned
    compiler-produced ``.swiftinterface``, authenticated by its declared
    SHA-256, never from a source regex of the original core.
  * The authenticated producer report and every file it points at are read with
    a lexical reserved-path guard, a no-links resolve and an exact SHA-256 match
    before use.  Missing or inconsistent evidence is rejected; nothing is
    compiled, executed, downloaded or published.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re

from . import bindings
from . import native_build


class SwiftFacadeError(ValueError):
    """Raised for malformed input or missing/inconsistent build evidence.

    Reserved for input that cannot be trusted enough to continue (bad producer
    report, hash mismatch, reserved path, interface/contract disagreement, ...).
    """


# Attacker-supplied / forbidden directory names that must never be read or
# written here (any case).  A lexical guard precedes any filesystem access.
RESERVED_PARTS = {"rea-analysis-reports", "attackerfolder", "env.setting", "linkrepro"}

ENV_CORE = "ANTIREA_NATIVE_CORE"
BRIDGE_MODULE = "AntireaBridge"
NATIVECORE_TYPE = "NativeCore"
BOOTSTRAP_TYPE = "ProtectedBootstrap"
# Swift identifiers the generated runtime occupies; an original root may not
# reuse them as a top-level function name.
RESERVED_SWIFT_NAMES = {NATIVECORE_TYPE, BOOTSTRAP_TYPE, BRIDGE_MODULE}

PRODUCER_STATUS = "artifact_created_unvalidated"
PRODUCER_BACKEND = "swift_llvm_native"
LANGUAGE = "swift"
STATUS_GENERATED = "generated_not_validated"
KIND = "native_application_facade"

# The frontend writes the authenticated contract to this fixed relative path and
# pins it in ``artifact_hashes`` (the report carries no inline contract).
CONTRACT_RELATIVE = "frontend/contract.json"

# Only the scalar integer ABI the engine protects; never bool/float/void roots.
SCALAR_TYPES = ("u32", "i32", "u64", "i64")
SWIFT_TYPE = {"u32": "UInt32", "i32": "Int32", "u64": "UInt64", "i64": "Int64"}

MAX_INTERFACE_BYTES = 1 * 1024 * 1024
MAX_CONTRACT_BYTES = 1 * 1024 * 1024
MAX_ROOTS = 128

SAFE_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}\Z")
SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")

_CDECL = re.compile(r'@_cdecl\("([A-Za-z_][A-Za-z0-9_]*)"\)')
_SIGNATURE = re.compile(
    r'public func ([A-Za-z_][A-Za-z0-9_]*)\((.*)\) -> (?:Swift(?:\.|::))?(UInt32|Int32|UInt64|Int64)')
_PARAMETER = re.compile(
    r'\s*(?:(_|[A-Za-z_][A-Za-z0-9_]*)\s+)?'
    r'([A-Za-z_][A-Za-z0-9_]*):\s*(?:Swift(?:\.|::))?(UInt32|Int32|UInt64|Int64)\s*')
_INTERFACE_SCALAR = {"UInt32": "u32", "Int32": "i32", "UInt64": "u64", "Int64": "i64"}

GENERATION_LIMITATIONS = [
    "Experimental: same-name Swift facades for selected public scalar roots "
    "(i32/u32/i64/u64 only); no objects, tuples, optionals, generics, throwing, "
    "async, floats or bool across the native boundary.",
    "Facades forward to the packaged protected native core via the generated "
    "NativeCore bridge; they are not the original algorithm and carry no "
    "original or helper bodies, constants or core source.",
    "External argument labels (named, '_' and implicit) are preserved from the "
    "pinned compiler .swiftinterface so unchanged application source compiles, "
    "but overloaded same-named roots are not supported in this initial integration.",
    "Reflection, dynamic dispatch, @objc and downstream module/ABI stability of "
    "the bundle are NOT preserved or claimed; this is not general Swift API equivalence.",
    "Generation does not compile, execute, download or publish; actual toolchain, "
    "load and behavior results belong to separate harnessed verification and are "
    "not inferred from generated source.",
    "Windows x64 only, matching the pinned native builder and common C bridge.",
]

__all__ = ["SwiftFacadeError", "generate_facade", "ENV_CORE", "LANGUAGE"]


# --------------------------------------------------------------------------
# Bounded, authorized, read-only reads of pinned producer metadata.
# --------------------------------------------------------------------------
def _reserved(path: Path) -> bool:
    return bool({part.casefold() for part in path.parts} & RESERVED_PARTS)


def _read_pinned(raw_path, sha, max_bytes, what):
    """Return ``(resolved_path, bytes)`` for one pinned producer metadata file.

    Lexical reserved-path guard first, then a no-links resolve, then a single
    bounded read of a regular, non-hard-linked file whose SHA-256 must equal the
    declared hash.  The same bytes are returned for parsing (never re-read)."""
    if not isinstance(raw_path, str) or not raw_path:
        raise SwiftFacadeError("%s path must be a non-empty string" % what)
    if not isinstance(sha, str) or not SHA256_HEX.fullmatch(sha):
        raise SwiftFacadeError("%s must declare a lowercase sha256 hex digest" % what)
    raw = Path(raw_path)
    if _reserved(raw):  # lexical guard precedes any filesystem access
        raise SwiftFacadeError("refusing to read reserved/untrusted path for %s: %s" % (what, raw_path))
    path = native_build._no_links(raw)  # rejects symlinks/reparse points in the path
    info = path.lstat() if path.exists() else None
    if info is None or not path.is_file():
        raise SwiftFacadeError("missing or non-regular %s: %s" % (what, raw_path))
    if getattr(info, "st_nlink", 1) not in (0, 1):
        raise SwiftFacadeError("%s must not be hard-linked: %s" % (what, raw_path))
    with open(path, "rb") as stream:
        data = stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise SwiftFacadeError("%s exceeds %d bytes: %s" % (what, max_bytes, raw_path))
    if hashlib.sha256(data).hexdigest() != sha:
        raise SwiftFacadeError("%s hash mismatch: %s" % (what, raw_path))
    return path, data


# --------------------------------------------------------------------------
# Compiler-interface label parser (captures external labels the frontend drops).
# Mirrors ``swift_frontend.parse_public_interface`` acceptance exactly, adding
# the external-argument-label capture group.
# --------------------------------------------------------------------------
def _parse_interface_labels(text, exports) -> dict:
    exports_set = set(exports)
    result, pending = {}, None
    for raw in text.splitlines():
        line = raw.strip()
        attribute = _CDECL.fullmatch(line)
        if attribute:
            pending = attribute[1]
            continue
        if not pending or not line or line.startswith("//"):
            continue
        if line.startswith("@"):
            continue
        export, pending = pending, None
        if export not in exports_set:
            continue
        signature = _SIGNATURE.fullmatch(line)
        if signature is None:
            raise SwiftFacadeError("unsupported Swift public signature for " + export)
        parameters = []
        items = signature[2].split(",") if signature[2].strip() else []
        for item in items:
            parameter = _PARAMETER.fullmatch(item)
            if parameter is None:
                raise SwiftFacadeError("Swift exports require explicit scalar named parameters")
            internal = parameter[2]
            external = parameter[1] if parameter[1] is not None else internal
            parameters.append({"external_label": external, "name": internal,
                               "type": _INTERFACE_SCALAR[parameter[3]]})
        if len(parameters) > 8 or len({p["name"] for p in parameters}) != len(parameters):
            raise SwiftFacadeError("duplicate/oversized Swift public signature for " + export)
        if export in result:
            raise SwiftFacadeError("duplicate compiler signature for export " + export)
        result[export] = {"name": export, "swift_name": signature[1],
                          "return_type": _INTERFACE_SCALAR[signature[3]], "parameters": parameters}
    if set(result) != exports_set:
        raise SwiftFacadeError("every selected export needs an exact compiler-emitted "
                               "public Swift scalar signature")
    return result


# --------------------------------------------------------------------------
# Producer validation + authoritative facade plan (pure).
# --------------------------------------------------------------------------
def _signature_view(function) -> dict:
    """The ABI-only view (name/return_type/parameters) used for equality."""
    return {"name": function["name"], "return_type": function["return_type"],
            "parameters": [{"name": p["name"], "type": p["type"]} for p in function["parameters"]]}


def _validate_producer(producer) -> None:
    if not isinstance(producer, dict):
        raise SwiftFacadeError("producer must be the full swift_frontend build report dict")
    if producer.get("schema_version") != 1:
        raise SwiftFacadeError("producer.schema_version must be 1")
    if producer.get("status") != PRODUCER_STATUS:
        raise SwiftFacadeError("producer must be a successful Swift source build "
                               "(status %s)" % PRODUCER_STATUS)
    if producer.get("backend") != PRODUCER_BACKEND:
        raise SwiftFacadeError("producer.backend must be %s" % PRODUCER_BACKEND)
    if producer.get("language") != LANGUAGE:
        raise SwiftFacadeError("producer.language must be swift")
    project = producer.get("project")
    if not isinstance(project, dict) or project.get("language") != LANGUAGE:
        raise SwiftFacadeError("producer.project must be the swift project description")
    if not isinstance(producer.get("source_functions"), list) or not producer["source_functions"]:
        raise SwiftFacadeError("producer.source_functions must be the non-empty signature list")
    if not isinstance(producer.get("exported_functions"), list) or not producer["exported_functions"]:
        raise SwiftFacadeError("producer.exported_functions must be the non-empty export list")
    if not isinstance(producer.get("public_interface"), dict):
        raise SwiftFacadeError("producer.public_interface must be the pinned {path, sha256}")
    if not isinstance(producer.get("artifact_hashes"), dict):
        raise SwiftFacadeError("producer.artifact_hashes must pin the build outputs")
    if not isinstance(producer.get("contract_path"), str) or not producer["contract_path"]:
        raise SwiftFacadeError("producer.contract_path must point at the pinned contract.json")


def _authenticated_contract(producer) -> dict:
    """Read and authenticate the pinned ``frontend/contract.json``.

    The report carries no inline contract: the contract is derived from the
    on-disk file pinned by ``artifact_hashes['frontend/contract.json']`` and
    validated with the fixed ``bindings`` validator."""
    artifact_hashes = producer["artifact_hashes"]
    expected = artifact_hashes.get(CONTRACT_RELATIVE)
    if not isinstance(expected, str) or not SHA256_HEX.fullmatch(expected):
        raise SwiftFacadeError("producer.artifact_hashes['%s'] must pin a sha256 digest" % CONTRACT_RELATIVE)
    contract_path = producer["contract_path"]
    normalized = Path(os.path.normpath(contract_path))
    if normalized.parts[-2:] != ("frontend", "contract.json"):
        raise SwiftFacadeError("producer.contract_path must be the frontend/contract.json artifact")
    _path, data = _read_pinned(contract_path, expected, MAX_CONTRACT_BYTES, "producer contract.json")
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SwiftFacadeError("producer contract.json is not valid UTF-8 JSON: %s" % exc)
    return bindings.validate_contract(parsed)


def _facade_plan(producer) -> dict:
    """Validate the producer and derive the exact facade plan.  Pure: reads the
    pinned interface and contract, writes nothing."""
    _validate_producer(producer)

    exports = list(producer["exported_functions"])
    if not 1 <= len(exports) <= MAX_ROOTS:
        raise SwiftFacadeError("exported_functions must contain 1..%d entries" % MAX_ROOTS)
    if len(set(exports)) != len(exports):
        raise SwiftFacadeError("exported_functions must be unique")

    contract = _authenticated_contract(producer)
    contract_by_name = {f["name"]: f for f in contract["functions"]}
    if set(contract_by_name) != set(exports):
        raise SwiftFacadeError("authenticated contract functions disagree with exported_functions")

    # source_functions (producer's own interface parse) keyed by export, with the
    # Swift name retained.  Their ABI view must equal the authenticated contract.
    source_by_name = {}
    for sf in producer["source_functions"]:
        if not isinstance(sf, dict) or not {"name", "swift_name", "return_type", "parameters"} <= set(sf):
            raise SwiftFacadeError("each source_function needs name, swift_name, return_type, parameters")
        if sf["name"] in source_by_name:
            raise SwiftFacadeError("duplicate source_function export: " + str(sf["name"]))
        source_by_name[sf["name"]] = sf
    if set(source_by_name) != set(exports):
        raise SwiftFacadeError("source_functions disagree with exported_functions")

    # External labels come ONLY from the pinned, hash-authenticated interface.
    interface_path = producer["public_interface"].get("path")
    interface_sha = producer["public_interface"].get("sha256")
    _ip, raw = _read_pinned(interface_path, interface_sha, MAX_INTERFACE_BYTES, "public_interface")
    try:
        interface_text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SwiftFacadeError("public_interface is not valid UTF-8: %s" % exc)
    parsed_interface = _parse_interface_labels(interface_text, exports)

    roots, seen_swift = [], set()
    for export in exports:                      # preserve producer-selected order
        cfunc = contract_by_name[export]
        sfunc = source_by_name[export]
        iface = parsed_interface[export]
        if _signature_view(sfunc) != _signature_view(cfunc):
            raise SwiftFacadeError("source_function ABI disagrees with authenticated contract: " + export)
        if _signature_view(iface) != _signature_view(cfunc):
            raise SwiftFacadeError("compiler interface ABI disagrees with authenticated contract: " + export)
        if sfunc["swift_name"] != iface["swift_name"]:
            raise SwiftFacadeError("source_function swift_name disagrees with compiler interface: " + export)

        swift_name = iface["swift_name"]
        if not SAFE_IDENTIFIER.fullmatch(swift_name) or swift_name in RESERVED_SWIFT_NAMES:
            raise SwiftFacadeError("unsupported or reserved Swift root name: " + str(swift_name))
        if swift_name in seen_swift:
            raise SwiftFacadeError("duplicate Swift root name (overloads unsupported): " + swift_name)
        seen_swift.add(swift_name)

        if cfunc["return_type"] not in SCALAR_TYPES:
            raise SwiftFacadeError("root %s must return a scalar integer, not %s"
                                   % (export, cfunc["return_type"]))
        for p in cfunc["parameters"]:
            if p["type"] not in SCALAR_TYPES:
                raise SwiftFacadeError("root %s parameter %s must be a scalar integer"
                                       % (export, p["name"]))
        external_labels = [p["external_label"] for p in iface["parameters"]]
        for label in external_labels:
            if label != "_" and not SAFE_IDENTIFIER.fullmatch(label):
                raise SwiftFacadeError("unsupported external argument label in root " + export)
        roots.append({
            "source_name": swift_name, "export": export,
            "return_type": cfunc["return_type"],
            "parameters": [{"name": p["name"], "type": p["type"]} for p in cfunc["parameters"]],
            "external_labels": external_labels,
            "native_call": "call_" + export})
    return {"contract": contract, "roots": roots}


# --------------------------------------------------------------------------
# Source generation (reuses the fixed bindings generator; pinned NativeCore).
# --------------------------------------------------------------------------
def _decl_parameters(root) -> str:
    parts = []
    for p, label in zip(root["parameters"], root["external_labels"]):
        swift_type = SWIFT_TYPE[p["type"]]
        if label == "_":
            parts.append("_ %s: %s" % (p["name"], swift_type))
        elif label == p["name"]:
            parts.append("%s: %s" % (p["name"], swift_type))
        else:
            parts.append("%s %s: %s" % (label, p["name"], swift_type))
    return ", ".join(parts)


def _facade_function_source(root) -> str:
    args = ", ".join(p["name"] for p in root["parameters"])
    return ("public func %s(%s) -> %s {\n"
            "    return %s.core.%s(%s)\n"
            "}\n") % (root["source_name"], _decl_parameters(root),
                      SWIFT_TYPE[root["return_type"]], BOOTSTRAP_TYPE, root["native_call"], args)


def _facade_source(roots) -> str:
    lines = [
        "// Generated ANTI-REA Swift application facade. Same top-level function",
        "// names and external argument labels as the original owned core, but each",
        "// public root forwards to the packaged protected native core through the",
        "// generated NativeCore bridge. This file carries NO original algorithm,",
        "// helper bodies, constants or core source.",
        "import Foundation",
        "import %s" % BRIDGE_MODULE,
        "",
        "// Loads the pinned protected native core exactly once from the absolute",
        "// local-drive path in %s. Fail closed: if the variable is unset or empty," % ENV_CORE,
        "// or the core cannot be loaded, the process aborts. There is NO",
        "// original-algorithm fallback and NO ambient/default path search; the core",
        "// is initialized on first protected call and retained for process lifetime.",
        "//",
        "// Swift 6 (-language-mode 6) note: %s is a non-Sendable class produced by" % NATIVECORE_TYPE,
        "// the fixed bindings generator, so this global is marked nonisolated(unsafe).",
        "// The stored reference is immutable after one-time initialization.",
        "// This annotation suppresses the compiler's Sendable checking; it does",
        "// not prove concurrent NativeCore/VM calls safe. Concurrency is untested",
        "// and outside this application's qualification scope.",
        "enum %s {" % BOOTSTRAP_TYPE,
        "    nonisolated(unsafe) static let core: %s = {" % NATIVECORE_TYPE,
        "        guard let path = ProcessInfo.processInfo.environment[\"%s\"], !path.isEmpty else {" % ENV_CORE,
        "            fatalError(\"%s must be set to an absolute local-drive path to the protected native core\")" % ENV_CORE,
        "        }",
        "        do {",
        "            return try %s(libraryPath: path)" % NATIVECORE_TYPE,
        "        } catch {",
        "            fatalError(\"failed to load protected native core from %s: \\(error)\")" % ENV_CORE,
        "        }",
        "    }()",
        "}",
        "",
    ]
    lines.append("\n".join(_facade_function_source(r) for r in roots).rstrip("\n"))
    return "\n".join(lines) + "\n"


def _hash_text(text) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _guard_output_dir(output_dir) -> Path:
    directory = Path(os.path.abspath(output_dir))
    parts = [part.casefold() for part in directory.parts]
    if set(parts) & RESERVED_PARTS:
        raise SwiftFacadeError("facades are private build inputs, not transfer/intake artifacts")
    if any(parts[i:i + 2] == ["defense-loop", "inbox"] for i in range(len(parts) - 1)):
        raise SwiftFacadeError("facades cannot be written into the untrusted intake inbox")
    native_build._no_links(directory)
    if directory.exists():
        raise SwiftFacadeError("output_dir must be new; facades never overwrite existing files")
    return directory


def generate_facade(producer: dict, output_dir: Path) -> dict:
    """Generate same-name Swift facades + bootstrap, reusing the fixed bindings.

    Pure: all producer, interface and contract preflight runs *before* any file
    is created, and nothing is compiled, executed, downloaded or published.
    Returns the report that is also persisted verbatim as ``output_dir/facade.json``.
    """
    directory = _guard_output_dir(output_dir)

    # Preflight everything (reads pinned interface + contract, builds the plan).
    plan = _facade_plan(producer)
    facade_source = _facade_source(plan["roots"])

    # All preflight passed: materialize the private bindings bundle, then the
    # generated facade source.  generate_bindings creates ``directory`` (and the
    # private ``bindings`` subtree) and requires both not to pre-exist.
    bindings_dir = directory / "bindings"
    bindings_manifest = bindings.generate_bindings(plan["contract"], bindings_dir)

    facade_rel = "protected/NativeFacade.swift"
    facade_path = directory / facade_rel
    facade_path.parent.mkdir(parents=True, exist_ok=True)
    with facade_path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(facade_source)

    # Trusted compile inputs.  The Swift import needs the module-map directory;
    # the module map resolves the header relative to itself, so only that
    # directory is exposed.  The common C bridge implementation is the only C source.
    compile_sources = ["bindings/swift/NativeCore.swift", facade_rel]
    c_sources = ["bindings/common/antirea_bridge.c"]
    include_dirs = ["bindings/swift"]

    # ``files`` = every generated file except facade.json itself, pinned by
    # sha256 (ancillary binding sources inventoried but not in compile_sources).
    files = {}
    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(directory).as_posix()
        if rel == "facade.json":
            continue
        files[rel] = native_build._hash(path)

    for rel in (*compile_sources, *c_sources):
        if rel not in files:
            raise SwiftFacadeError("internal error: compile input missing from generated tree: " + rel)
    for rel in include_dirs:
        if not (directory / rel).is_dir():
            raise SwiftFacadeError("internal error: include dir missing from generated tree: " + rel)
    # Defensive: the private bundle must not have leaked any original core source.
    if bindings_manifest.get("original_language_source_protection") is not False:
        raise SwiftFacadeError("unexpected bindings manifest shape")

    report = {
        "schema_version": 1,
        "kind": KIND,
        "status": STATUS_GENERATED,
        "language": LANGUAGE,
        "files": files,
        "compile_sources": compile_sources,
        "c_sources": c_sources,
        "include_dirs": include_dirs,
        "source_roots": [
            {"source_name": r["source_name"], "export": r["export"],
             "return_type": r["return_type"], "parameters": r["parameters"],
             "external_labels": r["external_labels"]}
            for r in plan["roots"]],
        "loader_environment": ENV_CORE,
        "original_core_sources_included": False,
        "limitations": list(GENERATION_LIMITATIONS),
    }

    serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
    with (directory / "facade.json").open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(serialized)
    return report
