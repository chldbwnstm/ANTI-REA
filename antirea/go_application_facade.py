"""Pure Go application-facade generation for owned-core app integration.

This module never executes: it parses authenticated producer metadata, generates
Go *source* and reuses the fixed ``bindings`` generator.  It is not a Go compiler,
not a whole-language promise, and it preserves no original algorithm.  A protected
deployment substitutes same-name ``package main`` facade declarations that forward
each selected public root to the packaged protected native core, which is loaded
by the generated ``bindings`` Windows/amd64 ``syscall`` bridge from the absolute
local-drive path in ``ANTIREA_NATIVE_CORE``.  The ordinary application source is
preserved unchanged and keeps calling the same package-local identities.

Boundaries (see ``.runs/phase22-root/brief.md`` and AGENTS.md):
  * Only separated pure-scalar cores already accepted by ``go_frontend`` are
    supported (cdecl, fixed-width ``u32``/``i32``/``u64``/``i64`` only), plus an
    ordinary ``package main`` application that references nothing of the core
    except its selected public roots.  A missing helper/constant reference in the
    ordinary app fails compilation; there is never a silent fallback.
  * Generation reuses the fixed ``bindings.generate_bindings`` pure generator in a
    private subdirectory; only the trusted Go compile inputs are exposed in the
    manifest.  ``bindings.py`` is not edited here.  No user-controlled flags,
    import directories, module graph, cgo or build hooks are produced.
  * The original core source is read ONLY indirectly as hash-pinned producer
    metadata: a lexical reserved-path guard, a no-links resolve and exact SHA-256
    matches against ``producer['frontend_artifact_hashes']`` for every metadata
    file read.  No original body, helper or constant is ever emitted.  Missing or
    inconsistent evidence is rejected (``GoAppFacadeError``), never worked around.

``generate_facade`` is pure: it validates everything *before* writing anything,
requires a brand-new output directory, and returns exactly the report it also
persists as ``<output_dir>/facade.json``.  Generation is not compilation,
behavior or defense-strength qualification; those are separate, harnessed claims.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re

from . import bindings
from . import native_build


class GoAppFacadeError(ValueError):
    """Raised for malformed input or missing/inconsistent build evidence."""


ENV_CORE = "ANTIREA_NATIVE_CORE"

# Attacker-supplied / forbidden directory names that must never be read or
# written here (any case/path component), matching the engine-wide guard.
RESERVED_PARTS = {"rea-analysis-reports", "attackerfolder", "env.setting", "linkrepro"}

# The frontend's fixed-width integer subset and its exact ABI mapping.  bool and
# float are intentionally absent: the app ABI is scalar integers only.
ABI_TO_GO = {"i32": "int32", "u32": "uint32", "i64": "int64", "u64": "uint64"}
GO_TO_ABI = {go: abi for abi, go in ABI_TO_GO.items()}

MAX_METADATA_BYTES = 8 * 1024 * 1024
MAX_ROOTS = 64

# Ordinary Go identifier (ASCII), used for the preserved public root names.
GO_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
GO_KEYWORDS = frozenset(
    "break default func interface select case defer go map struct chan else goto "
    "package switch const fallthrough if range type continue for import return var".split()
)
# Package-level identifiers the generated runtime (repackaged bridge + loader)
# occupies in ``package main``; a preserved root may not collide with them.  Any
# ``antirea``-prefixed name is reserved for generated runtime glue as well.
RESERVED_RUNTIME_SYMBOLS = frozenset(
    {"NativeCore", "Load", "Close", "loadLibraryExW",
     "antireaNativeCore", "antireaNativeCoreEnv",
     "antireaCoreOnce", "antireaCoreInstance", "antireaCoreErr"}
)

STATUS_GENERATED = "generated_not_validated"

GENERATION_LIMITATIONS = [
    "Experimental: same-name package main facades for selected public scalar roots "
    "(u32/i32/u64/i64 only); no bool, float, strings, slices, maps, pointers or objects.",
    "Each facade forwards to the packaged protected native core; it is not the original "
    "algorithm and carries no original or helper body, constant or control flow.",
    "A missing helper/constant reference in the ordinary application fails compilation; "
    "there is no silent fallback and no original-core source enters the protected compile.",
    "The native core is loaded once, on the first protected call, by the generated bindings "
    "Windows/amd64 syscall bridge from the absolute local-drive path in ANTIREA_NATIVE_CORE; "
    "a missing/empty variable or any loader error fails closed (panic), with no ambient search.",
    "Generation does not compile, execute, download or publish; actual toolchain, load and "
    "behavior results belong to separate harnessed verification, not inferred from source.",
    "Windows x64, package main, no cgo and no modules, matching the pinned native builder.",
]

__all__ = ["GoAppFacadeError", "generate_facade", "ENV_CORE"]


def _self_hash() -> str:
    return native_build._hash(Path(__file__).resolve())


def _reserved(parts) -> bool:
    return bool({str(p).casefold() for p in parts} & RESERVED_PARTS)


# --------------------------------------------------------------------------
# Producer validation + hash-pinned authenticated metadata read
# --------------------------------------------------------------------------
def _require(condition, message):
    if not condition:
        raise GoAppFacadeError(message)


def _sha256_hex(value):
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))


def _validate_producer(producer):
    _require(isinstance(producer, dict), "producer must be the full go_frontend build report dict")
    _require(producer.get("schema_version") == 1, "producer.schema_version must be 1")
    _require(producer.get("status") == "artifact_created_unvalidated",
             "producer must be a successful Go source build (status artifact_created_unvalidated)")
    _require(producer.get("backend") == "go_typed_native", "producer.backend must be go_typed_native")
    _require(producer.get("language") == "go", "producer.language must be go")

    project = producer.get("project")
    _require(isinstance(project, dict), "producer.project must be the frontend inspection dict")
    selectors = project.get("selectors")
    _require(isinstance(selectors, list) and 1 <= len(selectors) <= MAX_ROOTS,
             "producer.project.selectors must be a 1..%d root list" % MAX_ROOTS)
    for sel in selectors:
        _require(isinstance(sel, dict) and {"name", "export"} <= set(sel),
                 "each selector needs name and export")
        _require(isinstance(sel["name"], str) and isinstance(sel["export"], str),
                 "selector name/export must be strings")

    methods = producer.get("methods")
    _require(isinstance(methods, list) and methods, "producer.methods must be the non-empty method report list")
    for m in methods:
        _require(isinstance(m, dict) and {"name", "export", "is_root", "parameters", "return_type"} <= set(m),
                 "each method report needs name, export, is_root, parameters, return_type")
        _require(m["is_root"] is True or m["is_root"] is False, "method report is_root must be a bool")
        _require(isinstance(m["parameters"], list), "method report parameters must be a list of type strings")

    _require(isinstance(producer.get("contract"), dict), "producer.contract must be the inline cdecl ABI contract")
    _require(isinstance(producer.get("contract_path"), str) and producer["contract_path"],
             "producer.contract_path must be a non-empty path string")
    hashes = producer.get("frontend_artifact_hashes")
    _require(isinstance(hashes, dict), "producer.frontend_artifact_hashes must map frontend paths to sha256")
    for key in ("metadata.json", "contract.json"):
        _require(_sha256_hex(hashes.get(key)),
                 "producer.frontend_artifact_hashes['%s'] must be a lowercase sha256 hex pin" % key)


def _read_pinned(frontend_dir, name, producer, *, raw_path):
    """Read one hash-pinned frontend artifact as bytes.

    Lexical reserved-path guard first, then a no-links resolve, then a single
    bounded read of a regular, non-hard-linked file whose SHA-256 must equal the
    pin recorded in ``producer['frontend_artifact_hashes']``."""
    pinned = producer["frontend_artifact_hashes"][name]
    raw = Path(raw_path)
    if _reserved(raw.parts):  # lexical guard precedes any filesystem access
        raise GoAppFacadeError("refusing to read reserved/untrusted path: " + str(raw_path))
    path = native_build._no_links(raw)
    if frontend_dir is not None and path != native_build._no_links(frontend_dir / name):
        raise GoAppFacadeError("%s must live beside the contract in the frontend directory" % name)
    info = path.lstat() if path.exists() else None
    if info is None or not path.is_file():
        raise GoAppFacadeError("missing or non-regular frontend artifact: " + str(raw_path))
    if getattr(info, "st_nlink", 1) not in (0, 1):
        raise GoAppFacadeError("frontend artifact must not be hard-linked: " + str(raw_path))
    with open(path, "rb") as stream:
        data = stream.read(MAX_METADATA_BYTES + 1)
    if len(data) > MAX_METADATA_BYTES:
        raise GoAppFacadeError("frontend artifact exceeds %d bytes: %s" % (MAX_METADATA_BYTES, raw_path))
    if hashlib.sha256(data).hexdigest() != pinned:
        raise GoAppFacadeError("frontend artifact hash mismatch: " + str(raw_path))
    return path, data


def _parse_json_bytes(data, what):
    try:
        value = json.loads(data.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise GoAppFacadeError("invalid UTF-8 JSON in %s: %s" % (what, exc))
    if not isinstance(value, dict):
        raise GoAppFacadeError("%s must be a JSON object" % what)
    return value


def _metadata_signatures(metadata):
    """Return ``{name: (tuple(go_param_types), go_return_type)}`` from pinned metadata."""
    _require(metadata.get("package") == "main",
             "metadata.package must be main; the application route rejects non-main packages")
    methods = metadata.get("methods")
    _require(isinstance(methods, list) and methods, "metadata.methods must be a non-empty list")
    signatures = {}
    for m in methods:
        _require(isinstance(m, dict) and "name" in m and "parameters" in m and "return_type" in m,
                 "each metadata method needs name, parameters and return_type")
        name = m["name"]
        _require(isinstance(name, str), "metadata method name must be a string")
        _require(name not in signatures, "duplicate metadata method: " + str(name))
        params = m["parameters"]
        _require(isinstance(params, list), "metadata method parameters must be a list")
        param_types = []
        for p in params:
            _require(isinstance(p, dict) and "type" in p, "metadata parameter needs a type")
            param_types.append(p["type"])
        _require(isinstance(m["return_type"], str), "metadata return_type must be a string")
        signatures[name] = (tuple(param_types), m["return_type"])
    return signatures


# --------------------------------------------------------------------------
# Facade plan: cross-validate selectors / methods / contract / metadata
# --------------------------------------------------------------------------
def _facade_plan(producer, frontend_dir, metadata):
    contract = bindings.validate_contract(producer["contract"])
    by_export = {f["name"]: f for f in contract["functions"]}
    signatures = _metadata_signatures(metadata)

    methods_by_name = {}
    for m in producer["methods"]:
        _require(m["name"] not in methods_by_name, "duplicate producer method: " + str(m["name"]))
        methods_by_name[m["name"]] = m

    selectors = producer["project"]["selectors"]
    selector_names, selector_exports = set(), set()
    roots = []
    for sel in selectors:
        name, export = sel["name"], sel["export"]
        _require(name not in selector_names, "duplicate root selector name: " + str(name))
        _require(export not in selector_exports, "duplicate root selector export: " + str(export))
        selector_names.add(name)
        selector_exports.add(export)

        # Preserved identifier: ordinary, non-keyword, not a reserved runtime symbol.
        _require(GO_IDENTIFIER.fullmatch(name) and name not in GO_KEYWORDS,
                 "root name is not an ordinary Go identifier: " + str(name))
        _require(name not in RESERVED_RUNTIME_SYMBOLS and not name.casefold().startswith("antirea"),
                 "root name collides with a reserved generated-runtime identifier: " + str(name))

        method = methods_by_name.get(name)
        _require(method is not None, "selector has no matching producer method: " + str(name))
        _require(method["is_root"] is True, "selector method is not reported as a root: " + str(name))
        _require(method["export"] == export, "selector/method export disagree for " + str(name))
        _require(export in by_export, "root export missing from contract: " + str(export))
        _require(name in signatures, "root absent from pinned metadata signatures: " + str(name))

        producer_params = tuple(method["parameters"])
        producer_ret = method["return_type"]
        meta_params, meta_ret = signatures[name]
        _require(producer_params == meta_params and producer_ret == meta_ret,
                 "producer and metadata signatures disagree for root " + str(name))
        for go_type in (*producer_params, producer_ret):
            _require(go_type in GO_TO_ABI, "unsupported scalar type %s for root %s" % (go_type, name))

        func = by_export[export]
        abi_params = [GO_TO_ABI[t] for t in producer_params]
        abi_ret = GO_TO_ABI[producer_ret]
        _require([p["type"] for p in func["parameters"]] == abi_params and func["return_type"] == abi_ret,
                 "contract ABI does not match the root signature for " + str(name))
        _require(func["return_type"] in ABI_TO_GO,
                 "root %s must return an explicit scalar (u32/i32/u64/i64), not void" % name)
        _require(len(func["parameters"]) == len(abi_params), "contract/parameter arity mismatch for " + str(name))

        roots.append({
            "source_name": name,
            "export": export,
            "return_type": abi_ret,
            "go_return_type": ABI_TO_GO[abi_ret],
            "parameters": [{"name": p["name"], "type": p["type"]} for p in func["parameters"]],
            "go_params": [{"name": p["name"], "type": ABI_TO_GO[p["type"]]} for p in func["parameters"]],
            "external_labels": [],
        })

    # The contract must be EXACTLY the selected roots: no extra exports, and no
    # unselected helper may leak an exported symbol into the deployed ABI.
    _require(set(by_export) == selector_exports,
             "contract exports must be exactly the selected roots: "
             + str(sorted(set(by_export) ^ selector_exports)))
    for m in producer["methods"]:
        if not m["is_root"]:
            _require(m["export"] not in by_export,
                     "unselected helper export must not appear in the deployed contract: " + str(m["export"]))
        else:
            _require(m["name"] in selector_names and m["export"] in selector_exports,
                     "is_root method is not a selected root: " + str(m["name"]))

    return {"contract": contract, "roots": roots, "language": "go"}


# --------------------------------------------------------------------------
# Source generation (reuses the fixed bindings generator; package main)
# --------------------------------------------------------------------------
BUILD_TAG = "//go:build windows && amd64"


def _repackage_bridge(text):
    """Return the generated Windows/amd64 bindings bridge, repackaged to main.

    Only the package clause of GENERATED source is renamed; nothing else is
    rewritten.  The original app/core source is never touched by this module."""
    repackaged, count = re.subn(r"(?m)^package nativecore$", "package main", text, count=1)
    if count != 1:
        raise GoAppFacadeError("generated bindings bridge did not expose a single package clause to repackage")
    if "package nativecore" in repackaged:
        raise GoAppFacadeError("generated bindings bridge retains a nativecore package clause after repackage")
    return repackaged


def _facade_source(roots):
    lines = [
        BUILD_TAG,
        "",
        "// Generated ANTI-REA Go application facade.",
        "//",
        "// Each function below keeps the SAME package-local identity as a selected public",
        "// root of the original owned core, but its body only loads the packaged protected",
        "// native core and forwards the call. No original algorithm, helper or constant is",
        "// present and there is no fallback to an original body.",
        "package main",
        "",
        "import (",
        '\t"fmt"',
        '\t"os"',
        '\t"sync"',
        ")",
        "",
        "// ANTIREA_NATIVE_CORE must hold the absolute local-drive path of the protected",
        "// native core DLL. It is read once, on the first protected call.",
        'const antireaNativeCoreEnv = "%s"' % ENV_CORE,
        "",
        "var (",
        "\tantireaCoreOnce     sync.Once",
        "\tantireaCoreInstance *NativeCore",
        "\tantireaCoreErr      error",
        ")",
        "",
        "// antireaNativeCore lazily initializes the protected native core exactly once and",
        "// retains it for the lifetime of the process. It fails closed: a missing or empty",
        "// ANTIREA_NATIVE_CORE, or any loader error, panics. There is no default path,",
        "// ambient search or original-algorithm fallback.",
        "func antireaNativeCore() *NativeCore {",
        "\tantireaCoreOnce.Do(func() {",
        "\t\tpath := os.Getenv(antireaNativeCoreEnv)",
        '\t\tif path == "" {',
        '\t\t\tantireaCoreErr = fmt.Errorf("%s must be set to an absolute local-drive path", antireaNativeCoreEnv)',
        "\t\t\treturn",
        "\t\t}",
        "\t\tantireaCoreInstance, antireaCoreErr = Load(path)",
        "\t})",
        "\tif antireaCoreErr != nil {",
        "\t\tpanic(antireaCoreErr)",
        "\t}",
        "\treturn antireaCoreInstance",
        "}",
    ]
    for root in roots:
        params = ", ".join("%s %s" % (p["name"], p["type"]) for p in root["go_params"])
        args = ", ".join(p["name"] for p in root["go_params"])
        lines += [
            "",
            "func %s(%s) %s {" % (root["source_name"], params, root["go_return_type"]),
            "\treturn antireaNativeCore().Call_%s(%s)" % (root["export"], args),
            "}",
        ]
    return "\n".join(lines) + "\n"


def _hash_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def generate_facade(producer: dict, output_dir: Path) -> dict:
    """Generate the Go application facade and reuse ``bindings`` for the native bridge.

    Pure: all producer and metadata preflight runs *before* any file is created,
    and nothing is compiled, executed, downloaded or published.  Returns the exact
    report that is also persisted as ``<output_dir>/facade.json``."""
    directory = Path(os.path.abspath(output_dir))
    # Lexical reserved/inbox guard FIRST, before any filesystem access.
    if _reserved(directory.parts):
        raise GoAppFacadeError("facades are private build inputs, not transfer/intake artifacts")
    low = [p.casefold() for p in directory.parts]
    if any(low[i:i + 2] == ["defense-loop", "inbox"] for i in range(len(low) - 1)):
        raise GoAppFacadeError("facades cannot be written into the untrusted intake inbox")
    native_build._no_links(directory)
    if directory.exists():
        raise GoAppFacadeError("output_dir must be new; facades never overwrite existing files")

    # Preflight everything first (no writes).
    _validate_producer(producer)
    frontend_dir = native_build._no_links(Path(producer["contract_path"]).parent)
    _contract_path, contract_bytes = _read_pinned(
        frontend_dir, "contract.json", producer, raw_path=producer["contract_path"])
    metadata_path = frontend_dir / "metadata.json"
    _metadata_path, metadata_bytes = _read_pinned(
        frontend_dir, "metadata.json", producer, raw_path=metadata_path)

    # The pinned on-disk contract must agree with the inline producer contract.
    on_disk_contract = bindings.validate_contract(_parse_json_bytes(contract_bytes, "contract.json"))
    inline_contract = bindings.validate_contract(producer["contract"])
    if on_disk_contract != inline_contract:
        raise GoAppFacadeError("inline producer contract disagrees with the pinned on-disk contract.json")

    metadata = _parse_json_bytes(metadata_bytes, "metadata.json")
    plan = _facade_plan(producer, frontend_dir, metadata)
    contract = plan["contract"]
    roots = plan["roots"]

    facade_source = _facade_source(roots)  # fails fast on any generation surprise

    # All preflight passed: write the private bindings bundle, then the two
    # compiled Go facade sources, then the manifest.
    bindings_dir = directory / "_bindings"
    bindings.generate_bindings(contract, bindings_dir)

    bridge_src = (bindings_dir / "go" / "native_core_windows_amd64.go").read_text(encoding="utf-8")
    bridge_main = _repackage_bridge(bridge_src)

    go_dir = directory / "go"
    go_dir.mkdir(parents=True, exist_ok=False)
    bridge_rel = "go/antirea_nativecore.go"
    facade_rel = "go/antirea_facade.go"
    for rel, content in ((bridge_rel, bridge_main), (facade_rel, facade_source)):
        with (directory / rel).open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(content)

    # Inventory every generated file (private bindings tree + compiled sources),
    # EXCEPT facade.json itself, as slash-relative paths -> sha256.
    files = {}
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            files[path.relative_to(directory).as_posix()] = native_build._hash(path)

    report = {
        "schema_version": 1,
        "kind": "native_application_facade",
        "status": STATUS_GENERATED,
        "language": "go",
        "files": files,
        "compile_sources": [bridge_rel, facade_rel],
        "c_sources": [],
        "include_dirs": [],
        "source_roots": [
            {"source_name": r["source_name"], "export": r["export"],
             "return_type": r["return_type"], "parameters": r["parameters"],
             "external_labels": r["external_labels"]}
            for r in roots
        ],
        "loader_environment": ENV_CORE,
        "original_core_sources_included": False,
        "limitations": list(GENERATION_LIMITATIONS),
    }

    serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
    with (directory / "facade.json").open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(serialized)
    return report
