"""Explicit sampled application validation of owned mixed JavaScript/TypeScript builds.

A mixed-module build (antirea.javascript_mixed_module) replaces only selected
pure Number/BigInt/boolean function bodies of ONE owned CommonJS module with a
custom-VM backend while preserving every surrounding import, statement and UI
byte-for-byte for a JavaScript module, or, for a TypeScript module, across a
whole-module CommonJS transpilation of it (a full module compile, not mere type
erasure). Requiring such a module therefore runs ordinary owned application startup. The scalar pure-source
JavaScript validator (javascript_validate) loads a single file with no package
context and must never be used to authorize that require. This module is that
separate, explicit authority: it stages the owned package tree into a fresh
private root, swaps in the owned original (baseline) or protected artifact, and
in a fresh separate clean-environment child Node process requires the module in
its preserved package context and compares the value/type/throw results of the
declared selected (and optionally preserved) scalar entrypoints.

Design, honestly bounded:
  * Separate processes, one per arm, via run_logged: timeouts, STOP cancellation,
    logs and best-effort process-tree cleanup. This is NOT an OS security sandbox;
    requiring an owned module runs ordinary application code with full Node API
    access. The child is launched with --no-addons and a strict allow-listed clean
    environment and private TEMP, and the trusted per-arm runner bounds the
    new-require surface to the staged tree plus Node builtins -- surface reduction,
    not isolation of the already-running process.
  * Numbers are compared by their exact IEEE-754 binary64 bit pattern, so NaN
    payloads, negative zero and the infinities are distinguished, never collapsed.
    BigInts are compared as exact decimal; booleans/null/undefined by tag; a thrown
    result by its bounded type tag only (never message or stack). Any other return
    type fails the arm rather than being coerced.
  * Validation binds the trusted source-plan snapshot, build report, coverage,
    pinned toolchain and the new per-arm runner, and both arms' whole staged
    package inventories, and re-checks every binding after execution; any pre- or
    post-run drift fails closed.
  * JavaScript uses the exact original module. TypeScript requires a separate
    pinned compiler reference and explicit TS contract, and stages its emitted
    CommonJS entry in place of the original TS entry. General TS graphs and
    type checking are separate, unfinished requirements.

Sampling is not all-input or full-semantic equivalence, is not a performance
threshold, and is NOT evidence of external attack resistance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import re
import stat
import struct
import sys

from .process import run_logged
from . import javascript_frontend as jf

_no_links = jf._no_links
_pairs = jf._pairs


BACKEND = "javascript_mixed_module_vm"
MODE = "mixed_module"
CONTRACT_KIND = "javascript_mixed_module_application_samples"
SUPPORTED_LANGUAGE = "javascript"
SUPPORTED_SUFFIXES = (".js", ".cjs")
CONTRACT_KINDS = {"javascript": CONTRACT_KIND,
                  "typescript": "typescript_mixed_module_application_samples"}
LANGUAGE_SUFFIXES = {"javascript": SUPPORTED_SUFFIXES, "typescript": (".ts",)}

MAX_ENTRYPOINTS = 32
MAX_PARAMETERS = 16
MAX_NAME_CHARS = 128
MAX_SOURCE_CHARS = 512
MAX_NUMBER_MAGNITUDE = 2 ** 53 - 1      # exact-integer doubles only, as sample bounds
MAX_BIGINT_BITS = 256
MAX_RANDOM_CASES = 8192
MAX_TOTAL_CASES = 200000                # per-function, matched to the runner budget
MAX_PACKAGE_FILES = 1024
MAX_PACKAGE_ENTRIES = 4096
MAX_PACKAGE_DEPTH = 24
MAX_PACKAGE_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_HASH_BYTES = 512 * 1024 * 1024
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_CONTRACT_BYTES = 256 * 1024
MAX_REPLY_BYTES = 256 * 1024 * 1024

_NUMBER_SPECIAL_BITS = {
    "pos_zero": struct.pack(">d", 0.0).hex(),
    "neg_zero": struct.pack(">d", -0.0).hex(),
    "pos_inf": struct.pack(">d", float("inf")).hex(),
    "neg_inf": struct.pack(">d", float("-inf")).hex(),
    "nan": struct.pack(">d", float("nan")).hex(),
}

LIMITATIONS = [
    "Requiring an owned mixed module runs arbitrary ordinary application startup in child Node processes; --no-addons, an allow-listed clean environment and a staged-tree require bound reduce surface but this is NOT an OS security sandbox.",
    "Only the declared scalar Number/BigInt/boolean entrypoint value/type/throw results are compared; stdout, side effects, strings, objects, thrown messages/stacks and any non-scalar return are not (a non-scalar return fails the arm).",
    "Numbers are compared by exact IEEE-754 binary64 bits (NaN payloads, negative zero and infinities distinguished); BigInt by exact decimal; a throw by its bounded constructor-name/typeof tag only.",
    "Package staging copies owned source bytes into a fresh private tree and swaps the one module file; it is not a hermetic build/runtime environment and pins neither the Node runtime, standard library nor operating-system state beyond the recorded toolchain hashes.",
    "Sampled random/edge vectors are not all-input or full-semantic equivalence, performance acceptance, or external attack resistance.",
    "Module-origin binding checks the required file path, SHA-256 before and after, and that no require escaped the staged tree; it does not independently prove the protected bodies dispatch the VM rather than equivalent ordinary code.",
    "Integrity and the complete overlaid staged-tree inventory are re-verified against the trusted source/artifact map before launch (including after the prelaunch seam) and after each child; these are before/after snapshots and do not prove the absence of a transient swap-and-restore performed entirely within a single child's execution.",
    "Timing includes Node call/observation overhead and excludes require/startup; no performance threshold is inferred or enforced.",
    "Only fixed-arity ordinary exported functions are sampled; async/generator functions, classes and arity mismatches are refused, not sampled.",
    "JavaScript's reference is the exact BOM-normalized original. TypeScript uses an independently emitted pinned-compiler reference and a .cjs runtime entry replacing the .ts source entry; other TS runtime source files, runtime-name collisions, arbitrary TS graphs, tsconfig resolution and full type checking remain unsupported.",
    "Dependency node_modules are neither installed nor resolved; a module requiring an uninstalled or out-of-tree dependency fails closed. The owned staged tree is bounded by file, entry, depth and byte budgets -- input-size containment, not an OS sandbox.",
    "baseline.cjs, reports, staged trees, source snapshots and evidence are defender-private and must not be delivered to attackers.",
    "Build success and a sampled-pass do not establish functional equivalence, performance acceptance or attack resistance; external_attack_evaluation is not_evaluated.",
]

# Resolve the trusted per-arm runner relative to this module so the command does
# not depend on the current working directory. In the candidate layout this is
# candidate/tools/javascript_frontend/mixed_run_arm.cjs; copied to production it
# resolves to tools/javascript_frontend/mixed_run_arm.cjs beside the package.
_RUNNER = Path(__file__).resolve().parents[1] / "tools" / "javascript_frontend" / "mixed_run_arm.cjs"


class MixedValidateError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Small local IO helpers (stdlib + link/dup rejection; no cross-module policy)
# ---------------------------------------------------------------------------

def _hash(path):
    path = _no_links(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_HASH_BYTES:
        raise MixedValidateError("hash input must be a bounded regular file")
    value = hashlib.sha256()
    remaining = before.st_size
    with path.open("rb") as stream:
        while remaining:
            block = stream.read(min(remaining, 1024 * 1024))
            if not block:
                raise MixedValidateError("hash input shrank during read")
            remaining -= len(block)
            value.update(block)
        if stream.read(1):
            raise MixedValidateError("hash input grew during read")
    after = _no_links(path).stat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    if identity(before) != identity(after):
        raise MixedValidateError("hash input changed during read")
    return value.hexdigest()


def _read(path, cap):
    path = _no_links(path)
    size = path.stat().st_size
    if size > cap:
        raise MixedValidateError("input exceeds the byte budget: " + str(path))
    with path.open("rb") as stream:
        data = stream.read(size + 1)
    if len(data) != size or path.stat().st_size != size:
        raise MixedValidateError("input changed during read: " + str(path))
    return data


def _json(data):
    try:
        return json.loads(data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else data,
                          object_pairs_hook=_pairs)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise MixedValidateError("invalid JSON input: " + type(exc).__name__) from exc


def _save(path, obj):
    Path(path).write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")


def _hex64(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _js_identifier(value):
    return (isinstance(value, str) and 0 < len(value) <= MAX_NAME_CHARS and value.isascii()
            and re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", value) is not None
            and not value.startswith(("_ar_", "_arm_")))


# ---------------------------------------------------------------------------
# Contract
# ---------------------------------------------------------------------------

def _parameter(parameter, seen, label):
    if not isinstance(parameter, dict) or "name" not in parameter or "type" not in parameter:
        raise MixedValidateError(label + " parameters require at least name and type")
    name, kind = parameter["name"], parameter["type"]
    if not _js_identifier(name) or name in seen:
        raise MixedValidateError(label + " parameter name must be a unique ordinary identifier")
    seen.add(name)
    if kind == "boolean":
        if set(parameter) != {"name", "type"}:
            raise MixedValidateError("boolean parameter takes name and type only")
        return {"name": name, "type": "boolean"}
    if kind in ("number", "bigint"):
        if set(parameter) != {"name", "type", "minimum", "maximum"}:
            raise MixedValidateError(kind + " parameter requires name, type, minimum and maximum only")
        lo, hi = parameter["minimum"], parameter["maximum"]
        if type(lo) is not int or type(hi) is not int or lo > hi:
            raise MixedValidateError(kind + " parameter bounds must be integers with minimum <= maximum")
        if kind == "number" and (abs(lo) > MAX_NUMBER_MAGNITUDE or abs(hi) > MAX_NUMBER_MAGNITUDE):
            raise MixedValidateError("number sample bounds must be exact-integer doubles (|value| <= 2**53-1)")
        if kind == "bigint" and max(abs(lo).bit_length(), abs(hi).bit_length()) > MAX_BIGINT_BITS:
            raise MixedValidateError("bigint sample bounds exceed 256 bits")
        return {"name": name, "type": kind, "minimum": lo, "maximum": hi}
    raise MixedValidateError("parameter type must be number, bigint or boolean")


def _entrypoint_contracts(value, label):
    if not isinstance(value, list) or len(value) > MAX_ENTRYPOINTS:
        raise MixedValidateError(label + " must be a list of at most 32 entrypoint contracts")
    names, functions = set(), []
    for function in value:
        if not isinstance(function, dict) or set(function) != {"name", "parameters"}:
            raise MixedValidateError(label + " contracts require name and parameters only")
        name = function["name"]
        if not _js_identifier(name):
            raise MixedValidateError(label + " name must be an ordinary non-reserved identifier")
        if name in names:
            raise MixedValidateError("entrypoint names must be unique across selected and preserved entrypoints")
        names.add(name)
        parameters = function["parameters"]
        if not isinstance(parameters, list) or len(parameters) > MAX_PARAMETERS:
            raise MixedValidateError(label + " parameters must contain at most 16 scalar ranges")
        seen, resolved = set(), []
        for parameter in parameters:
            resolved.append(_parameter(parameter, seen, label))
        functions.append({"name": name, "parameters": resolved})
    return names, functions


def validate_application_contract(contract):
    """Validate the explicit, versioned, opt-in mixed-module application contract.

    This is a bounded, structured selected-entrypoint sampling contract; it never
    carries a shell command, a test command, a module path to import by name, or
    any arbitrary entry point. It binds to ONE owned source module (``source``).
    """
    if not isinstance(contract, dict) or set(contract) != {
            "schema_version", "kind", "source", "entrypoints", "preserved_entrypoints"}:
        raise MixedValidateError("mixed application contract requires schema_version, kind, source, "
                                 "entrypoints and preserved_entrypoints only")
    if type(contract["schema_version"]) is not int or contract["schema_version"] != 1:
        raise MixedValidateError("mixed application contract schema_version must be 1")
    language = next((name for name, kind in CONTRACT_KINDS.items() if kind == contract["kind"]), None)
    if language is None:
        raise MixedValidateError("mixed application validation requires a documented JavaScript or TypeScript contract kind")
    source = contract["source"]
    if (not isinstance(source, str) or not 0 < len(source) <= MAX_SOURCE_CHARS or "\x00" in source
            or source.startswith("/") or ".." in source.replace("\\", "/").split("/") or ":" in source):
        raise MixedValidateError("source must be a relative POSIX module path inside the project")
    if not source.lower().endswith(LANGUAGE_SUFFIXES[language]):
        raise MixedValidateError("contract kind and source language must match: " + language)
    selected_names, selected = _entrypoint_contracts(contract["entrypoints"], "entrypoints")
    if not selected:
        raise MixedValidateError("at least one selected entrypoint must be sampled")
    preserved_names, preserved = _entrypoint_contracts(contract["preserved_entrypoints"], "preserved_entrypoints")
    if selected_names & preserved_names:
        raise MixedValidateError("an entrypoint cannot be both selected and preserved")
    if len(selected) + len(preserved) > MAX_ENTRYPOINTS:
        raise MixedValidateError("total sampled entrypoints exceed the supported limit")
    return {"schema_version": 1, "kind": CONTRACT_KINDS[language], "source": source.replace("\\", "/"),
            "entrypoints": selected, "preserved_entrypoints": preserved}


# ---------------------------------------------------------------------------
# Case generation (typed, deterministic, JSON-serializable wire vectors)
# ---------------------------------------------------------------------------

def _number_arg(integer):
    return {"t": "number", "bits": struct.pack(">d", float(integer)).hex()}


def _arg_key(arg):
    return (arg["t"], arg.get("bits"), arg.get("v"))


def _param_random(rng, parameter):
    kind = parameter["type"]
    if kind == "number":
        return _number_arg(rng.randint(parameter["minimum"], parameter["maximum"]))
    if kind == "bigint":
        return {"t": "bigint", "v": str(rng.randint(parameter["minimum"], parameter["maximum"]))}
    return {"t": "boolean", "v": bool(rng.getrandbits(1))}


def _param_middle(parameter):
    kind = parameter["type"]
    if kind == "boolean":
        return {"t": "boolean", "v": False}
    centre = max(parameter["minimum"], min(0, parameter["maximum"]))
    return _number_arg(centre) if kind == "number" else {"t": "bigint", "v": str(centre)}


def _param_edges(parameter):
    kind = parameter["type"]
    if kind == "boolean":
        return [{"t": "boolean", "v": False}, {"t": "boolean", "v": True}]
    lo, hi = parameter["minimum"], parameter["maximum"]
    values, edges = [], []
    for value in (lo, lo + 1, -1, 0, 1, hi - 1, hi):
        if lo <= value <= hi and value not in values:
            values.append(value)
    for value in values:
        edges.append(_number_arg(value) if kind == "number" else {"t": "bigint", "v": str(value)})
    if kind == "number":
        for bits in _NUMBER_SPECIAL_BITS.values():
            edges.append({"t": "number", "bits": bits})
    return edges


def _function_cases(rng, parameters, random_cases):
    middle = [_param_middle(parameter) for parameter in parameters]
    seen, vectors = set(), []

    def add(vector):
        key = tuple(_arg_key(arg) for arg in vector)
        if key not in seen:
            seen.add(key)
            vectors.append(vector)

    for _ in range(random_cases):
        add([_param_random(rng, parameter) for parameter in parameters])
    add(list(middle))
    add([_param_edges(parameter)[0] for parameter in parameters] if parameters else [])
    add([_param_edges(parameter)[-1] for parameter in parameters] if parameters else [])
    for index, parameter in enumerate(parameters):
        for edge in _param_edges(parameter):
            vector = list(middle)
            vector[index] = edge
            add(vector)
    if not vectors:
        add([])
    if len(vectors) > MAX_TOTAL_CASES:
        raise MixedValidateError("sample count exceeds the per-function budget; lower random_cases")
    return vectors


def make_cases(contract, random_cases=8192, seed=20261020):
    contract = validate_application_contract(contract)
    if type(random_cases) is not int or not 1 <= random_cases <= MAX_RANDOM_CASES:
        raise MixedValidateError("random_cases must be an integer in 1..8192")
    if type(seed) is not int or not 0 <= seed <= 0x7FFFFFFF:
        raise MixedValidateError("seed must be a nonnegative 31-bit integer")
    rng = random.Random(seed)
    cases = {}
    for function in list(contract["entrypoints"]) + list(contract["preserved_entrypoints"]):
        cases[function["name"]] = _function_cases(rng, function["parameters"], random_cases)
    return cases


# ---------------------------------------------------------------------------
# Coverage + module binding
# ---------------------------------------------------------------------------

def _names(value, label, *, empty=False, maximum=128):
    if (not isinstance(value, list) or not (0 if empty else 1) <= len(value) <= maximum
            or any(not _js_identifier(name) for name in value) or len(set(value)) != len(value)):
        raise MixedValidateError("mixed coverage " + label + " must contain unique ordinary names")
    return set(value)


def _verify_mixed_coverage(coverage, selected_entrypoints, preserved_entrypoints):
    """Structurally verify the builder's hash-pinned mixed coverage before execution.

    Confirms internal consistency of the build evidence; it is not independent
    proof that the protected bodies execute a VM. Fields missing from the current
    mixed schema are rejected rather than inferred.
    """
    if (not isinstance(coverage, dict) or type(coverage.get("schema_version")) is not int
            or coverage["schema_version"] != 1 or coverage.get("backend") != BACKEND
            or coverage.get("protection_mode") != MODE):
        raise MixedValidateError("mixed coverage requires schema_version 1 and the mixed-module backend/mode")
    if not _hex64(coverage.get("original_module_source_sha256")):
        raise MixedValidateError("mixed coverage must bind the original module source SHA-256")
    if not _hex64(coverage.get("working_source_sha256")):
        raise MixedValidateError("mixed coverage must bind the working (built) source SHA-256")
    if type(coverage.get("transpiled_typescript")) is not bool:
        raise MixedValidateError("mixed coverage must declare transpiled_typescript as a boolean")
    roots = _names(coverage.get("selected_functions"), "selected_functions", maximum=64)
    exported = _names(coverage.get("exported_functions"), "exported_functions")
    closure = _names(coverage.get("helper_closure"), "helper_closure")
    if not roots <= exported or exported != closure:
        raise MixedValidateError("mixed coverage selected roots must be within the exported helper closure")
    preserved_declared = _names(coverage.get("preserved_unprotected_functions"),
                                "preserved_unprotected_functions", empty=True, maximum=256)
    if preserved_declared & closure:
        raise MixedValidateError("preserved unprotected functions cannot overlap virtualized functions")
    functions = coverage.get("functions")
    if not isinstance(functions, dict) or set(functions) != closure:
        raise MixedValidateError("mixed coverage.functions must exactly match the helper closure")
    for name, evidence in functions.items():
        if not isinstance(evidence, dict) or evidence.get("virtualized") is not True:
            raise MixedValidateError("every exported mixed function must carry virtualized VM coverage")
    if not selected_entrypoints <= roots:
        raise MixedValidateError("every selected entrypoint must be a selected virtualized root in coverage")
    if not preserved_entrypoints <= preserved_declared:
        raise MixedValidateError("every preserved entrypoint must be a preserved unprotected function in coverage")
    return functions


def _derive_module(report):
    """Derive the original source identity without conflating TS and emitted JS."""
    project = report.get("project")
    if not isinstance(project, dict):
        raise MixedValidateError("mixed build report must carry its inspected project")
    root = project.get("project_root")
    sources = project.get("sources")
    language = project.get("language")
    if not isinstance(root, str) or not isinstance(sources, list) or len(sources) != 1 or not isinstance(sources[0], str):
        raise MixedValidateError("mixed project must declare exactly one source under a project root")
    if not isinstance(language, str) or language not in LANGUAGE_SUFFIXES:
        raise MixedValidateError("actual execution validation supports language=javascript or typescript only")
    package_root = Path(os.path.abspath(root))
    source = Path(os.path.abspath(sources[0]))
    if not source.is_relative_to(package_root):
        raise MixedValidateError("mixed source must stay inside its project root")
    relative = source.relative_to(package_root)
    if relative.suffix.lower() not in LANGUAGE_SUFFIXES[language]:
        raise MixedValidateError("mixed source suffix must match its declared language")
    return package_root, relative.as_posix()


# ---------------------------------------------------------------------------
# Staging + source-plan drift binding
# ---------------------------------------------------------------------------

def _staging_guard(path, root):
    path = Path(os.path.abspath(path))
    _no_links(path)
    if not path.is_relative_to(root):
        raise MixedValidateError("staged package tree must stay inside the workspace")
    parts = {part.casefold() for part in path.relative_to(root).parts}
    if parts & {"rea-analysis-reports", "attackerfolder", "defense-loop"}:
        raise MixedValidateError("received/shared trees cannot be staged or executed")
    return path


def _walk_tree(package_root):
    """Yield (relative_posix, data) for eligible owned files under bounded budgets."""
    files, total, entries = 0, 0, 0
    pending = [(package_root, 0)]
    while pending:
        directory, depth = pending.pop()
        for entry in sorted(directory.iterdir()):
            entries += 1
            if entries > MAX_PACKAGE_ENTRIES:
                raise MixedValidateError("package tree exceeds the directory entry budget")
            if entry.name.casefold() in {"env.setting", "linkrepro", "rea-analysis-reports", "attackerfolder"}:
                raise MixedValidateError("reserved private/received input cannot be staged: " + entry.name)
            _no_links(entry)
            relative = entry.relative_to(package_root)
            if entry.is_dir():
                if depth + 1 > MAX_PACKAGE_DEPTH:
                    raise MixedValidateError("package tree exceeds the directory depth budget")
                pending.append((entry, depth + 1))
                continue
            if not entry.is_file():
                raise MixedValidateError("package tree contains a non-regular input: " + str(relative))
            files += 1
            if files > MAX_PACKAGE_FILES:
                raise MixedValidateError("package tree exceeds the staged file budget")
            # Stat and reject an oversize file BEFORE allocating it, so an outsized
            # input is refused on its size, never read into memory first. The read
            # is then bounded by that checked size, with a post-read consistency
            # check that the file did not grow or shrink under us.
            size = entry.stat().st_size
            if size > MAX_FILE_BYTES:
                raise MixedValidateError("package file exceeds the per-file byte budget: " + str(relative))
            if total + size > MAX_PACKAGE_BYTES:
                raise MixedValidateError("package tree exceeds the staged byte budget")
            # Bounded read: read at most size+1 bytes so a file that grew after the
            # stat cannot be slurped unbounded. The post-read consistency check then
            # rejects any grow (len > size) or shrink (len < size, or re-stat drift).
            with entry.open("rb") as stream:
                data = stream.read(size + 1)
            if len(data) != size or entry.stat().st_size != size:
                raise MixedValidateError("package file changed during read: " + str(relative))
            total += len(data)
            yield relative.as_posix(), data


def _snapshot_tree(package_root):
    return sorted(({"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
                   for relative, data in _walk_tree(package_root)), key=lambda item: item["path"])


def _snapshot_as_map(snapshot):
    return {item["path"]: {"sha256": item["sha256"], "bytes": item["bytes"]} for item in snapshot}


def snapshot_source_tree(package_root):
    """Public helper: produce the trusted source-plan snapshot for a package root.

    In production the service supplies expected_snapshot from the verified build
    plan; this exposes the identical shape for tests and standalone callers.
    """
    return _snapshot_tree(_no_links(package_root))


def _expected_source_files(expected_snapshot, package_root):
    if not isinstance(expected_snapshot, list) or not expected_snapshot:
        raise MixedValidateError("a non-empty source-plan snapshot is required to bind validation")
    expected = {}
    for item in expected_snapshot:
        if (not isinstance(item, dict) or not isinstance(item.get("path"), str)
                or not _hex64(item.get("sha256")) or type(item.get("bytes")) is not int
                or item["bytes"] < 0):
            raise MixedValidateError("source-plan snapshot entries must carry path, sha256 and bytes")
        candidate = Path(os.path.abspath(os.path.join(str(package_root), item["path"])))
        if not candidate.is_relative_to(package_root):
            continue
        relative = candidate.relative_to(package_root).as_posix()
        if relative in expected:
            raise MixedValidateError("source-plan snapshot contains a duplicate package input")
        expected[relative] = {"sha256": item["sha256"], "bytes": item["bytes"]}
    if not expected:
        raise MixedValidateError("source-plan snapshot does not cover the applicable package tree")
    return expected


def _verify_against_plan(package_root, expected_snapshot):
    expected = _expected_source_files(expected_snapshot, package_root)
    current = _snapshot_as_map(_snapshot_tree(package_root))
    if current != expected:
        added = sorted(set(current) - set(expected))
        removed = sorted(set(expected) - set(current))
        changed = sorted(name for name in set(current) & set(expected) if current[name] != expected[name])
        raise MixedValidateError("owned package tree changed since the bound source plan "
                                 + json.dumps({"added": added, "removed": removed, "changed": changed},
                                              sort_keys=True, separators=(",", ":")))
    return expected


def _prestage_drift_hook():
    """Deterministic test seam: invoked once after the plan preflight and before any
    staging. Production is a no-op; a test may patch it to mutate the owned tree and
    prove the per-arm pre-launch snapshot check catches a change that lands between
    the plan preflight and staging, before any child starts."""
    return None


def _stage_arm(package_root, module_relative, artifact_path, stage_root, workspace_root,
               *, expected_artifact_sha256=None, runtime_module_relative=None):
    """Copy the owned package tree into a fresh private root, then swap the module.

    The artifact bytes are hashed as they are read and, when an expected SHA-256 is
    supplied, verified against it immediately before they are written into the
    stage, so an artifact that drifted since the reviewed build fails closed here
    rather than being staged and launched."""
    package_root = Path(os.path.abspath(package_root))
    stage_root = Path(os.path.abspath(stage_root))
    _staging_guard(stage_root, workspace_root)
    if (stage_root == package_root or stage_root.is_relative_to(package_root)
            or package_root.is_relative_to(stage_root)):
        raise MixedValidateError("staging root must not overlap the owned package tree")
    if stage_root.exists():
        raise MixedValidateError("staging root must be fresh")
    stage_root.mkdir(parents=True)
    snapshot = []
    runtime_relative = runtime_module_relative or module_relative
    found_module = False
    for relative, data in _walk_tree(package_root):
        snapshot.append({"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
        if relative == module_relative:
            found_module = True
            if runtime_relative != module_relative:
                continue  # TS entry is replaced, not left available as a fallback.
        if runtime_relative != module_relative and relative.casefold() == runtime_relative.casefold():
            raise MixedValidateError("TypeScript runtime entry collides with an owned package file")
        destination = _staging_guard(stage_root / relative, workspace_root)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(data)
    snapshot.sort(key=lambda item: item["path"])
    target = _staging_guard(stage_root / runtime_relative, workspace_root)
    if not found_module or (runtime_relative == module_relative and not target.is_file()):
        raise MixedValidateError("target module was not present in the staged package tree")
    target.parent.mkdir(parents=True, exist_ok=True)
    artifact_bytes = _read(Path(artifact_path), MAX_FILE_BYTES)
    artifact_sha = hashlib.sha256(artifact_bytes).hexdigest()
    if expected_artifact_sha256 is not None and artifact_sha != expected_artifact_sha256:
        raise MixedValidateError("artifact bytes changed since the reviewed build before staging")
    with target.open("wb") as stream:
        stream.write(artifact_bytes)
    return {"stage_root": str(stage_root), "target": str(target),
            "target_sha256": artifact_sha,
            "files": len(snapshot), "bytes": sum(item["bytes"] for item in snapshot),
            "snapshot": snapshot}


# ---------------------------------------------------------------------------
# Child environment + command
# ---------------------------------------------------------------------------

def _child_env(private_temp):
    private_temp.mkdir(parents=True, exist_ok=False)
    allow = ("SystemRoot", "SystemDrive", "windir", "NUMBER_OF_PROCESSORS",
             "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "COMSPEC", "PATHEXT",
             "LANG", "LC_ALL", "LC_CTYPE", "TZ")
    env = {key: os.environ[key] for key in allow if key in os.environ}
    if os.name == "nt":
        system_root = env.get("SystemRoot") or env.get("windir") or "C:\\Windows"
        env["PATH"] = os.pathsep.join([str(Path(system_root) / "System32"), str(Path(system_root))])
    else:
        env["PATH"] = "/usr/bin:/bin"
    env["TEMP"] = env["TMP"] = env["TMPDIR"] = str(private_temp)
    return env


def _arm_command(node_path, request_path):
    runner = _no_links(_RUNNER)
    if not runner.is_file():
        raise MixedValidateError("trusted per-arm runner is missing: " + str(runner))
    return [str(node_path), "--no-addons", "--max-old-space-size=256", str(runner), str(request_path)]


def _runner_evidence():
    runner = _no_links(_RUNNER)
    if not runner.is_file():
        raise MixedValidateError("trusted per-arm runner is missing: " + str(runner))
    return {"path": str(runner), "sha256": _hash(runner), "bytes": runner.stat().st_size}


def _verify_toolchain(report):
    """Re-hash the pinned build toolchain and bind it; any drift fails closed."""
    toolchain = report.get("toolchain")
    if not isinstance(toolchain, dict) or not isinstance(toolchain.get("files"), dict):
        raise MixedValidateError("mixed build report must carry its pinned toolchain")
    files, drift, pins = toolchain["files"], [], {}
    for name, item in files.items():
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not _hex64(item.get("sha256")):
            raise MixedValidateError("toolchain entry " + str(name) + " is malformed")
        path = Path(item["path"])
        try:
            current = _hash(_no_links(path)) if path.is_file() else None
        except (OSError, ValueError):
            current = None
        pins[name] = {"path": item["path"], "reported_sha256": item["sha256"], "current_sha256": current}
        if current != item["sha256"]:
            drift.append(name)
    node = files.get("node")
    if not isinstance(node, dict) or not isinstance(node.get("path"), str):
        raise MixedValidateError("toolchain must pin the node executable")
    return node["path"], pins, drift


# ---------------------------------------------------------------------------
# Integrity re-binding + staged-tree overlay inventories
# ---------------------------------------------------------------------------

def _expected_integrity(result, artifacts, runner, toolchain_files):
    """The pinned-input integrity baseline re-checked before and after EACH child
    and at final completion: the build report, contract, every build artifact, the
    trusted per-arm runner and every pinned build tool (Node included). A success
    may never rest on an integrity flag taken only once at the start."""
    expected = {"report": result["build_report_sha256"], "contract": result["contract_sha256"],
                "runner": runner["sha256"]}
    for arm_name, art in artifacts.items():
        expected["artifact:" + arm_name] = art["sha256"]
    for name, item in toolchain_files.items():
        expected["tool:" + name] = item["sha256"]
    return expected


def _current_integrity(report_path, contract_path, artifacts, toolchain_files):
    current = {"report": _hash(report_path), "contract": _hash(contract_path),
               "runner": _hash(_no_links(_RUNNER))}
    for arm_name, art in artifacts.items():
        current["artifact:" + arm_name] = _hash(_no_links(Path(art["path"])))
    for name, item in toolchain_files.items():
        tool = Path(item["path"])
        try:
            current["tool:" + name] = _hash(_no_links(tool)) if tool.is_file() else None
        except (OSError, ValueError):
            current["tool:" + name] = None
    return current


def _integrity_drift(expected, current):
    return sorted(key for key in expected if current.get(key) != expected[key])


def _inventory_diff(before, after):
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    changed = sorted(name for name in set(before) & set(after) if before[name] != after[name])
    return added, removed, changed


def _expected_overlay(expected_source, module_relative, artifact, runtime_module_relative=None):
    """The TRUSTED complete overlaid staged-tree inventory an arm must present: the
    trusted source-plan map with the one target module replaced by the arm artifact's
    reviewed hash/size. The staged tree is compared to THIS, never to whatever bytes
    happened to be on disk after copying, so a sibling already corrupted during or
    after the copy cannot silently become the accepted baseline."""
    overlay = {path: dict(entry) for path, entry in expected_source.items()}
    runtime_relative = runtime_module_relative or module_relative
    if runtime_relative != module_relative:
        if any(name.casefold() == runtime_relative.casefold() for name in overlay):
            raise MixedValidateError("TypeScript runtime entry collides with an owned package file")
        del overlay[module_relative]
    overlay[runtime_relative] = {"sha256": artifact["sha256"], "bytes": artifact["bytes"]}
    return overlay


def _assert_overlay_matches(actual, expected, phase):
    """Compare a COMPLETE overlaid staged-tree inventory (every staged file, not only
    the swapped target) to the trusted expected map, failing closed on an extra
    (injected), missing OR modified entry."""
    added, removed, changed = _inventory_diff(expected, actual)
    if added or removed or changed:
        raise MixedValidateError("staged tree for " + phase + " does not match the trusted source/artifact map "
                                 + json.dumps({"added": added, "removed": removed, "changed": changed},
                                              sort_keys=True, separators=(",", ":")))


def _prelaunch_drift_hook(arm):
    """Deterministic test seam: invoked after an arm is staged and its overlay
    captured, immediately before the pre-launch integrity re-check and child
    launch. Production is a no-op; a test may patch it to mutate a pinned
    artifact/tool and prove pre-launch drift is caught before any child starts."""
    return None


def _postchild_drift_hook(arm, stage_root):
    """Deterministic test seam: invoked after an arm's child exits, before the
    post-child integrity re-check and the post-child overlay comparison.
    Production is a no-op; a test may patch it to mutate a pinned tool or inject/
    remove/modify a staged sibling and prove post-child drift is caught."""
    return None


# ---------------------------------------------------------------------------
# Strict per-arm reply validation (the parent trusts no child-asserted summary)
# ---------------------------------------------------------------------------

def _require(condition, message):
    if not condition:
        raise MixedValidateError(message)


def _validate_observation(item):
    _require(isinstance(item, dict), "reply observation must be an object")
    kind = item.get("kind")
    if kind == "throw":
        _require(set(item) == {"kind", "thrown"} and isinstance(item.get("thrown"), str)
                 and len(item["thrown"]) <= 64, "throw observation must carry a bounded string tag only")
        return
    _require(kind == "return", "observation kind must be 'return' or 'throw'")
    rtype = item.get("type")
    if rtype == "number":
        _require(set(item) == {"kind", "type", "bits"} and isinstance(item.get("bits"), str)
                 and re.fullmatch(r"[0-9a-f]{16}", item["bits"]) is not None,
                 "number observation must carry 16 lowercase hex bits only")
    elif rtype == "bigint":
        _require(set(item) == {"kind", "type", "value"} and isinstance(item.get("value"), str)
                 and re.fullmatch(r"-?(0|[1-9][0-9]*)", item["value"]) is not None,
                 "bigint observation must carry a decimal string only")
    elif rtype == "boolean":
        _require(set(item) == {"kind", "type", "value"} and type(item.get("value")) is bool,
                 "boolean observation must carry a JSON boolean only")
    elif rtype in ("null", "undefined"):
        _require(set(item) == {"kind", "type"}, rtype + " observation must carry kind and type only")
    else:
        raise MixedValidateError("unsupported observation return type")


def _validate_output_map(value, names, expected_lengths, label):
    _require(isinstance(value, dict) and set(value) == names,
             label + " must cover exactly the sampled entrypoints")
    for name in names:
        series = value[name]
        _require(isinstance(series, list) and len(series) == expected_lengths[name],
                 label + " for " + name + " must list exactly one observation per sampled vector")
        for item in series:
            _validate_observation(item)


def _validate_reply(reply, names, expected_lengths):
    """Strictly validate a status=ok per-arm reply before any value is used:
    schema, types, array lengths and every wire-value format. Deterministic
    booleans are NOT coerced here; the parent recomputes determinism from the
    retained first/second observation arrays (see _compare_functions)."""
    _require(isinstance(reply, dict) and reply.get("status") == "ok", "reply must be a status=ok object")
    origin = reply.get("module_origin")
    _require(isinstance(origin, dict), "reply must carry module_origin")
    _require(isinstance(origin.get("resolved"), str), "module_origin.resolved must be a string")
    _require(origin.get("require_executed") is True, "module_origin.require_executed must be exactly true")
    _require(_hex64(origin.get("file_sha256_before")) and _hex64(origin.get("file_sha256_after")),
             "module_origin must carry 64-hex before/after target hashes")
    _require(isinstance(origin.get("loaded_files"), list)
             and all(isinstance(p, str) for p in origin["loaded_files"]),
             "module_origin.loaded_files must be a list of strings")
    surface = origin.get("public_surface")
    _require(isinstance(surface, dict)
             and all(isinstance(k, str) and isinstance(v, str) for k, v in surface.items()),
             "module_origin.public_surface must map string keys to string typeofs")
    _require(isinstance(origin.get("env_keys"), list)
             and all(isinstance(k, str) for k in origin["env_keys"]),
             "module_origin.env_keys must be a list of strings")
    signatures = reply.get("signatures")
    _require(isinstance(signatures, dict) and set(signatures) == names,
             "reply.signatures must cover exactly the sampled entrypoints")
    for name in names:
        sig = signatures[name]
        _require(isinstance(sig, dict) and type(sig.get("length")) is int and sig["length"] >= 0
                 and sig.get("kind") == "function" and isinstance(sig.get("source_prefix"), str),
                 "signature for " + name + " is malformed")
    _validate_output_map(reply.get("outputs"), names, expected_lengths, "reply.outputs")
    _validate_output_map(reply.get("outputs_second"), names, expected_lengths, "reply.outputs_second")
    timings = reply.get("timings")
    _require(isinstance(timings, dict) and set(timings) == names,
             "reply.timings must cover exactly the sampled entrypoints")
    for name in names:
        timing = timings[name]
        _require(isinstance(timing, dict) and isinstance(timing.get("samples_ns"), list)
                 and len(timing["samples_ns"]) >= 1
                 and all(type(s) is int and s >= 0 for s in timing["samples_ns"])
                 and type(timing.get("median_ns")) is int and timing["median_ns"] >= 0
                 and type(timing.get("calls_per_batch")) is int and timing["calls_per_batch"] >= 0
                 and type(timing.get("warmup_batches")) is int and timing["warmup_batches"] >= 0,
                 "timing for " + name + " is malformed")
    return reply


def _compare_functions(baseline, protected, cases, selected_names):
    """Build the per-entrypoint result from two strictly-validated replies.
    Determinism is RECOMPUTED in the parent from the retained first/second arrays
    (``a == a2 and b == b2``), never read from a child-asserted truthy flag."""
    functions = {}
    for name, vectors in cases.items():
        a, b = baseline["outputs"][name], protected["outputs"][name]
        a2, b2 = baseline["outputs_second"][name], protected["outputs_second"][name]
        match = len(a) == len(b) == len(vectors) and a == b
        deterministic = (a == a2) and (b == b2)
        base_ns = baseline["timings"][name]["median_ns"]
        protected_ns = protected["timings"][name]["median_ns"]
        ordinary_returns = sum(item.get("kind") == "return" for item in a)
        thrown = sum(item.get("kind") == "throw" for item in a)
        functions[name] = {"sampled_output_match": match, "deterministic": deterministic,
            "cases": len(vectors), "selected": name in selected_names,
            "baseline_ordinary_returns": ordinary_returns, "baseline_throws": thrown,
            "baseline_timing": baseline["timings"][name], "protected_timing": protected["timings"][name],
            "slowdown_ratio": (protected_ns / base_ns) if base_ns else None}
    return functions


# ---------------------------------------------------------------------------
# Orchestration (parent process)
# ---------------------------------------------------------------------------

def _owned(path, root):
    path = _no_links(path)
    if not path.is_relative_to(root):
        raise MixedValidateError("path must stay inside the workspace: " + str(path))
    if any(part.casefold() in {"rea-analysis-reports", "attackerfolder"} for part in path.relative_to(root).parts):
        raise MixedValidateError("untrusted/shared path is not an owned input/output")
    return path


def validate_build(report_path, contract_path, output_dir, *, workspace_root, expected_snapshot,
                   random_cases=8192, seed=20261020, timeout_seconds=120, trusted_inputs=None):
    """Validate one owned mixed JavaScript/TypeScript build against its contract.

    Returns a JSON-serializable result dict and writes it to ``output_dir/validation.json``.
    A ``mixed_application_samples_passed`` status means only functional_preservation
    on the sampled vectors; it is never a defense or general-equivalence claim.
    """
    root = Path(os.path.abspath(workspace_root))
    if not root.is_dir():
        raise MixedValidateError("workspace_root must be an existing directory")
    report_path = _owned(report_path, root)
    contract_path = _owned(contract_path, root)
    output = _owned(output_dir, root)
    if output.exists():
        raise MixedValidateError("validation output must be a fresh directory")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
        raise MixedValidateError("timeout_seconds must be an integer in 1..600")

    contract_bytes = _read(contract_path, MAX_CONTRACT_BYTES)
    contract = validate_application_contract(_json(contract_bytes))
    cases = make_cases(contract, random_cases, seed)

    report_bytes = _read(report_path, MAX_REPORT_BYTES)
    report = _json(report_bytes)
    if (not isinstance(report, dict) or report.get("status") != "artifact_created_unvalidated"
            or report.get("backend") != BACKEND or report.get("protection_mode") != MODE):
        raise MixedValidateError("only a successful owned mixed-module VM build can be validated")

    selected_names = {function["name"] for function in contract["entrypoints"]}
    preserved_names = {function["name"] for function in contract["preserved_entrypoints"]}
    coverage = report.get("coverage")
    _verify_mixed_coverage(coverage, selected_names, preserved_names)

    package_root, module_relative = _derive_module(report)
    language = report["project"]["language"]
    is_typescript = language == "typescript"
    if contract["kind"] != CONTRACT_KINDS[language]:
        raise MixedValidateError("application contract kind must match the built source language")
    _staging_guard(package_root, root)
    if contract["source"] != module_relative:
        raise MixedValidateError("contract source must equal the inspected module path "
                                 + module_relative + ", not " + contract["source"])
    if (output == package_root or output.is_relative_to(package_root)
            or package_root.is_relative_to(output)):
        raise MixedValidateError("validation output must not overlap the owned package tree")

    node_path, toolchain_pins, toolchain_drift = _verify_toolchain(report)
    runner = _runner_evidence()

    artifacts = {}
    report_artifacts = report.get("artifacts", {})
    if not isinstance(report_artifacts, dict):
        raise MixedValidateError("mixed build report must carry baseline and protected artifacts")
    for arm in ("baseline", "protected"):
        artifact = report_artifacts.get(arm, {})
        if not isinstance(artifact, dict) or not isinstance(artifact.get("path"), str):
            raise MixedValidateError("missing " + arm + " artifact in build report")
        path = _owned(artifact["path"], root)
        if path.suffix.lower() != ".cjs" or not path.is_file() or _hash(path) != artifact.get("sha256"):
            raise MixedValidateError(arm + " artifact hash differs from the reviewed build")
        artifacts[arm] = {"path": str(path), "sha256": artifact["sha256"], "bytes": path.stat().st_size}

    expected_source = _verify_against_plan(package_root, expected_snapshot)
    original = _read(package_root / module_relative, MAX_FILE_BYTES).decode("utf-8-sig").encode("utf-8")
    if coverage["transpiled_typescript"] is not is_typescript:
        raise MixedValidateError("coverage transpilation flag must match the built source language")
    if hashlib.sha256(original).hexdigest() != coverage["original_module_source_sha256"]:
        raise MixedValidateError("baseline must equal the bound original module source identity")
    if not is_typescript and original != _read(Path(artifacts["baseline"]["path"]), MAX_FILE_BYTES):
        raise MixedValidateError("JavaScript baseline must equal the bound original module (UTF-8 BOM removed)")
    # The compiler's working source precedes VM replacement and excludes only
    # a leading shebang. It is not the protected artifact's hash.
    working_source = original
    if working_source.startswith(b"#!"):
        newline = working_source.find(b"\n")
        working_source = b"" if newline < 0 else working_source[newline + 1:]
    if not is_typescript and hashlib.sha256(working_source).hexdigest() != coverage["working_source_sha256"]:
        raise MixedValidateError("JavaScript working source hash must match the original module without its shebang")
    runtime_relative = Path(module_relative).with_suffix(".cjs").as_posix() if is_typescript else module_relative
    reference_pins = {}
    if is_typescript:
        if any(name.casefold() == runtime_relative.casefold() for name in expected_source):
            raise MixedValidateError("TypeScript runtime entry collides with an owned package file")
        if any(name != module_relative and Path(name).suffix.lower() in {".ts", ".tsx", ".cts", ".mts"}
               for name in expected_source):
            raise MixedValidateError("additional TypeScript source requires a qualified multi-module reference graph")
        from . import typescript_reference
        for pin in typescript_reference.helper_tool_pins():
            if (not isinstance(pin, dict) or set(pin) != {"path", "sha256"}
                    or not isinstance(pin["path"], str) or not _hex64(pin["sha256"])):
                raise MixedValidateError("invalid trusted TypeScript reference helper pin")
            reference_pins[str(_no_links(pin["path"]))] = pin["sha256"]
        if not reference_pins:
            raise MixedValidateError("TypeScript reference helper pins are required")
    trusted_pins = {}
    if trusted_inputs is not None:
        if not isinstance(trusted_inputs, list) or not trusted_inputs:
            raise MixedValidateError("trusted service inputs must be a non-empty pin list")
        for pin in trusted_inputs:
            if (not isinstance(pin, dict) or set(pin) != {"path", "sha256"}
                    or not isinstance(pin["path"], str) or not _hex64(pin["sha256"])):
                raise MixedValidateError("trusted service input must carry path and sha256")
            path = str(_no_links(pin["path"]))
            if path in trusted_pins and trusted_pins[path] != pin["sha256"]:
                raise MixedValidateError("conflicting trusted service input pins")
            trusted_pins[path] = pin["sha256"]

    def _service_inputs_unchanged():
        return all(_hash(path) == sha for path, sha in trusted_pins.items())

    def _reference_inputs_unchanged():
        return all(_hash(path) == sha for path, sha in reference_pins.items())

    functions_meta = list(contract["entrypoints"]) + list(contract["preserved_entrypoints"])
    runner_functions = [{"name": f["name"], "parameters": [{"name": p["name"], "type": p["type"]}
                                                            for p in f["parameters"]]} for f in functions_meta]

    result = {"schema_version": 1, "status": "failed", "backend": BACKEND, "mode": MODE,
              "module_relative": module_relative, "package_root": str(package_root),
              "runtime_module_relative": runtime_relative,
              "language": language,
              "baseline_source_kind": ("typescript_independent_transpile" if is_typescript
                                       else "javascript_original_module"),
              "transpiled_typescript": coverage["transpiled_typescript"],
              "original_module_source_sha256": coverage["original_module_source_sha256"],
              "working_source_sha256": coverage["working_source_sha256"],
              "artifacts": artifacts, "toolchain_pins": toolchain_pins, "toolchain_drift": sorted(toolchain_drift),
              "runner": runner, "node_path": node_path,
              "build_report_sha256": hashlib.sha256(report_bytes).hexdigest(),
              "contract_sha256": hashlib.sha256(contract_bytes).hexdigest(),
              "selected_entrypoints": sorted(selected_names), "preserved_entrypoints": sorted(preserved_names),
              "cases_per_function": {name: len(value) for name, value in cases.items()},
              "random_cases_per_function": random_cases, "seed": seed, "behavior_repeats": 2,
              "source_plan_files": len(expected_source), "source_plan_snapshot_bound": True,
              "service_plan_inputs_bound": bool(trusted_pins), "service_input_pins": trusted_pins,
              "reference_tool_pins": dict(reference_pins),
              "timeout_seconds": timeout_seconds, "staging": {}, "execution": {}, "functions": {},
              "module_origin": {}, "external_attack_evaluation": "not_evaluated", "limitations": list(LIMITATIONS)}

    toolchain_files = report["toolchain"]["files"]
    expected_integrity = _expected_integrity(result, artifacts, runner, toolchain_files)
    reply_names = set(cases)
    reply_lengths = {name: len(value) for name, value in cases.items()}

    def _check_integrity(phase):
        if not _service_inputs_unchanged():
            raise MixedValidateError("trusted service plan/engine input changed " + phase)
        if not _reference_inputs_unchanged():
            raise MixedValidateError("trusted TypeScript reference input changed " + phase)
        drift = _integrity_drift(expected_integrity,
                                 _current_integrity(report_path, contract_path, artifacts, toolchain_files))
        if drift:
            raise MixedValidateError("pinned integrity changed " + phase + ": " + ", ".join(drift))

    if toolchain_drift:
        result["error"] = "pinned build toolchain changed since the reviewed build: " + ", ".join(sorted(toolchain_drift))
        _save(output_mkdir(output) / "validation.json", result)
        return result

    stop = root / ".runs" / "defense-loop" / "STOP"
    if stop.exists():
        result["status"] = "cancelled"
        result["reason"] = "defense STOP exists"
        _save(output_mkdir(output) / "validation.json", result)
        return result
    output.mkdir(parents=True)

    try:
        if is_typescript:
            _check_integrity("before independent TypeScript reference")
            reference_dir = output / "reference"
            reference = typescript_reference.build_reference(
                package_root / module_relative, reference_dir, workspace_root=root,
                toolchain_files=toolchain_files,
                expected_source_sha256=expected_source[module_relative]["sha256"],
                timeout_seconds=timeout_seconds)
            result["reference_compilation"] = reference
            if reference.get("status") != "reference_created":
                if reference.get("status") in {"cancelled", "timed_out"}:
                    result["status"] = reference["status"]
                raise MixedValidateError("independent TypeScript reference did not complete: " + str(reference.get("error", reference.get("status"))))
            reference_process = reference.get("process", {})
            reference_cleanup = reference_process.get("cleanup", {})
            if (reference_process.get("returncode") != 0 or reference_process.get("cancelled") is not False
                    or reference_process.get("timed_out") is not False
                    or (os.name == "nt" and not (reference_cleanup.get("job_assigned") is True
                        and reference_cleanup.get("parent_exit_confirmed") is True
                        and reference_cleanup.get("job_handle_closed") is True
                        and reference_cleanup.get("active_after") == 0
                        and reference_cleanup.get("status") == "assigned_job_empty"))):
                raise MixedValidateError("independent TypeScript compiler process cleanup or outcome is unverified")
            independent = reference.get("reference", {})
            independent_path = _owned(independent.get("path", ""), root)
            if (not independent_path.is_relative_to(reference_dir) or independent_path.suffix != ".cjs"
                    or not _hex64(independent.get("sha256")) or _hash(independent_path) != independent["sha256"]
                    or independent_path.stat().st_size != independent.get("bytes")):
                raise MixedValidateError("invalid independent TypeScript reference artifact")
            emitted = _read(independent_path, MAX_FILE_BYTES)
            if emitted != _read(Path(artifacts["baseline"]["path"]), MAX_FILE_BYTES):
                raise MixedValidateError("TypeScript build baseline differs from independently compiled original source")
            emitted_working = emitted
            if emitted.startswith(b"#!"):
                newline = emitted.find(b"\n")
                emitted_working = b"" if newline < 0 else emitted[newline + 1:]
            if (reference.get("source_sha256") != expected_source[module_relative]["sha256"]
                    or reference.get("normalized_source_sha256") != coverage["original_module_source_sha256"]
                    or reference.get("working_source_sha256") != coverage["working_source_sha256"]
                    or hashlib.sha256(emitted_working).hexdigest() != coverage["working_source_sha256"]):
                raise MixedValidateError("TypeScript source/reference provenance or working source hash mismatch")
            reference_pins[str(independent_path)] = independent["sha256"]
            reference_report = reference_dir / "reference.json"
            if _json(_read(reference_report, MAX_REPORT_BYTES)) != reference:
                raise MixedValidateError("persisted TypeScript reference differs from returned compiler evidence")
            reference_pins[str(reference_report)] = _hash(reference_report)
            result["reference_evidence_pins"] = dict(reference_pins)
            _check_integrity("after independent TypeScript reference")
            _verify_against_plan(package_root, expected_snapshot)
        _prestage_drift_hook()
        replies, snapshots, expected_overlays, stage_roots = {}, {}, {}, {}
        for arm in ("baseline", "protected"):
            # Re-hash every pinned input (report, contract, artifacts, runner, all
            # build tools) before this child; artifact bytes are re-verified again
            # as they are staged against their reviewed SHA-256.
            _check_integrity("before child arm " + arm)
            stage_root = output / arm / "stage"
            staging = _stage_arm(package_root, module_relative, Path(artifacts[arm]["path"]), stage_root, root,
                                 expected_artifact_sha256=artifacts[arm]["sha256"],
                                 runtime_module_relative=runtime_relative)
            snapshots[arm] = staging["snapshot"]
            if _snapshot_as_map(staging["snapshot"]) != expected_source:
                raise MixedValidateError("owned package tree changed since the bound source plan before staging arm " + arm)
            stage_roots[arm] = Path(os.path.abspath(staging["stage_root"]))
            # The TRUSTED expected overlay: the source-plan map with the target swapped
            # for this arm's artifact. The complete staged tree (every file, not only
            # the target) is compared to THIS, so a sibling corrupted during/after the
            # copy cannot become the accepted baseline.
            expected_overlay = _expected_overlay(expected_source, module_relative, artifacts[arm], runtime_relative)
            expected_overlays[arm] = expected_overlay
            _assert_overlay_matches(_snapshot_as_map(_snapshot_tree(stage_roots[arm])), expected_overlay,
                                    "arm " + arm + " staged tree before launch")
            result["staging"][arm] = {key: staging[key] for key in ("stage_root", "target", "target_sha256", "files", "bytes")}
            request = {"stage_root": staging["stage_root"], "target": staging["target"],
                       "target_sha256": staging["target_sha256"], "module_relative": runtime_relative,
                       "functions": runner_functions, "cases": cases}
            request_path = output / arm / (arm + ".request.json")
            request_path.parent.mkdir(parents=True, exist_ok=True)
            request_path.write_text(json.dumps(request), encoding="utf-8")
            env = _child_env(output / arm / "tmp")
            _prelaunch_drift_hook(arm)
            # Re-verify artifact/tool/runner bytes AND the full staged tree against the
            # trusted map immediately before launch (also after the prelaunch seam), so
            # a stage change landing after the initial capture is caught, not baselined.
            _check_integrity("before launching arm " + arm)
            _assert_overlay_matches(_snapshot_as_map(_snapshot_tree(stage_roots[arm])), expected_overlay,
                                    "arm " + arm + " staged tree before launch (post-hook)")
            if stop.exists():
                result["status"] = "cancelled"
                raise MixedValidateError("defense STOP exists before launching arm " + arm)
            process = run_logged(_arm_command(node_path, request_path), output / arm, output / arm / "worker",
                                 timeout_seconds, env=env, cancel_file=stop)
            result["execution"][arm] = {**process, "child_env_keys": sorted(env)}
            if process.get("returncode") != 0 or process.get("cancelled") or process.get("timed_out"):
                runner_error = None
                reply_path = request_path.with_name(arm + ".reply.json")
                if reply_path.exists():
                    try:
                        runner_error = _json(_read(reply_path, MAX_REPLY_BYTES)).get("error")
                    except MixedValidateError:
                        runner_error = None
                result["execution"][arm]["runner_error"] = runner_error
                if process.get("cancelled"):
                    result["status"] = "cancelled"
                elif process.get("timed_out"):
                    result["status"] = "timed_out"
                raise MixedValidateError(arm + " mixed application worker failed, timed out or was cancelled"
                                         + (": " + str(runner_error)[:512] if runner_error else ""))
            cleanup = process.get("cleanup", {})
            if os.name == "nt" and not (cleanup.get("job_assigned") and cleanup.get("active_after") == 0
                                        and cleanup.get("parent_exit_confirmed") and cleanup.get("job_handle_closed")):
                raise MixedValidateError("worker process-tree cleanup could not be verified")
            # Re-hash every pinned input after this child, and re-compare the whole
            # overlaid staged tree: a changed/missing/injected sibling fails closed.
            _postchild_drift_hook(arm, stage_roots[arm])
            _check_integrity("after child arm " + arm)
            _assert_overlay_matches(_snapshot_as_map(_snapshot_tree(stage_roots[arm])), expected_overlay,
                                    "arm " + arm + " staged tree after execution")
            raw_reply = _json(_read(request_path.with_name(arm + ".reply.json"), MAX_REPLY_BYTES))
            if raw_reply.get("status") != "ok":
                raise MixedValidateError(arm + " runner reported: " + str(raw_reply.get("error", "unknown"))[:512])
            replies[arm] = _validate_reply(raw_reply, reply_names, reply_lengths)

        baseline, protected = replies["baseline"], replies["protected"]
        # Compare only arity/kind across arms: the protected VM wrapper deliberately
        # has a different function body (source text), so source_prefix is kept as
        # evidence but excluded from the consistency check.
        def _arity(reply):
            return {name: {"length": sig.get("length"), "kind": sig.get("kind")}
                    for name, sig in reply["signatures"].items()}
        origin_consistent = (baseline["module_origin"]["public_surface"] == protected["module_origin"]["public_surface"]
                             and _arity(baseline) == _arity(protected)
                             and baseline["module_origin"]["require_executed"] is True
                             and protected["module_origin"]["require_executed"] is True
                             and baseline["module_origin"]["file_sha256_before"] == artifacts["baseline"]["sha256"]
                             and baseline["module_origin"]["file_sha256_after"] == artifacts["baseline"]["sha256"]
                             and protected["module_origin"]["file_sha256_before"] == artifacts["protected"]["sha256"]
                             and protected["module_origin"]["file_sha256_after"] == artifacts["protected"]["sha256"])
        result["module_origin"] = {"baseline": baseline["module_origin"], "protected": protected["module_origin"],
                                   "signatures": baseline["signatures"], "consistent": origin_consistent}
        # Determinism is recomputed here in the parent from the retained first/
        # second observation arrays; no child-asserted flag is trusted or coerced.
        result["functions"] = _compare_functions(baseline, protected, cases, selected_names)

        reference = snapshots["baseline"]
        final_source = _snapshot_as_map(_snapshot_tree(package_root))
        # Final completion: re-hash every pinned input once more and re-compare
        # each arm's complete overlaid staged tree. A pass may not rest on a
        # stale integrity flag taken earlier in the run.
        final_integrity_ok = _service_inputs_unchanged() and _reference_inputs_unchanged() and not _integrity_drift(
            expected_integrity, _current_integrity(report_path, contract_path, artifacts, toolchain_files))
        overlays_ok = all(_snapshot_as_map(_snapshot_tree(stage_roots[arm])) == expected_overlays[arm]
                          for arm in ("baseline", "protected"))
        unchanged = (hashlib.sha256(_read(report_path, MAX_REPORT_BYTES)).hexdigest() == result["build_report_sha256"]
                     and hashlib.sha256(_read(contract_path, MAX_CONTRACT_BYTES)).hexdigest() == result["contract_sha256"]
                     and all(_hash(Path(a["path"])) == a["sha256"] for a in artifacts.values())
                     and snapshots["protected"] == reference
                     and _snapshot_as_map(reference) == expected_source
                     and final_source == expected_source
                     and _hash(_no_links(_RUNNER)) == runner["sha256"]
                     and final_integrity_ok and overlays_ok)
        passed = (unchanged and origin_consistent
                  and all(item["sampled_output_match"] and item["deterministic"]
                          and (item["baseline_ordinary_returns"] + item["baseline_throws"]) == item["cases"]
                          for item in result["functions"].values())
                  and any(item["baseline_ordinary_returns"] > 0 for item in result["functions"].values()))
        result["inputs_unchanged"] = unchanged
        result["status"] = "mixed_application_samples_passed" if passed else "failed"
    except MixedValidateError as exc:
        result["error"] = type(exc).__name__ + ": " + str(exc)[:2048]
    except Exception as exc:  # defensive: never leak a traceback as a pass
        result["error"] = type(exc).__name__ + ": " + str(exc)[:2048]
    _save(output / "validation.json", result)
    return result


def output_mkdir(output):
    if not output.exists():
        output.mkdir(parents=True)
    return output


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description="Validate an owned mixed-module JavaScript/TypeScript build (functional preservation).")
    parser.add_argument("--report", required=True)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--expected-snapshot", required=True,
                        help="JSON file holding the preexisting trusted source-plan snapshot list "
                             "(from the verified build plan). 'derive' is refused: an accepted "
                             "validation must bind a trusted snapshot, not one taken from the very "
                             "tree being validated at validation time.")
    parser.add_argument("--random-cases", type=int, default=8192)
    parser.add_argument("--seed", type=int, default=20261020)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    args = parser.parse_args(argv)
    # The 'derive' shortcut, which snapshotted the plan's project root on the fly,
    # is refused outright: a derived snapshot proves nothing about the plan and must
    # never back an accepted validation (source_plan_snapshot_bound). The caller must
    # supply a preexisting trusted snapshot file produced from the verified build plan.
    if args.expected_snapshot == "derive":
        raise MixedValidateError(
            "expected-snapshot=derive is refused: supply a preexisting trusted source-plan "
            "snapshot file produced from the verified build plan (snapshot_source_tree may "
            "precompute that shape at plan time, never at validation time)")
    snapshot = _json(_read(Path(args.expected_snapshot), MAX_REPORT_BYTES))
    result = validate_build(args.report, args.contract, args.output, workspace_root=args.workspace,
                            expected_snapshot=snapshot, random_cases=args.random_cases, seed=args.seed,
                            timeout_seconds=args.timeout_seconds)
    print(json.dumps({"status": result["status"], "error": result.get("error"),
                      "output": str(Path(os.path.abspath(args.output)) / "validation.json")}))
    return 0 if result["status"] == "mixed_application_samples_passed" else 1


if __name__ == "__main__":
    sys.exit(main())
