"""Opt-in functional sampling of owned native builds, in bounded child processes.

This executes the user's compiled code. It is not an OS security sandbox or an
attack tool. It measures returned integer values, not arbitrary side effects.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import statistics
import sys
import time

from .bindings import validate_contract
from .native_abi import verify_integer_abi
from .process import run_logged
from .protectors import _no_links, _read, _json


CTYPES = {"u32": ctypes.c_uint32, "i32": ctypes.c_int32,
          "u64": ctypes.c_uint64, "i64": ctypes.c_int64}
MAX_CASES = 262144


def _worker_command(request_path):
    # The workspace may be another checkout, or contain an unrelated antirea
    # package. Ignore cwd/PYTHONPATH/site hooks and import this installed engine.
    package_root = Path(__file__).absolute().parents[1]
    _no_links(package_root)
    bootstrap = ("import runpy,sys; sys.path.insert(0,sys.argv.pop(1)); "
                 "runpy.run_module('antirea.native_validate',run_name='__main__',alter_sys=True)")
    return [sys.executable, "-I", "-S", "-c", bootstrap, str(package_root), "--worker", str(request_path)]


def _hash(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _save(path, value):
    _no_links(path)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def make_cases(contract, random_cases=8192, seed=20261020):
    contract = validate_contract(contract)
    if type(random_cases) is not int or not 1 <= random_cases <= 8192:
        raise ValueError("random_cases must be an integer in 1..8192")
    if type(seed) is not int or not 0 <= seed <= 0x7FFFFFFF:
        raise ValueError("seed must be a nonnegative 31-bit integer")
    rng = random.Random(seed)
    cases = {}
    for function in contract["functions"]:
        if function["return_type"] == "void":
            raise ValueError("void/side-effect-only functions need a state-observation test contract")
        ranges = []
        for parameter in function["parameters"]:
            kind = parameter["type"]
            bits = int(kind[1:])
            ranges.append((0, 2**bits - 1) if kind[0] == "u" else (-2**(bits-1), 2**(bits-1)-1))
        values = [[rng.randint(lo, hi) for lo, hi in ranges] for _ in range(random_cases)]
        boundaries = {tuple(0 for _ in ranges)}
        for index, (lo, hi) in enumerate(ranges):
            for value in (lo, lo + 1, 0, 1, hi - 1, hi):
                vector = [0] * len(ranges)
                vector[index] = value
                boundaries.add(tuple(vector))
        boundaries.add(tuple(lo for lo, hi in ranges))
        boundaries.add(tuple(hi for lo, hi in ranges))
        cases[function["name"]] = values + [list(value) for value in sorted(boundaries)]
        if sum(len(value) for value in cases.values()) > MAX_CASES:
            raise ValueError("validation exceeds total case limit; lower cases per function explicitly")
    return cases


def _artifact_path(root, directory, value):
    path = Path(os.path.abspath(value))
    _no_links(path)
    if not path.is_relative_to(root) or not path.is_relative_to(directory):
        raise ValueError("library must stay inside the reviewed build directory")
    parts = {part.casefold() for part in path.relative_to(root).parts}
    if "rea-analysis-reports" in parts or "attackerfolder" in parts or "defense-loop" in parts:
        raise ValueError("received and shared binaries cannot be executed")
    if not path.is_file():
        raise ValueError("library is missing")
    return path


def _worker_run(request):
    root = Path(request["workspace_root"])
    directory = Path(request["build_directory"])
    library = _artifact_path(root, directory, request["library_path"])
    if _hash(library) != request["sha256"]:
        raise ValueError("library hash changed before execution")
    contract = validate_contract(request["contract"])
    cases = make_cases(contract, request["random_cases"], request["seed"])
    handle = ctypes.CDLL(str(library), **({"winmode": 0x1100} if os.name == "nt" else {}))
    outputs, deterministic, timings = {}, {}, {}
    for function in contract["functions"]:
        name = function["name"]
        callback = getattr(handle, name)
        callback.argtypes = [CTYPES[p["type"]] for p in function["parameters"]]
        callback.restype = CTYPES[function["return_type"]]
        first = [callback(*args) for args in cases[name]]
        second = [callback(*args) for args in cases[name]]
        outputs[name] = first
        deterministic[name] = first == second
        batch = cases[name][:min(256, len(cases[name]))]
        for args in batch:
            callback(*args)
        samples = []
        for _ in range(7):
            started = time.perf_counter_ns()
            for args in batch:
                callback(*args)
            samples.append(time.perf_counter_ns() - started)
        timings[name] = {"samples_ns": samples, "median_ns": statistics.median(samples),
                         "calls_per_batch": len(batch), "warmup_batches": 1}
    if _hash(library) != request["sha256"]:
        raise ValueError("library changed during execution")
    return {"outputs": outputs, "deterministic": deterministic, "timings": timings}


def _reference_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()


def _verify_reference_plan(report, root, directory, value, watched):
    """Bind recorded recipes to the saved normalized plan and raw database.

    This is a consistency check on owned build evidence, not an attestation of
    compiler execution or a replacement for the builder's full snapshot gates.
    """
    from . import compile_database as cd
    plan = report.get("compilation_database")
    hashes = report.get("artifact_hashes")
    if not isinstance(plan, dict) or not isinstance(hashes, dict):
        raise ValueError("original reference normalized plan and artifact hashes are required")
    plan_path = _artifact_path(root, directory, directory / "compile-database-plan.json")
    plan_bytes = _read(plan_path, 16 * 1024 * 1024)
    plan_hash = hashlib.sha256(plan_bytes).hexdigest()
    if hashes.get("compile-database-plan.json") != plan_hash or _json(plan_bytes) != plan:
        raise ValueError("original reference embedded/saved compilation plan differs")
    if (type(plan.get("schema_version")) is not int or plan["schema_version"] != 1
            or plan.get("workspace_root") != str(root)
            or plan.get("status") != "normalized_not_built"
            or plan.get("fingerprint") != _reference_digest({k: v for k, v in plan.items() if k != "fingerprint"})):
        raise ValueError("original reference normalized plan fingerprint/root is invalid")
    watched[str(plan_path)] = plan_hash
    database_record = report.get("compilation_database_source")
    if not isinstance(database_record, dict):
        raise ValueError("original reference private raw database snapshot is missing")
    database = _artifact_path(root, directory, database_record.get("path", ""))
    if database != directory / "compile-database-raw.json":
        raise ValueError("original reference raw database snapshot must use the fixed private path")
    database_bytes = _read(database, cd.MAX_DATABASE_BYTES)
    database_hash = hashlib.sha256(database_bytes).hexdigest()
    if (database_hash != plan.get("database_sha256") or database_hash != database_record.get("sha256")
            or database_hash != hashes.get("compile-database-raw.json")):
        raise ValueError("original reference private database content differs from recorded plan")
    watched[str(database)] = database_hash
    try:
        # Replays raw entries through the same option normalizer; does not run
        # target/compiler or rescan the complete SDK/source inventory.
        cd.verify_recorded_plan(plan, database_bytes=database_bytes)
    except (ValueError, KeyError, TypeError, OSError) as exc:
        raise ValueError("original reference recipe does not match the raw database: " + str(exc)) from exc
    expected = {
        "compilation_database_sha256": database_hash,
        "compilation_plan_fingerprint": plan["fingerprint"],
        "source_input_snapshot_sha256": _reference_digest(plan["inputs"]),
        "header_context_sha256": _reference_digest(plan["trusted_headers"]),
    }
    if any(value.get(key) != digest for key, digest in expected.items()):
        raise ValueError("original reference provenance digest differs from the recorded snapshot")
    compiler_inputs = {record["path"]: record["sha256"] for record in plan["tools"].values()}
    if value.get("compiler_inputs") != compiler_inputs:
        raise ValueError("original reference compiler set differs from normalized plan")
    header = report.get("header_inventory")
    if not isinstance(header, dict):
        raise ValueError("original reference header inventory descriptor is missing")
    header_path = _artifact_path(root, directory, header.get("path", ""))
    if header_path != directory / "compile-database-inputs.json":
        raise ValueError("original reference header inventory path is not the recorded sidecar")
    header_bytes = _read(header_path, 16 * 1024 * 1024)
    header_hash = hashlib.sha256(header_bytes).hexdigest()
    inventory = _json(header_bytes)
    if (header_hash != header.get("sha256") or header_hash != hashes.get("compile-database-inputs.json")
            or not isinstance(inventory, dict) or set(inventory) != {"project", "trusted_headers"}
            or inventory["project"] != plan["inputs"]
            or not isinstance(inventory["trusted_headers"], dict)
            or inventory["trusted_headers"].get("roots") != plan["trusted_headers"]["roots"]):
        raise ValueError("original reference input/header inventory differs from normalized plan")
    watched[str(header_path)] = header_hash
    planned_units = plan.get("translation_units")
    actual_units = value.get("translation_units")
    if (not isinstance(planned_units, list) or not 1 <= len(planned_units) <= 64
            or not isinstance(actual_units, list) or len(actual_units) != len(planned_units)
            or any(not isinstance(unit, dict) or not isinstance(unit.get("source"), str) for unit in actual_units)):
        raise ValueError("original reference translation units differ from the complete selected plan")
    by_source = {unit["source"]: (index, unit) for index, unit in enumerate(planned_units)}
    if (len(by_source) != len(planned_units)
            or len({unit["source"] for unit in actual_units}) != len(actual_units)
            or {unit["source"] for unit in actual_units} != set(by_source)):
        raise ValueError("original reference translation unit set differs from the complete selected plan")
    return plan, by_source


def _verify_reference_signature_binding(report, root, directory, units, trusted, command, watched):
    """Bind ABI evidence to the verified source compilations, including multi-TU merges."""
    reference = _artifact_path(root, directory, report["original_reference_signature_ir"]["path"])
    signatures = [_artifact_path(root, directory, unit["signature_ir_path"]) for unit in units]
    if len(signatures) == 1 and reference == signatures[0]:
        return
    if reference in signatures:
        raise ValueError("original reference signature omits translation units")
    tool = trusted["tools"]["llvm_link"]
    if report["tool_hashes"].get(tool["path"]) != tool["sha256"]:
        raise ValueError("original reference signature merge tool is not pinned")
    watched[tool["path"]] = tool["sha256"]
    expected = [tool["path"], "-S", *map(str, signatures), "-o", str(reference)]
    indices = [index for index, record in enumerate(report["commands"])
               if isinstance(record, dict) and record.get("argv") == expected]
    if len(indices) != 1 or command(indices[0])["cwd"] != str(directory):
        raise ValueError("original reference signature lacks a unique exact source-signature merge")
    digest = _hash(reference)
    if report["artifact_hashes"].get(str(reference.relative_to(directory))) != digest:
        raise ValueError("original reference merged signature differs from recorded artifact hash")
    watched[str(reference)] = digest


def _verify_reference_provenance(report, root, directory, exports, artifacts, watched):
    """Check the owned builder's recorded direct-source route, not semantic completeness."""
    value = report.get("original_reference_provenance")
    if (not isinstance(value, dict) or type(value.get("schema_version")) is not int or value["schema_version"] != 1
            or value.get("method") != "direct_source_compile"
            or value.get("source_semantics") != "recorded_compilation_database_arguments"
            or value.get("uses_protection_normalized_ir") is not False):
        raise ValueError("original reference direct-source provenance is missing or invalid")
    declared = value.get("exported_functions")
    if (not isinstance(declared, list) or any(not isinstance(name, str) for name in declared)
            or len(set(declared)) != len(declared) or set(declared) != exports):
        raise ValueError("original reference exports differ from the contract")
    digest = lambda item: isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item) is not None
    for key in ("compilation_database_sha256", "compilation_plan_fingerprint", "source_input_snapshot_sha256", "header_context_sha256"):
        if not digest(value.get(key)):
            raise ValueError("original reference provenance digest is missing: " + key)
    compilers = value.get("compiler_inputs")
    if (not isinstance(compilers, dict) or not compilers
            or any(not isinstance(path, str) or not Path(path).is_absolute() or not digest(sha)
                   for path, sha in compilers.items())):
        raise ValueError("original reference compiler inputs are missing or malformed")
    commands, units = report.get("commands"), value.get("translation_units")
    if (not isinstance(commands, list) or not isinstance(units, list) or not 1 <= len(units) <= 256):
        raise ValueError("original reference command/TU provenance is missing")
    from . import compile_database as cd
    plan, planned_units = _verify_reference_plan(report, root, directory, value, watched)
    used_indices = set()

    def command(index):
        if type(index) is not int or not 0 <= index < len(commands) or index in used_indices:
            raise ValueError("invalid or repeated original reference command index")
        used_indices.add(index)
        item = commands[index]
        if (not isinstance(item, dict) or type(item.get("returncode")) is not int or item["returncode"] != 0
                or item.get("timed_out") is not False or item.get("cancelled") is not False
                or not isinstance(item.get("argv"), list) or not item["argv"]
                or any(not isinstance(arg, str) for arg in item["argv"])
                or not isinstance(item.get("cwd"), str)):
            raise ValueError("original reference command did not complete successfully")
        cleanup = item.get("cleanup", {})
        if os.name == "nt" and not (isinstance(cleanup, dict) and cleanup.get("job_assigned") is True
                and type(cleanup.get("active_after")) is int and cleanup["active_after"] == 0
                and cleanup.get("parent_exit_confirmed") is True and cleanup.get("job_handle_closed") is True):
            raise ValueError("original reference build command cleanup is unverified")
        return item

    def names_output(argv, path):
        return any((arg == "-o" and index + 1 < len(argv) and argv[index + 1] == path)
                   or (arg == "/clang:-o" and index + 1 < len(argv) and argv[index + 1] == "/clang:" + path)
                   or (arg[:3].lower() == "/fo" and arg[3:] == path)
                   or (arg[:5].lower() in {"/out:", "-out:"} and arg[5:] == path)
                   for index, arg in enumerate(argv))

    objects, sources = [], set()
    for unit in units:
        if (not isinstance(unit, dict) or not digest(unit.get("entry_sha256"))
                or any(not isinstance(unit.get(key), str) or not unit[key]
                       for key in ("source", "source_operand", "compiler", "cwd", "object_path", "signature_ir_path"))):
            raise ValueError("original translation unit provenance is invalid")
        plan_index, planned = planned_units[unit["source"]]
        expected_fields = {"source": planned["source"], "source_operand": planned["source_operand"],
                           "entry_sha256": planned["entry_sha256"], "cwd": planned["directory"],
                           "compiler": planned["compiler"]["path"], "compiler_sha256": planned["compiler"]["sha256"]}
        if any(unit[key] != expected for key, expected in expected_fields.items()):
            raise ValueError("original TU fields differ from the exact selected database entry")
        if not Path(unit["source"]).is_absolute():
            raise ValueError("original TU canonical source path must be absolute")
        source = _artifact_path(root, root, unit.get("source", ""))
        if source.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx", ".c++"} or str(source) in sources:
            raise ValueError("original translation unit must be unique owned C/C++ source")
        sources.add(str(source))
        compiler, cwd = unit.get("compiler"), unit.get("cwd")
        if (not isinstance(compiler, str) or compilers.get(compiler) != unit.get("compiler_sha256")
                or not digest(unit.get("compiler_sha256")) or not isinstance(cwd, str)
                or not Path(cwd).is_absolute()):
            raise ValueError("original TU compiler/cwd provenance is invalid")
        working = Path(os.path.abspath(cwd))
        _no_links(working)
        if not working.is_relative_to(root) or not working.is_dir():
            raise ValueError("original TU working directory must be owned")
        # Keep the original operand spelling for __FILE__/__BASE_FILE__. Only
        # its ownership identity is canonicalized; never rewrite the argv token.
        operand = unit["source_operand"]
        if "\x00" in operand:
            raise ValueError("original TU source operand contains NUL")
        operand_path = Path(operand)
        lexical_path = operand_path if operand_path.is_absolute() else working / operand_path
        try:
            _no_links(lexical_path)
            resolved_source = _artifact_path(root, root, lexical_path.resolve(strict=True))
        except OSError as exc:
            raise ValueError("original TU source operand cannot resolve to an owned source") from exc
        if resolved_source != source.resolve(strict=True):
            raise ValueError("original TU lexical source operand differs from canonical source")
        obj = _artifact_path(root, directory, unit.get("object_path", ""))
        signature = _artifact_path(root, directory, unit.get("signature_ir_path", ""))
        if obj == signature or obj in objects:
            raise ValueError("original TU outputs must be separate owned files")
        objects.append(obj)
        for kind, path in (("object", obj), ("signature_ir", signature)):
            expected_hash = report["artifact_hashes"].get(str(path.relative_to(directory)))
            if not expected_hash or _hash(path) != expected_hash:
                raise ValueError("original TU output differs from recorded artifact hash")
            watched[str(path)] = expected_hash
            record = command(unit.get(kind + "_command_index"))
            argv = record["argv"]
            expected_command = cd.render_compile_argv(
                plan, plan_index, path, emit_ir=kind == "signature_ir", preoptimization=False)
            if (argv != expected_command["argv"] or record["cwd"] != expected_command["cwd"]
                    or expected_command.get("shell") is not False or expected_command.get("executed") is not False):
                raise ValueError("original TU argv differs from the exact preserved frontend recipe")
            flags = {arg.lower().removeprefix("/clang:") for arg in argv}
            if (argv[0] != compiler or record["cwd"] != cwd or operand not in argv
                    or not names_output(argv, str(path)) or "-disable-llvm-passes" in flags
                    or (("-emit-llvm" in flags) != (kind == "signature_ir"))):
                raise ValueError("original TU command differs from its direct-source provenance")
    link_contract = value.get("link_contract")
    if (not isinstance(link_contract, dict) or link_contract.get("kind") != "restricted_windows_shared_library"
            or link_contract.get("target") != "x86_64-pc-windows-msvc"
            or link_contract.get("complete_application_link") is not False):
        raise ValueError("original reference restricted link contract is missing")
    link = command(value.get("link_command_index"))
    if [unit["source"] for unit in units] != [unit["source"] for unit in plan["translation_units"]]:
        raise ValueError("original reference link object order differs from the selected plan")
    # Presence of each original object is not sufficient: extra objects, libs,
    # /FORCE, /ENTRY or a different driver can change the reference program.
    # This is the owned builder's fixed DLL recipe, not a general link manifest.
    # Historical reports without these pins are not silently grandfathered in;
    # their recorded validation remains history, not this stronger gate's result.
    from . import cpp_symbols
    try:
        trusted = cpp_symbols._trusted_link_tools(root)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ValueError("original reference link trusted toolchain is unavailable: " + str(exc)) from exc
    tool_hashes = report.get("tool_hashes")
    if not isinstance(tool_hashes, dict):
        raise ValueError("original reference link tool pins are missing")
    for row in (trusted["config"], trusted["tools"]["clangxx"], trusted["tools"]["lld_link"]):
        if tool_hashes.get(row["path"]) != row["sha256"]:
            raise ValueError("original reference link tool pin differs from the trusted local toolchain")
        watched[row["path"]] = row["sha256"]
    definition = _artifact_path(root, directory, directory / "exports.def")
    definition_bytes = _read(definition, 1024 * 1024)
    definition_hash = hashlib.sha256(definition_bytes).hexdigest()
    if (report["artifact_hashes"].get("exports.def") != definition_hash
            or definition_bytes != ("EXPORTS\n" + "\n".join(declared) + "\n").encode("ascii")):
        raise ValueError("original reference link export definition differs from its recorded public contract")
    watched[str(definition)] = definition_hash
    expected_link = [trusted["tools"]["clangxx"]["path"], "-target", "x86_64-pc-windows-msvc",
        "-shared", "-fuse-ld=lld", *map(str, objects), f"-Wl,/DEF:{definition}",
        "-Wl,/DEBUG:NONE", "-Wl,/INCREMENTAL:NO", "-o", artifacts["original_reference"]["path"]]
    if (link["argv"] != expected_link or link["cwd"] != str(directory)
            or sum(isinstance(record, dict) and record.get("argv") == expected_link for record in commands) != 1):
        raise ValueError("original reference link differs from the unique fixed trusted recipe")
    _verify_reference_signature_binding(report, root, directory, units, trusted, command, watched)
    return {**value, "link_verification": {"status": "fixed_recipe_and_trusted_tools_verified",
        "definition_sha256": definition_hash, "complete_application_link": False,
        "qualification": "Recorded direct-source DLL recipe and current local tool pins checked; not independent execution attestation."}}


def _verify_direct_reference_provenance(report, root, directory, exports, artifacts, watched):
    """Independent direct-source original reference for the C/C++/Rust route.

    Mirrors the compilation-database reference discipline with a smaller,
    plan-free verifier: separate source-compiled objects + signature IR, built
    with the normal direct recipe (O1 / rustc opt-level 1, never the scope
    analysis downgrade) and linked by the fixed trusted DLL recipe, so baseline/
    protected agreement cannot conceal a source-vs-normalized divergence. Reuses
    the fixed-link tail, exports.def check and per-command success/cleanup gate;
    binds the inspected source/tool bytes. Not a compilation-database plan replay,
    not an application link, not an execution attestation.
    """
    from . import native_build, cpp_symbols
    target = "x86_64-pc-windows-msvc"
    digest = lambda item: isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item) is not None
    project = report.get("project")
    if not isinstance(project, dict) or not isinstance(project.get("project_path"), str):
        raise ValueError("original reference direct route requires its inspected project manifest")
    input_hashes = project.get("input_hashes")
    if not isinstance(input_hashes, dict) or not input_hashes:
        raise ValueError("original reference requires the inspected project input snapshot")
    # Re-read and pin the manifest, then re-inspect it: the recorded project must
    # match a fresh inspection exactly, so a forged language/sources/defines/
    # include_dirs cannot bypass the route or downgrade the arm count, and a
    # manifest change mid-run is detected through the watched set.
    manifest = _artifact_path(root, root, project["project_path"])
    manifest_hash = hashlib.sha256(_read(manifest, 1024 * 1024)).hexdigest()
    if input_hashes.get(str(manifest)) != manifest_hash:
        raise ValueError("original reference project manifest is unpinned or differs from the inspected snapshot")
    watched[str(manifest)] = manifest_hash
    try:
        inspected = native_build.inspect_project(manifest, workspace_root=root)
    except (native_build.NativeBuildError, OSError) as exc:
        raise ValueError("original reference project manifest failed re-inspection: " + str(exc)) from exc
    language = inspected.get("language")
    if language not in {"c", "cpp", "rust"}:
        raise ValueError("original reference direct route requires a c/cpp/rust manifest")
    if _reference_digest(project) != _reference_digest(inspected):
        raise ValueError("original reference recorded project differs from the inspected manifest")
    watched.update(inspected["input_hashes"])
    inspected_sources = inspected["sources"]
    value = report.get("original_reference_provenance")
    if (not isinstance(value, dict) or type(value.get("schema_version")) is not int or value["schema_version"] != 1
            or value.get("method") != "direct_source_compile"
            or value.get("source_semantics") != "recorded_direct_source_arguments"
            or value.get("uses_protection_normalized_ir") is not False
            or value.get("language") != language
            or value.get("reference_optimization") != "normal_direct_recipe_no_scope_normalization"):
        raise ValueError("original reference direct-source provenance is missing or invalid")
    declared = value.get("exported_functions")
    if (not isinstance(declared, list) or any(not isinstance(name, str) for name in declared)
            or len(set(declared)) != len(declared) or set(declared) != exports
            or declared != inspected["exported_functions"]):
        raise ValueError("original reference exports differ from the contract or inspected manifest")
    compilers = value.get("compiler_inputs")
    if (not isinstance(compilers, dict) or not compilers
            or any(not isinstance(path, str) or not Path(path).is_absolute() or not digest(sha)
                   for path, sha in compilers.items())):
        raise ValueError("original reference compiler inputs are missing or malformed")
    commands, units = report.get("commands"), value.get("translation_units")
    if (not isinstance(commands, list) or not isinstance(units, list)
            or not all(isinstance(unit, dict) for unit in units)
            or [unit.get("source") for unit in units] != inspected_sources):
        raise ValueError("original reference translation units differ from the complete inspected source set")
    tool_hashes = report.get("tool_hashes")
    if not isinstance(tool_hashes, dict):
        raise ValueError("original reference tool pins are missing")
    artifact_hashes = report.get("artifact_hashes")
    if not isinstance(artifact_hashes, dict):
        raise ValueError("original reference artifact hashes are missing")
    try:
        trusted = cpp_symbols._trusted_link_tools(root)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ValueError("original reference link trusted toolchain is unavailable: " + str(exc)) from exc
    llvm_bin = Path(trusted["llvm_root"]) / "bin"
    used_indices = set()

    def command(index):
        if type(index) is not int or not 0 <= index < len(commands) or index in used_indices:
            raise ValueError("invalid or repeated original reference command index")
        used_indices.add(index)
        item = commands[index]
        if (not isinstance(item, dict) or type(item.get("returncode")) is not int or item["returncode"] != 0
                or item.get("timed_out") is not False or item.get("cancelled") is not False
                or not isinstance(item.get("argv"), list) or not item["argv"]
                or any(not isinstance(arg, str) for arg in item["argv"]) or not isinstance(item.get("cwd"), str)):
            raise ValueError("original reference command did not complete successfully")
        cleanup = item.get("cleanup", {})
        if os.name == "nt" and not (isinstance(cleanup, dict) and cleanup.get("job_assigned") is True
                and type(cleanup.get("active_after")) is int and cleanup["active_after"] == 0
                and cleanup.get("parent_exit_confirmed") is True and cleanup.get("job_handle_closed") is True):
            raise ValueError("original reference build command cleanup is unverified")
        return item

    objects = []
    for unit in units:
        if (not digest(unit.get("entry_sha256"))
                or any(not isinstance(unit.get(key), str) or not unit[key]
                       for key in ("source", "source_operand", "compiler", "cwd", "object_path", "signature_ir_path"))):
            raise ValueError("original reference translation unit provenance is invalid")
        source = _artifact_path(root, root, unit["source"])
        suffix = source.suffix.lower()
        allowed = {"c": {".c"}, "cpp": {".c", ".cc", ".cpp", ".cxx", ".c++"}, "rust": {".rs"}}[language]
        if suffix not in allowed:
            raise ValueError("original reference translation unit must be owned c/cpp/rust source")
        # The operand is the exact inspected direct source token (abs path).
        if unit["source_operand"] != unit["source"] or "\x00" in unit["source_operand"]:
            raise ValueError("original reference source operand must equal the inspected direct source")
        # Bind the source to the inspected project snapshot and its recorded hash.
        if input_hashes.get(str(source)) != unit["entry_sha256"] or _hash(source) != unit["entry_sha256"]:
            raise ValueError("original reference source differs from the inspected project snapshot")
        watched[str(source)] = unit["entry_sha256"]
        compiler = unit["compiler"]
        # The frontend must be the trusted local toolchain, not a consistently
        # self-declared replacement: clang/clang++ by TU suffix for C/C++ (a .c
        # unit in a cpp project keeps the C frontend), the pinned rustc for Rust.
        if language == "rust":
            if report.get("rustc_sha256") != unit.get("compiler_sha256"):
                raise ValueError("original reference frontend is not the pinned rust toolchain")
        elif compiler != str(llvm_bin / ("clang.exe" if suffix == ".c" else "clang++.exe")):
            raise ValueError("original reference frontend is not the trusted compiler")
        if (not digest(unit.get("compiler_sha256")) or compilers.get(compiler) != unit["compiler_sha256"]
                or tool_hashes.get(compiler) != unit["compiler_sha256"]):
            raise ValueError("original reference translation unit compiler provenance is invalid")
        compiler_file = Path(compiler)
        _no_links(compiler_file)
        if not compiler_file.is_file() or _hash(compiler_file) != unit["compiler_sha256"]:
            raise ValueError("original reference compiler changed or is not a pinned build tool")
        watched[compiler] = unit["compiler_sha256"]
        if unit["cwd"] != str(directory):
            raise ValueError("original reference translation unit must build in the reviewed output directory")
        obj = _artifact_path(root, directory, unit["object_path"])
        signature = _artifact_path(root, directory, unit["signature_ir_path"])
        if obj == signature or obj in objects:
            raise ValueError("original reference outputs must be separate owned files")
        objects.append(obj)
        # Reconstruct the recorded commands with the shared producer recipe helper
        # so one source of truth governs both the builder and this verifier.
        object_argv, signature_argv = native_build._direct_reference_commands(
            language, Path(unit["source"]), compiler, Path(unit["object_path"]), Path(unit["signature_ir_path"]),
            include_dirs=inspected["include_dirs"], defines=inspected["defines"])
        for kind, path, expected_cmd in (("object", obj, object_argv), ("signature_ir", signature, signature_argv)):
            expected_hash = artifact_hashes.get(str(path.relative_to(directory)))
            if not expected_hash or _hash(path) != expected_hash:
                raise ValueError("original reference output differs from recorded artifact hash")
            watched[str(path)] = expected_hash
            record = command(unit.get("object_command_index" if kind == "object" else "signature_ir_command_index"))
            if record["argv"] != expected_cmd or record["cwd"] != str(directory):
                raise ValueError("original reference command differs from the exact direct-source recipe")
    link_contract = value.get("link_contract")
    if (not isinstance(link_contract, dict) or link_contract.get("kind") != "restricted_windows_shared_library"
            or link_contract.get("target") != target or link_contract.get("complete_application_link") is not False):
        raise ValueError("original reference restricted link contract is missing")
    link = command(value.get("link_command_index"))
    for row in (trusted["config"], trusted["tools"]["clangxx"], trusted["tools"]["lld_link"]):
        if tool_hashes.get(row["path"]) != row["sha256"]:
            raise ValueError("original reference link tool pin differs from the trusted local toolchain")
        watched[row["path"]] = row["sha256"]
    definition = _artifact_path(root, directory, directory / "exports.def")
    definition_bytes = _read(definition, 1024 * 1024)
    definition_hash = hashlib.sha256(definition_bytes).hexdigest()
    if (artifact_hashes.get("exports.def") != definition_hash
            or definition_bytes != ("EXPORTS\n" + "\n".join(declared) + "\n").encode("ascii")):
        raise ValueError("original reference link export definition differs from its recorded public contract")
    watched[str(definition)] = definition_hash
    expected_link = [trusted["tools"]["clangxx"]["path"], "-target", target, "-shared", "-fuse-ld=lld",
        *map(str, objects), f"-Wl,/DEF:{definition}", "-Wl,/DEBUG:NONE", "-Wl,/INCREMENTAL:NO",
        "-o", artifacts["original_reference"]["path"]]
    if (link["argv"] != expected_link or link["cwd"] != str(directory)
            or sum(isinstance(record, dict) and record.get("argv") == expected_link for record in commands) != 1):
        raise ValueError("original reference link differs from the unique fixed trusted recipe")
    _verify_reference_signature_binding(report, root, directory, units, trusted, command, watched)
    return {**value, "link_verification": {"status": "fixed_recipe_and_trusted_tools_verified",
        "route": "direct_source", "definition_sha256": definition_hash, "complete_application_link": False,
        "inspected_project_sha256": _reference_digest(inspected),
        "qualification": "Recorded direct-source DLL recipe and current local tool pins checked; not independent execution attestation."}}


def _verify_reply(reply, contract, cases):
    """Reject empty, partial or malformed results before comparing any arm."""
    expected = set(cases)
    if (not isinstance(reply, dict) or set(reply) != {"outputs", "deterministic", "timings"}
            or any(not isinstance(reply[key], dict) or set(reply[key]) != expected
                   for key in ("outputs", "deterministic", "timings"))):
        raise ValueError("worker reply must contain exactly every requested export")
    for function in contract["functions"]:
        name, kind = function["name"], function["return_type"]
        values, timing = reply["outputs"][name], reply["timings"][name]
        bits = int(kind[1:])
        low, high = (0, 2**bits - 1) if kind[0] == "u" else (-2**(bits - 1), 2**(bits - 1) - 1)
        if (not isinstance(values, list) or not values or len(values) != len(cases[name])
                or any(type(value) is not int or not low <= value <= high for value in values)):
            raise ValueError("worker output count/type/range differs from requested ABI cases: " + name)
        if type(reply["deterministic"][name]) is not bool:
            raise ValueError("worker determinism result must be an explicit boolean: " + name)
        if (not isinstance(timing, dict)
                or set(timing) != {"samples_ns", "median_ns", "calls_per_batch", "warmup_batches"}):
            raise ValueError("worker timing record is incomplete: " + name)
        samples, median = timing["samples_ns"], timing["median_ns"]
        if (not isinstance(samples, list) or len(samples) != 7
                or any(type(value) is not int or value < 0 for value in samples)
                or type(median) not in {int, float} or not math.isfinite(median)
                or median != statistics.median(samples)
                or type(timing["calls_per_batch"]) is not int
                or timing["calls_per_batch"] != min(256, len(cases[name]))
                or type(timing["warmup_batches"]) is not int or timing["warmup_batches"] != 1):
            raise ValueError("worker timing count/value differs from requested cases: " + name)
    return reply


def _boundary_inputs_unchanged(watched):
    """Check private evidence and the trusted parser, never follow replacement links."""
    try:
        for name, digest in watched.items():
            path = Path(name)
            _no_links(path)
            if _hash(path) != digest:
                return False
        return True
    except (OSError, ValueError):
        return False


def _cpp_mapping_present(report, coverage):
    """A partial mapping claim must not enter the historical no-replay route."""
    return (any(key in report for key in ("cpp_symbol_mapping", "cpp_symbol_mapping_descriptor",
                "cpp_symbol_link_evidence", "cpp_symbol_coverage", "cpp_symbol_export_sets"))
            or any(key in coverage for key in ("symbol_mapping", "source_selected_functions", "by_source_symbol"))
            or any(isinstance(value, dict) and value.get("symbol_mapping") is not None
                   for value in (report.get("boundary_transit"), coverage.get("boundary_transit"))))


def _verify_cpp_mapping_stages(report, coverage, root, directory, original, protection, final,
                               library, mapping, symbol_map, tools, artifact, watched):
    """Replay a protection-only rename and re-read all three actual VM stages."""
    from . import cpp_symbols, native_build, swift_frontend

    def same(left, right):
        return _reference_digest(left) == _reference_digest(right)

    for module in (cpp_symbols, swift_frontend):
        path = Path(module.__file__).resolve()
        _no_links(path)
        digest = _hash(path)
        if tools.get(str(path)) != digest:
            raise ValueError("C++ mapping/binding source changed since build")
        watched[str(path)] = digest
    closed = mapping.get("link_boundary")
    database = report.get("compilation_database")
    if (not isinstance(closed, dict) or not isinstance(database, dict)
            or closed.get("plan_fingerprint") != database.get("fingerprint")
            or closed.get("workspace_root") != str(root) or closed.get("build_directory") != str(directory)):
        raise ValueError("C++ mapping closed-link plan differs from original-reference provenance")
    hashes = report["artifact_hashes"]

    def stage_file(name):
        path = directory / name
        actual = artifact({"path": str(path), "sha256": hashes.get(name)}, name, {name})
        if actual != path:
            raise ValueError("C++ mapping stage belongs to another native build")
        return actual

    # The original-reference gate ran first and tied this same plan to its
    # private raw compilation DB; also watch it for this independent replay.
    plan_path = stage_file("compile-database-plan.json")
    if not same(_json(_read(plan_path, 16 * 1024 * 1024)), database):
        raise ValueError("C++ mapping saved plan differs from original-reference provenance")
    closed_tools = cpp_symbols._check_trusted_link_tools(closed, root)
    for row in [closed_tools["config"], *closed_tools["tools"].values()]:
        if tools.get(row["path"]) != row["sha256"]:
            raise ValueError("C++ closed-link tool differs from original build pins")
        watched[row["path"]] = row["sha256"]
    modules = closed.get("source_modules")
    units = database.get("translation_units")
    if (not isinstance(modules, list) or not 1 <= len(modules) <= 64
            or not isinstance(units, list) or len(modules) != len(units)):
        raise ValueError("C++ mapping source module inventory is malformed")
    for index, (row, unit) in enumerate(zip(modules, units)):
        name = f"source-{index:03d}.ll"
        if (not isinstance(row, dict) or not isinstance(unit, dict)
                or row.get("source") != unit.get("source") or row.get("entry_sha256") != unit.get("entry_sha256")
                or artifact(row, "mapping source module", {name}) != directory / name):
            raise ValueError("C++ mapping source IR differs from the selected translation unit")
    if artifact(closed.get("raw_ir"), "mapping raw", {"module.raw.ll"}) != directory / "module.raw.ll":
        raise ValueError("C++ mapping raw IR belongs to a different native build")
    if artifact(closed.get("input_ir"), "mapping input", {"module.before.ll"}) != original:
        raise ValueError("C++ mapping input is not the reviewed original IR")
    commands = report.get("commands")
    if not isinstance(commands, list):
        raise ValueError("C++ mapping build commands are missing")
    for key in ("module_link_record", "canonicalize_record"):
        record = closed.get(key)
        if not isinstance(record, dict) or not isinstance(record.get("argv"), list):
            raise ValueError("C++ closed-link command record is malformed")
        matches = [item for item in commands if isinstance(item, dict) and item.get("argv") == record["argv"]]
        if len(matches) != 1 or not same(matches[0], record):
            raise ValueError("C++ closed-link command is not a unique exact build record")
    # The mapper itself revalidates exact compiler paths/argv and strict Job
    # cleanup against the caller's local configuration before loading LLVM.
    replay_bytes, replay_mapping = cpp_symbols.remap_protection_symbols(
        _read(original, cpp_symbols.MAX_IR), selected_symbols=sorted(symbol_map),
        exported_symbols=coverage["exported_functions"], llvm_library=library,
        link_boundary=closed, workspace_root=root)
    if replay_bytes != _read(protection, cpp_symbols.MAX_IR) or not same(replay_mapping, mapping):
        raise ValueError("C++ symbol mapping cannot be reproduced from the original scope/IR")
    vm_ir, diversified_ir = stage_file("module.after.ll"), stage_file("core.diversified.ll")
    diversification = _json(_read(stage_file("diversification.json"), 16 * 1024 * 1024))
    targets = sorted(symbol_map.values())
    stages = {
        "post_vm": native_build._vm_evidence(_read(vm_ir, 32 * 1024 * 1024).decode("utf-8"), targets, "kagura_vm_execute"),
        "diversified": native_build._manifest_vm_evidence(_read(diversified_ir, 32 * 1024 * 1024).decode("utf-8"), targets, diversification),
        "final_codegen": native_build._manifest_vm_evidence(_read(final, 32 * 1024 * 1024).decode("utf-8"), targets, diversification),
    }
    by_source = cpp_symbols.bind_coverage(replay_mapping, **stages)
    if (not same(by_source, coverage.get("by_source_symbol"))
            or not same(by_source, report.get("cpp_symbol_coverage"))
            or not same(stages["post_vm"], coverage.get("original_vm"))
            or not same(stages["diversified"], coverage["functions"])
            or not same(stages["final_codegen"], coverage.get("final_vm"))):
        raise ValueError("C++ mapped coverage differs from actual recorded VM stages")
    definition = stage_file("exports.def")
    matches = [item for item in commands
               if isinstance(item, dict) and item.get("argv") == closed.get("protected_link_argv")]
    if len(matches) != 1:
        raise ValueError("C++ mapping requires exactly one fixed protected-link command")
    protected = _artifact_path(root, directory, report["artifacts"]["protected"]["path"])
    if protected != directory / "protected.dll":
        raise ValueError("C++ protected artifact differs from fixed link output")
    link_evidence = cpp_symbols.verify_final_link(closed, matches[0], _read(protected, 128 * 1024 * 1024),
                                                 _read(definition, 1024 * 1024), workspace_root=root)
    if not same(link_evidence, report.get("cpp_symbol_link_evidence")):
        raise ValueError("C++ fixed link/export evidence differs")
    return {"status": "replayed_and_vm_stages_verified", "source_to_protected": symbol_map,
            "link_evidence": link_evidence,
            "qualification": "Exact linked LLVM identities, not demangled source declarations or whole-C++ protection."}


def _verify_boundary_transit(report, coverage, root, directory, signature_ir, watched):
    """Recompute schema-2 forwarding evidence before any target library executes.

    Hashes bind the recorded artifacts, not a hostile-operator attestation. The
    loaded library is selected only by the local toolchain configuration; an IR
    descriptor cannot choose native code to load into the validation process.
    """
    def same_json(left, right):
        # Python equality treats True == 1; a recorded contract must preserve
        # JSON value types as well as apparent numeric values.
        return _reference_digest(left) == _reference_digest(right)

    native_report_descriptor = None
    if "native_report" in report or "native_report_sha256" in report:
        if _cpp_mapping_present(report, coverage):
            raise ValueError("C++ symbol mapping is not a composed-frontend backend")
        value = report.get("native_report")
        if not isinstance(value, str):
            raise ValueError("composed frontend native report descriptor is missing")
        native_path = _artifact_path(root, directory, value)
        if native_path != directory / "native" / "report.json":
            raise ValueError("composed frontend must reference its fixed private native/report.json")
        native_bytes = _read(native_path, 16 * 1024 * 1024)
        digest = hashlib.sha256(native_bytes).hexdigest()
        if digest != report.get("native_report_sha256"):
            raise ValueError("composed frontend native report hash differs")
        if "artifact_hashes" in report:
            hashes = report["artifact_hashes"]
            # New frontend inventories use canonical slash keys. Preserve the
            # exact historical Windows spelling, but reject ambiguous aliases
            # even when both claim the same digest. The file path above remains
            # confined to the fixed native/report.json before either lookup.
            keys = {"native/report.json", "native\\report.json"}
            present = keys.intersection(hashes) if isinstance(hashes, dict) else set()
            if len(present) != 1 or hashes[next(iter(present))] != digest:
                raise ValueError("composed frontend native report differs from artifact hashes")
        native = _json(native_bytes)
        if (not isinstance(native, dict) or native.get("status") != "artifact_created_unvalidated"
                or "native_report" in native or "native_report_sha256" in native
                or not same_json(native.get("coverage"), coverage)
                or not same_json(native.get("artifacts"), report.get("artifacts"))):
            raise ValueError("composed frontend coverage/artifacts differ from its native report")
        native_hashes = native.get("artifact_hashes")
        signature = report.get("signature_ir")
        if (not isinstance(native_hashes, dict) or not isinstance(signature, dict)
                or signature_ir != native_path.parent / "module.before.ll"
                or signature.get("sha256") != native_hashes.get("module.before.ll")):
            raise ValueError("composed frontend signature differs from its native report")
        for key in ("coverage_schema_version", "boundary_transit"):
            if key in report and not same_json(report[key], native.get(key)):
                raise ValueError("composed frontend boundary metadata differs from its native report")
        watched[str(native_path)] = digest
        native_report_descriptor = {"path": str(native_path), "sha256": digest}
        report, coverage, directory = native, native["coverage"], native_path.parent
    version = coverage.get("schema_version", 1)
    mapping_present = _cpp_mapping_present(report, coverage)
    if mapping_present and (type(version) is not int or version != 2 or native_report_descriptor is not None):
        raise ValueError("C++ mapping requires native coverage schema 2 without a composed frontend")
    marker = report.get("coverage_schema_version", version)
    if type(version) is not int or version not in (1, 2) or type(marker) is not int or marker != version:
        raise ValueError("unsupported or inconsistent native coverage schema")
    if version == 1:
        if "boundary_transit" in report or "boundary_transit" in coverage:
            raise ValueError("boundary transit evidence requires coverage schema 2")
        return {"status": "legacy_unverified", "coverage_schema_version": 1,
                "qualification": "Historical coverage; parsed boundary transit was not independently verified."}
    descriptor = report.get("boundary_transit")
    if (not isinstance(descriptor, dict) or not same_json(descriptor, coverage.get("boundary_transit"))
            or not {"schema_version", "status", "contract", "evidence", "original_ir", "business_ir",
                    "boundary_ir", "final_ir"}.issubset(descriptor)
            or type(descriptor.get("schema_version")) is not int or descriptor["schema_version"] != 1):
        raise ValueError("schema 2 requires identical report and coverage boundary transit descriptors")
    artifact_hashes = report.get("artifact_hashes")
    if not isinstance(artifact_hashes, dict):
        raise ValueError("boundary transit artifact hashes are missing")

    def artifact(record, label, names):
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            raise ValueError("boundary transit IR descriptor is missing: " + label)
        path = _artifact_path(root, directory, record["path"])
        if path.name not in names:
            raise ValueError("unexpected boundary transit artifact name: " + label)
        digest = hashlib.sha256(_read(path, 32 * 1024 * 1024)).hexdigest()
        if (digest != record.get("sha256")
                or artifact_hashes.get(str(path.relative_to(directory))) != digest):
            raise ValueError("boundary transit artifact hash differs: " + label)
        watched[str(path)] = digest
        return path

    names = sorted(coverage.get("public_boundaries", {}))
    if set(names) & set(coverage["functions"]):
        raise ValueError("boundary transit and selected VM functions must be disjoint")
    for name in names:
        state = coverage["public_boundaries"][name]
        if state.get("defined") is not True or state.get("virtualized") is not False:
            raise ValueError("boundary transit requires defined non-VM public boundaries")
    original = artifact(descriptor.get("original_ir"), "original", {"module.before.ll"})
    if original != signature_ir:
        raise ValueError("boundary transit original differs from the reviewed signature IR")
    mapping = report.get("cpp_symbol_mapping")
    mapping_descriptor = report.get("cpp_symbol_mapping_descriptor")
    symbol_map, source_selected = {}, set(coverage["functions"])
    protection = artifact(descriptor.get("protection_ir", descriptor["original_ir"]), "protection",
                          {"module.symbol-mapped.ll"} if mapping_present else {"module.before.ll"})
    if mapping_present:
        if (report.get("backend") != "compile_database_native" or not isinstance(mapping, dict)
                or not same_json(mapping_descriptor, descriptor.get("symbol_mapping"))
                or not same_json(mapping_descriptor, coverage.get("symbol_mapping"))):
            raise ValueError("C++ mapping requires one consistent native compile-database descriptor")
        mapping_path = artifact(mapping_descriptor, "symbol mapping", {"cpp-symbol-mapping.json"})
        if not same_json(_json(_read(mapping_path, 16 * 1024 * 1024)), mapping):
            raise ValueError("C++ mapping sidecar differs from embedded evidence")
        sources, rows = mapping.get("source_selected_functions"), mapping.get("functions")
        if (not isinstance(sources, list) or not 1 <= len(sources) <= 64
                or any(not isinstance(name, str) or not name for name in sources)
                or len(set(sources)) != len(sources) or not isinstance(rows, dict) or set(rows) != set(sources)):
            raise ValueError("C++ source mapping set is malformed")
        for name, row in rows.items():
            if (not isinstance(row, dict) or row.get("source_symbol") != name
                    or not isinstance(row.get("protected_symbol"), str)
                    or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", row["protected_symbol"])):
                raise ValueError("C++ source/protected symbol mapping is malformed")
            symbol_map[name] = row["protected_symbol"]
        source_selected = set(sources)
        if (len(set(symbol_map.values())) != len(symbol_map)
                or set(symbol_map.values()) != set(coverage["functions"])
                or not same_json(mapping.get("protected_selected_functions"), sorted(symbol_map.values()))
                or not same_json(coverage.get("source_selected_functions"), sorted(source_selected))
                or mapping.get("input_sha256") != _hash(original)
                or mapping.get("output_sha256") != _hash(protection)
                or any(symbol_map.get(name, name) != name for name in [*names, *coverage["exported_functions"]])):
            raise ValueError("C++ source scope and protected VM scope are not a public-identity bijection")
    business = artifact(descriptor.get("business_ir"), "business",
                        {"module.protection-business.ll"} if names else
                        ({"module.symbol-mapped.ll"} if mapping_present else {"module.before.ll", "module.protection-input.ll"}))
    final = artifact(descriptor.get("final_ir"), "final", {"protected.codegen.ll"})
    paths = [original, protection, business, final]
    if mapping_present:
        paths.append(mapping_path)
        if not names and business != protection:
            raise ValueError("No-boundary mapped build must use the mapped module as business input")
    if names:
        paths.append(artifact(descriptor.get("boundary_ir"), "boundary", {"module.public-boundaries.ll"}))
    elif descriptor.get("boundary_ir") is not None:
        raise ValueError("no-boundary build must have a null boundary IR descriptor")
    if any(path.parent != original.parent for path in paths):
        raise ValueError("boundary transit IR must belong to the same native build")

    # Persisted coverage is another watched sidecar; a top-level composed
    # frontend may add fields, but cannot substitute different native evidence.
    coverage_path = original.parent / "coverage.json"
    persisted_path = artifact({"path": str(coverage_path),
                               "sha256": artifact_hashes.get(str(coverage_path.relative_to(directory)))},
                              "coverage", {"coverage.json"})
    persisted = _json(_read(persisted_path, 16 * 1024 * 1024))
    if not isinstance(persisted, dict) or any(not same_json(persisted.get(key), coverage.get(key)) for key in (
            "schema_version", "boundary_transit", "functions", "selected_functions",
            "exported_functions", "public_boundaries", "scope_plan", "symbol_mapping",
            "source_selected_functions", "by_source_symbol")):
        raise ValueError("persisted native coverage differs from the report")

    from . import native_build, scope
    plan = coverage.get("scope_plan")
    expected_calls = None
    if plan is not None:
        if not isinstance(plan, dict) or not isinstance(plan.get("policy"), dict):
            raise ValueError("boundary transit requires a valid recorded scope plan")
        derived_scope = scope.analyze_scope([original], plan["policy"], mode=plan.get("mode"))
        expected_calls = derived_scope["graph"]["calls"]
        if (derived_scope["status"] != "ready" or plan.get("status") != "ready"
                or plan.get("graph", {}).get("calls") != expected_calls
                or set(derived_scope["selected_functions"]) != source_selected
                or set(plan.get("selected_functions", [])) != source_selected
                or sorted(set(derived_scope["boundary_functions"]) - source_selected) != names):
            raise ValueError("boundary transit scope differs from the original IR")
    elif names or mapping_present:
        raise ValueError("public boundaries require the original reviewed scope graph")

    # Do not accept a report-supplied parser path. Pin configuration and library
    # against the build's trusted-tool record before the first LLVM load.
    config_path = root / ".tools" / "kagura-toolchain.json"
    _no_links(config_path)
    config_bytes = _read(config_path, 1024 * 1024)
    config = _json(config_bytes)
    if not isinstance(config, dict) or not isinstance(config.get("llvm_root"), str):
        raise ValueError("missing local LLVM parser configuration")
    llvm_root = Path(config["llvm_root"])
    if not llvm_root.is_absolute():
        raise ValueError("local LLVM parser root must be absolute")
    library = llvm_root / "bin" / "LLVM-C.dll"
    _no_links(library)
    if not library.is_file():
        raise ValueError("local LLVM parser library is missing")
    tools = report.get("tool_hashes")
    trusted = {str(config_path): hashlib.sha256(config_bytes).hexdigest(), str(library): _hash(library)}
    if not isinstance(tools, dict) or any(tools.get(path) != digest for path, digest in trusted.items()):
        raise ValueError("local LLVM parser/config hash differs from the build tool pins")
    watched.update(trusted)
    mapping_evidence = None
    if mapping_present:
        mapping_evidence = _verify_cpp_mapping_stages(report, coverage, root, directory, original, protection,
                                                     final, library, mapping, symbol_map, tools, artifact, watched)
    derived_contract = native_build._boundary_contract(original, names, library, expected_calls=expected_calls)
    if not same_json(descriptor.get("contract"), derived_contract):
        raise ValueError("boundary transit contract differs from original parsed IR")
    if mapping_present:
        native_build._boundary_transit_evidence(protection, derived_contract, library, symbol_map=symbol_map)
        evidence = native_build._boundary_transit_evidence(final, derived_contract, library, symbol_map=symbol_map)
    else:
        evidence = native_build._boundary_transit_evidence(final, derived_contract, library)
    if not same_json(descriptor.get("evidence"), evidence) or descriptor.get("status") != evidence["status"]:
        raise ValueError("boundary transit evidence differs from final parsed IR")
    if not _boundary_inputs_unchanged(watched):
        raise ValueError("boundary transit evidence changed while parsing")
    return {"status": evidence["status"], "coverage_schema_version": 2,
            "contract": derived_contract, "evidence": evidence,
            "native_report": native_report_descriptor,
            "cpp_symbol_mapping": mapping_evidence,
            "evidence_hashes": dict(watched),
            "qualification": "Original and final parsed forwarding relation verified; not whole-program semantics or attack resistance."}


def validate_build(report_path, contract_path, output_dir, *, workspace_root,
                   random_cases=8192, seed=20261020, timeout_seconds=120):
    root = Path(os.path.abspath(workspace_root))
    report_path = Path(os.path.abspath(report_path))
    output = Path(os.path.abspath(output_dir))
    for path in (root, report_path, output):
        _no_links(path)
    if not report_path.is_relative_to(root) or not output.is_relative_to(root):
        raise ValueError("validation inputs/outputs must stay inside workspace")
    if any(part.casefold() in {"rea-analysis-reports", "attackerfolder"}
           for path in (report_path, output) for part in path.relative_to(root).parts):
        raise ValueError("untrusted/shared validation path")
    if output.exists():
        raise ValueError("validation output must be a fresh directory")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
        raise ValueError("timeout_seconds must be an integer in 1..600")
    from .projects import ProjectService
    contract_path = ProjectService(root)._owned(contract_path)
    contract_bytes = _read(contract_path, 256 * 1024)
    contract = validate_contract(_json(contract_bytes))
    cases = make_cases(contract, random_cases, seed)
    report_bytes = _read(report_path, 16 * 1024 * 1024)
    report = _json(report_bytes)
    if not isinstance(report, dict) or report.get("status") != "artifact_created_unvalidated":
        raise ValueError("only a successful owned native build can be validated")
    coverage = report.get("coverage", {})
    if not isinstance(coverage, dict):
        raise ValueError("invalid native coverage record")
    functions = coverage.get("functions", {})
    if (not isinstance(functions, dict) or not functions
            or any(not isinstance(name, str) or not name or not isinstance(entry, dict)
                   or entry.get("virtualized") is not True for name, entry in functions.items())):
        raise ValueError("all selected internal functions require VM coverage")
    if "selected_functions" in coverage:
        vm_selected = coverage["selected_functions"]
        if (not isinstance(vm_selected, list)
                or any(not isinstance(name, str) or not name for name in vm_selected)
                or len(set(vm_selected)) != len(vm_selected) or set(vm_selected) != set(functions)):
            raise ValueError("selected internal function list must exactly match verified VM coverage")
    exports = coverage.get("exported_functions", list(functions))
    boundaries = coverage.get("public_boundaries", {})
    if (not isinstance(boundaries, dict)
            or any(not isinstance(name, str) or not name or not isinstance(entry, dict)
                   for name, entry in boundaries.items())):
        raise ValueError("invalid public boundary coverage")
    selected = {f["name"] for f in contract["functions"]}
    if (not isinstance(exports, list) or any(not isinstance(name, str) for name in exports)
            or len(set(exports)) != len(exports) or set(exports) != selected
            or not selected.issubset(set(functions) | {name for name, entry in boundaries.items()
                                                     if entry.get("defined") is True and entry.get("virtualized") is False})):
        raise ValueError("contract must observe every verified export; all selected internal functions require VM coverage")
    signature = report.get("signature_ir")
    if signature is not None:
        if not isinstance(signature, dict):
            raise ValueError("invalid signature IR provenance")
        original_ir = _artifact_path(root, report_path.parent, signature.get("path", ""))
        expected_ir_hash = signature.get("sha256")
    else:
        original_ir = report_path.parent / "module.before.ll"
        expected_ir_hash = report.get("artifact_hashes", {}).get("module.before.ll")
    original_ir_bytes = _read(original_ir, 16 * 1024 * 1024)
    if not expected_ir_hash or hashlib.sha256(original_ir_bytes).hexdigest() != expected_ir_hash:
        raise ValueError("original signature IR is missing or differs from build hash")
    abi_evidence = verify_integer_abi(original_ir_bytes.decode("utf-8-sig"), contract)
    # The three-arm requirement derives from the bound project route, not an
    # optional/forgeable flag: a direct native source build (inspected project
    # language c/cpp/rust) requires its independent source reference even with no
    # backend field, while compile_database keeps its own existing verifier.
    # Composed frontends (non-native top-level language, e.g. go/jvm/dotnet/swift
    # or script lowerings) and the llvm_ir handoff keep their two-arm behavior.
    project = report.get("project")
    # Classify the manifest BEFORE demanding direct-source artifacts. Composed
    # frontends also have manifests, but compare their original runtime separately.
    # Neither a forged backend nor a forged recorded language exempts a native manifest.
    route_hashes = {}
    native_languages = {"c", "cpp", "rust"}
    direct_native_route = isinstance(project, dict) and project.get("language") in native_languages
    if isinstance(project, dict) and isinstance(project.get("project_path"), str):
        manifest = _artifact_path(root, root, project["project_path"])
        manifest_bytes = _read(manifest, 1024 * 1024)
        manifest_value = _json(manifest_bytes)
        if not isinstance(manifest_value, dict):
            raise ValueError("original reference route requires a project manifest object")
        direct_native_route = direct_native_route or manifest_value.get("language") in native_languages
        route_hashes[str(manifest)] = hashlib.sha256(manifest_bytes).hexdigest()
    reference_required = report.get("backend") == "compile_database_native" or direct_native_route
    required_arms = ("original_reference", "baseline", "protected") if reference_required else ("baseline", "protected")
    signature_hashes = {str(original_ir): expected_ir_hash, **route_hashes}
    reference_abi = None
    reference_signature = None
    if reference_required:
        reference_signature = report.get("original_reference_signature_ir")
        if not isinstance(reference_signature, dict):
            raise ValueError("this build requires an original reference signature IR")
        reference_ir = _artifact_path(root, report_path.parent, reference_signature.get("path", ""))
        reference_bytes = _read(reference_ir, 16 * 1024 * 1024)
        reference_hash = reference_signature.get("sha256")
        if not reference_hash or hashlib.sha256(reference_bytes).hexdigest() != reference_hash:
            raise ValueError("original reference signature IR differs from build hash")
        if reference_ir == original_ir:
            raise ValueError("original reference must have separate source-compiled signature IR")
        reference_abi = verify_integer_abi(reference_bytes.decode("utf-8-sig"), contract)
        signature_hashes[str(reference_ir)] = reference_hash
    artifacts = {}
    report_artifacts = report.get("artifacts")
    if not isinstance(report_artifacts, dict):
        raise ValueError("native artifact records are missing")
    for arm in required_arms:
        artifact = report_artifacts.get(arm)
        if not isinstance(artifact, dict) or not artifact.get("path"):
            raise ValueError("required native artifact is missing: " + arm)
        path = _artifact_path(root, report_path.parent, artifact.get("path", ""))
        if _hash(path) != artifact.get("sha256"):
            raise ValueError("artifact hash differs from reviewed build")
        if "bytes" in artifact and (type(artifact["bytes"]) is not int or artifact["bytes"] != path.stat().st_size):
            raise ValueError("artifact byte count differs from reviewed build: " + arm)
        artifacts[arm] = {"path": str(path), "sha256": artifact["sha256"], "bytes": path.stat().st_size}
    if reference_required and len({entry["path"] for entry in artifacts.values()}) != len(artifacts):
        raise ValueError("original reference, baseline and protected must be separate owned artifacts")
    reference_evidence_hashes = {}
    if not reference_required:
        reference_provenance = None
    elif report.get("backend") == "compile_database_native":
        reference_provenance = _verify_reference_provenance(report, root, report_path.parent, selected, artifacts, reference_evidence_hashes)
    else:
        reference_provenance = _verify_direct_reference_provenance(report, root, report_path.parent, selected, artifacts, reference_evidence_hashes)
    boundary_evidence_hashes = {}
    boundary_evidence = _verify_boundary_transit(report, coverage, root, report_path.parent,
                                                original_ir, boundary_evidence_hashes)
    stop = root / ".runs" / "defense-loop" / "STOP"
    if stop.exists():
        return {"status": "cancelled", "reason": "defense STOP exists"}
    output.mkdir(parents=True)
    result = {"schema_version": 1, "status": "failed", "artifacts": artifacts,
              "build_report_sha256": hashlib.sha256(report_bytes).hexdigest(),
              "contract_sha256": hashlib.sha256(contract_bytes).hexdigest(),
              "abi_evidence": abi_evidence, "signature_ir_sha256": expected_ir_hash,
              "boundary_transit": boundary_evidence,
              "required_arms": list(required_arms), "original_reference_required": reference_required,
              "case_set_sha256": hashlib.sha256(json.dumps(cases, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
              "worker_launch": {"package_root": str(Path(__file__).absolute().parents[1]),
                                "python_executable": sys.executable,
                                "isolated_imports": True, "site_hooks_disabled": True},
              "cases_per_function": {name: len(value) for name, value in cases.items()},
              "random_cases_per_function": random_cases, "seed": seed, "behavior_repeats": 2,
              "execution": {}, "functions": {}, "external_attack_evaluation": "not_evaluated",
              "limitations": ["Native code executes in a bounded child process, not a security sandbox.",
                              "Sampled returned integers and determinism only; side effects and all inputs are not proven.",
                              "LLVM widths/arity/C calling convention checked; signed interpretation comes from the user contract.",
                              "Timing includes Python/ctypes call overhead, excludes process startup and library load.",
                              "Seven batches per arm; separate worker runs are not an interleaved performance experiment.",
                              "No speed acceptance threshold or attack-resistance result is inferred."]}
    if reference_required:
        result["validation_backend"] = "original_compilation_reference_and_native_comparison"
        result["original_reference_abi_evidence"] = reference_abi
        result["original_reference_signature_ir"] = reference_signature
        result["original_reference_provenance"] = reference_provenance
        result["original_reference_evidence_hashes"] = reference_evidence_hashes
        result["limitations"].append("Original compilation reference is a separately source-compiled DLL, not proof of full application/link semantics.")
    try:
        replies = {}
        for arm, artifact in artifacts.items():
            if not _boundary_inputs_unchanged(boundary_evidence_hashes):
                raise ValueError("boundary transit inputs changed before native worker execution")
            request = {"workspace_root": str(root), "build_directory": str(report_path.parent),
                       "library_path": artifact["path"], "sha256": artifact["sha256"],
                       "contract": contract, "random_cases": random_cases, "seed": seed}
            request_path = output / (arm + ".request.json")
            _save(request_path, request)
            process = run_logged(_worker_command(request_path),
                                 root, output / arm, timeout_seconds, cancel_file=stop)
            result["execution"][arm] = process
            if process.get("returncode") != 0 or process.get("cancelled") or process.get("timed_out"):
                if process.get("cancelled"):
                    result["status"] = "cancelled"
                elif process.get("timed_out"):
                    result["status"] = "timed_out"
                raise ValueError(arm + " worker failed, timed out or was cancelled")
            cleanup = process.get("cleanup", {})
            if os.name == "nt" and not (cleanup.get("job_assigned") and cleanup.get("active_after") == 0
                                         and cleanup.get("parent_exit_confirmed") and cleanup.get("job_handle_closed")):
                raise ValueError("worker cleanup could not be verified")
            replies[arm] = _verify_reply(
                _json(_read(request_path.with_suffix(".reply.json"), 32 * 1024 * 1024)), contract, cases)
        for name, vectors in cases.items():
            baseline, protected = replies["baseline"], replies["protected"]
            a, b = baseline["outputs"][name], protected["outputs"][name]
            match = len(a) == len(b) == len(vectors) and a == b
            deterministic = all(replies[arm]["deterministic"][name] for arm in required_arms)
            base_ns, protected_ns = baseline["timings"][name]["median_ns"], protected["timings"][name]["median_ns"]
            result["functions"][name] = {"sampled_output_match": match, "deterministic": deterministic,
                                         "cases": len(vectors), "baseline_timing": baseline["timings"][name],
                                         "protected_timing": protected["timings"][name],
                                         "slowdown_ratio": protected_ns / base_ns if base_ns else None}
            if reference_required:
                reference_values = replies["original_reference"]["outputs"][name]
                comparisons = {
                    arm: {"matched": sum(left == right for left, right in zip(reference_values, replies[arm]["outputs"][name])),
                          "total": len(vectors)}
                    for arm in ("baseline", "protected")}
                result["functions"][name].update(
                    original_reference_match=all(item["matched"] == item["total"] for item in comparisons.values()),
                    original_reference_comparisons=comparisons,
                    original_reference_timing=replies["original_reference"]["timings"][name])
        unchanged = (hashlib.sha256(_read(report_path, 16 * 1024 * 1024)).hexdigest() == result["build_report_sha256"]
                     and hashlib.sha256(_read(contract_path, 256 * 1024)).hexdigest() == result["contract_sha256"]
                     and all(_hash(Path(a["path"])) == a["sha256"] for a in artifacts.values())
                     and all(hashlib.sha256(_read(Path(path), 16 * 1024 * 1024)).hexdigest() == digest
                             for path, digest in signature_hashes.items())
                     and all(_hash(Path(path)) == digest for path, digest in reference_evidence_hashes.items()))
        unchanged = unchanged and _boundary_inputs_unchanged(boundary_evidence_hashes)
        passed = (unchanged and set(result["functions"]) == selected and bool(result["functions"])
                  and all(item["sampled_output_match"] and item["deterministic"]
                          and (not reference_required or item["original_reference_match"])
                          for item in result["functions"].values()))
        result["status"] = "functional_samples_passed" if passed else "failed"
        result["inputs_unchanged"] = unchanged
    except Exception as exc:
        result["error"] = type(exc).__name__ + ": " + str(exc)[:2048]
    result["boundary_transit_inputs_unchanged"] = _boundary_inputs_unchanged(boundary_evidence_hashes)
    if not result["boundary_transit_inputs_unchanged"]:
        result["inputs_unchanged"] = False
        if result["status"] not in {"timed_out", "cancelled"}:
            result["status"] = "failed"
    if stop.exists():
        result["status"] = "cancelled"
    _save(output / "validation.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path, required=True)
    args = parser.parse_args()
    request = _json(_read(args.worker, 32 * 1024 * 1024))
    # Native constructors/functions may write stdout. Keep that as a log, not
    # the result protocol, and never overwrite a reply from an earlier worker.
    result_path = args.worker.with_suffix(".reply.json")
    _save(result_path, _worker_run(request))
    print(json.dumps({"status": "worker_completed", "result_path": str(result_path)}))


if __name__ == "__main__":
    main()
