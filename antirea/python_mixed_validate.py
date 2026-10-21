"""Explicit sampled application validation of owned mixed-module Python VM builds.

A mixed-module build replaces only selected integer/bool function bodies with a
custom-VM backend while preserving every surrounding import, statement and UI
function byte-for-byte. Importing such a module therefore runs ordinary owned
application startup. The scalar pure-source validator (python_validate) loads a
single file with no package context and must never be used to authorize that
import. This module is that separate, explicit authority: it imports the owned
original and protected modules inside their preserved package context, in fresh
separate child processes, and compares the value/type/exception results of the
declared selected (and optionally preserved) scalar entrypoints.

Children execute owned original and protected code, not received artifacts. The
process boundary provides timeouts, logs and best-effort tree cleanup, not an OS
security sandbox. Sampling is not all-input or full-semantic equivalence, is not
a performance threshold and is not evidence of external attack resistance.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
from importlib.machinery import SourceFileLoader
import json
import keyword
import os
from pathlib import Path
import statistics
import sys
import time

from .native_validate import _artifact_path, _hash, _save
from .process import run_logged
from .protectors import _json, _no_links, _read
from .script_validation_evidence import compare_repeated_observations
from . import python_validate as pv


BACKEND = "python_mixed_module_vm"
MODE = "mixed_module"
CONTRACT_KIND = "python_mixed_module_application_samples"

MAX_ENTRYPOINTS = 32
MAX_PARAMETERS = pv.MAX_PARAMETERS
MAX_MODULE_CHARS = 512
MAX_COMPONENT_CHARS = 128
MAX_PACKAGE_FILES = 1024
MAX_PACKAGE_ENTRIES = 4096
MAX_PACKAGE_DEPTH = 24
MAX_PACKAGE_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024

LIMITATIONS = [
    "Importing owned mixed modules runs arbitrary ordinary application startup in child processes; this is not an OS security sandbox.",
    "Only the declared scalar int/bool entrypoint value/type/exception results are compared; stdout, side effects, strings, objects, UI text and exception messages/tracebacks are not.",
    "Import and UI preservation evidence is limited to a successful package-context import plus identical public surface and identical declared signatures across both arms.",
    "Package staging copies owned source bytes into a fresh private tree; it is not a hermetic build/runtime environment and does not pin interpreter, standard library or operating-system state.",
    "Sampled random/edge vectors are not all-input or full-semantic equivalence, performance acceptance, or external attack resistance.",
    "Module-origin binding checks the imported file path, SHA-256 and that the target was loaded by the standard source file loader; it does not independently prove the protected body dispatches the VM rather than equivalent ordinary code.",
    "Timing includes Python call/observation overhead and excludes import/startup; no performance threshold is inferred.",
    "The target module must be a regular package member loaded by the standard source file loader from the bound file; namespace packages and non-source loaders for the target are rejected.",
    "Dynamic import-hook manipulation (sys.meta_path/sys.path_hooks) and re-imports of modules already present in sys.modules by the owned application are neither sandboxed nor fully verified; dropping the antirea checkout from the child sys.path only reduces the new-import surface and does not unload already-loaded modules.",
    "The owned package tree is bounded by file, entry, depth and byte budgets and is bound to the originating source-plan snapshot; this is input-size containment, not an OS security sandbox.",
    "baseline.py, reports, staged trees and evidence are defender-private and must not be delivered to attackers.",
    "No claim of arbitrary Python semantics coverage or native Kagura parity.",
]

# Resolved once from the installed scalar validator so the worker command and
# subject isolation do not depend on this candidate file's on-disk location.
_ANTIREA_ROOT = Path(pv.__file__).absolute().parents[1]
_THIS_FILE = Path(__file__).absolute()

_WORKER_BOOTSTRAP = """\
import importlib.util, sys
antirea_root = sys.argv.pop(1)
module_file = sys.argv.pop(1)
sys.path.insert(0, antirea_root)
import antirea
spec = importlib.util.spec_from_file_location("antirea.python_mixed_validate", module_file)
module = importlib.util.module_from_spec(spec)
sys.modules["antirea.python_mixed_validate"] = module
setattr(antirea, "python_mixed_validate", module)
spec.loader.exec_module(module)
module.main()
"""


def _hex64(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _component(value):
    return (isinstance(value, str) and 0 < len(value) <= MAX_COMPONENT_CHARS
            and value.isascii() and value.isidentifier() and not keyword.iskeyword(value))


# ---------------------------------------------------------------------------
# Contract
# ---------------------------------------------------------------------------

def _entrypoint_contracts(value, label):
    if not isinstance(value, list) or len(value) > MAX_ENTRYPOINTS:
        raise ValueError(label + " must be a list of at most 32 entrypoint contracts")
    names, functions = set(), []
    for function in value:
        if not isinstance(function, dict) or set(function) != {"name", "parameters"}:
            raise ValueError(label + " contracts require name and parameters only")
        name = function["name"]
        if not pv._identifier(name) or len(name) > MAX_COMPONENT_CHARS or name.startswith(("_ar_", "_arm_", "__")):
            raise ValueError(label + " name must be an ordinary non-reserved Python identifier")
        if name in names:
            raise ValueError("entrypoint names must be unique across selected and preserved entrypoints")
        names.add(name)
        parameters = function["parameters"]
        if not isinstance(parameters, list) or len(parameters) > MAX_PARAMETERS:
            raise ValueError(label + " parameters must contain at most 16 scalar integer ranges")
        seen = set()
        for parameter in parameters:
            if not isinstance(parameter, dict) or set(parameter) != {"name", "minimum", "maximum"}:
                raise ValueError("parameter contracts require name, minimum and maximum only")
            if not pv._identifier(parameter["name"]) or parameter["name"] in seen:
                raise ValueError("parameter name must be a unique ordinary Python identifier")
            seen.add(parameter["name"])
            lo, hi = parameter["minimum"], parameter["maximum"]
            if (type(lo) is not int or type(hi) is not int or lo > hi
                    or max(abs(lo).bit_length(), abs(hi).bit_length()) > pv.MAX_BOUND_BITS):
                raise ValueError("invalid integer sample bounds (maximum 256 bits)")
        functions.append({"name": name, "parameters": parameters})
    return names, functions


def validate_application_contract(contract):
    """Validate the explicit mixed-module application sampling contract.

    This is a bounded, structured selected-entrypoint sampling contract; it never
    carries a shell command, a test command or an arbitrary module entry point.
    """
    if not isinstance(contract, dict) or set(contract) != {
            "schema_version", "kind", "module", "entrypoints", "preserved_entrypoints"}:
        raise ValueError("mixed application contract requires schema_version, kind, module, "
                         "entrypoints and preserved_entrypoints only")
    if type(contract["schema_version"]) is not int or contract["schema_version"] != 1:
        raise ValueError("mixed application contract schema_version must be 1")
    if contract["kind"] != CONTRACT_KIND:
        raise ValueError("mixed application validation requires kind " + CONTRACT_KIND
                         + ", not a scalar pure-source or native ABI contract")
    module = contract["module"]
    if (not isinstance(module, str) or not 0 < len(module) <= MAX_MODULE_CHARS
            or not all(_component(part) for part in module.split("."))):
        raise ValueError("module must be a dotted path of ordinary Python package/module identifiers")
    selected_names, selected = _entrypoint_contracts(contract["entrypoints"], "entrypoints")
    if not selected:
        raise ValueError("at least one selected entrypoint must be sampled")
    preserved_names, preserved = _entrypoint_contracts(contract["preserved_entrypoints"], "preserved_entrypoints")
    if selected_names & preserved_names:
        raise ValueError("an entrypoint cannot be both selected and preserved")
    if len(selected) + len(preserved) > MAX_ENTRYPOINTS:
        raise ValueError("total sampled entrypoints exceed the supported limit")
    return contract


def _scalar_like(contract):
    """Reuse the frozen scalar contract/case generator for the merged entrypoints."""
    functions = list(contract["entrypoints"]) + list(contract["preserved_entrypoints"])
    return {"schema_version": 1, "kind": "python_integer_samples", "functions": functions}


def make_cases(contract, random_cases=8192, seed=20261020):
    validate_application_contract(contract)
    return pv.make_cases(_scalar_like(contract), random_cases, seed)


# ---------------------------------------------------------------------------
# Coverage + module-origin binding
# ---------------------------------------------------------------------------

def _names(value, label, *, empty=False, maximum=128):
    if (not isinstance(value, list) or not (0 if empty else 1) <= len(value) <= maximum
            or any(not pv._identifier(name) or len(name) > MAX_COMPONENT_CHARS
                   or name.startswith(("_ar_", "_arm_", "__")) for name in value)
            or len(set(value)) != len(value)):
        raise ValueError("mixed coverage " + label + " must contain unique ordinary names")
    return set(value)


def _verify_mixed_coverage(coverage, selected_entrypoints, preserved_entrypoints):
    """Structurally verify hash-pinned mixed-build evidence before any import.

    This confirms consistency of the builder's own coverage record; it is not
    independent proof that the protected bodies execute a VM. Fields missing from
    the current mixed schema are rejected rather than inferred.
    """
    if (not isinstance(coverage, dict) or type(coverage.get("schema_version")) is not int
            or coverage["schema_version"] != 1 or coverage.get("backend") != BACKEND
            or coverage.get("protection_mode") != MODE):
        raise ValueError("mixed coverage requires schema_version 1 and the mixed-module backend/mode")
    if not _hex64(coverage.get("original_module_source_sha256")):
        raise ValueError("mixed coverage must bind the original module source SHA-256")
    roots = _names(coverage.get("selected_functions"), "selected_functions", maximum=64)
    exported = _names(coverage.get("exported_functions"), "exported_functions")
    closure = _names(coverage.get("helper_closure"), "helper_closure")
    # Every selected root must be contained in the exported helper closure. A
    # strict-superset test (roots > exported) wrongly accepts partially
    # overlapping roots such as {a, b} against an export of {b, c}; require the
    # subset relation explicitly so an out-of-closure root is refused.
    if not roots <= exported or exported != closure:
        raise ValueError("mixed coverage selected roots must be within the exported helper closure")
    preserved_declared = _names(coverage.get("preserved_unprotected_functions"),
                                "preserved_unprotected_functions", empty=True, maximum=256)
    if preserved_declared & closure:
        raise ValueError("preserved unprotected functions cannot overlap virtualized functions")
    functions = coverage.get("functions")
    if not isinstance(functions, dict) or set(functions) != closure:
        raise ValueError("mixed coverage.functions must exactly match the helper closure")
    for name, evidence in functions.items():
        if not isinstance(evidence, dict) or evidence.get("virtualized") is not True:
            raise ValueError("every exported mixed function must carry virtualized source VM coverage")
        _names(evidence.get("parameters"), name + ".parameters", empty=True, maximum=MAX_PARAMETERS)
    if not selected_entrypoints <= roots:
        raise ValueError("every selected entrypoint must be a selected virtualized root in coverage")
    if not preserved_entrypoints <= preserved_declared:
        raise ValueError("every preserved entrypoint must be a preserved unprotected function in coverage")
    return functions


def _derive_module(report):
    """Derive the importable package root and dotted module name from the plan."""
    project = report.get("project")
    if not isinstance(project, dict):
        raise ValueError("mixed build report must carry its inspected project")
    root = project.get("project_root")
    sources = project.get("sources")
    if not isinstance(root, str) or not isinstance(sources, list) or len(sources) != 1 or not isinstance(sources[0], str):
        raise ValueError("mixed project must declare one source under a project root")
    package_root = Path(os.path.abspath(root))
    source = Path(os.path.abspath(sources[0]))
    if not source.is_relative_to(package_root):
        raise ValueError("mixed source must stay inside its project root")
    relative = source.relative_to(package_root)
    if relative.suffix.lower() != ".py":
        raise ValueError("mixed source must be a .py module")
    parts = list(relative.parts)
    module_name = parts[-1][:-3]
    components = parts[:-1] + [module_name]
    if not components or not all(_component(part) for part in components):
        raise ValueError("every package/module path component must be an ordinary identifier")
    return package_root, ".".join(components), relative


# ---------------------------------------------------------------------------
# Staging
# ---------------------------------------------------------------------------

def _staging_guard(path, root):
    path = Path(os.path.abspath(path))
    _no_links(path)
    if not path.is_relative_to(root):
        raise ValueError("staged package tree must stay inside the workspace")
    parts = {part.casefold() for part in path.relative_to(root).parts}
    if parts & {"rea-analysis-reports", "attackerfolder", "defense-loop"}:
        raise ValueError("received/shared trees cannot be staged or imported")
    return path


def _walk_tree(package_root):
    """Yield (relative_posix, data) for eligible owned files under bounded budgets.

    Directory entries (files and subdirectories), nesting depth, file count and
    total bytes are all bounded, so a pathological tree is rejected before any
    output or child process is created. __pycache__ directories and compiled
    .pyc/.pyo files are skipped, so a stale cache can never shadow the staged
    source with original bytecode. Each file is read through the integrity-checked
    reader, which rejects links and mid-read changes.
    """
    files, total, entries = 0, 0, 0
    pending = [(package_root, 0)]
    while pending:
        directory, depth = pending.pop()
        for entry in sorted(directory.iterdir()):
            entries += 1
            if entries > MAX_PACKAGE_ENTRIES:
                raise ValueError("package tree exceeds the directory entry budget")
            _no_links(entry)
            relative = entry.relative_to(package_root)
            if entry.is_dir():
                if entry.name == "__pycache__":
                    continue
                if depth + 1 > MAX_PACKAGE_DEPTH:
                    raise ValueError("package tree exceeds the directory depth budget")
                pending.append((entry, depth + 1))
                continue
            if not entry.is_file():
                raise ValueError("package tree contains a non-regular input: " + str(relative))
            if entry.suffix.lower() in {".pyc", ".pyo"}:
                continue
            files += 1
            if files > MAX_PACKAGE_FILES:
                raise ValueError("package tree exceeds the staged file budget")
            data = _read(entry, MAX_FILE_BYTES) if entry.stat().st_size else b""
            total += len(data)
            if total > MAX_PACKAGE_BYTES:
                raise ValueError("package tree exceeds the staged byte budget")
            yield str(relative).replace("\\", "/"), data


def _snapshot_tree(package_root):
    """Hash the owned package tree without copying it (used to detect drift)."""
    return sorted(({"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
                   for relative, data in _walk_tree(package_root)), key=lambda item: item["path"])


def _snapshot_as_map(snapshot):
    """Reduce a {path, sha256, bytes} snapshot list to {path: {sha256, bytes}}."""
    return {item["path"]: {"sha256": item["sha256"], "bytes": item["bytes"]} for item in snapshot}


def _prestage_drift_hook():
    """Deterministic test seam: invoked once after the source-plan preflight and
    before any staging. Production is a no-op; a test may patch it to mutate the
    owned tree and prove the per-arm pre-launch snapshot check catches a change
    that lands between the plan preflight and staging, before any child starts."""
    return None


def _expected_source_files(expected_snapshot, package_root):
    """Project the trusted source-plan snapshot onto the applicable source tree.

    The plan records absolute paths for every bounded project file. Reduce it to
    the same {relative_posix: (sha256, bytes)} shape this validator hashes,
    dropping only cache artifacts (which staging also never copies), so a changed,
    added or removed source sibling is detected. The expected hashes come from the
    plan, never from the current tree.
    """
    if not isinstance(expected_snapshot, list) or not expected_snapshot:
        raise ValueError("a non-empty source-plan snapshot is required to bind validation")
    expected = {}
    for item in expected_snapshot:
        if (not isinstance(item, dict) or not isinstance(item.get("path"), str)
                or not _hex64(item.get("sha256")) or type(item.get("bytes")) is not int):
            raise ValueError("source-plan snapshot entries must carry path, sha256 and bytes")
        candidate = Path(os.path.abspath(item["path"]))
        if not candidate.is_relative_to(package_root):
            continue
        relative = candidate.relative_to(package_root).as_posix()
        parts = relative.split("/")
        if relative.endswith((".pyc", ".pyo")) or "__pycache__" in parts:
            continue
        expected[relative] = {"sha256": item["sha256"], "bytes": item["bytes"]}
    if not expected:
        raise ValueError("source-plan snapshot does not cover the applicable package tree")
    return expected


def _verify_against_plan(package_root, expected_snapshot):
    """Compare the complete current source tree to the trusted plan snapshot.

    Runs before any staging, import or output creation. Fails closed on any
    modified, added or removed applicable source file since the originating plan.
    """
    expected = _expected_source_files(expected_snapshot, package_root)
    current = {item["path"]: {"sha256": item["sha256"], "bytes": item["bytes"]}
               for item in _snapshot_tree(package_root)}
    if current != expected:
        added = sorted(set(current) - set(expected))
        removed = sorted(set(expected) - set(current))
        changed = sorted(name for name in set(current) & set(expected) if current[name] != expected[name])
        raise ValueError("owned package tree changed since the bound source plan "
                         + json.dumps({"added": added, "removed": removed, "changed": changed},
                                      sort_keys=True, separators=(",", ":")))
    return expected


def _stage_arm(package_root, module_relative, artifact_path, stage_root, workspace_root):
    """Copy the owned package tree into a fresh private root, then swap the module."""
    package_root = Path(os.path.abspath(package_root))
    stage_root = Path(os.path.abspath(stage_root))
    _staging_guard(stage_root, workspace_root)
    # Defense-in-depth overlap guard before mkdir, independent of the caller:
    # the staging root must not equal, nest in, or contain the owned package tree.
    if (stage_root == package_root or stage_root.is_relative_to(package_root)
            or package_root.is_relative_to(stage_root)):
        raise ValueError("staging root must not overlap the owned package tree")
    if stage_root.exists():
        raise ValueError("staging root must be fresh")
    stage_root.mkdir(parents=True)
    snapshot = []
    for relative, data in _walk_tree(package_root):
        destination = _staging_guard(stage_root / relative, workspace_root)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(data)
        snapshot.append({"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
    snapshot.sort(key=lambda item: item["path"])
    target = _staging_guard(stage_root / module_relative, workspace_root)
    if not target.is_file():
        raise ValueError("target module was not present in the staged package tree")
    # Confirm every non-leaf package directory is a regular package: namespace
    # packages and import hooks are rejected rather than silently tolerated.
    staged = {item["path"] for item in snapshot}
    for index in range(len(module_relative.parts) - 1):
        package_init = "/".join(module_relative.parts[: index + 1] + ("__init__.py",))
        if package_init not in staged:
            raise ValueError("each package directory must contain __init__.py; namespace packages are unsupported")
    artifact_bytes = _read(Path(artifact_path), MAX_FILE_BYTES)
    with target.open("wb") as stream:
        stream.write(artifact_bytes)
    return {"stage_root": str(stage_root), "target": str(target),
            "target_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
            "files": len(snapshot), "bytes": sum(item["bytes"] for item in snapshot),
            "snapshot": snapshot}


# ---------------------------------------------------------------------------
# Child environment
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


# ---------------------------------------------------------------------------
# Worker (child process)
# ---------------------------------------------------------------------------

def _worker_command(request_path):
    _no_links(_ANTIREA_ROOT)
    _no_links(_THIS_FILE)
    return [sys.executable, "-I", "-S", "-B", "-c", _WORKER_BOOTSTRAP,
            str(_ANTIREA_ROOT), str(_THIS_FILE), "--worker", str(request_path)]


def _public_surface(module):
    surface = {}
    for name in dir(module):
        if name.startswith("_"):
            continue
        value = getattr(module, name)
        surface[name] = type(value).__name__
    return surface


def _worker_run(request):
    import inspect

    stage_root = Path(request["stage_root"])
    target = Path(request["target"])
    module_name = request["module"]
    # Reduce the subject's new-import surface: drop the antirea checkout root from
    # sys.path so the owned application does not newly resolve sibling engine
    # modules from disk. This does NOT unload modules already present in
    # sys.modules (including the worker's own antirea imports), so it is a surface
    # reduction, not isolation. The standard library already on sys.path under
    # -I -S is kept.
    antirea_root = Path(request["antirea_root"]).resolve()
    sys.path[:] = [entry for entry in sys.path
                   if entry and Path(entry).resolve() != antirea_root]
    sys.path.insert(0, str(stage_root))
    importlib.invalidate_caches()
    if module_name in sys.modules:
        raise ValueError("subject module name was already imported")
    module = importlib.import_module(module_name)
    # Bind the imported target to its staged origin AND to the standard source
    # loader. This verifies how the target itself was loaded; it does not and
    # cannot prevent the owned application from mutating import hooks or importing
    # modules already present in sys.modules at runtime (see LIMITATIONS).
    spec = getattr(module, "__spec__", None)
    loader = getattr(spec, "loader", None) if spec is not None else None
    if not isinstance(loader, SourceFileLoader):
        raise ValueError("target module was not loaded by the standard source file loader")
    resolved = Path(os.path.abspath(getattr(module, "__file__", "")))
    _no_links(resolved)
    expected_target = Path(os.path.abspath(target))
    if resolved != expected_target:
        raise ValueError("imported module origin is not the staged target file")
    spec_origin = getattr(spec, "origin", None)
    if not isinstance(spec_origin, str) or Path(os.path.abspath(spec_origin)) != expected_target:
        raise ValueError("imported module spec origin is not the staged target file")
    if _hash(resolved) != request["target_sha256"]:
        raise ValueError("imported module file changed from the staged artifact")
    if module.__name__ != module_name:
        raise ValueError("imported module name differs from the bound dotted name")
    expected_package = module_name.rpartition(".")[0]
    if (getattr(module, "__package__", None) or "") != expected_package:
        raise ValueError("imported module package origin differs from the bound package")
    contract = request["contract"]
    cases = request["cases"]
    functions = list(contract["entrypoints"]) + list(contract["preserved_entrypoints"])
    outputs, outputs_second, deterministic, timings, signatures = {}, {}, {}, {}, {}
    for function in functions:
        name = function["name"]
        callback = getattr(module, name)
        pv._verify_signature(callback, function["parameters"])
        signatures[name] = str(inspect.signature(callback, follow_wrapped=False))
        vectors = cases[name]
        first = [pv._observed_call(callback, vector) for vector in vectors]
        second = [pv._observed_call(callback, vector) for vector in vectors]
        outputs[name] = first
        outputs_second[name] = second
        deterministic[name] = first == second
        batch = vectors[: min(128, len(vectors))]
        for vector in batch:
            pv._observed_call(callback, vector)
        samples = []
        for _ in range(7):
            started = time.perf_counter_ns()
            for vector in batch:
                pv._observed_call(callback, vector)
            samples.append(time.perf_counter_ns() - started)
        timings[name] = {"samples_ns": samples, "median_ns": statistics.median(samples),
                         "calls_per_batch": len(batch), "warmup_batches": 1}
    if _hash(resolved) != request["target_sha256"]:
        raise ValueError("imported module file changed during execution")
    return {"module_origin": {"name": module.__name__, "package": getattr(module, "__package__", None),
                              "file": str(resolved), "file_sha256": request["target_sha256"],
                              "loader": type(loader).__name__, "import_executed": True,
                              "public_surface": _public_surface(module)},
            "signatures": signatures, "outputs": outputs, "outputs_second": outputs_second,
            "deterministic": deterministic, "timings": timings}


# ---------------------------------------------------------------------------
# Orchestration (parent process)
# ---------------------------------------------------------------------------

def validate_build(report_path, contract_path, output_dir, *, workspace_root, expected_snapshot,
                   random_cases=8192, seed=20261020, timeout_seconds=120):
    root = Path(os.path.abspath(workspace_root))
    report_path = Path(os.path.abspath(report_path))
    output = Path(os.path.abspath(output_dir))
    for path in (root, report_path, output):
        _no_links(path)
    if not report_path.is_relative_to(root) or not output.is_relative_to(root):
        raise ValueError("mixed validation inputs/outputs must stay inside workspace")
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
    contract = validate_application_contract(_json(contract_bytes))
    cases = make_cases(contract, random_cases, seed)

    report_bytes = _read(report_path, MAX_FILE_BYTES)
    report = _json(report_bytes)
    if (not isinstance(report, dict) or report.get("status") != "artifact_created_unvalidated"
            or report.get("backend") != BACKEND):
        raise ValueError("only a successful owned mixed-module VM build can be validated")

    selected_names = {function["name"] for function in contract["entrypoints"]}
    preserved_names = {function["name"] for function in contract["preserved_entrypoints"]}
    coverage = report.get("coverage")
    functions = _verify_mixed_coverage(coverage, selected_names, preserved_names)
    for function in contract["entrypoints"]:
        if functions[function["name"]].get("parameters") != [p["name"] for p in function["parameters"]]:
            raise ValueError("selected entrypoint parameters differ from the inspected VM source")

    package_root, module_name, module_relative = _derive_module(report)
    _staging_guard(package_root, root)
    if contract["module"] != module_name:
        raise ValueError("contract module must equal the inspected package.module origin")
    # Reject an output/stage location that overlaps the owned package tree BEFORE
    # creating anything: otherwise the source walk would recurse into the fresh
    # staging directory created underneath it.
    if (output == package_root or output.is_relative_to(package_root)
            or package_root.is_relative_to(output)):
        raise ValueError("validation output must not overlap the owned package tree")

    artifacts = {}
    for arm in ("baseline", "protected"):
        artifact = report.get("artifacts", {}).get(arm, {})
        path = _artifact_path(root, report_path.parent, artifact.get("path", ""))
        if path.suffix != ".py" or _hash(path) != artifact.get("sha256"):
            raise ValueError("mixed artifact hash differs from reviewed build")
        artifacts[arm] = {"path": str(path), "sha256": artifact["sha256"], "bytes": path.stat().st_size}
    if artifacts["baseline"]["sha256"] != coverage["original_module_source_sha256"]:
        raise ValueError("baseline artifact is not the bound original module source")

    # Bind validation to the originating source plan: the complete applicable
    # package tree must match the trusted prebuild snapshot (passed in by the
    # service after verifying the plan fingerprint), not just be internally
    # consistent during this run. Runs before any staging, import or output.
    expected_source = _verify_against_plan(package_root, expected_snapshot)

    stop = root / ".runs" / "defense-loop" / "STOP"
    if stop.exists():
        return {"status": "cancelled", "reason": "defense STOP exists"}
    output.mkdir(parents=True)

    result = {"schema_version": 1, "status": "failed", "backend": BACKEND, "mode": MODE,
              "module": module_name, "package_root": str(package_root),
              "module_relative": str(module_relative).replace("\\", "/"), "artifacts": artifacts,
              "build_report_sha256": hashlib.sha256(report_bytes).hexdigest(),
              "contract_sha256": hashlib.sha256(contract_bytes).hexdigest(),
              "selected_entrypoints": sorted(selected_names), "preserved_entrypoints": sorted(preserved_names),
              "cases_per_function": {name: len(value) for name, value in cases.items()},
              "random_cases_per_function": random_cases, "seed": seed, "behavior_repeats": 2,
              "source_plan_snapshot_bound": True, "source_plan_files": len(expected_source),
              "staging": {}, "execution": {}, "functions": {}, "module_origin": {},
              "external_attack_evaluation": "not_evaluated", "limitations": list(LIMITATIONS)}
    try:
        # Test seam: a source change that lands between the plan preflight above
        # and the first staging below must still be caught (per-arm check, next).
        _prestage_drift_hook()
        replies, snapshots = {}, {}
        for arm, artifact in artifacts.items():
            stage_root = output / arm / "stage"
            staging = _stage_arm(package_root, module_relative, Path(artifact["path"]), stage_root, root)
            snapshots[arm] = staging["snapshot"]
            # Bind THIS arm's pre-overlay staged source to the trusted plan
            # snapshot before launching its child. Catches a source/sibling change
            # that lands after the plan preflight but before (or between) staging,
            # which a baseline-stage-only comparison would miss.
            if _snapshot_as_map(staging["snapshot"]) != expected_source:
                raise ValueError("owned package tree changed since the bound source plan "
                                 "before staging arm " + arm)
            result["staging"][arm] = {key: staging[key] for key in ("stage_root", "target", "target_sha256", "files", "bytes")}
            request = {"antirea_root": str(_ANTIREA_ROOT), "workspace_root": str(root),
                       "stage_root": staging["stage_root"], "target": staging["target"],
                       "target_sha256": staging["target_sha256"], "module": module_name,
                       "contract": contract, "cases": cases}
            request_path = output / (arm + ".request.json")
            _save(request_path, request)
            env = _child_env(output / arm / "tmp")
            process = run_logged(_worker_command(request_path), output / arm, output / arm / "worker",
                                 timeout_seconds, env=env, cancel_file=stop)
            result["execution"][arm] = {**process, "child_env_keys": sorted(env)}
            if process.get("returncode") != 0 or process.get("cancelled") or process.get("timed_out"):
                if process.get("cancelled"):
                    result["status"] = "cancelled"
                elif process.get("timed_out"):
                    result["status"] = "timed_out"
                raise ValueError(arm + " mixed application worker failed, timed out or was cancelled")
            cleanup = process.get("cleanup", {})
            if os.name == "nt" and not (cleanup.get("job_assigned") and cleanup.get("active_after") == 0
                                        and cleanup.get("parent_exit_confirmed") and cleanup.get("job_handle_closed")):
                raise ValueError("worker cleanup could not be verified")
            replies[arm] = _json(_read(request_path.with_suffix(".reply.json"), 64 * 1024 * 1024))

        baseline, protected = replies["baseline"], replies["protected"]
        origin_consistent = (baseline["module_origin"]["public_surface"] == protected["module_origin"]["public_surface"]
                             and baseline["signatures"] == protected["signatures"]
                             and baseline["module_origin"]["import_executed"] is True
                             and protected["module_origin"]["import_executed"] is True
                             and baseline["module_origin"]["file_sha256"] == artifacts["baseline"]["sha256"]
                             and protected["module_origin"]["file_sha256"] == artifacts["protected"]["sha256"])
        result["module_origin"] = {"baseline": baseline["module_origin"], "protected": protected["module_origin"],
                                   "signatures": baseline["signatures"], "consistent": origin_consistent}
        for name, vectors in cases.items():
            agreement = compare_repeated_observations(baseline, protected, name, len(vectors))
            a = baseline["outputs"][name]
            base_ns = baseline["timings"][name]["median_ns"]
            protected_ns = protected["timings"][name]["median_ns"]
            ordinary_returns = sum(item["kind"] == "return" for item in a)
            result["functions"][name] = {**agreement,
                "cases": len(vectors), "selected": name in selected_names,
                "baseline_ordinary_returns": ordinary_returns, "baseline_exceptions": len(a) - ordinary_returns,
                "baseline_timing": baseline["timings"][name], "protected_timing": protected["timings"][name],
                "slowdown_ratio": protected_ns / base_ns if base_ns else None}

        # Final binding is to the trusted ORIGINAL plan snapshot, not merely to a
        # (possibly already-drifted) baseline stage: re-hash the live source tree
        # and require it to still equal expected_source. The baseline/protected
        # stage agreement is kept as an additional, non-relaxed check.
        reference = snapshots["baseline"]
        result["package_tree_files"] = len(expected_source)
        final_source = _snapshot_as_map(_snapshot_tree(package_root))
        unchanged = (hashlib.sha256(_read(report_path, MAX_FILE_BYTES)).hexdigest() == result["build_report_sha256"]
                     and hashlib.sha256(_read(contract_path, 256 * 1024)).hexdigest() == result["contract_sha256"]
                     and all(_hash(Path(a["path"])) == a["sha256"] for a in artifacts.values())
                     and snapshots["protected"] == reference
                     and _snapshot_as_map(reference) == expected_source
                     and final_source == expected_source)
        passed = (unchanged and origin_consistent
                  and all(item["sampled_output_match"] and item["deterministic"]
                          and item["baseline_ordinary_returns"] > 0 for item in result["functions"].values()))
        result["status"] = "mixed_application_samples_passed" if passed else "failed"
        result["inputs_unchanged"] = unchanged
    except Exception as exc:
        result["error"] = type(exc).__name__ + ": " + str(exc)[:2048]
    _save(output / "validation.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path, required=True)
    args = parser.parse_args()
    result = _worker_run(_json(_read(args.worker, 64 * 1024 * 1024)))
    _save(args.worker.with_suffix(".reply.json"), result)
    print(json.dumps({"status": "worker_completed"}))


if __name__ == "__main__":
    main()
