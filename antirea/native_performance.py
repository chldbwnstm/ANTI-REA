"""Explicit private native-build comparison, never an attack or acceptance claim.

Loads three owned DLLs in one bounded worker. Functional sampling precedes a
rotating seven-round measurement, so process startup and imports are excluded.
Python/ctypes loop overhead remains included. This is not an OS sandbox.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import statistics
import sys
import time

from .bindings import validate_contract
from .native_validate import CTYPES, _artifact_path, _hash, make_cases, verify_integer_abi
from .process import run_logged
from .protectors import _json, _no_links, _read


ARMS = ("baseline", "current", "candidate")
QUALIFICATION = ("Same-worker rotating measurements; includes Python/ctypes loop overhead, "
                 "excludes DLL load/process startup. Sampled return-value equivalence only; "
                 "not whole-application performance acceptance or attack resistance.")


def _save(path, value):
    _no_links(path)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def _load(path):
    value = _json(_read(path, 32 * 1024 * 1024))
    if not isinstance(value, dict):
        raise ValueError("comparison input must be a JSON object")
    return value


def _path(value):
    path = Path(os.path.abspath(value))
    _no_links(path)
    return path


def _measure(callbacks, batch, *, clock=time.perf_counter_ns):
    """One warmup per arm, then rotate the leading arm on each measured round."""
    for arm in ARMS:
        for args in batch:
            callbacks[arm](*args)
    samples, order = {arm: [] for arm in ARMS}, []
    for turn in range(7):
        rotated = ARMS[turn % len(ARMS):] + ARMS[:turn % len(ARMS)]
        order.append(list(rotated))
        for arm in rotated:
            start = clock()
            for args in batch:
                callbacks[arm](*args)
            samples[arm].append(clock() - start)
    summary = {arm: {"samples_ns": values, "median_ns": statistics.median(values),
                     "min_ns": min(values), "max_ns": max(values)} for arm, values in samples.items()}
    for arm in ARMS:
        summary[arm]["ratio_to_baseline"] = summary[arm]["median_ns"] / max(1, summary["baseline"]["median_ns"])
        summary[arm]["ratio_to_current"] = summary[arm]["median_ns"] / max(1, summary["current"]["median_ns"])
    return {"arms": summary, "round_order": order, "warmup_batches": 1,
            "measured_batches": 7, "calls_per_batch": len(batch)}


def _proof_identity(report, manifest):
    coverage = report.get("coverage", {})
    if not isinstance(coverage, dict):
        raise ValueError("invalid build coverage")
    runtime = coverage.get("runtime_evidence", {})
    functions = coverage.get("functions", {})
    if (not isinstance(functions, dict) or not functions or not isinstance(runtime, dict)
            or any(not isinstance(state, dict) or state.get("virtualized") is not True for state in functions.values())
            or runtime.get("fla_dispatcher") is not True
            or not runtime.get("substitution_instructions") or not runtime.get("constant_obfuscation_instructions")):
        raise ValueError("comparison requires retained VM and runtime FLA/SUB/CO evidence")
    return {"selected_functions": coverage.get("selected_functions", list(functions)),
            "exports": coverage.get("exported_functions", list(functions)),
            "requested_core_passes": coverage.get("requested_core_passes"),
            "parameters": manifest["parameters"], "blobs": manifest["blobs"],
            "engine_mode": manifest.get("engine_mode", "shared_direct"),
            "engines": manifest.get("engines", []),
            "dispatcher_symbols": manifest.get("dispatcher_symbols", []),
            "handlers": manifest["used_handlers"], "format": manifest["format_version"],
            "requested_hardening_layers": manifest["requested_hardening_layers"],
            "retained_components": coverage.get("hardening_evidence", {}).get("verified_retained_components")}


def prepare(current_report, candidate_report, contract_path, workspace_root):
    root = _path(workspace_root)
    contract_file = _path(contract_path)
    if not contract_file.is_relative_to(root):
        raise ValueError("contract must be owned by this workspace")
    contract = validate_contract(_load(contract_file))
    reports, manifests, paths = {}, {}, {}
    for name, supplied in (("current", current_report), ("candidate", candidate_report)):
        path = _path(supplied)
        if not path.is_relative_to(root / ".runs"):
            raise ValueError("comparison only accepts private workspace builds")
        # Apply the shared-path rejection even before any candidate library load.
        _artifact_path(root, path.parent, str(path))
        report = _load(path)
        if report.get("status") != "artifact_created_unvalidated":
            raise ValueError("comparison requires successful owned native builds")
        manifest_path = path.parent / "diversification.json"
        if report.get("artifact_hashes", {}).get("diversification.json") != _hash(manifest_path):
            raise ValueError("diversification manifest hash differs from build report")
        manifests[name] = _load(manifest_path)
        reports[name], paths[name] = report, path
        original_ir = path.parent / "module.before.ll"
        if report.get("artifact_hashes", {}).get("module.before.ll") != _hash(original_ir):
            raise ValueError("signature IR hash differs from build report")
        verify_integer_abi(original_ir.read_text(encoding="utf-8-sig"), contract)
    current, candidate = reports["current"], reports["candidate"]
    if (current["seed"] != candidate["seed"]
            or current["project"]["input_hashes"] != candidate["project"]["input_hashes"]):
        raise ValueError("comparison requires identical pinned project inputs and seed")
    proof = _proof_identity(current, manifests["current"])
    if proof != _proof_identity(candidate, manifests["candidate"]):
        raise ValueError("VM bytecode, format, layer requests or retained protection evidence changed")
    if (not isinstance(proof["exports"], list) or len(set(proof["exports"])) != len(proof["exports"])
            or set(proof["exports"]) != {item["name"] for item in contract["functions"]}):
        raise ValueError("comparison contract must observe every exported function")
    artifacts = {}
    for arm, report_name, artifact_name in (("baseline", "current", "baseline"),
                                            ("current", "current", "protected"),
                                            ("candidate", "candidate", "protected")):
        artifact = reports[report_name]["artifacts"][artifact_name]
        library = _artifact_path(root, paths[report_name].parent, artifact["path"])
        if _hash(library) != artifact["sha256"]:
            raise ValueError("artifact hash differs from build report")
        artifacts[arm] = {"path": str(library), "sha256": artifact["sha256"],
                          "bytes": library.stat().st_size, "build_directory": str(paths[report_name].parent)}
    return {"schema_version": 1, "workspace_root": str(root), "contract": contract,
            "contract_sha256": _hash(contract_file), "artifacts": artifacts,
            "build_reports": {key: {"path": str(path), "sha256": _hash(path)} for key, path in paths.items()},
            "measurement_engine": {"path": str(Path(__file__).absolute()), "sha256": _hash(Path(__file__))},
            "protection_identity_sha256": hashlib.sha256(json.dumps(proof, sort_keys=True).encode()).hexdigest(),
            "qualification": QUALIFICATION}


def _worker_run(request):
    if request.get("measurement_engine", {}).get("sha256") != _hash(Path(__file__)):
        raise ValueError("measurement engine changed before worker execution")
    contract = validate_contract(request["contract"])
    cases = make_cases(contract, random_cases=8192, seed=20261020)
    libraries, handles = {}, {}
    for arm in ARMS:
        artifact = request["artifacts"][arm]
        path = _artifact_path(Path(request["workspace_root"]), Path(artifact["build_directory"]), artifact["path"])
        if _hash(path) != artifact["sha256"]:
            raise ValueError("library changed before comparison")
        libraries[arm] = path
        handles[arm] = ctypes.CDLL(str(path), **({"winmode": 0x1100} if os.name == "nt" else {}))
    functional, timings = {}, {}
    for function in contract["functions"]:
        name, callbacks = function["name"], {}
        for arm in ARMS:
            callback = getattr(handles[arm], name)
            callback.argtypes = [CTYPES[item["type"]] for item in function["parameters"]]
            callback.restype = CTYPES[function["return_type"]]
            callbacks[arm] = callback
        expected = [callbacks["baseline"](*args) for args in cases[name]]
        counts = {arm: [] for arm in ARMS}
        for _ in range(2):
            for arm in ARMS:
                actual = [callbacks[arm](*args) for args in cases[name]]
                counts[arm].append(sum(left == right for left, right in zip(expected, actual)))
        passed = all(value == len(cases[name]) for values in counts.values() for value in values)
        functional[name] = {"cases": len(cases[name]), "repeats": 2, "matches": counts, "passed": passed,
                            "baseline_outputs_sha256": hashlib.sha256(json.dumps(expected).encode()).hexdigest(),
                            "reference": "owned original baseline; independent fixture oracle is a separate gate"}
        if not passed:
            return {"status": "functional_mismatch", "functional": functional, "timings": {}}
        timings[name] = _measure(callbacks, cases[name][:256])
    for arm, path in libraries.items():
        if _hash(path) != request["artifacts"][arm]["sha256"]:
            raise ValueError("library changed during comparison")
    return {"status": "measured", "functional": functional, "timings": timings}


def compare(current_report, candidate_report, contract_path, output_dir, *, workspace_root, timeout_seconds=300):
    request = prepare(current_report, candidate_report, contract_path, workspace_root)
    root, output = Path(request["workspace_root"]), _path(output_dir)
    if output.exists() or not output.is_relative_to(root / ".runs") or output == root / ".runs":
        raise ValueError("comparison output must be a fresh private run directory")
    if any(part.casefold() in {"defense-loop", "rea-analysis-reports", "attackerfolder"} for part in output.relative_to(root).parts):
        raise ValueError("shared output directory is not permitted")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
        raise ValueError("timeout must be an integer in 1..600")
    stop = root / ".runs/defense-loop/STOP"
    if stop.exists():
        raise ValueError("defense STOP marker exists")
    output.mkdir(parents=True, exist_ok=False)
    request["reply_path"] = str(output / "worker-reply.json")
    request_path = output / "worker-request.json"
    _save(request_path, request)
    package_root = Path(__file__).absolute().parents[1]
    bootstrap = ("import runpy,sys; sys.path.insert(0,sys.argv.pop(1)); "
                 "runpy.run_module('antirea.native_performance',run_name='__main__',alter_sys=True)")
    process = run_logged([sys.executable, "-I", "-S", "-c", bootstrap, str(package_root), "--worker", str(request_path)],
                         output, output / "worker", timeout=timeout_seconds, cancel_file=stop)
    result = dict(request, process=process, status="failed")
    cleanup = process.get("cleanup", {})
    if (process.get("returncode") == 0 and not process.get("cancelled") and not process.get("timed_out")
            and cleanup.get("parent_exit_confirmed") is True and cleanup.get("status") == "assigned_job_empty"
            and cleanup.get("job_handle_closed") is True):
        result.update(_load(Path(request["reply_path"])))
    for artifact in request["artifacts"].values():
        if _hash(Path(artifact["path"])) != artifact["sha256"]:
            result["status"] = "artifact_changed"
    _save(output / "performance.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--current-report", type=Path)
    parser.add_argument("--candidate-report", type=Path)
    parser.add_argument("--contract", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--workspace-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    if args.worker:
        request = _load(args.worker)
        _save(Path(request["reply_path"]), _worker_run(request))
        return 0
    if not all((args.current_report, args.candidate_report, args.contract, args.output_dir)):
        parser.error("current/candidate reports, contract and fresh output directory are required")
    result = compare(args.current_report, args.candidate_report, args.contract, args.output_dir,
                     workspace_root=args.workspace_root)
    print(json.dumps({"status": result["status"], "timings": result.get("timings", {})}, indent=2))
    return 0 if result["status"] == "measured" else 1


if __name__ == "__main__":
    raise SystemExit(main())
