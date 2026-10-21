"""Explicit sampled validation of owned Python-source VM builds.

Children execute owned original and protected code, not received artifacts.
The process boundary is for timeouts/logs, not an OS security sandbox.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import keyword
import os
from pathlib import Path
import random
import statistics
import sys
import time

from .native_validate import _artifact_path, _hash, _save
from .process import run_logged
from .protectors import _json, _no_links, _read
from .script_validation_evidence import compare_repeated_observations


MAX_FUNCTIONS = 32
MAX_PARAMETERS = 16
MAX_CASES = 131072
MAX_BOUND_BITS = 256


def _identifier(value):
    return isinstance(value, str) and value.isascii() and value.isidentifier() and not keyword.iskeyword(value)


def validate_contract(contract):
    """Sampling ranges do not change Python integer semantics or truncate output."""
    if not isinstance(contract, dict) or set(contract) != {"schema_version", "kind", "functions"}:
        raise ValueError("Python sampling contract requires schema_version, kind and functions only")
    if type(contract["schema_version"]) is not int or contract["schema_version"] != 1:
        raise ValueError("Python sampling contract schema_version must be 1")
    if contract["kind"] != "python_integer_samples":
        raise ValueError("Python source validation requires kind python_integer_samples, not a native ABI contract")
    functions = contract["functions"]
    if not isinstance(functions, list) or not 1 <= len(functions) <= MAX_FUNCTIONS:
        raise ValueError("functions must contain 1..32 exported function contracts")
    seen = set()
    for function in functions:
        if not isinstance(function, dict) or set(function) != {"name", "parameters"}:
            raise ValueError("function contracts require name and parameters only")
        name = function["name"]
        if not _identifier(name) or name in seen:
            raise ValueError("function name must be a unique ordinary Python identifier")
        seen.add(name)
        parameters = function["parameters"]
        if not isinstance(parameters, list) or len(parameters) > MAX_PARAMETERS:
            raise ValueError("parameters must contain at most 16 scalar integer ranges")
        names = set()
        for parameter in parameters:
            if not isinstance(parameter, dict) or set(parameter) != {"name", "minimum", "maximum"}:
                raise ValueError("parameter contracts require name, minimum and maximum only")
            if not _identifier(parameter["name"]) or parameter["name"] in names:
                raise ValueError("parameter name must be a unique ordinary Python identifier")
            names.add(parameter["name"])
            lo, hi = parameter["minimum"], parameter["maximum"]
            if (type(lo) is not int or type(hi) is not int or lo > hi
                    or max(abs(lo).bit_length(), abs(hi).bit_length()) > MAX_BOUND_BITS):
                raise ValueError("invalid integer sample bounds (maximum 256 bits)")
    return contract


def make_cases(contract, random_cases=8192, seed=20261020):
    validate_contract(contract)
    if type(random_cases) is not int or not 1 <= random_cases <= 8192:
        raise ValueError("random_cases must be an integer in 1..8192")
    if type(seed) is not int or not 0 <= seed <= 0x7FFFFFFF:
        raise ValueError("seed must be a nonnegative 31-bit integer")
    rng = random.Random(seed)
    cases = {}
    for function in contract["functions"]:
        bounds = [(p["minimum"], p["maximum"]) for p in function["parameters"]]
        middle = [max(lo, min(0, hi)) for lo, hi in bounds]
        edges = {tuple(middle), tuple(lo for lo, hi in bounds), tuple(hi for lo, hi in bounds)}
        for index, (lo, hi) in enumerate(bounds):
            for value in (lo, lo + 1, -1, 0, 1, hi - 1, hi):
                if lo <= value <= hi:
                    vector = middle.copy()
                    vector[index] = value
                    edges.add(tuple(vector))
        cases[function["name"]] = ([[rng.randint(lo, hi) for lo, hi in bounds] for _ in range(random_cases)]
                                   + [list(value) for value in sorted(edges)])
    if sum(map(len, cases.values())) > MAX_CASES:
        raise ValueError("sample count exceeds total budget; lower random_cases explicitly")
    return cases


def _observed_call(callback, arguments):
    try:
        value = callback(*arguments)
    except Exception as exc:
        return {"kind": "exception", "type": type(exc).__module__ + "." + type(exc).__qualname__}
    if type(value) not in (int, bool):
        raise ValueError("sampled Python source must return an int/bool or raise an Exception")
    # A decimal string preserves arbitrary integer precision in JSON consumers.
    return {"kind": "return", "type": type(value).__name__, "value": str(value)}


def _verify_signature(callback, parameters):
    signature = inspect.signature(callback, follow_wrapped=False)
    actual = list(signature.parameters.values())
    if [p.name for p in actual] != [p["name"] for p in parameters]:
        raise ValueError("sampling contract parameter names/order differ from Python function")
    if any(p.kind not in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD) or p.default is not p.empty for p in actual):
        raise ValueError("only ordinary fixed positional Python function signatures are supported")


def _worker_run(request):
    root = Path(request["workspace_root"])
    directory = Path(request["build_directory"])
    source = _artifact_path(root, directory, request["source_path"])
    if source.suffix != ".py" or _hash(source) != request["sha256"]:
        raise ValueError("Python artifact changed or is not a Python module")
    contract = validate_contract(request["contract"])
    cases = make_cases(contract, request["random_cases"], request["seed"])
    # Import from this exact reviewed path, never a module name from cwd/PATH.
    spec = importlib.util.spec_from_file_location("antirea_owned_subject", source)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load owned Python module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    outputs, outputs_second, deterministic, timings = {}, {}, {}, {}
    for function in contract["functions"]:
        name = function["name"]
        callback = getattr(module, name)
        _verify_signature(callback, function["parameters"])
        first = [_observed_call(callback, vector) for vector in cases[name]]
        second = [_observed_call(callback, vector) for vector in cases[name]]
        outputs[name] = first
        outputs_second[name] = second
        deterministic[name] = first == second
        batch = cases[name][:min(128, len(cases[name]))]
        for vector in batch:
            _observed_call(callback, vector)
        samples = []
        for _ in range(7):
            started = time.perf_counter_ns()
            for vector in batch:
                _observed_call(callback, vector)
            samples.append(time.perf_counter_ns() - started)
        timings[name] = {"samples_ns": samples, "median_ns": statistics.median(samples),
                         "calls_per_batch": len(batch), "warmup_batches": 1}
    if _hash(source) != request["sha256"]:
        raise ValueError("Python artifact changed during execution")
    return {"outputs": outputs, "outputs_second": outputs_second,
            "deterministic": deterministic, "timings": timings}


def _worker_command(request):
    package_root = Path(__file__).absolute().parents[1]
    _no_links(package_root)
    bootstrap = ("import runpy,sys; sys.path.insert(0,sys.argv.pop(1)); "
                 "runpy.run_module('antirea.python_validate',run_name='__main__',alter_sys=True)")
    return [sys.executable, "-I", "-S", "-B", "-c", bootstrap, str(package_root), "--worker", str(request)]


def _verify_coverage(coverage, observed_names):
    """Require the complete v1 frontend scope before executing either module.

    This checks structural consistency of hash-pinned builder evidence; it is not
    independent proof that arbitrary code was actually transformed into a VM.
    Missing legacy fields are rejected rather than inferring helper coverage.
    """
    if (not isinstance(coverage, dict) or type(coverage.get("schema_version")) is not int
            or coverage["schema_version"] != 1 or coverage.get("backend") != "python_vm"):
        raise ValueError("Python VM coverage requires the current schema_version 1/backend")

    def names(value, label, *, empty=False, maximum=128):
        if (not isinstance(value, list) or not (0 if empty else 1) <= len(value) <= maximum
                or any(not _identifier(name) or len(name) > 128 or name.startswith(("_ar_", "__")) for name in value)
                or len(set(value)) != len(value)):
            raise ValueError(f"Python VM coverage {label} must contain unique ordinary names")
        return set(value)

    roots = names(coverage.get("selected_functions"), "selected_functions", maximum=64)
    exports = names(coverage.get("exported_functions"), "exported_functions", maximum=64)
    validation_exports = names(coverage.get("validation_exports"), "validation_exports", maximum=64)
    if roots != exports or exports != validation_exports:
        raise ValueError("Python VM coverage selected roots/exported/validation functions must agree")
    if exports != set(observed_names):
        raise ValueError("sampling contract must observe every exported function")
    closure = names(coverage.get("helper_closure"), "helper_closure")
    functions = coverage.get("functions")
    if not isinstance(functions, dict) or set(functions) != closure or not roots <= closure:
        raise ValueError("Python VM coverage.functions must exactly match helper_closure and include every root")
    identifiers, graph = set(), {}
    for name, evidence in functions.items():
        if not isinstance(evidence, dict) or evidence.get("virtualized") is not True:
            raise ValueError("Every root/helper must have virtualized source VM coverage")
        names(evidence.get("parameters"), f"{name}.parameters", empty=True, maximum=MAX_PARAMETERS)
        helpers = names(evidence.get("helpers"), f"{name}.helpers", empty=True)
        if not helpers <= closure:
            raise ValueError("Python VM coverage references a helper missing from helper_closure")
        graph[name] = helpers
        count, identifier = evidence.get("instruction_count"), evidence.get("vm_function_id")
        if type(count) is not int or count < 1 or type(identifier) is not int or not 0 <= identifier < len(closure):
            raise ValueError("Python VM function instruction count/id must be valid integers")
        if identifier in identifiers:
            raise ValueError("Python VM function ids must be unique")
        identifiers.add(identifier)
    reached, active = set(), set()

    def visit(name):
        if name in active:
            raise ValueError("Python VM coverage contains an unsupported recursive helper cycle")
        if name in reached:
            return
        active.add(name)
        for helper in graph[name]:
            visit(helper)
        active.remove(name)
        reached.add(name)

    for root_name in roots:
        visit(root_name)
    if reached != closure:
        raise ValueError("Python VM helper_closure must exactly match functions reachable from selected roots")
    return functions


def validate_build(report_path, contract_path, output_dir, *, workspace_root,
                   random_cases=8192, seed=20261020, timeout_seconds=120):
    root = Path(os.path.abspath(workspace_root))
    report_path = Path(os.path.abspath(report_path))
    output = Path(os.path.abspath(output_dir))
    for path in (root, report_path, output):
        _no_links(path)
    if not report_path.is_relative_to(root) or not output.is_relative_to(root):
        raise ValueError("Python validation inputs/outputs must stay inside workspace")
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
    if (not isinstance(report, dict) or report.get("status") != "artifact_created_unvalidated"
            or report.get("backend") != "python_vm"):
        raise ValueError("only a successful owned Python VM build can be validated")
    names = [item["name"] for item in contract["functions"]]
    functions = _verify_coverage(report.get("coverage"), names)
    for function in contract["functions"]:
        if functions[function["name"]].get("parameters") != [p["name"] for p in function["parameters"]]:
            raise ValueError("sampling contract parameters differ from inspected source")
    artifacts = {}
    for arm in ("baseline", "protected"):
        artifact = report.get("artifacts", {}).get(arm, {})
        path = _artifact_path(root, report_path.parent, artifact.get("path", ""))
        if path.suffix != ".py" or _hash(path) != artifact.get("sha256"):
            raise ValueError("Python artifact hash differs from reviewed build")
        artifacts[arm] = {"path": str(path), "sha256": artifact["sha256"], "bytes": path.stat().st_size}
    stop = root / ".runs" / "defense-loop" / "STOP"
    if stop.exists():
        return {"status": "cancelled", "reason": "defense STOP exists"}
    output.mkdir(parents=True)
    result = {"schema_version": 1, "status": "failed", "backend": "python_vm", "artifacts": artifacts,
              "build_report_sha256": hashlib.sha256(report_bytes).hexdigest(),
              "contract_sha256": hashlib.sha256(contract_bytes).hexdigest(),
              "cases_per_function": {name: len(value) for name, value in cases.items()},
              "random_cases_per_function": random_cases, "seed": seed, "behavior_repeats": 2,
              "execution": {}, "functions": {}, "external_attack_evaluation": "not_evaluated",
              "limitations": ["Owned Python modules execute in child processes, not an OS security sandbox.",
                              "Sampled scalar integer inputs; exact int/bool returns and exception classes only.",
                              "Exception messages, traces, side effects and all-input equivalence are not proven.",
                              "Timing includes Python call and result-observation overhead, excludes startup/import.",
                              "No performance threshold or attack-resistance result is inferred."]}
    try:
        replies = {}
        for arm, artifact in artifacts.items():
            request = {"workspace_root": str(root), "build_directory": str(report_path.parent),
                       "source_path": artifact["path"], "sha256": artifact["sha256"],
                       "contract": contract, "random_cases": random_cases, "seed": seed}
            request_path = output / (arm + ".request.json")
            _save(request_path, request)
            process = run_logged(_worker_command(request_path), root, output / arm, timeout_seconds, cancel_file=stop)
            result["execution"][arm] = process
            if process.get("returncode") != 0 or process.get("cancelled") or process.get("timed_out"):
                if process.get("cancelled"):
                    result["status"] = "cancelled"
                elif process.get("timed_out"):
                    result["status"] = "timed_out"
                raise ValueError(arm + " Python worker failed, timed out or was cancelled")
            cleanup = process.get("cleanup", {})
            if os.name == "nt" and not (cleanup.get("job_assigned") and cleanup.get("active_after") == 0
                                         and cleanup.get("parent_exit_confirmed") and cleanup.get("job_handle_closed")):
                raise ValueError("worker cleanup could not be verified")
            replies[arm] = _json(_read(request_path.with_suffix(".reply.json"), 64 * 1024 * 1024))
        for name, vectors in cases.items():
            baseline, protected = replies["baseline"], replies["protected"]
            agreement = compare_repeated_observations(baseline, protected, name, len(vectors))
            a = baseline["outputs"][name]
            base_ns = baseline["timings"][name]["median_ns"]
            protected_ns = protected["timings"][name]["median_ns"]
            ordinary_returns = sum(item["kind"] == "return" for item in a)
            result["functions"][name] = {**agreement,
                "cases": len(vectors), "baseline_ordinary_returns": ordinary_returns,
                "baseline_exceptions": len(a) - ordinary_returns,
                "baseline_timing": baseline["timings"][name], "protected_timing": protected["timings"][name],
                "slowdown_ratio": protected_ns / base_ns if base_ns else None}
        unchanged = (hashlib.sha256(_read(report_path, 16 * 1024 * 1024)).hexdigest() == result["build_report_sha256"]
                     and hashlib.sha256(_read(contract_path, 256 * 1024)).hexdigest() == result["contract_sha256"]
                     and all(_hash(Path(a["path"])) == a["sha256"] for a in artifacts.values()))
        # Equal crashes/exceptions on every test do not demonstrate useful behavior.
        passed = unchanged and all(item["sampled_output_match"] and item["deterministic"]
                                   and item["baseline_ordinary_returns"] > 0 for item in result["functions"].values())
        result["status"] = "functional_samples_passed" if passed else "failed"
        result["inputs_unchanged"] = unchanged
    except Exception as exc:
        result["error"] = type(exc).__name__ + ": " + str(exc)[:2048]
    _save(output / "validation.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path, required=True)
    args = parser.parse_args()
    result = _worker_run(_json(_read(args.worker, 32 * 1024 * 1024)))
    _save(args.worker.with_suffix(".reply.json"), result)
    print(json.dumps({"status": "worker_completed"}))


if __name__ == "__main__":
    main()
