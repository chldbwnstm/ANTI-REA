"""Explicit bounded execution of owned JavaScript VM artifacts with exact tags."""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import struct

from .javascript_frontend import BACKEND, TOOLS, _hash, _encoded, clean_node_environment
from .native_validate import _artifact_path, _save
from .process import run_logged
from .protectors import _json, _no_links, _read
from .script_validation_evidence import compare_repeated_observations


def _identifier(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]{0,127}", value) and not value.startswith("_ar_")


def validate_contract(contract):
    if (not isinstance(contract, dict) or set(contract) != {"schema_version", "kind", "functions"}
            or type(contract["schema_version"]) is not int or contract["schema_version"] != 1
            or contract["kind"] != "javascript_scalar_samples"):
        raise ValueError("Use schema_version 1, kind javascript_scalar_samples and functions only")
    functions = contract["functions"]
    if not isinstance(functions, list) or not 1 <= len(functions) <= 32:
        raise ValueError("Require 1..32 function sampling contracts")
    seen = set()
    for fn in functions:
        if not isinstance(fn, dict) or set(fn) != {"name", "parameters"} or not _identifier(fn["name"]) or fn["name"] in seen:
            raise ValueError("Function contract names must be unique ordinary identifiers")
        seen.add(fn["name"])
        if not isinstance(fn["parameters"], list) or len(fn["parameters"]) > 16:
            raise ValueError("At most 16 scalar parameters supported")
        names = set()
        for param in fn["parameters"]:
            if not isinstance(param, dict) or not _identifier(param.get("name")) or param["name"] in names:
                raise ValueError("Parameter names must be unique identifiers")
            names.add(param["name"])
            kind = param.get("type")
            if not isinstance(kind, str):
                raise ValueError("Parameter type must be a string")
            if kind == "boolean":
                if set(param) != {"name", "type"}:
                    raise ValueError("Boolean parameters have no numeric bounds")
            elif kind in {"number", "bigint"}:
                if set(param) != {"name", "type", "minimum", "maximum"}:
                    raise ValueError("Numeric parameters require inclusive minimum/maximum")
                lo, hi = param["minimum"], param["maximum"]
                if kind == "bigint":
                    if (not isinstance(lo, str) or not isinstance(hi, str) or not re.fullmatch(r"-?(0|[1-9][0-9]{0,77})", lo)
                            or not re.fullmatch(r"-?(0|[1-9][0-9]{0,77})", hi)):
                        raise ValueError("BigInt bounds must be canonical bounded decimal strings")
                    lo, hi = int(lo), int(hi)
                if type(lo) is not int or type(hi) is not int or lo > hi:
                    raise ValueError("Random numeric bounds must be integers in increasing order")
                limit = 2 ** 53 - 1 if kind == "number" else 2 ** 256 - 1
                if abs(lo) > limit or abs(hi) > limit:
                    raise ValueError("Number random bounds must be safe integers; BigInt bounded to 256 bits")
            else:
                raise ValueError("Parameter type must be number, bigint or boolean")
    return contract


def _tag(kind, value):
    if kind == "number":
        return {"type": kind, "value": struct.pack(">d", float(value)).hex()}
    return {"type": kind, "value": str(value) if kind == "bigint" else bool(value)}


def make_cases(contract, random_cases=8192, seed=20261020):
    validate_contract(contract)
    if type(random_cases) is not int or not 1 <= random_cases <= 8192 or type(seed) is not int or not 0 <= seed < 2 ** 31:
        raise ValueError("Use 1..8192 random cases and a nonnegative 31-bit seed")
    rng, result = random.Random(seed), {}
    for fn in contract["functions"]:
        parameters = fn["parameters"]
        bounds = [(0, 1) if p["type"] == "boolean" else (int(p["minimum"]), int(p["maximum"])) for p in parameters]
        # Distinct random pairs where the finite domain permits; tiny Boolean/
        # zero-arity domains are exhaustively enumerated rather than padded.
        domain = math.prod(hi - lo + 1 for lo, hi in bounds)
        target = min(random_cases, domain)
        samples, seen = [], set()
        while len(samples) < target:
            row = [_tag(p["type"], rng.randint(lo, hi)) for p, (lo, hi) in zip(parameters, bounds)]
            key = _encoded(row)
            if key not in seen:
                seen.add(key); samples.append(row)
        middle = [_tag(p["type"], max(lo, min(0, hi))) for p, (lo, hi) in zip(parameters, bounds)]
        edges = [middle]
        for index, (p, (lo, hi)) in enumerate(zip(parameters, bounds)):
            values = [False, True] if p["type"] == "boolean" else [lo, hi, -1, 0, 1]
            if p["type"] == "number":
                values += [-0.0, 0.5, -0.5, float("nan"), float("inf"), -float("inf"), 2 ** 53, -(2 ** 53)]
            for value in values:
                row = list(middle); row[index] = _tag(p["type"], value); edges.append(row)
        for row in edges:
            key = _encoded(row)
            if key not in seen:
                seen.add(key); samples.append(row)
        result[fn["name"]] = samples
    if sum(map(len, result.values())) > 131072:
        raise ValueError("Total sample budget exceeded")
    return result


def _verify_coverage(coverage, functions):
    if not isinstance(coverage, dict) or type(coverage.get("schema_version")) is not int or coverage["schema_version"] != 1 or coverage.get("backend") != BACKEND:
        raise ValueError("Current JavaScript VM coverage required")
    def names(value, empty=False):
        if (not isinstance(value, list) or not (0 if empty else 1) <= len(value) <= 128
                or any(not _identifier(name) for name in value) or len(set(value)) != len(value)):
            raise ValueError("Coverage name lists must be unique ordinary identifiers")
        return set(value)
    exports = names(coverage.get("exported_functions"))
    if exports != names(coverage.get("selected_functions")) or exports != names(coverage.get("validation_exports")) or exports != {fn["name"] for fn in functions}:
        raise ValueError("Contract and selected/exported/validation roots must agree")
    closure, evidence = names(coverage.get("helper_closure")), coverage.get("functions")
    if not isinstance(evidence, dict) or set(evidence) != closure or not exports <= closure:
        raise ValueError("Function evidence must exactly match helper closure")
    graph, ids = {}, set()
    for name, item in evidence.items():
        if not isinstance(item, dict) or item.get("virtualized") is not True:
            raise ValueError("Every selected root/helper must have virtualized evidence")
        names(item.get("parameters"), True)
        if len(item["parameters"]) > 16:
            raise ValueError("Invalid parameter count")
        graph[name] = names(item.get("helpers"), True)
        if not graph[name] <= closure:
            raise ValueError("Helper reference outside closure")
        count, identifier = item.get("instruction_count"), item.get("vm_function_id")
        if type(count) is not int or count < 1 or type(identifier) is not int or not 0 <= identifier < len(closure) or identifier in ids:
            raise ValueError("Invalid instruction count/VM id")
        ids.add(identifier)
    active, reached = set(), set()
    def visit(name):
        if name in active:
            raise ValueError("Recursive helper coverage unsupported")
        if name not in reached:
            active.add(name)
            for child in graph[name]: visit(child)
            active.remove(name); reached.add(name)
    for name in exports: visit(name)
    if reached != closure:
        raise ValueError("Helper closure includes unreachable functions")
    for fn in functions:
        if evidence[fn["name"]]["parameters"] != [p["name"] for p in fn["parameters"]]:
            raise ValueError("Sampling parameters differ from inspected source")


def validate_build(report_path, contract_path, output_dir, *, workspace_root,
                   random_cases=8192, seed=20261020, timeout_seconds=120):
    root, report_path, output = (Path(os.path.abspath(value)) for value in (workspace_root, report_path, output_dir))
    for path in (root, report_path, output): _no_links(path)
    if not report_path.is_relative_to(root) or not output.is_relative_to(root) or output.exists():
        raise ValueError("Owned workspace input and fresh validation output required")
    if any(p.casefold() in {"rea-analysis-reports", "attackerfolder"} for path in (report_path, output) for p in path.parts):
        raise ValueError("Received/shared paths are not validation inputs")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
        raise ValueError("timeout_seconds must be an integer in 1..600")
    from .projects import ProjectService
    contract_path = ProjectService(root)._owned(contract_path)
    contract_bytes, report_bytes = _read(contract_path, 256 * 1024), _read(report_path, 16 * 1024 * 1024)
    contract, report = validate_contract(_json(contract_bytes)), _json(report_bytes)
    cases = make_cases(contract, random_cases, seed)
    if not isinstance(report, dict) or report.get("status") != "artifact_created_unvalidated" or report.get("backend") != BACKEND:
        raise ValueError("Successful owned JavaScript VM build report required")
    _verify_coverage(report.get("coverage"), contract["functions"])
    node_record = report.get("toolchain", {}).get("files", {}).get("node", {})
    node = Path(node_record.get("path", ""))
    _no_links(node)
    if not node.is_absolute() or not node.is_file() or _hash(node) != node_record.get("sha256"):
        raise ValueError("Pinned Node executable changed/missing")
    worker = TOOLS / "validate.cjs"
    _no_links(worker)
    worker_hash = _hash(worker)
    artifacts = {}
    for arm in ("baseline", "protected"):
        item = report.get("artifacts", {}).get(arm, {})
        path = _artifact_path(root, report_path.parent, item.get("path", ""))
        if path.suffix != ".cjs" or _hash(path) != item.get("sha256"):
            raise ValueError("Owned JavaScript artifact hash differs from build")
        artifacts[arm] = {"path": str(path), "sha256": item["sha256"], "bytes": path.stat().st_size}
    stop = root / ".runs/defense-loop/STOP"
    if stop.exists(): return {"status": "cancelled", "reason": "Defense STOP exists"}
    output.mkdir(parents=True, exist_ok=False)
    result = {"schema_version": 1, "status": "failed", "backend": BACKEND, "artifacts": artifacts,
              "build_report_sha256": hashlib.sha256(report_bytes).hexdigest(), "contract_sha256": hashlib.sha256(contract_bytes).hexdigest(),
              "tool_hashes": {str(node): node_record["sha256"], str(worker): worker_hash,
                             str(Path(__file__).resolve()): _hash(__file__),
                             str(Path(__file__).with_name("script_validation_evidence.py").resolve()):
                             _hash(Path(__file__).with_name("script_validation_evidence.py"))},
              "random_cases_requested": random_cases, "cases_per_function": {name: len(rows) for name, rows in cases.items()},
              "seed": seed, "behavior_repeats": 2, "functions": {}, "execution": {}, "external_attack_evaluation": "not_evaluated",
              "limitations": ["Owned module child execution is bounded, not an OS security sandbox.",
                              "Number inputs include special/fractional edges outside random integer bounds.",
                              "Exact scalar values/types and exception classes; not traces/messages/all-input equivalence.",
                              "Timing includes JS calls and tagged observation, excludes process startup/module load.",
                              "Memory/timeout/output limits may reject large computations; no performance or defense pass inferred."]}
    _save(output / "cases.json", cases)
    try:
        replies = {}
        for arm, artifact in artifacts.items():
            if _hash(node) != node_record["sha256"] or _hash(worker) != worker_hash:
                raise ValueError("Validation tools changed before execution")
            request_path, reply_path = output / (arm + ".request.json"), output / (arm + ".reply.json")
            _save(request_path, {"source_path": artifact["path"], "sha256": artifact["sha256"],
                                 "functions": contract["functions"], "cases": cases, "reply_path": str(reply_path)})
            process = run_logged([str(node), "--no-addons", "--max-old-space-size=256", str(worker), str(request_path)],
                                 root, output / arm, timeout_seconds, cancel_file=stop, env=clean_node_environment())
            result["execution"][arm] = process
            if process.get("returncode") != 0 or process.get("cancelled") or process.get("timed_out"):
                result["status"] = "cancelled" if process.get("cancelled") else "timed_out" if process.get("timed_out") else "failed"
                raise ValueError(arm + " Node worker failed/timed out/cancelled")
            cleanup = process.get("cleanup", {})
            if os.name == "nt" and not (cleanup.get("job_assigned") and cleanup.get("active_after") == 0 and cleanup.get("parent_exit_confirmed") and cleanup.get("job_handle_closed")):
                raise ValueError("Node worker cleanup unverified")
            replies[arm] = _json(_read(reply_path, 64 * 1024 * 1024))
        for name, rows in cases.items():
            a, b = replies["baseline"], replies["protected"]
            agreement = compare_repeated_observations(a, b, name, len(rows))
            first = a["outputs"][name]
            base_ns, protected_ns = a["timings"][name]["median_ns"], b["timings"][name]["median_ns"]
            result["functions"][name] = {"cases": len(rows), **agreement,
                "baseline_ordinary_returns": sum(item["kind"] == "return" for item in first),
                "baseline_exceptions": sum(item["kind"] == "exception" for item in first),
                "baseline_timing": a["timings"][name], "protected_timing": b["timings"][name],
                "slowdown_ratio": protected_ns / base_ns if base_ns else None}
        unchanged = (hashlib.sha256(_read(report_path, 16 * 1024 * 1024)).hexdigest() == result["build_report_sha256"]
                     and hashlib.sha256(_read(contract_path, 256 * 1024)).hexdigest() == result["contract_sha256"]
                     and all(_hash(Path(item["path"])) == item["sha256"] for item in artifacts.values())
                     and all(_hash(Path(path)) == digest for path, digest in result["tool_hashes"].items()))
        result["inputs_unchanged"] = unchanged
        if unchanged and all(item["sampled_output_match"] and item["deterministic"] and item["baseline_ordinary_returns"] > 0 for item in result["functions"].values()):
            result["status"] = "functional_samples_passed"
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {str(exc)[:2048]}"
    _save(output / "validation.json", result)
    return result
