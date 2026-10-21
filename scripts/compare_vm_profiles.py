"""Private shared-vs-per-function VM cost comparison; explicitly different profiles.

This does not relax native_performance.prepare's same-profile gate. It reuses
only that module's pinned, bounded measurement worker after its own preflight.
No attack, publication, protection-efficiency or performance-acceptance claim.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from antirea import native_performance as perf
from antirea.bindings import validate_contract
from antirea.diversify import inspect_vm_bindings
from antirea.hardening import inspect_hardening_artifact


MULTI_COMPONENT = "per_function_independent_vm_indirect_dispatch"
QUALIFICATION = ("Different protection profiles: shared direct VM versus per-function independent codecs and indirect dispatch. "
                 "Not a same-profile optimization or proof of stronger resistance. " + perf.QUALIFICATION)


def _source_ir_identity(text, directory):
    """Exclude only build-location comment/DIFile directory, not code or data."""
    escaped = str(directory).replace('\\', '\\\\')
    text = re.sub(r"(?m)^; ModuleID = [^\n]*\n", "", text)
    text = re.sub(r'(?m)^(!\d+ = !DIFile\(filename: "[^"\n]*", directory: ")'
                  + re.escape(escaped) + r'("\).*)$', r'\1<BUILD_DIRECTORY>\2', text)
    return hashlib.sha256(text.encode()).hexdigest()


def _profile_delta(current, candidate):
    """Permit the named diversification change, never lost scope/passes/fusion."""
    old_report, old_manifest = current
    new_report, new_manifest = candidate
    old = perf._proof_identity(old_report, old_manifest)
    new = perf._proof_identity(new_report, new_manifest)
    if old_manifest.get("engine_mode", "shared_direct") != "shared_direct" or new_manifest.get("engine_mode") != "per_function_indirect":
        raise ValueError("comparison requires shared-direct current and per-function-indirect candidate")
    for field in ("selected_functions", "exports", "requested_core_passes", "handlers", "format", "requested_hardening_layers"):
        if old[field] != new[field]:
            raise ValueError("profile comparison changed invariant: " + field)
    invariant_fields = ("global", "original_bytes", "original_instructions", "emitted_instructions", "fused_groups",
                        "fusion_counts", "absorbed_dispatches", "original_sha256", "encoded_bytes", "relocated_branch_targets")
    def original_records(manifest):
        return sorted([{key: blob[key] for key in invariant_fields} for blob in manifest["blobs"]], key=lambda item: item["global"])
    if original_records(old_manifest) != original_records(new_manifest):
        raise ValueError("original bytecode or instruction fusion changed")
    old_retained, new_retained = set(old["retained_components"] or []), set(new["retained_components"] or [])
    if not old_retained.issubset(new_retained) or MULTI_COMPONENT not in new_retained:
        raise ValueError("candidate lost retained protection or lacks multi-VM evidence")
    return {"current": "shared_direct", "candidate": "per_function_indirect",
            "same_protection_profile": False, "preserved_fields": list(invariant_fields),
            "current_engine_count": 1, "candidate_engine_count": len(new_manifest["engines"]),
            "new_retained_components": sorted(new_retained - old_retained),
            "scope_and_original_bytecode_unchanged": True}


def prepare_profiles(current_report, candidate_report, contract_path, workspace_root):
    root, contract_path = perf._path(workspace_root), perf._path(contract_path)
    if not contract_path.is_relative_to(root):
        raise ValueError("contract must be owned by the workspace")
    perf._artifact_path(root, contract_path.parent, str(contract_path))
    contract = validate_contract(perf._load(contract_path))
    reports, manifests, pinned, original_ir_identities = {}, {}, {}, {}
    for arm, supplied in (("current", current_report), ("candidate", candidate_report)):
        path = perf._path(supplied)
        if not path.is_relative_to(root / ".runs"):
            raise ValueError("comparison only accepts private workspace builds")
        perf._artifact_path(root, path.parent, str(path))
        report = perf._load(path)
        if report.get("status") != "artifact_created_unvalidated":
            raise ValueError("comparison requires successful owned builds")
        files = {}
        for filename in ("module.before.ll", "diversification.json", "runtime.after.ll", "protected.codegen.ll"):
            file = perf._artifact_path(root, path.parent, str(path.parent / filename))
            if perf._hash(file) != report.get("artifact_hashes", {}).get(filename):
                raise ValueError("build artifact hash differs: " + filename)
            files[filename] = file
            pinned[str(file)] = perf._hash(file)
        manifest = perf._load(files["diversification.json"])
        original_ir_identities[arm] = _source_ir_identity(files["module.before.ll"].read_text(encoding="utf-8-sig"), path.parent)
        perf.verify_integer_abi(files["module.before.ll"].read_text(encoding="utf-8-sig"), contract)
        retained = inspect_hardening_artifact(manifest, files["runtime.after.ll"].read_text(encoding="utf-8-sig"),
                                              files["protected.codegen.ll"].read_text(encoding="utf-8-sig"))
        if retained["verified_retained_components"] != report["coverage"]["hardening_evidence"]["verified_retained_components"]:
            raise ValueError("retained protection evidence differs from pinned IR")
        if arm == "candidate":
            bindings = inspect_vm_bindings(files["protected.codegen.ll"].read_text(encoding="utf-8-sig"), manifest)
            if set(bindings) != set(report["coverage"]["selected_functions"]):
                raise ValueError("candidate VM binding set differs from selected scope")
        reports[arm], manifests[arm] = report, manifest
        pinned[str(path)] = perf._hash(path)
    current, candidate = reports["current"], reports["candidate"]
    if current["seed"] != candidate["seed"] or current["project"]["input_hashes"] != candidate["project"]["input_hashes"]:
        raise ValueError("comparison requires identical original inputs and build seed")
    if original_ir_identities["current"] != original_ir_identities["candidate"]:
        raise ValueError("original source IR differs")
    delta = _profile_delta((current, manifests["current"]), (candidate, manifests["candidate"]))
    exports = candidate["coverage"]["exported_functions"]
    if len(exports) != len(set(exports)) or set(exports) != {function["name"] for function in contract["functions"]}:
        raise ValueError("contract must observe every exported function")
    artifacts = {}
    for arm, report_name, kind in (("baseline", "current", "baseline"), ("current", "current", "protected"),
                                    ("candidate", "candidate", "protected")):
        artifact = reports[report_name]["artifacts"][kind]
        folder = Path(current_report if report_name == "current" else candidate_report).absolute().parent
        file = perf._artifact_path(root, folder, artifact["path"])
        if perf._hash(file) != artifact["sha256"]:
            raise ValueError("DLL hash differs from build report")
        artifacts[arm] = {"path": str(file), "sha256": artifact["sha256"], "bytes": file.stat().st_size,
                          "build_directory": str(folder)}
        pinned[str(file)] = artifact["sha256"]
    pinned[str(contract_path)] = perf._hash(contract_path)
    pinned[str(Path(__file__).absolute())] = perf._hash(Path(__file__))
    return {"schema_version": 1, "workspace_root": str(root), "contract": contract, "artifacts": artifacts,
            "profile_comparison": delta, "pinned_inputs": pinned, "qualification": QUALIFICATION,
            "original_ir_identity": {"sha256": original_ir_identities["current"],
                                     "normalization": "ModuleID comment and exact build directory in DIFile only; original raw hashes also pinned"},
            "measurement_engine": {"path": str(Path(perf.__file__).absolute()), "sha256": perf._hash(Path(perf.__file__))}}


def compare_profiles(current_report, candidate_report, contract_path, output_dir, *, workspace_root, timeout_seconds=300):
    request = prepare_profiles(current_report, candidate_report, contract_path, workspace_root)
    root, output = Path(request["workspace_root"]), perf._path(output_dir)
    if output.exists() or not output.is_relative_to(root / ".runs") or output == root / ".runs":
        raise ValueError("output must be a fresh private run directory")
    if any(part.casefold() in {"defense-loop", "rea-analysis-reports", "attackerfolder"}
           for part in output.relative_to(root).parts):
        raise ValueError("shared output directory is not permitted")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
        raise ValueError("timeout must be an integer in 1..600")
    stop = root / ".runs/defense-loop/STOP"
    if stop.exists():
        raise ValueError("defense STOP marker exists")
    output.mkdir(parents=True)
    request["reply_path"] = str(output / "worker-reply.json")
    request_path = output / "worker-request.json"
    perf._save(request_path, request)
    bootstrap = ("import runpy,sys; sys.path.insert(0,sys.argv.pop(1)); "
                 "runpy.run_module('antirea.native_performance',run_name='__main__',alter_sys=True)")
    process = perf.run_logged([sys.executable, "-I", "-S", "-c", bootstrap, str(ROOT), "--worker", str(request_path)],
                               output, output / "worker", timeout=timeout_seconds, cancel_file=stop)
    result = dict(request, process=process, status="failed")
    cleanup = process.get("cleanup", {})
    if (process.get("returncode") == 0 and not process.get("cancelled") and not process.get("timed_out")
            and cleanup.get("parent_exit_confirmed") is True and cleanup.get("status") == "assigned_job_empty"
            and cleanup.get("job_handle_closed") is True):
        result.update(perf._load(Path(request["reply_path"])))
    if any(perf._hash(Path(path)) != digest for path, digest in request["pinned_inputs"].items()):
        result["status"] = "input_changed"
    perf._save(output / "performance.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("current-report", "candidate-report", "contract", "output-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path, default=ROOT)
    args = parser.parse_args()
    result = compare_profiles(args.current_report, args.candidate_report, args.contract, args.output_dir,
                               workspace_root=args.workspace_root)
    print(json.dumps({"status": result["status"], "profile_comparison": result["profile_comparison"],
                      "timings": result.get("timings", {})}, indent=2))
    return 0 if result["status"] == "measured" else 1


if __name__ == "__main__":
    raise SystemExit(main())
