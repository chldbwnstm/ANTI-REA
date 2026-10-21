"""Service-level tests for the native (Go / Swift) source-integrate route.

Defender-only (phase22 SERVICE lane). These exercise the public service boundary of
``antirea.native_application.integrate_source_application`` -- binding a saved
``go_typed_native`` / ``swift_llvm_native`` producer job, validating the strict
integration spec and application-sample contract, INDEPENDENTLY AUTHENTICATING the
producer scalar-ABI contract (schema + claimed frontend hash + Go inline equality)
and native build origin (confined path + actual hash + status/artifacts/coverage +
selected closure) BEFORE the engine, resolving application sources relative to the
SPEC's own parent directory, pinning inputs, authenticating a persisted engine
report (exact staging path->sha map + producer artifact path/size/sha), independently
re-deriving per-case / control / preparation raw child evidence (exact 9-key command
metadata, two controls, no adapter controls) from pinned receipts + captured logs,
and inventorying the engine-owned deployment bundle -- entirely against PURE
SYNTHETIC, fully self-consistent saved producer fixtures (NO compiler) plus a
BOUNDARY MOCK of the trusted engine for the execution phase.

The synthetic fixtures and the mocked engine are never real integration evidence;
the only real integration proof is root's separate fresh Go + Swift CLI E2E after
production freeze. No REA/attack/received code runs; no native compiler or target is
launched here; no attacker/received-report path, ``env.setting`` or ``LINKREPRO``
artifact is traversed (reserved segments are only ever synthetic strings under a
private temp dir); no install/download/publish/commit happens. Neither native
runtime uses an external adapter DLL, so there are NO adapter controls.

Run ONLY through the OUTER bounded harness ``.runs/phase22-root/run_focused.py`` ->
``antirea.process.run_logged``; do not launch directly with unbounded unittest.
Mock/pure tests are not real compiler or application qualification.
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from antirea import native_application as na  # REQUIRED production module: no skip gate.
from antirea.native_application import NativeApplicationError
from antirea.projects import ProjectService

REAL_STOP = ROOT / ".runs" / "defense-loop" / "STOP"

# Reused protected native core bytes hash to the producer's PROTECTED pin. The
# baseline / original reference exe / original source bytes are FORBIDDEN in a bundle.
_NATIVE_BYTES = b"MZ\x90\x00native-reused-protected-core-0001"
_PROT_SHA = na._digest(_NATIVE_BYTES)
_BASE_BYTES = b"MZ\x90\x00native-baseline-unprotected-0002"
_BASE_SHA = na._digest(_BASE_BYTES)
_REF_BYTES = b"MZ\x90\x00native-original-reference-exe-0003"
_REF_SHA = na._digest(_REF_BYTES)
_ORIG_CORE_SRC_SHA = na._digest(b"ORIGINAL-CORE-SOURCE-BYTES")

_APP_EXE = b"MZ\x90\x00native-protected-app-exe"
_SWIFT_RT = b"MZ\x90\x00swiftCore-runtime-dll"

_EXE_REL = "app.exe"
_CORE_REL = "protected.dll"
_SWIFT_RT_REL = "swiftCore.dll"

# Native VM coverage recorded in the native build report; the producer (go/swift)
# report republishes it (Go merges exported_functions).
_NATIVE_COVERAGE = {"functions": {"fold": 2}, "original_vm": 1, "final_vm": 4,
                    "selected_functions": ["fold"], "exported_functions": ["fold"]}


def _synthetic_job_id() -> str:
    return "source-20261020T010203Z-" + uuid.uuid4().hex[:12]


def _backend(language):
    return na._BACKEND_BY_LANGUAGE[language]


def _spec_obj(language, application_sources):
    return {"schema_version": 1, "kind": na.INTEGRATION_SPEC_KIND, "language": language,
            "application_sources": list(application_sources)}


def _valid_contract():
    return {"schema_version": 1, "kind": na.APPLICATION_CONTRACT_KIND,
            "cases": [{"label": "fold(5)", "args": ["5"], "expect": {"returncode": 0, "stdout": "25\n"}},
                      {"label": "add(7,3)", "args": ["7", "3"], "expect": {"returncode": 0, "stdout": "10\n"}}]}


def _scalar_contract():
    return {"schema_version": 1, "library_name": "NativeApp", "calling_convention": "cdecl",
            "functions": [{"name": "fold", "return_type": "int32_t",
                           "parameters": [{"name": "a0", "type": "int32_t"}]}]}


def _build_producer(ws: Path, *, language="go", spec_subdir=None, app_sources=None,
                    decoy_same_name=False, contract_obj=None, scalar_contract=None,
                    mutate_plan=None, mutate_result=None, mutate_report=None, mutate_native=None,
                    recompute_fingerprint=True, artifacts=None):
    """Write a fully consistent synthetic native producer job for ``language``,
    including the on-disk scalar-ABI contract file and native build report the
    service independently authenticates in block 2b.

    ``spec_subdir`` places the integration spec in a project subdirectory;
    ``app_sources`` are spec-relative source names (resolved against the spec's own
    parent); ``decoy_same_name`` additionally drops a same-name wrong-root file so a
    test can prove the service resolves relative to spec_path.parent, not app_dir.
    """
    ext = na._SOURCE_SUFFIX[language]
    if app_sources is None:
        app_sources = ["App" + ext] if spec_subdir else ["app/App" + ext]
    svc = ProjectService(ws)
    tools_dir = ws / ".tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    (tools_dir / "kagura-toolchain.json").write_text(
        json.dumps({"llvm_version": "test-18", "target": "x86_64-pc-windows-msvc"}), encoding="utf-8")

    backend = _backend(language)
    pkg = ws / ("pkg-" + uuid.uuid4().hex[:8])
    (pkg / "core").mkdir(parents=True)
    source = pkg / "project.json"
    core_src = pkg / "core" / ("Core" + ext)
    source.write_text(json.dumps({"schema_version": 1, "name": "NativeApp", "language": language,
                                  "sources": ["core/Core" + ext], "functions": ["fold"]}), encoding="utf-8")
    core_src.write_text("// core " + language + " scalar source leaf\n", encoding="utf-8")

    spec_dir = pkg / spec_subdir if spec_subdir else pkg
    spec_dir.mkdir(parents=True, exist_ok=True)
    app_files = []
    for rel in app_sources:
        f = spec_dir / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("// app %s caller %s\n" % (language, rel), encoding="utf-8")
        app_files.append(f)
    if decoy_same_name:
        for rel in app_sources:
            decoy = pkg / Path(rel).name
            if os.path.normcase(str(decoy)) != os.path.normcase(str(spec_dir / rel)):
                decoy.write_text("// DECOY wrong-root same-name file; MUST NOT be selected\n", encoding="utf-8")

    spec = _spec_obj(language, app_sources)
    contract = _valid_contract() if contract_obj is None else contract_obj
    spec_file = spec_dir / "integration.json"
    contract_file = spec_dir / "application-contract.json"
    spec_file.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
    contract_file.write_text(json.dumps(contract, indent=2) + "\n", encoding="utf-8")

    inspection = {"schema_version": 1, "language": language, "name": "NativeApp",
                  "project_path": str(source), "project_root": str(pkg),
                  "sources": [str(svc._owned(core_src))], "source_files": [str(svc._owned(core_src))],
                  "compiler_inputs": {}, "input_hashes": {},
                  "exported_functions": ["fold"], "functions": ["fold"]}
    if artifacts is None:
        artifacts = {"baseline": {"path": str(pkg / "baseline.bin"), "sha256": _BASE_SHA, "bytes": 11},
                     "protected": {"path": str(pkg / "protected.bin"), "sha256": _PROT_SHA, "bytes": 22}}
    coverage = dict(_NATIVE_COVERAGE)

    job = ws / ".runs" / "source-protection" / _synthetic_job_id()
    (job / "build" / "frontend").mkdir(parents=True)
    (job / "build" / "native").mkdir(parents=True)

    scalar = _scalar_contract() if scalar_contract is None else scalar_contract
    scalar_file = job / "build" / "frontend" / "contract.json"
    scalar_data = (json.dumps(scalar, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    scalar_file.write_bytes(scalar_data)
    scalar_sha = na._digest(scalar_data)
    metadata_sha = na._digest(b'{"package":"main"}')

    # The native build report carries its OWN (deep-copied) artifacts/coverage so a
    # test can diverge the native origin from the producer report without aliasing.
    native_obj = {"schema_version": 1, "status": "artifact_created_unvalidated",
                  "artifacts": json.loads(json.dumps(artifacts)), "coverage": dict(_NATIVE_COVERAGE)}
    if mutate_native is not None:
        mutate_native(native_obj)
    native_file = job / "build" / "native" / "report.json"
    native_data = (json.dumps(native_obj, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    native_file.write_bytes(native_data)
    native_sha = na._digest(native_data)

    report = {"schema_version": 1, "backend": backend,
              "status": "artifact_created_unvalidated", "language": language, "project": inspection,
              "artifacts": artifacts, "coverage": coverage,
              "contract_path": str(Path(os.path.abspath(scalar_file))),
              "native_report": str(Path(os.path.abspath(native_file))), "native_report_sha256": native_sha,
              "reference_executable": {"path": str(job / "build" / "frontend" / "reference.exe"),
                                       "sha256": _REF_SHA},
              "source_hashes": {str(core_src): _ORIG_CORE_SRC_SHA}}
    if language == "go":
        report["contract"] = scalar
        report["frontend_artifact_hashes"] = {"contract.json": scalar_sha, "metadata.json": metadata_sha}
        report["methods"] = [{"name": "Fold", "export": "fold", "is_root": True,
                              "parameters": ["i32"], "return_type": "i32"}]
    else:
        report["artifact_hashes"] = {"frontend/contract.json": scalar_sha}
        report["normalization"] = {"selected_functions": ["fold"]}
        report["public_interface"] = {"path": str(job / "build" / "frontend" / "AntireaOwned.swiftinterface"),
                                      "sha256": na._digest(b"interface")}
    if mutate_report is not None:
        mutate_report(report)
    report_bytes = na._create_json(job / "build" / "report.json", report)
    build_report_sha = na._digest(report_bytes)

    snapshot = svc._snapshot(source, inspection)
    toolchain = svc._toolchain(inspection)
    plan = {"schema_version": 1, "plan_id": job.name, "kind": "native_source_build",
            "workspace_root": str(ws), "project_path": str(source), "seed": 1729,
            "inspection": inspection, "inputs": snapshot, "toolchain": toolchain,
            "blockers": [], "output_dir": str(job / "build")}
    if mutate_plan is not None:
        mutate_plan(plan)
    fingerprint = na._digest(na._encoded(plan))
    result = {"schema_version": 1, "status": "artifact_created_unvalidated",
              "backend": backend, "plan_id": job.name,
              "fingerprint": fingerprint if recompute_fingerprint else "0" * 64,
              "build_report_sha256": build_report_sha, "artifacts": artifacts, "coverage": coverage,
              "external_attack_evaluation": "not_evaluated", "published": False}
    if mutate_result is not None:
        mutate_result(result)
    na._create_json(job / "plan.json", plan)
    na._create_json(job / "result.json", result)

    app_source_map = {str(svc._owned(f)): na._digest(f.read_bytes()) for f in app_files}
    return SimpleNamespace(svc=svc, ws=ws, job=job, plan_id=job.name, pkg=pkg, source=source,
                           spec=spec_file, contract=contract_file, spec_dir=spec_dir,
                           inspection=inspection, fingerprint=fingerprint, artifacts=artifacts,
                           report_path=job / "build" / "report.json", report_sha=build_report_sha,
                           snapshot=snapshot, language=language, backend=backend,
                           app_files=app_files, app_source_map=app_source_map,
                           scalar_file=scalar_file, scalar_sha=scalar_sha,
                           native_file=native_file, native_sha=native_sha)


def _deploy_files(language):
    files = {_EXE_REL: _APP_EXE, _CORE_REL: _NATIVE_BYTES}
    if language == "swift":
        files[_SWIFT_RT_REL] = _SWIFT_RT
    return files


def _runtime_files(language):
    return [_SWIFT_RT_REL] if language == "swift" else []


def _clean_receipt(pid, rc, *, stdout=None, stderr=None):
    r = {"argv": [".\\app.exe"], "pid": pid, "returncode": rc,
         "timed_out": False, "cancelled": False, "error": None, "post_cleanup_wait_error": None,
         "seconds": 0.08, "cleanup": {"method": "windows_job", "job_assigned": True, "parent_pid": pid,
                                      "parent_exit_confirmed": True, "active_after": 0,
                                      "status": "assigned_job_empty", "job_handle_closed": True}}
    if stdout is not None:
        r["stdout"] = str(stdout)
    if stderr is not None:
        r["stderr"] = str(stderr)
    return r


def _safe(label):
    return re.sub(r"[^A-Za-z0-9]+", "_", label)[:60]


def _child(out: Path, name, pid, rc, stdout_bytes=b""):
    receipts, logs = out / "receipts", out / "logs"
    receipts.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    sout = logs / (name + ".stdout.log")
    serr = logs / (name + ".stderr.log")
    sout.write_bytes(stdout_bytes)
    serr.write_bytes(b"")
    receipt = _clean_receipt(pid, rc, stdout=str(sout), stderr=str(serr))
    rp = receipts / (name + ".process.json")
    data = json.dumps(receipt).encode("utf-8")
    rp.write_bytes(data)
    return {"receipt_path": str(rp), "receipt_sha256": na._digest(data),
            "stdout_log": str(sout), "stderr_log": str(serr)}


def _build_child_evidence(out: Path, cases, language):
    """Persisted raw receipts + bound logs + matching comparison.commands /
    preparation_commands / cases. Comparison command entries carry EXACTLY the 9
    metadata keys with case_arm/control tokens and unused identity fields None; only
    two fail-closed controls (missing_core, unset_core); preparation holds the
    language's required labels."""
    commands, case_reports = [], []
    i = 0
    for c in cases:
        exp = c["expect"]
        for arm in ("original", "protected"):
            lbl = "case:%s:%s" % (c["label"], arm)
            i += 1
            fields = _child(out, "%d_%s" % (i, _safe(lbl)), 1000 + i, exp["returncode"],
                            stdout_bytes=exp["stdout"].encode("utf-8"))
            commands.append({"label": lbl, "kind": "case_arm", "arm": arm,
                             "case_label": c["label"], "control": None, **fields})
        obs = {"returncode": exp["returncode"], "stdout": exp["stdout"], "stderr_sha256": na._digest(b"")}
        case_reports.append({"label": c["label"], "args": c["args"], "expect": dict(exp),
                             "baseline": dict(obs), "protected": dict(obs), "match": True})
    for short in ("missing_core", "unset_core"):
        lbl = "control:%s" % short
        i += 1
        fields = _child(out, "%d_%s" % (i, _safe(lbl)), 2000 + i, 3)  # fail-closed: non-zero
        commands.append({"label": lbl, "kind": "control", "control": short,
                         "arm": None, "case_label": None, **fields})
    prep = []
    for j, plbl in enumerate(na._REQUIRED_PREP_LABELS[language]):
        tool = "swiftc" if language == "swift" else "go"
        fields = _child(out, "prep_%d_%s" % (j, _safe(plbl)), 3000 + j, 0)  # exit 0
        prep.append({"label": plbl, "kind": "compile", "tool": tool, "cwd": str(out), **fields})
    return {"commands": commands, "preparation_commands": prep, "cases": case_reports}


def _authentic_engine(h, *, native_bytes=_NATIVE_BYTES, during_run=None, mutate_report=None,
                      child_tamper=None, persist_divergent=False, deploy_outside=False,
                      extra_disk_file=None, drop_from_disk=None, deploy_files=None,
                      runtime_files=None):
    """Boundary stand-in returning a FULLY AUTHENTIC native engine report + deployment
    + persisted raw child receipts/logs. Knobs introduce a single realistic defect to
    prove the service fails closed."""
    language = h.language
    files = dict(deploy_files if deploy_files is not None else _deploy_files(language))
    if _CORE_REL in files:
        files[_CORE_REL] = native_bytes
    rt = _runtime_files(language) if runtime_files is None else runtime_files

    def run_integration(*, producer_report_path, integration_spec_path, application_contract_path,
                        output_dir, workspace_root, timeout_seconds=120, trusted_inputs=None):
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        deploy = (out.parent if deploy_outside else out) / "deployment"
        deploy.mkdir(parents=True, exist_ok=True)
        manifest = []
        for rel, data in files.items():
            dst = deploy / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(data)
            manifest.append({"relative_path": rel, "sha256": na._digest(data), "bytes": len(data)})
        if extra_disk_file is not None:
            (deploy / extra_disk_file).parent.mkdir(parents=True, exist_ok=True)
            (deploy / extra_disk_file).write_bytes(b"UNLISTED")
        if drop_from_disk is not None:
            (deploy / drop_from_disk).unlink()

        cases = na._validate_app_contract(json.loads(Path(application_contract_path).read_text(encoding="utf-8")))
        prod = json.loads(Path(producer_report_path).read_text(encoding="utf-8"))
        prod_sha = na._digest(Path(producer_report_path).read_bytes())
        contract_sha = na._digest(Path(prod["contract_path"]).read_bytes())
        ce = _build_child_evidence(out, cases, language)
        if child_tamper is not None:
            child_tamper(ce, out)
        report = {
            "schema_version": 1, "kind": "native_application_integration", "status": na.ENGINE_STATUS_PASSED,
            "language": language, "fresh_protected_native_build": False,
            "producer": {"backend": h.backend, "report_path": producer_report_path, "report_sha256": prod_sha,
                         "artifacts": prod["artifacts"],
                         "contract_path": prod["contract_path"], "contract_sha256": contract_sha,
                         "native_report": {"path": prod["native_report"],
                                           "sha256": prod["native_report_sha256"]}},
            "staging": {"native_core_sha256": na._digest(native_bytes),
                        "application_source_hashes": dict(h.app_source_map),
                        "original_core_excluded_from_protected_compile": True},
            "comparison": {"status": na.ENGINE_COMPARISON_PASSED, "all_match": True, "env_ok": True,
                           "route_proof_ok": True, "integrity_verified_before_and_after": True,
                           "expectations_ok": True, "missing_core_control_ok": True,
                           "total_cases": len(cases), "stop_cancellations": [],
                           "cases": ce["cases"], "commands": ce["commands"]},
            "preparation_commands": ce["preparation_commands"],
            "deployment": {"path": str(deploy), "allowlist": sorted(files),
                           "files": sorted(manifest, key=lambda m: m["relative_path"]),
                           "forbidden_absent": True, "executable": _EXE_REL,
                           "native_core": _CORE_REL, "runtime_files": list(rt)},
            "trusted_inputs_verification": {"verified": True, "declared_count": len(trusted_inputs or [])},
        }
        if mutate_report is not None:
            mutate_report(report)
        persisted = report
        if persist_divergent:
            persisted = json.loads(json.dumps(report))
            persisted["status"] = "TAMPERED_ON_DISK"
        (out / "integration.json").write_text(json.dumps(persisted), encoding="utf-8")
        if during_run is not None:
            during_run()
        return report

    return SimpleNamespace(run_integration=run_integration)


def _run(h, engine, *, timeout_seconds=90):
    with mock.patch.object(na, "_load_engine", lambda: engine):
        return na.integrate_source_application(h.svc, h.plan_id, str(h.spec), str(h.contract),
                                               timeout_seconds=timeout_seconds)


class _TmpWs(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.ws = Path(self._td.name)


# ---------------------------------------------------------------------------
# Reserved / safe-name guards (pure, synthetic strings only)
# ---------------------------------------------------------------------------
class ReservedGuardUnitTests(unittest.TestCase):
    def test_reserved_segments_refused_lexically(self):
        for bad in ("rea-analysis-reports/x", "a/attackerfolder/b", "env.setting",
                    "LINKREPRO/y", "defense-loop/STOP"):
            with self.assertRaises(NativeApplicationError):
                na._reserved_guard(bad)

    def test_non_string_and_control_char_paths_refused(self):
        for bad in (None, 5, "", "a\x00b", "ok\nno"):
            with self.assertRaises(NativeApplicationError):
                na._reserved_guard(bad)

    def test_ordinary_owned_path_passes(self):
        na._reserved_guard("app/App.go")
        na._reserved_guard("sub/dir/main.swift")


class SafeRelativeSourceTests(unittest.TestCase):
    def test_valid_nested_source(self):
        self.assertEqual(na._safe_relative_source("app\\App.go", "s", ".go"), "app/App.go")
        self.assertEqual(na._safe_relative_source("a/b/main.swift", "s", ".swift"), "a/b/main.swift")

    def test_rejects_traversal_absolute_drive_reserved(self):
        for bad in ("../x.go", "/abs/x.go", "C:/x.go", "a/../b.go", "attackerfolder/x.go", "a//b.go"):
            with self.assertRaises(NativeApplicationError):
                na._safe_relative_source(bad, "s", ".go")

    def test_rejects_wrong_extension_and_control(self):
        with self.assertRaises(NativeApplicationError):
            na._safe_relative_source("app/App.swift", "s", ".go")
        with self.assertRaises(NativeApplicationError):
            na._safe_relative_source("app/App\x00.go", "s", ".go")


# ---------------------------------------------------------------------------
# Integration spec validation (NO main_class / entry symbol field)
# ---------------------------------------------------------------------------
class IntegrationSpecValidationTests(unittest.TestCase):
    def test_valid_go_and_swift(self):
        for lang in ("go", "swift"):
            out = na._validate_integration_spec(_spec_obj(lang, ["app/App" + na._SOURCE_SUFFIX[lang]]),
                                                plan_language=lang)
            self.assertEqual(out["language"], lang)
            self.assertEqual(out["kind"], na.INTEGRATION_SPEC_KIND)
            self.assertNotIn("main_class", out)

    def test_rejects_main_class_or_any_extra_key(self):
        spec = _spec_obj("go", ["app/App.go"])
        spec["main_class"] = "sample.App"
        with self.assertRaises(NativeApplicationError):
            na._validate_integration_spec(spec, plan_language="go")
        spec2 = _spec_obj("go", ["app/App.go"])
        spec2["runtime_path"] = "x"
        with self.assertRaises(NativeApplicationError):
            na._validate_integration_spec(spec2, plan_language="go")

    def test_rejects_bad_shape(self):
        for bad in (
            [],
            {"schema_version": 2, "kind": na.INTEGRATION_SPEC_KIND, "language": "go", "application_sources": ["app/App.go"]},
            {"schema_version": 1, "kind": "wrong", "language": "go", "application_sources": ["app/App.go"]},
            {"schema_version": 1, "kind": na.INTEGRATION_SPEC_KIND, "language": "rust", "application_sources": ["x.go"]},
            {"schema_version": 1, "kind": na.INTEGRATION_SPEC_KIND, "language": "go", "application_sources": []},
            {"schema_version": 1, "kind": na.INTEGRATION_SPEC_KIND, "language": "go", "application_sources": ["app/App.swift"]},
        ):
            with self.assertRaises(NativeApplicationError):
                na._validate_integration_spec(bad, plan_language="go")

    def test_rejects_duplicate_sources(self):
        spec = _spec_obj("go", ["app/App.go", "app\\App.go"])
        with self.assertRaises(NativeApplicationError):
            na._validate_integration_spec(spec, plan_language="go")

    def test_rejects_language_mismatch_with_plan(self):
        with self.assertRaises(NativeApplicationError):
            na._validate_integration_spec(_spec_obj("go", ["app/App.go"]), plan_language="swift")

    def test_rejects_too_many_sources(self):
        spec = _spec_obj("go", ["app/A%d.go" % i for i in range(na.MAX_APPLICATION_SOURCES + 1)])
        with self.assertRaises(NativeApplicationError):
            na._validate_integration_spec(spec, plan_language="go")


# ---------------------------------------------------------------------------
# Application-sample contract validation
# ---------------------------------------------------------------------------
class ContractValidationTests(unittest.TestCase):
    def test_valid_returns_normalised_cases(self):
        cases = na._validate_app_contract(_valid_contract())
        self.assertEqual([c["label"] for c in cases], ["fold(5)", "add(7,3)"])
        self.assertEqual(cases[0]["expect"], {"returncode": 0, "stdout": "25\n"})

    def test_rejects_non_object_and_missing_or_extra_keys(self):
        for bad in ([], {"schema_version": 1, "kind": na.APPLICATION_CONTRACT_KIND},
                    {"schema_version": 1, "kind": na.APPLICATION_CONTRACT_KIND, "cases": [], "extra": 1}):
            with self.assertRaises(NativeApplicationError):
                na._validate_app_contract(bad)

    def test_rejects_bad_schema_and_kind(self):
        for bad in ({"schema_version": 2, "kind": na.APPLICATION_CONTRACT_KIND, "cases": [{"label": "a", "args": [], "expect": {"returncode": 0, "stdout": ""}}]},
                    {"schema_version": 1, "kind": "nope", "cases": [{"label": "a", "args": [], "expect": {"returncode": 0, "stdout": ""}}]}):
            with self.assertRaises(NativeApplicationError):
                na._validate_app_contract(bad)

    def test_rejects_empty_and_oversized_lists(self):
        with self.assertRaises(NativeApplicationError):
            na._validate_app_contract({"schema_version": 1, "kind": na.APPLICATION_CONTRACT_KIND, "cases": []})
        big = {"schema_version": 1, "kind": na.APPLICATION_CONTRACT_KIND,
               "cases": [{"label": "c%d" % i, "args": [], "expect": {"returncode": 0, "stdout": ""}}
                         for i in range(na.MAX_CASES + 1)]}
        with self.assertRaises(NativeApplicationError):
            na._validate_app_contract(big)

    def test_rejects_malformed_cases(self):
        def one(case):
            return {"schema_version": 1, "kind": na.APPLICATION_CONTRACT_KIND, "cases": [case]}
        for case in (
            {"label": "", "args": [], "expect": {"returncode": 0, "stdout": ""}},
            {"label": "a", "args": "x", "expect": {"returncode": 0, "stdout": ""}},
            {"label": "a", "args": [1], "expect": {"returncode": 0, "stdout": ""}},
            {"label": "a", "args": [True], "expect": {"returncode": 0, "stdout": ""}},
            {"label": "a", "args": ["ok\x00"], "expect": {"returncode": 0, "stdout": ""}},
            {"label": "a", "args": [], "expect": {"returncode": True, "stdout": ""}},
            {"label": "a", "args": [], "expect": {"returncode": 0, "stdout": "x\x00y"}},
            {"label": "a", "args": [], "expect": {"returncode": 0}},
            {"label": "a", "args": [], "expect": {"returncode": 0, "stdout": "", "extra": 1}},
            {"label": "a", "args": []},
        ):
            with self.assertRaises(NativeApplicationError):
                na._validate_app_contract(one(case))

    def test_stdout_allows_whitespace_control(self):
        cases = na._validate_app_contract({"schema_version": 1, "kind": na.APPLICATION_CONTRACT_KIND,
                                           "cases": [{"label": "a", "args": [], "expect": {"returncode": 0, "stdout": "a\tb\r\n"}}]})
        self.assertEqual(cases[0]["expect"]["stdout"], "a\tb\r\n")

    def test_rejects_duplicate_labels(self):
        dup = {"schema_version": 1, "kind": na.APPLICATION_CONTRACT_KIND,
               "cases": [{"label": "x", "args": [], "expect": {"returncode": 0, "stdout": ""}},
                         {"label": "x", "args": [], "expect": {"returncode": 0, "stdout": ""}}]}
        with self.assertRaises(NativeApplicationError):
            na._validate_app_contract(dup)


# ---------------------------------------------------------------------------
# Producer scalar-ABI contract schema (independent, pure)
# ---------------------------------------------------------------------------
class ContractSchemaTests(unittest.TestCase):
    def test_valid_contract_and_exports(self):
        na._validate_producer_contract_schema(_scalar_contract(), ["fold"])

    def test_rejects_undocumented_and_bad_fields(self):
        c = _scalar_contract(); c["unexpected"] = 1
        with self.assertRaises(NativeApplicationError):
            na._validate_producer_contract_schema(c, ["fold"])
        c = _scalar_contract(); c["schema_version"] = 2
        with self.assertRaises(NativeApplicationError):
            na._validate_producer_contract_schema(c, ["fold"])
        c = _scalar_contract(); c["calling_convention"] = "stdcall"
        with self.assertRaises(NativeApplicationError):
            na._validate_producer_contract_schema(c, ["fold"])

    def test_rejects_bad_function_and_param_shape(self):
        c = _scalar_contract(); c["functions"][0]["extra"] = 1
        with self.assertRaises(NativeApplicationError):
            na._validate_producer_contract_schema(c, ["fold"])
        c = _scalar_contract(); c["functions"][0]["parameters"][0] = {"name": "a0"}
        with self.assertRaises(NativeApplicationError):
            na._validate_producer_contract_schema(c, ["fold"])
        c = _scalar_contract(); c["functions"][0]["return_type"] = ""
        with self.assertRaises(NativeApplicationError):
            na._validate_producer_contract_schema(c, ["fold"])

    def test_rejects_exports_disagreement(self):
        with self.assertRaises(NativeApplicationError):
            na._validate_producer_contract_schema(_scalar_contract(), ["fold", "other"])
        with self.assertRaises(NativeApplicationError):
            na._validate_producer_contract_schema(_scalar_contract(), ["notfold"])


# ---------------------------------------------------------------------------
# Comparison-case verifier
# ---------------------------------------------------------------------------
class ComparisonCaseVerifyTests(unittest.TestCase):
    def _cases(self):
        return [{"label": "a", "args": ["1"], "expect": {"returncode": 0, "stdout": "1\n"}}]

    def _reported(self, cases):
        out = []
        for c in cases:
            obs = {"returncode": c["expect"]["returncode"], "stdout": c["expect"]["stdout"]}
            out.append({"label": c["label"], "args": c["args"], "expect": dict(c["expect"]),
                        "baseline": dict(obs), "protected": dict(obs), "match": True})
        return out

    def test_accepts_faithful_reports(self):
        cases = self._cases()
        self.assertTrue(na._verify_comparison_cases({"cases": self._reported(cases)}, cases))

    def test_rejects_count_label_args_expect_arm_and_match_defects(self):
        cases = self._cases()
        self.assertFalse(na._verify_comparison_cases({"cases": []}, cases))
        for mut in (
            lambda b: b[0].__setitem__("label", "other"),
            lambda b: b[0].__setitem__("args", ["2"]),
            lambda b: b[0]["expect"].__setitem__("stdout", "2\n"),
            lambda b: b[0]["protected"].__setitem__("returncode", 1),
            lambda b: b[0].__setitem__("match", False),
            lambda b: b[0].pop("baseline"),
        ):
            bad = self._reported(cases)
            mut(bad)
            self.assertFalse(na._verify_comparison_cases({"cases": bad}, cases))


# ---------------------------------------------------------------------------
# Receipt clean predicate
# ---------------------------------------------------------------------------
class ReceiptCleanTests(unittest.TestCase):
    def _clean(self):
        return _clean_receipt(1234, 0, stdout="o", stderr="e")

    def test_full_clean_receipt_accepted(self):
        self.assertTrue(na._receipt_clean(self._clean()))

    def test_nonzero_exit_still_infrastructure_clean(self):
        self.assertTrue(na._receipt_clean(_clean_receipt(5, 3, stdout="o", stderr="e")))

    def test_empty_or_non_dict_receipt_is_not_clean(self):
        for bad in (None, {}, [], "x"):
            self.assertFalse(na._receipt_clean(bad))

    def test_each_required_field_defect_is_not_clean(self):
        base = self._clean()
        mutations = [
            lambda r: r.update(pid=0), lambda r: r.update(pid=True), lambda r: r.update(pid="x"),
            lambda r: r.update(returncode=True), lambda r: r.update(returncode=1.0),
            lambda r: r.update(timed_out=True), lambda r: r.update(cancelled=True),
            lambda r: r.update(error="boom"), lambda r: r.update(post_cleanup_wait_error="x"),
            lambda r: r.pop("cleanup"),
            lambda r: r["cleanup"].update(method="taskkill"),
            lambda r: r["cleanup"].update(job_assigned=False),
            lambda r: r["cleanup"].update(parent_pid=999999),
            lambda r: r["cleanup"].update(parent_exit_confirmed=False),
            lambda r: r["cleanup"].update(active_after=1),
            lambda r: r["cleanup"].update(active_after=True),
            lambda r: r["cleanup"].update(status="busy"),
            lambda r: r["cleanup"].update(job_handle_closed=False),
        ]
        for mut in mutations:
            r = json.loads(json.dumps(base))
            mut(r)
            self.assertFalse(na._receipt_clean(r))


class ClassifyChildIssuesTests(unittest.TestCase):
    def test_shapes_evidence_into_public_keys(self):
        good = {"infra_failures": [], "cancellations": [], "coverage_ok": True,
                "observations_ok": True, "controls_ok": True, "prep_ok": True}
        out = na._classify_child_issues(good)
        self.assertEqual(out, {"child_infrastructure_failures": [], "child_cancellations": [],
                               "comparison_mismatch": False})
        bad = dict(good, observations_ok=False, infra_failures=[{"label": "x", "reason": "y"}],
                   cancellations=["z"])
        out = na._classify_child_issues(bad)
        self.assertTrue(out["comparison_mismatch"])
        self.assertEqual(out["child_cancellations"], ["z"])


class ForbiddenShaTests(unittest.TestCase):
    def test_collects_baseline_reference_and_source_bytes(self):
        report = {"reference_executable": {"path": "ref.exe", "sha256": _REF_SHA},
                  "source_hashes": {"core/Core.go": _ORIG_CORE_SRC_SHA, "bad": "nothex"}}
        artifacts = {"baseline": {"sha256": _BASE_SHA}, "protected": {"sha256": _PROT_SHA}}
        forbidden = na._forbidden_byte_shas(report, artifacts)
        self.assertIn(_BASE_SHA, forbidden)
        self.assertIn(_REF_SHA, forbidden)
        self.assertIn(_ORIG_CORE_SRC_SHA, forbidden)
        self.assertNotIn(_PROT_SHA, forbidden)
        self.assertNotIn("nothex", forbidden)


# ---------------------------------------------------------------------------
# Independent producer-origin authentication (block 2b), via the full route
# ---------------------------------------------------------------------------
class ProducerOriginAuthTests(_TmpWs):
    """Each defect perturbs exactly one producer-origin fact and must drive the whole
    route to a NativeApplicationError (block 2b runs before the engine)."""

    def _expect_reject(self, h):
        with self.assertRaises(NativeApplicationError):
            _run(h, _authentic_engine(h))

    def test_authentic_origin_accepted_go_and_swift(self):
        if REAL_STOP.exists():
            self.skipTest("defense STOP present")
        for lang in ("go", "swift"):
            h = _build_producer(self.ws, language=lang)
            out = _run(h, _authentic_engine(h))
            self.assertEqual(out["status"], na.PUBLIC_STATUS_PASSED)

    def test_contract_claimed_hash_must_match_file_go(self):
        h = _build_producer(self.ws, language="go",
                            mutate_report=lambda r: r["frontend_artifact_hashes"].update({"contract.json": "0" * 64}))
        self._expect_reject(h)

    def test_contract_claimed_hash_must_match_file_swift(self):
        h = _build_producer(self.ws, language="swift",
                            mutate_report=lambda r: r["artifact_hashes"].update({"frontend/contract.json": "0" * 64}))
        self._expect_reject(h)

    def test_go_inline_contract_must_equal_file(self):
        def bend(r):
            r["contract"] = {**r["contract"], "library_name": "Different"}
        h = _build_producer(self.ws, language="go", mutate_report=bend)
        self._expect_reject(h)

    def test_contract_schema_must_agree_with_exports(self):
        # Contract function name 'other' disagrees with project exports ['fold'];
        # the claimed hash is recomputed so only the schema/exports check fails.
        bad = {"schema_version": 1, "library_name": "NativeApp", "calling_convention": "cdecl",
               "functions": [{"name": "other", "return_type": "int32_t",
                              "parameters": [{"name": "a0", "type": "int32_t"}]}]}
        h = _build_producer(self.ws, language="go", scalar_contract=bad)
        self._expect_reject(h)

    def test_native_report_hash_mismatch_rejected(self):
        h = _build_producer(self.ws, language="go",
                            mutate_report=lambda r: r.update(native_report_sha256="0" * 64))
        self._expect_reject(h)

    def test_native_report_status_must_be_success(self):
        # The native report is honestly pinned (mutate_native runs before its hash is
        # computed), so only the non-success status trips block 2b.
        h = _build_producer(self.ws, language="go",
                            mutate_native=lambda n: n.update(status="failed"))
        self._expect_reject(h)

    def test_native_artifacts_must_equal_report_artifacts(self):
        h = _build_producer(self.ws, language="go",
                            mutate_native=lambda n: n["artifacts"]["protected"].update(bytes=999))
        self._expect_reject(h)

    def test_coverage_disagreement_rejected(self):
        # In-place coverage edit mutates the shared report+result coverage object (so
        # step-1 report==result holds) but NOT the native report's own copy, so the
        # block-2b coverage-agreement check is what rejects.
        h = _build_producer(self.ws, language="go",
                            mutate_report=lambda r: r["coverage"].update(final_vm=999))
        self._expect_reject(h)

    def test_selected_closure_mismatch_rejected(self):
        def bend(r):
            r["methods"] = [{"name": "Other", "export": "other", "is_root": True,
                             "parameters": ["i32"], "return_type": "i32"}]
        h = _build_producer(self.ws, language="go", mutate_report=bend)
        self._expect_reject(h)

    def test_contract_file_not_confined_rejected(self):
        # Point the report's contract_path outside the job directory; block 2b's
        # confinement guard rejects before reading it. build_report_sha is recomputed
        # inside _build_producer after this mutate_report, keeping step-1 intact.
        loose = str(self.ws / "loose" / "contract.json")
        h = _build_producer(self.ws, language="go",
                            mutate_report=lambda r: r.update(contract_path=loose))
        self._expect_reject(h)


# ---------------------------------------------------------------------------
# Engine-report authentication
# ---------------------------------------------------------------------------
class VerifyEngineReportTests(_TmpWs):
    def _capture(self, h, engine):
        cap = {}

        def grab(**kw):
            rep = engine.run_integration(**kw)
            cap["report"] = rep
            cap["out"] = Path(kw["output_dir"])
            cap["declared"] = len(kw.get("trusted_inputs") or [])
            return rep
        with mock.patch.object(na, "_load_engine", lambda: SimpleNamespace(run_integration=grab)):
            na.integrate_source_application(h.svc, h.plan_id, str(h.spec), str(h.contract), timeout_seconds=90)
        return cap

    def _verify(self, h, cap):
        out = cap["out"]
        return na._verify_engine_report(
            cap["report"], out / "integration.json", report_path=h.report_path,
            report_sha=h.report_sha, artifacts=h.artifacts,
            cases=na._validate_app_contract(json.loads(h.contract.read_text(encoding="utf-8"))),
            language=h.language, declared_trusted_count=cap["declared"],
            source_report=json.loads(h.report_path.read_text(encoding="utf-8")),
            contract_path=h.report_contract_abspath(), contract_sha=h.scalar_sha,
            app_source_hash_map=dict(h.app_source_map))

    def _h(self, language="go"):
        h = _build_producer(self.ws, language=language)
        h.report_contract_abspath = lambda: str(Path(os.path.abspath(h.scalar_file)))
        return h

    def test_authentic_report_accepted_go_and_swift(self):
        for lang in ("go", "swift"):
            h = self._h(lang)
            cap = self._capture(h, _authentic_engine(h))
            v = self._verify(h, cap)
            self.assertTrue(v["authentic"], v["reason"])
            self.assertTrue(all(v["checks"].values()))

    def test_persisted_must_equal_returned(self):
        h = self._h("go")
        cap = self._capture(h, _authentic_engine(h, persist_divergent=True))
        v = self._verify(h, cap)
        self.assertFalse(v["authentic"])
        self.assertFalse(v["checks"]["persisted_equals_returned"])

    def test_missing_persisted_file_rejected(self):
        h = self._h("go")
        cap = self._capture(h, _authentic_engine(h))
        (cap["out"] / "integration.json").unlink()
        v = self._verify(h, cap)
        self.assertFalse(v["authentic"])
        self.assertFalse(v["checks"]["persisted_report_present_bounded_regular"])

    def test_single_field_defects_each_fail_closed(self):
        defects = {
            "engine_status_passed": lambda r: r.update(status="other"),
            "language_match": lambda r: r.update(language="swift"),
            "producer_backend_match": lambda r: r["producer"].update(backend="rust_cargo_native"),
            "producer_report_sha_match": lambda r: r["producer"].update(report_sha256="0" * 64),
            "producer_protected_artifact_bound": lambda r: r["producer"]["artifacts"]["protected"].update(sha256="0" * 64),
            "producer_baseline_artifact_bound": lambda r: r["producer"]["artifacts"]["baseline"].update(bytes=123456),
            "producer_contract_sha_match": lambda r: r["producer"].update(contract_sha256="0" * 64),
            "producer_contract_path_match": lambda r: r["producer"].update(contract_path="C:/elsewhere/contract.json"),
            "producer_native_report_match": lambda r: r["producer"]["native_report"].update(sha256="0" * 64),
            "native_core_is_reused_protected": lambda r: r["staging"].update(native_core_sha256="0" * 64),
            "original_core_excluded_from_protected_compile": lambda r: r["staging"].update(original_core_excluded_from_protected_compile=False),
            "staging_application_source_hashes_exact": lambda r: r["staging"].update(application_source_hashes={"x": "0" * 64}),
            "comparison_status_passed": lambda r: r["comparison"].update(status="nope"),
            "comparison_flags_present_true": lambda r: r["comparison"].update(env_ok=False),
            "comparison_covers_all_cases": lambda r: r["comparison"].update(total_cases=99),
            "trusted_inputs_verified": lambda r: r["trusted_inputs_verification"].update(verified=False),
            "fresh_protected_native_build_false": lambda r: r.update(fresh_protected_native_build=True),
        }
        for check, mut in defects.items():
            with self.subTest(check=check):
                h = self._h("go")
                cap = self._capture(h, _authentic_engine(h, mutate_report=mut))
                v = self._verify(h, cap)
                self.assertFalse(v["authentic"], check)
                self.assertFalse(v["checks"][check], check)

    def test_staging_map_wrong_path_key_rejected_even_with_right_sha(self):
        # A staging map that carries the right SHA under a DIFFERENT path key must be
        # rejected (exact path->sha map, not a sha-value subset).
        def bend(r):
            (only_sha,) = set(r["staging"]["application_source_hashes"].values())
            r["staging"]["application_source_hashes"] = {"C:/wrong/app.go": only_sha}
        h = self._h("go")
        cap = self._capture(h, _authentic_engine(h, mutate_report=bend))
        v = self._verify(h, cap)
        self.assertFalse(v["checks"]["staging_application_source_hashes_exact"])

    def test_producer_artifact_wrong_path_rejected(self):
        def bend(r):
            r["producer"]["artifacts"]["protected"]["path"] = "C:/elsewhere/protected.bin"
        h = self._h("go")
        cap = self._capture(h, _authentic_engine(h, mutate_report=bend))
        v = self._verify(h, cap)
        self.assertFalse(v["checks"]["producer_protected_artifact_bound"])


# ---------------------------------------------------------------------------
# Independent child-evidence re-derivation
# ---------------------------------------------------------------------------
class VerifyChildEvidenceTests(_TmpWs):
    def _setup(self, language="go", *, child_tamper=None, mutate_report=None):
        h = _build_producer(self.ws, language=language)
        engine = _authentic_engine(h, child_tamper=child_tamper, mutate_report=mutate_report)
        cap = {}

        def grab(**kw):
            rep = engine.run_integration(**kw)
            cap["report"] = rep; cap["out"] = Path(kw["output_dir"])
            return rep
        with mock.patch.object(na, "_load_engine", lambda: SimpleNamespace(run_integration=grab)):
            na.integrate_source_application(h.svc, h.plan_id, str(h.spec), str(h.contract), timeout_seconds=90)
        return h, cap

    def _verify(self, h, cap):
        cases = na._validate_app_contract(json.loads(h.contract.read_text(encoding="utf-8")))
        return na._verify_child_evidence(cap["report"], engine_out=cap["out"], cases=cases,
                                         required_prep=na._REQUIRED_PREP_LABELS[h.language])

    def _set_receipt(self, entry, receipt):
        data = json.dumps(receipt).encode("utf-8")
        Path(entry["receipt_path"]).write_bytes(data)
        entry["receipt_sha256"] = na._digest(data)

    def test_authentic_child_evidence_accepted_go_and_swift(self):
        for lang in ("go", "swift"):
            h, cap = self._setup(lang)
            v = self._verify(h, cap)
            self.assertTrue(v["authentic"], v["reason"])
            self.assertTrue(v["coverage_ok"] and v["observations_ok"] and v["controls_ok"] and v["prep_ok"])

    def test_only_two_controls_no_adapter(self):
        def add_adapter(ce, out):
            fields = _child(out, "x_adapter", 9001, 3)
            ce["commands"].append({"label": "control:missing_adapter", "kind": "control",
                                   "control": "missing_adapter", "arm": None, "case_label": None, **fields})
        h, cap = self._setup("go", child_tamper=add_adapter)
        v = self._verify(h, cap)
        self.assertFalse(v["authentic"])
        self.assertFalse(v["coverage_ok"])

    def test_command_entry_must_have_exactly_nine_keys(self):
        # Extra key.
        def extra(ce, out):
            ce["commands"][0]["sneaky"] = 1
        h, cap = self._setup("go", child_tamper=extra)
        self.assertFalse(self._verify(h, cap)["authentic"])

    def test_case_arm_missing_control_none_key_fails(self):
        def drop(ce, out):
            e = next(c for c in ce["commands"] if c.get("arm") == "original")
            del e["control"]          # case_arm must still carry control=None (9 keys)
        h, cap = self._setup("go", child_tamper=drop)
        self.assertFalse(self._verify(h, cap)["authentic"])

    def test_case_arm_control_not_none_fails(self):
        def bend(ce, out):
            e = next(c for c in ce["commands"] if c.get("arm") == "original")
            e["control"] = "missing_core"
        h, cap = self._setup("go", child_tamper=bend)
        self.assertFalse(self._verify(h, cap)["authentic"])

    def test_control_arm_not_none_fails(self):
        def bend(ce, out):
            e = next(c for c in ce["commands"] if c["label"] == "control:missing_core")
            e["arm"] = "protected"
        h, cap = self._setup("go", child_tamper=bend)
        self.assertFalse(self._verify(h, cap)["authentic"])

    def test_empty_commands_fails(self):
        h, cap = self._setup("go", mutate_report=lambda r: r["comparison"].update(commands=[]))
        v = self._verify(h, cap)
        self.assertFalse(v["coverage_ok"])

    def test_missing_command_identity_fails(self):
        def drop(ce, out):
            ce["commands"] = [c for c in ce["commands"] if c["label"] != "control:unset_core"]
        h, cap = self._setup("go", child_tamper=drop)
        self.assertFalse(self._verify(h, cap)["coverage_ok"])

    def test_duplicate_command_identity_fails(self):
        def dup(ce, out):
            ce["commands"].append(dict(ce["commands"][0]))
        h, cap = self._setup("go", child_tamper=dup)
        self.assertFalse(self._verify(h, cap)["coverage_ok"])

    def test_inconsistent_arm_identity_fails(self):
        def flip(ce, out):
            e = next(c for c in ce["commands"] if c.get("arm") == "original")
            e["arm"] = "protected"
        h, cap = self._setup("go", child_tamper=flip)
        self.assertFalse(self._verify(h, cap)["authentic"])

    def test_dirty_receipt_not_clean_fails(self):
        def dirty(ce, out):
            e = ce["commands"][0]
            r = json.loads(Path(e["receipt_path"]).read_text())
            r["cleanup"]["status"] = "busy"
            self._set_receipt(e, r)
        h, cap = self._setup("go", child_tamper=dirty)
        self.assertFalse(self._verify(h, cap)["authentic"])

    def test_broken_receipt_pin_fails(self):
        def tamper(ce, out):
            Path(ce["commands"][0]["receipt_path"]).write_bytes(b'{"pid": 1}')
        h, cap = self._setup("go", child_tamper=tamper)
        self.assertFalse(self._verify(h, cap)["authentic"])

    def test_unconfined_receipt_path_fails(self):
        outside = self.ws / "outside.process.json"
        outside.write_bytes(json.dumps(_clean_receipt(1, 0, stdout="x", stderr="y")).encode("utf-8"))

        def repoint(ce, out):
            e = ce["commands"][0]
            e["receipt_path"] = str(outside)
            e["receipt_sha256"] = na._digest(outside.read_bytes())
        h, cap = self._setup("go", child_tamper=repoint)
        self.assertFalse(self._verify(h, cap)["authentic"])

    def test_control_not_failing_closed_fails(self):
        def zero(ce, out):
            e = next(c for c in ce["commands"] if c["label"] == "control:missing_core")
            r = json.loads(Path(e["receipt_path"]).read_text())
            r["returncode"] = 0
            self._set_receipt(e, r)
        h, cap = self._setup("go", child_tamper=zero)
        self.assertFalse(self._verify(h, cap)["controls_ok"])

    def test_observation_mismatch_from_logs_fails(self):
        def retamper(ce, out):
            e = next(c for c in ce["commands"] if c["label"] == "case:fold(5):protected")
            Path(e["stdout_log"]).write_bytes(b"999\n")
        h, cap = self._setup("go", child_tamper=retamper)
        self.assertFalse(self._verify(h, cap)["observations_ok"])

    def test_observation_wrong_exit_from_receipt_fails(self):
        def retamper(ce, out):
            e = next(c for c in ce["commands"] if c["label"] == "case:fold(5):protected")
            r = json.loads(Path(e["receipt_path"]).read_text())
            r["returncode"] = 7
            self._set_receipt(e, r)
        h, cap = self._setup("go", child_tamper=retamper)
        self.assertFalse(self._verify(h, cap)["observations_ok"])

    def test_unrelated_stdout_log_binding_fails(self):
        def rebind(ce, out):
            e = ce["commands"][0]
            other = Path(e["stdout_log"]).with_name("unrelated.log")
            other.write_bytes(b"whatever")
            e["stdout_log"] = str(other)
        h, cap = self._setup("go", child_tamper=rebind)
        self.assertFalse(self._verify(h, cap)["authentic"])

    def test_receipt_path_reuse_across_entries_fails(self):
        def reuse(ce, out):
            ce["commands"][1]["receipt_path"] = ce["commands"][0]["receipt_path"]
            ce["commands"][1]["receipt_sha256"] = ce["commands"][0]["receipt_sha256"]
        h, cap = self._setup("go", child_tamper=reuse)
        self.assertFalse(self._verify(h, cap)["authentic"])

    def test_missing_or_empty_preparation_fails(self):
        h, cap = self._setup("go", mutate_report=lambda r: r.update(preparation_commands=[]))
        self.assertFalse(self._verify(h, cap)["prep_ok"])

    def test_prep_missing_each_required_label_fails(self):
        for lang in ("go", "swift"):
            for label in na._REQUIRED_PREP_LABELS[lang]:
                def drop(ce, out, label=label):
                    ce["preparation_commands"] = [p for p in ce["preparation_commands"] if p["label"] != label]
                h, cap = self._setup(lang, child_tamper=drop)
                self.assertFalse(self._verify(h, cap)["prep_ok"], "%s/%s" % (lang, label))

    def test_prep_unknown_label_fails(self):
        def add(ce, out):
            fields = _child(out, "prep_extra", 9100, 0)
            ce["preparation_commands"].append({"label": "compile-bonus", "kind": "compile",
                                               "tool": "go", "cwd": str(out), **fields})
        h, cap = self._setup("go", child_tamper=add)
        self.assertFalse(self._verify(h, cap)["prep_ok"])

    def test_prep_nonzero_exit_fails(self):
        def boom(ce, out):
            e = ce["preparation_commands"][0]
            r = json.loads(Path(e["receipt_path"]).read_text())
            r["returncode"] = 2
            self._set_receipt(e, r)
        h, cap = self._setup("go", child_tamper=boom)
        self.assertFalse(self._verify(h, cap)["prep_ok"])

    def test_go_two_prep_labels_swift_four(self):
        h_go, cap_go = self._setup("go")
        self.assertEqual(len(cap_go["report"]["preparation_commands"]), 2)
        h_sw, cap_sw = self._setup("swift")
        self.assertEqual(len(cap_sw["report"]["preparation_commands"]), 4)
        v = na._verify_child_evidence(cap_go["report"], engine_out=cap_go["out"],
                                      cases=na._validate_app_contract(json.loads(h_go.contract.read_text(encoding="utf-8"))),
                                      required_prep=na._REQUIRED_PREP_LABELS["swift"])
        self.assertFalse(v["prep_ok"])

    def test_no_comparison_block_fails(self):
        h, cap = self._setup("go", mutate_report=lambda r: r.pop("comparison"))
        self.assertFalse(self._verify(h, cap)["authentic"])


# ---------------------------------------------------------------------------
# Deployment-bundle inventory
# ---------------------------------------------------------------------------
class InventoryBundleTests(_TmpWs):
    def _setup(self, language="go", **engine_kwargs):
        h = _build_producer(self.ws, language=language)
        engine = _authentic_engine(h, **engine_kwargs)
        cap = {}

        def grab(**kw):
            rep = engine.run_integration(**kw)
            cap["report"] = rep; cap["out"] = Path(kw["output_dir"])
            return rep
        with mock.patch.object(na, "_load_engine", lambda: SimpleNamespace(run_integration=grab)):
            na.integrate_source_application(h.svc, h.plan_id, str(h.spec), str(h.contract), timeout_seconds=90)
        return h, cap

    def _inv(self, h, cap):
        return na._inventory_bundle(cap["report"], engine_out=cap["out"], artifacts=h.artifacts,
                                    expected_native_sha=_PROT_SHA,
                                    source_report=json.loads(h.report_path.read_text(encoding="utf-8")),
                                    language=h.language)

    def test_authentic_bundle_go_and_swift(self):
        for lang in ("go", "swift"):
            h, cap = self._setup(lang)
            bundle = self._inv(h, cap)
            self.assertEqual(bundle["executable"], _EXE_REL)
            self.assertEqual(bundle["native_core"], _CORE_REL)
            self.assertEqual(bundle["runtime_files"], _runtime_files(lang))

    def test_native_core_must_be_reused_protected(self):
        h, cap = self._setup("go", native_bytes=b"MZ\x90\x00not-the-protected-core")
        with self.assertRaises(NativeApplicationError):
            self._inv(h, cap)

    def test_forbidden_baseline_bytes_in_bundle_rejected(self):
        h, cap = self._setup("go", deploy_files={_EXE_REL: _BASE_BYTES, _CORE_REL: _NATIVE_BYTES})
        with self.assertRaises(NativeApplicationError):
            self._inv(h, cap)

    def test_forbidden_reference_exe_bytes_in_bundle_rejected(self):
        h, cap = self._setup("go", deploy_files={_EXE_REL: _REF_BYTES, _CORE_REL: _NATIVE_BYTES})
        with self.assertRaises(NativeApplicationError):
            self._inv(h, cap)

    def test_extra_disk_file_rejected(self):
        h, cap = self._setup("go", extra_disk_file="stowaway.dll")
        with self.assertRaises(NativeApplicationError):
            self._inv(h, cap)

    def test_missing_disk_file_rejected(self):
        h, cap = self._setup("swift", drop_from_disk=_SWIFT_RT_REL)
        with self.assertRaises(NativeApplicationError):
            self._inv(h, cap)

    def test_bundle_outside_engine_output_rejected(self):
        h, cap = self._setup("go", deploy_outside=True)
        with self.assertRaises(NativeApplicationError):
            self._inv(h, cap)

    def test_non_allowlisted_suffix_rejected(self):
        h, cap = self._setup("go", deploy_files={_EXE_REL: _APP_EXE, _CORE_REL: _NATIVE_BYTES,
                                                 "notes.txt": b"hello"})
        with self.assertRaises(NativeApplicationError):
            self._inv(h, cap)

    def test_go_runtime_files_must_be_empty(self):
        h, cap = self._setup("go", runtime_files=[_CORE_REL])
        with self.assertRaises(NativeApplicationError):
            self._inv(h, cap)

    def test_executable_equal_to_core_rejected(self):
        h, cap = self._setup("go", mutate_report=lambda r: r["deployment"].update(executable=_CORE_REL))
        with self.assertRaises(NativeApplicationError):
            self._inv(h, cap)

    def test_runtime_file_overlaps_core_rejected(self):
        h, cap = self._setup("swift", mutate_report=lambda r: r["deployment"].update(runtime_files=[_CORE_REL]))
        with self.assertRaises(NativeApplicationError):
            self._inv(h, cap)

    def test_runtime_non_dll_rejected(self):
        h, cap = self._setup("swift", deploy_files={_EXE_REL: _APP_EXE, _CORE_REL: _NATIVE_BYTES, "rt.exe": _SWIFT_RT},
                             runtime_files=["rt.exe"])
        with self.assertRaises(NativeApplicationError):
            self._inv(h, cap)

    def test_allowlist_disagrees_with_manifest_rejected(self):
        h, cap = self._setup("go", mutate_report=lambda r: r["deployment"].update(allowlist=[_EXE_REL]))
        with self.assertRaises(NativeApplicationError):
            self._inv(h, cap)

    def test_forbidden_absent_flag_required(self):
        h, cap = self._setup("go", mutate_report=lambda r: r["deployment"].update(forbidden_absent=False))
        with self.assertRaises(NativeApplicationError):
            self._inv(h, cap)


# ---------------------------------------------------------------------------
# End-to-end public service route (real verifiers, mocked engine)
# ---------------------------------------------------------------------------
class EndToEndServiceTests(_TmpWs):
    def _assert_passed(self, h, out):
        self.assertEqual(out["status"], na.PUBLIC_STATUS_PASSED)
        self.assertEqual(out["plan_id"], h.plan_id)
        self.assertEqual(out["language"], h.language)
        self.assertEqual(out["backend"], h.backend)
        self.assertTrue(out["engine_report_authentic"])
        self.assertTrue(out["child_evidence_authentic"])
        self.assertTrue(out["reused_native_core"])
        self.assertFalse(out["fresh_protected_native_build"])
        self.assertTrue(out["original_inputs_unchanged"])
        self.assertFalse(out["comparison_mismatch"])
        self.assertEqual(out["public_route"], na.PUBLIC_ROUTE)
        for k in ("external_attack_evaluation", "performance_evaluation", "defense_strength_evaluation"):
            self.assertEqual(out[k], "not_evaluated")
        self.assertIsNotNone(out["deployment_bundle"])
        self.assertNotIn("allowlist", out["deployment_bundle"])
        self.assertNotIn("forbidden_absent", out["deployment_bundle"])
        self.assertEqual(out["deployment_bundle"]["executable"], _EXE_REL)
        self.assertEqual(out["deployment_bundle"]["native_core"], _CORE_REL)
        self.assertEqual(out["deployment_bundle"]["runtime_files"], _runtime_files(h.language))
        self.assertTrue(out["launch_instructions"])
        rpath = Path(out["integration_report_path"])
        self.assertTrue(rpath.is_file())
        self.assertEqual(na._digest(rpath.read_bytes()), out["integration_report_sha256"])

    def test_authentic_pass_go(self):
        if REAL_STOP.exists():
            self.skipTest("defense STOP present")
        h = _build_producer(self.ws, language="go")
        self._assert_passed(h, _run(h, _authentic_engine(h)))

    def test_authentic_pass_swift(self):
        if REAL_STOP.exists():
            self.skipTest("defense STOP present")
        h = _build_producer(self.ws, language="swift")
        self._assert_passed(h, _run(h, _authentic_engine(h)))

    def test_nested_spec_resolves_relative_to_spec_parent_not_app_dir(self):
        # Correction (3): a spec in pkg/sub/ names "App.go" which MUST resolve to
        # pkg/sub/App.go. A same-name decoy at pkg/App.go (wrong root) must be
        # ignored; the service binds the sub file and the route passes.
        if REAL_STOP.exists():
            self.skipTest("defense STOP present")
        for lang in ("go", "swift"):
            ws = Path(tempfile.mkdtemp(dir=self.ws))
            ext = na._SOURCE_SUFFIX[lang]
            app = "main" + ext if lang == "swift" else "App" + ext
            h = _build_producer(ws, language=lang, spec_subdir="sub",
                                app_sources=[app], decoy_same_name=True)
            out = _run(h, _authentic_engine(h))
            self.assertEqual(out["status"], na.PUBLIC_STATUS_PASSED, lang)
            plan = json.loads(Path(out["integration_plan_path"]).read_text(encoding="utf-8"))
            bound = plan["application_source_pins"][0]["path"]
            self.assertEqual(os.path.normcase(bound),
                             os.path.normcase(str(h.svc._owned(h.spec_dir / app))), lang)
            self.assertTrue(bound.replace("\\", "/").endswith("sub/" + app), bound)
            self.assertNotEqual(os.path.normcase(bound),
                                os.path.normcase(str(h.svc._owned(h.pkg / app))), lang)

    def test_nested_spec_and_contract_accepted(self):
        # The spec/contract may live in a project subdirectory (not only directly in
        # app_dir); the service must accept them as snapshot members.
        h = _build_producer(self.ws, language="go", spec_subdir="sub", app_sources=["App.go"])
        self.assertTrue(h.spec.parent.name == "sub")
        if REAL_STOP.exists():
            self.skipTest("defense STOP present")
        out = _run(h, _authentic_engine(h))
        self.assertEqual(out["status"], na.PUBLIC_STATUS_PASSED)

    def test_stop_short_circuits_before_engine(self):
        h = _build_producer(self.ws, language="go")
        stop = self.ws / ".runs" / "defense-loop" / "STOP"
        stop.parent.mkdir(parents=True, exist_ok=True)
        stop.write_text("stop", encoding="utf-8")
        called = {"n": 0}
        out = _run(h, _authentic_engine(h, during_run=lambda: called.__setitem__("n", called["n"] + 1)))
        self.assertEqual(out["status"], "cancelled")
        self.assertIsNone(out["integration_id"])
        self.assertEqual(called["n"], 0)

    def test_timeout_bounds_enforced(self):
        h = _build_producer(self.ws, language="go")
        for bad in (0, 601, 1.0, True, "90"):
            with self.assertRaises(NativeApplicationError):
                na.integrate_source_application(h.svc, h.plan_id, str(h.spec), str(h.contract), timeout_seconds=bad)

    def test_backend_not_native_rejected(self):
        h = _build_producer(self.ws, language="go",
                            mutate_result=lambda r: r.update(backend="jvm_bytecode_native"))
        with self.assertRaises(NativeApplicationError):
            _run(h, _authentic_engine(h))

    def test_unsuccessful_result_rejected(self):
        h = _build_producer(self.ws, language="go", mutate_result=lambda r: r.update(status="failed"))
        with self.assertRaises(NativeApplicationError):
            _run(h, _authentic_engine(h))

    def test_stale_fingerprint_rejected(self):
        h = _build_producer(self.ws, language="go", recompute_fingerprint=False)
        with self.assertRaises(NativeApplicationError):
            _run(h, _authentic_engine(h))

    def test_spec_bytes_changed_after_plan_rejected(self):
        h = _build_producer(self.ws, language="go")
        h.spec.write_text(h.spec.read_text(encoding="utf-8") + "   ", encoding="utf-8")
        with self.assertRaises(NativeApplicationError):
            _run(h, _authentic_engine(h))

    def test_contract_bytes_changed_after_plan_rejected(self):
        h = _build_producer(self.ws, language="go")
        h.contract.write_text(h.contract.read_text(encoding="utf-8") + "   ", encoding="utf-8")
        with self.assertRaises(NativeApplicationError):
            _run(h, _authentic_engine(h))

    def test_engine_exception_yields_failed_not_crash(self):
        if REAL_STOP.exists():
            self.skipTest("defense STOP present")
        h = _build_producer(self.ws, language="go")

        def raiser(**kw):
            raise RuntimeError("engine blew up")
        out = _run(h, SimpleNamespace(run_integration=raiser))
        self.assertEqual(out["status"], "failed")
        self.assertFalse(out["engine_report_authentic"])
        self.assertIsNone(out["deployment_bundle"])
        self.assertIsNotNone(out["integration_report_path"])

    def test_persisted_divergent_report_yields_failed(self):
        if REAL_STOP.exists():
            self.skipTest("defense STOP present")
        h = _build_producer(self.ws, language="go")
        out = _run(h, _authentic_engine(h, persist_divergent=True))
        self.assertEqual(out["status"], "failed")
        self.assertFalse(out["engine_report_authentic"])
        self.assertIsNone(out["deployment_bundle"])

    def test_adapter_control_present_yields_failed(self):
        if REAL_STOP.exists():
            self.skipTest("defense STOP present")
        h = _build_producer(self.ws, language="go")

        def add_adapter(ce, out):
            fields = _child(out, "x_adapter", 9001, 3)
            ce["commands"].append({"label": "control:missing_adapter", "kind": "control",
                                   "control": "missing_adapter", "arm": None, "case_label": None, **fields})
        out = _run(h, _authentic_engine(h, child_tamper=add_adapter))
        self.assertEqual(out["status"], "failed")
        self.assertTrue(out["comparison_mismatch"])
        self.assertIsNone(out["deployment_bundle"])

    def test_deploy_outside_engine_output_yields_failed(self):
        if REAL_STOP.exists():
            self.skipTest("defense STOP present")
        h = _build_producer(self.ws, language="go")
        out = _run(h, _authentic_engine(h, deploy_outside=True))
        self.assertEqual(out["status"], "failed")
        self.assertIsNone(out["deployment_bundle"])

    def test_staging_map_wrong_key_yields_failed_end_to_end(self):
        if REAL_STOP.exists():
            self.skipTest("defense STOP present")
        h = _build_producer(self.ws, language="go")

        def bend(r):
            (only_sha,) = set(r["staging"]["application_source_hashes"].values())
            r["staging"]["application_source_hashes"] = {"C:/wrong/app.go": only_sha}
        out = _run(h, _authentic_engine(h, mutate_report=bend))
        self.assertEqual(out["status"], "failed")
        self.assertFalse(out["engine_report_authentic"])

    def test_spec_and_contract_must_be_distinct_files(self):
        h = _build_producer(self.ws, language="go")
        with self.assertRaises(NativeApplicationError):
            with mock.patch.object(na, "_load_engine", lambda: _authentic_engine(h)):
                na.integrate_source_application(h.svc, h.plan_id, str(h.spec), str(h.spec), timeout_seconds=90)

    def test_missing_producer_contract_file_rejected(self):
        h = _build_producer(self.ws, language="go")
        h.scalar_file.unlink()
        with self.assertRaises(NativeApplicationError):
            _run(h, _authentic_engine(h))


if __name__ == "__main__":        # pragma: no cover
    unittest.main()
