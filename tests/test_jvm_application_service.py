"""Service-level tests for the JVM source-integrate route.

Defender-only (phase21 SERVICE lane). These exercise the public service boundary
of ``antirea.jvm_application.integrate_source_application`` -- binding a saved
``jvm_bytecode_native`` producer job, validating the strict integration spec and
application-sample contract, pinning inputs, authenticating a persisted engine
report, and inventorying the engine-owned deployment bundle -- entirely against
PURE SYNTHETIC, fully self-consistent saved producer fixtures (no compiler) plus a
BOUNDARY MOCK of the trusted engine for the execution phase.

The synthetic fixtures and the mocked engine are never real integration evidence;
the only real integration proof is root's separate fresh Java/Kotlin CLI E2E after
production freeze. No REA/attack/received code runs; no native compiler or target
is launched here; no attacker/received-report path, ``env.setting`` or
``LINKREPRO`` artifact is traversed (reserved segments are only ever synthetic
strings under a private temp dir); no install/download/publish/commit happens.

Run through the OUTER bounded harness (``.runs/phase21-service/run_service_tests.py``
-> ``antirea.process.run_logged``); do not launch directly with unbounded unittest.
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

from antirea import jvm_application as ja  # REQUIRED production module: no skip gate.
from antirea.jvm_application import JvmApplicationError
from antirea.projects import ProjectService

REAL_STOP = ROOT / ".runs" / "defense-loop" / "STOP"

# Reused protected native core bytes hash to the producer's PROTECTED pin -- the
# "deployed native core IS the reused protected build" invariant the inventory
# enforces. The baseline / original-core / helper bytes are FORBIDDEN in a bundle.
_NATIVE_BYTES = b"MZ\x90\x00jvm-reused-protected-native-core-0001"
_PROT_SHA = ja._digest(_NATIVE_BYTES)
_BASE_BYTES = b"MZ\x90\x00jvm-baseline-native-0002"
_BASE_SHA = ja._digest(_BASE_BYTES)
_ORIG_CORE_SHA = ja._digest(b"ORIGINAL-CORE-CLASSFILE-BYTES")
_HELPER_SHA = ja._digest(b"ORIGINAL-HELPER-RUNNER-BYTES")

# Deployed (facade / app / bootstrap / nativecore / adapter) bytes. Facade keeps
# the ORIGINAL core class identity (path core/Core.class) but carries DIFFERENT
# bytes, so its sha must not collide with the forbidden originals above.
_APP_CLASS = b"\xca\xfe\xba\xbe-jvm-app-class"
_FACADE_CLASS = b"\xca\xfe\xba\xbe-jvm-facade-forwarding-core"
_BOOTSTRAP_CLASS = b"\xca\xfe\xba\xbe-jvm-protected-bootstrap"
_NATIVECORE_CLASS = b"\xca\xfe\xba\xbe-jvm-nativecore-binding"
_ADAPTER_DLL = b"MZ\x90\x00-jvm-jni-adapter"

_NATIVE_REL = "JvmApp_core.dll"
_ADAPTER_REL = "JvmApp_adapter.dll"


def _synthetic_job_id() -> str:
    # Matches antirea.projects.JOB_ID: source-<8>T<6>Z-<12 hex>.
    return "source-20261020T010203Z-" + uuid.uuid4().hex[:12]


def _valid_spec(language="java"):
    ext = ".java" if language == "java" else ".kt"
    main = "sample.App" if language == "java" else "sample.AppKt"
    return {"schema_version": 1, "kind": ja.INTEGRATION_SPEC_KIND, "language": language,
            "application_sources": ["app/App" + ext], "main_class": main}


def _valid_contract():
    return {"schema_version": 1, "kind": ja.APPLICATION_CONTRACT_KIND,
            "cases": [{"label": "square(5)", "args": ["5"], "expect": {"returncode": 0, "stdout": "25\n"}},
                      {"label": "add(7,3)", "args": ["7", "3"], "expect": {"returncode": 0, "stdout": "10\n"}}]}


def _build_producer(ws: Path, *, language="java", spec_obj=None, contract_obj=None,
                    mutate_plan=None, mutate_result=None, mutate_report=None,
                    recompute_fingerprint=True, artifacts=None):
    """Write a fully consistent synthetic ``jvm_bytecode_native`` producer job.

    Without perturbation the result passes every service boundary check and reaches
    the (mocked) engine. ``mutate_*`` hooks perturb exactly one bound field so an
    individual guard can be isolated; ``recompute_fingerprint=False`` leaves
    ``result.fingerprint`` stale to exercise the fingerprint binding.
    """
    svc = ProjectService(ws)
    # A present (but path-field-free) native toolchain config, so _toolchain is
    # 'present' and the fixed-config preflight runs its sha path.
    tools_dir = ws / ".tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    (tools_dir / "kagura-toolchain.json").write_text(
        json.dumps({"llvm_version": "test-18", "target": "x86_64-pc-windows-msvc"}), encoding="utf-8")

    ext = ".java" if language == "java" else ".kt"
    pkg = ws / ("pkg-" + uuid.uuid4().hex[:8])
    (pkg / "core").mkdir(parents=True)
    (pkg / "app").mkdir(parents=True)
    source = pkg / "project.json"
    core_src = pkg / "core" / ("Core" + ext)
    app_src = pkg / "app" / ("App" + ext)
    source.write_text(json.dumps({"schema_version": 1, "name": "JvmApp", "language": language,
                                  "sources": ["core/Core" + ext], "methods": []}), encoding="utf-8")
    core_src.write_text("// core " + language + " source leaf\n", encoding="utf-8")
    app_src.write_text("// app " + language + " caller\n", encoding="utf-8")

    spec = _valid_spec(language) if spec_obj is None else spec_obj
    contract = _valid_contract() if contract_obj is None else contract_obj
    (pkg / "integration.json").write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
    (pkg / "application-contract.json").write_text(json.dumps(contract, indent=2) + "\n", encoding="utf-8")

    inspection = {"schema_version": 1, "language": language, "name": "JvmApp",
                  "project_path": str(source), "sources": [str(svc._owned(core_src))],
                  "compiler_inputs": {}, "input_hashes": {},
                  "exported_functions": ["leaf_a"], "functions": ["leaf_a"]}
    if artifacts is None:
        artifacts = {"baseline": {"path": str(pkg / "baseline.bin"), "sha256": _BASE_SHA},
                     "protected": {"path": str(pkg / "protected.bin"), "sha256": _PROT_SHA}}
    coverage = {"exported_functions": ["leaf_a"]}
    report = {"schema_version": 1, "backend": "jvm_bytecode_native",
              "status": "artifact_created_unvalidated", "language": language, "project": inspection,
              "artifacts": artifacts, "coverage": coverage,
              "original_classes": {str(pkg / "core" / "Core.class"): _ORIG_CORE_SHA},
              "reference_runner_hashes": {str(pkg / "ReferenceRunner.class"): _HELPER_SHA}}
    if mutate_report is not None:
        mutate_report(report)

    job = ws / ".runs" / "source-protection" / _synthetic_job_id()
    (job / "build").mkdir(parents=True)
    report_bytes = ja._create_json(job / "build" / "report.json", report)
    build_report_sha = ja._digest(report_bytes)

    snapshot = svc._snapshot(source, inspection)
    toolchain = svc._toolchain(inspection)
    plan = {"schema_version": 1, "plan_id": job.name, "kind": "native_source_build",
            "workspace_root": str(ws), "project_path": str(source), "seed": 1729,
            "inspection": inspection, "inputs": snapshot, "toolchain": toolchain,
            "blockers": [], "output_dir": str(job / "build")}
    if mutate_plan is not None:
        mutate_plan(plan)
    fingerprint = ja._digest(ja._encoded(plan))
    result = {"schema_version": 1, "status": "artifact_created_unvalidated",
              "backend": "jvm_bytecode_native", "plan_id": job.name,
              "fingerprint": fingerprint if recompute_fingerprint else "0" * 64,
              "build_report_sha256": build_report_sha, "artifacts": artifacts, "coverage": coverage,
              "external_attack_evaluation": "not_evaluated", "published": False}
    if mutate_result is not None:
        mutate_result(result)
    ja._create_json(job / "plan.json", plan)
    ja._create_json(job / "result.json", result)
    return SimpleNamespace(svc=svc, ws=ws, job=job, plan_id=job.name, pkg=pkg, source=source,
                           spec=pkg / "integration.json", contract=pkg / "application-contract.json",
                           inspection=inspection, fingerprint=fingerprint, artifacts=artifacts,
                           report_path=job / "build" / "report.json", report_sha=build_report_sha,
                           snapshot=snapshot, language=language)


def _authentic_deploy_files():
    """relpath -> bytes for a fully valid bundle."""
    return {
        "sample/App.class": _APP_CLASS,
        "core/Core.class": _FACADE_CLASS,           # facade keeps identity, new bytes
        "antirea/runtime/ProtectedBootstrap.class": _BOOTSTRAP_CLASS,
        "antirea/runtime/NativeCore.class": _NATIVECORE_CLASS,
        _ADAPTER_REL: _ADAPTER_DLL,
        _NATIVE_REL: _NATIVE_BYTES,                 # sha == _PROT_SHA
    }


def _clean_receipt(pid, rc, *, stdout=None, stderr=None):
    """A FULL Windows-Job infrastructure-clean raw process receipt. ``stdout`` and
    ``stderr`` are the receipt's OWN captured-log paths (bound by the verifier)."""
    r = {"argv": ["java", "-cp", ".", "sample.App"], "pid": pid, "returncode": rc,
         "timed_out": False, "cancelled": False, "error": None, "post_cleanup_wait_error": None,
         "seconds": 0.12, "cleanup": {"method": "windows_job", "job_assigned": True, "parent_pid": pid,
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
    """Write one child's UNIQUE persisted stdout/stderr logs + raw receipt (whose
    own stdout/stderr point at those logs). Returns the inline entry fields."""
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
    return {"receipt_path": str(rp), "receipt_sha256": ja._digest(data),
            "stdout_log": str(sout), "stderr_log": str(serr)}


def _build_child_evidence(out: Path, cases):
    """Write persisted raw receipts + bound stdout/stderr logs under the engine out
    dir and return matching comparison.commands / preparation_commands / cases.
    Every child has UNIQUE receipt+log paths; each entry's logs are bound to the
    receipt's own stdout/stderr; preparation holds EXACTLY the four required labels."""
    commands, case_reports = [], []
    i = 0
    for c in cases:
        exp = c["expect"]
        for arm in ("original", "protected"):
            lbl = "case:%s:%s" % (c["label"], arm)
            i += 1
            fields = _child(out, "%d_%s" % (i, _safe(lbl)), 1000 + i, exp["returncode"],
                            stdout_bytes=exp["stdout"].encode("utf-8"))
            commands.append({"label": lbl, "kind": "case_arm", "arm": arm, "case_label": c["label"], **fields})
        obs = {"returncode": exp["returncode"], "stdout": exp["stdout"], "stderr_sha256": ja._digest(b"")}
        case_reports.append({"label": c["label"], "args": c["args"], "expect": dict(exp),
                             "baseline": dict(obs), "protected": dict(obs), "match": True})
    for short in ("missing_core", "unset_core", "missing_adapter", "unset_adapter"):
        lbl = "control:%s" % short
        i += 1
        fields = _child(out, "%d_%s" % (i, _safe(lbl)), 2000 + i, 3)  # fail-closed: non-zero
        commands.append({"label": lbl, "kind": "control", "control": short, **fields})
    prep = []
    for j, plbl in enumerate(("sdk-capture", "cl-adapter", "compile-app", "compile-facade")):
        fields = _child(out, "prep_%d_%s" % (j, _safe(plbl)), 3000 + j, 0)  # exit 0
        prep.append({"label": plbl, "kind": "prepare", "tool": "javac", "cwd": str(out), **fields})
    return {"commands": commands, "preparation_commands": prep, "cases": case_reports}


def _authentic_engine(h, *, native_bytes=_NATIVE_BYTES, during_run=None, mutate_report=None,
                      child_tamper=None, persist_divergent=False, deploy_outside=False,
                      extra_disk_file=None, drop_from_disk=None, deploy_files=None):
    """Boundary stand-in returning a FULLY AUTHENTIC engine report + deployment +
    persisted raw child receipts/logs. Knobs introduce a single realistic defect to
    prove the service fails closed; ``child_tamper(ce, out)`` mutates the child
    evidence after its files are written (e.g. to dirty one receipt)."""
    files = dict(deploy_files if deploy_files is not None else _authentic_deploy_files())
    files[_NATIVE_REL] = native_bytes

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
            manifest.append({"relative_path": rel, "sha256": ja._digest(data), "bytes": len(data)})
        if extra_disk_file is not None:
            (deploy / extra_disk_file).parent.mkdir(parents=True, exist_ok=True)
            (deploy / extra_disk_file).write_bytes(b"UNLISTED")
        if drop_from_disk is not None:
            (deploy / drop_from_disk).unlink()

        cases = ja._validate_app_contract(json.loads(Path(application_contract_path).read_text(encoding="utf-8")))
        prod = json.loads(Path(producer_report_path).read_text(encoding="utf-8"))
        prod_sha = ja._digest(Path(producer_report_path).read_bytes())
        ce = _build_child_evidence(out, cases)
        if child_tamper is not None:
            child_tamper(ce, out)
        report = {
            "schema_version": 1, "kind": ja.INTEGRATION_SPEC_KIND, "status": ja.ENGINE_STATUS_PASSED,
            "language": h.language, "fresh_protected_native_build": False,
            "producer": {"report_path": producer_report_path, "report_sha256": prod_sha,
                         "backend": "jvm_bytecode_native", "artifacts": prod["artifacts"],
                         "coverage": prod["coverage"]},
            "staging": {"native_core": str(deploy / _NATIVE_REL), "native_core_sha256": ja._digest(native_bytes),
                        "jni_adapter": str(deploy / _ADAPTER_REL), "jni_adapter_sha256": ja._digest(_ADAPTER_DLL),
                        "native_library": "JvmApp"},
            "comparison": {"status": ja.ENGINE_COMPARISON_PASSED, "all_match": True, "env_ok": True,
                           "route_proof_ok": True, "integrity_verified_before_and_after": True,
                           "expectations_ok": True, "missing_core_control_ok": True,
                           "missing_adapter_control_ok": True, "total_cases": len(cases),
                           "stop_cancellations": 0, "cases": ce["cases"], "commands": ce["commands"]},
            "preparation_commands": ce["preparation_commands"],
            "deployment": {"path": str(deploy), "allowlist": sorted(files),
                           "files": sorted(manifest, key=lambda m: m["relative_path"]),
                           "forbidden_absent": True, "main_class": "sample.App" if h.language == "java" else "sample.AppKt",
                           "classpath_entries": ["."], "native_core": _NATIVE_REL, "jni_adapter": _ADAPTER_REL},
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
    with mock.patch.object(ja, "_load_engine", lambda: engine):
        return ja.integrate_source_application(h.svc, h.plan_id, str(h.spec), str(h.contract),
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
        for seg in ("rea-analysis-reports", "attackerfolder", "defense-loop",
                    "env.setting", "LINKREPRO", "linkrepro"):
            with self.subTest(seg=seg), self.assertRaises(JvmApplicationError) as ctx:
                ja._reserved_guard("C:/synthetic/" + seg + "/thing.json")
            self.assertIn("reserved", str(ctx.exception).lower())

    def test_non_string_and_control_char_paths_refused(self):
        for bad in (None, 123, "", "has\nnewline", "tab\tchar"):
            with self.subTest(bad=repr(bad)), self.assertRaises(JvmApplicationError):
                ja._reserved_guard(bad)

    def test_ordinary_owned_path_passes(self):
        ja._reserved_guard("pkg/integration.json")


class SafeRelativeSourceTests(unittest.TestCase):
    def test_valid_nested_source(self):
        self.assertEqual(ja._safe_relative_source("app/App.java", "s", ".java"), "app/App.java")
        self.assertEqual(ja._safe_relative_source("app\\App.kt", "s", ".kt"), "app/App.kt")

    def test_rejects_traversal_absolute_drive_reserved(self):
        for bad in ("../App.java", "/abs/App.java", "C:/App.java", "a//App.java",
                    "attackerfolder/App.java", "app/./App.java"):
            with self.subTest(bad=bad), self.assertRaises(JvmApplicationError):
                ja._safe_relative_source(bad, "s", ".java")

    def test_rejects_wrong_extension_and_control(self):
        with self.assertRaises(JvmApplicationError):
            ja._safe_relative_source("App.kt", "s", ".java")
        with self.assertRaises(JvmApplicationError):
            ja._safe_relative_source("App\n.java", "s", ".java")


# ---------------------------------------------------------------------------
# Integration spec schema validation (pure)
# ---------------------------------------------------------------------------

class IntegrationSpecValidationTests(unittest.TestCase):
    def test_valid_java_and_kotlin(self):
        j = ja._validate_integration_spec(_valid_spec("java"), plan_language="java")
        self.assertEqual(j["main_class"], "sample.App")
        self.assertEqual(j["application_sources"], ["app/App.java"])
        k = ja._validate_integration_spec(_valid_spec("kotlin"), plan_language="kotlin")
        self.assertEqual(k["application_sources"], ["app/App.kt"])

    def test_rejects_bad_shape(self):
        bads = [
            {},
            {**_valid_spec(), "extra": 1},
            {**_valid_spec(), "schema_version": 2},
            {**_valid_spec(), "kind": "other"},
            {**_valid_spec(), "language": "python"},
            {**_valid_spec(), "application_sources": []},
            {**_valid_spec(), "application_sources": ["a.java", "a.java"]},
            {**_valid_spec(), "application_sources": ["a.txt"]},
            {**_valid_spec(), "application_sources": ["x" for _ in range(ja.MAX_APPLICATION_SOURCES + 1)]},
            {**_valid_spec(), "main_class": ""},
            {**_valid_spec(), "main_class": "pkg.Outer$Inner"},
            {**_valid_spec(), "main_class": "1bad.Class"},
            {**_valid_spec(), "main_class": "x" * (ja.MAX_MAIN_CLASS_LEN + 1)},
        ]
        for bad in bads:
            with self.subTest(bad=bad), self.assertRaises(JvmApplicationError):
                ja._validate_integration_spec(bad, plan_language="java")

    def test_rejects_language_mismatch_with_plan(self):
        with self.assertRaises(JvmApplicationError):
            ja._validate_integration_spec(_valid_spec("kotlin"), plan_language="java")


# ---------------------------------------------------------------------------
# Application contract schema / case validation (pure)
# ---------------------------------------------------------------------------

class ContractValidationTests(unittest.TestCase):
    def test_valid_returns_normalised_cases(self):
        cases = ja._validate_app_contract(_valid_contract())
        self.assertEqual(len(cases), 2)
        self.assertEqual(cases[0], {"label": "square(5)", "args": ["5"], "expect": {"returncode": 0, "stdout": "25\n"}})

    def test_rejects_non_object_and_missing_or_extra_keys(self):
        for bad in ([], "x", 5, {"schema_version": 1, "kind": ja.APPLICATION_CONTRACT_KIND},
                    {**_valid_contract(), "extra": 1}):
            with self.subTest(bad=bad), self.assertRaises(JvmApplicationError):
                ja._validate_app_contract(bad)

    def test_rejects_bad_schema_and_kind(self):
        for bad in ({**_valid_contract(), "schema_version": 2}, {**_valid_contract(), "kind": "nope"}):
            with self.subTest(bad=bad), self.assertRaises(JvmApplicationError):
                ja._validate_app_contract(bad)

    def test_rejects_empty_and_oversized_lists(self):
        empty = {**_valid_contract(), "cases": []}
        toomany = {**_valid_contract(),
                   "cases": [{"label": "c%d" % i, "args": [], "expect": {"returncode": 0, "stdout": ""}}
                             for i in range(ja.MAX_CASES + 1)]}
        for bad in (empty, toomany):
            with self.subTest(n=len(bad["cases"])), self.assertRaises(JvmApplicationError):
                ja._validate_app_contract(bad)

    def test_rejects_malformed_cases(self):
        def case(**over):
            base = {"label": "a", "args": ["1"], "expect": {"returncode": 0, "stdout": "ok\n"}}
            base.update(over)
            return {**_valid_contract(), "cases": [base]}
        bads = [
            case(label=""),                                            # empty label
            case(label="x" * (ja.MAX_LABEL_LEN + 1)),                  # oversize label
            case(args={}),                                             # args not list
            case(args=[1]),                                            # int arg (JVM argv is str)
            case(args=[True]),                                         # bool arg
            case(args=["a\x00b"]),                                     # NUL in arg
            case(args=["a\tb"]),                                       # control char in arg
            case(args=["x" * (ja.MAX_ARG_LEN + 1)]),                   # oversize arg
            case(args=["1" for _ in range(ja.MAX_CASE_ARGS + 1)]),     # too many args
            case(expect={"returncode": 0}),                            # missing stdout
            case(expect={"stdout": "x"}),                              # missing returncode
            case(expect={"returncode": 0, "stdout": "x", "extra": 1}), # extra expect key
            case(expect={"returncode": True, "stdout": "x"}),          # bool returncode
            case(expect={"returncode": 0, "stdout": "x\x00y"}),        # NUL in stdout
            case(expect={"returncode": 0, "stdout": "x" * (ja.MAX_STDOUT_LEN + 1)}),  # oversize stdout
        ]
        for bad in bads:
            with self.subTest(case=bad["cases"][0]), self.assertRaises(JvmApplicationError):
                ja._validate_app_contract(bad)

    def test_stdout_allows_whitespace_control(self):
        ok = {**_valid_contract(), "cases": [{"label": "a", "args": [], "expect": {"returncode": 0, "stdout": "a\tb\r\nc\n"}}]}
        cases = ja._validate_app_contract(ok)
        self.assertEqual(cases[0]["expect"]["stdout"], "a\tb\r\nc\n")

    def test_rejects_duplicate_labels(self):
        dup = {**_valid_contract(),
               "cases": [{"label": "d", "args": [], "expect": {"returncode": 0, "stdout": ""}},
                         {"label": "d", "args": [], "expect": {"returncode": 1, "stdout": ""}}]}
        with self.assertRaises(JvmApplicationError):
            ja._validate_app_contract(dup)


# ---------------------------------------------------------------------------
# Engine-report helper units (pure)
# ---------------------------------------------------------------------------

class ComparisonCaseVerifyTests(unittest.TestCase):
    def _cases(self):
        return ja._validate_app_contract(_valid_contract())

    def _reported(self, cases):
        out = []
        for c in cases:
            arm = {"returncode": c["expect"]["returncode"], "stdout": c["expect"]["stdout"]}
            out.append({"label": c["label"], "args": c["args"], "expect": dict(c["expect"]),
                        "baseline": dict(arm), "protected": dict(arm), "match": True})
        return out

    def test_accepts_faithful_reports(self):
        cases = self._cases()
        self.assertTrue(ja._verify_comparison_cases({"cases": self._reported(cases)}, cases))

    def test_rejects_count_label_args_expect_arm_and_match_defects(self):
        cases = self._cases()
        good = self._reported(cases)
        # wrong count
        self.assertFalse(ja._verify_comparison_cases({"cases": good[:1]}, cases))
        # wrong args
        d = json.loads(json.dumps(good)); d[0]["args"] = ["999"]
        self.assertFalse(ja._verify_comparison_cases({"cases": d}, cases))
        # protected arm disagrees with expected stdout
        d = json.loads(json.dumps(good)); d[0]["protected"]["stdout"] = "wrong"
        self.assertFalse(ja._verify_comparison_cases({"cases": d}, cases))
        # match flag not True
        d = json.loads(json.dumps(good)); d[0]["match"] = False
        self.assertFalse(ja._verify_comparison_cases({"cases": d}, cases))
        # missing arm
        d = json.loads(json.dumps(good)); del d[0]["baseline"]
        self.assertFalse(ja._verify_comparison_cases({"cases": d}, cases))
        # not a list
        self.assertFalse(ja._verify_comparison_cases({"cases": None}, cases))


class ReceiptCleanTests(unittest.TestCase):
    def _clean(self):
        return _clean_receipt(1234, 0)

    def test_full_clean_receipt_accepted(self):
        self.assertTrue(ja._receipt_clean(self._clean()))
        # A non-zero exit is still infrastructure-clean (fail-closed controls).
        self.assertTrue(ja._receipt_clean(_clean_receipt(1234, 3)))

    def test_empty_or_non_dict_receipt_is_not_clean(self):
        for bad in ({}, None, "x", [], 7):
            with self.subTest(bad=bad):
                self.assertFalse(ja._receipt_clean(bad))

    def test_each_required_field_defect_is_not_clean(self):
        mutations = [
            lambda r: r.pop("pid"),
            lambda r: r.update(pid=0),
            lambda r: r.update(pid=-1),
            lambda r: r.update(pid=True),               # bool pid rejected
            lambda r: r.pop("returncode"),
            lambda r: r.update(returncode=True),         # bool rc rejected
            lambda r: r.update(returncode="0"),
            lambda r: r.update(timed_out=True),
            lambda r: r.pop("timed_out"),                # missing -> not exactly False
            lambda r: r.update(cancelled=True),
            lambda r: r.update(error="boom"),
            lambda r: r.update(post_cleanup_wait_error="late"),
            lambda r: r.pop("cleanup"),
            lambda r: r["cleanup"].update(method="process_group"),
            lambda r: r["cleanup"].update(job_assigned=False),   # explicitly rejected
            lambda r: r["cleanup"].pop("job_assigned"),
            lambda r: r["cleanup"].update(parent_pid=999999),    # != pid
            lambda r: r["cleanup"].update(parent_exit_confirmed=False),
            lambda r: r["cleanup"].update(active_after=1),
            lambda r: r["cleanup"].update(active_after=True),
            lambda r: r["cleanup"].pop("active_after"),
            lambda r: r["cleanup"].update(status="leaked"),
            lambda r: r["cleanup"].update(status=None),          # missing/None rejected
            lambda r: r["cleanup"].update(job_handle_closed=False),
            lambda r: r["cleanup"].pop("job_handle_closed"),
        ]
        for mut in mutations:
            r = self._clean()
            mut(r)
            with self.subTest(mut=mut):
                self.assertFalse(ja._receipt_clean(r))


class ClassifyChildIssuesTests(unittest.TestCase):
    def test_shapes_evidence_into_public_keys(self):
        ev = {"infra_failures": [{"label": "x", "reason": "r"}], "cancellations": ["x"],
              "coverage_ok": True, "observations_ok": True, "controls_ok": True, "prep_ok": True}
        res = ja._classify_child_issues(ev)
        self.assertEqual(res["child_infrastructure_failures"], [{"label": "x", "reason": "r"}])
        self.assertEqual(res["child_cancellations"], ["x"])
        self.assertFalse(res["comparison_mismatch"])  # all *_ok True
        ev2 = {"infra_failures": [], "cancellations": [], "coverage_ok": True,
               "observations_ok": False, "controls_ok": True, "prep_ok": True}
        self.assertTrue(ja._classify_child_issues(ev2)["comparison_mismatch"])


class ForbiddenShaTests(unittest.TestCase):
    def test_collects_originals_helpers_and_baseline(self):
        report = {"original_classes": {"a": _ORIG_CORE_SHA}, "reference_runner_hashes": {"b": _HELPER_SHA}}
        artifacts = {"baseline": {"sha256": _BASE_SHA}, "protected": {"sha256": _PROT_SHA}}
        forbidden = ja._forbidden_byte_shas(report, artifacts)
        self.assertEqual(forbidden, {_ORIG_CORE_SHA, _HELPER_SHA, _BASE_SHA})
        self.assertNotIn(_PROT_SHA, forbidden)  # protected is REQUIRED, never forbidden


# ---------------------------------------------------------------------------
# _verify_engine_report (pure, with a persisted tmp file)
# ---------------------------------------------------------------------------

class VerifyEngineReportTests(_TmpWs):
    def _setup(self):
        h = _build_producer(self.ws)
        cases = ja._validate_app_contract(_valid_contract())
        out = self.ws / ("engine_out-" + uuid.uuid4().hex[:8])
        out.mkdir()
        arm = lambda c: {"returncode": c["expect"]["returncode"], "stdout": c["expect"]["stdout"]}
        report = {
            "schema_version": 1, "kind": ja.INTEGRATION_SPEC_KIND, "status": ja.ENGINE_STATUS_PASSED,
            "language": "java", "fresh_protected_native_build": False,
            "producer": {"report_path": str(h.report_path), "report_sha256": h.report_sha,
                         "backend": "jvm_bytecode_native",
                         "artifacts": {"baseline": {"sha256": _BASE_SHA}, "protected": {"sha256": _PROT_SHA}},
                         "coverage": {"exported_functions": ["leaf_a"]}},
            "staging": {"native_core_sha256": _PROT_SHA, "jni_adapter": "a.dll",
                        "jni_adapter_sha256": ja._digest(_ADAPTER_DLL), "native_library": "JvmApp"},
            "comparison": {"status": ja.ENGINE_COMPARISON_PASSED, **{f: True for f in ja._COMPARISON_PASS_FLAGS},
                           "total_cases": len(cases),
                           "cases": [{"label": c["label"], "args": c["args"], "expect": dict(c["expect"]),
                                      "baseline": arm(c), "protected": arm(c), "match": True} for c in cases]},
            "trusted_inputs_verification": {"verified": True, "declared_count": 9},
        }
        path = out / "integration.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        kw = dict(report_path=h.report_path, report_sha=h.report_sha,
                  artifacts=h.artifacts, cases=cases, language="java", declared_trusted_count=9)
        return report, path, kw

    def test_authentic_report_accepted(self):
        report, path, kw = self._setup()
        v = ja._verify_engine_report(report, path, **kw)
        self.assertTrue(v["authentic"], v)

    def test_persisted_must_equal_returned(self):
        report, path, kw = self._setup()
        path.write_text(json.dumps({**report, "status": "X"}), encoding="utf-8")
        v = ja._verify_engine_report(report, path, **kw)
        self.assertFalse(v["authentic"])
        self.assertFalse(v["checks"]["persisted_equals_returned"])

    def test_missing_persisted_file_rejected(self):
        report, path, kw = self._setup()
        path.unlink()
        self.assertFalse(ja._verify_engine_report(report, path, **kw)["authentic"])

    def test_single_field_defects_each_fail_closed(self):
        report, path, kw = self._setup()
        mutations = {
            "engine_status_passed": lambda r: r.update(status="failed"),
            "language_match": lambda r: r.update(language="kotlin"),
            "producer_report_sha_match": lambda r: r["producer"].update(report_sha256="0" * 64),
            "producer_protected_sha_match": lambda r: r["producer"]["artifacts"]["protected"].update(sha256="0" * 64),
            "native_core_is_reused_protected": lambda r: r["staging"].update(native_core_sha256="0" * 64),
            "comparison_flags_present_true": lambda r: r["comparison"].update(all_match=False),
            "comparison_covers_all_cases": lambda r: r["comparison"].update(total_cases=99),
            "comparison_cases_match": lambda r: r["comparison"]["cases"][0]["protected"].update(stdout="wrong"),
            "trusted_inputs_verified": lambda r: r["trusted_inputs_verification"].update(declared_count=1),
            "fresh_protected_native_build_false": lambda r: r.update(fresh_protected_native_build=True),
        }
        for check, mut in mutations.items():
            report, path, kw = self._setup()
            mut(report)
            path.write_text(json.dumps(report), encoding="utf-8")
            v = ja._verify_engine_report(report, path, **kw)
            with self.subTest(check=check):
                self.assertFalse(v["authentic"])
                self.assertFalse(v["checks"][check], check)


# ---------------------------------------------------------------------------
# _verify_child_evidence (pure, with a tmp engine out dir) — regression matrix
# ---------------------------------------------------------------------------

class VerifyChildEvidenceTests(_TmpWs):
    def _setup(self):
        cases = ja._validate_app_contract(_valid_contract())
        out = self.ws / ("engine-" + uuid.uuid4().hex[:8])
        out.mkdir()
        ce = _build_child_evidence(out, cases)
        report = {"comparison": {"status": ja.ENGINE_COMPARISON_PASSED,
                                 **{f: True for f in ja._COMPARISON_PASS_FLAGS},
                                 "total_cases": len(cases), "cases": ce["cases"], "commands": ce["commands"]},
                  "preparation_commands": ce["preparation_commands"]}
        return report, out, cases

    def _verify(self, report, out, cases):
        return ja._verify_child_evidence(report, engine_out=out, cases=cases)

    def _cmd(self, report, label):
        for e in report["comparison"]["commands"]:
            if e["label"] == label:
                return e
        raise KeyError(label)

    def _prep(self, report, label):
        for e in report["preparation_commands"]:
            if e["label"] == label:
                return e
        raise KeyError(label)

    def _set_receipt(self, entry, receipt):
        # Preserve the stdout/stderr BINDING so a defect is exercised at the
        # intended check (clean-ness / exit), not at the log-binding step.
        receipt = dict(receipt)
        receipt.setdefault("stdout", entry.get("stdout_log"))
        receipt.setdefault("stderr", entry.get("stderr_log"))
        p = Path(entry["receipt_path"])
        data = json.dumps(receipt).encode("utf-8")
        p.write_bytes(data)
        entry["receipt_sha256"] = ja._digest(data)

    def test_authentic_child_evidence_accepted(self):
        report, out, cases = self._setup()
        v = self._verify(report, out, cases)
        self.assertTrue(v["authentic"], v)
        self.assertEqual(v["infra_failures"], [])
        self.assertTrue(v["coverage_ok"] and v["observations_ok"] and v["controls_ok"] and v["prep_ok"])

    def test_empty_commands_fails(self):
        report, out, cases = self._setup()
        report["comparison"]["commands"] = []
        self.assertFalse(self._verify(report, out, cases)["authentic"])

    def test_missing_command_identity_fails(self):
        report, out, cases = self._setup()
        report["comparison"]["commands"] = [e for e in report["comparison"]["commands"]
                                            if e["label"] != "control:unset_adapter"]
        v = self._verify(report, out, cases)
        self.assertFalse(v["authentic"])
        self.assertFalse(v["coverage_ok"])

    def test_unknown_command_identity_fails(self):
        report, out, cases = self._setup()
        rogue = dict(self._cmd(report, "control:missing_core"))
        rogue["label"] = "control:bogus"
        rogue["control"] = "bogus"
        report["comparison"]["commands"].append(rogue)
        self.assertFalse(self._verify(report, out, cases)["authentic"])

    def test_duplicate_command_identity_fails(self):
        report, out, cases = self._setup()
        report["comparison"]["commands"].append(dict(self._cmd(report, "control:missing_core")))
        self.assertFalse(self._verify(report, out, cases)["authentic"])

    def test_command_entry_extra_key_fails(self):
        report, out, cases = self._setup()
        self._cmd(report, "control:missing_core")["returncode"] = 0  # a non-metadata key
        self.assertFalse(self._verify(report, out, cases)["authentic"])

    def test_inconsistent_arm_identity_fails(self):
        report, out, cases = self._setup()
        self._cmd(report, "case:square(5):original")["arm"] = "protected"  # label/arm mismatch
        self.assertFalse(self._verify(report, out, cases)["authentic"])

    def test_malformed_entry_and_field_omissions_fail(self):
        # non-dict entry
        report, out, cases = self._setup()
        report["comparison"]["commands"].append(["not", "a", "dict"])
        self.assertFalse(self._verify(report, out, cases)["authentic"])
        # omit receipt_path
        report, out, cases = self._setup()
        del self._cmd(report, "control:missing_core")["receipt_path"]
        self.assertFalse(self._verify(report, out, cases)["authentic"])
        # omit receipt_sha256
        report, out, cases = self._setup()
        del self._cmd(report, "control:missing_core")["receipt_sha256"]
        self.assertFalse(self._verify(report, out, cases)["authentic"])
        # omit stdout_log on a case arm
        report, out, cases = self._setup()
        del self._cmd(report, "case:square(5):protected")["stdout_log"]
        self.assertFalse(self._verify(report, out, cases)["authentic"])

    def test_dirty_receipt_not_clean_fails(self):
        report, out, cases = self._setup()
        entry = self._cmd(report, "case:square(5):original")
        dirty = _clean_receipt(55, 0)
        dirty["cleanup"]["job_assigned"] = False          # the exact defect root flagged
        self._set_receipt(entry, dirty)                   # sha updated so the PIN still matches
        v = self._verify(report, out, cases)
        self.assertFalse(v["authentic"])
        self.assertTrue(any("infrastructure-clean" in f["reason"] for f in v["infra_failures"]))

    def test_broken_receipt_pin_fails(self):
        report, out, cases = self._setup()
        self._cmd(report, "control:missing_core")["receipt_sha256"] = "0" * 64  # file unchanged
        self.assertFalse(self._verify(report, out, cases)["authentic"])

    def test_unconfined_receipt_path_fails(self):
        report, out, cases = self._setup()
        outside = self.ws / "outside.process.json"
        outside.write_bytes(json.dumps(_clean_receipt(9, 0)).encode("utf-8"))
        entry = self._cmd(report, "control:missing_core")
        entry["receipt_path"] = str(outside)
        entry["receipt_sha256"] = ja._digest(outside.read_bytes())
        self.assertFalse(self._verify(report, out, cases)["authentic"])

    def test_control_not_failing_closed_fails(self):
        report, out, cases = self._setup()
        entry = self._cmd(report, "control:missing_core")
        self._set_receipt(entry, _clean_receipt(77, 0))   # control exited 0 -> NOT fail-closed
        v = self._verify(report, out, cases)
        self.assertFalse(v["authentic"])
        self.assertFalse(v["controls_ok"])

    def test_observation_mismatch_from_logs_fails(self):
        report, out, cases = self._setup()
        entry = self._cmd(report, "case:square(5):protected")
        Path(entry["stdout_log"]).write_bytes(b"WRONG OUTPUT\n")   # disagrees with expected stdout
        v = self._verify(report, out, cases)
        self.assertFalse(v["authentic"])
        self.assertFalse(v["observations_ok"])

    def test_observation_wrong_exit_from_receipt_fails(self):
        report, out, cases = self._setup()
        entry = self._cmd(report, "case:square(5):protected")
        self._set_receipt(entry, _clean_receipt(88, 9))   # exit disagrees with expected 0
        v = self._verify(report, out, cases)
        self.assertFalse(v["authentic"])
        self.assertFalse(v["observations_ok"])

    def test_missing_or_empty_preparation_fails(self):
        report, out, cases = self._setup()
        del report["preparation_commands"]
        self.assertFalse(self._verify(report, out, cases)["authentic"])
        report, out, cases = self._setup()
        report["preparation_commands"] = []
        self.assertFalse(self._verify(report, out, cases)["authentic"])

    def test_dirty_or_duplicate_or_extra_preparation_fails(self):
        # dirty prep receipt
        report, out, cases = self._setup()
        prep = report["preparation_commands"][0]
        self._set_receipt(prep, dict(_clean_receipt(5, 0), timed_out=True))
        self.assertFalse(self._verify(report, out, cases)["authentic"])
        # duplicate prep label
        report, out, cases = self._setup()
        report["preparation_commands"].append(dict(report["preparation_commands"][0]))
        self.assertFalse(self._verify(report, out, cases)["authentic"])
        # prep extra non-metadata key
        report, out, cases = self._setup()
        report["preparation_commands"][0]["returncode"] = 0
        self.assertFalse(self._verify(report, out, cases)["authentic"])

    def test_no_comparison_block_fails(self):
        self.assertFalse(ja._verify_child_evidence({}, engine_out=self.ws, cases=[])["authentic"])

    def _reasons(self, v):
        return [f.get("reason", "") for f in v.get("infra_failures", [])]

    # ---- Check 1: stdout_log / stderr_log must be BOUND to the pinned receipt ----
    def test_unrelated_stdout_log_fails(self):
        report, out, cases = self._setup()
        entry = self._cmd(report, "case:square(5):protected")
        other = out / "logs" / "unrelated.stdout.log"
        other.write_bytes(b"25\n")                 # a genuine, content-PASSING, but UNRELATED log
        entry["stdout_log"] = str(other)           # receipt.stdout still points at the real log
        v = self._verify(report, out, cases)
        self.assertFalse(v["authentic"])
        self.assertTrue(any("bound to the receipt's own stdout" in r for r in self._reasons(v)), self._reasons(v))

    def test_unrelated_stderr_log_fails(self):
        report, out, cases = self._setup()
        entry = self._cmd(report, "control:missing_core")
        other = out / "logs" / "unrelated.stderr.log"
        other.write_bytes(b"")
        entry["stderr_log"] = str(other)
        v = self._verify(report, out, cases)
        self.assertFalse(v["authentic"])
        self.assertTrue(any("bound to the receipt's own stderr" in r for r in self._reasons(v)), self._reasons(v))

    # ---- Check 2: receipt + bound log paths must be UNIQUE across all entries ----
    def test_receipt_path_reuse_across_entries_fails(self):
        report, out, cases = self._setup()
        a = self._cmd(report, "case:square(5):original")
        b = self._cmd(report, "control:missing_core")
        b["receipt_path"] = a["receipt_path"]      # one child cannot back two identities
        b["receipt_sha256"] = a["receipt_sha256"]
        v = self._verify(report, out, cases)
        self.assertFalse(v["authentic"])
        self.assertTrue(any("reused" in r for r in self._reasons(v)), self._reasons(v))

    def test_stdout_log_reuse_across_entries_fails(self):
        report, out, cases = self._setup()
        a = self._cmd(report, "case:square(5):original")
        b = self._cmd(report, "case:add(7,3):original")
        b["stdout_log"] = a["stdout_log"]          # bind b's receipt to a's log, then reuse is detected
        self._set_receipt(b, _clean_receipt(99, 0))
        v = self._verify(report, out, cases)
        self.assertFalse(v["authentic"])
        self.assertTrue(any("reused" in r for r in self._reasons(v)), self._reasons(v))

    # ---- Check 3: preparation_commands must be EXACTLY the four labels, clean, exit 0 ----
    def test_prep_missing_each_required_label_fails(self):
        for lbl in ja._REQUIRED_PREP_LABELS:
            report, out, cases = self._setup()
            report["preparation_commands"] = [e for e in report["preparation_commands"] if e["label"] != lbl]
            with self.subTest(missing=lbl):
                v = self._verify(report, out, cases)
                self.assertFalse(v["authentic"])
                self.assertFalse(v["prep_ok"])

    def test_prep_unknown_label_fails(self):
        report, out, cases = self._setup()
        extra = dict(_child(out, "prep_extra", 4100, 0), label="prep-bogus", kind="prepare", tool="x", cwd=str(out))
        report["preparation_commands"].append(extra)
        v = self._verify(report, out, cases)
        self.assertFalse(v["authentic"])
        self.assertFalse(v["prep_ok"])

    def test_prep_duplicate_label_fails(self):
        report, out, cases = self._setup()
        dup = dict(_child(out, "prep_dup", 4200, 0), label="sdk-capture", kind="prepare", tool="x", cwd=str(out))
        report["preparation_commands"].append(dup)
        self.assertFalse(self._verify(report, out, cases)["authentic"])

    def test_prep_nonzero_compile_exit_fails(self):
        report, out, cases = self._setup()
        self._set_receipt(self._prep(report, "compile-facade"), _clean_receipt(4300, 1))  # nonzero compile
        v = self._verify(report, out, cases)
        self.assertFalse(v["authentic"])
        self.assertFalse(v["prep_ok"])

    def test_prep_all_four_clean_exit0_accepted(self):
        report, out, cases = self._setup()
        v = self._verify(report, out, cases)
        self.assertTrue(v["authentic"], v)
        self.assertTrue(v["prep_ok"])


# ---------------------------------------------------------------------------
# _inventory_bundle (pure, with a tmp engine out dir)
# ---------------------------------------------------------------------------

class InventoryBundleTests(_TmpWs):
    def _setup(self, *, files=None, mutate_report=None, extra_disk=None, drop_disk=None, outside=False):
        engine_out = self.ws / "engine_out"
        engine_out.mkdir()
        deploy = (self.ws if outside else engine_out) / "deployment"
        deploy.mkdir(parents=True)
        files = dict(files if files is not None else _authentic_deploy_files())
        manifest = []
        for rel, data in files.items():
            dst = deploy / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(data)
            manifest.append({"relative_path": rel, "sha256": ja._digest(data), "bytes": len(data)})
        if extra_disk is not None:
            (deploy / extra_disk).write_bytes(b"UNLISTED")
        if drop_disk is not None:
            (deploy / drop_disk).unlink()
        report = {"deployment": {"path": str(deploy), "allowlist": sorted(files),
                                 "files": manifest, "forbidden_absent": True,
                                 "main_class": "sample.App", "classpath_entries": ["."],
                                 "native_core": _NATIVE_REL, "jni_adapter": _ADAPTER_REL}}
        if mutate_report is not None:
            mutate_report(report)
        producer_report = {"original_classes": {"c": _ORIG_CORE_SHA},
                           "reference_runner_hashes": {"h": _HELPER_SHA}}
        artifacts = {"baseline": {"sha256": _BASE_SHA}, "protected": {"sha256": _PROT_SHA}}
        return report, engine_out, producer_report, artifacts

    def test_authentic_bundle_returns_inventory(self):
        report, engine_out, producer_report, artifacts = self._setup()
        bundle = ja._inventory_bundle(report, engine_out=engine_out, artifacts=artifacts,
                                      expected_native_sha=_PROT_SHA, report=producer_report)
        self.assertEqual(bundle["native_core"], _NATIVE_REL)
        self.assertEqual(bundle["main_class"], "sample.App")
        self.assertEqual({f["relative_path"] for f in bundle["files"]}, set(_authentic_deploy_files()))
        self.assertIn(_PROT_SHA, {f["sha256"] for f in bundle["files"]})

    def test_rejects_extra_disk_file(self):
        report, engine_out, pr, art = self._setup(extra_disk="stowaway.class")
        with self.assertRaises(JvmApplicationError):
            ja._inventory_bundle(report, engine_out=engine_out, artifacts=art,
                                 expected_native_sha=_PROT_SHA, report=pr)

    def test_rejects_missing_disk_file(self):
        report, engine_out, pr, art = self._setup(drop_disk="sample/App.class")
        with self.assertRaises(JvmApplicationError):
            ja._inventory_bundle(report, engine_out=engine_out, artifacts=art,
                                 expected_native_sha=_PROT_SHA, report=pr)

    def test_rejects_forbidden_original_bytes(self):
        files = _authentic_deploy_files()
        files["core/Core.class"] = b"ORIGINAL-CORE-CLASSFILE-BYTES"  # sha == _ORIG_CORE_SHA (forbidden)
        report, engine_out, pr, art = self._setup(files=files)
        with self.assertRaises(JvmApplicationError) as ctx:
            ja._inventory_bundle(report, engine_out=engine_out, artifacts=art,
                                 expected_native_sha=_PROT_SHA, report=pr)
        self.assertIn("forbidden original bytes", str(ctx.exception))

    def test_rejects_non_allowlisted_suffix(self):
        files = _authentic_deploy_files()
        files["notes.txt"] = b"text"
        report, engine_out, pr, art = self._setup(files=files)
        with self.assertRaises(JvmApplicationError):
            ja._inventory_bundle(report, engine_out=engine_out, artifacts=art,
                                 expected_native_sha=_PROT_SHA, report=pr)

    def test_rejects_allowlist_manifest_disagreement(self):
        def drop_allow(r):
            r["deployment"]["allowlist"] = r["deployment"]["allowlist"][:-1]
        report, engine_out, pr, art = self._setup(mutate_report=drop_allow)
        with self.assertRaises(JvmApplicationError):
            ja._inventory_bundle(report, engine_out=engine_out, artifacts=art,
                                 expected_native_sha=_PROT_SHA, report=pr)

    def test_rejects_wrong_native_core_sha(self):
        report, engine_out, pr, art = self._setup()
        with self.assertRaises(JvmApplicationError):
            ja._inventory_bundle(report, engine_out=engine_out, artifacts=art,
                                 expected_native_sha="0" * 64, report=pr)

    def test_rejects_unconfined_deployment(self):
        report, engine_out, pr, art = self._setup(outside=True)
        with self.assertRaises(JvmApplicationError):
            ja._inventory_bundle(report, engine_out=engine_out, artifacts=art,
                                 expected_native_sha=_PROT_SHA, report=pr)

    def test_rejects_forbidden_absent_not_asserted(self):
        def unassert(r):
            r["deployment"]["forbidden_absent"] = False
        report, engine_out, pr, art = self._setup(mutate_report=unassert)
        with self.assertRaises(JvmApplicationError):
            ja._inventory_bundle(report, engine_out=engine_out, artifacts=art,
                                 expected_native_sha=_PROT_SHA, report=pr)

    def test_rejects_launch_metadata_non_member(self):
        def break_cp(r):
            r["deployment"]["classpath_entries"] = ["../escape.jar"]
        report, engine_out, pr, art = self._setup(mutate_report=break_cp)
        with self.assertRaises(JvmApplicationError):
            ja._inventory_bundle(report, engine_out=engine_out, artifacts=art,
                                 expected_native_sha=_PROT_SHA, report=pr)


# ---------------------------------------------------------------------------
# Top-level request guards (pure; no workspace needed)
# ---------------------------------------------------------------------------

class TimeoutGuardTests(unittest.TestCase):
    def test_invalid_timeout_rejected_before_filesystem(self):
        sentinel = SimpleNamespace()  # no .root / ._directory: proves no fs access first
        for bad in (0, -1, 601, 1.0, True, "90"):
            with self.subTest(bad=bad), self.assertRaises(JvmApplicationError):
                ja.integrate_source_application(sentinel, "pid", "s.json", "c.json", timeout_seconds=bad)


# ---------------------------------------------------------------------------
# End-to-end service flow through the mocked engine
# ---------------------------------------------------------------------------

class EndToEndPassTests(_TmpWs):
    def test_java_pass_produces_bundle_and_pins(self):
        h = _build_producer(self.ws, language="java")
        res = _run(h, _authentic_engine(h))
        self.assertEqual(res["status"], ja.PUBLIC_STATUS_PASSED, res)
        self.assertTrue(res["engine_report_authentic"])
        self.assertTrue(res["original_inputs_unchanged"])
        self.assertFalse(res["comparison_mismatch"])
        self.assertEqual(res["reused_native_core"], True)
        self.assertEqual(res["fresh_protected_native_build"], False)
        self.assertEqual(res["total_cases"], 2)
        b = res["deployment_bundle"]
        self.assertEqual(b["native_core"], _NATIVE_REL)
        self.assertEqual(b["jni_adapter"], _ADAPTER_REL)
        self.assertEqual(b["main_class"], "sample.App")
        self.assertIn(_PROT_SHA, {f["sha256"] for f in b["files"]})
        self.assertIsInstance(res["launch_instructions"], list)
        # The persisted service result + plan exist and are hash-pinned.
        self.assertTrue(Path(res["integration_report_path"]).is_file())
        self.assertTrue(Path(res["integration_plan_path"]).is_file())
        self.assertEqual(res["external_attack_evaluation"], "not_evaluated")
        self.assertEqual(res["performance_evaluation"], "not_evaluated")

    def test_kotlin_pass(self):
        h = _build_producer(self.ws, language="kotlin",
                            spec_obj=_valid_spec("kotlin"))
        res = _run(h, _authentic_engine(h))
        self.assertEqual(res["status"], ja.PUBLIC_STATUS_PASSED, res)
        self.assertEqual(res["language"], "kotlin")
        self.assertEqual(res["deployment_bundle"]["main_class"], "sample.AppKt")

    def test_routing_through_service_integrate(self):
        h = _build_producer(self.ws, language="java")
        engine = _authentic_engine(h)
        with mock.patch.object(ja, "_load_engine", lambda: engine):
            res = h.svc.integrate(h.plan_id, str(h.spec), str(h.contract), timeout_seconds=90)
        self.assertEqual(res["status"], ja.PUBLIC_STATUS_PASSED, res)


class EndToEndNegativeTests(_TmpWs):
    def test_wrong_backend_rejected(self):
        h = _build_producer(self.ws)
        # Flip the saved result backend; the service must refuse to integrate.
        res_path = h.job / "result.json"
        result = json.loads(res_path.read_text(encoding="utf-8"))
        result["backend"] = "dotnet_il_native"
        res_path.unlink()
        ja._create_json(res_path, result)
        with self.assertRaises(JvmApplicationError):
            _run(h, _authentic_engine(h))

    def test_stop_marker_cancels_before_engine(self):
        h = _build_producer(self.ws)
        stop = h.svc.root / ".runs" / "defense-loop" / "STOP"
        stop.parent.mkdir(parents=True, exist_ok=True)
        stop.write_text("private-test-marker", encoding="utf-8")

        def boom():
            raise AssertionError("engine must not run when STOP is present")
        engine = SimpleNamespace(run_integration=lambda **k: boom())
        res = _run(h, engine)
        self.assertEqual(res["status"], "cancelled")
        self.assertIsNone(res["integration_id"])

    def test_engine_exception_is_failed_no_bundle(self):
        h = _build_producer(self.ws)

        def run_integration(**kwargs):
            Path(kwargs["output_dir"]).mkdir(parents=True, exist_ok=True)
            raise RuntimeError("engine blew up")
        res = _run(h, SimpleNamespace(run_integration=run_integration))
        self.assertEqual(res["status"], "failed")
        self.assertIsNone(res["deployment_bundle"])
        record = json.loads(Path(res["integration_report_path"]).read_text(encoding="utf-8"))
        self.assertIsNotNone(record["execution_error"])

    def test_engine_non_dict_is_failed(self):
        h = _build_producer(self.ws)

        def run_integration(**kwargs):
            Path(kwargs["output_dir"]).mkdir(parents=True, exist_ok=True)
            (Path(kwargs["output_dir"]) / "integration.json").write_text("[]", encoding="utf-8")
            return ["not", "a", "dict"]
        res = _run(h, SimpleNamespace(run_integration=run_integration))
        self.assertEqual(res["status"], "failed")

    def test_persisted_divergent_report_is_failed(self):
        h = _build_producer(self.ws)
        res = _run(h, _authentic_engine(h, persist_divergent=True))
        self.assertEqual(res["status"], "failed")
        self.assertFalse(res["engine_report_authentic"])

    def test_forbidden_bytes_in_bundle_is_failed(self):
        h = _build_producer(self.ws)
        files = _authentic_deploy_files()
        files["core/Core.class"] = b"ORIGINAL-CORE-CLASSFILE-BYTES"  # sha == forbidden
        res = _run(h, _authentic_engine(h, deploy_files=files))
        self.assertEqual(res["status"], "failed")
        self.assertIsNone(res["deployment_bundle"])
        record = json.loads(Path(res["integration_report_path"]).read_text(encoding="utf-8"))
        self.assertIsNotNone(record["package_error"])
        self.assertIn("forbidden original bytes", record["package_error"])

    def test_unconfined_deployment_is_failed(self):
        h = _build_producer(self.ws)
        res = _run(h, _authentic_engine(h, deploy_outside=True))
        self.assertEqual(res["status"], "failed")
        self.assertIsNone(res["deployment_bundle"])

    def test_snapshot_drift_during_run_is_failed(self):
        h = _build_producer(self.ws)

        def drift():
            # mutate a pinned project source mid-run -> post-recompute mismatch
            (h.pkg / "app" / "App.java").write_text("// tampered after planning\n", encoding="utf-8")
        res = _run(h, _authentic_engine(h, during_run=drift))
        self.assertEqual(res["status"], "failed")
        self.assertFalse(res["original_inputs_unchanged"])

    def test_stop_created_during_run_is_cancelled(self):
        h = _build_producer(self.ws)
        stop = h.svc.root / ".runs" / "defense-loop" / "STOP"

        def plant_stop():
            stop.parent.mkdir(parents=True, exist_ok=True)
            stop.write_text("late", encoding="utf-8")
        res = _run(h, _authentic_engine(h, during_run=plant_stop))
        self.assertEqual(res["status"], "cancelled")
        self.assertIsNone(res["deployment_bundle"])

    def test_child_infrastructure_failure_is_failed(self):
        # An otherwise-authentic run whose PERSISTED raw receipt shows an unclean
        # Windows-Job cleanup must NOT pass -- the service reads the pinned receipt,
        # not the engine's returned booleans.
        h = _build_producer(self.ws)

        def dirty_one(ce, out):
            entry = ce["commands"][0]
            # Keep the log binding intact so the ONLY defect is unclean cleanup.
            bad = _clean_receipt(42, 0, stdout=entry["stdout_log"], stderr=entry["stderr_log"])
            bad["timed_out"] = True
            p = Path(entry["receipt_path"])
            data = json.dumps(bad).encode("utf-8")
            p.write_bytes(data)
            entry["receipt_sha256"] = ja._digest(data)  # pin matches, but receipt is unclean
        res = _run(h, _authentic_engine(h, child_tamper=dirty_one))
        self.assertEqual(res["status"], "failed")
        self.assertIsNone(res["deployment_bundle"])
        record = json.loads(Path(res["integration_report_path"]).read_text(encoding="utf-8"))
        self.assertTrue(record["child_infrastructure_failures"])
        self.assertFalse(record["child_evidence_verification"]["authentic"])

    def test_stale_fingerprint_rejected(self):
        h = _build_producer(self.ws, recompute_fingerprint=False)
        with self.assertRaises(JvmApplicationError):
            _run(h, _authentic_engine(h))

    def test_spec_contract_must_be_distinct(self):
        h = _build_producer(self.ws)
        with self.assertRaises(JvmApplicationError):
            with mock.patch.object(ja, "_load_engine", lambda: _authentic_engine(h)):
                ja.integrate_source_application(h.svc, h.plan_id, str(h.spec), str(h.spec), timeout_seconds=90)

    def test_app_source_overlapping_core_rejected(self):
        # application_sources naming the protected CORE source must be refused.
        spec = _valid_spec("java")
        spec["application_sources"] = ["core/Core.java"]
        h = _build_producer(self.ws, spec_obj=spec)
        with self.assertRaises(JvmApplicationError):
            _run(h, _authentic_engine(h))

    def test_app_source_not_in_snapshot_rejected(self):
        spec = _valid_spec("java")
        spec["application_sources"] = ["app/Missing.java"]  # not created on disk
        h = _build_producer(self.ws, spec_obj=spec)
        with self.assertRaises(JvmApplicationError):
            _run(h, _authentic_engine(h))


if __name__ == "__main__":  # pragma: no cover - direct run is NOT the sanctioned path
    unittest.main(verbosity=2)
