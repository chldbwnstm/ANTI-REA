"""Service-level tests for the C# source-integrate route (ProjectService.integrate).

Defender-only (service-tests worker), follow-up delivery. The forthcoming engine
and the public service module have now LANDED, so the public service boundary
matrix is exercised for real against ``antirea.csharp_application`` (imported
directly -- no capability skip; a missing required module/guard must FAIL, not
skip). Only the optional installed-toolchain native E2E skips under ordinary
discovery, behind an explicit ``ANTIREA_RUN_CSHARP_APP_E2E`` opt-in.

Technique: the whole binding/snapshot/toolchain/spec/contract boundary is driven
through the real public function using PURE SYNTHETIC, fully self-consistent saved
C# source-plan/result/build-report fixtures written into a private workspace (no
compiler), and a BOUNDARY MOCK of the trusted engine for the execution phase. The
synthetic fixtures and the mocked engine are never presented as real integration
evidence -- the only real integration proof is root's separate fresh CLI E2E.

Every child process this suite launches goes through the OUTER bounded
``run_logged`` wrapper: the real controller STOP as ``cancel_file`` (existence
only; never created/read/deleted), an explicit allow-listed environment (never an
``os.environ`` copy), a private TEMP/HOME, a fresh append-only run dir, retained
raw stdout/stderr + process JSON, and -- per root review ``msg_658ba84a4a67`` --
assertions on returncode and the complete Windows Job cleanup record (method,
``parent_pid == proc.pid``, ``parent_exit_confirmed``, ``job_assigned``,
``active_after == 0``, ``job_handle_closed`` and ``assigned_job_empty``). CLI
children use ``-I -S -B`` with a trusted-root bootstrap. No REA/attack/received
code runs; no attacker/received-report path, ``env.setting`` or ``LINKREPRO``
artifact is traversed (reserved segments are only ever synthetic strings under a
private temp dir); no install/download/publish/commit happens.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sys
import tempfile
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from antirea import csharp_application as ca  # REQUIRED production module: no skip gate.
from antirea.csharp_application import CSharpApplicationError
from antirea.process import run_logged
from antirea.projects import ProjectService

REAL_STOP = ROOT / ".runs" / "defense-loop" / "STOP"
RUN_ROOT = ROOT / ".runs" / "orca-wave6-csharp-public-tests"
SAMPLE_CSHARP_APP = ROOT / "samples" / "multilang" / "csharp_application"

_HAS_DOTNET = shutil.which("dotnet") is not None
_OPT_IN = os.environ.get("ANTIREA_RUN_CSHARP_APP_E2E") == "1"
_requires_e2e = unittest.skipUnless(
    _OPT_IN and _HAS_DOTNET and SAMPLE_CSHARP_APP.is_dir(),
    "optional installed-toolchain C# integration E2E requires ANTIREA_RUN_CSHARP_APP_E2E=1, "
    "an installed dotnet SDK and the csharp_application sample")

_SYSROOT = r"C:\Windows"
_DOTNET_DIR = r"C:\Program Files\dotnet"
_SUCCESS_STATUS = ca.PUBLIC_STATUS_PASSED  # root-pinned public success status

_BOOTSTRAP = RUN_ROOT / "_cli_bootstrap.py"
_BOOTSTRAP_SRC = (
    '"""Trusted-root bootstrap for launching the defender CLI under -I -S -B."""\n'
    "import sys\n"
    "from pathlib import Path\n"
    "_REPO = Path(__file__).resolve().parents[2]\n"
    "if str(_REPO) not in sys.path:\n"
    "    sys.path.insert(0, str(_REPO))\n"
    "from antirea.defense_mcp import main\n"
    "raise SystemExit(main(sys.argv[1:]))\n"
)


def _ensure_bootstrap() -> Path:
    RUN_ROOT.mkdir(parents=True, exist_ok=True)
    if not _BOOTSTRAP.is_file() or _BOOTSTRAP.read_text(encoding="utf-8") != _BOOTSTRAP_SRC:
        _BOOTSTRAP.write_text(_BOOTSTRAP_SRC, encoding="utf-8")
    return _BOOTSTRAP


def _allowlisted_env(priv_tmp: Path, priv_home: Path) -> dict:
    """Explicit allow-listed literals ONLY -- never an ``os.environ`` copy."""
    py_dir = str(Path(sys.executable).parent)
    return {
        "SystemRoot": _SYSROOT, "windir": _SYSROOT, "SystemDrive": "C:",
        "PATH": os.pathsep.join([py_dir, _DOTNET_DIR, _SYSROOT + r"\System32", _SYSROOT]),
        "TEMP": str(priv_tmp), "TMP": str(priv_tmp),
        "USERPROFILE": str(priv_home),
        "APPDATA": str(priv_home / "AppData" / "Roaming"),
        "LOCALAPPDATA": str(priv_home / "AppData" / "Local"),
        "DOTNET_ROOT": _DOTNET_DIR, "DOTNET_CLI_HOME": str(priv_home),
        "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
        "DOTNET_NOLOGO": "1", "DOTNET_MULTILEVEL_LOOKUP": "0",
        "NUGET_PACKAGES": str(priv_home / "nuget"),
        "PROCESSOR_ARCHITECTURE": "AMD64",
        "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1",
    }


def _fresh_run_dir(label: str) -> Path:
    RUN_ROOT.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%f")
    out = RUN_ROOT / (label + "-" + stamp)
    out.mkdir()  # fresh unique dir; append-only, never overwrites a prior run
    return out


def _outer_run(argv, label, *, cwd=ROOT, timeout=300, cancel_file=REAL_STOP):
    """Run ONE owned command through the OUTER bounded ``run_logged`` wrapper."""
    out = _fresh_run_dir(label)
    priv_tmp = out / "_tmp"
    priv_home = out / "_home"
    priv_tmp.mkdir()
    priv_home.mkdir()
    env = _allowlisted_env(priv_tmp, priv_home)
    proc = run_logged([str(a) for a in argv], cwd, out / "logs" / label,
                      timeout=timeout, env=env, cancel_file=cancel_file)
    cleanup = proc.get("cleanup", {})
    receipt = {
        "label": label, "argv": proc.get("argv"), "returncode": proc.get("returncode"),
        "pid": proc.get("pid"), "timed_out": proc.get("timed_out"),
        "cancelled": proc.get("cancelled"), "seconds": proc.get("seconds"), "cleanup": cleanup,
        "stdout_log": proc.get("stdout"), "stderr_log": proc.get("stderr"),
        "cancel_file": str(cancel_file), "env_keys": sorted(env), "out_dir": str(out),
    }
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return proc, receipt, out


def _cli_argv(*args):
    return [sys.executable, "-I", "-S", "-B", str(_ensure_bootstrap()), *args]


class _WrapperAsserts(unittest.TestCase):
    def assert_bounded_cleanup(self, proc):
        """Complete bounded-cleanup record (root review msg_658ba84a4a67)."""
        self.assertFalse(proc["timed_out"], proc)
        self.assertFalse(proc["cancelled"], proc)
        self.assertIsInstance(proc["returncode"], int, proc)
        cleanup = proc["cleanup"]
        self.assertIn("method", cleanup)
        self.assertTrue(cleanup.get("parent_exit_confirmed"), cleanup)
        self.assertEqual(cleanup.get("parent_pid"), proc["pid"], cleanup)
        if os.name == "nt":
            self.assertEqual(cleanup.get("method"), "windows_job", cleanup)
            self.assertTrue(cleanup.get("job_assigned"), cleanup)
            self.assertEqual(cleanup.get("active_after"), 0, cleanup)
            self.assertTrue(cleanup.get("job_handle_closed"), cleanup)
            self.assertEqual(cleanup.get("status"), "assigned_job_empty", cleanup)
        self.assertTrue(Path(proc["stdout"]).is_file())
        self.assertTrue(Path(proc["stderr"]).is_file())
        self.assertTrue(Path(proc["stdout"]).with_name(
            Path(proc["stdout"]).name.replace(".stdout.log", ".process.json")).is_file())


# ---------------------------------------------------------------------------
# Synthetic, self-consistent saved producer job fixtures (no compiler)
# ---------------------------------------------------------------------------

def _copy_tree_into(src: Path, dst: Path):
    dst.mkdir(parents=True)
    for item in sorted(src.iterdir()):
        if item.is_file():
            shutil.copy2(item, dst / item.name)


def _synthetic_job_id() -> str:
    # Matches antirea.projects.JOB_ID: source-<8>T<6>Z-<12 hex>.
    return "source-20261020T010203Z-" + uuid.uuid4().hex[:12]


def _build_producer(ws: Path, *, spec_obj=None, contract_obj=None,
                    mutate_plan=None, mutate_result=None, mutate_report=None,
                    recompute_fingerprint=True, artifacts=None):
    """Write a fully consistent synthetic dotnet_il_native producer job.

    Without perturbation the result passes every service boundary check and
    reaches the (mocked) engine. ``mutate_*`` hooks perturb exactly one bound
    field so an individual guard can be isolated; ``recompute_fingerprint=False``
    leaves ``result.fingerprint`` stale to exercise the fingerprint binding.
    """
    svc = ProjectService(ws)
    pkg = ws / "pkg"
    _copy_tree_into(SAMPLE_CSHARP_APP, pkg)
    if spec_obj is not None:
        (pkg / "integration.json").write_text(json.dumps(spec_obj, indent=2) + "\n", encoding="utf-8")
    if contract_obj is not None:
        (pkg / "application-contract.json").write_text(json.dumps(contract_obj, indent=2) + "\n", encoding="utf-8")
    source = pkg / "project.json"

    inspection = {"language": "csharp", "name": "CsharpApp", "project_path": str(source),
                  "backend": "dotnet_il_native", "exports": ["cs_leaf_a", "cs_leaf_b", "cs_leaf_c"]}
    if artifacts is None:
        artifacts = {"baseline": {"path": str(pkg / "baseline.bin"), "sha256": "ab" * 32},
                     "protected": {"path": str(pkg / "protected.bin"), "sha256": "cd" * 32}}
    coverage = {"exported_functions": ["cs_leaf_a", "cs_leaf_b", "cs_leaf_c"]}
    report = {"schema_version": 1, "backend": "dotnet_il_native",
              "status": "artifact_created_unvalidated", "project": inspection,
              "artifacts": artifacts, "coverage": coverage}
    if mutate_report is not None:
        mutate_report(report)

    job = ws / ".runs" / "source-protection" / _synthetic_job_id()
    (job / "build").mkdir(parents=True)
    report_bytes = ca._create_json(job / "build" / "report.json", report)
    build_report_sha = ca._digest(report_bytes)

    snapshot = svc._snapshot(source, inspection)
    toolchain = svc._toolchain(inspection)
    plan = {"schema_version": 1, "plan_id": job.name, "kind": "native_source_build",
            "workspace_root": str(ws), "project_path": str(source), "seed": 1729,
            "inspection": inspection, "inputs": snapshot, "toolchain": toolchain,
            "blockers": [], "output_dir": str(job / "build")}
    if mutate_plan is not None:
        mutate_plan(plan)
    fingerprint = ca._digest(ca._encoded(plan))
    result = {"schema_version": 1, "status": "artifact_created_unvalidated",
              "backend": "dotnet_il_native", "plan_id": job.name,
              "fingerprint": fingerprint if recompute_fingerprint else "0" * 64,
              "build_report_sha256": build_report_sha, "artifacts": artifacts, "coverage": coverage,
              "external_attack_evaluation": "not_evaluated", "published": False}
    if mutate_result is not None:
        mutate_result(result)
    ca._create_json(job / "plan.json", plan)
    ca._create_json(job / "result.json", result)
    return SimpleNamespace(svc=svc, job=job, plan_id=job.name, pkg=pkg, source=source,
                           spec=pkg / "integration.json", contract=pkg / "application-contract.json",
                           inspection=inspection, fingerprint=fingerprint, artifacts=artifacts,
                           report_path=job / "build" / "report.json", report_sha=build_report_sha,
                           snapshot=snapshot)


def _fake_engine(report, *, raise_exc=None, during_run=None):
    """A boundary stand-in for the trusted engine (NOT real integration evidence)."""
    class _WP:
        @staticmethod
        def resolve(*, workspace_root, out_dir, stop_file, transform_module):
            Path(out_dir).mkdir(parents=True, exist_ok=True)
            return SimpleNamespace(out_dir=out_dir)

    def run_integration(producer, receipt, toolchain, workspace, app_dir, spec_path,
                        *, timeout_seconds, cases, trusted_inputs=None):
        if during_run is not None:
            during_run()
        try:
            (Path(workspace.out_dir) / "integration.json").write_text(
                json.dumps(report or {}), encoding="utf-8")
        except OSError:
            pass
        if raise_exc is not None:
            raise raise_exc
        return report

    return SimpleNamespace(
        WorkspacePlan=_WP,
        ProducerManifest=SimpleNamespace(at=staticmethod(lambda p: SimpleNamespace(path=str(p)))),
        ProtectedBuildReceipt=SimpleNamespace(reused_from_report=staticmethod(lambda p, **k: SimpleNamespace())),
        ToolchainSnapshot=SimpleNamespace(discover=staticmethod(lambda **k: SimpleNamespace())),
        TRUSTED_TRANSFORM_MODULE="antirea.csharp_transform",
        run_integration=run_integration)


# The reused native core's bytes hash to the producer's PROTECTED artifact pin --
# the "native core IS the reused protected build" invariant the verifier enforces.
_NATIVE_BYTES = b"MZ\x90\x00reused-native-core-fixture-0001"
_PROT_SHA = ca._digest(_NATIVE_BYTES)
_BASE_SHA = "ab" * 32


def _authentic_artifacts():
    return {"baseline": {"path": "baseline.bin", "sha256": _BASE_SHA},
            "protected": {"path": "protected.bin", "sha256": _PROT_SHA}}


# ---------------------------------------------------------------------------
# Shared synthetic raw child-evidence builder (NO real evidence; no child run).
# Writes confined per-case + control + preparation receipts/logs in the exact shape
# antirea.process.run_logged persists, so the service's independent child-evidence
# binding accepts an authentic run and refuses a forged one. Reused by the authentic
# boundary engine here and by the child-evidence suite.
# ---------------------------------------------------------------------------
def _clean_cleanup(pid):
    if os.name == "nt":
        return {"method": "windows_job", "job_assigned": True, "active_after": 0,
                "status": "assigned_job_empty", "job_handle_closed": True,
                "parent_exit_confirmed": True, "parent_pid": pid}
    return {"method": "posix_session", "status": "reaped", "parent_exit_confirmed": True, "parent_pid": pid}


def _case_obs(i, case):
    """Honest observation for case ``i`` that satisfies its own contract expect."""
    e = case.get("expect") or {}
    if case["kind"] == "exception":
        return {"rc": e.get("returncode", 134), "stdout": "", "exc": e.get("exception", "System.Exception")}
    rc = e.get("returncode", 0)
    if e.get("stdout_is_integer") is False:
        stdout = "usage: csharp-app <seed> <rounds>"      # non-integer (usage error value case)
    elif "stdout" in e:
        stdout = e["stdout"]
    else:
        stdout = str(1000 + i)
    return {"rc": rc, "stdout": stdout, "exc": None}


def _expectation_record(expect, obs):
    """Mirror antirea.csharp_app_integration._evaluate_expectation over ``obs``."""
    if expect is None:
        return None
    checks = {}
    if "returncode" in expect:
        checks["returncode"] = (obs["rc"] == expect["returncode"])
    if "exception" in expect:
        checks["exception"] = (obs["exc"] == expect["exception"])
    if "stdout" in expect:
        checks["stdout"] = (obs["stdout"] == expect["stdout"])
    if "stdout_is_integer" in expect:
        is_int = bool(re.fullmatch(r"-?\d+", obs["stdout"]))
        checks["stdout_is_integer"] = (is_int == expect["stdout_is_integer"])
    return {"expected": dict(expect), "checks": checks, "satisfied": all(checks.values())}


def _write_child(logs, label, argv, obs, *, pid=4242):
    """Persist one child's raw evidence (.stdout.log/.stderr.log/.process.json) as
    run_logged would, returning the inline comparison.commands entry that pins it."""
    stdout_log = logs / (label + ".stdout.log")
    stderr_log = logs / (label + ".stderr.log")
    receipt_path = logs / (label + ".process.json")
    stdout_log.write_text("" if obs["stdout"] == "" else obs["stdout"] + "\n", encoding="utf-8")
    stderr_log.write_text("" if obs["exc"] is None
                          else "Unhandled exception. " + obs["exc"] + ": synthetic\n   at Sample.Ops.Run()\n",
                          encoding="utf-8")
    cleanup = _clean_cleanup(pid)
    receipt = {"argv": argv, "returncode": obs["rc"], "pid": pid, "timed_out": False, "cancelled": False,
               "seconds": 0.11, "stdout": str(stdout_log), "stderr": str(stderr_log), "cleanup": cleanup}
    receipt_path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    return {"label": label, "argv": argv, "returncode": obs["rc"], "pid": pid, "timed_out": False,
            "cancelled": False, "seconds": 0.11, "cleanup": cleanup, "cleanup_status": cleanup["status"],
            "job_handle_closed": cleanup["job_handle_closed"], "parent_exit_confirmed": True,
            "clean_completion": True, "receipt_path": str(receipt_path),
            "stdout": str(stdout_log), "stderr": str(stderr_log)}


def _write_child_evidence(out, cases, *, original_dll, deployable_dll):
    """Write the full confined evidence tree under ``out/logs`` and return
    ``{commands, comparisons, route_proofs, control_index}`` with argv bound to the
    given assemblies (which the caller also reports as original/deployable_app.dll)."""
    logs = out / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    obs_list = [_case_obs(i, c) for i, c in enumerate(cases)]
    commands, comparisons = [], []
    for i, case in enumerate(cases):
        args = [str(a) for a in case["args"]]
        obs = obs_list[i]
        commands.append(_write_child(logs, "orig-%03d" % i, ["dotnet", "exec", original_dll, *args], obs))
        commands.append(_write_child(logs, "depl-%03d" % i, ["dotnet", "exec", deployable_dll, *args], obs))
        comparisons.append({"case": case["label"], "args": args, "kind": case["kind"],
                            "value_match": True, "returncode_match": True, "exception_match": True,
                            "match": True, "expectation": _expectation_record(case.get("expect"), obs),
                            "original": dict(obs), "protected": dict(obs)})
    ci = next(i for i, c in enumerate(cases)
              if c["kind"] == "value" and (c.get("expect") or {}).get("returncode") == 0)
    cargs = [str(a) for a in cases[ci]["args"]]
    commands.append(_write_child(logs, "route-control", ["dotnet", "exec", original_dll, *cargs],
                                 {"rc": 0, "stdout": obs_list[ci]["stdout"], "exc": None}))
    route_proofs = []
    for variant, token in (("missing-core", "System.DllNotFoundException"),
                           ("unset-core", "System.InvalidOperationException")):
        commands.append(_write_child(logs, "route-" + variant, ["dotnet", "exec", deployable_dll, *cargs],
                                     {"rc": 1, "stdout": "", "exc": token}))
        route_proofs.append({"variant": variant, "control_case": cases[ci]["label"], "control_args": cargs,
                             "control_rc": 0, "control_succeeded": True, "deployable_rc": 1, "deployable_exc": token,
                             "expected_exc": token, "failed_cleanly": True, "silent_fallback_detected": False,
                             "proves_native_required": True})
    for prep in ("csc-EnvProbe", "env-probe", "csc-original_app", "csc-deployable_app", "csc-Inspect",
                 "il-original", "il-deployable"):
        # env-probe's first two raw stdout lines are the genuine clean-env proof the
        # engine emits (sentinel <unset>, dotnet opt-out 1); other preps exit 0.
        stdout = "<unset>\n1" if prep == "env-probe" else "prep-ok"
        commands.append(_write_child(logs, prep, ["dotnet", "exec", prep], {"rc": 0, "stdout": stdout, "exc": None}))
    return {"commands": commands, "comparisons": comparisons, "route_proofs": route_proofs, "control_index": ci}


def _authentic_engine(h, *, dll_bytes=b"MZ\x90\x00managed-app-fixture",
                      rc_bytes=b'{"runtimeOptions":{"tfm":"net10.0"}}',
                      native_bytes=_NATIVE_BYTES, confine=True, break_rc_pin=False, tamper_plan=False,
                      during_run=None):
    """A boundary stand-in that returns a FULLY AUTHENTIC engine report.

    It writes the deployable artifacts confined under the engine out dir and binds
    producer/native/comparison fields to the producer this service bound, so the
    service's authenticity verifier accepts it. This is a mock -- never real
    integration evidence. Knobs introduce single realistic defects to prove the
    service fails closed (unconfined artifact, runtimeconfig pin mismatch, or an
    integration-plan tampered mid-run).
    """
    report_path, report_sha = str(h.report_path), h.report_sha

    def run_integration(producer, receipt, toolchain, workspace, app_dir, spec_path,
                        *, timeout_seconds, cases, trusted_inputs=None):
        out = Path(workspace.out_dir)
        app = (out if confine else out.parent) / "app"
        app.mkdir(parents=True, exist_ok=True)
        stg = out / "staging"
        stg.mkdir(parents=True, exist_ok=True)
        dll = app / "App.dll"
        dll.write_bytes(dll_bytes)
        rc = app / "App.runtimeconfig.json"
        rc.write_bytes(rc_bytes)
        core = stg / "core.dll"
        core.write_bytes(native_bytes)
        rc_sha = ca._digest(rc_bytes if not break_rc_pin else rc_bytes + b"drift")
        orig_dll = str(out / "original_app.dll")
        # Full confined per-case + control + prep raw evidence in the engine's shape,
        # so the service's independent child-evidence binding accepts an authentic run.
        ev = _write_child_evidence(out, cases, original_dll=orig_dll, deployable_dll=str(dll))
        value_cases = sum(1 for c in cases if c.get("kind", "value") == "value")
        report = {
            "status": "producer_bound_integration_passed", "fresh_protected_native_build": False,
            "producer": {"report_path": report_path, "report_sha256": report_sha,
                         "protected": {"sha256": _PROT_SHA}, "baseline": {"sha256": _BASE_SHA}},
            "staging": {"native_core": str(core), "native_core_sha256": ca._digest(native_bytes),
                        "native_library": "NativeCore"},
            "comparison": {"status": "producer_bound_integration_passed", "all_match": True,
                           "env_ok": True, "il_evidence_ok": True, "route_proof_ok": True,
                           "route_control_ok": True,
                           "integrity_verified_before_and_after": True, "expectations_ok": True,
                           "total_cases": len(cases), "value_cases": value_cases,
                           "exception_cases": len(cases) - value_cases, "framework": "net10.0",
                           "runtime_version": "10.0.0", "sdk_version": "10.0.201",
                           "original_app": {"dll": orig_dll, "sha256": ca._digest(b"orig"),
                                            "runtimeconfig": {"path": str(out / "original_app.runtimeconfig.json"),
                                                              "sha256": ca._digest(b"orc")}},
                           "deployable_app": {"dll": str(dll), "sha256": ca._digest(dll_bytes),
                                              "runtimeconfig": {"path": str(rc), "sha256": rc_sha}},
                           "comparisons": ev["comparisons"], "route_proofs": ev["route_proofs"],
                           "commands": ev["commands"]},
            "trusted_inputs_verification": {"verified": True, "declared_count": len(trusted_inputs or [])},
        }
        (out / "integration.json").write_text(json.dumps(report), encoding="utf-8")
        if tamper_plan:
            (out.parent / "integration-plan.json").write_text("tampered", encoding="utf-8")
        if during_run is not None:
            during_run()
        return report

    wp = SimpleNamespace(resolve=staticmethod(
        lambda **k: (Path(k["out_dir"]).mkdir(parents=True, exist_ok=True) or SimpleNamespace(out_dir=k["out_dir"]))))
    return SimpleNamespace(
        WorkspacePlan=wp,
        ProducerManifest=SimpleNamespace(at=staticmethod(lambda p: SimpleNamespace(path=str(p)))),
        ProtectedBuildReceipt=SimpleNamespace(reused_from_report=staticmethod(lambda p, **k: SimpleNamespace())),
        ToolchainSnapshot=SimpleNamespace(discover=staticmethod(lambda **k: SimpleNamespace())),
        TRUSTED_TRANSFORM_MODULE="antirea.csharp_transform", run_integration=run_integration)


class _TmpWs(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.ws = Path(self._td.name)


# ---------------------------------------------------------------------------
# OUTER bounded wrapper mechanics (runs now)
# ---------------------------------------------------------------------------

class OuterWrapperMechanicsTests(_WrapperAsserts):
    def test_real_defender_cli_runs_cleanly_through_outer_wrapper(self):
        proc, _, _ = _outer_run(_cli_argv("languages"), "mechanics-languages", timeout=120)
        self.assert_bounded_cleanup(proc)
        self.assertEqual(proc["returncode"], 0, proc)
        catalog = json.loads(Path(proc["stdout"]).read_text(encoding="utf-8"))
        self.assertIsInstance(catalog, (dict, list))

    def test_trivial_owned_child_is_bounded(self):
        proc, _, _ = _outer_run([sys.executable, "-I", "-B", "-c", "print('owned-ok')"],
                                "mechanics-trivial", timeout=60)
        self.assert_bounded_cleanup(proc)
        self.assertEqual(proc["returncode"], 0, proc)
        self.assertIn("owned-ok", Path(proc["stdout"]).read_text(encoding="utf-8"))

    def test_stop_marker_cancels_before_launch(self):
        out = _fresh_run_dir("mechanics-stop")
        priv_tmp = out / "_tmp"
        priv_home = out / "_home"
        priv_tmp.mkdir()
        priv_home.mkdir()
        private_stop = out / "STOP"  # PRIVATE marker; never the controller STOP
        private_stop.write_text("private-test-marker", encoding="utf-8")
        env = _allowlisted_env(priv_tmp, priv_home)
        proc = run_logged([sys.executable, "-I", "-B", "-c", "print('should-not-run')"],
                          ROOT, out / "logs" / "stop", timeout=30, env=env, cancel_file=private_stop)
        self.assertTrue(proc["cancelled"], proc)
        self.assertIsNone(proc["pid"], proc)
        self.assertFalse(proc["timed_out"], proc)
        self.assertTrue(Path(proc["stdout"]).is_file())


# ---------------------------------------------------------------------------
# Reserved/received path guards (runs now; synthetic strings only)
# ---------------------------------------------------------------------------

class ReservedGuardUnitTests(unittest.TestCase):
    def test_reserved_segments_refused_lexically_before_any_fs_access(self):
        for seg in ("rea-analysis-reports", "attackerfolder", "defense-loop",
                    "env.setting", "LINKREPRO", "linkrepro"):
            with self.subTest(seg=seg), self.assertRaises(CSharpApplicationError) as ctx:
                ca._reserved_guard("C:/synthetic/" + seg + "/thing.json")
            self.assertIn("reserved", str(ctx.exception).lower())

    def test_non_string_and_control_char_paths_refused(self):
        for bad in (None, 123, "", "has\nnewline", "tab\tchar"):
            with self.subTest(bad=repr(bad)), self.assertRaises(CSharpApplicationError):
                ca._reserved_guard(bad)

    def test_ordinary_owned_path_passes_guard(self):
        ca._reserved_guard("pkg/integration.json")  # no raise


class OwnedPathReservedTests(_TmpWs):
    def test_service_owned_rejects_received_and_output_segments(self):
        # Synthetic non-existent paths only -- no received/private data is read.
        svc = ProjectService(self.ws)
        for parts in (("rea-analysis-reports", "x.json"), ("attackerfolder", "y.json"),
                      (".runs", "defense-loop", "z.json"), (".runs", "source-protection", "w.json")):
            candidate = self.ws.joinpath(*parts)
            self.assertFalse(candidate.exists())
            with self.subTest(parts=parts), self.assertRaises(ValueError):
                svc._owned(candidate)


# ---------------------------------------------------------------------------
# Application-contract schema / case validation (runs now, no child)
# ---------------------------------------------------------------------------

class ContractValidationUnitTests(unittest.TestCase):
    def _valid(self):
        return {"schema_version": 1, "kind": ca.APPLICATION_CONTRACT_KIND,
                "cases": [{"label": "v", "kind": "value", "args": [1, "2"],
                           "expect": {"returncode": 0, "stdout_is_integer": True}}]}

    def test_valid_contract_returns_normalised_cases(self):
        cases = ca._validate_app_contract(self._valid())
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["label"], "v")

    def test_rejects_non_object_and_wrong_keys(self):
        for bad in ([], "x", 5, {"schema_version": 1, "kind": ca.APPLICATION_CONTRACT_KIND}):
            with self.subTest(bad=bad), self.assertRaises(CSharpApplicationError):
                ca._validate_app_contract(bad)

    def test_rejects_unsupported_extra_key(self):
        c = self._valid()
        c["unexpected"] = True
        with self.assertRaises(CSharpApplicationError):
            ca._validate_app_contract(c)

    def test_rejects_wrong_schema_version_and_kind(self):
        bad_v = self._valid(); bad_v["schema_version"] = 2
        bad_k = self._valid(); bad_k["kind"] = "something_else"
        for bad in (bad_v, bad_k):
            with self.subTest(bad=bad), self.assertRaises(CSharpApplicationError):
                ca._validate_app_contract(bad)

    def test_rejects_empty_and_oversized_case_lists(self):
        empty = self._valid(); empty["cases"] = []
        toomany = self._valid()
        toomany["cases"] = [{"label": "c%d" % i, "kind": "value", "args": []}
                            for i in range(ca.MAX_CASES + 1)]
        for bad in (empty, toomany):
            with self.subTest(n=len(bad["cases"])), self.assertRaises(CSharpApplicationError):
                ca._validate_app_contract(bad)

    def test_rejects_malformed_case_shapes(self):
        base = self._valid()
        mutations = [
            {"label": "", "kind": "value", "args": []},                         # empty label
            {"label": "a", "kind": "nope", "args": []},                          # bad kind
            {"label": "a", "kind": "value"},                                     # missing args
            {"label": "a", "kind": "value", "args": {}},                         # args not a list
            {"label": "a", "kind": "value", "args": [True]},                     # bool arg rejected
            {"label": "a", "kind": "value", "args": [1.5]},                      # float arg rejected
            {"label": "a", "kind": "value", "args": ["x" * (ca.MAX_ARG_LEN + 1)]},  # oversized arg
            {"label": "a", "kind": "value", "args": [], "extra": 1},             # unsupported key
        ]
        for m in mutations:
            c = dict(base); c["cases"] = [m]
            with self.subTest(case=m), self.assertRaises(CSharpApplicationError):
                ca._validate_app_contract(c)

    def test_rejects_duplicate_labels(self):
        c = self._valid()
        c["cases"] = [{"label": "dup", "kind": "value", "args": []},
                      {"label": "dup", "kind": "value", "args": []}]
        with self.assertRaises(CSharpApplicationError):
            ca._validate_app_contract(c)

    def test_rejects_embedded_nul_in_string_args(self):
        # Root-mandated preflight gate (sent to the service worker): a case string
        # argument carrying an embedded NUL must be refused BEFORE any engine/child,
        # so it can never reach a process argv. No child is launched here.
        for bad_arg in ("\x00", "a\x00b", "trailing\x00"):
            c = self._valid()
            c["cases"] = [{"label": "a", "kind": "value", "args": [bad_arg]}]
            with self.subTest(bad_arg=repr(bad_arg)), self.assertRaises(CSharpApplicationError):
                ca._validate_app_contract(c)

    def test_rejects_bad_expect_blocks(self):
        for expect, kind in (({"returncode": "0"}, "value"),            # non-int rc
                             ({"exception": "NotAToken"}, "exception"),  # bad token
                             ({"exception": "System.FooException"}, "value"),  # exception w/ value kind
                             ({"stdout_is_integer": "yes"}, "value"),    # non-bool
                             ({}, "value")):                             # empty expect object
            case = {"label": "a", "kind": kind, "args": [], "expect": expect}
            with self.subTest(expect=expect), self.assertRaises(CSharpApplicationError):
                ca._validate_app_contract({"schema_version": 1, "kind": ca.APPLICATION_CONTRACT_KIND,
                                           "cases": [case]})


# ---------------------------------------------------------------------------
# Guard-helper unit tests (runs now; synthetic inputs only)
# ---------------------------------------------------------------------------

class GuardHelperUnitTests(unittest.TestCase):
    def test_safe_direct_name_accepts_plain_file(self):
        self.assertEqual(ca._safe_direct_name("Ops.cs", "src"), "Ops.cs")

    def test_safe_direct_name_rejects_escapes(self):
        for bad in (r"C:\evil.cs", "a/b.cs", "a\\b.cs", "../x.cs", "..", ".",
                    "sub/x.cs", "env.setting", "has\x00nul", ""):
            with self.subTest(bad=repr(bad)), self.assertRaises(CSharpApplicationError):
                ca._safe_direct_name(bad, "src")

    def test_guarded_tree_preflight_rejects_reserved_descendant(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        (d / "ok.cs").write_text("x", encoding="utf-8")
        ca._guarded_tree_preflight(d)  # clean tree: no raise
        (d / "LINKREPRO").mkdir()
        (d / "LINKREPRO" / "x.bin").write_text("y", encoding="utf-8")
        with self.assertRaises(CSharpApplicationError):
            ca._guarded_tree_preflight(d)

    def test_guard_saved_plan_paths_rejects_reserved(self):
        ca._guard_saved_plan_paths({"inputs": [{"path": "C:/x/ok.cs", "sha256": "0" * 64}]})  # ok
        with self.assertRaises(CSharpApplicationError):
            ca._guard_saved_plan_paths({"inputs": [{"path": "C:/x/env.setting/p.cs"}]})
        with self.assertRaises(CSharpApplicationError):
            ca._guard_saved_plan_paths(
                {"inputs": [], "inspection": {"compiler_inputs": {"C:/x/attackerfolder/t.exe": "0" * 64}}})

    def test_guard_saved_plan_paths_rejects_reserved_toolchain_tool_path(self):
        # A saved plan whose toolchain tool paths hit a reserved segment is refused
        # lexically before generic tool discovery would follow them.
        with self.assertRaises(CSharpApplicationError):
            ca._guard_saved_plan_paths(
                {"inputs": [], "toolchain": {"tools": {"clang": {"path": "C:/x/LINKREPRO/clang.exe"}}}})

    def test_guarded_tree_preflight_bound_is_enforced_incrementally(self):
        # Residual 1: the streaming scandir walk enforces the entry budget per entry.
        # Patch the module bound to a small value so a modest fixture trips it.
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        for i in range(4):
            (d / ("f%d.cs" % i)).write_text("x", encoding="utf-8")
        with mock.patch.object(ca, "MAX_PREFLIGHT_ENTRIES", 2):
            with self.assertRaises(CSharpApplicationError) as ctx:
                ca._guarded_tree_preflight(d)
        self.assertIn("bounded preflight entry limit", str(ctx.exception))


class ChildIssueClassifierUnitTests(unittest.TestCase):
    def test_expected_nonzero_commands_are_not_infrastructure_failures(self):
        # A nonzero returncode that is an expected exception/control outcome is NOT
        # an infrastructure failure (the comparison + route proofs account for it).
        report = {"comparison": {"status": "producer_bound_integration_passed",
                                 "all_match": True, "env_ok": True, "il_evidence_ok": True,
                                 "route_proof_ok": True, "integrity_verified_before_and_after": True,
                                 "expectations_ok": True,
                                 "commands": [{"label": "usage", "returncode": 2, "timed_out": False,
                                               "cancelled": False, "cleanup_status": "assigned_job_empty",
                                               "job_handle_closed": True}]}}
        issues = ca._classify_child_issues(report)
        self.assertEqual(issues["child_infrastructure_failures"], [])
        self.assertEqual(issues["child_cancellations"], [])
        self.assertIs(issues["comparison_mismatch"], False)

    def test_timeout_and_cancel_are_infrastructure_failures(self):
        report = {"comparison": {"status": "producer_bound_integration_passed",
                                 "all_match": True, "env_ok": True, "il_evidence_ok": True,
                                 "route_proof_ok": True, "integrity_verified_before_and_after": True,
                                 "expectations_ok": True,
                                 "commands": [{"label": "slow", "timed_out": True},
                                              {"label": "stopped", "cancelled": True}]}}
        issues = ca._classify_child_issues(report)
        self.assertEqual(len(issues["child_infrastructure_failures"]), 2)
        self.assertEqual(issues["child_cancellations"], ["stopped"])

    def test_comparison_mismatch_flagged(self):
        report = {"comparison": {"status": "failed", "commands": []}}
        self.assertIs(ca._classify_child_issues(report)["comparison_mismatch"], True)


# ---------------------------------------------------------------------------
# Fixed-toolchain-config pre-read guard (runs now; synthetic config bytes only)
# ---------------------------------------------------------------------------

class PreflightToolchainConfigUnitTests(unittest.TestCase):
    def _service_with_config(self, config_obj):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / ".tools").mkdir()
        cfg = root / ".tools" / "kagura-toolchain.json"
        cfg.write_text(json.dumps(config_obj), encoding="utf-8")
        raw = cfg.read_bytes()
        return SimpleNamespace(root=root), cfg, ca._digest(raw)

    def test_matching_config_with_clean_fields_passes(self):
        svc, _, sha = self._service_with_config({"clang": "C:/tools/llvm/bin/clang.exe"})
        ca._preflight_toolchain_config(svc, {"status": "present", "sha256": sha},
                                       {"language": "csharp"})  # no raise

    def test_changed_config_rejected_before_following_paths(self):
        svc, _, _ = self._service_with_config({"clang": "C:/tools/llvm/bin/clang.exe"})
        with self.assertRaises(CSharpApplicationError) as ctx:
            ca._preflight_toolchain_config(svc, {"status": "present", "sha256": "0" * 64},
                                           {"language": "csharp"})
        self.assertIn("changed since planning", str(ctx.exception))

    def test_reserved_config_path_field_rejected(self):
        svc, _, sha = self._service_with_config({"clang": "C:/x/env.setting/clang.exe"})
        with self.assertRaises(CSharpApplicationError) as ctx:
            ca._preflight_toolchain_config(svc, {"status": "present", "sha256": sha},
                                           {"language": "csharp"})
        self.assertIn("reserved", str(ctx.exception).lower())

    def test_missing_planned_config_rejected(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)  # no .tools/kagura-toolchain.json
        with self.assertRaises(CSharpApplicationError):
            ca._preflight_toolchain_config(SimpleNamespace(root=root),
                                           {"status": "present", "sha256": "ab" * 32},
                                           {"language": "csharp"})

    def test_non_native_route_needs_no_config(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        ca._preflight_toolchain_config(SimpleNamespace(root=root),
                                       {"status": "missing", "sha256": None},
                                       {"language": "python"})  # no raise


# ---------------------------------------------------------------------------
# Genuinely bounded artifact reads (runs now)
# ---------------------------------------------------------------------------

class BoundedReadUnitTests(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.d = Path(self._td.name)

    def test_read_rejects_oversize_with_limit_plus_one(self):
        f = self.d / "big.bin"
        f.write_bytes(b"x" * 11)
        with self.assertRaises(Exception):  # ProtectorError(ValueError)
            ca._read(f, 10)
        self.assertEqual(ca._read(f, 11), b"x" * 11)  # exactly at the limit is fine

    def test_bounded_source_rejects_grown_file_via_bounded_read(self):
        engine_out = self.d / "engine"
        engine_out.mkdir()
        f = engine_out / "art.dll"
        f.write_bytes(b"y" * 9)
        with mock.patch.object(ca, "MAX_BUNDLE_FILE_BYTES", 8):
            with self.assertRaises(CSharpApplicationError) as ctx:
                ca._bounded_source(f, engine_out, "artifact")
        self.assertIn("not a bounded regular file", str(ctx.exception))

    def test_bounded_source_rejects_unconfined_and_reserved(self):
        engine_out = self.d / "engine"
        engine_out.mkdir()
        outside = self.d / "outside.dll"
        outside.write_bytes(b"z")
        with self.assertRaises(CSharpApplicationError):
            ca._bounded_source(outside, engine_out, "artifact")  # not confined
        with self.assertRaises(CSharpApplicationError):
            ca._bounded_source(self.d / "env.setting" / "x.dll", engine_out, "artifact")  # reserved

    def test_bounded_source_delegates_to_actual_bounded_reader(self):
        # A stat-only limit would pass the old oversize test too. Require the
        # bounded reader itself; no file content or stat is needed in this probe.
        engine_out = self.d / "engine"
        path = engine_out / "artifact.dll"
        with mock.patch.object(ca, "_read", return_value=b"bounded") as reader:
            self.assertEqual(ca._bounded_source(path, engine_out, "artifact"), b"bounded")
        reader.assert_called_once_with(path, ca.MAX_BUNDLE_FILE_BYTES)


# ---------------------------------------------------------------------------
# Final residual integrate-level coverage (boundary-mocked engine)
# ---------------------------------------------------------------------------

class IntegrateFinalResidualTests(_TmpWs):
    def _run(self, h, engine):
        with mock.patch.object(ca, "_load_engine", lambda: engine):
            return h.svc.integrate(h.plan_id, str(h.spec), str(h.contract), timeout_seconds=90)

    def _result_record(self, h):
        integ = next(p for p in h.job.iterdir() if p.name.startswith("integration-"))
        return json.loads((integ / "integration-result.json").read_text(encoding="utf-8"))

    def test_post_execution_reserved_descendant_rejected(self):
        # Residual 2: a child that plants a reserved descendant in the project tree
        # during execution is refused by the post-execution guarded preflight.
        h = _build_producer(self.ws, artifacts=_authentic_artifacts())

        def plant():
            (h.pkg / "env.setting").write_text("synthetic reserved marker", encoding="utf-8")
        res = self._run(h, _authentic_engine(h, during_run=plant))
        self.assertEqual(res["status"], "failed", res)
        self.assertIsNone(res["deployment_bundle"])

    def test_base_source_pin_tampered_during_run_fails_closed(self):
        # Residual 4: a change to a base source pin (here the saved source result)
        # must drop an otherwise-authentic pass to failed, with append-only evidence.
        h = _build_producer(self.ws, artifacts=_authentic_artifacts())

        def tamper():
            (h.job / "result.json").write_text("{\"tampered\":true}\n", encoding="utf-8")
        res = self._run(h, _authentic_engine(h, during_run=tamper))
        self.assertEqual(res["status"], "failed", res)
        self.assertIsNone(res["deployment_bundle"])
        self.assertEqual(self._result_record(h)["status"], "failed")

    def test_success_path_runs_and_passes_every_post_package_recheck(self):
        # Residual 4/5: the clean pass genuinely performs all post-package rechecks.
        h = _build_producer(self.ws, artifacts=_authentic_artifacts())
        res = self._run(h, _authentic_engine(h))
        self.assertEqual(res["status"], _SUCCESS_STATUS, res)
        rec = self._result_record(h)
        self.assertEqual(rec["post_package_recheck"], {
            "stop_absent": True, "plan_unchanged": True, "build_report_unchanged": True,
            "base_pins_unchanged": True, "snapshot_unchanged": True, "toolchain_unchanged": True,
            "engine_report_unchanged": True})

    def test_early_stop_returns_cancelled_without_bundle(self):
        # Residual 5: STOP present before execution -> cancelled, no integration id,
        # no bundle. Uses a PRIVATE workspace STOP, never the real controller STOP.
        h = _build_producer(self.ws, artifacts=_authentic_artifacts())
        stop = h.svc.root / ".runs" / "defense-loop" / "STOP"
        stop.parent.mkdir(parents=True, exist_ok=True)
        stop.write_text("private-test-marker", encoding="utf-8")
        res = self._run(h, _authentic_engine(h))
        self.assertEqual(res["status"], "cancelled", res)
        self.assertIsNone(res["integration_id"])
        self.assertIsNone(res.get("deployment_bundle"))

    def test_late_stop_during_run_yields_cancelled_without_bundle(self):
        # Residual 5: a STOP appearing during execution forces cancelled status and
        # clears any deployment bundle (a nominal bundle must never be returned).
        h = _build_producer(self.ws, artifacts=_authentic_artifacts())

        def drop_stop():
            stop = h.svc.root / ".runs" / "defense-loop" / "STOP"
            stop.parent.mkdir(parents=True, exist_ok=True)
            stop.write_text("private-test-marker", encoding="utf-8")
        res = self._run(h, _authentic_engine(h, during_run=drop_stop))
        self.assertEqual(res["status"], "cancelled", res)
        self.assertIsNone(res["deployment_bundle"])

    def test_result_tamper_after_packaging_rejects_bundle(self):
        h = _build_producer(self.ws, artifacts=_authentic_artifacts())
        package = ca._package_bundle

        def after_copy(*args, **kwargs):
            bundle = package(*args, **kwargs)
            (h.job / "result.json").write_text('{"changed_after_copy":true}\n', encoding="utf-8")
            return bundle

        with mock.patch.object(ca, "_package_bundle", side_effect=after_copy) as copying:
            res = self._run(h, _authentic_engine(h))
        copying.assert_called_once()
        self.assertEqual(res["status"], "failed", res)
        self.assertIsNone(res["deployment_bundle"])
        rec = self._result_record(h)
        self.assertEqual(rec["status"], "failed")
        self.assertFalse(rec["post_package_recheck"]["base_pins_unchanged"])
        self.assertTrue((Path(rec["integration_plan_path"])).is_file())

    def test_stop_after_successful_post_package_checks_clears_all_delivery_fields(self):
        h = _build_producer(self.ws, artifacts=_authentic_artifacts())
        launch = ca._launch_instructions

        def stop_after_checks(*args, **kwargs):
            result = launch(*args, **kwargs)
            stop = h.svc.root / ".runs" / "defense-loop" / "STOP"
            stop.parent.mkdir(parents=True, exist_ok=True)
            stop.write_text("private final-status test", encoding="utf-8")
            return result

        with mock.patch.object(ca, "_launch_instructions", side_effect=stop_after_checks) as launching:
            res = self._run(h, _authentic_engine(h))
        launching.assert_called_once()
        rec = self._result_record(h)
        self.assertTrue(all(rec["post_package_recheck"].values()))
        for row in (res, rec):
            self.assertEqual(row["status"], "cancelled")
            for key in ("deployment_bundle", "managed_runtime_requirements", "launch_instructions"):
                self.assertIsNone(row[key], key)

    def _assert_recompute_guard_order(self, rejected_call):
        h = _build_producer(self.ws, artifacts=_authentic_artifacts())
        guard, calls = ca._guarded_preflight, []

        def reject_before_recompute(*args, **kwargs):
            calls.append(len(calls) + 1)
            if len(calls) == rejected_call:
                raise CSharpApplicationError("synthetic guard rejection before generic recomputation")
            return guard(*args, **kwargs)

        with mock.patch.object(ca, "_guarded_preflight", side_effect=reject_before_recompute), \
                mock.patch.object(h.svc, "_snapshot", wraps=h.svc._snapshot) as snapshot, \
                mock.patch.object(h.svc, "_toolchain", wraps=h.svc._toolchain) as toolchain:
            res = self._run(h, _authentic_engine(h))
        self.assertEqual(len(calls), rejected_call)
        self.assertEqual(snapshot.call_count, rejected_call - 1)
        self.assertEqual(toolchain.call_count, rejected_call - 1)
        self.assertEqual(res["status"], "failed", res)
        self.assertIsNone(res["deployment_bundle"])
        self.assertEqual(self._result_record(h)["status"], "failed")

    def test_post_execution_guard_precedes_generic_recomputation(self):
        self._assert_recompute_guard_order(2)

    def test_post_package_guard_precedes_generic_recomputation(self):
        self._assert_recompute_guard_order(3)

    def test_spec_bytes_drift_after_snapshot_rejected_before_engine(self):
        # Residual 6: freshly read spec bytes must equal the original snapshot pin,
        # even if the snapshot step is made to pass (mocked stale) -- isolating the
        # post-snapshot/pre-engine re-read. No engine is invoked.
        h = _build_producer(self.ws, artifacts=_authentic_artifacts())
        engine = _authentic_engine(h)
        with mock.patch.object(h.svc, "_snapshot", return_value=h.snapshot), \
                mock.patch.object(ca, "_load_engine", return_value=engine) as load_engine:
            h.spec.write_text(json.dumps({"schema_version": 1, "sources": ["Ops.cs"],
                                          "methods": [], "native_library": "NativeCore",
                                          "drifted": True}) + "\n", encoding="utf-8")
            with self.assertRaises(CSharpApplicationError) as ctx:
                h.svc.integrate(h.plan_id, str(h.spec), str(h.contract), timeout_seconds=90)
        self.assertIn("integration spec bytes differ from the original plan snapshot pin", str(ctx.exception))
        load_engine.assert_not_called()

    def test_contract_bytes_drift_after_snapshot_rejected_before_engine(self):
        h = _build_producer(self.ws, artifacts=_authentic_artifacts())
        engine = _authentic_engine(h)
        with mock.patch.object(h.svc, "_snapshot", return_value=h.snapshot), \
                mock.patch.object(ca, "_load_engine", return_value=engine) as load_engine:
            h.contract.write_text(json.dumps({"schema_version": 1, "kind": "csharp_application_samples",
                                               "cases": [{"label": "v", "kind": "value", "args": []}],
                                               "drifted": True}) + "\n", encoding="utf-8")
            with self.assertRaises(CSharpApplicationError) as ctx:
                h.svc.integrate(h.plan_id, str(h.spec), str(h.contract), timeout_seconds=90)
        self.assertIn("application contract bytes differ from the original plan snapshot pin", str(ctx.exception))
        load_engine.assert_not_called()


# ---------------------------------------------------------------------------
# Public integrate route: binding / snapshot / toolchain / spec boundary matrix
# ---------------------------------------------------------------------------

class IntegrateBindingMatrixTests(_TmpWs):
    def _expect(self, h, substr, *, spec=None, contract=None, timeout=120):
        spec = spec if spec is not None else str(h.spec)
        contract = contract if contract is not None else str(h.contract)
        with self.assertRaises(CSharpApplicationError) as ctx:
            h.svc.integrate(h.plan_id, spec, contract, timeout_seconds=timeout)
        self.assertIn(substr, str(ctx.exception))

    def test_timeout_rejected_before_anything(self):
        h = _build_producer(self.ws)
        for bad in (0, 601, -1):
            with self.subTest(t=bad):
                self._expect(h, "timeout_seconds must be an integer", timeout=bad)
        for bad in (1.5, True, "120"):
            with self.subTest(t=bad), self.assertRaises(CSharpApplicationError):
                h.svc.integrate(h.plan_id, str(h.spec), str(h.contract), timeout_seconds=bad)

    def test_invalid_plan_id_rejected(self):
        svc = ProjectService(self.ws)
        with self.assertRaises(ValueError):
            svc.integrate("not a valid plan id", "a.json", "b.json")

    def test_missing_plan_rejected(self):
        svc = ProjectService(self.ws)
        with self.assertRaises(ValueError):
            svc.integrate("source-20991231T235959Z-0123456789ab", "a.json", "b.json")

    def test_unbuilt_result_rejected(self):
        h = _build_producer(self.ws, mutate_result=lambda r: r.update(status="artifact_created_unvalidated_NOT"))
        self._expect(h, "no successful artifact to integrate")

    def test_unsupported_backend_rejected(self):
        h = _build_producer(self.ws, mutate_result=lambda r: r.update(backend="unsupported_native_backend"))
        self._expect(h, "supports only csharp/dotnet_il_native")

    def test_direct_csharp_service_rejects_go_and_swift_backends(self):
        for backend in ("go_typed_native", "swift_llvm_native"):
            with self.subTest(backend=backend):
                lane = self.ws / backend
                lane.mkdir()
                h = _build_producer(lane, mutate_result=lambda r: r.update(backend=backend))
                with mock.patch.object(ca, "_load_engine") as load_engine:
                    with self.assertRaisesRegex(CSharpApplicationError, "supports only csharp/dotnet_il_native"):
                        ca.integrate_source_application(
                            h.svc, h.plan_id, str(h.spec), str(h.contract), timeout_seconds=120)
                    load_engine.assert_not_called()

    def test_public_native_dispatch_rejects_mislabeled_csharp_producer(self):
        from antirea import native_application as na
        for backend in ("go_typed_native", "swift_llvm_native"):
            with self.subTest(backend=backend):
                lane = self.ws / backend
                lane.mkdir()
                h = _build_producer(lane, mutate_result=lambda r: r.update(backend=backend))
                with mock.patch.object(na, "_load_engine") as load_engine:
                    with self.assertRaisesRegex(
                            na.NativeApplicationError, "build report is not a successful native artifact"):
                        h.svc.integrate(h.plan_id, str(h.spec), str(h.contract), timeout_seconds=120)
                    load_engine.assert_not_called()

    def test_fingerprint_mismatch_rejected(self):
        h = _build_producer(self.ws, recompute_fingerprint=False)
        self._expect(h, "does not bind this csharp build result")

    def test_plan_id_mismatch_rejected(self):
        h = _build_producer(self.ws, mutate_plan=lambda p: p.update(plan_id="source-20261020T010203Z-ffffffffffff"))
        self._expect(h, "does not bind this csharp build result")

    def test_workspace_mismatch_rejected(self):
        h = _build_producer(self.ws, mutate_plan=lambda p: p.update(workspace_root="C:/elsewhere"))
        self._expect(h, "does not bind this csharp build result")

    def test_kind_mismatch_rejected(self):
        h = _build_producer(self.ws, mutate_plan=lambda p: p.update(kind="python_source_build"))
        self._expect(h, "does not bind this csharp build result")

    def test_build_report_sha_mismatch_rejected(self):
        h = _build_producer(self.ws, mutate_result=lambda r: r.update(build_report_sha256="0" * 64))
        self._expect(h, "refusing silent repinning")

    def test_repinning_artifacts_mismatch_rejected(self):
        # report.artifacts differs from result.artifacts, but the report sha is kept
        # self-consistent, so the repinning guard (not the sha guard) must fire.
        h = _build_producer(self.ws, mutate_report=lambda rep: rep.update(
            artifacts={"baseline": {"path": "x", "sha256": "11" * 32},
                       "protected": {"path": "y", "sha256": "22" * 32}}))
        self._expect(h, "refusing silent repinning")

    def test_report_not_success_rejected(self):
        h = _build_producer(self.ws, mutate_report=lambda rep: rep.update(backend="jvm_bytecode_native"))
        self._expect(h, "not a successful csharp native artifact")

    def test_inspection_project_mismatch_rejected(self):
        # plan.inspection != report.project (report.project replaced wholesale).
        h = _build_producer(self.ws, mutate_report=lambda rep: rep.update(
            project={"language": "csharp", "name": "Other", "project_path": "C:/nope/project.json",
                     "backend": "dotnet_il_native", "exports": []}))
        self._expect(h, "inspection does not match the build report project metadata")

    def test_missing_baseline_protected_rejected(self):
        only_base = {"baseline": {"path": "b", "sha256": "ab" * 32}}

        def mut(obj):
            obj["artifacts"] = {"baseline": {"path": "b", "sha256": "ab" * 32}}
        h = _build_producer(self.ws, mutate_report=mut, mutate_result=mut)
        self._expect(h, "missing baseline/protected artifacts")

    def test_report_project_path_mismatch_rejected(self):
        # plan.inspection == report.project (same mutated dict) but its project_path
        # disagrees with the resolved source, isolating the project-path guard.
        def mut(rep):
            rep["project"]["project_path"] = "C:/wrong/project.json"
        h = _build_producer(self.ws, mutate_report=mut)
        self._expect(h, "build report project path does not match")

    def test_snapshot_added_input_rejected(self):
        h = _build_producer(self.ws)
        (h.pkg / "added_after_plan.cs").write_text("// added", encoding="utf-8")
        self._expect(h, "source tree changed before integration")

    def test_snapshot_removed_input_rejected(self):
        h = _build_producer(self.ws)
        (h.pkg / "Ops.cs").unlink()
        self._expect(h, "source tree changed before integration")

    def test_toolchain_drift_rejected(self):
        h = _build_producer(self.ws, mutate_plan=lambda p: p.__setitem__(
            "toolchain", {"status": "present", "tampered": True}))
        self._expect(h, "source toolchain changed before integration")

    def test_spec_outside_project_dir_rejected(self):
        h = _build_producer(self.ws)
        self._expect(h, "must live directly in the planned project directory",
                     spec=str(self.ws / "integration.json"))

    def test_contract_missing_file_rejected(self):
        h = _build_producer(self.ws)
        self._expect(h, "must be an existing regular file",
                     contract=str(h.pkg / "does-not-exist.json"))

    def test_reserved_spec_path_rejected_before_reads(self):
        h = _build_producer(self.ws)
        self._expect(h, "reserved/excluded path segment",
                     spec=str(self.ws / "env.setting" / "integration.json"))

    def test_spec_and_contract_must_differ(self):
        h = _build_producer(self.ws)
        self._expect(h, "must be distinct files", contract=str(h.spec))

    def test_malformed_spec_schema_rejected(self):
        h = _build_producer(self.ws, spec_obj={"schema_version": 1, "sources": ["Ops.cs"]})  # no methods/native_library
        self._expect(h, "integration spec must be schema_version 1")

    def test_wrong_contract_kind_rejected_through_route(self):
        bad = {"schema_version": 1, "kind": "not_the_right_kind",
               "cases": [{"label": "v", "kind": "value", "args": []}]}
        h = _build_producer(self.ws, contract_obj=bad)
        self._expect(h, "kind must be")

    def test_spec_source_absolute_or_traversal_rejected(self):
        # A valid-schema spec whose source names escape the project directory must
        # be refused before any stat/read of the escaping path.
        valid_spec = json.loads((SAMPLE_CSHARP_APP / "integration.json").read_text(encoding="utf-8"))
        for bad_name in (r"C:\evil.cs", "../evil.cs", "sub/evil.cs", ".."):
            sub_ws = Path(tempfile.mkdtemp())
            self.addCleanup(shutil.rmtree, sub_ws, True)
            spec = dict(valid_spec)
            spec["sources"] = [bad_name]
            h = _build_producer(sub_ws, spec_obj=spec)
            with self.subTest(bad_name=bad_name):
                self._expect(h, "integration spec source")

    def test_spec_source_not_in_snapshot_rejected(self):
        # A safe direct name that is not a pinned snapshot member is refused.
        valid_spec = json.loads((SAMPLE_CSHARP_APP / "integration.json").read_text(encoding="utf-8"))
        spec = dict(valid_spec)
        spec["sources"] = ["NotPinned.cs"]
        h = _build_producer(self.ws, spec_obj=spec)
        self._expect(h, "not part of the fingerprinted plan snapshot")

    def test_reserved_descendant_in_project_tree_rejected(self):
        # A reserved-named descendant appearing in the planned project directory is
        # refused by the bounded preflight BEFORE the generic snapshot walk reads it.
        h = _build_producer(self.ws)
        (h.pkg / "env.setting").write_text("synthetic reserved marker", encoding="utf-8")
        self._expect(h, "reserved/excluded descendant is not allowed")

    def test_saved_plan_reserved_input_path_rejected(self):
        # A malformed saved plan whose recorded inputs reference a reserved path is
        # refused lexically before the service recomputation touches the disk.
        reserved = str(self.ws / "env.setting" / "planted.cs")

        def mut(plan):
            plan["inputs"] = list(plan["inputs"]) + [{"path": reserved, "sha256": "0" * 64, "bytes": 1}]
        h = _build_producer(self.ws, mutate_plan=mut)
        self._expect(h, "reserved/excluded path segment")


# ---------------------------------------------------------------------------
# Public integrate route: engine execution phase (boundary-mocked engine)
# ---------------------------------------------------------------------------

class IntegrateEngineBoundaryTests(_TmpWs):
    def _run(self, h, fake):
        with mock.patch.object(ca, "_load_engine", lambda: fake):
            return h.svc.integrate(h.plan_id, str(h.spec), str(h.contract), timeout_seconds=90)

    def _read_result_record(self, h):
        integ = next(p for p in h.job.iterdir() if p.name.startswith("integration-"))
        rec = json.loads((integ / "integration-result.json").read_text(encoding="utf-8"))
        return integ, rec

    def test_failed_engine_status_yields_failed_no_bundle(self):
        h = _build_producer(self.ws)
        res = self._run(h, _fake_engine({"status": "producer_bound_integration_failed",
                                         "fresh_protected_native_build": False}))
        self.assertEqual(res["status"], "failed", res)
        self.assertIsNone(res["deployment_bundle"])
        integ, rec = self._read_result_record(h)
        self.assertEqual(rec["status"], "failed")
        self.assertIsNone(rec["deployment_bundle"])
        # Append-only: a second write to the same result file must be refused.
        with self.assertRaises(FileExistsError):
            ca._create_json(integ / "integration-result.json", {"x": 1})

    def test_engine_exception_captured_as_failed(self):
        h = _build_producer(self.ws)
        res = self._run(h, _fake_engine({"status": "x"}, raise_exc=RuntimeError("engine blew up")))
        self.assertEqual(res["status"], "failed", res)
        self.assertIsNone(res["deployment_bundle"])
        _, rec = self._read_result_record(h)
        self.assertIn("engine blew up", rec["execution_error"])

    def test_engine_claiming_fresh_native_is_not_accepted(self):
        # Even with a 'passed' engine status, a fresh_protected_native_build=True
        # claim must NOT be accepted (reused native is never relabelled fresh).
        h = _build_producer(self.ws)
        res = self._run(h, _fake_engine({"status": "producer_bound_integration_passed",
                                         "fresh_protected_native_build": True}))
        self.assertNotEqual(res["status"], _SUCCESS_STATUS, res)
        self.assertIsNone(res["deployment_bundle"])

    def test_post_execution_source_drift_fails_closed(self):
        h = _build_producer(self.ws)
        passed_report = {"status": "producer_bound_integration_passed",
                         "fresh_protected_native_build": False,
                         "comparison": {}, "staging": {}}

        def drift():
            (h.pkg / "sneaked_in.cs").write_text("// drift during execution", encoding="utf-8")
        res = self._run(h, _fake_engine(passed_report, during_run=drift))
        self.assertEqual(res["status"], "failed", res)
        self.assertIs(res["original_inputs_unchanged"], False)
        self.assertIsNone(res["deployment_bundle"])

    def test_engine_passed_status_but_inauthentic_report_rejected(self):
        # A 'passed' engine status with a report that does NOT genuinely bind the
        # producer/native/comparison (finding 4) must NOT yield success or a bundle.
        h = _build_producer(self.ws)
        res = self._run(h, _fake_engine({"status": "producer_bound_integration_passed",
                                         "fresh_protected_native_build": False,
                                         "comparison": {}, "staging": {}}))
        self.assertEqual(res["status"], "failed", res)
        self.assertIs(res["engine_report_authentic"], False, res)
        self.assertIsNone(res["deployment_bundle"])

    def test_clean_authentic_pass_produces_compact_bundle_and_reused_flag(self):
        h = _build_producer(self.ws, artifacts=_authentic_artifacts())
        res = self._run(h, _authentic_engine(h))
        self.assertEqual(res["status"], _SUCCESS_STATUS, res)
        self.assertIs(res["engine_report_authentic"], True, res)
        self.assertEqual(res["plan_id"], h.plan_id)
        self.assertTrue(res["integration_id"].startswith("integration-"))
        self.assertIs(res["reused_native_core"], True)
        self.assertIs(res["fresh_protected_native_build"], False)
        self.assertIs(res["original_inputs_unchanged"], True)
        bundle = res["deployment_bundle"]
        self.assertEqual(set(f["relative_path"] for f in bundle["files"]),
                         {"CsharpApp.dll", "CsharpApp.runtimeconfig.json", "NativeCore.dll"})
        for entry in bundle["files"]:
            self.assertEqual(set(entry) >= {"relative_path", "sha256", "bytes"}, True, entry)
        # Bundle holds EXACTLY the three allowlisted files -- no source/IR leaks.
        present = sorted(p.name for p in Path(bundle["path"]).iterdir())
        self.assertEqual(present, ["CsharpApp.dll", "CsharpApp.runtimeconfig.json", "NativeCore.dll"])
        # Reused native core is copied byte-for-byte to the producer's protected pin.
        native_entry = next(f for f in bundle["files"] if f["relative_path"] == "NativeCore.dll")
        self.assertEqual(native_entry["sha256"], _PROT_SHA)

    def test_integration_plan_tampered_mid_run_fails_closed(self):
        # The saved integration-plan.json is re-pinned after the engine runs; a
        # mid-run tamper must drop an otherwise-authentic pass to failed.
        h = _build_producer(self.ws, artifacts=_authentic_artifacts())
        res = self._run(h, _authentic_engine(h, tamper_plan=True))
        self.assertEqual(res["status"], "failed", res)
        self.assertIsNone(res["deployment_bundle"])

    def test_bundle_runtimeconfig_pin_mismatch_fails_closed(self):
        # Authentic report, but the runtimeconfig file bytes disagree with the
        # engine's pin -> _package_bundle refuses; no success, no bundle.
        h = _build_producer(self.ws, artifacts=_authentic_artifacts())
        res = self._run(h, _authentic_engine(h, break_rc_pin=True))
        self.assertEqual(res["status"], "failed", res)
        self.assertIsNone(res["deployment_bundle"])

    def test_bundle_unconfined_artifact_fails_closed(self):
        # Authentic report, but a deployable artifact lies OUTSIDE the engine out
        # dir -> bundle source confinement refuses it; no success, no bundle.
        h = _build_producer(self.ws, artifacts=_authentic_artifacts())
        res = self._run(h, _authentic_engine(h, confine=False))
        self.assertEqual(res["status"], "failed", res)
        self.assertIsNone(res["deployment_bundle"])


# ---------------------------------------------------------------------------
# Optional installed-toolchain native E2E (opt-in; root owns the authoritative run)
# ---------------------------------------------------------------------------

@_requires_e2e
class IntegrateInstalledToolchainTests(_WrapperAsserts):
    @classmethod
    def setUpClass(cls):
        cls._td = tempfile.TemporaryDirectory()
        cls.ws = Path(cls._td.name)
        cls.pkg = cls.ws / "pkg"
        _copy_tree_into(SAMPLE_CSHARP_APP, cls.pkg)
        cls.config = cls.ws / "protectors.local.json"
        cls.config.write_text(json.dumps(
            {"schema_version": 1, "workspace_root": str(cls.ws), "providers": {}}) + "\n",
            encoding="utf-8")
        # Provision the defender's own native toolchain manifest into this private
        # workspace. Its tool paths are absolute (the real repo .tools), so the
        # source-build resolves the installed clang/LLVM/Kagura runtime while all
        # produced artifacts stay inside this private ws. Skip if unavailable.
        repo_manifest = ROOT / ".tools" / "kagura-toolchain.json"
        if not repo_manifest.is_file():
            raise unittest.SkipTest("native kagura-toolchain.json is not configured in the repo")
        (cls.ws / ".tools").mkdir()
        shutil.copyfile(repo_manifest, cls.ws / ".tools" / "kagura-toolchain.json")

    @classmethod
    def tearDownClass(cls):
        cls._td.cleanup()

    def _cli(self, label, *args, timeout=420):
        proc, _, out = _outer_run(_cli_argv("--config", str(self.config), *args), label, timeout=timeout)
        self.assert_bounded_cleanup(proc)
        return proc, json.loads(Path(proc["stdout"]).read_text(encoding="utf-8")), out

    def test_cli_source_integrate_end_to_end(self):
        _, plan, _ = self._cli("e2e-plan", "source-plan", "--project", str(self.pkg / "project.json"))
        self.assertEqual(plan.get("status"), "planned", plan)
        _, built, _ = self._cli("e2e-build", "source-build",
                                "--plan-id", plan["plan_id"], "--fingerprint", plan["fingerprint"])
        if built.get("status") != "artifact_created_unvalidated":
            # The native dotnet_il_native link needs the full MSVC/VS developer
            # environment, which the OUTER wrapper's clean allow-listed env
            # deliberately omits. The authoritative fresh native build + end-to-end
            # acceptance is root's, run with the proper build environment; this
            # harness only smoke-tests the public CLI wiring.
            self.skipTest("native source-build not completable under the clean-env harness "
                          "(build status=%r); root owns the authoritative fresh build" % built.get("status"))
        self.assertEqual(built.get("status"), "artifact_created_unvalidated", built)
        proc, integrated, out = self._cli(
            "e2e-integrate", "source-integrate", "--plan-id", plan["plan_id"],
            "--integration-spec", str(self.pkg / "integration.json"),
            "--contract", str(self.pkg / "application-contract.json"))
        self.assertEqual(proc["returncode"], 0, integrated)
        self.assertEqual(integrated.get("status"), _SUCCESS_STATUS, integrated)
        self.assertEqual(integrated.get("plan_id"), plan["plan_id"], integrated)
        self.assertIs(integrated.get("fresh_protected_native_build"), False, integrated)
        bundle = integrated.get("deployment_bundle")
        self.assertIsInstance(bundle, dict, integrated)
        for entry in bundle["files"]:
            self.assertEqual(set(entry) >= {"relative_path", "sha256", "bytes"}, True, entry)
        (out / "integrate-summary.json").write_text(json.dumps(
            {k: integrated.get(k) for k in ("status", "plan_id", "integration_id",
                                            "integration_report_path", "deployment_bundle",
                                            "reused_native_core", "fresh_protected_native_build")},
            indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
