"""Independent raw child-evidence verification for the public C# source-integrate
gate.

Task 1 of docs/superpowers/plans/2026-10-21-supported-languages.md: a persisted
engine report that carries passing ``comparison`` flags but whose confined,
bounded, persisted per-case RECEIPTS and raw stdout/stderr LOGS contradict those
flags (or are missing / duplicated / substituted / unclean / timed-out /
cancelled / out-of-root / malformed) MUST NOT pass
``antirea.csharp_application``'s public service gate. The public pass must rest on
observations the service re-derives itself from the raw logs/receipts -- never on
the engine's copied boolean flags alone.

Defender-only. Every fixture here is PURE SYNTHETIC and the trusted integration
engine is REPLACED by a boundary stand-in (:func:`_evidence_engine`) that writes a
realistic on-disk evidence tree via the shared builder
``test_csharp_application_service._write_child_evidence`` (the exact shape
``antirea.process.run_logged`` persists), then perturbs exactly one piece of raw
evidence. None of this is real integration evidence; the only real integration
proof is root's separate fresh CLI E2E. No REA/attack/received code runs; no
compiler or application is executed by this suite; reserved segments
(``env.setting`` / ``LINKREPRO`` / ``attackerfolder`` / ``rea-analysis-reports`` /
``defense-loop``) are never traversed -- the sole out-of-root path used is a
synthetic sibling of the engine output directory under the private temp workspace.
No install/download/publish/commit happens. The new verifier is exercised for
real (never mocked out).
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for _p in (str(ROOT), str(Path(__file__).resolve().parent)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from antirea import csharp_application as ca            # REQUIRED production module: no skip gate.
# Reuse the sibling service suite's synthetic producer/native fixtures and the
# shared raw-evidence builder (no compiler, no real evidence); referenced by
# attribute so its TestCases are not re-collected here.
import test_csharp_application_service as svc

_SUCCESS = ca.PUBLIC_STATUS_PASSED

_DLL_BYTES = b"MZ\x90\x00managed-app-fixture-child-evidence"
_RC_BYTES = b'{"runtimeOptions":{"tfm":"net10.0"}}'

# Explicit contract cases (distinct args AND distinct observed stdout per index, so a
# receipt substituted from another case is detectable by both argv and observation).
_VALUE0 = {"label": "v0", "kind": "value", "args": [7, 3], "expect": {"returncode": 0, "stdout_is_integer": True}}
_VALUE1 = {"label": "v1", "kind": "value", "args": [9, 4], "expect": {"returncode": 0, "stdout_is_integer": True}}
_EXC0 = {"label": "e0", "kind": "exception", "args": [2147483647, 1],
         "expect": {"exception": "System.OverflowException"}}


def _contract(cases):
    return {"schema_version": 1, "kind": ca.APPLICATION_CONTRACT_KIND, "cases": cases}


def _cmd(report, label):
    return next(c for c in report["comparison"]["commands"] if c["label"] == label)


def _rewrite_receipt(logs, label, mutate):
    p = logs / (label + ".process.json")
    r = json.loads(p.read_text(encoding="utf-8"))
    mutate(r)
    p.write_text(json.dumps(r, indent=2), encoding="utf-8")


# --------------------------------------------------------------------------- #
# Single-defect hooks (applied AFTER a fully honest evidence tree + report).
# Each perturbs exactly one thing so one gate obligation is isolated.
# --------------------------------------------------------------------------- #
def _d_contradictory_stdout(out, logs, report):
    (logs / "depl-000.stdout.log").write_text("999\n", encoding="utf-8")       # raw != claimed


def _d_contradictory_exit(out, logs, report):
    _rewrite_receipt(logs, "depl-000", lambda r: r.__setitem__("returncode", 7))   # raw != claimed 0


def _d_missing_receipt(out, logs, report):
    (logs / "depl-000.process.json").unlink()


def _d_duplicate_receipt(out, logs, report):
    dep, orig = _cmd(report, "depl-000"), _cmd(report, "orig-000")
    dep["receipt_path"], dep["stdout"], dep["stderr"] = orig["receipt_path"], orig["stdout"], orig["stderr"]


def _d_substituted_receipt(out, logs, report):
    for ext in ("process.json", "stdout.log", "stderr.log"):
        (logs / ("depl-001." + ext)).write_bytes((logs / ("depl-000." + ext)).read_bytes())


def _d_unclean_child(out, logs, report):
    def mut(r):
        r["cleanup"]["status"] = "terminated_active"
        r["cleanup"]["job_handle_closed"] = False
        r["cleanup"]["parent_exit_confirmed"] = False
    _rewrite_receipt(logs, "orig-000", mut)


def _d_timeout_child(out, logs, report):
    _rewrite_receipt(logs, "depl-000", lambda r: (r.__setitem__("timed_out", True), r.__setitem__("returncode", None)))


def _d_cancelled_child(out, logs, report):
    _rewrite_receipt(logs, "orig-000", lambda r: (r.__setitem__("cancelled", True),
                                                   r.__setitem__("returncode", None), r.__setitem__("pid", None)))


def _d_unconfined_receipt(out, logs, report):
    # A synthetic sibling of the engine output dir (NOT reserved): the receipt lives
    # outside the engine output, so it must be refused BEFORE it is read.
    escaped = out.parent / "escaped.process.json"
    escaped.write_bytes((logs / "depl-000.process.json").read_bytes())
    _cmd(report, "depl-000")["receipt_path"] = str(escaped)


def _d_malformed_receipt(out, logs, report):
    (logs / "depl-000.process.json").write_bytes(b"this is not valid json {{{{")


def _d_forged_route_control(out, logs, report):
    # A negative control claimed to prove native-required, but the raw evidence shows
    # a clean rc==0 success with no exception.
    (logs / "route-missing-core.stdout.log").write_text("1000\n", encoding="utf-8")
    (logs / "route-missing-core.stderr.log").write_text("", encoding="utf-8")
    _rewrite_receipt(logs, "route-missing-core", lambda r: r.__setitem__("returncode", 0))


def _evidence_engine(h, *, defect=None):
    """Boundary stand-in for the trusted engine: writes a realistic confined per-case
    raw evidence tree (via the shared builder) and a report whose ``comparison``
    flags all claim a pass; ``defect`` perturbs exactly one piece of raw evidence (or
    one command pin) AFTER the honest tree+report are written. The report dict stays
    byte-equal to the persisted ``integration.json`` (a return-only forgery is
    already rejected by the existing gate, so it is never the isolated variable)."""
    report_path, report_sha = str(h.report_path), h.report_sha

    def run_integration(producer, receipt, toolchain, workspace, app_dir, spec_path,
                        *, timeout_seconds, cases, trusted_inputs=None):
        out = Path(workspace.out_dir)
        app, stg = out / "app", out / "staging"
        app.mkdir(parents=True, exist_ok=True)
        stg.mkdir(parents=True, exist_ok=True)
        dll, rc, core = app / "App.dll", app / "App.runtimeconfig.json", stg / "core.dll"
        dll.write_bytes(_DLL_BYTES)
        rc.write_bytes(_RC_BYTES)
        core.write_bytes(svc._NATIVE_BYTES)                       # hashes to the producer PROTECTED pin
        orig_dll = str(out / "original_app.dll")
        ev = svc._write_child_evidence(out, cases, original_dll=orig_dll, deployable_dll=str(dll))
        value_cases = sum(1 for c in cases if c["kind"] == "value")
        report = {
            "status": "producer_bound_integration_passed", "fresh_protected_native_build": False,
            "producer": {"report_path": report_path, "report_sha256": report_sha,
                         "protected": {"sha256": svc._PROT_SHA}, "baseline": {"sha256": svc._BASE_SHA}},
            "staging": {"native_core": str(core), "native_core_sha256": ca._digest(svc._NATIVE_BYTES),
                        "native_library": "NativeCore"},
            "comparison": {
                "status": "producer_bound_integration_passed", "all_match": True, "env_ok": True,
                "il_evidence_ok": True, "route_proof_ok": True, "route_control_ok": True,
                "integrity_verified_before_and_after": True, "expectations_ok": True,
                "total_cases": len(cases), "value_cases": value_cases,
                "exception_cases": len(cases) - value_cases, "framework": "net10.0",
                "runtime_version": "10.0.0", "sdk_version": "10.0.201",
                "original_app": {"dll": orig_dll, "sha256": ca._digest(b"orig"),
                                 "runtimeconfig": {"path": str(out / "original_app.runtimeconfig.json"),
                                                   "sha256": ca._digest(b"orc")}},
                "deployable_app": {"dll": str(dll), "sha256": ca._digest(_DLL_BYTES),
                                   "runtimeconfig": {"path": str(rc), "sha256": ca._digest(_RC_BYTES)}},
                "comparisons": ev["comparisons"], "route_proofs": ev["route_proofs"], "commands": ev["commands"]},
            "trusted_inputs_verification": {"verified": True, "declared_count": len(trusted_inputs or [])},
        }
        (out / "integration.json").write_text(json.dumps(report), encoding="utf-8")
        if defect is not None:
            defect(out, out / "logs", report)
            # Keep the persisted report byte-equal to the returned one (the existing
            # persisted==returned check must not be the variable under test).
            (out / "integration.json").write_text(json.dumps(report), encoding="utf-8")
        return report

    wp = SimpleNamespace(resolve=staticmethod(
        lambda **k: (Path(k["out_dir"]).mkdir(parents=True, exist_ok=True) or SimpleNamespace(out_dir=k["out_dir"]))))
    return SimpleNamespace(
        WorkspacePlan=wp,
        ProducerManifest=SimpleNamespace(at=staticmethod(lambda p: SimpleNamespace(path=str(p)))),
        ProtectedBuildReceipt=SimpleNamespace(reused_from_report=staticmethod(lambda p, **k: SimpleNamespace())),
        ToolchainSnapshot=SimpleNamespace(discover=staticmethod(lambda **k: SimpleNamespace())),
        TRUSTED_TRANSFORM_MODULE="antirea.csharp_transform", run_integration=run_integration)


class _EvidenceBase(svc._TmpWs):
    def _producer(self, cases):
        return svc._build_producer(self.ws, contract_obj=_contract(cases), artifacts=svc._authentic_artifacts())

    def _run(self, h, *, defect=None):
        engine = _evidence_engine(h, defect=defect)
        with mock.patch.object(ca, "_load_engine", lambda: engine):
            return h.svc.integrate(h.plan_id, str(h.spec), str(h.contract), timeout_seconds=90)

    def _result_record(self, h):
        integ = next(p for p in h.job.iterdir() if p.name.startswith("integration-"))
        return integ, json.loads((integ / "integration-result.json").read_text(encoding="utf-8"))

    def assert_rejected(self, res):
        self.assertEqual(res["status"], "failed", res)
        self.assertIsNone(res["deployment_bundle"], res)
        self.assertIs(res["engine_report_authentic"], False, res)


# --------------------------------------------------------------------------- #
# Positive controls: honest raw evidence (values + exception) is accepted, and
# an expected-nonzero exception case is NOT mistaken for an infrastructure failure.
# --------------------------------------------------------------------------- #
class HonestChildEvidenceTests(_EvidenceBase):
    def test_honest_values_and_exception_pass_with_bound_evidence(self):
        h = self._producer([_VALUE0, _VALUE1, _EXC0])
        res = self._run(h)
        self.assertEqual(res["status"], _SUCCESS, res)
        self.assertIs(res["engine_report_authentic"], True, res)
        self.assertIsInstance(res["deployment_bundle"], dict, res)

    def test_expected_nonzero_exception_case_preserved_not_infra_failure(self):
        # The exception case exits non-zero yet is a clean, expected outcome: the
        # pass must stand and no child-infrastructure failure is recorded for it.
        h = self._producer([_VALUE0, _EXC0])
        res = self._run(h)
        self.assertEqual(res["status"], _SUCCESS, res)
        self.assertEqual(res.get("comparison_mismatch"), False, res)
        _, rec = self._result_record(h)
        self.assertEqual(rec["child_infrastructure_failures"], [], rec)


# --------------------------------------------------------------------------- #
# Forged pass flags vs contradictory / missing / corrupt raw evidence: rejected.
# --------------------------------------------------------------------------- #
class ForgedChildEvidenceRejectedTests(_EvidenceBase):
    def test_contradictory_stdout_rejected(self):
        self.assert_rejected(self._run(self._producer([_VALUE0, _VALUE1]), defect=_d_contradictory_stdout))

    def test_contradictory_exit_code_rejected(self):
        self.assert_rejected(self._run(self._producer([_VALUE0, _VALUE1]), defect=_d_contradictory_exit))

    def test_missing_receipt_rejected(self):
        self.assert_rejected(self._run(self._producer([_VALUE0, _VALUE1]), defect=_d_missing_receipt))

    def test_duplicate_receipt_identity_rejected(self):
        self.assert_rejected(self._run(self._producer([_VALUE0, _VALUE1]), defect=_d_duplicate_receipt))

    def test_substituted_receipt_from_other_case_rejected(self):
        self.assert_rejected(self._run(self._producer([_VALUE0, _VALUE1]), defect=_d_substituted_receipt))

    def test_unclean_child_cleanup_rejected(self):
        self.assert_rejected(self._run(self._producer([_VALUE0, _VALUE1]), defect=_d_unclean_child))

    def test_timed_out_child_rejected(self):
        self.assert_rejected(self._run(self._producer([_VALUE0, _VALUE1]), defect=_d_timeout_child))

    def test_cancelled_child_rejected(self):
        self.assert_rejected(self._run(self._producer([_VALUE0, _VALUE1]), defect=_d_cancelled_child))

    def test_malformed_receipt_rejected(self):
        self.assert_rejected(self._run(self._producer([_VALUE0, _VALUE1]), defect=_d_malformed_receipt))

    def test_forged_negative_control_rejected(self):
        self.assert_rejected(self._run(self._producer([_VALUE0, _VALUE1]), defect=_d_forged_route_control))

    def test_out_of_root_receipt_rejected_without_unsafe_read(self):
        # The out-of-root receipt must be refused by the confinement guard BEFORE any
        # bounded read, proven by spying the real reader: it is never handed the
        # escaped path (while confined receipts are still read normally).
        h = self._producer([_VALUE0, _VALUE1])
        engine = _evidence_engine(h, defect=_d_unconfined_receipt)
        real_read, seen = ca._read, []

        def spy(path, limit):
            seen.append(os.path.normcase(os.path.abspath(str(path))))
            return real_read(path, limit)

        with mock.patch.object(ca, "_read", side_effect=spy), \
                mock.patch.object(ca, "_load_engine", lambda: engine):
            res = h.svc.integrate(h.plan_id, str(h.spec), str(h.contract), timeout_seconds=90)
        self.assert_rejected(res)
        integ, _ = self._result_record(h)
        escaped = os.path.normcase(str(integ / "escaped.process.json"))
        self.assertNotIn(escaped, seen, "out-of-root receipt must not be read")


# --------------------------------------------------------------------------- #
# Child evidence gates packaging AND survives a post-package raw-evidence drift.
# --------------------------------------------------------------------------- #
class PostPackageDriftTests(_EvidenceBase):
    def test_raw_evidence_drift_after_packaging_rejected(self):
        h = self._producer([_VALUE0, _VALUE1])
        engine = _evidence_engine(h)                     # honest; passes the pre-package gate
        real_package = ca._package_bundle

        def after_copy(*args, **kwargs):
            bundle = real_package(*args, **kwargs)
            integ = next(p for p in h.job.iterdir() if p.name.startswith("integration-"))
            (integ / "engine" / "logs" / "depl-000.stdout.log").write_text("999\n", encoding="utf-8")
            return bundle

        with mock.patch.object(ca, "_package_bundle", side_effect=after_copy) as packaging, \
                mock.patch.object(ca, "_load_engine", lambda: engine):
            res = h.svc.integrate(h.plan_id, str(h.spec), str(h.contract), timeout_seconds=90)
        packaging.assert_called_once()
        self.assertEqual(res["status"], "failed", res)
        self.assertIsNone(res["deployment_bundle"], res)
        _, rec = self._result_record(h)
        self.assertEqual(rec["status"], "failed")
        self.assertIsNotNone(rec["package_error"], rec)
        self.assertIn("child_evidence", rec["package_error"])


# --------------------------------------------------------------------------- #
# Targeted candidate-hardening regressions (root review msg_4af66473276b /
# msg_33c0192dc99c). Each exposes a gap in the first child-evidence candidate and
# must fail against it before the minimal correction, then pass after.
# --------------------------------------------------------------------------- #
# A value case whose contract expect does NOT constrain stdout shape (so an
# invalid-UTF-8 arm-byte mismatch is isolated from the stdout_is_integer check).
_RAW0 = {"label": "raw0", "kind": "value", "args": [7, 3], "expect": {"returncode": 0}}
# A genuinely quiet app: original succeeds with EMPTY stdout (not a silent fallback).
_QUIET = {"label": "quiet", "kind": "value", "args": ["q"], "expect": {"returncode": 0, "stdout": ""}}
# A control whose expect pins an exact stdout, so a rc0/clean route-control that
# violates it must still be refused.
_CTRL_STDOUT = {"label": "ctrl", "kind": "value", "args": [0, 0],
                "expect": {"returncode": 0, "stdout": "0", "stdout_is_integer": True}}


def _d_argv_position(out, logs, report):
    # Execute a DIFFERENT dll at the exec slot while listing the expected dll as a
    # later argument: membership alone would pass, position/shape must not.
    def mut(r):
        expected = r["argv"][2]
        r["argv"] = [r["argv"][0], "exec", str(out / "OTHER.dll"), expected, *r["argv"][3:]]
    _rewrite_receipt(logs, "depl-000", mut)


def _d_invalid_utf8_arm_mismatch(out, logs, report):
    # Distinct invalid UTF-8 bytes per arm that collapse to the same replacement text
    # under errors="replace": a decoded-string arm comparison wrongly calls them equal.
    (logs / "orig-000.stdout.log").write_bytes(b"\xff")
    (logs / "depl-000.stdout.log").write_bytes(b"\xef")
    comp = next(c for c in report["comparison"]["comparisons"] if c["case"] == "raw0")
    comp["original"]["stdout"] = "�"
    comp["protected"]["stdout"] = "�"


def _d_unknown_label(out, logs, report):
    entry = svc._write_child(logs, "bogus-extra", ["dotnet", "exec", "bogus"],
                             {"rc": 0, "stdout": "x", "exc": None})
    report["comparison"]["commands"].append(entry)


def _d_prep_nonzero(out, logs, report):
    _rewrite_receipt(logs, "csc-Inspect", lambda r: r.__setitem__("returncode", 3))


def _d_env_probe_leak(out, logs, report):
    (logs / "env-probe.stdout.log").write_text("LEAKED_IF_AMBIENT\n1\n", encoding="utf-8")


def _d_route_control_bad_stdout(out, logs, report):
    (logs / "route-control.stdout.log").write_text("999\n", encoding="utf-8")


class CandidateHardeningRejectedTests(_EvidenceBase):
    def test_argv_assembly_position_enforced(self):
        self.assert_rejected(self._run(self._producer([_VALUE0, _VALUE1]), defect=_d_argv_position))

    def test_invalid_utf8_arm_bytes_mismatch(self):
        self.assert_rejected(self._run(self._producer([_RAW0]), defect=_d_invalid_utf8_arm_mismatch))

    def test_unknown_command_identity_rejected(self):
        self.assert_rejected(self._run(self._producer([_VALUE0, _VALUE1]), defect=_d_unknown_label))

    def test_prep_nonzero_exit_rejected(self):
        self.assert_rejected(self._run(self._producer([_VALUE0, _VALUE1]), defect=_d_prep_nonzero))

    def test_env_probe_sentinel_leak_rejected(self):
        self.assert_rejected(self._run(self._producer([_VALUE0, _VALUE1]), defect=_d_env_probe_leak))

    def test_route_control_expectation_enforced(self):
        self.assert_rejected(self._run(self._producer([_CTRL_STDOUT]), defect=_d_route_control_bad_stdout))


class QuietAppPositiveTests(_EvidenceBase):
    def test_quiet_silent_app_not_rejected_as_fallback(self):
        # original rc0 + empty stdout and expected-exception controls rc1 + empty
        # stdout is NOT a silent fallback; a quiet app must still pass.
        h = self._producer([_QUIET])
        res = self._run(h)
        self.assertEqual(res["status"], _SUCCESS, res)
        self.assertIs(res["engine_report_authentic"], True, res)


class PostPackageByteStabilityTests(_EvidenceBase):
    def test_post_package_semantics_equal_byte_drift_rejected(self):
        # A post-package receipt byte change whose SEMANTICS stay valid (seconds) must
        # still be refused: initial raw evidence hashes are pinned and re-checked.
        h = self._producer([_VALUE0, _VALUE1])
        engine = _evidence_engine(h)
        real_package = ca._package_bundle

        def after_copy(*args, **kwargs):
            bundle = real_package(*args, **kwargs)
            integ = next(p for p in h.job.iterdir() if p.name.startswith("integration-"))
            _rewrite_receipt(integ / "engine" / "logs", "depl-000", lambda r: r.__setitem__("seconds", 0.99))
            return bundle

        with mock.patch.object(ca, "_package_bundle", side_effect=after_copy) as packaging, \
                mock.patch.object(ca, "_load_engine", lambda: engine):
            res = h.svc.integrate(h.plan_id, str(h.spec), str(h.contract), timeout_seconds=90)
        packaging.assert_called_once()
        self.assertEqual(res["status"], "failed", res)
        self.assertIsNone(res["deployment_bundle"], res)


if __name__ == "__main__":
    unittest.main()
