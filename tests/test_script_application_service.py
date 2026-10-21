"""Independent service tamper tests for the phase24 script application route.

Authored by the INDEPENDENT worker lane (``.runs/phase24-root/brief.md``) against
the LANDED root service ``antirea.script_application``. These exercise the service's
real plan/artifact/pin/receipt helpers with real files and directories, pairing each
tamper (negative) case with a concrete positive oracle. No production helper is
mocked; refusals are asserted as ``ValueError`` (the service/protector/engine error
convention) and a ``TypeError`` is never accepted as a refusal.

Author-only: nothing is executed as a subprocess, compiler or application. The
helpers under test are pure structural/evidence verifiers over bytes already on
disk -- they spawn no child. Root runs this suite after source owners freeze.

The service is a required module; if it is absent the import fails loudly (a missing
required module is a qualification failure, not a skip).
"""
import os
import stat
import tempfile
import unittest
from pathlib import Path

from antirea import script_application as svc
from antirea import script_python_application as py_adapter

import json


def _abs(path):
    return str(Path(os.path.abspath(str(path))))


# Reserved/received components that must be refused before any filesystem access.
FORBIDDEN = ("env.setting", "LINKREPRO", "attackerfolder", "rea-analysis-reports")


class _TmpCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self._counter = 0

    def _fresh_dir(self, name=None):
        self._counter += 1
        path = self.root / (name or ("d%03d" % self._counter))
        path.mkdir(parents=True)
        return path

    def _file(self, directory, rel, data):
        path = directory / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path


class PathGuardTests(_TmpCase):
    """``_path`` / ``_relative``: forbidden-component and traversal refusals."""

    def test_path_accepts_clean_existing_file(self):
        f = self._file(self.root, "pkg/main.py", b"print(1)\n")
        self.assertEqual(svc._path(str(f)), Path(os.path.abspath(str(f))))

    def test_path_rejects_forbidden_components_before_filesystem_access(self):
        # Synthetic, never-created paths: the lexical reserved check must fire
        # before any abspath/stat/link resolution.
        for token in FORBIDDEN:
            probe = os.path.join(str(self.root), "stage", token, "does-not-exist.py")
            with self.subTest(token=token):
                with self.assertRaisesRegex(ValueError, "reserved"):
                    svc._path(probe)

    def test_path_rejects_control_characters(self):
        with self.assertRaises(ValueError):
            svc._path(str(self.root) + "/bad\x00name.py")

    def test_path_enforces_inside_confinement(self):
        inside = self._fresh_dir("owned")
        outside = self.root / "sibling.py"
        outside.write_bytes(b"x")
        self.assertEqual(svc._path(str(inside / "ok.py"), inside=inside),
                         Path(os.path.abspath(str(inside / "ok.py"))))
        with self.assertRaisesRegex(ValueError, "escapes"):
            svc._path(str(outside), inside=inside)

    def test_relative_accepts_ordinary_posix_name(self):
        self.assertEqual(svc._relative("pkg/app/main.py"), "pkg/app/main.py")

    def test_relative_rejects_malformed_and_reserved_names(self):
        bad = ["", "/abs.py", "a\\b.py", "c:/x.py", "a/./b.py", "a/../b.py", "a/..",
               "trail./x.py", "space /x.py", "bad\x00.py",
               "env.setting", "attackerfolder/x.py", "rea-analysis-reports/y.py",
               "con.py", "nul", "com1.txt", "lpt9", "aux.json", "prn"]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError):
                svc._relative(value)


class BoundedReadHashPinTests(_TmpCase):
    """``_read`` / ``_hash`` / ``_pins_match`` / ``_digest`` (pin verification)."""

    def test_read_returns_exact_bytes(self):
        f = self._file(self.root, "data.bin", b"abc123")
        self.assertEqual(svc._read(str(f)), b"abc123")

    def test_read_rejects_oversized_file(self):
        f = self._file(self.root, "big.bin", b"0123456789")
        with self.assertRaises(ValueError):
            svc._read(str(f), 4)

    def test_read_rejects_non_regular_input(self):
        d = self._fresh_dir("adir")
        with self.assertRaises(ValueError):
            svc._read(str(d))

    def test_hash_matches_digest_of_contents(self):
        data = b"content-under-hash"
        f = self._file(self.root, "h.bin", data)
        self.assertEqual(svc._hash(str(f)), svc._digest(data))

    def test_pins_match_accepts_consistent_pins_and_rejects_tamper(self):
        a = self._file(self.root, "a.py", b"A-bytes")
        b = self._file(self.root, "b.py", b"B-bytes")
        pins = {str(a): svc._hash(str(a)), str(b): svc._hash(str(b))}
        self.assertTrue(svc._pins_match(pins))        # positive oracle
        b.write_bytes(b"B-bytes-TAMPERED")             # content drift
        self.assertFalse(svc._pins_match(pins))

    def test_pins_match_rejects_non_hex_expectation(self):
        a = self._file(self.root, "a.py", b"A")
        self.assertFalse(svc._pins_match({str(a): "not-a-sha256"}))


class RuntimeInventoryTests(_TmpCase):
    """``_inventory`` (relocatable runtime/deployment bundle) exact-map checks."""

    def _bundle(self):
        directory = self._fresh_dir("bundle")
        a = self._file(directory, "a.py", b"print('a')\n")
        b = self._file(directory, "sub/b.json", b"{}\n")
        expected = {"a.py": svc._hash(str(a)), "sub/b.json": svc._hash(str(b))}
        return directory, expected

    def test_accepts_exact_matching_tree(self):
        directory, expected = self._bundle()
        self.assertEqual(svc._inventory(directory, expected), expected)

    def test_rejects_unlisted_file(self):
        directory, expected = self._bundle()
        self._file(directory, "extra.txt", b"surprise")
        with self.assertRaises(ValueError):
            svc._inventory(directory, expected)

    def test_rejects_missing_expected_file(self):
        directory, expected = self._bundle()
        expected = dict(expected, **{"ghost.py": "a" * 64})
        with self.assertRaises(ValueError):
            svc._inventory(directory, expected)

    def test_rejects_casefold_collision(self):
        directory = self._fresh_dir("cf")
        with self.assertRaises(ValueError):
            svc._inventory(directory, {"A.py": "a" * 64, "a.py": "b" * 64})

    def test_rejects_non_sha_values(self):
        directory = self._fresh_dir("badsha")
        with self.assertRaises(ValueError):
            svc._inventory(directory, {"a.py": "not-hex"})

    def test_rejects_over_128_entries(self):
        directory = self._fresh_dir("many")
        expected = {"f%d.py" % i: "a" * 64 for i in range(129)}
        with self.assertRaises(ValueError):
            svc._inventory(directory, expected)

    def test_rejects_reserved_or_device_relative_name(self):
        directory = self._fresh_dir("reserved")
        for name in ("attackerfolder/x.py", "nul.py"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                svc._inventory(directory, {name: "a" * 64})


class ReceiptEvidenceTests(_TmpCase):
    """``_command_evidence`` / ``_receipt_evidence`` (Windows-Job receipt binding)."""

    def _receipt(self, engine_out, *, ordinal="001", rc=0, out=b"42\r\n", err=b"",
                 argv=None, clean=True, pid=4321):
        stdout = engine_out / (ordinal + ".stdout.log")
        stderr = engine_out / (ordinal + ".stderr.log")
        receipt = engine_out / (ordinal + ".process.json")
        stdout.write_bytes(out)
        stderr.write_bytes(err)
        if argv is None:
            argv = ["C:/python.exe", "-I", "-B", str(engine_out / "app.py")]
        process = {
            "argv": argv, "pid": pid, "returncode": rc, "timed_out": False, "cancelled": False,
            "stdout": str(stdout), "stderr": str(stderr),
            "cleanup": {"method": "windows_job", "job_assigned": clean, "parent_pid": pid,
                        "parent_exit_confirmed": True, "active_after": 0,
                        "status": "assigned_job_empty", "job_handle_closed": True},
        }
        svc._create_json(receipt, process)
        entry = {
            "receipt_path": str(receipt), "receipt_sha256": svc._digest(receipt.read_bytes()),
            "stdout_log": str(stdout), "stderr_log": str(stderr),
            "argv": argv, "returncode": rc,
            "stdout_sha256": svc._digest(out), "stdout_bytes": len(out),
        }
        return entry, process, receipt

    def test_accepts_faithful_receipt_and_normalizes_stdout(self):
        out = self._fresh_dir("eok")
        entry, _process, receipt = self._receipt(out)
        observed = svc._command_evidence(entry, out, set(), {}, expected_argv=entry["argv"])
        self.assertEqual(observed["returncode"], 0)
        self.assertEqual(observed["stdout"], "42\n")      # CRLF -> LF only
        self.assertEqual(observed["stdout_bytes"], 4)
        self.assertEqual(observed["receipt"], str(receipt))

    def test_rejects_tampered_receipt_hash(self):
        out = self._fresh_dir("ehash")
        entry, _p, _r = self._receipt(out)
        entry["receipt_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            svc._command_evidence(entry, out, set(), {})

    def test_rejects_argv_mismatch(self):
        out = self._fresh_dir("eargv")
        entry, _p, _r = self._receipt(out)
        with self.assertRaises(ValueError):
            svc._command_evidence(entry, out, set(), {}, expected_argv=["C:/python.exe", "other.py"])

    def test_rejects_log_path_disagreement(self):
        out = self._fresh_dir("elog")
        entry, _p, _r = self._receipt(out)
        entry["stdout_log"] = str(out / "unrelated.stdout.log")
        with self.assertRaises(ValueError):
            svc._command_evidence(entry, out, set(), {})

    def test_rejects_returncode_disagreement(self):
        out = self._fresh_dir("erc")
        entry, _p, _r = self._receipt(out)
        entry["returncode"] = 7         # raw receipt says 0
        with self.assertRaises(ValueError):
            svc._command_evidence(entry, out, set(), {})

    def test_rejects_unclean_windows_job_receipt(self):
        out = self._fresh_dir("eunclean")
        entry, _p, _r = self._receipt(out, clean=False)
        with self.assertRaises(ValueError):
            svc._command_evidence(entry, out, set(), {})

    def test_rejects_reused_receipt_across_observations(self):
        out = self._fresh_dir("ereuse")
        entry, _p, _r = self._receipt(out)
        seen = set()
        svc._command_evidence(entry, out, seen, {}, expected_argv=entry["argv"])  # first: ok
        with self.assertRaises(ValueError):
            svc._command_evidence(entry, out, seen, {}, expected_argv=entry["argv"])


class PythonFullVerifierTests(_TmpCase):
    """Faithful on-disk Python ``_verify_engine_evidence`` POSITIVE fixture plus
    tamper mutations proving the FULL verifier refuses.

    The fixture builds a complete saved engine tree -- integration.json report,
    staging/preparation.json, the fixed runpy bootstrap, original/protected/
    deployment/control runtime trees, synthetic Windows-Job receipts + logs, and
    the exact case/control summaries -- entirely from real service helpers and
    the real adapter's ``RUNPY_BOOTSTRAP``. Receipt bytes are synthetic; NO
    application, interpreter, compiler or subprocess is executed. Each tamper
    pairs against the accepted positive, and refusals are asserted as
    ``ValueError`` (never an accepted ``TypeError``).
    """

    APP = b"import sys\nprint(42)\n"
    CORE = b"# original selected core\n"
    DATA = b"{}\n"
    PROTECTED = b"# VM-protected core artifact\n"
    BASELINE = b"# normalized baseline artifact\n"

    def _w(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def _wjson(self, path, value):
        return self._w(path, svc._encoded(value) + b"\n")

    def _rewrite_report(self, fx):
        self._w(fx["engine_out"] / "integration.json", svc._encoded(fx["report"]) + b"\n")

    def _receipt(self, eo, name, argv, rc, out):
        stdout = self._w(eo / (name + ".stdout.log"), out)
        stderr = self._w(eo / (name + ".stderr.log"), b"")
        pid = 2048
        process = {"argv": list(argv), "pid": pid, "returncode": rc, "timed_out": False,
                   "cancelled": False, "stdout": str(stdout), "stderr": str(stderr),
                   "cleanup": {"method": "windows_job", "job_assigned": True, "parent_pid": pid,
                               "parent_exit_confirmed": True, "active_after": 0,
                               "status": "assigned_job_empty", "job_handle_closed": True}}
        receipt = self._w(eo / (name + ".process.json"), svc._encoded(process) + b"\n")
        return {"receipt_path": str(receipt), "receipt_sha256": svc._digest(receipt.read_bytes()),
                "stdout_log": str(stdout), "stderr_log": str(stderr), "argv": list(argv),
                "returncode": rc, "stdout_sha256": svc._digest(out), "stdout_bytes": len(out)}

    def _build(self, *, app=None):
        app = self.APP if app is None else app
        core, data, prot, base = self.CORE, self.DATA, self.PROTECTED, self.BASELINE
        d = svc._digest
        ch_core, ch_app, ch_data, bl, pr = d(core), d(app), d(data), d(base), d(prot)
        src_sha = d(b"normalized-pure-source")

        src_root = self.root / "src"
        for name, content in (("core.py", core), ("app.py", app), ("data.json", data)):
            self._w(src_root / name, content)
        project_path = src_root / "project.json"

        eo = Path(_abs(self.root / "engine"))
        eo.mkdir(parents=True)
        original_root = eo / "staging" / "original"
        protected_root = eo / "staging" / "protected"
        deployment_root = eo / "deployment"
        control_root = eo / "control"
        for name, content in (("core.py", core), ("app.py", app), ("data.json", data)):
            self._w(original_root / name, content)
        for name, content in (("core.py", prot), ("app.py", app), ("data.json", data)):
            self._w(protected_root / name, content)
            self._w(deployment_root / name, content)
        for name, content in (("app.py", app), ("data.json", data)):
            self._w(control_root / name, content)

        boot = self._w(eo / "staging" / "bootstrap.py", py_adapter.RUNPY_BOOTSTRAP.encode("utf-8"))
        boot_sha = d(boot.read_bytes())

        original_map = {"core.py": ch_core, "app.py": ch_app, "data.json": ch_data}
        protected_map = {"core.py": pr, "app.py": ch_app, "data.json": ch_data}
        reference_evidence = {"module_execution": {"module": "app"},
                              "runpy_bootstrap": {"path": str(boot), "sha256": boot_sha}}
        inner = {"language": "python", "original_root": str(original_root),
                 "protected_root": str(protected_root), "runtime_entrypoint": "app.py",
                 "protected_relative": "core.py", "protected_sha256": pr,
                 "original_core_sha256": ch_core,
                 "file_maps": {"original": dict(original_map), "protected": dict(protected_map)},
                 "reference_evidence": reference_evidence, "limitations": ["stages only"],
                 "preparation_commands": []}
        self._wjson(eo / "staging" / "preparation.json", inner)

        names = {"script_app_integration.py": "antirea.script_app_integration",
                 "jvm_app_integration.py": "antirea.jvm_app_integration",
                 "process.py": "antirea.process",
                 "script_python_application.py": "antirea.script_python_application"}
        support, trusted = {}, {}
        for fname, modname in names.items():
            p = _abs(Path(svc.__file__).with_name(fname))
            sha = svc._hash(p)
            support[modname] = {"path": p, "sha256": sha}
            trusted[p] = sha
        for name, sha in (("core.py", ch_core), ("app.py", ch_app), ("data.json", ch_data)):
            trusted[_abs(src_root / name)] = sha

        adapter_name = "antirea.script_python_application"
        adapter = {"name": adapter_name, **support[adapter_name]}
        baseline = {"path": _abs(self.root / "build" / "baseline.py"), "sha256": bl, "bytes": len(base)}
        protected = {"path": _abs(self.root / "build" / "protected.py"), "sha256": pr, "bytes": len(prot)}
        producer = {"backend": "python_vm",
                    "artifacts": {"baseline": dict(baseline), "protected": dict(protected)},
                    "project": {"project_path": str(project_path), "source_sha256": src_sha,
                                "language": "python"}}
        tools = {"python_executable": {"path": "C:/py/python.exe", "sha256": "a" * 64}}
        cases = [{"label": "ok", "args": ["7"], "expect": {"returncode": 0, "stdout": "42\n"}}]
        spec = {"schema_version": 1, "kind": "script_application_integration", "language": "python",
                "protected_source": "core.py", "entrypoint": "app.py",
                "application_files": ["core.py", "app.py", "data.json"]}

        py = tools["python_executable"]["path"]

        def argv(root):
            return [py, "-I", "-S", "-B", str(boot), str(root), "app", "7"]

        commands = []
        for i, (arm, root) in enumerate((("original", original_root), ("protected", protected_root),
                                         ("deployment", deployment_root)), start=1):
            e = self._receipt(eo, "r%d" % i, argv(root), 0, b"42\n")
            commands.append({"label": "case:ok:" + arm, "kind": "case_arm", "arm": arm,
                             "case_label": "ok", "control": None, **e})
        ec = self._receipt(eo, "r4", argv(control_root), 1, b"boom\n")
        commands.append({"label": "control:missing_protected_module", "kind": "control", "arm": None,
                         "case_label": "ok", "control": "missing_module", **ec})
        sha42 = d(b"42\n")
        results = {arm: {"returncode": 0, "stdout_sha256": sha42, "stdout_bytes": 3, "stdout_preview": "42\n"}
                   for arm in ("original", "protected", "deployment")}
        records = [{"label": "ok", "args": ["7"], "expect": {"returncode": 0, "stdout": "42\n"},
                    "results": results, "match": True}]
        controls = [{"label": "missing_protected_module", "control": "missing_module", "case_label": "ok",
                     "returncode": 1, "stdout_sha256": d(b"boom\n"), "reproduced_success": False,
                     "failed_as_required": True}]
        sizes = {"core.py": len(prot), "app.py": len(app), "data.json": len(data)}
        deploy_files = [{"relative_path": n, "sha256": protected_map[n], "bytes": sizes[n]}
                        for n in sorted(protected_map)]
        report = {"schema_version": 1, "kind": "script_application_integration", "language": "python",
                  "status": svc.PUBLIC_STATUS_PASSED, "fresh_protected_build": False,
                  "reused_protected_artifact": True, "whole_application_verified": False,
                  "published": False, "external_resistance": "not_evaluated",
                  "performance_acceptance": "not_evaluated",
                  "producer": {"backend": "python_vm", "baseline": dict(baseline),
                               "protected": dict(protected), "original_source_sha256": src_sha},
                  "support_modules": support, "adapter": adapter,
                  "staging": {"adapter": adapter_name, "adapter_sha256": support[adapter_name]["sha256"],
                              **inner},
                  "deployment": {"path": str(deployment_root), "files": deploy_files,
                                 "allowlist": sorted(protected_map), "protected_module": "core.py",
                                 "runtime_entrypoint": "app.py"},
                  "comparison": {"arms": ["original", "protected", "deployment"],
                                 "commands": commands, "cases": records, "controls": controls}}
        self._wjson(eo / "integration.json", report)
        return {"report": report, "engine_out": eo, "cases": cases, "producer": producer,
                "spec": spec, "trusted": trusted, "tools": tools}

    def _verify(self, fx):
        return svc._verify_engine_evidence(fx["report"], fx["engine_out"], cases=fx["cases"],
                                           producer=fx["producer"], spec=fx["spec"],
                                           trusted_inputs=fx["trusted"], tools=fx["tools"])

    # --- positive oracle ------------------------------------------------- #
    def test_positive_full_python_verification(self):
        fx = self._build()
        result = self._verify(fx)
        self.assertIs(result["whole_application_verified"], False)
        self.assertEqual(result["vm_call_tracing"], "not_performed")
        self.assertIs(result["dependency_presence_verified"], True)
        self.assertEqual(len(result["raw_cases"]), 1)
        self.assertEqual(result["missing_module_control"]["returncode"], 1)
        self.assertTrue(result["report"]["path"].endswith("integration.json"))

    # --- tamper refusals (full verifier, not status flag) ---------------- #
    def test_forged_status_without_command_evidence_refused(self):
        fx = self._build()                                  # status stays PASSED
        fx["report"]["comparison"]["commands"] = []
        self._rewrite_report(fx)
        with self.assertRaises(ValueError):
            self._verify(fx)

    def test_wrong_output_refused(self):
        fx = self._build()
        self._w(fx["engine_out"] / "r1.stdout.log", b"999\n")   # contradicts recorded/expected
        with self.assertRaises(ValueError):
            self._verify(fx)

    def test_wrong_argv_refused(self):
        fx = self._build()
        rp = fx["engine_out"] / "r1.process.json"
        proc = json.loads(rp.read_bytes().decode("utf-8"))
        a = proc["argv"]
        proc["argv"] = [a[0], "-I", "-S", "-B", a[4], a[5], "evil", "7"]  # wrong module
        self._w(rp, svc._encoded(proc) + b"\n")
        cmd = fx["report"]["comparison"]["commands"][0]
        cmd["argv"] = list(proc["argv"])
        cmd["receipt_sha256"] = svc._digest(rp.read_bytes())
        self._rewrite_report(fx)
        with self.assertRaises(ValueError):
            self._verify(fx)

    def test_wrong_protected_map_refused(self):
        fx = self._build()
        wrong = "d" * 64
        fx["report"]["staging"]["file_maps"]["protected"]["app.py"] = wrong
        prep_path = fx["engine_out"] / "staging" / "preparation.json"
        prep = json.loads(prep_path.read_bytes().decode("utf-8"))
        prep["file_maps"]["protected"]["app.py"] = wrong      # keep staging==preparation
        self._w(prep_path, svc._encoded(prep) + b"\n")
        self._rewrite_report(fx)
        with self.assertRaises(ValueError):
            self._verify(fx)

    def test_wrong_deployment_inventory_refused(self):
        fx = self._build()
        fx["report"]["deployment"]["files"][0]["bytes"] += 1
        self._rewrite_report(fx)
        with self.assertRaises(ValueError):
            self._verify(fx)

    def test_missing_control_evidence_refused(self):
        fx = self._build()
        fx["report"]["comparison"]["controls"] = []
        self._rewrite_report(fx)
        with self.assertRaises(ValueError):
            self._verify(fx)

    def test_control_that_did_not_fail_refused(self):
        fx = self._build()
        rp = fx["engine_out"] / "r4.process.json"
        proc = json.loads(rp.read_bytes().decode("utf-8"))
        proc["returncode"] = 0                               # control "succeeded" without the core
        self._w(rp, svc._encoded(proc) + b"\n")
        cmd = fx["report"]["comparison"]["commands"][-1]
        cmd["returncode"] = 0
        cmd["receipt_sha256"] = svc._digest(rp.read_bytes())
        fx["report"]["comparison"]["controls"][0]["returncode"] = 0
        self._rewrite_report(fx)
        with self.assertRaises(ValueError):
            self._verify(fx)

    def test_copied_original_core_into_bundle_refused(self):
        # app.py carries the exact original core bytes, so the raw original core
        # hash appears among the protected bundle values -> leak refusal.
        fx = self._build(app=self.CORE)
        with self.assertRaises(ValueError):
            self._verify(fx)

    def test_missing_planned_support_hash_refused(self):
        fx = self._build()
        del fx["trusted"][_abs(Path(svc.__file__).with_name("process.py"))]
        with self.assertRaises(ValueError):
            self._verify(fx)

    def _control_metadata(self, fx):
        return {
            "control_root": str(fx["engine_out"] / "control"),
            "removed_module": "core.py",
            "inventory": [{"relative_path": name, "sha256": sha}
                          for name, sha in sorted(fx["report"]["staging"]["file_maps"]["protected"].items())
                          if name != "core.py"],
        }

    def test_positive_with_independently_bound_control_metadata(self):
        fx = self._build()
        fx["report"]["comparison"]["controls"][0].update(self._control_metadata(fx))
        self._rewrite_report(fx)
        self.assertTrue(self._verify(fx)["dependency_presence_verified"])

    def test_false_optional_control_metadata_refused(self):
        fx = self._build()
        control = fx["report"]["comparison"]["controls"][0]
        control.update(self._control_metadata(fx))
        for key, wrong in (("control_root", str(fx["engine_out"] / "deployment")),
                           ("removed_module", "app.py"), ("inventory", [])):
            with self.subTest(key=key):
                original = control[key]
                control[key] = wrong
                self._rewrite_report(fx)
                with self.assertRaises(ValueError):
                    self._verify(fx)
                control[key] = original

    def test_unknown_control_metadata_refused(self):
        fx = self._build()
        fx["report"]["comparison"]["controls"][0]["unverified_claim"] = True
        self._rewrite_report(fx)
        with self.assertRaises(ValueError):
            self._verify(fx)


if __name__ == "__main__":
    unittest.main()
