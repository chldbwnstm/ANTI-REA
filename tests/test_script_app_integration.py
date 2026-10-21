"""Authored (not executed) unittest suite for the script application integration ENGINE.

Workers author code and tests only; root executes these after source freeze with the
reviewed ``python -I -S -B -m unittest`` discovery runner (no pytest, no installs).
The ``run_integration`` orchestration tests inject a staging DOUBLE for the (separately
owned) language adapters and a synthetic ``process.run_logged`` that writes clean
Windows-Job receipts, so the engine's validation/orchestration logic is exercised
WITHOUT launching any real interpreter, compiler or target. The pure ``validate_spec``
/ ``validate_contract`` checks need no doubles.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from antirea import script_app_integration as mod
from antirea import jvm_app_integration as safe
from antirea.script_app_integration import ScriptIntegrateError

_NT = os.name == "nt"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _persist_prep(output_dir, result):
    """Mirror the adapter's parse-identical preparation.json next to the staged trees."""
    (Path(output_dir) / "preparation.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=True, allow_nan=False, sort_keys=True) + "\n",
        encoding="utf-8")


def _clean_receipt(log_prefix: Path, returncode: int, stdout: str, stderr: str) -> dict:
    log_prefix.parent.mkdir(parents=True, exist_ok=True)
    out_log = log_prefix.with_suffix(".stdout.log")
    err_log = log_prefix.with_suffix(".stderr.log")
    out_log.write_text(stdout, encoding="utf-8")
    err_log.write_text(stderr, encoding="utf-8")
    pid = 4321
    return {"argv": [], "returncode": returncode, "pid": pid, "timed_out": False,
            "cancelled": False, "seconds": 0.01, "stdout": str(out_log), "stderr": str(err_log),
            "cleanup": {"method": "windows_job", "job_assigned": True, "parent_pid": pid,
                        "parent_exit_confirmed": True, "active_after": 0,
                        "status": "assigned_job_empty", "job_handle_closed": True}}


def _spec(**over):
    spec = {"schema_version": 1, "kind": "script_application_integration",
            "language": "python", "protected_source": "core.py", "entrypoint": "main.py",
            "application_files": ["main.py", "core.py", "data.txt"]}
    spec.update(over)
    return spec


def _contract(cases=None):
    if cases is None:
        cases = [{"label": "ok", "args": ["5"], "expect": {"returncode": 0, "stdout": "6"}}]
    return {"schema_version": 1, "kind": "script_application_samples", "cases": cases}


# --------------------------------------------------------------------------- #
# validate_spec (pure)
# --------------------------------------------------------------------------- #
class ValidateSpecTests(unittest.TestCase):
    def test_python_ok(self):
        out = mod.validate_spec(_spec())
        self.assertEqual(out["language"], "python")
        self.assertEqual(out["protected_source"], "core.py")
        self.assertEqual(out["entrypoint"], "main.py")
        self.assertEqual(out["application_files"], ["main.py", "core.py", "data.txt"])
        self.assertEqual(set(out), {"schema_version", "kind", "language", "protected_source",
                                    "entrypoint", "application_files"})

    def test_idempotent(self):
        self.assertEqual(mod.validate_spec(mod.validate_spec(_spec())), mod.validate_spec(_spec()))

    def test_typescript_sources(self):
        out = mod.validate_spec(_spec(language="typescript", protected_source="src/core.ts",
                                      entrypoint="src/app.ts",
                                      application_files=["src/app.ts", "src/core.ts", "cfg.json"]))
        self.assertEqual(out["protected_source"], "src/core.ts")

    def test_rejections(self):
        cases = [
            ({"schema_version": 2}, "schema_version"),
            ({"kind": "other"}, "kind"),
            ({"language": "ruby"}, "language"),
            ({"protected_source": "core.py", "entrypoint": "core.py"}, "differ"),
            ({"application_files": ["main.py", "data.txt"]}, "protected_source"),
            ({"application_files": ["core.py", "data.txt"]}, "entrypoint"),
            ({"protected_source": "core.js"}, "protected_source suffix"),
            ({"application_files": ["main.py", "core.py", "data.txt", "data.txt"]}, "duplicate"),
            ({"application_files": ["main.py", "core.py", "../x.py", "data.txt"]}, "canonical"),
            ({"application_files": ["main.py", "core.py", "/abs.py", "data.txt"]}, "relative"),
            ({"entrypoint": "main.json", "application_files": ["main.json", "core.py"]}, "entrypoint suffix"),
            ({"application_files": ["main.py", "core.py", "a/con.py"]}, "DOS device"),
            # A path COMPONENT with trailing whitespace ("trail " before the slash) is
            # rejected; an internal space ("trail .py") is a valid filename and allowed.
            ({"application_files": ["main.py", "core.py", "trail /a.py"]}, "trailing"),
        ]
        for over, needle in cases:
            with self.subTest(over=over):
                with self.assertRaises(ScriptIntegrateError) as cm:
                    mod.validate_spec(_spec(**over))
                self.assertIn(needle, str(cm.exception))

    def test_reserved_component(self):
        with self.assertRaises(ScriptIntegrateError):
            mod.validate_spec(_spec(application_files=["main.py", "core.py", "attackerfolder/x.py"]))

    def test_declaration_jsx_map_rejected(self):
        for bad in ("types.d.ts", "widget.tsx", "mod.mjs", "bundle.js.map"):
            with self.subTest(bad=bad):
                with self.assertRaises(ScriptIntegrateError):
                    mod.validate_spec(_spec(language="typescript", protected_source="core.ts",
                                            entrypoint="app.ts",
                                            application_files=["app.ts", "core.ts", bad]))

    def test_typescript_output_collision(self):
        with self.assertRaises(ScriptIntegrateError) as cm:
            mod.validate_spec(_spec(language="typescript", protected_source="core.ts",
                                    entrypoint="app.ts",
                                    application_files=["app.ts", "core.ts", "helper.ts", "helper.js"]))
        self.assertIn("collision", str(cm.exception))

    def test_bounds(self):
        many = ["f%d.py" % i for i in range(mod.MAX_APPLICATION_FILES + 1)]
        with self.assertRaises(ScriptIntegrateError):
            mod.validate_spec(_spec(application_files=many))


# --------------------------------------------------------------------------- #
# validate_contract (pure)
# --------------------------------------------------------------------------- #
class ValidateContractTests(unittest.TestCase):
    def test_ok(self):
        cases = mod.validate_contract(_contract())
        self.assertEqual(cases, [{"label": "ok", "args": ["5"], "expect": {"returncode": 0, "stdout": "6"}}])

    def test_requires_success_case(self):
        with self.assertRaises(ScriptIntegrateError) as cm:
            mod.validate_contract(_contract([{"label": "bad", "args": [],
                                              "expect": {"returncode": 2, "stdout": ""}}]))
        self.assertIn("successful", str(cm.exception))

    def test_rejections(self):
        cases = [
            ({"schema_version": 2, "kind": "script_application_samples", "cases": []}, "schema_version"),
            ({"schema_version": 1, "kind": "x", "cases": []}, "kind"),
            (_contract([]), "non-empty"),
            (_contract([{"label": "a", "args": [], "expect": {"returncode": 0, "stdout": "x"}},
                        {"label": "a", "args": [], "expect": {"returncode": 0, "stdout": "y"}}]), "duplicate"),
            (_contract([{"label": "a", "args": [True], "expect": {"returncode": 0, "stdout": ""}}]), "strings"),
            (_contract([{"label": "a", "args": ["x\x00"], "expect": {"returncode": 0, "stdout": ""}}]), "control"),
            (_contract([{"label": "a", "args": [], "expect": {"returncode": True, "stdout": ""}}]), "returncode"),
            (_contract([{"label": "a", "args": [], "expect": {"returncode": 0, "stdout": "a" * 5000}}]), "stdout"),
            (_contract([{"label": "a", "args": [], "expect": {"returncode": 0}}]), "exactly"),
        ]
        for contract, needle in cases:
            with self.subTest(needle=needle):
                with self.assertRaises(ScriptIntegrateError) as cm:
                    mod.validate_contract(contract)
                self.assertIn(needle, str(cm.exception))

    def test_arg_too_long(self):
        with self.assertRaises(ScriptIntegrateError):
            mod.validate_contract(_contract([{"label": "a", "args": ["x" * (mod.MAX_ARG_LEN + 1)],
                                              "expect": {"returncode": 0, "stdout": ""}}]))


# --------------------------------------------------------------------------- #
# run_integration orchestration (adapter + process doubles; Windows only).
# --------------------------------------------------------------------------- #
_MAIN = b"import core\nimport sys\nprint(core.f(int(sys.argv[1])) if len(sys.argv)>1 else 'ok')\n"
_CORE_SRC = b"def f(x):\n    return x + 1\n"
_DATA = b"payload\n"
_BASELINE = b"# baseline (unprotected generated)\ndef f(x):\n    return x + 1\n"
_PROTECTED = b"# protected VM dispatch\ndef f(x):\n    return x + 1\n"
_BOOTSTRAP = b"import runpy, sys\nroot, module = sys.argv[1], sys.argv[2]\nsys.path.insert(0, root)\n"

_APP_JS = b"const core = require('./core.cjs');\nconsole.log('ok');\n"
_CORE_CJS = b"module.exports.f = (x) => x + 1;\n"
_DATA_JSON = b"{\"k\": 1}\n"
_PROT_CJS = b"// protected vm\nmodule.exports.f = (x) => x + 1;\n"
_BASE_CJS = b"// baseline\nmodule.exports.f = (x) => x + 1;\n"

_APP_JS_T = b'"use strict";\nconst core = require("./core.cjs");\nconsole.log("ok");\n'
_CORE_TS = b"export function f(x: number) { return x + 1; }\n"
_APP_TS = b"import { f } from './core';\nconsole.log('ok');\n"
_CORE_CJS_REF = b'"use strict";\nexports.f = (x) => x + 1; // independent reference\n'
_CORE_CJS_PROT = b"// protected vm\nexports.f = (x) => x + 1;\n"
_BASE_CJS_T = b"// baseline cjs\nexports.f = (x) => x + 1;\n"


@unittest.skipUnless(_NT, "script integration requires Windows Job receipts")
class RunIntegrationTests(unittest.TestCase):
    def setUp(self):
        box = TemporaryDirectory()
        self.addCleanup(box.cleanup)
        self.tmp = Path(box.name)

    def _patch(self, obj, attr, value):
        patcher = mock.patch.object(obj, attr, value)
        patcher.start()
        self.addCleanup(patcher.stop)

    # ----- Python scenario -----
    def _install_python(self, *, run_logged=None, adapter_return=None,
                        baseline=_BASELINE, protected=_PROTECTED):
        tmp = self.tmp
        source_root = tmp / "proj"
        source_root.mkdir()
        (source_root / "main.py").write_bytes(_MAIN)
        (source_root / "core.py").write_bytes(_CORE_SRC)
        (source_root / "data.txt").write_bytes(_DATA)
        build = tmp / "build"
        build.mkdir()
        (build / "baseline.py").write_bytes(baseline)
        (build / "protected.py").write_bytes(protected)
        tools_dir = tmp / "toolchain"
        tools_dir.mkdir()
        (tools_dir / "python.exe").write_bytes(b"MZ-fake-python")
        adapter_src = tmp / "fake_adapter_source.py"
        adapter_src.write_bytes(b"# fake adapter source bytes\n")
        sha = {"main": _sha(_MAIN), "core_src": _sha(_CORE_SRC), "data": _sha(_DATA),
               "baseline": _sha(baseline), "protected": _sha(protected), "py": _sha(b"MZ-fake-python"),
               "adapter": _sha(b"# fake adapter source bytes\n"), "bootstrap": _sha(_BOOTSTRAP)}
        producer = {
            "backend": "python_vm", "status": "artifact_created_unvalidated",
            "project": {"language": "python", "source_sha256": sha["core_src"]},
            "artifacts": {
                "baseline": {"path": str(build / "baseline.py"), "sha256": sha["baseline"], "bytes": len(baseline)},
                "protected": {"path": str(build / "protected.py"), "sha256": sha["protected"], "bytes": len(protected)}},
            "coverage": {"runtime_hardening": {"external_resistance": "not_evaluated"}},
            "coverage_path": str(build / "coverage.json")}
        tools = {"python_executable": {"path": str(tools_dir / "python.exe"), "sha256": sha["py"]}}
        spec = mod.validate_spec(_spec())
        contract = _contract([{"label": "ok", "args": [], "expect": {"returncode": 0, "stdout": "ok"}}])
        input_files = {"main.py": sha["main"], "core.py": sha["core_src"], "data.txt": sha["data"]}
        trusted_inputs = {
            str(source_root / "main.py"): sha["main"], str(source_root / "core.py"): sha["core_src"],
            str(source_root / "data.txt"): sha["data"], str(build / "baseline.py"): sha["baseline"],
            str(build / "protected.py"): sha["protected"], str(tools_dir / "python.exe"): sha["py"],
            str(adapter_src): sha["adapter"]}

        def default_return(output_dir):
            output_dir = Path(output_dir)
            output_dir.mkdir()
            orig, prot = output_dir / "original", output_dir / "protected"
            orig.mkdir()
            prot.mkdir()
            for rel in ("main.py", "data.txt"):
                data = (source_root / rel).read_bytes()
                (orig / rel).write_bytes(data)
                (prot / rel).write_bytes(data)
            (orig / "core.py").write_bytes(_CORE_SRC)   # raw original selected source
            (prot / "core.py").write_bytes(protected)   # reused protected artifact
            (output_dir / "bootstrap.py").write_bytes(_BOOTSTRAP)
            return {
                "language": "python", "original_root": str(orig), "protected_root": str(prot),
                "runtime_entrypoint": "main.py", "protected_relative": "core.py",
                "preparation_commands": [],
                "file_maps": {
                    "original": {"main.py": sha["main"], "data.txt": sha["data"], "core.py": sha["core_src"]},
                    "protected": {"main.py": sha["main"], "data.txt": sha["data"], "core.py": sha["protected"]}},
                "protected_sha256": sha["protected"], "original_core_sha256": sha["core_src"],
                "reference_evidence": {
                    "module_execution": {"module": "main", "runtime_entrypoint": "main.py",
                                         "package_chain": [], "is_package": False},
                    "runpy_bootstrap": {"path": str(output_dir / "bootstrap.py"), "sha256": sha["bootstrap"],
                                        "run_name": "__main__", "interpreter_flags": ["-I", "-S", "-B"]}},
                "limitations": []}

        class FakeAdapter:
            RUNPY_BOOTSTRAP = _BOOTSTRAP.decode("utf-8")

            def prepare_application(self, *, output_dir, **_):
                result = default_return(output_dir)
                if adapter_return is not None:
                    result = adapter_return(result)
                _persist_prep(output_dir, result)
                return result

        self._patch(mod, "_pin_support_modules", lambda name, pins: {})
        self._patch(mod, "_load_adapter", lambda language, pins: {
            "name": "fake.adapter", "path": str(adapter_src), "sha256": sha["adapter"], "module": FakeAdapter()})

        def default_run_logged(argv, directory, log_prefix, timeout, env=None, stdin=None, *, cancel_file=None):
            core_present = (Path(directory) / "core.py").is_file()
            proc = _clean_receipt(Path(log_prefix), 0 if core_present else 1,
                                  "ok" if core_present else "", "" if core_present else "ImportError: core")
            proc["argv"] = [str(x) for x in argv]
            Path(log_prefix).with_suffix(".process.json").write_text(json.dumps(proc, indent=2), encoding="utf-8")
            return proc

        self._patch(mod.process, "run_logged", run_logged or default_run_logged)
        return {"language": "python", "source_root": source_root, "input_files": input_files,
                "producer": producer, "spec": spec, "contract": contract,
                "output_dir": tmp / "engine_out", "tools": tools, "trusted_inputs": trusted_inputs,
                "timeout_seconds": 60, "stop_file": tmp / "STOP"}

    # ----- JavaScript (mixed, raw-preserving) scenario -----
    def _install_js(self):
        tmp = self.tmp
        source_root = tmp / "proj"
        source_root.mkdir()
        (source_root / "app.js").write_bytes(_APP_JS)
        (source_root / "core.cjs").write_bytes(_CORE_CJS)
        (source_root / "data.json").write_bytes(_DATA_JSON)
        build = tmp / "build"
        build.mkdir()
        (build / "baseline.cjs").write_bytes(_BASE_CJS)
        (build / "protected.cjs").write_bytes(_PROT_CJS)
        tools_dir = tmp / "toolchain"
        tools_dir.mkdir()
        (tools_dir / "node.exe").write_bytes(b"MZ-fake-node")
        (tools_dir / "python.exe").write_bytes(b"MZ-fake-python")
        adapter_src = tmp / "fake_js_adapter.py"
        adapter_src.write_bytes(b"# fake js adapter\n")
        sha = {"app": _sha(_APP_JS), "core": _sha(_CORE_CJS), "data": _sha(_DATA_JSON),
               "base": _sha(_BASE_CJS), "prot": _sha(_PROT_CJS), "node": _sha(b"MZ-fake-node"),
               "py": _sha(b"MZ-fake-python"), "adapter": _sha(b"# fake js adapter\n")}
        producer = {
            "backend": "javascript_mixed_module_vm", "status": "artifact_created_unvalidated",
            "project": {"language": "javascript", "source_sha256": sha["core"]},
            "artifacts": {
                "baseline": {"path": str(build / "baseline.cjs"), "sha256": sha["base"], "bytes": len(_BASE_CJS)},
                "protected": {"path": str(build / "protected.cjs"), "sha256": sha["prot"], "bytes": len(_PROT_CJS)}},
            "coverage": {"runtime_hardening": {"external_resistance": "not_evaluated"}},
            "coverage_path": str(build / "coverage.json")}
        tools = {"python_executable": {"path": str(tools_dir / "python.exe"), "sha256": sha["py"]},
                 "node": {"path": str(tools_dir / "node.exe"), "sha256": sha["node"]}}
        spec = mod.validate_spec({"schema_version": 1, "kind": "script_application_integration",
                                  "language": "javascript", "protected_source": "core.cjs",
                                  "entrypoint": "app.js",
                                  "application_files": ["app.js", "core.cjs", "data.json"]})
        contract = _contract([{"label": "ok", "args": [], "expect": {"returncode": 0, "stdout": "ok"}}])
        input_files = {"app.js": sha["app"], "core.cjs": sha["core"], "data.json": sha["data"]}
        trusted_inputs = {
            str(source_root / "app.js"): sha["app"], str(source_root / "core.cjs"): sha["core"],
            str(source_root / "data.json"): sha["data"], str(build / "baseline.cjs"): sha["base"],
            str(build / "protected.cjs"): sha["prot"], str(tools_dir / "node.exe"): sha["node"],
            str(tools_dir / "python.exe"): sha["py"], str(adapter_src): sha["adapter"]}

        class FakeJsAdapter:
            def prepare_application(self, *, output_dir, **_):
                output_dir = Path(output_dir)
                output_dir.mkdir()
                orig, prot = output_dir / "original", output_dir / "protected"
                orig.mkdir()
                prot.mkdir()
                for rel in ("app.js", "data.json"):
                    data = (source_root / rel).read_bytes()
                    (orig / rel).write_bytes(data)
                    (prot / rel).write_bytes(data)
                (orig / "core.cjs").write_bytes(_CORE_CJS)
                (prot / "core.cjs").write_bytes(_PROT_CJS)
                result = {
                    "language": "javascript", "original_root": str(orig), "protected_root": str(prot),
                    "runtime_entrypoint": "app.js", "protected_relative": "core.cjs",
                    "preparation_commands": [],
                    "file_maps": {
                        "original": {"app.js": sha["app"], "data.json": sha["data"], "core.cjs": sha["core"]},
                        "protected": {"app.js": sha["app"], "data.json": sha["data"], "core.cjs": sha["prot"]}},
                    "protected_sha256": sha["prot"], "original_core_sha256": sha["core"],
                    "reference_evidence": {}, "limitations": []}
                _persist_prep(output_dir, result)
                return result

        self._patch(mod, "_pin_support_modules", lambda name, pins: {})
        self._patch(mod, "_load_adapter", lambda language, pins: {
            "name": "fake.js", "path": str(adapter_src), "sha256": sha["adapter"], "module": FakeJsAdapter()})

        def run_logged(argv, directory, log_prefix, timeout, env=None, stdin=None, *, cancel_file=None):
            core_present = (Path(directory) / "core.cjs").is_file()
            proc = _clean_receipt(Path(log_prefix), 0 if core_present else 1,
                                  "ok" if core_present else "", "" if core_present else "Cannot find module")
            proc["argv"] = [str(x) for x in argv]
            Path(log_prefix).with_suffix(".process.json").write_text(json.dumps(proc, indent=2), encoding="utf-8")
            return proc

        self._patch(mod.process, "run_logged", run_logged)
        return {"language": "javascript", "source_root": source_root, "input_files": input_files,
                "producer": producer, "spec": spec, "contract": contract,
                "output_dir": tmp / "engine_out", "tools": tools, "trusted_inputs": trusted_inputs,
                "timeout_seconds": 60, "stop_file": tmp / "STOP"}

    # ----- TypeScript (independent reference) scenario -----
    def _install_ts(self, *, drop_prep=False):
        tmp = self.tmp
        source_root = tmp / "proj"
        source_root.mkdir()
        (source_root / "app.ts").write_bytes(_APP_TS)
        (source_root / "core.ts").write_bytes(_CORE_TS)
        (source_root / "data.json").write_bytes(_DATA_JSON)
        build = tmp / "build"
        build.mkdir()
        (build / "baseline.cjs").write_bytes(_BASE_CJS_T)
        (build / "protected.cjs").write_bytes(_CORE_CJS_PROT)
        tools_dir = tmp / "toolchain"
        tools_dir.mkdir()
        for name, data in (("node.exe", b"MZ-node"), ("python.exe", b"MZ-py"), ("tsc.cmd", b"@tsc")):
            (tools_dir / name).write_bytes(data)
        adapter_src = tmp / "fake_ts_adapter.py"
        adapter_src.write_bytes(b"# fake ts adapter\n")
        sha = {"app_ts": _sha(_APP_TS), "core_ts": _sha(_CORE_TS), "data": _sha(_DATA_JSON),
               "app_js": _sha(_APP_JS_T), "core_ref": _sha(_CORE_CJS_REF), "prot": _sha(_CORE_CJS_PROT),
               "base": _sha(_BASE_CJS_T), "node": _sha(b"MZ-node"), "py": _sha(b"MZ-py"),
               "tsc": _sha(b"@tsc"), "adapter": _sha(b"# fake ts adapter\n")}
        producer = {
            "backend": "javascript_vm", "status": "artifact_created_unvalidated",
            "project": {"language": "typescript", "source_sha256": sha["core_ts"]},
            "artifacts": {
                "baseline": {"path": str(build / "baseline.cjs"), "sha256": sha["base"], "bytes": len(_BASE_CJS_T)},
                "protected": {"path": str(build / "protected.cjs"), "sha256": sha["prot"], "bytes": len(_CORE_CJS_PROT)}},
            "coverage": {"runtime_hardening": {"external_resistance": "not_evaluated"}},
            "coverage_path": str(build / "coverage.json")}
        tools = {"python_executable": {"path": str(tools_dir / "python.exe"), "sha256": sha["py"]},
                 "node": {"path": str(tools_dir / "node.exe"), "sha256": sha["node"]},
                 "typescript": {"path": str(tools_dir / "tsc.cmd"), "sha256": sha["tsc"]}}
        spec = mod.validate_spec({"schema_version": 1, "kind": "script_application_integration",
                                  "language": "typescript", "protected_source": "core.ts",
                                  "entrypoint": "app.ts",
                                  "application_files": ["app.ts", "core.ts", "data.json"]})
        contract = _contract([{"label": "ok", "args": [], "expect": {"returncode": 0, "stdout": "ok"}}])
        input_files = {"app.ts": sha["app_ts"], "core.ts": sha["core_ts"], "data.json": sha["data"]}
        trusted_inputs = {
            str(source_root / "app.ts"): sha["app_ts"], str(source_root / "core.ts"): sha["core_ts"],
            str(source_root / "data.json"): sha["data"], str(build / "baseline.cjs"): sha["base"],
            str(build / "protected.cjs"): sha["prot"], str(tools_dir / "node.exe"): sha["node"],
            str(tools_dir / "python.exe"): sha["py"], str(tools_dir / "tsc.cmd"): sha["tsc"],
            str(adapter_src): sha["adapter"]}

        class FakeTsAdapter:
            def prepare_application(self, *, output_dir, **_):
                output_dir = Path(output_dir)
                output_dir.mkdir()
                orig, prot = output_dir / "original", output_dir / "protected"
                orig.mkdir()
                prot.mkdir()
                for root in (orig, prot):
                    (root / "app.js").write_bytes(_APP_JS_T)
                    (root / "data.json").write_bytes(_DATA_JSON)
                (orig / "core.cjs").write_bytes(_CORE_CJS_REF)
                (prot / "core.cjs").write_bytes(_CORE_CJS_PROT)
                prepdir = output_dir / "prep"
                prepdir.mkdir()
                prefix = prepdir / "001"
                proc = _clean_receipt(prefix, 0, "transpiled core.ts -> core.cjs", "")
                proc["argv"] = [str(tools_dir / "tsc.cmd"), "--module", "commonjs"]
                receipt = prefix.with_suffix(".process.json")
                receipt.write_text(json.dumps(proc, indent=2), encoding="utf-8")
                prep = [] if drop_prep else [{
                    "label": "transpile-core", "kind": "typescript_transpile",
                    "receipt_path": str(receipt), "receipt_sha256": _sha(receipt.read_bytes()),
                    "stdout_log": proc["stdout"], "stderr_log": proc["stderr"]}]
                result = {
                    "language": "typescript", "original_root": str(orig), "protected_root": str(prot),
                    "runtime_entrypoint": "app.js", "protected_relative": "core.cjs",
                    "preparation_commands": prep,
                    "file_maps": {
                        "original": {"app.js": sha["app_js"], "data.json": sha["data"], "core.cjs": sha["core_ref"]},
                        "protected": {"app.js": sha["app_js"], "data.json": sha["data"], "core.cjs": sha["prot"]}},
                    "protected_sha256": sha["prot"], "original_core_sha256": sha["core_ref"],
                    "reference_evidence": {"compiler": "tsc", "module": "commonjs",
                                           "declaration": False, "source_map": False},
                    "limitations": ["sampled functional equivalence only"]}
                _persist_prep(output_dir, result)
                return result

        self._patch(mod, "_pin_support_modules", lambda name, pins: {})
        self._patch(mod, "_load_adapter", lambda language, pins: {
            "name": "fake.ts", "path": str(adapter_src), "sha256": sha["adapter"], "module": FakeTsAdapter()})

        def run_logged(argv, directory, log_prefix, timeout, env=None, stdin=None, *, cancel_file=None):
            core_present = (Path(directory) / "core.cjs").is_file()
            proc = _clean_receipt(Path(log_prefix), 0 if core_present else 1,
                                  "ok" if core_present else "", "" if core_present else "Cannot find module")
            proc["argv"] = [str(x) for x in argv]
            Path(log_prefix).with_suffix(".process.json").write_text(json.dumps(proc, indent=2), encoding="utf-8")
            return proc

        self._patch(mod.process, "run_logged", run_logged)
        return {"language": "typescript", "source_root": source_root, "input_files": input_files,
                "producer": producer, "spec": spec, "contract": contract,
                "output_dir": tmp / "engine_out", "tools": tools, "trusted_inputs": trusted_inputs,
                "timeout_seconds": 60, "stop_file": tmp / "STOP"}

    # ----------------------------- Python tests ----------------------------- #
    def test_happy_path_python(self):
        report = mod.run_integration(**self._install_python())
        self.assertEqual(report["status"], "script_application_samples_passed", report.get("error"))
        self.assertIs(report["fresh_protected_build"], False)
        self.assertEqual(report["external_resistance"], "not_evaluated")
        self.assertEqual(report["performance_acceptance"], "not_evaluated")
        self.assertIs(report["whole_application_verified"], False)
        self.assertIs(report["published"], False)
        self.assertEqual(report["comparison"]["status"], "producer_bound_integration_passed")
        self.assertEqual(report["comparison"]["total_cases"], 1)
        self.assertIs(report["comparison"]["missing_module_control_ok"], True)
        self.assertEqual(len(report["comparison"]["commands"]), 4)
        self.assertEqual(len({c["receipt_path"] for c in report["comparison"]["commands"]}), 4)
        self.assertIs(report["comparison"]["cases"][0]["match"], True)
        self.assertEqual(set(report["comparison"]["cases"][0]["results"]),
                         {"original", "protected", "deployment"})
        ctrl = report["comparison"]["controls"][0]
        self.assertIs(ctrl["failed_as_required"], True)
        self.assertNotEqual(ctrl["returncode"], 0)
        self.assertEqual(ctrl["removed_module"], "core.py")
        dep = report["deployment"]
        self.assertEqual(dep["protected_module"], "core.py")
        self.assertEqual(dep["runtime_entrypoint"], "main.py")
        self.assertEqual(sorted(dep["allowlist"]), ["core.py", "data.txt", "main.py"])
        self.assertIs(dep["forbidden_absent"], True)
        self.assertIs(report["trusted_inputs_verification"]["postflight_verified"], True)
        # Python argv is [python, -I, -S, -B, bootstrap, stage_root, module, *args].
        argv = report["comparison"]["commands"][0]["argv"]
        self.assertEqual(argv[1:4], ["-I", "-S", "-B"])
        self.assertEqual(argv[-1], "main")

    def test_persisted_report_is_parse_identical(self):
        kwargs = self._install_python()
        report = mod.run_integration(**kwargs)
        persisted = json.loads((kwargs["output_dir"] / "integration.json").read_text(encoding="utf-8"))
        self.assertEqual(persisted, report)

    def test_case_mismatch_fails(self):
        kwargs = self._install_python()
        kwargs["contract"] = _contract([{"label": "ok", "args": [],
                                         "expect": {"returncode": 0, "stdout": "DIFFERENT"}}])
        report = mod.run_integration(**kwargs)
        self.assertEqual(report["status"], "failed")
        self.assertIn("did not match", report["error"])

    def test_control_must_fail(self):
        def always_ok(argv, directory, log_prefix, timeout, env=None, stdin=None, *, cancel_file=None):
            proc = _clean_receipt(Path(log_prefix), 0, "ok", "")
            proc["argv"] = [str(x) for x in argv]
            Path(log_prefix).with_suffix(".process.json").write_text(json.dumps(proc, indent=2), encoding="utf-8")
            return proc

        report = mod.run_integration(**self._install_python(run_logged=always_ok))
        self.assertEqual(report["status"], "failed")
        self.assertIn("control did not fail", report["error"])

    def test_bad_adapter_keys_fail(self):
        kwargs = self._install_python(adapter_return=lambda r: {k: v for k, v in r.items() if k != "limitations"})
        report = mod.run_integration(**kwargs)
        self.assertEqual(report["status"], "failed")
        self.assertIn("agreed contract", report["error"])

    def test_protected_equals_original_core_fails(self):
        def tamper(r):
            r["protected_sha256"] = r["original_core_sha256"]
            r["file_maps"]["protected"]["core.py"] = r["original_core_sha256"]
            return r

        report = mod.run_integration(**self._install_python(adapter_return=tamper))
        self.assertEqual(report["status"], "failed")
        self.assertIn("byte-identical", report["error"])

    def test_staged_core_not_pinned_producer_artifact_fails(self):
        def tamper(r):
            bad = _sha(b"some other protected bytes")
            r["protected_sha256"] = bad
            r["file_maps"]["protected"]["core.py"] = bad
            return r

        report = mod.run_integration(**self._install_python(adapter_return=tamper))
        self.assertEqual(report["status"], "failed")
        self.assertIn("pinned producer protected artifact", report["error"])

    def test_stop_during_run_is_cancelled(self):
        kwargs = self._install_python()
        stop = kwargs["stop_file"]

        def stop_then_ok(argv, directory, log_prefix, timeout, env=None, stdin=None, *, cancel_file=None):
            core_present = (Path(directory) / "core.py").is_file()
            proc = _clean_receipt(Path(log_prefix), 0 if core_present else 1, "ok" if core_present else "", "")
            proc["argv"] = [str(x) for x in argv]
            Path(log_prefix).with_suffix(".process.json").write_text(json.dumps(proc, indent=2), encoding="utf-8")
            stop.write_text("STOP", encoding="utf-8")
            return proc

        self._patch(mod.process, "run_logged", stop_then_ok)
        report = mod.run_integration(**kwargs)
        self.assertEqual(report["status"], "cancelled")

    def test_preflight_stop_raises(self):
        kwargs = self._install_python()
        kwargs["stop_file"].write_text("STOP", encoding="utf-8")
        with self.assertRaises(safe.JvmIntegrateError):
            mod.run_integration(**kwargs)

    def test_producer_identical_artifacts_raise(self):
        with self.assertRaises(ScriptIntegrateError) as cm:
            mod.run_integration(**self._install_python(baseline=_PROTECTED, protected=_PROTECTED))
        self.assertIn("no protection applied", str(cm.exception))

    def test_rejects_non_fresh_output(self):
        kwargs = self._install_python()
        kwargs["output_dir"].mkdir()
        with self.assertRaises(ScriptIntegrateError):
            mod.run_integration(**kwargs)

    def test_timeout_bounds(self):
        kwargs = self._install_python()
        kwargs["timeout_seconds"] = 0
        with self.assertRaises(ScriptIntegrateError):
            mod.run_integration(**kwargs)

    def test_overall_deadline_includes_preflight(self):
        kwargs = self._install_python()
        with mock.patch.object(mod.time, "monotonic", side_effect=[0.0, 61.0]):
            report = mod.run_integration(**kwargs)
        self.assertEqual(report["status"], "failed")
        self.assertIn("overall integration execution deadline", report["error"])
        self.assertFalse((kwargs["output_dir"] / "staging").exists())

    def test_interpreter_drift_between_children_is_rejected(self):
        state = {"calls": 0}
        holder = {}

        def drift(argv, directory, log_prefix, timeout, env=None, stdin=None, *, cancel_file=None):
            core_present = (Path(directory) / "core.py").is_file()
            proc = _clean_receipt(Path(log_prefix), 0 if core_present else 1, "ok" if core_present else "", "")
            proc["argv"] = [str(x) for x in argv]
            Path(log_prefix).with_suffix(".process.json").write_text(json.dumps(proc, indent=2), encoding="utf-8")
            state["calls"] += 1
            if state["calls"] == 1:
                Path(holder["python"]).write_bytes(b"TAMPERED-interpreter-bytes")
            return proc

        kwargs = self._install_python(run_logged=drift)
        holder["python"] = kwargs["tools"]["python_executable"]["path"]
        report = mod.run_integration(**kwargs)
        self.assertEqual(report["status"], "failed")
        self.assertIn("pinned input changed", report["error"])

    def test_control_copy_tamper_is_rejected(self):
        # Adding a stray file into the control copy during its run breaks the exact
        # control inventory check.
        def tamper(argv, directory, log_prefix, timeout, env=None, stdin=None, *, cancel_file=None):
            core_present = (Path(directory) / "core.py").is_file()
            proc = _clean_receipt(Path(log_prefix), 0 if core_present else 1, "ok" if core_present else "", "")
            proc["argv"] = [str(x) for x in argv]
            Path(log_prefix).with_suffix(".process.json").write_text(json.dumps(proc, indent=2), encoding="utf-8")
            if not core_present:  # the missing-module control copy
                (Path(directory) / "stray.py").write_bytes(b"injected\n")
            return proc

        report = mod.run_integration(**self._install_python(run_logged=tamper))
        self.assertEqual(report["status"], "failed")
        self.assertIn("control copy", report["error"])

    # ----------------------------- JS / TS tests ---------------------------- #
    def test_happy_path_javascript(self):
        report = mod.run_integration(**self._install_js())
        self.assertEqual(report["status"], "script_application_samples_passed", report.get("error"))
        self.assertIsNone(report["staging"]["module"])
        self.assertIsNone(report["staging"]["bootstrap"])
        node_cmd = report["comparison"]["commands"][0]["argv"]
        self.assertEqual(node_cmd[1], "--no-addons")
        self.assertTrue(node_cmd[2].endswith("app.js"))
        self.assertEqual(report["deployment"]["protected_module"], "core.cjs")
        self.assertIs(report["comparison"]["controls"][0]["failed_as_required"], True)

    def test_happy_path_typescript(self):
        kwargs = self._install_ts()
        report = mod.run_integration(**kwargs)
        self.assertEqual(report["status"], "script_application_samples_passed", report.get("error"))
        staging = report["staging"]
        self.assertNotEqual(staging["original_core_sha256"], kwargs["input_files"]["core.ts"])
        self.assertNotEqual(staging["original_core_sha256"], report["producer"]["baseline"]["sha256"])
        self.assertEqual(staging["protected_sha256"], report["producer"]["protected"]["sha256"])
        prep = staging["preparation_commands"]
        self.assertEqual(len(prep), 1)
        self.assertTrue({"receipt_path", "receipt_sha256", "stdout_log", "stderr_log",
                         "label", "kind", "returncode"} <= set(prep[0]))
        self.assertNotIn("core.ts", staging["file_maps"]["protected"])
        self.assertNotIn("core.ts", staging["file_maps"]["original"])
        self.assertIs(report["comparison"]["cases"][0]["match"], True)

    def test_typescript_without_prep_receipt_fails(self):
        report = mod.run_integration(**self._install_ts(drop_prep=True))
        self.assertEqual(report["status"], "failed")
        self.assertIn("compiler receipts", report["error"])


if __name__ == "__main__":
    unittest.main()
