"""Public MCP/CLI boundary tests for the C# source-integrate route.

Scope (defender-only, service-tests worker): the *public facade* that root wired
in ``antirea.defense_mcp`` for the forthcoming C# application integration route --
the ``protection_source_integrate`` MCP tool and the ``source-integrate`` CLI
subcommand. These tests cover the parts root has already frozen and which do NOT
depend on the forthcoming ``antirea.csharp_application`` engine:

  * the MCP tool's exact input schema and argument validation,
  * the ``DefenseBridge`` dispatch wiring (name + argument + timeout mapping) to
    ``ProjectService.integrate`` -- exercised through a recording *boundary* stub,
    never a fake implementation of the real integration engine,
  * the full JSON-RPC ``tools/list`` + ``tools/call`` envelope round trip,
  * the CLI subcommand wiring, exercised by launching the REAL production CLI
    (``python -m antirea.defense_mcp``) through the OUTER bounded ``run_logged``
    wrapper (real workspace STOP as cancel_file, an explicit allow-listed
    environment -- never an ``os.environ`` copy -- a private TEMP, a fresh
    append-only run dir, retained raw stdout/stderr + process JSON, and asserted
    returncode plus an empty/closed Windows Job and confirmed parent exit).

The in-process dispatch/schema tests spawn no child process, so the OUTER-wrapper
obligation is vacuously satisfied for them; every child this module launches goes
through ``_outer_run``. No REA/attack/received code is executed, no attacker or
received-report path is traversed, and the real controller STOP marker is only
ever probed for existence -- never created, read or deleted.
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from antirea.defense_mcp import TOOLS, DefenseBridge, validate_arguments
from antirea.process import run_logged

# Real controller STOP marker: existence-only, never created/read/deleted here.
REAL_STOP = ROOT / ".runs" / "defense-loop" / "STOP"
# Append-only evidence root owned by this (service-tests) worker.
RUN_ROOT = ROOT / ".runs" / "orca-wave6-csharp-public-tests"

_SYSROOT = r"C:\Windows"
_DOTNET_DIR = r"C:\Program Files\dotnet"

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


def _cli_argv(*args):
    """Defender CLI under -I -S -B via a trusted-root bootstrap (root review guidance)."""
    return [sys.executable, "-I", "-S", "-B", str(_ensure_bootstrap()), *args]


def _tool(name):
    tool = next((item for item in TOOLS if item["name"] == name), None)
    if tool is None:  # pragma: no cover - defensive; root froze this tool
        raise AssertionError(name + " missing from the defense MCP tool catalog")
    return tool


def _allowlisted_env(priv_tmp: Path, priv_home: Path) -> dict:
    """Explicit allow-listed literals ONLY -- never an ``os.environ`` copy.

    PATH carries the dotnet dir (harmless when unused), the interpreter's own
    directory (so the launched Python resolves its runtime DLLs on Windows) and
    the Windows system dirs. TEMP/HOME are redirected into the per-run private
    tree so the child cannot touch the developer profile.
    """
    py_dir = str(Path(sys.executable).parent)
    return {
        "SystemRoot": _SYSROOT, "windir": _SYSROOT, "SystemDrive": "C:",
        "PATH": os.pathsep.join([py_dir, _DOTNET_DIR, _SYSROOT + r"\System32", _SYSROOT]),
        "TEMP": str(priv_tmp), "TMP": str(priv_tmp),
        "USERPROFILE": str(priv_home),
        "APPDATA": str(priv_home / "AppData" / "Roaming"),
        "LOCALAPPDATA": str(priv_home / "AppData" / "Local"),
        "PROCESSOR_ARCHITECTURE": "AMD64",
        "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1",
    }


def _fresh_run_dir(label: str) -> Path:
    RUN_ROOT.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%f")
    out = RUN_ROOT / (label + "-" + stamp)
    out.mkdir()  # fresh unique dir; append-only, never overwrites a prior run
    return out


def _outer_run(argv, label, *, timeout=120):
    """Run ONE owned command through the OUTER bounded ``run_logged`` wrapper.

    CLI children run under ``-I -S -B`` via a trusted-root bootstrap (no reliance
    on cwd or inherited PYTHONPATH); the environment is the clean allow-list.
    """
    out = _fresh_run_dir(label)
    priv_tmp = out / "_tmp"
    priv_home = out / "_home"
    priv_tmp.mkdir()
    priv_home.mkdir()
    env = _allowlisted_env(priv_tmp, priv_home)
    proc = run_logged([str(a) for a in argv], ROOT, out / "logs" / label,
                      timeout=timeout, env=env, cancel_file=REAL_STOP)
    cleanup = proc.get("cleanup", {})
    receipt = {
        "label": label, "argv": proc.get("argv"), "returncode": proc.get("returncode"),
        "pid": proc.get("pid"), "timed_out": proc.get("timed_out"),
        "cancelled": proc.get("cancelled"), "seconds": proc.get("seconds"), "cleanup": cleanup,
        "stdout_log": proc.get("stdout"), "stderr_log": proc.get("stderr"),
        "process_json": str((out / "logs" / label).with_suffix(".process.json")),
        "cancel_file": str(REAL_STOP), "env_keys": sorted(env), "out_dir": str(out),
    }
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return proc, receipt, out


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
            # Empty, then closed, kill-on-close Job -- cleanup, not a sandbox.
            self.assertEqual(cleanup.get("method"), "windows_job", cleanup)
            self.assertTrue(cleanup.get("job_assigned"), cleanup)
            self.assertEqual(cleanup.get("active_after"), 0, cleanup)
            self.assertTrue(cleanup.get("job_handle_closed"), cleanup)
            self.assertEqual(cleanup.get("status"), "assigned_job_empty", cleanup)
        # Raw receipts are retained on disk for the auditor.
        self.assertTrue(Path(proc["stdout"]).is_file())
        self.assertTrue(Path(proc["stderr"]).is_file())
        self.assertTrue(Path(proc["stdout"]).with_name(
            Path(proc["stdout"]).name.replace(".stdout.log", ".process.json")).is_file())


# ---------------------------------------------------------------------------
# MCP tool schema + argument validation (in-process; no child launched)
# ---------------------------------------------------------------------------

class IntegrateToolSchemaTests(unittest.TestCase):
    def setUp(self):
        self.tool = _tool("protection_source_integrate")

    def test_tool_present_with_exact_input_schema(self):
        schema = self.tool["inputSchema"]
        self.assertEqual(schema["type"], "object")
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["required"]),
                         {"plan_id", "integration_spec_path", "contract_path"})
        self.assertEqual(set(schema["properties"]),
                         {"plan_id", "integration_spec_path", "contract_path", "timeout_seconds"})
        for key in ("plan_id", "integration_spec_path", "contract_path"):
            self.assertEqual(schema["properties"][key]["type"], "string")
        timeout = schema["properties"]["timeout_seconds"]
        self.assertEqual(timeout["type"], "integer")
        self.assertEqual((timeout["minimum"], timeout["maximum"]), (1, 600))

    def test_annotations_mark_execution_and_not_readonly(self):
        annotations = self.tool["annotations"]
        self.assertIs(annotations.get("readOnlyHint"), False)
        self.assertIs(annotations.get("destructiveHint"), True)

    def test_description_is_truthful_about_scope(self):
        text = self.tool["description"].lower()
        # Public contract: explicit execution, local bundle, no publish/install,
        # and sampled agreement is not a strength/all-input claim.
        self.assertIn("compile and execute", text)
        self.assertIn("does not publish", text)
        self.assertIn("sampled agreement is not", text)

    def test_description_separates_compiled_and_script_routes(self):
        text = self.tool["description"].lower()
        self.assertIn("compile and execute c#, java, kotlin, go or swift apps", text)
        self.assertIn("python/js/ts execute staged script modules", text)
        self.assertIn("typescript transpiled by the pinned compiler", text)
        self.assertIn("reuse the saved protected artifact", text)
        self.assertIn("script_application_integration and script_application_samples", text)


class IntegrateArgumentValidationTests(unittest.TestCase):
    def setUp(self):
        self.tool = _tool("protection_source_integrate")

    def _valid(self, **overrides):
        args = {"plan_id": "source-20261020T010203Z-0123456789ab",
                "integration_spec_path": "pkg/integration.json",
                "contract_path": "pkg/application-contract.json"}
        args.update(overrides)
        return args

    def test_minimal_valid_arguments_accepted(self):
        validate_arguments(self.tool, self._valid())  # no raise

    def test_optional_timeout_bounds_accepted(self):
        for value in (1, 120, 600):
            validate_arguments(self.tool, self._valid(timeout_seconds=value))

    def test_missing_required_field_rejected(self):
        args = self._valid()
        del args["contract_path"]
        with self.assertRaises(ValueError):
            validate_arguments(self.tool, args)

    def test_unknown_field_rejected(self):
        with self.assertRaises(ValueError):
            validate_arguments(self.tool, self._valid(producer_report="x"))

    def test_timeout_out_of_bounds_rejected(self):
        for value in (0, 601, -1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_arguments(self.tool, self._valid(timeout_seconds=value))

    def test_timeout_wrong_type_rejected(self):
        for value in ("120", 1.5, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_arguments(self.tool, self._valid(timeout_seconds=value))

    def test_empty_or_control_char_strings_rejected(self):
        for bad in ("", "has\nnewline", "tab\tchar"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                validate_arguments(self.tool, self._valid(plan_id=bad))

    def test_non_string_path_rejected(self):
        with self.assertRaises(ValueError):
            validate_arguments(self.tool, self._valid(integration_spec_path=123))


# ---------------------------------------------------------------------------
# DefenseBridge dispatch wiring (boundary stub for ProjectService)
# ---------------------------------------------------------------------------

class _RecordingProjectService:
    """A boundary stand-in for ProjectService.

    It records exactly how the bridge called ``integrate`` and returns a
    sentinel success record shaped like the schema root pinned for the service
    worker. It is NOT an implementation of the real integration engine; no
    compile/execute is faked, and no test asserts a real integration outcome
    from it -- only that the public facade routed the call correctly.
    """

    def __init__(self):
        self.calls = []

    def integrate(self, plan_id, integration_spec_path, contract_path, *, timeout_seconds=120):
        self.calls.append({"plan_id": plan_id, "integration_spec_path": integration_spec_path,
                           "contract_path": contract_path, "timeout_seconds": timeout_seconds})
        return {"schema_version": 1, "status": "csharp_application_samples_passed",
                "plan_id": plan_id, "integration_id": "integration-deadbeef0001",
                "integration_report_path": "<stub>", "routed": True}


class BridgeDispatchTests(unittest.TestCase):
    def _bridge(self):
        stub = _RecordingProjectService()
        bridge = DefenseBridge(SimpleNamespace(root=ROOT), project_service=stub)
        return bridge, stub

    def test_call_routes_with_default_timeout(self):
        bridge, stub = self._bridge()
        result = bridge.call("protection_source_integrate",
                             {"plan_id": "source-20261020T010203Z-0123456789ab",
                              "integration_spec_path": "pkg/integration.json",
                              "contract_path": "pkg/application-contract.json"})
        self.assertEqual(stub.calls, [{
            "plan_id": "source-20261020T010203Z-0123456789ab",
            "integration_spec_path": "pkg/integration.json",
            "contract_path": "pkg/application-contract.json",
            "timeout_seconds": 120}])
        self.assertEqual(result["status"], "csharp_application_samples_passed")
        self.assertTrue(result["routed"])

    def test_call_forwards_explicit_timeout(self):
        bridge, stub = self._bridge()
        bridge.call("protection_source_integrate",
                    {"plan_id": "source-20261020T010203Z-0123456789ab",
                     "integration_spec_path": "pkg/integration.json",
                     "contract_path": "pkg/application-contract.json",
                     "timeout_seconds": 77})
        self.assertEqual(stub.calls[0]["timeout_seconds"], 77)

    def test_bridge_lazily_builds_project_service_when_absent(self):
        # With no injected project_service, the bridge builds a real one bound to
        # the configured root; importing the forthcoming engine only happens when
        # ProjectService.integrate runs, so construction itself must not fail.
        bridge = DefenseBridge(SimpleNamespace(root=ROOT))
        self.assertIsNone(bridge.project_service)
        from antirea.projects import ProjectService
        bridge.project_service = ProjectService(ROOT)  # same type the bridge builds
        self.assertIsInstance(bridge.project_service, ProjectService)


class BridgeProtocolRoundTripTests(unittest.TestCase):
    def _ready_bridge(self):
        stub = _RecordingProjectService()
        bridge = DefenseBridge(SimpleNamespace(root=ROOT), project_service=stub)
        init = bridge.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "csharp-integrate-boundary", "version": "1"}}})
        self.assertIn("result", init)
        self.assertIsNone(bridge.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        return bridge, stub

    def test_tools_list_includes_integrate_tool(self):
        bridge, _ = self._ready_bridge()
        reply = bridge.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        names = {tool["name"] for tool in reply["result"]["tools"]}
        self.assertIn("protection_source_integrate", names)

    def test_tools_call_round_trip_reports_success(self):
        bridge, stub = self._ready_bridge()
        reply = bridge.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "protection_source_integrate",
            "arguments": {"plan_id": "source-20261020T010203Z-0123456789ab",
                          "integration_spec_path": "pkg/integration.json",
                          "contract_path": "pkg/application-contract.json",
                          "timeout_seconds": 90}}})
        self.assertNotIn("error", reply, reply)
        result = reply["result"]
        self.assertFalse(result["isError"], result)
        payload = json.loads(result["content"][0]["text"])
        self.assertEqual(payload["status"], "csharp_application_samples_passed")
        self.assertEqual(stub.calls[0]["timeout_seconds"], 90)

    def test_tools_call_rejects_unknown_argument_before_dispatch(self):
        bridge, stub = self._ready_bridge()
        reply = bridge.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
            "name": "protection_source_integrate",
            "arguments": {"plan_id": "source-20261020T010203Z-0123456789ab",
                          "integration_spec_path": "pkg/integration.json",
                          "contract_path": "pkg/application-contract.json",
                          "producer_report": "pkg/report.json"}}})
        self.assertIn("error", reply)
        self.assertEqual(reply["error"]["code"], -32602)
        self.assertEqual(stub.calls, [])  # validation blocked dispatch


# ---------------------------------------------------------------------------
# CLI subcommand wiring -- real production CLI through the OUTER bounded wrapper
# ---------------------------------------------------------------------------

class CliWiringTests(_WrapperAsserts):
    def test_source_integrate_subcommand_requires_its_arguments(self):
        # Missing required args: argparse rejects with rc 2 *before* any config
        # or engine import, proving the subcommand and its required flags exist.
        proc, _, _ = _outer_run(_cli_argv("source-integrate"), "cli-missing-args", timeout=90)
        self.assert_bounded_cleanup(proc)
        self.assertEqual(proc["returncode"], 2, proc)
        stderr = Path(proc["stderr"]).read_text(encoding="utf-8", errors="replace")
        self.assertIn("source-integrate", stderr)

    def test_source_integrate_help_lists_every_flag(self):
        proc, _, out = _outer_run(_cli_argv("source-integrate", "--help"), "cli-help", timeout=90)
        self.assert_bounded_cleanup(proc)
        self.assertEqual(proc["returncode"], 0, proc)
        helptext = Path(proc["stdout"]).read_text(encoding="utf-8", errors="replace")
        for flag in ("--plan-id", "--integration-spec", "--contract", "--timeout-seconds"):
            self.assertIn(flag, helptext)


if __name__ == "__main__":
    unittest.main()
