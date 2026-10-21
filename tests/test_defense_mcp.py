"""Defense MCP boundary tests using only a fake service and in-memory streams.

No protection engine, binary, attacker, agent, or network service is launched.
"""
from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import unittest
from unittest.mock import patch

from antirea import defense_mcp


TOOLS = {
    "protection_languages", "protection_source_plan", "protection_source_build", "protection_bindings",
    "protection_source_validate", "protection_source_integrate",
    "protection_providers", "protection_doctor", "protection_plan",
    "protection_protect", "protection_job",
    "protection_generate_project", "protection_benchmark", "protection_auto_protect",
}
INITIALIZE = {
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {"protocolVersion": "2024-11-05", "capabilities": {},
               "clientInfo": {"name": "anti-rea-boundary-test", "version": "1.0"}},
}
INITIALIZED = {"jsonrpc": "2.0", "method": "notifications/initialized"}
FINGERPRINT = "a" * 64


class FakeService:
    def __init__(self):
        self.calls = []
        self.reply_status = "completed"
        self.raise_on = None

    def _result(self, method, arguments):
        self.calls.append((method, arguments))
        if self.raise_on == method:
            raise ValueError("controlled validation failure")
        return {"status": self.reply_status, "method": method, "arguments": arguments}

    def providers(self):
        return self._result("providers", {})

    def doctor(self, provider=None):
        return self._result("doctor", {"provider": provider})

    def plan(self, provider, input_path, project_path, timeout_seconds=600):
        return self._result("plan", {"provider": provider, "input_path": input_path,
                                     "project_path": project_path, "timeout_seconds": timeout_seconds})

    def protect(self, plan_id, fingerprint):
        return self._result("protect", {"plan_id": plan_id, "fingerprint": fingerprint})

    def job(self, job_id):
        return self._result("job", {"job_id": job_id})

    def generate_project(self, provider, input_path, *, functions=(), defense_level="max_vm",
                         min_speed_percent=80, output_project_path=None):
        return self._result("generate_project", {
            "provider": provider, "input_path": input_path, "functions": list(functions),
            "defense_level": defense_level, "min_speed_percent": min_speed_percent,
            "output_project_path": output_project_path,
        })

    def benchmark(self, baseline_path, candidate_path, *, test_inputs=(), min_speed_percent=80,
                  repeats=5, timeout_seconds=60):
        return self._result("benchmark", {
            "baseline_path": baseline_path, "candidate_path": candidate_path,
            "test_inputs": list(test_inputs), "min_speed_percent": min_speed_percent,
            "repeats": repeats, "timeout_seconds": timeout_seconds,
        })

    def auto_protect(self, provider, input_path, *, functions=(), defense_level="max_vm",
                     min_speed_percent=80, test_inputs=(), timeout_seconds=600):
        return self._result("auto_protect", {
            "provider": provider, "input_path": input_path, "functions": list(functions),
            "defense_level": defense_level, "min_speed_percent": min_speed_percent,
            "test_inputs": list(test_inputs), "timeout_seconds": timeout_seconds,
        })


def request(method, params=None, request_id=10):
    result = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        result["params"] = params
    return result


def call(name, arguments=None, request_id=10):
    return request("tools/call", {"name": name, "arguments": {} if arguments is None else arguments}, request_id)


def tool_payload(response):
    content = response["result"]["content"]
    if len(content) != 1 or content[0]["type"] != "text":
        raise AssertionError("tool result must have exactly one JSON text content block")
    return json.loads(content[0]["text"])


class DefenseBridgeTests(unittest.TestCase):
    def setUp(self):
        self.service = FakeService()
        self.bridge = defense_mcp.DefenseBridge(self.service)

    def ready(self):
        response = self.bridge.handle(INITIALIZE)
        self.assertNotIn("error", response)
        self.assertIsNone(self.bridge.handle(INITIALIZED))

    def assert_rpc_error(self, response, code=None):
        self.assertIsInstance(response, dict)
        self.assertEqual(response["jsonrpc"], "2.0")
        self.assertIn("error", response)
        self.assertNotIn("result", response)
        self.assertIsInstance(response["error"]["code"], int)
        self.assertLess(response["error"]["code"], 0)
        if code is not None:
            self.assertEqual(response["error"]["code"], code)

    def test_initialize_negotiates_supported_protocol_and_tool_capability(self):
        response = self.bridge.handle(INITIALIZE)
        self.assertEqual(response["id"], 1)
        self.assertEqual(response["jsonrpc"], "2.0")
        self.assertEqual(response["result"]["protocolVersion"], "2024-11-05")
        self.assertIn("tools", response["result"]["capabilities"])
        self.assertIsInstance(response["result"]["serverInfo"]["name"], str)
        self.assertIsInstance(response["result"]["serverInfo"]["version"], str)
        self.assertEqual(self.service.calls, [])

    def test_all_declared_protocol_versions_negotiate(self):
        for version in ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"):
            with self.subTest(version=version):
                bridge = defense_mcp.DefenseBridge(FakeService())
                initialize = {**INITIALIZE, "params": {**INITIALIZE["params"], "protocolVersion": version}}
                self.assertEqual(bridge.handle(initialize)["result"]["protocolVersion"], version)

    def test_unknown_protocol_negotiates_latest_supported_not_unknown_version(self):
        initialize = {**INITIALIZE, "params": {**INITIALIZE["params"], "protocolVersion": "1900-01-01"}}
        result = self.bridge.handle(initialize)["result"]
        self.assertEqual(result["protocolVersion"], defense_mcp.SUPPORTED_PROTOCOLS[-1])

    def test_ping_allowed_before_and_after_initialization(self):
        for index in range(2):
            response = self.bridge.handle(request("ping", request_id="ping-id"))
            self.assertEqual(response, {"jsonrpc": "2.0", "id": "ping-id", "result": {}})
            if index == 0:
                self.ready()
        self.assertEqual(self.service.calls, [])

    def test_tools_require_initialize_and_initialized_notification(self):
        self.assert_rpc_error(self.bridge.handle(request("tools/list")))
        self.assert_rpc_error(self.bridge.handle(call("protection_providers")))
        self.bridge.handle(INITIALIZE)
        self.assert_rpc_error(self.bridge.handle(request("tools/list")))
        self.assert_rpc_error(self.bridge.handle(call("protection_providers")))
        self.assertEqual(self.service.calls, [])
        self.bridge.handle(INITIALIZED)
        self.assertIn("result", self.bridge.handle(request("tools/list")))

    def test_initialized_notification_alone_does_not_establish_session(self):
        self.assertIsNone(self.bridge.handle(INITIALIZED))
        self.assert_rpc_error(self.bridge.handle(call("protection_providers")))
        self.assertEqual(self.service.calls, [])

    def test_invalid_initialization_params_do_not_enable_tools(self):
        invalid = [None, [], {}, {"protocolVersion": "2024-11-05"},
                   {**INITIALIZE["params"], "protocolVersion": 1},
                   {**INITIALIZE["params"], "capabilities": []},
                   {**INITIALIZE["params"], "clientInfo": "client"},
                   {**INITIALIZE["params"], "clientInfo": {"name": "client"}},
                   {**INITIALIZE["params"], "clientInfo": {"name": 1, "version": "1"}}]
        for params in invalid:
            with self.subTest(params=params):
                bridge = defense_mcp.DefenseBridge(self.service)
                self.assert_rpc_error(bridge.handle(request("initialize", params)), -32602)
                bridge.handle(INITIALIZED)
                self.assert_rpc_error(bridge.handle(call("protection_providers")))
        self.assertEqual(self.service.calls, [])

    def test_tool_catalog_is_closed_and_has_strict_object_schemas(self):
        self.ready()
        response = self.bridge.handle(request("tools/list"))
        tools = response["result"]["tools"]
        self.assertEqual({item["name"] for item in tools}, TOOLS)
        # The explicit name set is authoritative; the length also rejects duplicates.
        self.assertEqual(len(tools), len(TOOLS))
        for tool in tools:
            self.assertIsInstance(tool["description"], str)
            self.assertEqual(tool["inputSchema"]["type"], "object")
            self.assertIs(tool["inputSchema"].get("additionalProperties"), False)
        self.assertEqual(self.service.calls, [])

    def test_provider_and_doctor_routes(self):
        self.ready()
        for name, args, expected in (
            ("protection_providers", {}, ("providers", {})),
            ("protection_doctor", {}, ("doctor", {"provider": None})),
            ("protection_doctor", {"provider": "vmprotect"}, ("doctor", {"provider": "vmprotect"})),
        ):
            with self.subTest(name=name, args=args):
                response = self.bridge.handle(call(name, args))
                self.assertFalse(response["result"].get("isError", False))
                self.assertEqual(tool_payload(response)["method"], expected[0])
                self.assertEqual(self.service.calls[-1], expected)

    def test_plan_routes_with_default_and_explicit_timeouts_without_shell_interpolation(self):
        self.ready()
        # These are arguments, not a shell command. The service owns later path
        # admission; this boundary must not interpret punctuation as execution.
        args = {"provider": "vmprotect", "input_path": "C:/work/my app.exe",
                "project_path": "C:/work/protection profile.vmp"}
        for timeout in (None, 1, 3600):
            payload = dict(args)
            if timeout is not None:
                payload["timeout_seconds"] = timeout
            response = self.bridge.handle(call("protection_plan", payload))
            self.assertEqual(tool_payload(response)["method"], "plan")
            self.assertEqual(self.service.calls[-1], ("plan", {**args, "timeout_seconds": 600 if timeout is None else timeout}))

    def test_protect_requires_explicit_plan_and_fingerprint_and_job_routes(self):
        self.ready()
        response = self.bridge.handle(call("protection_protect", {"plan_id": "plan-test", "fingerprint": FINGERPRINT}))
        self.assertEqual(tool_payload(response)["method"], "protect")
        self.assertEqual(self.service.calls[-1], ("protect", {"plan_id": "plan-test", "fingerprint": FINGERPRINT}))
        response = self.bridge.handle(call("protection_job", {"job_id": "job-test"}))
        self.assertEqual(tool_payload(response)["method"], "job")
        self.assertEqual(self.service.calls[-1], ("job", {"job_id": "job-test"}))

    def test_generate_project_benchmark_and_auto_protect_routes(self):
        self.ready()
        gen_resp = self.bridge.handle(call("protection_generate_project", {
            "provider": "vmprotect", "input_path": "C:/work/app.exe",
            "functions": ["antirea_score", "antirea_mix"], "defense_level": "balanced", "min_speed_percent": 80,
        }))
        self.assertEqual(tool_payload(gen_resp)["method"], "generate_project")
        self.assertEqual(self.service.calls[-1], ("generate_project", {
            "provider": "vmprotect", "input_path": "C:/work/app.exe",
            "functions": ["antirea_score", "antirea_mix"], "defense_level": "balanced",
            "min_speed_percent": 80, "output_project_path": None,
        }))
        bench_resp = self.bridge.handle(call("protection_benchmark", {
            "baseline_path": "C:/work/app.exe", "candidate_path": "C:/work/app.protected.exe",
            "test_inputs": ["1 2\n"], "min_speed_percent": 80, "repeats": 3,
        }))
        self.assertEqual(tool_payload(bench_resp)["method"], "benchmark")
        self.assertEqual(self.service.calls[-1], ("benchmark", {
            "baseline_path": "C:/work/app.exe", "candidate_path": "C:/work/app.protected.exe",
            "test_inputs": ["1 2\n"], "min_speed_percent": 80, "repeats": 3, "timeout_seconds": 60,
        }))
        auto_resp = self.bridge.handle(call("protection_auto_protect", {
            "provider": "kagura", "input_path": "C:/work/app.exe",
            "defense_level": "max_vm", "min_speed_percent": 80,
        }))
        self.assertEqual(tool_payload(auto_resp)["method"], "auto_protect")
        self.assertEqual(self.service.calls[-1], ("auto_protect", {
            "provider": "kagura", "input_path": "C:/work/app.exe",
            "functions": [], "defense_level": "max_vm", "min_speed_percent": 80,
            "test_inputs": [], "timeout_seconds": 600,
        }))

    def test_unknown_tool_is_rejected_without_service_call(self):
        self.ready()
        for name in ("exec", "read_file", "run_rea", "protection_publish", "shell", "unknown"):
            with self.subTest(name=name):
                self.assert_rpc_error(self.bridge.handle(call(name)), -32602)
        self.assertEqual(self.service.calls, [])

    def test_unknown_argument_is_rejected_for_every_tool(self):
        self.ready()
        valid = {
            "protection_providers": {}, "protection_doctor": {},
            "protection_plan": {"provider": "vmprotect", "input_path": "app.exe", "project_path": "project.vmp"},
            "protection_protect": {"plan_id": "plan-test", "fingerprint": FINGERPRINT},
            "protection_job": {"job_id": "job-test"},
            "protection_generate_project": {"provider": "vmprotect", "input_path": "app.exe"},
            "protection_benchmark": {"baseline_path": "app.exe", "candidate_path": "app.protected.exe"},
            "protection_auto_protect": {"provider": "vmprotect", "input_path": "app.exe"},
        }
        for name, args in valid.items():
            with self.subTest(name=name):
                self.assert_rpc_error(self.bridge.handle(call(name, {**args, "command": "never run"})), -32602)
        self.assertEqual(self.service.calls, [])

    def test_missing_required_arguments_rejected(self):
        self.ready()
        for name in ("protection_plan", "protection_protect", "protection_job",
                     "protection_generate_project", "protection_benchmark", "protection_auto_protect"):
            with self.subTest(name=name):
                self.assert_rpc_error(self.bridge.handle(call(name, {})), -32602)
        self.assertEqual(self.service.calls, [])

    def test_invalid_provider_and_timeout_types_rejected(self):
        self.ready()
        args = {"provider": "vmprotect", "input_path": "app.exe", "project_path": "project.vmp"}
        for provider in ("ghidra", "", 1, True, None, [], {}):
            with self.subTest(provider=provider):
                self.assert_rpc_error(self.bridge.handle(call("protection_plan", {**args, "provider": provider})), -32602)
                self.assert_rpc_error(self.bridge.handle(call("protection_doctor", {"provider": provider})), -32602)
        for timeout in (0, -1, 3601, "600", True, False, None, float("nan"), float("inf"), [], {}):
            with self.subTest(timeout=timeout):
                self.assert_rpc_error(self.bridge.handle(call("protection_plan", {**args, "timeout_seconds": timeout})), -32602)
        self.assertEqual(self.service.calls, [])

    def test_invalid_path_plan_id_fingerprint_and_job_id_types_rejected(self):
        self.ready()
        valid = {"provider": "vmprotect", "input_path": "app.exe", "project_path": "project.vmp"}
        for key in ("input_path", "project_path"):
            for value in (None, True, 1, [], {}, ""):
                with self.subTest(key=key, value=value):
                    self.assert_rpc_error(self.bridge.handle(call("protection_plan", {**valid, key: value})), -32602)
        for value in (None, True, 1, [], {}, ""):
            with self.subTest(value=value):
                self.assert_rpc_error(self.bridge.handle(call("protection_job", {"job_id": value})), -32602)
                self.assert_rpc_error(self.bridge.handle(call("protection_protect", {"plan_id": value, "fingerprint": FINGERPRINT})), -32602)
                self.assert_rpc_error(self.bridge.handle(call("protection_protect", {"plan_id": "plan-test", "fingerprint": value})), -32602)
        self.assertEqual(self.service.calls, [])

    def test_fingerprint_format_and_control_characters_are_rejected(self):
        self.ready()
        for fingerprint in ("a" * 63, "a" * 65, "A" * 64, "z" * 64, "a" * 63 + "\n"):
            with self.subTest(fingerprint=fingerprint):
                self.assert_rpc_error(self.bridge.handle(call("protection_protect", {
                    "plan_id": "plan-test", "fingerprint": fingerprint})), -32602)
        for job_id in ("job\n", "job\0", "x" * 4097):
            self.assert_rpc_error(self.bridge.handle(call("protection_job", {"job_id": job_id})), -32602)
        self.assertEqual(self.service.calls, [])

    def test_backend_failure_is_a_tool_error_and_connection_remains_usable(self):
        self.ready()
        self.service.raise_on = "plan"
        response = self.bridge.handle(call("protection_plan", {
            "provider": "vmprotect", "input_path": "app.exe", "project_path": "project.vmp"}))
        self.assertTrue(response["result"]["isError"])
        self.assertIsInstance(tool_payload(response), dict)
        self.assertNotIn("Traceback", json.dumps(response))
        self.service.raise_on = None
        self.assertFalse(self.bridge.handle(call("protection_providers"))["result"].get("isError", False))

    def test_failure_statuses_are_tool_errors_and_success_is_not(self):
        self.ready()
        for status in ("error", "failed", "blocked", "cancelled", "timeout", "timed_out", "rejected",
                       "vendor_failed", "original_input_changed", "interrupted", "cleanup_unverified"):
            with self.subTest(status=status):
                self.service.reply_status = status
                response = self.bridge.handle(call("protection_providers"))
                self.assertTrue(response["result"]["isError"])
                self.assertEqual(tool_payload(response)["status"], status)
        self.service.reply_status = "completed"
        self.assertFalse(self.bridge.handle(call("protection_providers"))["result"].get("isError", False))

    def test_oversized_backend_response_is_bounded_tool_error(self):
        self.ready()
        with patch.object(self.service, "job", return_value={"status": "completed", "log": "x" * (defense_mcp.MAX_RESPONSE_BYTES + 1)}):
            response = self.bridge.handle(call("protection_job", {"job_id": "job-test"}))
        self.assertTrue(response["result"]["isError"])
        self.assertEqual(tool_payload(response)["status"], "error")
        self.assertLess(len(json.dumps(response).encode("utf-8")), defense_mcp.MAX_RESPONSE_BYTES)

    def test_notifications_never_execute_tools_or_return_responses(self):
        self.ready()
        for method, params in (
            ("tools/call", {"name": "protection_protect", "arguments": {"plan_id": "plan-test", "fingerprint": FINGERPRINT}}),
            ("tools/list", {}), ("ping", {}), ("unknown/notification", {}),
            ("initialize", INITIALIZE["params"]),
        ):
            with self.subTest(method=method):
                self.assertIsNone(self.bridge.handle({"jsonrpc": "2.0", "method": method, "params": params}))
        self.assertEqual(self.service.calls, [])

    def test_unknown_methods_are_method_not_found(self):
        self.ready()
        for method in ("resources/read", "prompts/get", "exec", "unknown/method"):
            with self.subTest(method=method):
                self.assert_rpc_error(self.bridge.handle(request(method)), -32601)
        self.assertEqual(self.service.calls, [])

    def test_invalid_rpc_envelopes_rejected(self):
        malformed = [None, [], "text", 1, {}, {"id": 1, "method": "ping"},
                     {"jsonrpc": "1.0", "id": 1, "method": "ping"},
                     {"jsonrpc": "2.0", "id": 1, "method": 1},
                     {"jsonrpc": "2.0", "id": [], "method": "ping"},
                     {"jsonrpc": "2.0", "id": {}, "method": "ping"},
                     {"jsonrpc": "2.0", "id": True, "method": "ping"}]
        for value in malformed:
            with self.subTest(value=value):
                self.assert_rpc_error(self.bridge.handle(value), -32600)
        self.assertEqual(self.service.calls, [])

    def test_invalid_tool_call_params_and_nonobject_arguments_rejected(self):
        self.ready()
        for params in (None, [], "text", {}, {"name": []}, {"name": "protection_providers", "arguments": []},
                       {"name": "protection_providers", "arguments": None},
                       {"name": "protection_providers", "arguments": "{}"}):
            with self.subTest(params=params):
                self.assert_rpc_error(self.bridge.handle(request("tools/call", params)), -32602)
        self.assertEqual(self.service.calls, [])


class DefenseServeTests(unittest.TestCase):
    def serve_text(self, text):
        service = FakeService()
        output, errors = io.StringIO(), io.StringIO()
        code = defense_mcp.serve(service, io.StringIO(text), output, errors)
        lines = output.getvalue().splitlines()
        parsed = [json.loads(line) for line in lines]
        return code, parsed, errors.getvalue(), service

    def test_newline_delimited_stdio_handshake_and_tool_result(self):
        values = [INITIALIZE, INITIALIZED, call("protection_providers", request_id=3)]
        code, replies, _, service = self.serve_text("\n".join(json.dumps(value) for value in values) + "\n")
        self.assertEqual(code, 0)
        self.assertEqual([item["id"] for item in replies], [1, 3])
        self.assertEqual(tool_payload(replies[-1])["method"], "providers")
        self.assertEqual(service.calls, [("providers", {})])

    def test_malformed_bounded_json_line_recovers_for_later_requests(self):
        code, replies, _, service = self.serve_text('{malformed}\n' + json.dumps(request("ping", request_id=7)) + "\n")
        self.assertEqual(code, 0)
        self.assertEqual(replies[0]["error"]["code"], -32700)
        self.assertEqual(replies[-1], {"jsonrpc": "2.0", "id": 7, "result": {}})
        self.assertEqual(service.calls, [])

    def test_duplicate_keys_nonfinite_numbers_and_batch_are_not_processed(self):
        lines = [
            '{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}',
            '{"jsonrpc":"2.0","id":NaN,"method":"ping"}',
            '[{"jsonrpc":"2.0","id":1,"method":"ping"}]',
        ]
        code, replies, _, service = self.serve_text("\n".join(lines) + "\n")
        self.assertEqual(code, 0)
        self.assertEqual(len(replies), 3)
        for response in replies:
            self.assertIn("error", response)
        self.assertEqual(service.calls, [])

    def test_oversized_request_stops_without_processing_following_input(self):
        text = "x" * (defense_mcp.MAX_REQUEST_BYTES + 1) + "\n" + json.dumps(request("ping")) + "\n"
        code, replies, _, service = self.serve_text(text)
        self.assertEqual(code, 2)
        self.assertEqual(len(replies), 1)
        self.assertIn("error", replies[0])
        self.assertEqual(service.calls, [])

    def test_oversize_uses_utf8_bytes_not_only_character_count(self):
        text = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping",
                           "params": {"text": "가" * (defense_mcp.MAX_REQUEST_BYTES // 2)}}, ensure_ascii=False) + "\n"
        self.assertLess(len(text), defense_mcp.MAX_REQUEST_BYTES)
        self.assertGreater(len(text.encode("utf-8")), defense_mcp.MAX_REQUEST_BYTES)
        code, replies, _, service = self.serve_text(text)
        self.assertEqual(code, 2)
        self.assertIn("error", replies[0])
        self.assertEqual(service.calls, [])

    def test_serve_never_invokes_subprocess_for_fake_service(self):
        values = [INITIALIZE, INITIALIZED, call("protection_providers"),
                  call("protection_plan", {"provider": "vmprotect", "input_path": "app.exe", "project_path": "profile.vmp"})]
        with patch("subprocess.run") as run, patch("subprocess.Popen") as popen:
            code, _, _, _ = self.serve_text("\n".join(json.dumps(value) for value in values) + "\n")
            run.assert_not_called()
            popen.assert_not_called()
        self.assertEqual(code, 0)

    def test_invalid_utf8_from_real_text_decoder_closes_without_traceback(self):
        service = FakeService()
        output, errors = io.StringIO(), io.StringIO()
        with io.TextIOWrapper(io.BytesIO(b"\xff\n"), encoding="utf-8", errors="strict") as input_stream:
            code = defense_mcp.serve(service, input_stream, output, errors)
        self.assertEqual(code, 2)
        replies = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(replies), 1)
        self.assertIn("error", replies[0])
        self.assertNotIn("Traceback", errors.getvalue())
        self.assertEqual(service.calls, [])


class DefenseCliTests(unittest.TestCase):
    def invoke(self, arguments, service=None, stdin=""):
        service = FakeService() if service is None else service
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("antirea.protectors.Service.from_config", return_value=service) as create, \
                patch("sys.stdin", io.StringIO(stdin)), redirect_stdout(stdout), redirect_stderr(stderr):
            code = defense_mcp.main(["--config", "unit-test-not-read.json", *arguments])
        create.assert_called_once_with(Path("unit-test-not-read.json"))
        return code, stdout.getvalue(), stderr.getvalue(), service

    def test_cli_commands_use_the_same_service_contracts(self):
        cases = [
            (["providers"], ("providers", {})),
            (["doctor"], ("doctor", {"provider": None})),
            (["doctor", "--provider", "themida"], ("doctor", {"provider": "themida"})),
            (["plan", "--provider", "vmprotect", "--input", "C:/work/app.exe", "--project", "C:/work/project.vmp"],
             ("plan", {"provider": "vmprotect", "input_path": "C:/work/app.exe", "project_path": "C:/work/project.vmp", "timeout_seconds": 600})),
            (["protect", "--plan-id", "plan-test", "--fingerprint", FINGERPRINT],
             ("protect", {"plan_id": "plan-test", "fingerprint": FINGERPRINT})),
            (["job", "--job-id", "job-test"], ("job", {"job_id": "job-test"})),
        ]
        for arguments, expected in cases:
            with self.subTest(arguments=arguments):
                code, stdout, stderr, service = self.invoke(arguments)
                self.assertEqual(code, 0)
                self.assertEqual(service.calls, [expected])
                self.assertEqual(json.loads(stdout)["method"], expected[0])
                self.assertEqual(stderr, "")

    def test_cli_failure_statuses_exit_nonzero_consistent_with_mcp(self):
        for status in ("error", "failed", "blocked", "cancelled", "timeout", "timed_out", "rejected",
                       "vendor_failed", "original_input_changed", "interrupted", "cleanup_unverified"):
            with self.subTest(status=status):
                service = FakeService()
                service.reply_status = status
                code, stdout, _, _ = self.invoke(["providers"], service)
                self.assertNotEqual(code, 0)
                self.assertEqual(json.loads(stdout)["status"], status)

    def test_cli_serve_emits_only_jsonrpc_on_stdout(self):
        values = [INITIALIZE, INITIALIZED, call("protection_providers", request_id=3)]
        stdin = "\n".join(json.dumps(value) for value in values) + "\n"
        code, stdout, stderr, service = self.invoke(["serve"], stdin=stdin)
        self.assertEqual(code, 0)
        replies = [json.loads(line) for line in stdout.splitlines()]
        self.assertEqual([response["id"] for response in replies], [1, 3])
        self.assertEqual(service.calls, [("providers", {})])
        self.assertEqual(stderr, "")

    def test_cli_configuration_failure_does_not_write_nonprotocol_stdout_in_serve_mode(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("antirea.protectors.Service.from_config", side_effect=ValueError("controlled config failure")), \
                redirect_stdout(stdout), redirect_stderr(stderr), patch("sys.stdin", io.StringIO()):
            code = defense_mcp.main(["--config", "not-read.json", "serve"])
        self.assertNotEqual(code, 0)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(json.loads(stderr.getvalue())["status"], "error")


if __name__ == "__main__":
    unittest.main()
