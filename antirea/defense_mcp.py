"""Defender-only MCP/CLI facade for native-source and commercial protection.

This server does not load the historical attacker bridge. It has no arbitrary
shell, REA, package installation or public-publishing tools. Existing benchmark
tools execute owned binaries; source build and binding tools do not execute apps.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .languages import LANGUAGE_IDS


SUPPORTED_PROTOCOLS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
PROVIDER_IDS = ("themida", "vmprotect", "code_virtualizer")
AUTO_PROVIDER_IDS = (*PROVIDER_IDS, "antirea", "antirea_engine", "kagura")
DEFENSE_LEVEL_IDS = ("mutation", "balanced", "max_vm")
FAILURE_STATUSES = {"error", "failed", "blocked", "cancelled", "timeout", "timed_out",
                    "rejected", "interrupted", "original_input_changed", "vendor_failed", "cleanup_unverified"}


def schema(properties=None, required=()):
    return {"type": "object", "properties": properties or {}, "required": list(required),
            "additionalProperties": False}


TEXT = {"type": "string", "minLength": 1, "maxLength": 4096}
PROVIDER = {"type": "string", "enum": list(PROVIDER_IDS)}
AUTO_PROVIDER = {"type": "string", "enum": list(AUTO_PROVIDER_IDS)}
DEFENSE_LEVEL = {"type": "string", "enum": list(DEFENSE_LEVEL_IDS)}
SPEED_PERCENT = {"type": "integer", "minimum": 1, "maximum": 100}
FUNCTION_LIST = {"type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 128}, "minItems": 1, "maxItems": 64}
INPUT_LIST = {"type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 4096}, "minItems": 1, "maxItems": 64}
TOOLS = [
    {"name": "protection_languages", "description": "List direct-source routes and native-core bindings separately. Tool discovery and generated wrappers do not establish language-wide protection or platform verification.",
     "inputSchema": schema({"language": {"type": "string", "enum": list(LANGUAGE_IDS)}}),
     "annotations": {"readOnlyHint": True, "openWorldHint": False}},
    {"name": "protection_source_plan", "description": "Inspect an owned source-project manifest and create a fingerprinted plan. Pins bounded project and tool inputs. May run a trusted parser or offline locked Cargo metadata (including compiler information queries), but never target source compilation, application code or publication. Cargo project inspection remains explicitly build-blocked.",
     "inputSchema": schema({"project_path": TEXT, "seed": {"type": "integer", "minimum": 1, "maximum": 2147483647}}, ("project_path",)),
     "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False}},
    {"name": "protection_source_build", "description": "Build a reviewed source plan into a fresh private directory using its exact fingerprint. Native/.NET/JVM routes execute compilers; Python and JS/TS routes transform source into language-specific VMs. Cargo inspection plans fail with rust_cargo_build_not_implemented before commands. Does not execute resulting applications. Unsupported functions or missing VM coverage fail; artifact creation is not a defense verdict.",
     "inputSchema": schema({"plan_id": TEXT, "fingerprint": {"type": "string", "pattern": "^[a-f0-9]{64}$"}}, ("plan_id", "fingerprint")),
     "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": True}},
    {"name": "protection_bindings", "description": "Generate typed language bindings from an owned native ABI contract in a fresh private directory. Does not compile or run code, and does not protect host-language source.",
     "inputSchema": schema({"contract_path": TEXT}, ("contract_path",)),
     "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False}},
    {"name": "protection_source_validate", "description": "Explicitly execute owned baseline/protected artifacts and, for C#/JVM lowering, original CLR/JVM code. Native backends require a scalar ABI contract; Python/JS VMs use language-specific sample contracts. Compare sampled outputs and repeated behavior with timing. Not a sandbox, all-input proof or attack-resistance test.",
     "inputSchema": schema({"plan_id": TEXT, "contract_path": TEXT,
                            "random_cases": {"type": "integer", "minimum": 1, "maximum": 8192},
                            "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 600}}, ("plan_id", "contract_path")),
     "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True}},
    {"name": "protection_source_integrate", "description": "Explicitly integrate an owned application around an existing reviewed source build. Compile and execute C#, Java, Kotlin, Go or Swift apps; Python/JS/TS execute staged script modules, with TypeScript transpiled by the pinned compiler. Reuse the saved protected artifact. Requires a language-specific integration spec and application-samples contract in the original planned source tree. JVM uses JNI facades; Go/Swift use native-backed facades; Python/JS/TS replace one protected module in an explicit application-file inventory and verify a copied deployment bundle. Ordinary callers remain unprotected. Script execution requires script_application_integration and script_application_samples. Creates only local deployment files. Does not publish, install dependencies, overwrite original source or invoke package/build hooks. Sampled agreement is not defense strength or all-input equivalence.",
     "inputSchema": schema({"plan_id": TEXT, "integration_spec_path": TEXT, "contract_path": TEXT,
                            "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 600}},
                           ("plan_id", "integration_spec_path", "contract_path")),
     "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True}},
    {"name": "protection_providers", "description": "List adapter contracts and limitations. Does not install or execute protectors.",
     "inputSchema": schema(), "annotations": {"readOnlyHint": True, "openWorldHint": False}},
    {"name": "protection_doctor", "description": "Inspect configured local tool paths, declared editions and execution blockers without launching tools. Discovery is not license or protection verification.",
     "inputSchema": schema({"provider": PROVIDER}),
     "annotations": {"readOnlyHint": True, "openWorldHint": False}},
    {"name": "protection_plan", "description": "Create an immutable audited dry-run plan for an owned input and reviewed vendor project. Does not execute the vendor. Return blockers, plan_id and fingerprint for explicit review.",
     "inputSchema": schema({"provider": PROVIDER, "input_path": TEXT, "project_path": TEXT,
                           "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 3600}},
                          ("provider", "input_path", "project_path")),
     "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False}},
    {"name": "protection_protect", "description": "Execute an explicitly reviewed plan only when local config authorizes execution and pins the vendor tool and project hashes. Requires the exact plan fingerprint. Produces an unvalidated artifact, never a defense-success verdict or public release. Vendor projects may contain scripts/plugins; this is not an OS sandbox.",
     "inputSchema": schema({"plan_id": TEXT, "fingerprint": {"type": "string", "pattern": "^[a-f0-9]{64}$"}},
                          ("plan_id", "fingerprint")),
     "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True}},
    {"name": "protection_job", "description": "Read the bounded local record for a protection plan/job. Does not execute, retry, validate or publish it.",
     "inputSchema": schema({"job_id": TEXT}, ("job_id",)),
     "annotations": {"readOnlyHint": True, "openWorldHint": False}},
    {"name": "protection_generate_project", "description": "Generate and approve a vendor project (.vmp, .tmd, .cv) from desired defense_level (mutation, balanced, max_vm), target min_speed_percent (1..100), and target functions.",
     "inputSchema": schema({"provider": PROVIDER, "input_path": TEXT, "functions": FUNCTION_LIST,
                           "defense_level": DEFENSE_LEVEL, "min_speed_percent": SPEED_PERCENT,
                           "output_project_path": TEXT},
                          ("provider", "input_path")),
     "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False}},
    {"name": "protection_benchmark", "description": "Verify 100% functional output match between baseline and protected candidate binaries and measure relative execution speed (speed_percent of original speed).",
     "inputSchema": schema({"baseline_path": TEXT, "candidate_path": TEXT, "test_inputs": INPUT_LIST,
                           "min_speed_percent": SPEED_PERCENT,
                           "repeats": {"type": "integer", "minimum": 1, "maximum": 25},
                           "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 600}},
                          ("baseline_path", "candidate_path")),
     "annotations": {"readOnlyHint": True, "openWorldHint": False}},
    {"name": "protection_auto_protect", "description": "Commercial binary workflow: generate a vendor project, protect an owned binary, benchmark its sampled behavior and speed, and step down defense_level if speed falls below min_speed_percent. Built-in ANTI-REA/Kagura providers return blocked: use source_plan, source_build and source_validate for reviewed source projects instead.",
     "inputSchema": schema({"provider": AUTO_PROVIDER, "input_path": TEXT, "functions": FUNCTION_LIST,
                           "defense_level": DEFENSE_LEVEL, "min_speed_percent": SPEED_PERCENT,
                           "test_inputs": INPUT_LIST,
                           "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 3600}},
                          ("provider", "input_path")),
     "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True}},
]


def parse_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def invalid_constant(_):
        raise ValueError("non-finite JSON number")

    return json.loads(text, object_pairs_hook=pairs, parse_constant=invalid_constant)


def error_response(request_id, code, message):
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def valid_id(value):
    return type(value) in (str, int) and (not isinstance(value, str) or len(value) <= 256)


def validate_arguments(tool, arguments):
    if not isinstance(arguments, dict):
        raise ValueError("tool arguments must be an object")
    contract = tool["inputSchema"]
    properties = contract["properties"]
    if set(arguments) - properties.keys() or set(contract["required"]) - arguments.keys():
        raise ValueError("tool arguments contain unknown fields or omit required fields")
    for key, value in arguments.items():
        field = properties[key]
        if field["type"] == "string":
            if (not isinstance(value, str) or not 1 <= len(value) <= 4096
                    or any(ord(char) < 32 for char in value)):
                raise ValueError(key + " must be a nonempty bounded string without control characters")
            if "enum" in field and value not in field["enum"]:
                raise ValueError("unknown " + key)
            if key == "fingerprint" and (len(value) != 64 or any(char not in "0123456789abcdef" for char in value)):
                raise ValueError("fingerprint must be a lowercase SHA-256")
        elif field["type"] == "integer":
            if type(value) is not int or not field["minimum"] <= value <= field["maximum"]:
                raise ValueError(key + " is outside its integer bounds")
        elif field["type"] == "array":
            if not isinstance(value, list) or not field["minItems"] <= len(value) <= field["maxItems"]:
                raise ValueError(key + " must be a bounded non-empty list")
            item_max = field["items"]["maxLength"]
            allow_whitespace = key == "test_inputs"
            for item in value:
                if (not isinstance(item, str) or not 1 <= len(item) <= item_max
                        or any(ord(ch) < 32 and (not allow_whitespace or ch not in "\n\r\t") for ch in item)):
                    raise ValueError(key + " items must be nonempty bounded strings")


class DefenseBridge:
    def __init__(self, service, project_service=None):
        self.service = service
        self.project_service = project_service
        self.initialized = False
        self.ready = False

    def call(self, name, arguments):
        if name == "protection_languages":
            from .languages import language_catalog
            return language_catalog(arguments.get("language"))
        if name in {"protection_source_plan", "protection_source_build", "protection_bindings", "protection_source_validate", "protection_source_integrate"}:
            if self.project_service is None:
                from .projects import ProjectService
                self.project_service = ProjectService(self.service.root)
            if name == "protection_source_plan":
                return self.project_service.plan(arguments["project_path"], seed=arguments.get("seed", 1729))
            if name == "protection_source_build":
                return self.project_service.build(arguments["plan_id"], arguments["fingerprint"])
            if name == "protection_source_validate":
                return self.project_service.validate(arguments["plan_id"], arguments["contract_path"],
                                                     random_cases=arguments.get("random_cases", 8192),
                                                     timeout_seconds=arguments.get("timeout_seconds", 120))
            if name == "protection_source_integrate":
                return self.project_service.integrate(arguments["plan_id"], arguments["integration_spec_path"],
                                                      arguments["contract_path"],
                                                      timeout_seconds=arguments.get("timeout_seconds", 120))
            return self.project_service.bindings(arguments["contract_path"])
        if name == "protection_providers":
            return self.service.providers()
        if name == "protection_doctor":
            return self.service.doctor(arguments.get("provider"))
        if name == "protection_plan":
            return self.service.plan(arguments["provider"], arguments["input_path"], arguments["project_path"],
                                     timeout_seconds=arguments.get("timeout_seconds", 600))
        if name == "protection_protect":
            return self.service.protect(arguments["plan_id"], arguments["fingerprint"])
        if name == "protection_job":
            return self.service.job(arguments["job_id"])
        if name == "protection_generate_project":
            return self.service.generate_project(
                arguments["provider"], arguments["input_path"],
                functions=arguments.get("functions", ()),
                defense_level=arguments.get("defense_level", "max_vm"),
                min_speed_percent=arguments.get("min_speed_percent", 80),
                output_project_path=arguments.get("output_project_path"),
            )
        if name == "protection_benchmark":
            return self.service.benchmark(
                arguments["baseline_path"], arguments["candidate_path"],
                test_inputs=arguments.get("test_inputs", ()),
                min_speed_percent=arguments.get("min_speed_percent", 80),
                repeats=arguments.get("repeats", 5),
                timeout_seconds=arguments.get("timeout_seconds", 60),
            )
        if name == "protection_auto_protect":
            return self.service.auto_protect(
                arguments["provider"], arguments["input_path"],
                functions=arguments.get("functions", ()),
                defense_level=arguments.get("defense_level", "max_vm"),
                min_speed_percent=arguments.get("min_speed_percent", 80),
                test_inputs=arguments.get("test_inputs", ()),
                timeout_seconds=arguments.get("timeout_seconds", 600),
            )
        raise ValueError("unknown protection tool")

    def handle(self, request):
        if (not isinstance(request, dict) or request.get("jsonrpc") != "2.0"
                or not isinstance(request.get("method"), str)):
            return error_response(None, -32600, "Invalid JSON-RPC request")
        has_id = "id" in request
        request_id = request.get("id")
        if has_id and not valid_id(request_id):
            return error_response(None, -32600, "Invalid request ID")
        method = request["method"]
        params = request.get("params", {})
        if not has_id:
            # In particular, never run a mutating tools/call notification.
            if (method == "notifications/initialized" and self.initialized and isinstance(params, dict)):
                self.ready = True
            return None
        if not isinstance(params, dict):
            return error_response(request_id, -32602, "Parameters must be an object")
        if method == "initialize":
            if self.initialized:
                return error_response(request_id, -32600, "Session already initialized")
            client = params.get("clientInfo")
            if (not isinstance(params.get("protocolVersion"), str)
                    or not isinstance(params.get("capabilities"), dict)
                    or not isinstance(client, dict)
                    or not all(isinstance(client.get(key), str) and client[key] for key in ("name", "version"))):
                return error_response(request_id, -32602, "Invalid initialize parameters")
            self.initialized = True
            requested = params["protocolVersion"]
            result = {"protocolVersion": requested if requested in SUPPORTED_PROTOCOLS else SUPPORTED_PROTOCOLS[-1],
                      "capabilities": {"tools": {"listChanged": False}},
                      "serverInfo": {"name": "anti-rea-defense", "version": "0.1.0"},
                      "instructions": "Defender-only local adapters. Review plans before execution. Artifact creation does not establish functional preservation or attack resistance. Source builds execute compilers; benchmark tools execute owned binaries. Binding generation does not protect host-language source. No attack or publishing tools are exposed."}
        elif method == "ping":
            result = {}
        elif method in {"tools/list", "tools/call"}:
            if not self.ready:
                return error_response(request_id, -32002, "Complete initialize and notifications/initialized first")
            if method == "tools/list":
                if set(params) - {"_meta", "cursor"} or params.get("cursor") is not None:
                    return error_response(request_id, -32602, "This tool catalog is not paginated")
                result = {"tools": TOOLS}
            else:
                if set(params) - {"name", "arguments", "_meta"}:
                    return error_response(request_id, -32602, "Unknown tool-call parameters")
                tool = next((item for item in TOOLS if item["name"] == params.get("name")), None)
                if tool is None:
                    return error_response(request_id, -32602, "Unknown tool")
                arguments = params.get("arguments", {})
                try:
                    validate_arguments(tool, arguments)
                except ValueError as exc:
                    return error_response(request_id, -32602, str(exc))
                try:
                    payload = self.call(tool["name"], arguments)
                    failed = isinstance(payload, dict) and payload.get("status") in FAILURE_STATUSES
                    body = json.dumps(payload, ensure_ascii=False, allow_nan=False)
                    if len(body.encode("utf-8")) > MAX_RESPONSE_BYTES:
                        raise ValueError("Job response exceeds bounded delivery limit; inspect local audit record")
                except Exception as exc:
                    failed = True
                    body = json.dumps({"status": "error", "error": type(exc).__name__ + ": " + str(exc)[:2048]}, ensure_ascii=True)
                result = {"content": [{"type": "text", "text": body}], "isError": bool(failed)}
        else:
            return error_response(request_id, -32601, "Method not found")
        return {"jsonrpc": "2.0", "id": request_id, "result": result}


def serve(service, input_stream, output_stream, error_stream):
    bridge = DefenseBridge(service)
    while True:
        try:
            line = input_stream.readline(MAX_REQUEST_BYTES + 1)
            encoded_size = len(line.encode("utf-8"))
        except UnicodeError:
            response = error_response(None, -32700, "Invalid UTF-8; session closed")
            output_stream.write(json.dumps(response) + "\n")
            output_stream.flush()
            return 2
        if not line:
            return 0
        if encoded_size > MAX_REQUEST_BYTES:
            response = error_response(None, -32600, "Request exceeds size limit; session closed")
            output_stream.write(json.dumps(response) + "\n")
            output_stream.flush()
            return 2
        try:
            response = bridge.handle(parse_json(line))
        except (ValueError, RecursionError):
            response = error_response(None, -32700, "Parse error")
        except Exception as exc:
            error_stream.write("defense MCP internal error: " + type(exc).__name__ + "\n")
            error_stream.flush()
            response = error_response(None, -32603, "Internal error")
        if response is not None:
            output_stream.write(json.dumps(response, ensure_ascii=False, allow_nan=False) + "\n")
            output_stream.flush()


DEFAULT_CONFIG_PATH = Path(".runs/protectors.local.json")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    sub.add_parser("providers")
    languages = sub.add_parser("languages")
    languages.add_argument("--language", choices=LANGUAGE_IDS)
    source_plan = sub.add_parser("source-plan")
    source_plan.add_argument("--project", dest="project_path", required=True)
    source_plan.add_argument("--seed", type=int, default=1729)
    source_build = sub.add_parser("source-build")
    source_build.add_argument("--plan-id", required=True)
    source_build.add_argument("--fingerprint", required=True)
    bindings = sub.add_parser("bindings")
    bindings.add_argument("--contract", dest="contract_path", required=True)
    source_validate = sub.add_parser("source-validate")
    source_validate.add_argument("--plan-id", required=True)
    source_validate.add_argument("--contract", dest="contract_path", required=True)
    source_validate.add_argument("--random-cases", type=int, default=8192)
    source_validate.add_argument("--timeout-seconds", type=int, default=120)
    source_integrate = sub.add_parser("source-integrate")
    source_integrate.add_argument("--plan-id", required=True)
    source_integrate.add_argument("--integration-spec", dest="integration_spec_path", required=True)
    source_integrate.add_argument("--contract", dest="contract_path", required=True)
    source_integrate.add_argument("--timeout-seconds", type=int, default=120)
    doctor = sub.add_parser("doctor")
    doctor.add_argument("--provider", choices=PROVIDER_IDS)
    plan = sub.add_parser("plan")
    plan.add_argument("--provider", choices=PROVIDER_IDS, required=True)
    plan.add_argument("--input", dest="input_path", required=True)
    plan.add_argument("--project", dest="project_path", required=True)
    plan.add_argument("--timeout-seconds", type=int, default=600)
    protect = sub.add_parser("protect")
    protect.add_argument("--plan-id", required=True)
    protect.add_argument("--fingerprint", required=True)
    job = sub.add_parser("job")
    job.add_argument("--job-id", required=True)
    gen = sub.add_parser("generate-project")
    gen.add_argument("--provider", choices=PROVIDER_IDS, required=True)
    gen.add_argument("--input", dest="input_path", required=True)
    gen.add_argument("--function", dest="functions", action="append", default=[])
    gen.add_argument("--defense-level", choices=DEFENSE_LEVEL_IDS, default="max_vm")
    gen.add_argument("--min-speed-percent", type=int, default=80)
    gen.add_argument("--output-project", dest="output_project_path")
    bench = sub.add_parser("benchmark")
    bench.add_argument("--baseline", dest="baseline_path", required=True)
    bench.add_argument("--candidate", dest="candidate_path", required=True)
    bench.add_argument("--test-input", dest="test_inputs", action="append", default=[])
    bench.add_argument("--min-speed-percent", type=int, default=80)
    bench.add_argument("--repeats", type=int, default=5)
    bench.add_argument("--timeout-seconds", type=int, default=60)
    auto = sub.add_parser("auto-protect")
    auto.add_argument("--provider", choices=AUTO_PROVIDER_IDS, required=True)
    auto.add_argument("--input", dest="input_path", required=True)
    auto.add_argument("--function", dest="functions", action="append", default=[])
    auto.add_argument("--defense-level", choices=DEFENSE_LEVEL_IDS, default="max_vm")
    auto.add_argument("--min-speed-percent", type=int, default=80)
    auto.add_argument("--test-input", dest="test_inputs", action="append", default=[])
    auto.add_argument("--timeout-seconds", type=int, default=600)
    sub.add_parser("serve")
    args = parser.parse_args(argv)
    if args.command == "serve":
        for stream in (sys.stdin, sys.stdout, sys.stderr):
            if hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8", errors="strict")
    try:
        from antirea.protectors import Service
        if args.command == "init":
            service = Service.ensure_default_config(args.config)
            result = {"schema_version": 1, "status": "completed", "config_path": str(service.config_path),
                      "workspace_root": str(service.root)}
            print(json.dumps(result, ensure_ascii=True, indent=2, allow_nan=False))
            return 0
        config_path = args.config
        if config_path == DEFAULT_CONFIG_PATH:
            if not config_path.exists():
                Service.ensure_default_config(config_path)
            config_path = config_path.resolve()
        elif config_path.exists() and not config_path.is_absolute():
            config_path = config_path.resolve()
        service = Service.from_config(config_path)
        if args.command == "serve":
            return serve(service, sys.stdin, sys.stdout, sys.stderr)
        if args.command == "languages":
            from .languages import language_catalog
            result = language_catalog(args.language)
        elif args.command in {"source-plan", "source-build", "bindings", "source-validate", "source-integrate"}:
            from .projects import ProjectService
            projects = ProjectService(service.root)
            if args.command == "source-plan":
                result = projects.plan(args.project_path, seed=args.seed)
            elif args.command == "source-build":
                result = projects.build(args.plan_id, args.fingerprint)
            elif args.command == "source-validate":
                result = projects.validate(args.plan_id, args.contract_path, random_cases=args.random_cases,
                                           timeout_seconds=args.timeout_seconds)
            elif args.command == "source-integrate":
                result = projects.integrate(args.plan_id, args.integration_spec_path, args.contract_path,
                                            timeout_seconds=args.timeout_seconds)
            else:
                result = projects.bindings(args.contract_path)
        elif args.command == "providers":
            result = service.providers()
        elif args.command == "doctor":
            result = service.doctor(args.provider)
        elif args.command == "plan":
            result = service.plan(args.provider, args.input_path, args.project_path, timeout_seconds=args.timeout_seconds)
        elif args.command == "protect":
            result = service.protect(args.plan_id, args.fingerprint)
        elif args.command == "job":
            result = service.job(args.job_id)
        elif args.command == "generate-project":
            result = service.generate_project(
                args.provider, args.input_path, functions=tuple(args.functions),
                defense_level=args.defense_level, min_speed_percent=args.min_speed_percent,
                output_project_path=args.output_project_path,
            )
        elif args.command == "benchmark":
            result = service.benchmark(
                args.baseline_path, args.candidate_path, test_inputs=tuple(args.test_inputs),
                min_speed_percent=args.min_speed_percent, repeats=args.repeats,
                timeout_seconds=args.timeout_seconds,
            )
        elif args.command == "auto-protect":
            result = service.auto_protect(
                args.provider, args.input_path, functions=tuple(args.functions),
                defense_level=args.defense_level, min_speed_percent=args.min_speed_percent,
                test_inputs=tuple(args.test_inputs), timeout_seconds=args.timeout_seconds,
            )
        else:
            raise ValueError("unknown command")
        print(json.dumps(result, ensure_ascii=True, indent=2, allow_nan=False))
        return int(isinstance(result, dict) and result.get("status") in FAILURE_STATUSES)
    except (ValueError, OSError, RuntimeError) as exc:
        stream = sys.stderr if args.command == "serve" else sys.stdout
        print(json.dumps({"status": "error", "error": type(exc).__name__ + ": " + str(exc)[:2048]}), file=stream)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
