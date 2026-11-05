"""Read-only Semantic Ontology MCP Server & CLI for ANTI-REA.

Mirrors `NVIDIA/auto-ontology`'s `auto_ontology_mcp` isolation model:
- Exposes a curated, strictly read-only (`readOnlyHint: True`) JSON-RPC 2.0 MCP
  tool surface (`check_readiness`, `search_terms`, `get_term`,
  `get_term_columns`, `get_term_sql_attributes`, `get_sql_attribute`,
  `describe_table`, `check_answerable`, `recommend_scope`, `run_sql_attribute`).
- Dynamically inherits tool descriptions from the pinned upstream
  `.tools/auto-ontology/mcp/auto_ontology_mcp/tools.py` checkout whenever
  upstream updates are synced.
- Physically isolated from mutating build/protection routes in `defense_mcp.py`.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from . import __version__
from . import auto_ontology_sync
from . import ontology
from .defense_mcp import MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, SUPPORTED_PROTOCOLS, parse_json, valid_id


READONLY_ANNOTATIONS = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "openWorldHint": False,
}

TEXT_PROP = {"type": "string", "minLength": 1, "maxLength": 1024}


def _schema(properties: dict[str, Any] | None = None, required: tuple[str, ...] = ()) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties or {},
        "required": list(required),
        "additionalProperties": False,
    }


def _error_response(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _validate_args(tool: dict[str, Any], arguments: Any) -> None:
    if not isinstance(arguments, dict):
        raise ValueError("tool arguments must be an object")
    contract = tool["inputSchema"]
    props = contract["properties"]
    if set(arguments) - props.keys() or set(contract["required"]) - arguments.keys():
        raise ValueError("tool arguments contain unknown fields or omit required fields")
    for key, value in arguments.items():
        spec = props[key]
        ftype = spec["type"]
        if ftype == "string":
            min_len = spec.get("minLength", 0)
            max_len = spec.get("maxLength", 1024)
            if not isinstance(value, str) or not (min_len <= len(value) <= max_len) or any(ord(c) < 32 for c in value):
                raise ValueError(f"{key} must be a bounded string without control characters")
        elif ftype == "number":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{key} must be a number")
            if not (spec["minimum"] <= float(value) <= spec["maximum"]):
                raise ValueError(f"{key} is outside allowed bounds")
        elif ftype == "boolean":
            if not isinstance(value, bool):
                raise ValueError(f"{key} must be a boolean")


def build_tool_catalog(workspace_root: Path) -> list[dict[str, Any]]:
    rt = auto_ontology_sync.load_upstream_runtime(workspace_root)
    upstream_desc = {item["name"]: item["description"] for item in rt.curated_mcp_tools}

    return [
        {
            "name": "check_readiness",
            "description": (
                "Verify whether the ANTI-REA semantic ontology layer is compiled, "
                "read-only SQLite execution is live, and upstream Auto Ontology contracts match."
            ),
            "inputSchema": _schema(),
            "annotations": READONLY_ANNOTATIONS,
        },
        {
            "name": "search_terms",
            "description": upstream_desc.get(
                "search_terms",
                "Search compiled ontology glossary terms.",
            ),
            "inputSchema": _schema({"query": {"type": "string", "minLength": 0, "maxLength": 256}}),
            "annotations": READONLY_ANNOTATIONS,
        },
        {
            "name": "get_term",
            "description": upstream_desc.get(
                "get_term",
                "Fetch one glossary term and its semantic representations.",
            ),
            "inputSchema": _schema({"term_id": TEXT_PROP}, ("term_id",)),
            "annotations": READONLY_ANNOTATIONS,
        },
        {
            "name": "get_term_columns",
            "description": upstream_desc.get(
                "get_term_columns",
                "List physical catalog columns mapped to a glossary term.",
            ),
            "inputSchema": _schema({"term_id": TEXT_PROP}, ("term_id",)),
            "annotations": READONLY_ANNOTATIONS,
        },
        {
            "name": "get_term_sql_attributes",
            "description": upstream_desc.get(
                "get_term_sql_attributes",
                "List certified SQL expressions defined under a glossary term.",
            ),
            "inputSchema": _schema({"term_id": TEXT_PROP}, ("term_id",)),
            "annotations": READONLY_ANNOTATIONS,
        },
        {
            "name": "get_sql_attribute",
            "description": upstream_desc.get(
                "get_sql_attribute",
                "Fetch one certified SQL attribute definition.",
            ),
            "inputSchema": _schema({"attr_id": TEXT_PROP}, ("attr_id",)),
            "annotations": READONLY_ANNOTATIONS,
        },
        {
            "name": "describe_table",
            "description": upstream_desc.get(
                "describe_table",
                "Describe one catalog table, its columns, terms, and SQL attributes.",
            ),
            "inputSchema": _schema({"table_id": TEXT_PROP}, ("table_id",)),
            "annotations": READONLY_ANNOTATIONS,
        },
        {
            "name": "check_answerable",
            "description": upstream_desc.get(
                "check_answerable",
                "Grade whether the semantic layer covers the entities in a question.",
            ),
            "inputSchema": _schema({"question": TEXT_PROP}, ("question",)),
            "annotations": READONLY_ANNOTATIONS,
        },
        {
            "name": "recommend_scope",
            "description": (
                "Deterministically select boundary/secret_core functions within `max_slowdown` "
                "while excluding inner `HotLoopFunction` traps."
            ),
            "inputSchema": _schema(
                {
                    "max_slowdown": {"type": "number", "minimum": 0.5, "maximum": 100000.0},
                    "project": TEXT_PROP,
                    "only_vm_lowerable": {"type": "boolean"},
                }
            ),
            "annotations": READONLY_ANNOTATIONS,
        },
        {
            "name": "run_sql_attribute",
            "description": (
                "Execute a pre-certified `ModelSqlAttribute` against the read-only SQLite "
                "catalog under the strict SELECT-only authorizer."
            ),
            "inputSchema": _schema({"attr_id": TEXT_PROP}, ("attr_id",)),
            "annotations": READONLY_ANNOTATIONS,
        },
    ]


class OntologyMcpBridge:
    def __init__(self, bundle: ontology.CompiledDefenseOntology, *, workspace_root: Path):
        self.bundle = bundle
        self.workspace_root = Path(workspace_root).resolve()
        self.tools = build_tool_catalog(self.workspace_root)
        self.initialized = False
        self.ready = False

    def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "check_readiness":
            can_sql = False
            blockers: list[str] = []
            try:
                self.bundle.execute_readonly_sql("SELECT 1")
                can_sql = True
            except Exception as exc:
                blockers.append(f"SQLite read probe failed: {exc}")

            doc = self.bundle.model_dict()
            dbs = [d["id"] for d in doc["data_layer"]["databases"]]
            sem_built = bool(doc["semantic_layer"]["terms"])
            if not dbs:
                blockers.append("No catalog database ingested")
            if not sem_built:
                blockers.append("Semantic layer terms empty")

            rt = self.bundle.upstream_runtime
            return {
                "ready": bool(can_sql and dbs and sem_built and not blockers),
                "semantic_layer_built": sem_built,
                "can_execute_sql": can_sql,
                "catalog_present": bool(dbs),
                "databases": dbs,
                "blockers": blockers,
                "unverified": [] if rt.upstream_loaded else ["upstream_checkout_fallback_shim"],
                "upstream": {
                    "upstream_loaded": rt.upstream_loaded,
                    "eval_loaded": rt.eval_loaded,
                    "auto_ontology_version": rt.auto_ontology_version,
                    "auto_ontology_commit": rt.auto_ontology_commit,
                    "auto_ontology_eval_commit": rt.auto_ontology_eval_commit,
                },
            }

        if name == "search_terms":
            hits = self.bundle.search_terms(arguments.get("query", ""))
            return {"terms": hits, "count": len(hits)}

        if name == "get_term":
            return self.bundle.get_term(arguments["term_id"])

        if name == "get_term_columns":
            term = self.bundle.get_term(arguments["term_id"])
            return {
                "term_id": term["id"],
                "columns_attributes": term.get("columns_attributes") or [],
            }

        if name == "get_term_sql_attributes":
            term_id = arguments["term_id"]
            self.bundle.get_term(term_id)
            attrs = [a for a in self.bundle.all_sql_attributes() if a.get("term_id") == term_id]
            return {"term_id": term_id, "sql_attributes": attrs}

        if name == "get_sql_attribute":
            attr_id = arguments["attr_id"]
            for attr in self.bundle.all_sql_attributes():
                if attr["id"] == attr_id or attr["name"] == attr_id:
                    return attr
            raise KeyError(f"Unknown attr_id: {attr_id}")

        if name == "describe_table":
            return self.bundle.describe_table(arguments["table_id"])

        if name == "check_answerable":
            return self.bundle.check_answerable(arguments["question"])

        if name == "recommend_scope":
            return self.bundle.recommend_scope(
                max_slowdown=float(arguments.get("max_slowdown", 10.0)),
                project=arguments.get("project"),
                only_vm_lowerable=bool(arguments.get("only_vm_lowerable", False)),
            )

        if name == "run_sql_attribute":
            attr_id = arguments["attr_id"]
            target = None
            for attr in self.bundle.all_sql_attributes():
                if attr["id"] == attr_id or attr["name"] == attr_id:
                    target = attr
                    break
            if target is None:
                raise KeyError(f"Unknown attr_id: {attr_id}")
            rows = self.bundle.execute_readonly_sql(target["sql"])
            return {
                "attr_id": target["id"],
                "name": target["name"],
                "sql": target["sql"],
                "rows": [list(r) for r in rows],
            }

        raise ValueError(f"Unknown ontology tool: {name}")

    def handle(self, request: Any) -> dict[str, Any] | None:
        if (
            not isinstance(request, dict)
            or request.get("jsonrpc") != "2.0"
            or not isinstance(request.get("method"), str)
        ):
            return _error_response(None, -32600, "Invalid JSON-RPC request")
        has_id = "id" in request
        request_id = request.get("id")
        if has_id and not valid_id(request_id):
            return _error_response(None, -32600, "Invalid request ID")
        method = request["method"]
        params = request.get("params", {})
        if not has_id:
            if method == "notifications/initialized" and self.initialized and isinstance(params, dict):
                self.ready = True
            return None
        if not isinstance(params, dict):
            return _error_response(request_id, -32602, "Parameters must be an object")
        if method == "initialize":
            if self.initialized:
                return _error_response(request_id, -32600, "Session already initialized")
            client = params.get("clientInfo")
            if (
                not isinstance(params.get("protocolVersion"), str)
                or not isinstance(params.get("capabilities"), dict)
                or not isinstance(client, dict)
                or not all(isinstance(client.get(k), str) and client[k] for k in ("name", "version"))
            ):
                return _error_response(request_id, -32602, "Invalid initialize parameters")
            self.initialized = True
            requested = params["protocolVersion"]
            result: dict[str, Any] = {
                "protocolVersion": requested if requested in SUPPORTED_PROTOCOLS else SUPPORTED_PROTOCOLS[-1],
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "anti-rea-ontology", "version": __version__},
                "instructions": (
                    "Read-only semantic ontology layer for ANTI-REA powered by NVIDIA Auto Ontology. "
                    "Use search_terms, get_term, get_term_sql_attributes, and recommend_scope instead "
                    "of guessing raw catalog schemas or hot-loop boundaries."
                ),
            }
        elif method == "ping":
            result = {}
        elif method in {"tools/list", "tools/call"}:
            if not self.ready:
                return _error_response(request_id, -32002, "Complete initialize and notifications/initialized first")
            if method == "tools/list":
                if set(params) - {"_meta", "cursor"} or params.get("cursor") is not None:
                    return _error_response(request_id, -32602, "This tool catalog is not paginated")
                result = {"tools": self.tools}
            else:
                if set(params) - {"name", "arguments", "_meta"}:
                    return _error_response(request_id, -32602, "Unknown tool-call parameters")
                tool = next((item for item in self.tools if item["name"] == params.get("name")), None)
                if tool is None:
                    return _error_response(request_id, -32602, "Unknown tool")
                arguments = params.get("arguments", {})
                try:
                    _validate_args(tool, arguments)
                except ValueError as exc:
                    return _error_response(request_id, -32602, str(exc))
                try:
                    payload = self.call(tool["name"], arguments)
                    body = json.dumps(payload, ensure_ascii=False, allow_nan=False)
                    if len(body.encode("utf-8")) > MAX_RESPONSE_BYTES:
                        raise ValueError("Ontology response exceeds bounded delivery limit")
                    failed = False
                except Exception as exc:
                    failed = True
                    body = json.dumps(
                        {"status": "error", "error": f"{type(exc).__name__}: {str(exc)[:1024]}"},
                        ensure_ascii=True,
                    )
                result = {"content": [{"type": "text", "text": body}], "isError": failed}
        else:
            return _error_response(request_id, -32601, "Method not found")
        return {"jsonrpc": "2.0", "id": request_id, "result": result}


def serve(bundle: ontology.CompiledDefenseOntology, *, workspace_root: Path) -> int:
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="strict")
    bridge = OntologyMcpBridge(bundle, workspace_root=workspace_root)
    while True:
        line = sys.stdin.readline(MAX_REQUEST_BYTES + 1)
        if not line:
            return 0
        if len(line.encode("utf-8")) > MAX_REQUEST_BYTES:
            sys.stdout.write(json.dumps(_error_response(None, -32600, "Request exceeds size limit")) + "\n")
            sys.stdout.flush()
            return 2
        try:
            resp = bridge.handle(parse_json(line))
        except Exception:
            resp = _error_response(None, -32700, "Parse error")
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False, allow_nan=False) + "\n")
            sys.stdout.flush()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--db-root", type=Path, default=Path(".runs/ontology-catalog"))
    parser.add_argument("--ir", action="append", type=Path, default=[])
    parser.add_argument("--policy", type=Path)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve")
    sub.add_parser("readiness")
    sub.add_parser("export-yaml")
    rec = sub.add_parser("recommend-scope")
    rec.add_argument("--max-slowdown", type=float, default=10.0)
    rec.add_argument("--project")
    args = parser.parse_args(argv)

    policy_dict = json.loads(args.policy.read_text(encoding="utf-8")) if args.policy else None
    bundle = ontology.compile_defense_ontology(
        db_root=args.db_root,
        workspace_root=args.workspace,
        ir_modules=args.ir,
        scope_policy=policy_dict,
    )
    if args.command == "serve":
        return serve(bundle, workspace_root=args.workspace)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if args.command == "export-yaml":
        sys.stdout.write(bundle.to_yaml())
        return 0
    bridge = OntologyMcpBridge(bundle, workspace_root=args.workspace)
    if args.command == "readiness":
        out = bridge.call("check_readiness", {})
    else:
        out = bridge.call(
            "recommend_scope",
            {
                "max_slowdown": args.max_slowdown,
                **({"project": args.project} if args.project else {}),
            },
        )
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
