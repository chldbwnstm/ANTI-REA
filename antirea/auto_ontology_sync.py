"""Upstream synchronization and live contract loader for NVIDIA Auto Ontology.

Tracks unmodified upstream git checkouts under `.tools/auto-ontology` and
`.tools/auto-ontology-eval`, pins verified commits in
`.tools/auto-ontology-toolchain.json`, and dynamically loads upstream Pydantic
interchange schemas, curated MCP tool contracts, and deterministic SQLite
evaluation graders.

Security invariants:
- External git repositories are always accessed with `-c core.hooksPath=NUL` so
  untrusted repository hooks never execute.
- `sync_upstream(..., apply_update=True)` fast-forwards only and automatically
  rolls back to the prior known-good commit if upstream introduces a breaking
  schema, OpenAPI route, or grader contract change.
"""
from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tomllib
from typing import Any


DEFAULT_AUTO_ONTOLOGY_URL = "https://github.com/NVIDIA/auto-ontology.git"
DEFAULT_AUTO_ONTOLOGY_EVAL_URL = "https://github.com/NVIDIA/auto-ontology-eval.git"

REQUIRED_SCHEMA_CLASSES = (
    "AutoOntologyModelDocument",
    "ModelColumn",
    "ModelColumnAttribute",
    "ModelCustomAnalysis",
    "ModelDatabase",
    "ModelDataLayer",
    "ModelForeignKey",
    "ModelJoin",
    "ModelSchema",
    "ModelSemanticFk",
    "ModelSemanticLayer",
    "ModelSqlAttribute",
    "ModelSqlAttributesBySource",
    "ModelTable",
    "ModelTerm",
)

REQUIRED_CURATED_MCP_NAMES = frozenset(
    {
        "search_terms",
        "get_term",
        "get_term_columns",
        "get_term_sql_attributes",
        "get_sql_attribute",
        "describe_table",
        "check_answerable",
    }
)

_MODULE_CACHE: dict[tuple[str, int], Any] = {}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _run_git(cwd: Path, *args: str, timeout: int = 120) -> str:
    proc = subprocess.run(
        ["git", "-c", "core.hooksPath=NUL", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed in {cwd}: {(proc.stderr or proc.stdout).strip()}"
        )
    return proc.stdout.strip()


def _load_file_module(module_prefix: str, file_path: Path):
    resolved = file_path.resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"Upstream module not found: {resolved}")
    mtime_ns = resolved.stat().st_mtime_ns
    cache_key = (str(resolved), mtime_ns)
    if cache_key in _MODULE_CACHE:
        return _MODULE_CACHE[cache_key]

    unique_name = f"{module_prefix}_{hashlib.sha256(f'{resolved}:{mtime_ns}'.encode()).hexdigest()[:12]}"
    spec = importlib.util.spec_from_file_location(unique_name, str(resolved))
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not create import spec for {resolved}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[unique_name] = module
    spec.loader.exec_module(module)
    _MODULE_CACHE[cache_key] = module
    return module


def _read_pyproject_version(repo_dir: Path) -> str:
    pyproject = repo_dir / "pyproject.toml"
    if not pyproject.is_file():
        return "unknown"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    return str(data.get("project", {}).get("version", "unknown"))


def _parse_curated_mcp_tools(tools_py: Path) -> list[dict[str, str]]:
    """Extract `CURATED` ToolSpec entries from `mcp/auto_ontology_mcp/tools.py` via AST."""
    tree = ast.parse(tools_py.read_text(encoding="utf-8"), filename=str(tools_py))
    specs: list[dict[str, str]] = []
    for node in tree.body:
        value = None
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "CURATED":
            value = node.value
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "CURATED":
                    value = node.value
        if isinstance(value, (ast.Tuple, ast.List)):
            for elt in value.elts:
                if not isinstance(elt, ast.Call):
                    continue
                entry: dict[str, str] = {}
                for kw in elt.keywords:
                    if kw.arg in {"method", "path", "name", "description"}:
                        entry[kw.arg] = str(ast.literal_eval(kw.value))
                if {"method", "path", "name", "description"} <= entry.keys():
                    specs.append(entry)
    return specs


def _missing_from_openapi(curated: list[dict[str, str]], openapi_spec: dict[str, Any]) -> list[str]:
    published = {
        (method.upper(), path)
        for path, item in (openapi_spec.get("paths") or {}).items()
        if isinstance(item, dict)
        for method in item
        if method.lower() in {"get", "post", "put", "patch", "delete"}
    }
    return [
        f"{spec['method'].upper()} {spec['path']}"
        for spec in curated
        if (spec["method"].upper(), spec["path"]) not in published
    ]


# ---------------------------------------------------------------------------
# Offline Fallback Shims (used only when `.tools/` checkouts are absent)
# ---------------------------------------------------------------------------

DEFAULT_CURATED_MCP_TOOLS: list[dict[str, str]] = [
    {
        "method": "GET",
        "path": "/api/terms",
        "name": "search_terms",
        "description": "Search the compiled ontology glossary terms by keyword or synonym.",
    },
    {
        "method": "GET",
        "path": "/api/terms/{term_id}",
        "name": "get_term",
        "description": "Fetch one glossary term, its description, and related representations.",
    },
    {
        "method": "GET",
        "path": "/api/terms/{term_id}/column-attributes",
        "name": "get_term_columns",
        "description": "List physical catalog columns mapped to a glossary term.",
    },
    {
        "method": "GET",
        "path": "/api/terms/{term_id}/sql-attributes",
        "name": "get_term_sql_attributes",
        "description": "List certified SQL metric/filter expressions defined under a term.",
    },
    {
        "method": "GET",
        "path": "/api/sql-attributes/{attr_id}",
        "name": "get_sql_attribute",
        "description": "Fetch one certified SQL attribute expression and metadata.",
    },
    {
        "method": "GET",
        "path": "/api/exploration/tables/{table_id}/details",
        "name": "describe_table",
        "description": "Describe a physical catalog table, its columns, terms, and SQL attributes.",
    },
    {
        "method": "POST",
        "path": "/api/question-entity-coverage",
        "name": "check_answerable",
        "description": "Pre-flight check grading whether the ontology covers a question's entities.",
    },
]


def _build_fallback_schemas():
    from pydantic import BaseModel, Field

    class ModelColumn(BaseModel):
        id: str
        name: str = ""
        description: str = ""
        type: str = ""
        sample_values: list[Any] = Field(default_factory=list)
        is_nullable: bool = True
        is_unique: bool = False

    class ModelTable(BaseModel):
        id: str
        name: str = ""
        description: str = ""
        pk: list[str] = Field(default_factory=list)
        type: str = ""
        columns: list[ModelColumn] = Field(default_factory=list)

    class ModelSchema(BaseModel):
        id: str
        name: str = ""
        database_name: str = ""
        tables: list[ModelTable] = Field(default_factory=list)

    class ModelDatabase(BaseModel):
        id: str
        dialect: str = ""
        schemas: list[ModelSchema] = Field(default_factory=list)

    class ModelForeignKey(BaseModel):
        source_column_id: str
        target_column_id: str

    class ModelJoin(BaseModel):
        source_table_id: str
        target_table_id: str
        join_columns: list[dict[str, str]] = Field(default_factory=list)

    class ModelDataLayer(BaseModel):
        databases: list[ModelDatabase] = Field(default_factory=list)
        foreign_keys: list[ModelForeignKey] = Field(default_factory=list)
        joins: list[ModelJoin] = Field(default_factory=list)

    class ModelColumnAttribute(BaseModel):
        id: str
        name: str = ""
        description: str = ""
        column_id: str = ""

    class ModelTerm(BaseModel):
        id: str
        name: str = ""
        description: str = ""
        represents: list[str] = Field(default_factory=list)
        columns_attributes: list[ModelColumnAttribute] = Field(default_factory=list)

    class ModelSemanticFk(BaseModel):
        column_attribute_id: str
        column_id: str
        use_in_join_paths: bool = True

    class ModelSqlAttribute(BaseModel):
        id: str
        name: str = ""
        description: str = ""
        sql: str = ""
        sql_column_is: list[str] = Field(default_factory=list)
        term_id: str = ""

    class ModelSqlAttributesBySource(BaseModel):
        manual: list[ModelSqlAttribute] = Field(default_factory=list)
        table: list[ModelSqlAttribute] = Field(default_factory=list)
        sql: list[ModelSqlAttribute] = Field(default_factory=list)
        bridge_table: list[ModelSqlAttribute] = Field(default_factory=list)

    class ModelCustomAnalysis(BaseModel):
        id: str
        name: str = ""
        description: str = ""
        sql: str = ""
        sql_column_is: list[str] = Field(default_factory=list)

    class ModelSemanticLayer(BaseModel):
        terms: list[ModelTerm] = Field(default_factory=list)
        semantic_fks: list[ModelSemanticFk] = Field(default_factory=list)
        sql_attributes: ModelSqlAttributesBySource = Field(
            default_factory=ModelSqlAttributesBySource
        )
        custom_analyses: list[ModelCustomAnalysis] = Field(default_factory=list)

    class AutoOntologyModelDocument(BaseModel):
        data_layer: ModelDataLayer = Field(default_factory=ModelDataLayer)
        semantic_layer: ModelSemanticLayer = Field(default_factory=ModelSemanticLayer)
        zones: list[dict[str, str]] = Field(default_factory=list)

    import types

    ns = {
        "AutoOntologyModelDocument": AutoOntologyModelDocument,
        "ModelColumn": ModelColumn,
        "ModelColumnAttribute": ModelColumnAttribute,
        "ModelCustomAnalysis": ModelCustomAnalysis,
        "ModelDatabase": ModelDatabase,
        "ModelDataLayer": ModelDataLayer,
        "ModelForeignKey": ModelForeignKey,
        "ModelJoin": ModelJoin,
        "ModelSchema": ModelSchema,
        "ModelSemanticFk": ModelSemanticFk,
        "ModelSemanticLayer": ModelSemanticLayer,
        "ModelSqlAttribute": ModelSqlAttribute,
        "ModelSqlAttributesBySource": ModelSqlAttributesBySource,
        "ModelTable": ModelTable,
        "ModelTerm": ModelTerm,
    }
    for cls in ns.values():
        cls.model_rebuild(_types_namespace=ns)
    return types.SimpleNamespace(**ns)


@dataclass(frozen=True)
class UpstreamRuntime:
    upstream_loaded: bool
    eval_loaded: bool
    auto_ontology_version: str
    auto_ontology_eval_version: str
    auto_ontology_commit: str | None
    auto_ontology_eval_commit: str | None
    schemas: Any
    curated_mcp_tools: list[dict[str, str]] = field(default_factory=list)
    exec_match: Any = None
    compare: Any = None


def load_upstream_runtime(workspace_root: Path) -> UpstreamRuntime:
    """Load live upstream modules from `.tools/` if present, else fallback shim."""
    root = Path(workspace_root).resolve()
    ao_dir = root / ".tools" / "auto-ontology"
    eval_dir = root / ".tools" / "auto-ontology-eval"

    schemas_path = ao_dir / "auto_ontology" / "server" / "model_interchange" / "schemas.py"
    tools_path = ao_dir / "mcp" / "auto_ontology_mcp" / "tools.py"

    upstream_loaded = False
    ao_version = "fallback"
    ao_commit: str | None = None
    curated_tools = list(DEFAULT_CURATED_MCP_TOOLS)

    if schemas_path.is_file() and tools_path.is_file():
        schemas_mod = _load_file_module("antirea_upstream_ao_schemas", schemas_path)
        for cls_name in REQUIRED_SCHEMA_CLASSES:
            if not hasattr(schemas_mod, cls_name):
                raise RuntimeError(f"Upstream schemas.py missing required class {cls_name}")
        parsed_tools = _parse_curated_mcp_tools(tools_path)
        if parsed_tools:
            curated_tools = parsed_tools
        ao_version = _read_pyproject_version(ao_dir)
        if (ao_dir / ".git").exists():
            ao_commit = _run_git(ao_dir, "rev-parse", "HEAD")
        upstream_loaded = True
    else:
        schemas_mod = _build_fallback_schemas()

    exec_match_path = eval_dir / "ontology_sql_eval" / "gym" / "exec_match.py"
    compare_path = eval_dir / "ontology_sql_eval" / "gym" / "compare.py"
    eval_loaded = False
    eval_version = "fallback"
    eval_commit: str | None = None
    exec_match_mod = None
    compare_mod = None

    if exec_match_path.is_file() and compare_path.is_file():
        exec_match_mod = _load_file_module("antirea_upstream_ao_exec_match", exec_match_path)
        # Ensure `ontology_sql_eval.gym.exec_match` resolves to the exact loaded module
        # before loading `compare.py`, which imports `UNUSABLE_FAILURES` from it.
        import types

        pkg_root = sys.modules.setdefault("ontology_sql_eval", types.ModuleType("ontology_sql_eval"))
        pkg_gym = sys.modules.setdefault("ontology_sql_eval.gym", types.ModuleType("ontology_sql_eval.gym"))
        setattr(pkg_root, "gym", pkg_gym)
        sys.modules["ontology_sql_eval.gym.exec_match"] = exec_match_mod
        setattr(pkg_gym, "exec_match", exec_match_mod)
        compare_mod = _load_file_module("antirea_upstream_ao_compare", compare_path)
        eval_version = _read_pyproject_version(eval_dir)
        if (eval_dir / ".git").exists():
            eval_commit = _run_git(eval_dir, "rev-parse", "HEAD")
        eval_loaded = True

    return UpstreamRuntime(
        upstream_loaded=upstream_loaded,
        eval_loaded=eval_loaded,
        auto_ontology_version=ao_version,
        auto_ontology_eval_version=eval_version,
        auto_ontology_commit=ao_commit,
        auto_ontology_eval_commit=eval_commit,
        schemas=schemas_mod,
        curated_mcp_tools=curated_tools,
        exec_match=exec_match_mod,
        compare=compare_mod,
    )


def verify_upstream_contracts(workspace_root: Path) -> dict[str, Any]:
    """Verify upstream schema, OpenAPI MCP route coverage, and eval grader contracts."""
    root = Path(workspace_root).resolve()
    ao_dir = root / ".tools" / "auto-ontology"
    eval_dir = root / ".tools" / "auto-ontology-eval"

    rt = load_upstream_runtime(root)
    issues: list[str] = []
    missing_routes: list[str] = []
    openapi_version = "missing"
    openapi_path_count = 0

    if not rt.upstream_loaded:
        issues.append("auto-ontology checkout missing under .tools/auto-ontology")
    else:
        # Instantiate AutoOntologyModelDocument round-trip smoke check
        doc = rt.schemas.AutoOntologyModelDocument()
        dumped = doc.model_dump()
        rt.schemas.AutoOntologyModelDocument.model_validate(dumped)

        curated_names = {item["name"] for item in rt.curated_mcp_tools}
        missing_curated = sorted(REQUIRED_CURATED_MCP_NAMES - curated_names)
        if missing_curated:
            issues.append(f"CURATED tools missing expected names: {missing_curated}")

        api_json_path = ao_dir / "mcp" / "auto_ontology_mcp" / "auto-ontology-api.json"
        if not api_json_path.is_file():
            issues.append("auto-ontology-api.json missing")
        else:
            api_spec = json.loads(api_json_path.read_text(encoding="utf-8"))
            openapi_version = str(api_spec.get("info", {}).get("version", "unknown"))
            openapi_path_count = len(api_spec.get("paths") or {})
            missing_routes = _missing_from_openapi(rt.curated_mcp_tools, api_spec)
            if missing_routes:
                issues.append(f"OpenAPI spec missing curated routes: {missing_routes}")

    if not rt.eval_loaded:
        issues.append("auto-ontology-eval checkout missing under .tools/auto-ontology-eval")
    else:
        for attr in ("SqliteExecutor", "execute_and_compare", "result_sets_match", "FailureCode"):
            if not hasattr(rt.exec_match, attr):
                issues.append(f"exec_match.py missing required symbol {attr}")
        for attr in ("compare", "broken_rate", "HEALTH_THRESHOLD"):
            if not hasattr(rt.compare, attr):
                issues.append(f"compare.py missing required symbol {attr}")
        if hasattr(rt.exec_match, "result_sets_match"):
            if not rt.exec_match.result_sets_match([(1, "ok")], [(1, "ok")]):
                issues.append("exec_match.result_sets_match smoke test failed")

    file_hashes: dict[str, str] = {}
    for rel, base in (
        ("schemas.py", ao_dir / "auto_ontology/server/model_interchange/schemas.py"),
        ("tools.py", ao_dir / "mcp/auto_ontology_mcp/tools.py"),
        ("auto-ontology-api.json", ao_dir / "mcp/auto_ontology_mcp/auto-ontology-api.json"),
        ("exec_match.py", eval_dir / "ontology_sql_eval/gym/exec_match.py"),
        ("compare.py", eval_dir / "ontology_sql_eval/gym/compare.py"),
    ):
        if base.is_file():
            file_hashes[rel] = _sha256_file(base)

    return {
        "schema_version": 1,
        "status": "verified" if not issues else "failed",
        "verified_utc": _utc_now(),
        "upstream_loaded": rt.upstream_loaded,
        "eval_loaded": rt.eval_loaded,
        "auto_ontology_version": rt.auto_ontology_version,
        "auto_ontology_eval_version": rt.auto_ontology_eval_version,
        "auto_ontology_commit": rt.auto_ontology_commit,
        "auto_ontology_eval_commit": rt.auto_ontology_eval_commit,
        "openapi_version": openapi_version,
        "openapi_path_count": openapi_path_count,
        "curated_mcp_tools": rt.curated_mcp_tools,
        "missing_curated_routes": missing_routes,
        "file_sha256": file_hashes,
        "issues": issues,
    }


def write_toolchain_manifest(
    workspace_root: Path,
    verification: dict[str, Any],
    *,
    auto_ontology_url: str = DEFAULT_AUTO_ONTOLOGY_URL,
    auto_ontology_eval_url: str = DEFAULT_AUTO_ONTOLOGY_EVAL_URL,
) -> Path:
    root = Path(workspace_root).resolve()
    tools_dir = root / ".tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = tools_dir / "auto-ontology-toolchain.json"
    manifest = {
        "schema_version": 1,
        "updated_utc": _utc_now(),
        "auto_ontology_url": auto_ontology_url,
        "auto_ontology_eval_url": auto_ontology_eval_url,
        "auto_ontology_source": str(tools_dir / "auto-ontology"),
        "auto_ontology_eval_source": str(tools_dir / "auto-ontology-eval"),
        "auto_ontology_version": verification["auto_ontology_version"],
        "auto_ontology_eval_version": verification["auto_ontology_eval_version"],
        "auto_ontology_commit": verification["auto_ontology_commit"],
        "auto_ontology_eval_commit": verification["auto_ontology_eval_commit"],
        "openapi_version": verification["openapi_version"],
        "file_sha256": verification["file_sha256"],
        "status": verification["status"],
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest_path


def sync_upstream(
    workspace_root: Path,
    *,
    auto_ontology_url: str = DEFAULT_AUTO_ONTOLOGY_URL,
    auto_ontology_eval_url: str = DEFAULT_AUTO_ONTOLOGY_EVAL_URL,
    branch: str = "main",
    check_remote: bool = False,
    apply_update: bool = False,
) -> dict[str, Any]:
    """Clone or fast-forward `.tools/auto-ontology*`, verifying contracts with rollback."""
    root = Path(workspace_root).resolve()
    tools_dir = root / ".tools"
    tools_dir.mkdir(parents=True, exist_ok=True)

    repos = (
        ("auto_ontology", tools_dir / "auto-ontology", auto_ontology_url),
        ("auto_ontology_eval", tools_dir / "auto-ontology-eval", auto_ontology_eval_url),
    )

    prior_commits: dict[str, str | None] = {}
    updates_available: dict[str, bool] = {"auto_ontology": False, "auto_ontology_eval": False}
    remote_commits: dict[str, str | None] = {"auto_ontology": None, "auto_ontology_eval": None}

    for key, repo_dir, url in repos:
        if not (repo_dir / ".git").exists():
            if not apply_update:
                prior_commits[key] = None
                continue
            _run_git(tools_dir, "clone", "--depth", "1", "--branch", branch, url, str(repo_dir))
            prior_commits[key] = _run_git(repo_dir, "rev-parse", "HEAD")
            remote_commits[key] = prior_commits[key]
        else:
            local_head = _run_git(repo_dir, "rev-parse", "HEAD")
            prior_commits[key] = local_head
            if check_remote or apply_update:
                _run_git(repo_dir, "fetch", "origin", branch)
                remote_head = _run_git(repo_dir, "rev-parse", "FETCH_HEAD")
                remote_commits[key] = remote_head
                updates_available[key] = remote_head != local_head
                if apply_update and remote_head != local_head:
                    _run_git(repo_dir, "merge", "--ff-only", "FETCH_HEAD")

    verification = verify_upstream_contracts(root)
    if apply_update and verification["status"] != "verified":
        # Roll back any repo that had a known-good prior commit!
        rolled_back = False
        for key, repo_dir, _ in repos:
            prev = prior_commits.get(key)
            if prev and (repo_dir / ".git").exists():
                current = _run_git(repo_dir, "rev-parse", "HEAD")
                if current != prev:
                    _run_git(repo_dir, "reset", "--hard", prev)
                    rolled_back = True
        if rolled_back:
            restored = verify_upstream_contracts(root)
            return {
                **restored,
                "status": "rolled_back",
                "failed_update_issues": verification["issues"],
                "updates_available": updates_available,
                "remote_commits": remote_commits,
            }

    if verification["status"] == "verified":
        manifest_path = write_toolchain_manifest(
            root,
            verification,
            auto_ontology_url=auto_ontology_url,
            auto_ontology_eval_url=auto_ontology_eval_url,
        )
        verification["toolchain_manifest"] = str(manifest_path)

    verification["updates_available"] = updates_available
    verification["remote_commits"] = remote_commits
    return verification


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("verify")
    sync_p = sub.add_parser("sync")
    sync_p.add_argument("--check-remote", action="store_true")
    sync_p.add_argument("--apply", action="store_true")
    sync_p.add_argument("--branch", default="main")
    args = parser.parse_args(argv)

    if args.command == "verify":
        res = verify_upstream_contracts(args.workspace)
        if res["status"] == "verified":
            manifest_path = write_toolchain_manifest(args.workspace, res)
            res["toolchain_manifest"] = str(manifest_path)
    else:
        res = sync_upstream(
            args.workspace,
            branch=args.branch,
            check_remote=args.check_remote,
            apply_update=args.apply,
        )
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0 if res["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
