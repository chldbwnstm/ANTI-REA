"""Tests for upstream-updatable NVIDIA Auto Ontology (A) + Eval (C) integration.

Covers:
1. Live loading of upstream `.tools/auto-ontology` & `.tools/auto-ontology-eval`
   plus git fast-forward update & automatic rollback on breaking upstream changes.
2. Compilation of ANTI-REA IR scope + benchmark telemetry into a genuine upstream
   `AutoOntologyModelDocument` (YAML round-trip + SQLite read-only authorizer).
3. Read-only `antirea.ontology_mcp` JSON-RPC 2.0 server aligned with upstream
   curated MCP tools (`check_readiness`, `search_terms`, `get_term`, etc.).
4. Controlled A/B deterministic evaluation (`antirea.ontology_eval`) powered by
   upstream `ontology_sql_eval.gym.exec_match` and `ontology_sql_eval.gym.compare`.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from antirea import __version__
from antirea import auto_ontology_sync
from antirea import ontology
from antirea import ontology_eval
from antirea import ontology_mcp


REPO_ROOT = Path(__file__).resolve().parent.parent

SAMPLE_IR = """\
define i64 @packet_ hot_inner_step(i64 %x, i64 %k) {
entry:
  br label %loop
loop:
  %acc = add i64 %x, %k
  %cmp = icmp eq i64 %acc, 0
  br i1 %cmp, label %exit, label %loop
exit:
  ret i64 %acc
}
""".replace("@packet_ hot_inner_step", "@packet_hot_inner_step") + """
@SECRET_KEY_TABLE = internal constant [4 x i64] [i64 11, i64 22, i64 33, i64 44]

define i64 @verify_license_boundary(i64 %input) {
entry:
  %ptr = getelementptr [4 x i64], ptr @SECRET_KEY_TABLE, i64 0, i64 0
  %k = load i64, ptr %ptr
  %mixed = xor i64 %input, %k
  ret i64 %mixed
}

define i64 @finalize_frame_tag(i64 %frame_crc) {
entry:
  %tag = call i64 @verify_license_boundary(i64 %frame_crc)
  ret i64 %tag
}

define i64 @counter_low_helper(i64 %ctr) {
entry:
  %lo = and i64 %ctr, 4294967295
  ret i64 %lo
}

define i64 @chunk_compress_driver(i64 %chunks) {
entry:
  br label %chunk_loop
chunk_loop:
  %c = call i64 @counter_low_helper(i64 %chunks)
  %done_cond = icmp eq i64 %c, 0
  br i1 %done_cond, label %after_loop, label %chunk_loop
after_loop:
  ret i64 %c
}

define i64 @process_stream_chunk(i64 %chunk) {
entry:
  %step = call i64 @packet_hot_inner_step(i64 %chunk, i64 7)
  %drv = call i64 @chunk_compress_driver(i64 %step)
  %done = call i64 @finalize_frame_tag(i64 %drv)
  ret i64 %done
}
"""

SAMPLE_OSS_METRICS = [
    {
        "project": "xxHash",
        "protected_functions": ["XXH64_mergeRound", "XXH64_avalanche"],
        "workload": "16mb_stream_hash",
        "function_role": "boundary",
        "before_ms": 0.771,
        "after_ms": 4.944,
        "slowdown_ratio": 6.41,
        "pure_cpu_us_per_call": 67.08,
        "usable": True,
        "standalone_recovered": 0,
    },
    {
        "project": "xxHash",
        "protected_functions": ["XXH64_avalanche"],
        "workload": "64b_short_records_2048",
        "function_role": "hot_loop",
        "before_ms": 0.012,
        "after_ms": 500.917,
        "slowdown_ratio": 41743.08,
        "pure_cpu_us_per_call": 244.59,
        "usable": False,
        "standalone_recovered": 0,
    },
    {
        "project": "LZ4",
        "protected_functions": ["LZ4_compressBound", "XXH32_avalanche"],
        "workload": "4mb_lz4f_roundtrip",
        "function_role": "boundary",
        "before_ms": 1.347,
        "after_ms": 2.278,
        "slowdown_ratio": 1.69,
        "pure_cpu_us_per_call": 96.11,
        "usable": True,
        "standalone_recovered": 0,
    },
    {
        "project": "BLAKE3",
        "protected_functions": ["counter_low", "counter_high"],
        "workload": "64kb_merkle_stream",
        "function_role": "hot_loop",
        "before_ms": 0.055,
        "after_ms": 66.022,
        "slowdown_ratio": 1200.40,
        "pure_cpu_us_per_call": 59.92,
        "usable": True,
        "standalone_recovered": 0,
    },
    {
        "project": "Lua-5.4",
        "protected_functions": ["luaV_shiftl", "luaO_applyparam"],
        "workload": "prime_sieve_and_gc",
        "function_role": "boundary",
        "before_ms": 2.000,
        "after_ms": 3.500,
        "slowdown_ratio": 1.75,
        "pure_cpu_us_per_call": 408.16,
        "usable": True,
        "standalone_recovered": 0,
    },
    {
        "project": "SQLite-3.46.1",
        "protected_functions": ["sqlite3VarintLen", "sqlite3AbsInt32"],
        "workload": "1000_insert_create_index",
        "function_role": "hot_loop",
        "before_ms": 0.410,
        "after_ms": 71.718,
        "slowdown_ratio": 174.92,
        "pure_cpu_us_per_call": 301.12,
        "usable": True,
        "standalone_recovered": 0,
    },
    {
        "project": "SQLite-3.46.1",
        "protected_functions": ["sqlite3AbsInt32"],
        "workload": "5000_indexed_select",
        "function_role": "boundary",
        "before_ms": 0.784,
        "after_ms": 0.775,
        "slowdown_ratio": 0.99,
        "pure_cpu_us_per_call": 301.12,
        "usable": True,
        "standalone_recovered": 0,
    },
]


def _git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-c", "core.hooksPath=NUL", *args],
        cwd=str(cwd),
        check=True,
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip()


_HAS_UPSTREAM_TOOLS = (
    (REPO_ROOT / ".tools/auto-ontology").is_dir()
    and (REPO_ROOT / ".tools/auto-ontology-eval").is_dir()
)


class UpstreamSyncTests(unittest.TestCase):
    @unittest.skipUnless(
        _HAS_UPSTREAM_TOOLS,
        "Requires synced .tools/auto-ontology* checkout (run `python -m antirea.auto_ontology_sync sync --apply`)",
    )
    def test_live_upstream_checkout_loads_schemas_mcp_and_eval_contracts(self) -> None:
        info = auto_ontology_sync.verify_upstream_contracts(REPO_ROOT)
        self.assertEqual(info["status"], "verified")
        self.assertTrue(info["upstream_loaded"])
        self.assertTrue(info["eval_loaded"])
        self.assertEqual(info["missing_curated_routes"], [])
        curated_names = {item["name"] for item in info["curated_mcp_tools"]}
        self.assertTrue(
            {
                "search_terms",
                "get_term",
                "get_term_columns",
                "get_term_sql_attributes",
                "get_sql_attribute",
                "describe_table",
                "check_answerable",
            }.issubset(curated_names)
        )
        self.assertRegex(info["auto_ontology_commit"], r"^[0-9a-f]{40}$")
        self.assertRegex(info["auto_ontology_eval_commit"], r"^[0-9a-f]{40}$")

    @unittest.skipUnless(
        _HAS_UPSTREAM_TOOLS,
        "Requires synced .tools/auto-ontology* checkout (run `python -m antirea.auto_ontology_sync sync --apply`)",
    )
    def test_cli_verify_writes_toolchain_manifest_under_windows_encoding(self) -> None:
        proc = subprocess.run(
            ["python", "-m", "antirea.auto_ontology_sync", "--workspace", str(REPO_ROOT), "verify"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "verified")
        self.assertTrue((REPO_ROOT / ".tools/auto-ontology-toolchain.json").is_file())

    def test_clean_clone_fallback_without_upstream_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            empty_ws = Path(tmp)
            ir_file = empty_ws / "clean.ll"
            ir_file.write_text(SAMPLE_IR, encoding="utf-8")
            bundle = ontology.compile_defense_ontology(
                db_root=empty_ws / "dbs",
                workspace_root=empty_ws,
                ir_modules=[ir_file],
                benchmark_records=SAMPLE_OSS_METRICS,
                target_engine_version="V19.0",
            )
            self.assertFalse(bundle.upstream_runtime.upstream_loaded)
            yaml_text = bundle.to_yaml()
            reloaded = ontology.validate_model_yaml(yaml_text, workspace_root=empty_ws)
            self.assertGreaterEqual(len(reloaded["semantic_layer"]["terms"]), 4)
            report = ontology_eval.run_ab_evaluation(
                bundle,
                output_dir=empty_ws / "eval-out",
                workspace_root=empty_ws,
            )
            self.assertEqual(report["status"], "completed")
            self.assertEqual(report["treatment_accuracy"], 1.0)
            self.assertEqual(report["lost"], [])

    def test_sync_upstream_fast_forwards_valid_update_and_rolls_back_breaking_update(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            origin_ao = tmp_path / "origin-ao"
            origin_eval = tmp_path / "origin-eval"
            workspace = tmp_path / "workspace"
            (workspace / ".tools").mkdir(parents=True)

            # Create minimal valid upstream git repositories matching NVIDIA contracts.
            for repo in (origin_ao, origin_eval):
                repo.mkdir(parents=True)
                _git(repo, "init", "-b", "main")
                _git(repo, "config", "user.email", "test@example.com")
                _git(repo, "config", "user.name", "Test")

            ao_schemas_dir = origin_ao / "auto_ontology" / "server" / "model_interchange"
            ao_schemas_dir.mkdir(parents=True)
            for pkg in (
                origin_ao / "auto_ontology",
                origin_ao / "auto_ontology" / "server",
                ao_schemas_dir,
            ):
                (pkg / "__init__.py").write_text("", encoding="utf-8")
            schemas_file = REPO_ROOT / ".tools/auto-ontology/auto_ontology/server/model_interchange/schemas.py"
            if schemas_file.is_file():
                real_schemas = schemas_file.read_text(encoding="utf-8")
            else:
                cls_defs = "\n".join(
                    f"class {c}:\n    def model_dump(self): return {{}}\n    @classmethod\n    def model_validate(cls, d): return cls()\n"
                    for c in auto_ontology_sync.REQUIRED_SCHEMA_CLASSES
                )
                real_schemas = cls_defs
            (ao_schemas_dir / "schemas.py").write_text(real_schemas, encoding="utf-8")
            (origin_ao / "pyproject.toml").write_text(
                '[project]\nname = "auto-ontology-server"\nversion = "1.1.0"\n',
                encoding="utf-8",
            )
            mcp_dir = origin_ao / "mcp" / "auto_ontology_mcp"
            mcp_dir.mkdir(parents=True)
            tools_file = REPO_ROOT / ".tools/auto-ontology/mcp/auto_ontology_mcp/tools.py"
            api_file = REPO_ROOT / ".tools/auto-ontology/mcp/auto_ontology_mcp/auto-ontology-api.json"
            real_tools = tools_file.read_text(encoding="utf-8") if tools_file.is_file() else "# fallback curated tools\n"
            if api_file.is_file():
                real_api = api_file.read_text(encoding="utf-8")
            else:
                real_api = json.dumps(
                    {
                        "info": {"version": "1.1.0"},
                        "paths": {item["path"]: {item["method"].lower(): {}} for item in auto_ontology_sync.DEFAULT_CURATED_MCP_TOOLS},
                    }
                )
            (mcp_dir / "tools.py").write_text(real_tools, encoding="utf-8")
            (mcp_dir / "auto-ontology-api.json").write_text(real_api, encoding="utf-8")
            _git(origin_ao, "add", ".")
            _git(origin_ao, "commit", "-m", "initial v1.1.0")
            c1_ao = _git(origin_ao, "rev-parse", "HEAD")

            eval_gym = origin_eval / "ontology_sql_eval" / "gym"
            eval_gym.mkdir(parents=True)
            (origin_eval / "ontology_sql_eval" / "__init__.py").write_text("", encoding="utf-8")
            (eval_gym / "__init__.py").write_text("", encoding="utf-8")
            exec_src = REPO_ROOT / ".tools/auto-ontology-eval/ontology_sql_eval/gym/exec_match.py"
            cmp_src = REPO_ROOT / ".tools/auto-ontology-eval/ontology_sql_eval/gym/compare.py"
            (eval_gym / "exec_match.py").write_text(
                exec_src.read_text(encoding="utf-8")
                if exec_src.is_file()
                else "UNUSABLE_FAILURES = set()\nclass SqliteExecutor: pass\nclass FailureCode: pass\ndef result_sets_match(a, b): return a == b\nasync def execute_and_compare(*a, **k): return True, None, 'nonempty_gold'\n",
                encoding="utf-8",
            )
            (eval_gym / "compare.py").write_text(
                cmp_src.read_text(encoding="utf-8")
                if cmp_src.is_file()
                else "HEALTH_THRESHOLD = 0.05\ndef broken_rate(rows): return 0.0, {}\ndef compare(*a, **k): return 0\n",
                encoding="utf-8",
            )
            (origin_eval / "pyproject.toml").write_text(
                '[project]\nname = "ontology-sql-eval"\nversion = "0.1.0"\n',
                encoding="utf-8",
            )
            _git(origin_eval, "add", ".")
            _git(origin_eval, "commit", "-m", "initial eval v0.1.0")

            # Initial clone + pin via sync_upstream
            res1 = auto_ontology_sync.sync_upstream(
                workspace,
                auto_ontology_url=str(origin_ao),
                auto_ontology_eval_url=str(origin_eval),
                apply_update=True,
            )
            self.assertEqual(res1["status"], "verified")
            self.assertEqual(res1["auto_ontology_commit"], c1_ao)
            self.assertTrue((workspace / ".tools/auto-ontology-toolchain.json").is_file())

            # Upstream releases v1.2.0 (valid non-breaking update)
            (origin_ao / "pyproject.toml").write_text(
                '[project]\nname = "auto-ontology-server"\nversion = "1.2.0"\n',
                encoding="utf-8",
            )
            _git(origin_ao, "add", "pyproject.toml")
            _git(origin_ao, "commit", "-m", "release v1.2.0")
            c2_ao = _git(origin_ao, "rev-parse", "HEAD")

            check_only = auto_ontology_sync.sync_upstream(
                workspace,
                auto_ontology_url=str(origin_ao),
                auto_ontology_eval_url=str(origin_eval),
                check_remote=True,
                apply_update=False,
            )
            self.assertTrue(check_only["updates_available"]["auto_ontology"])
            self.assertEqual(check_only["auto_ontology_commit"], c1_ao)

            res2 = auto_ontology_sync.sync_upstream(
                workspace,
                auto_ontology_url=str(origin_ao),
                auto_ontology_eval_url=str(origin_eval),
                apply_update=True,
            )
            self.assertEqual(res2["status"], "verified")
            self.assertEqual(res2["auto_ontology_commit"], c2_ao)
            self.assertEqual(res2["auto_ontology_version"], "1.2.0")

            # Upstream pushes a breaking change removing /api/terms from OpenAPI spec
            broken_api = json.loads(real_api)
            broken_api["paths"].pop("/api/terms", None)
            (mcp_dir / "auto-ontology-api.json").write_text(
                json.dumps(broken_api), encoding="utf-8"
            )
            _git(origin_ao, "add", "mcp/auto_ontology_mcp/auto-ontology-api.json")
            _git(origin_ao, "commit", "-m", "breaking openapi removal")

            res3 = auto_ontology_sync.sync_upstream(
                workspace,
                auto_ontology_url=str(origin_ao),
                auto_ontology_eval_url=str(origin_eval),
                apply_update=True,
            )
            self.assertEqual(res3["status"], "rolled_back")
            # Must have rolled back to known-good c2_ao!
            head_after = _git(workspace / ".tools/auto-ontology", "rev-parse", "HEAD")
            self.assertEqual(head_after, c2_ao)


class OntologyBuildAndMcpTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp.name)
        self.ir_path = self.tmp_path / "sample.ll"
        self.ir_path.write_text(SAMPLE_IR, encoding="utf-8")
        self.policy = {
            "schema_version": 1,
            "core_roots": ["verify_license_boundary", "counter_low_helper"],
            "sensitive_functions": ["finalize_frame_tag"],
            "public_presentation": {"process_stream_chunk": "stream entrypoint"},
            "sensitive_globals": ["SECRET_KEY_TABLE"],
            "public_globals": {},
        }
        self.bundle = ontology.compile_defense_ontology(
            db_root=self.tmp_path / "dbs",
            workspace_root=REPO_ROOT,
            ir_modules=[self.ir_path],
            scope_policy=self.policy,
            benchmark_records=SAMPLE_OSS_METRICS,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_compiled_model_validates_against_upstream_schema_and_roundtrips_yaml(self) -> None:
        yaml_text = self.bundle.to_yaml()
        self.assertIn("data_layer:", yaml_text)
        self.assertIn("semantic_layer:", yaml_text)
        reloaded = ontology.validate_model_yaml(yaml_text, workspace_root=REPO_ROOT)
        term_names = {t["name"] for t in reloaded["semantic_layer"]["terms"]}
        self.assertIn("Boundary Function", term_names)
        self.assertIn("Hot Loop Function", term_names)
        self.assertIn("Secret Asset", term_names)
        self.assertIn("Protection Benchmark", term_names)

    def test_readonly_authorizer_blocks_sql_mutations(self) -> None:
        rows = self.bundle.execute_readonly_sql("SELECT COUNT(*) FROM ir_functions")
        self.assertEqual(rows[0][0], 6)
        for malicious in (
            "DROP TABLE ir_functions",
            "DELETE FROM ir_functions",
            "INSERT INTO ir_functions VALUES ('x','x',0,0,0,0,0,1,'boundary')",
            "PRAGMA writable_schema = 1",
        ):
            with self.subTest(sql=malicious):
                with self.assertRaises(PermissionError):
                    self.bundle.execute_readonly_sql(malicious)

    def test_recommend_scope_selects_boundary_and_excludes_direct_and_transitive_hot_loops(self) -> None:
        rec = self.bundle.recommend_scope(max_slowdown=10.0)
        self.assertIn("verify_license_boundary", rec["recommended_ir_functions"])
        self.assertIn("finalize_frame_tag", rec["recommended_ir_functions"])
        self.assertNotIn("packet_hot_inner_step", rec["recommended_ir_functions"])
        self.assertNotIn("chunk_compress_driver", rec["recommended_ir_functions"])
        # `counter_low_helper` has NO loop inside itself, but is called inside `chunk_loop`!
        self.assertNotIn("counter_low_helper", rec["recommended_ir_functions"])
        self.assertIn("counter_low_helper", rec["excluded_hot_loop_ir_functions"])
        # Benchmark scope recommendations also exclude >10x hot-loop traps
        oss_projects = {item["project"]: item for item in rec["benchmark_budget_safe"]}
        self.assertIn("xxHash", oss_projects)
        self.assertIn("LZ4", oss_projects)
        self.assertNotIn("BLAKE3", oss_projects)  # 1200.4x exceeds max_slowdown=10

    def test_zero_config_ir_analysis_infers_vm_lowerable_scope_without_manual_policy(self) -> None:
        raw_oss_ir = """\
define dso_local i64 @xxh_round_trap(i64 %acc, i64 %input) {
entry:
  %m = mul i64 %input, -4417276706812531889
  %a = add i64 %acc, %m
  %r = call i64 @llvm.fshl.i64(i64 %a, i64 %a, i64 31)
  %out = mul i64 %r, -7046029288634856825
  ret i64 %out
}

define dso_local i64 @xxh_stripe_loop(ptr %buf, i64 %blocks) {
entry:
  br label %stripe
stripe:
  %idx = phi i64 [ 0, %entry ], [ %next, %stripe ]
  %acc = phi i64 [ 1, %entry ], [ %upd, %stripe ]
  %p = getelementptr inbounds nuw i8, ptr %buf, i64 %idx
  %v = load i64, ptr %p, align 1
  %upd = call i64 @xxh_round_trap(i64 %acc, i64 %v)
  %next = add i64 %idx, 8
  %done = icmp uge i64 %next, %blocks
  br i1 %done, label %exit, label %stripe
exit:
  ret i64 %upd
}

define dso_local i64 @xxh_avalanche_final(i64 %h) {
entry:
  %s1 = lshr i64 %h, 33
  %x1 = xor i64 %h, %s1
  %m1 = mul i64 %x1, -4417276706812531889
  %s2 = lshr i64 %m1, 29
  %x2 = xor i64 %m1, %s2
  %m2 = mul i64 %x2, -8796714831421723037
  %s3 = lshr i64 %m2, 32
  %out = xor i64 %m2, %s3
  ret i64 %out
}

declare void @external_io_hook(ptr)

define dso_local i64 @non_lowerable_wrapper(ptr %ctx) {
entry:
  call void @external_io_hook(ptr %ctx)
  ret i64 0
}
"""
        raw_ll = self.tmp_path / "zero_cfg.ll"
        raw_ll.write_text(raw_oss_ir, encoding="utf-8")
        zero_bundle = ontology.compile_defense_ontology(
            db_root=self.tmp_path / "dbs-zero",
            workspace_root=REPO_ROOT,
            ir_modules=[raw_ll],
        )
        rec = zero_bundle.recommend_scope(max_slowdown=10.0, only_vm_lowerable=True)
        self.assertEqual(rec["recommended_ir_functions"], ["xxh_avalanche_final"])
        self.assertIn("xxh_round_trap", rec["excluded_hot_loop_ir_functions"])
        self.assertIn("xxh_stripe_loop", rec["excluded_hot_loop_ir_functions"])
        self.assertNotIn("non_lowerable_wrapper", rec["recommended_ir_functions"])

    def test_foothold_and_mitigation_lineage_tracks_open_and_mitigated_surfaces(self) -> None:
        bridge = ontology_mcp.OntologyMcpBridge(self.bundle, workspace_root=REPO_ROOT)
        bridge.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "test-client", "version": "1.0"},
                },
            }
        )
        bridge.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
        foothold_terms = bridge.call("search_terms", {"query": "foothold"})
        self.assertTrue(any(t["id"] == "term.attack_foothold" for t in foothold_terms["terms"]))
        mitigated = bridge.call("run_sql_attribute", {"attr_id": "attr.mitigated_foothold_lineage"})
        self.assertGreaterEqual(len(mitigated["rows"]), 2)
        open_before_v16 = ontology.compile_defense_ontology(
            db_root=self.tmp_path / "dbs-v15",
            workspace_root=REPO_ROOT,
            target_engine_version="V15.2",
        )
        open_rows = open_before_v16.execute_readonly_sql(
            "SELECT foothold_id FROM attacker_footholds WHERE status = 'open' ORDER BY foothold_id"
        )
        open_ids = [r[0] for r in open_rows]
        self.assertIn("F1_FIXED_INPUT_PACKING_AND_ASCII_IMMS", open_ids)
        self.assertIn("F2_PROLOGUE_LINEAR_STEP_AND_MOD8_CADENCE", open_ids)
        self.assertIn("F3_FIXED_16_CLUSTER_PDATA_AND_CALL_ABI", open_ids)

        open_at_v16 = self.bundle.execute_readonly_sql(
            "SELECT foothold_id FROM attacker_footholds WHERE status = 'open' ORDER BY foothold_id"
        )
        v16_open_ids = [r[0] for r in open_at_v16]
        self.assertNotIn("F1_FIXED_INPUT_PACKING_AND_ASCII_IMMS", v16_open_ids)
        self.assertNotIn("F2_PROLOGUE_LINEAR_STEP_AND_MOD8_CADENCE", v16_open_ids)
        self.assertNotIn("F3_FIXED_16_CLUSTER_PDATA_AND_CALL_ABI", v16_open_ids)
        self.assertIn("F5_FIXED_ROTATE_11_17_53_SALTS", v16_open_ids)
        self.assertIn("F6_FIXED_256_RDATA_TABLE_AND_SINGLE_MULHI_ROUTER", v16_open_ids)
        self.assertIn("F7_FRAME_ARG_SPILL_AND_COUNTED_SECONDARY_LOOPS", v16_open_ids)
        self.assertIn("F8_PDATA_BIMODAL_FUNCTION_SIZE_GAP", v16_open_ids)

        v17_bundle = ontology.compile_defense_ontology(
            db_root=self.tmp_path / "dbs-v17",
            workspace_root=REPO_ROOT,
            target_engine_version="V17.0",
        )
        v17_open_ids = [
            r[0]
            for r in v17_bundle.execute_readonly_sql(
                "SELECT foothold_id FROM attacker_footholds WHERE status = 'open' ORDER BY foothold_id"
            )
        ]
        self.assertNotIn("F5_FIXED_ROTATE_11_17_53_SALTS", v17_open_ids)
        self.assertNotIn("F6_FIXED_256_RDATA_TABLE_AND_SINGLE_MULHI_ROUTER", v17_open_ids)
        self.assertNotIn("F7_FRAME_ARG_SPILL_AND_COUNTED_SECONDARY_LOOPS", v17_open_ids)
        self.assertNotIn("F8_PDATA_BIMODAL_FUNCTION_SIZE_GAP", v17_open_ids)
        self.assertIn("F9_MULTILANG_NULL_BC_ABI_AND_MOD512_RING", v17_open_ids)
        self.assertIn("F10_SYMMETRIC_BINARY_BOUNDARY_INPUT_COLLAPSE", v17_open_ids)

        v18_bundle = ontology.compile_defense_ontology(
            db_root=self.tmp_path / "dbs-v18",
            workspace_root=REPO_ROOT,
            target_engine_version="V18.0",
        )
        v18_open_ids = [
            r[0]
            for r in v18_bundle.execute_readonly_sql(
                "SELECT foothold_id FROM attacker_footholds WHERE status = 'open' ORDER BY foothold_id"
            )
        ]
        self.assertNotIn("F9_MULTILANG_NULL_BC_ABI_AND_MOD512_RING", v18_open_ids)
        self.assertNotIn("F10_SYMMETRIC_BINARY_BOUNDARY_INPUT_COLLAPSE", v18_open_ids)
        self.assertIn("F12_VAULT_UNIFORM_SCALAR_BYTE_MASK", v18_open_ids)
        self.assertIn("F13_FAST_ENTROPY_FIXED_SIMD_SHIFT_SIGNATURE", v18_open_ids)
        self.assertIn("F14_HDR_ROUTE_LOW7_UNBLINDED_BITFIELD", v18_open_ids)

        v17_rounds = dict(
            v18_bundle.execute_readonly_sql(
                "SELECT mitigation_id, verified_fleet_rounds FROM defense_mitigations WHERE introduced_engine = 'V17.0'"
            )
        )
        for mid in ("V17-M1", "V17-M2", "V17-M3", "V17-M4"):
            self.assertGreaterEqual(v17_rounds[mid], 2)

        v18_rounds = dict(
            v18_bundle.execute_readonly_sql(
                "SELECT mitigation_id, verified_fleet_rounds FROM defense_mitigations WHERE introduced_engine = 'V18.0'"
            )
        )
        self.assertGreaterEqual(v18_rounds["V18-M1"], 3)
        self.assertGreaterEqual(v18_rounds["ONTO-SYM-V3"], 3)

        v19_bundle = ontology.compile_defense_ontology(
            db_root=self.tmp_path / "dbs-v19",
            workspace_root=REPO_ROOT,
            target_engine_version="V19.0",
        )
        v19_open_ids = [
            r[0]
            for r in v19_bundle.execute_readonly_sql(
                "SELECT foothold_id FROM attacker_footholds WHERE status = 'open' ORDER BY foothold_id"
            )
        ]
        self.assertNotIn("F12_VAULT_UNIFORM_SCALAR_BYTE_MASK", v19_open_ids)
        self.assertNotIn("F13_FAST_ENTROPY_FIXED_SIMD_SHIFT_SIGNATURE", v19_open_ids)
        self.assertNotIn("F14_HDR_ROUTE_LOW7_UNBLINDED_BITFIELD", v19_open_ids)
        self.assertEqual(v19_open_ids, ["F11_PUBLIC_IO_DIFFERENTIAL_ORACLE_BOUNDARY"])

        v19_rounds = dict(
            v19_bundle.execute_readonly_sql(
                "SELECT mitigation_id, verified_fleet_rounds FROM defense_mitigations WHERE introduced_engine = 'V19.0'"
            )
        )
        for mid in ("V19-M1", "V19-M2", "V19-M3"):
            self.assertGreaterEqual(v19_rounds[mid], 2)

    def test_detects_symmetric_binary_boundary_input_collapse_advisory(self) -> None:
        sym_ir = """\
define dso_local i64 @symmetric_finalize(i64 %state, i64 %secret) {
entry:
  %collapsed = xor i64 %state, %secret
  %m = mul i64 %collapsed, -7046029288634856825
  ret i64 %m
}

define dso_local i64 @asymmetric_finalize(i64 %state, i64 %secret) {
entry:
  %s1 = mul i64 %secret, -4417276706812531889
  %mixed = xor i64 %state, %s1
  ret i64 %mixed
}
"""
        sym_ll = self.tmp_path / "sym_check.ll"
        sym_ll.write_text(sym_ir, encoding="utf-8")
        sym_bundle = ontology.compile_defense_ontology(
            db_root=self.tmp_path / "dbs-sym",
            workspace_root=REPO_ROOT,
            ir_modules=[sym_ll],
        )
        rec = sym_bundle.recommend_scope(max_slowdown=10.0, only_vm_lowerable=True)
        self.assertIn("symmetric_finalize", rec["symmetric_input_mix_warnings"])
        self.assertNotIn("asymmetric_finalize", rec["symmetric_input_mix_warnings"])

    def test_loads_verified_oss_v16_3arm_ab_records(self) -> None:
        fixture_ab = (
            self.tmp_path
            / "results/2026-11-05/ledger/defense-loop/20261105-oss-ontology-v16-rsi2/oss-ontology-ab-metrics.json"
        )
        fixture_ab.parent.mkdir(parents=True, exist_ok=True)
        fixture_ab.write_text(
            json.dumps(
                {
                    "full_application_3arm_ab": [
                        {
                            "project": "LZ4",
                            "workload_primary": "128 KB LZ4F",
                            "naive_scope": ["XXH32_round", "LZ4_compressBound"],
                            "ontology_scope": ["LZ4_compressBound"],
                            "primary_ms": {
                                "baseline_median_ms": 0.086,
                                "naive_v16_median_ms": 3389.673,
                                "ontology_v16_median_ms": 0.780,
                                "naive_usable": False,
                                "ontology_usable": True,
                            },
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        synth_rows = ontology.load_verified_oss_v16_ab_records(self.tmp_path)
        self.assertEqual(len(synth_rows), 2)
        self.assertFalse(synth_rows[0]["usable"])
        self.assertTrue(synth_rows[1]["usable"])

        live_ab = (
            REPO_ROOT
            / "results/2026-11-05/ledger/defense-loop/20261105-oss-ontology-v16-rsi2/oss-ontology-ab-metrics.json"
        )
        if live_ab.is_file():
            v16_rows = ontology.load_verified_oss_v16_ab_records(REPO_ROOT)
            self.assertEqual(len(v16_rows), 10)
            ont_rows = [r for r in v16_rows if r["function_role"] == "boundary"]
            naive_rows = [r for r in v16_rows if r["function_role"] == "hot_loop"]
            self.assertEqual(len(ont_rows), 5)
            self.assertEqual(len(naive_rows), 5)
            self.assertTrue(all(r["usable"] for r in ont_rows))
            self.assertGreaterEqual(sum(1 for r in naive_rows if not r["usable"]), 4)

    def test_ontology_mcp_jsonrpc_readonly_tools(self) -> None:
        bridge = ontology_mcp.OntologyMcpBridge(self.bundle, workspace_root=REPO_ROOT)
        init = bridge.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "test-client", "version": "1.0"},
                },
            }
        )
        self.assertEqual(init["result"]["serverInfo"]["version"], __version__)
        self.assertIsNone(
            bridge.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
        )

        listed = bridge.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tools = listed["result"]["tools"]
        names = {t["name"] for t in tools}
        self.assertTrue(
            {
                "check_readiness",
                "search_terms",
                "get_term",
                "get_term_columns",
                "get_term_sql_attributes",
                "get_sql_attribute",
                "describe_table",
                "check_answerable",
                "recommend_scope",
                "run_sql_attribute",
            }.issubset(names)
        )
        for tool in tools:
            self.assertTrue(tool["annotations"]["readOnlyHint"])
            self.assertIs(tool["inputSchema"]["additionalProperties"], False)

        def call_tool(name: str, arguments: dict | None = None) -> dict:
            resp = bridge.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 10,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments or {}},
                }
            )
            self.assertFalse(resp["result"]["isError"], resp)
            return json.loads(resp["result"]["content"][0]["text"])

        readiness = call_tool("check_readiness")
        self.assertTrue(readiness["ready"])
        self.assertTrue(readiness["semantic_layer_built"])
        self.assertTrue(readiness["can_execute_sql"])

        hits = call_tool("search_terms", {"query": "hot loop"})
        self.assertGreaterEqual(len(hits["terms"]), 1)
        hot_term_id = hits["terms"][0]["id"]

        term_detail = call_tool("get_term", {"term_id": hot_term_id})
        self.assertEqual(term_detail["id"], hot_term_id)
        cols = call_tool("get_term_columns", {"term_id": hot_term_id})
        self.assertGreaterEqual(len(cols["columns_attributes"]), 1)

        answerable = call_tool(
            "check_answerable",
            {"question": "Which boundary functions stay under 10x slowdown ratio?"},
        )
        self.assertTrue(answerable["answerable"])

    def test_aligned_bitslice_symmetric_boundary_detection_catches_trunc_and_shift_xor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ir_path = tmp_path / "bitslice.ll"
            ir_path.write_text(
                """
define dso_local i64 @aligned_halfword_fold(i64 %0, i64 %1) {
entry:
  %t0 = trunc i64 %0 to i32
  %t1 = trunc i64 %1 to i32
  %x0 = xor i32 %t0, %t1
  %s0 = lshr i64 %0, 32
  %s1 = lshr i64 %1, 32
  %hi = xor i64 %s0, %s1
  %lo64 = zext i32 %x0 to i64
  %res = add i64 %lo64, %hi
  ret i64 %res
}

define dso_local i64 @misaligned_cross_fold(i64 %0, i64 %1) {
entry:
  %t0 = trunc i64 %0 to i32
  %s1 = lshr i64 %1, 32
  %t1 = trunc i64 %s1 to i32
  %x0 = xor i32 %t0, %t1
  %res = zext i32 %x0 to i64
  ret i64 %res
}
""",
                encoding="utf-8",
            )
            bundle = ontology.compile_defense_ontology(
                db_root=tmp_path / "dbs",
                workspace_root=REPO_ROOT,
                ir_modules=[ir_path],
            )
            bridge = ontology_mcp.OntologyMcpBridge(bundle, workspace_root=REPO_ROOT)
            rec = bridge.call("recommend_scope", {"max_slowdown": 10.0, "only_vm_lowerable": True})
            warnings = set(rec["symmetric_input_mix_warnings"])
            self.assertIn("aligned_halfword_fold", warnings)
            self.assertNotIn("misaligned_cross_fold", warnings)


class OntologyEvalHarnessTests(unittest.TestCase):
    def test_controlled_ab_evaluation_uses_upstream_grader_and_proves_positive_delta(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ir_path = tmp_path / "sample.ll"
            eval_ir = SAMPLE_IR + """
define dso_local i64 @sym_tag_fold(i64 %lhs, i64 %rhs) {
entry:
  %x = xor i64 %lhs, %rhs
  %m = mul i64 %x, -7046029288634856825
  ret i64 %m
}
"""
            ir_path.write_text(eval_ir, encoding="utf-8")
            policy = {
                "schema_version": 1,
                "core_roots": ["verify_license_boundary", "counter_low_helper"],
                "sensitive_functions": ["finalize_frame_tag", "sym_tag_fold"],
                "public_presentation": {"process_stream_chunk": "stream entrypoint"},
                "sensitive_globals": ["SECRET_KEY_TABLE"],
                "public_globals": {},
            }
            bundle = ontology.compile_defense_ontology(
                db_root=tmp_path / "dbs",
                workspace_root=REPO_ROOT,
                ir_modules=[ir_path],
                scope_policy=policy,
                benchmark_records=SAMPLE_OSS_METRICS,
            )
            report = ontology_eval.run_ab_evaluation(
                bundle,
                output_dir=tmp_path / "eval-out",
                workspace_root=REPO_ROOT,
            )
            self.assertEqual(report["status"], "completed")
            self.assertTrue(report["health_ok"])
            self.assertEqual(report["compare_exit_code"], 0)
            self.assertGreaterEqual(report["task_count"], 28)
            self.assertGreater(report["treatment_accuracy"], report["control_accuracy"])
            self.assertGreater(report["accuracy_delta"], 0.5)
            self.assertEqual(report["treatment_accuracy"], 1.0)
            self.assertEqual(report["lost"], [])
            self.assertGreaterEqual(len(report["gained"]), 18)


if __name__ == "__main__":
    unittest.main()
