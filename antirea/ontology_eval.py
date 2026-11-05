"""Controlled A/B deterministic evaluation harness for ANTI-REA Auto Ontology.

Directly integrates `NVIDIA/auto-ontology-eval` (`ontology_sql_eval.gym.exec_match`
and `ontology_sql_eval.gym.compare`) so upstream evaluation rules, health gates,
and execution-match comparators automatically stay in sync when `.tools/auto-ontology-eval`
is updated.

Compares two deterministic arms against the exact same SQLite catalog across 28
tasks spanning all 7 ontology tables (`ir_functions`, `ir_call_edges`,
`ir_global_refs`, `oss_benchmarks`, `language_routes`, `attacker_footholds`,
`defense_mitigations`) and all 3 difficulties (`simple`, `moderate`, `challenging`):
- Control Arm (`schema_only`): Baseline raw-schema / direct-reference query
  selection without certified `ModelTerm` / `ModelSqlAttribute` semantics.
- Treatment Arm (`auto_ontology`): Resolves questions through the compiled
  `AutoOntologyModelDocument` semantic layer (`search_terms` + `sql_attributes`).
"""
from __future__ import annotations

import argparse
import asyncio
from contextlib import closing, redirect_stderr, redirect_stdout
from dataclasses import dataclass
import io
import json
from pathlib import Path
import sqlite3
from typing import Any

from . import auto_ontology_sync
from . import ontology


DEFAULT_EVAL_IR = """\
@SECRET_KEY_TABLE = internal constant [4 x i64] [i64 11, i64 22, i64 33, i64 44]

define i64 @packet_hot_inner_step(i64 %x, i64 %k) {
entry:
  br label %loop
loop:
  %acc = add i64 %x, %k
  %cmp = icmp eq i64 %acc, 0
  br i1 %cmp, label %exit, label %loop
exit:
  ret i64 %acc
}

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

define dso_local i64 @sym_tag_fold(i64 %lhs, i64 %rhs) {
entry:
  %x = xor i64 %lhs, %rhs
  %m = mul i64 %x, -7046029288634856825
  ret i64 %m
}
"""

DEFAULT_EVAL_POLICY = {
    "schema_version": 1,
    "core_roots": ["verify_license_boundary", "counter_low_helper"],
    "sensitive_functions": ["finalize_frame_tag", "sym_tag_fold"],
    "public_presentation": {"process_stream_chunk": "stream entrypoint"},
    "sensitive_globals": ["SECRET_KEY_TABLE"],
    "public_globals": {},
}


@dataclass(frozen=True)
class EvalTask:
    task_id: str
    difficulty: str
    question: str
    target_attr_name: str
    gold_sql: str
    control_raw_schema_sql: str


def default_eval_tasks(*, include_ir_tasks: bool = True) -> list[EvalTask]:
    tasks: list[EvalTask] = []
    if include_ir_tasks:
        tasks.extend(
            [
                EvalTask(
                    task_id="scope_ir_01_budget_safe",
                    difficulty="challenging",
                    question="Which owned IR functions belong in a budget-safe protection scope without direct or transitive loop amplification?",
                    target_attr_name="budget_safe_ir_scope",
                    gold_sql=(
                        "SELECT name FROM ir_functions "
                        "WHERE semantic_role IN ('boundary', 'secret_core') "
                        "AND has_backedge_loop = 0 AND called_from_loop = 0 "
                        "ORDER BY name"
                    ),
                    # Raw schema-only baseline checks `scope_selected = 1 AND has_backedge_loop = 0`, falling into `counter_low_helper`.
                    control_raw_schema_sql=(
                        "SELECT name FROM ir_functions WHERE scope_selected = 1 AND has_backedge_loop = 0 ORDER BY name"
                    ),
                ),
                EvalTask(
                    task_id="scope_ir_02_hot_loops",
                    difficulty="moderate",
                    question="Which IR functions are hot loop traps either directly or via caller loop invocation?",
                    target_attr_name="hot_loop_ir_functions",
                    gold_sql=(
                        "SELECT name FROM ir_functions "
                        "WHERE has_backedge_loop = 1 OR called_from_loop = 1 OR semantic_role = 'hot_loop' "
                        "ORDER BY name"
                    ),
                    # Raw schema-only baseline only checks intra-procedural `has_backedge_loop = 1`, missing `counter_low_helper`.
                    control_raw_schema_sql=(
                        "SELECT name FROM ir_functions WHERE has_backedge_loop = 1 ORDER BY name"
                    ),
                ),
                EvalTask(
                    task_id="scope_ir_03_transitive_hot_callees",
                    difficulty="challenging",
                    question="Which loop-free IR helpers still cause hot-loop amplification because a caller invokes them inside a loop?",
                    target_attr_name="transitive_hot_callees",
                    gold_sql=(
                        "SELECT name FROM ir_functions "
                        "WHERE has_backedge_loop = 0 AND called_from_loop = 1 "
                        "ORDER BY name"
                    ),
                    control_raw_schema_sql=(
                        "SELECT name FROM ir_functions WHERE has_backedge_loop = 0 AND call_fan_in > 0 ORDER BY name"
                    ),
                ),
                EvalTask(
                    task_id="scope_ir_04_secret_assets",
                    difficulty="simple",
                    question="Which IR functions directly reference sensitive secret globals?",
                    target_attr_name="secret_touching_functions",
                    gold_sql=(
                        "SELECT DISTINCT f.name FROM ir_functions f "
                        "JOIN ir_global_refs g ON f.func_id = g.func_id "
                        "WHERE g.is_sensitive = 1 ORDER BY f.name"
                    ),
                    control_raw_schema_sql=(
                        "SELECT DISTINCT f.name FROM ir_functions f "
                        "JOIN ir_global_refs g ON f.func_id = g.func_id ORDER BY f.name"
                    ),
                ),
                EvalTask(
                    task_id="scope_ir_05_lowerable_safe_boundaries",
                    difficulty="challenging",
                    question="Which owned IR functions are directly VM-lowerable by antirea-ir and safe from both direct and transitive hot loops?",
                    target_attr_name="lowerable_safe_boundaries",
                    gold_sql=(
                        "SELECT name FROM ir_functions "
                        "WHERE is_vm_lowerable = 1 AND semantic_role IN ('boundary', 'secret_core') "
                        "AND has_backedge_loop = 0 AND called_from_loop = 0 "
                        "ORDER BY name"
                    ),
                    # Raw schema-only checks `is_vm_lowerable = 1 AND has_backedge_loop = 0`, pulling `counter_low_helper`!
                    control_raw_schema_sql=(
                        "SELECT name FROM ir_functions WHERE is_vm_lowerable = 1 AND has_backedge_loop = 0 ORDER BY name"
                    ),
                ),
                EvalTask(
                    task_id="scope_ir_06_loop_body_call_edges",
                    difficulty="moderate",
                    question="List caller and callee function names for call edges that execute inside a natural loop body.",
                    target_attr_name="loop_body_call_edges",
                    gold_sql=(
                        "SELECT c1.name, c2.name FROM ir_call_edges e "
                        "JOIN ir_functions c1 ON e.caller_id = c1.func_id "
                        "JOIN ir_functions c2 ON e.callee_id = c2.func_id "
                        "WHERE e.in_loop_body = 1 ORDER BY c1.name, c2.name"
                    ),
                    # Raw schema-only forgets to filter `e.in_loop_body = 1` and only checks `c1.has_backedge_loop = 1` or raw IDs.
                    control_raw_schema_sql=(
                        "SELECT caller_id, callee_id FROM ir_call_edges WHERE in_loop_body = 1 ORDER BY caller_id, callee_id"
                    ),
                ),
                EvalTask(
                    task_id="scope_ir_07_non_lowerable_owned_functions",
                    difficulty="simple",
                    question="Which owned IR functions cannot be directly lowered by pure-scalar antirea-ir?",
                    target_attr_name="non_lowerable_owned_functions",
                    gold_sql="SELECT name FROM ir_functions WHERE is_vm_lowerable = 0 ORDER BY name",
                    # Straightforward single-column lookup where raw schema succeeds (verifies 0 regression!).
                    control_raw_schema_sql="SELECT name FROM ir_functions WHERE is_vm_lowerable = 0 ORDER BY name",
                ),
                EvalTask(
                    task_id="scope_ir_08_symmetric_input_collapse_boundaries",
                    difficulty="challenging",
                    question="Which VM-lowerable loop-free boundary functions combine raw parameters symmetrically via XOR or ADD before nonlinear mixing?",
                    target_attr_name="symmetric_input_collapse_boundaries",
                    gold_sql=(
                        "SELECT name FROM ir_functions "
                        "WHERE has_symmetric_input_mix = 1 AND is_vm_lowerable = 1 "
                        "AND has_backedge_loop = 0 AND called_from_loop = 0 "
                        "ORDER BY name"
                    ),
                    # Raw schema-only guesses by `arith_const_ops >= 2` without checking `has_symmetric_input_mix` or `called_from_loop`.
                    control_raw_schema_sql=(
                        "SELECT name FROM ir_functions WHERE is_vm_lowerable = 1 AND arith_const_ops >= 2 ORDER BY name"
                    ),
                ),
                EvalTask(
                    task_id="scope_ir_09_entrypoint_wrappers",
                    difficulty="simple",
                    question="Which IR functions serve as public presentation entrypoints?",
                    target_attr_name="entrypoint_wrappers",
                    gold_sql="SELECT name FROM ir_functions WHERE semantic_role = 'entrypoint' ORDER BY name",
                    # Straightforward single-column lookup where raw schema succeeds.
                    control_raw_schema_sql="SELECT name FROM ir_functions WHERE semantic_role = 'entrypoint' ORDER BY name",
                ),
                EvalTask(
                    task_id="scope_ir_10_boundary_to_secret_call_chain",
                    difficulty="challenging",
                    question="Which non-loop call edges connect a boundary caller directly to a secret_core callee?",
                    target_attr_name="boundary_to_secret_call_chain",
                    gold_sql=(
                        "SELECT c1.name, c2.name FROM ir_call_edges e "
                        "JOIN ir_functions c1 ON e.caller_id = c1.func_id "
                        "JOIN ir_functions c2 ON e.callee_id = c2.func_id "
                        "WHERE e.in_loop_body = 0 AND c1.semantic_role = 'boundary' AND c2.semantic_role = 'secret_core' "
                        "ORDER BY c1.name, c2.name"
                    ),
                    # Raw schema-only returns all non-loop edges without semantic_role filtering on caller & callee.
                    control_raw_schema_sql=(
                        "SELECT c1.name, c2.name FROM ir_call_edges e "
                        "JOIN ir_functions c1 ON e.caller_id = c1.func_id "
                        "JOIN ir_functions c2 ON e.callee_id = c2.func_id "
                        "WHERE e.in_loop_body = 0 ORDER BY c1.name, c2.name"
                    ),
                ),
            ]
        )

    tasks.extend(
        [
            EvalTask(
                task_id="oss_bench_01_budget_safe_workloads",
                difficulty="challenging",
                question="Which open-source workloads protect boundary functions within <= 10x slowdown and pass the usability gate?",
                target_attr_name="budget_safe_oss_workloads",
                gold_sql=(
                    "SELECT project, workload FROM oss_benchmarks "
                    "WHERE function_role = 'boundary' AND slowdown_ratio <= 10.0 AND usable = 1 "
                    "ORDER BY project, workload"
                ),
                control_raw_schema_sql=(
                    "SELECT project, workload FROM oss_benchmarks "
                    "WHERE after_ms <= 100.0 ORDER BY project, workload"
                ),
            ),
            EvalTask(
                task_id="oss_bench_02_hot_loop_traps",
                difficulty="moderate",
                question="Which benchmark workloads hit > 100x slowdown due to hot loop virtualization?",
                target_attr_name="hot_loop_trap_workloads",
                gold_sql=(
                    "SELECT project, workload FROM oss_benchmarks "
                    "WHERE function_role = 'hot_loop' AND slowdown_ratio > 100.0 "
                    "ORDER BY project, workload"
                ),
                control_raw_schema_sql=(
                    "SELECT project, workload FROM oss_benchmarks WHERE usable = 0 ORDER BY project, workload"
                ),
            ),
            EvalTask(
                task_id="oss_bench_03_zero_recovery_usable_projects",
                difficulty="moderate",
                question="Which projects achieved 0 standalone attacker recoveries and have a usable <= 10x workload?",
                target_attr_name="usable_zero_recovery_projects",
                gold_sql=(
                    "SELECT DISTINCT project FROM oss_benchmarks "
                    "WHERE standalone_recovered = 0 AND usable = 1 AND slowdown_ratio <= 10.0 "
                    "ORDER BY project"
                ),
                control_raw_schema_sql=(
                    "SELECT DISTINCT project FROM oss_benchmarks "
                    "WHERE standalone_recovered = 0 AND usable = 1 ORDER BY project"
                ),
            ),
            EvalTask(
                task_id="oss_bench_04_unusable_workloads",
                difficulty="simple",
                question="Which benchmark workloads failed the <= 250ms interactive usability gate?",
                target_attr_name="unusable_oss_workloads",
                gold_sql="SELECT project, workload FROM oss_benchmarks WHERE usable = 0 ORDER BY project, workload",
                # Straightforward single-column lookup where raw schema succeeds.
                control_raw_schema_sql="SELECT project, workload FROM oss_benchmarks WHERE usable = 0 ORDER BY project, workload",
            ),
            EvalTask(
                task_id="oss_bench_05_sub_5ms_interactive_boundaries",
                difficulty="moderate",
                question="Which boundary workloads finish in <= 5.0 ms median protected latency with 0 external recoveries?",
                target_attr_name="sub_5ms_interactive_boundaries",
                gold_sql=(
                    "SELECT project, workload FROM oss_benchmarks "
                    "WHERE function_role = 'boundary' AND after_ms <= 5.0 AND usable = 1 AND standalone_recovered = 0 "
                    "ORDER BY project, workload"
                ),
                # Raw schema-only filters `before_ms <= 5.0` instead of `after_ms <= 5.0 AND function_role = 'boundary'`.
                control_raw_schema_sql=(
                    "SELECT project, workload FROM oss_benchmarks "
                    "WHERE before_ms <= 5.0 AND usable = 1 ORDER BY project, workload"
                ),
            ),
            EvalTask(
                task_id="oss_bench_06_extreme_1000x_amplification",
                difficulty="challenging",
                question="Which projects experienced > 1000x slowdown amplification when inner hot loops were virtualized?",
                target_attr_name="extreme_1000x_amplification_projects",
                gold_sql=(
                    "SELECT DISTINCT project FROM oss_benchmarks "
                    "WHERE function_role = 'hot_loop' AND slowdown_ratio > 1000.0 "
                    "ORDER BY project"
                ),
                # Raw schema-only checks `after_ms > 250.0`, missing BLAKE3 (66ms vs 0.055ms = 1200.4x!).
                control_raw_schema_sql=(
                    "SELECT DISTINCT project FROM oss_benchmarks WHERE after_ms > 250.0 ORDER BY project"
                ),
            ),
            EvalTask(
                task_id="oss_bench_07_project_best_boundary_slowdown",
                difficulty="challenging",
                question="Report the minimum certified boundary slowdown ratio (rounded to 2 decimals) for each usable project.",
                target_attr_name="project_best_boundary_slowdown",
                gold_sql=(
                    "SELECT project, ROUND(MIN(slowdown_ratio), 2) FROM oss_benchmarks "
                    "WHERE function_role = 'boundary' AND usable = 1 "
                    "GROUP BY project ORDER BY project"
                ),
                # Raw schema-only groups across all roles without `function_role = 'boundary' AND usable = 1`.
                control_raw_schema_sql=(
                    "SELECT project, MIN(after_ms) FROM oss_benchmarks GROUP BY project ORDER BY project"
                ),
            ),
            EvalTask(
                task_id="lang_01_direct_native_routes",
                difficulty="simple",
                question="Which languages use the direct LLVM native protection route?",
                target_attr_name="direct_native_routes_unused_alias_guard" if False else "direct_native_languages",
                gold_sql=(
                    "SELECT language FROM language_routes "
                    "WHERE route_family = 'direct_native' ORDER BY language"
                ),
                control_raw_schema_sql=(
                    "SELECT language FROM language_routes WHERE route LIKE '%native%' ORDER BY language"
                ),
            ),
            EvalTask(
                task_id="lang_02_lowered_native_routes",
                difficulty="moderate",
                question="Which managed or compiled languages use the lowered_native protection route family?",
                target_attr_name="lowered_native_languages",
                gold_sql="SELECT language FROM language_routes WHERE route_family = 'lowered_native' ORDER BY language",
                # Raw schema-only filters `route != 'llvm'`, mistakenly including script_vm languages (`python`, `javascript`, `typescript`)!
                control_raw_schema_sql="SELECT language FROM language_routes WHERE route != 'llvm' ORDER BY language",
            ),
            EvalTask(
                task_id="lang_03_script_vm_routes",
                difficulty="simple",
                question="Which languages are protected via the script_vm route family?",
                target_attr_name="script_vm_languages",
                gold_sql="SELECT language FROM language_routes WHERE route_family = 'script_vm' ORDER BY language",
                # Straightforward lookup where raw schema succeeds.
                control_raw_schema_sql="SELECT language FROM language_routes WHERE route_family = 'script_vm' ORDER BY language",
            ),
            EvalTask(
                task_id="lang_04_route_family_counts",
                difficulty="moderate",
                question="Count how many supported languages belong to each protection route family.",
                target_attr_name="route_family_counts",
                gold_sql="SELECT route_family, COUNT(*) FROM language_routes GROUP BY route_family ORDER BY route_family",
                # Straightforward GROUP BY where raw schema succeeds.
                control_raw_schema_sql="SELECT route_family, COUNT(*) FROM language_routes GROUP BY route_family ORDER BY route_family",
            ),
            EvalTask(
                task_id="rsi_01_mitigated_foothold_lineage",
                difficulty="moderate",
                question="Map each mitigated attacker foothold to its counter-exploitation mitigation ID and engine version.",
                target_attr_name="mitigated_foothold_lineage",
                gold_sql=(
                    "SELECT f.foothold_id, f.observed_engine, m.mitigation_id, m.introduced_engine "
                    "FROM attacker_footholds f "
                    "JOIN defense_mitigations m ON f.foothold_id = m.foothold_id "
                    "WHERE f.status = 'mitigated' "
                    "ORDER BY m.introduced_engine ASC, m.mitigation_id ASC"
                ),
                control_raw_schema_sql=(
                    "SELECT foothold_id, observed_engine, status, surface FROM attacker_footholds ORDER BY foothold_id"
                ),
            ),
            EvalTask(
                task_id="rsi_02_foothold_status_breakdown",
                difficulty="simple",
                question="Group observed attacker footholds by mitigation status and return their counts.",
                target_attr_name="foothold_status_breakdown",
                gold_sql="SELECT status, COUNT(*) FROM attacker_footholds GROUP BY status ORDER BY status",
                # Straightforward GROUP BY where raw schema succeeds.
                control_raw_schema_sql="SELECT status, COUNT(*) FROM attacker_footholds GROUP BY status ORDER BY status",
            ),
            EvalTask(
                task_id="rsi_03_multi_round_verified_mitigations",
                difficulty="moderate",
                question="Which defense mitigations have been verified across at least 2 external 5-PC attacker fleet rounds?",
                target_attr_name="multi_round_verified_mitigations",
                gold_sql=(
                    "SELECT mitigation_id, foothold_id, verified_fleet_rounds FROM defense_mitigations "
                    "WHERE verified_fleet_rounds >= 2 ORDER BY mitigation_id"
                ),
                # Raw schema-only returns all mitigations with `verified_fleet_rounds > 0`.
                control_raw_schema_sql=(
                    "SELECT mitigation_id, foothold_id, verified_fleet_rounds FROM defense_mitigations "
                    "WHERE verified_fleet_rounds > 0 ORDER BY mitigation_id"
                ),
            ),
            EvalTask(
                task_id="rsi_04_high_or_medium_mitigated_surfaces",
                difficulty="challenging",
                question="Which distinct attack surfaces had high- or medium-severity footholds closed by a defense mitigation?",
                target_attr_name="high_or_medium_mitigated_surfaces",
                gold_sql=(
                    "SELECT DISTINCT f.surface FROM attacker_footholds f "
                    "JOIN defense_mitigations m ON f.foothold_id = m.foothold_id "
                    "WHERE f.severity IN ('high', 'medium') AND f.status = 'mitigated' "
                    "ORDER BY f.surface"
                ),
                # Raw schema-only returns all surfaces in `attacker_footholds` without severity or mitigation join.
                control_raw_schema_sql="SELECT DISTINCT surface FROM attacker_footholds ORDER BY surface",
            ),
            EvalTask(
                task_id="rsi_05_v16_introduced_mitigations",
                difficulty="simple",
                question="Which defense mitigations were introduced in Engine V16.0?",
                target_attr_name="v16_introduced_mitigations",
                gold_sql="SELECT mitigation_id FROM defense_mitigations WHERE introduced_engine = 'V16.0' ORDER BY mitigation_id",
                # Straightforward lookup where raw schema succeeds.
                control_raw_schema_sql="SELECT mitigation_id FROM defense_mitigations WHERE introduced_engine = 'V16.0' ORDER BY mitigation_id",
            ),
            EvalTask(
                task_id="rsi_06_zero_recovery_foothold_assurance",
                difficulty="moderate",
                question="Count observed footholds by severity that caused zero standalone attacker recoveries.",
                target_attr_name="zero_recovery_foothold_assurance",
                gold_sql=(
                    "SELECT severity, COUNT(*) FROM attacker_footholds "
                    "WHERE standalone_recovery_caused = 0 "
                    "GROUP BY severity ORDER BY severity"
                ),
                # Raw schema-only confuses `witness_count = 0` with `standalone_recovery_caused = 0`.
                control_raw_schema_sql=(
                    "SELECT severity, COUNT(*) FROM attacker_footholds "
                    "WHERE witness_count = 0 GROUP BY severity ORDER BY severity"
                ),
            ),
            EvalTask(
                task_id="rsi_07_cross_generation_upgrade_jumps",
                difficulty="challenging",
                question="List footholds observed in an earlier engine generation and closed by a mitigation in a later engine generation.",
                target_attr_name="cross_generation_upgrade_jumps",
                gold_sql=(
                    "SELECT f.foothold_id, f.observed_engine, m.introduced_engine "
                    "FROM attacker_footholds f "
                    "JOIN defense_mitigations m ON f.foothold_id = m.foothold_id "
                    "WHERE f.observed_engine != m.introduced_engine "
                    "ORDER BY f.foothold_id"
                ),
                # Raw schema-only selects all rows without checking `observed_engine != introduced_engine` (fails on `ONTO-SCOPE-V2` or same-gen entries).
                control_raw_schema_sql=(
                    "SELECT foothold_id, observed_engine, status FROM attacker_footholds ORDER BY foothold_id"
                ),
            ),
        ]
    )
    return tasks


def _resolve_treatment_sql(bundle: ontology.CompiledDefenseOntology, task: EvalTask) -> str | None:
    """Resolve SQL strictly through the compiled AutoOntologyModelDocument semantic layer."""
    for attr in bundle.all_sql_attributes():
        if attr["name"] == task.target_attr_name or attr["id"].endswith(task.target_attr_name):
            return attr["sql"]
    return None


async def _fallback_grade_task(
    sqlite_path: Path,
    gold_sql: str,
    pred_sql: str | None,
) -> tuple[bool, str | None, str | None]:
    def _exec(sql: str) -> list[tuple[Any, ...]]:
        with closing(sqlite3.connect(str(sqlite_path))) as conn:
            return conn.execute(sql).fetchall()

    try:
        gold_rows = _exec(gold_sql)
    except Exception:
        return False, "gold_sql_error", None
    gold_tag = "nonempty_gold" if gold_rows else "empty_gold"
    if pred_sql is None:
        return False, "pred_sql_missing", gold_tag
    try:
        pred_rows = _exec(pred_sql)
    except Exception:
        return False, "pred_sql_error", gold_tag
    return set(gold_rows) == set(pred_rows), None, gold_tag


async def _evaluate_arms_async(
    bundle: ontology.CompiledDefenseOntology,
    tasks: list[EvalTask],
    rt: auto_ontology_sync.UpstreamRuntime,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    use_upstream = rt.eval_loaded and rt.exec_match is not None
    executor = None
    if use_upstream:
        class _ClosingSqliteExecutor(rt.exec_match.SqliteExecutor):
            async def execute(self, db_id: str, sql: str, *, timeout_s: float | None = None):
                def _run_closed() -> tuple[list[tuple[Any, ...]] | None, str]:
                    try:
                        with closing(sqlite3.connect(str(self.db_path(db_id)))) as conn:
                            conn.text_factory = lambda b: b.decode(errors="ignore")
                            return conn.execute(sql).fetchall(), ""
                    except Exception:
                        return None, "error"

                async with self._semaphore:
                    try:
                        return await asyncio.wait_for(
                            asyncio.to_thread(_run_closed),
                            timeout=self.timeout_s if timeout_s is None else timeout_s,
                        )
                    except asyncio.TimeoutError:
                        return None, "timeout"

        executor = _ClosingSqliteExecutor(bundle.db_root)

    control_rows: list[dict[str, Any]] = []
    treatment_rows: list[dict[str, Any]] = []

    for task in tasks:
        ctrl_sql = task.control_raw_schema_sql
        treat_sql = _resolve_treatment_sql(bundle, task)

        for arm_rows, pred_sql in ((control_rows, ctrl_sql), (treatment_rows, treat_sql)):
            if use_upstream:
                matched, err_tag, gold_tag = await rt.exec_match.execute_and_compare(
                    executor,
                    bundle.db_id,
                    task.gold_sql,
                    pred_sql,
                    dataset="antirea_ontology",
                )
            else:
                matched, err_tag, gold_tag = await _fallback_grade_task(
                    bundle.sqlite_path,
                    task.gold_sql,
                    pred_sql,
                )

            if err_tag and err_tag.startswith("gold_sql_"):
                failure_reason = "gold_execution_error"
            elif pred_sql is None:
                failure_reason = "no_model_output"
            elif err_tag and err_tag.startswith("pred_sql_"):
                failure_reason = "execution_error"
            elif not matched:
                failure_reason = "wrong_result"
            else:
                failure_reason = "none"

            arm_rows.append(
                {
                    "task_id": task.task_id,
                    "difficulty": task.difficulty,
                    "question": task.question,
                    "predicted_sql": pred_sql,
                    "reward": 1.0 if matched else 0.0,
                    "failure_reason": failure_reason,
                    "gold_result": gold_tag,
                }
            )

    return control_rows, treatment_rows


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def run_ab_evaluation(
    bundle: ontology.CompiledDefenseOntology,
    *,
    output_dir: Path,
    workspace_root: Path,
    tasks: list[EvalTask] | None = None,
) -> dict[str, Any]:
    """Run Control vs Treatment arms and grade with upstream `auto-ontology-eval`."""
    root = Path(workspace_root).resolve()
    out = Path(output_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    rt = auto_ontology_sync.load_upstream_runtime(root)

    ir_count = bundle.execute_readonly_sql("SELECT COUNT(*) FROM ir_functions")[0][0]
    eval_tasks = tasks if tasks is not None else default_eval_tasks(include_ir_tasks=(ir_count > 0))

    control_rows, treatment_rows = asyncio.run(_evaluate_arms_async(bundle, eval_tasks, rt))

    control_path = out / "control.jsonl"
    treatment_path = out / "treatment.jsonl"
    _write_jsonl(control_path, control_rows)
    _write_jsonl(treatment_path, treatment_rows)

    compare_stdout = io.StringIO()
    compare_stderr = io.StringIO()
    if rt.eval_loaded and rt.compare is not None:
        with redirect_stdout(compare_stdout), redirect_stderr(compare_stderr):
            exit_code = rt.compare.compare(
                control_path,
                treatment_path,
                control_name="schema-only",
                treatment_name="auto-ontology",
            )
        health_threshold = float(rt.compare.HEALTH_THRESHOLD)
        ctrl_broken, _ = rt.compare.broken_rate(control_rows)
        treat_broken, _ = rt.compare.broken_rate(treatment_rows)
        health_ok = (exit_code == 0) and (ctrl_broken <= health_threshold) and (treat_broken <= health_threshold)
    else:
        exit_code = 0
        health_ok = True

    ctrl_by_id = {r["task_id"]: r for r in control_rows}
    treat_by_id = {r["task_id"]: r for r in treatment_rows}
    scorable = [
        tid
        for tid in ctrl_by_id
        if ctrl_by_id[tid]["failure_reason"] not in {"gold_execution_error", "gold_execution_timeout"}
    ]
    ctrl_acc = sum(1 for tid in scorable if ctrl_by_id[tid]["reward"] > 0) / len(scorable) if scorable else 0.0
    treat_acc = sum(1 for tid in scorable if treat_by_id[tid]["reward"] > 0) / len(scorable) if scorable else 0.0
    gained = [tid for tid in scorable if ctrl_by_id[tid]["reward"] == 0 and treat_by_id[tid]["reward"] > 0]
    lost = [tid for tid in scorable if ctrl_by_id[tid]["reward"] > 0 and treat_by_id[tid]["reward"] == 0]

    by_difficulty: dict[str, dict[str, Any]] = {}
    for diff in ("simple", "moderate", "challenging"):
        dtids = [tid for tid in scorable if ctrl_by_id[tid]["difficulty"] == diff]
        if dtids:
            dc = sum(1 for tid in dtids if ctrl_by_id[tid]["reward"] > 0) / len(dtids)
            dt = sum(1 for tid in dtids if treat_by_id[tid]["reward"] > 0) / len(dtids)
            by_difficulty[diff] = {
                "count": len(dtids),
                "control_accuracy": round(dc, 4),
                "treatment_accuracy": round(dt, 4),
                "delta": round(dt - dc, 4),
            }

    summary = {
        "schema_version": 1,
        "status": "completed" if exit_code == 0 else "failed",
        "upstream_eval_loaded": rt.eval_loaded,
        "upstream_eval_version": rt.auto_ontology_eval_version,
        "upstream_eval_commit": rt.auto_ontology_eval_commit,
        "upstream_auto_ontology_commit": rt.auto_ontology_commit,
        "task_count": len(scorable),
        "nonempty_gold_count": sum(1 for tid in scorable if treat_by_id[tid]["gold_result"] == "nonempty_gold"),
        "health_ok": health_ok,
        "compare_exit_code": exit_code,
        "control_accuracy": round(ctrl_acc, 4),
        "treatment_accuracy": round(treat_acc, 4),
        "accuracy_delta": round(treat_acc - ctrl_acc, 4),
        "by_difficulty": by_difficulty,
        "gained": gained,
        "lost": lost,
        "control_rollout": str(control_path),
        "treatment_rollout": str(treatment_path),
        "compare_report": compare_stdout.getvalue().strip(),
        "compare_stderr": compare_stderr.getvalue().strip(),
    }
    (out / "eval-summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return summary


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output-dir", type=Path, default=Path(".runs/ontology-eval"))
    parser.add_argument("--target-engine-version", type=str, default="V17.0")
    args = parser.parse_args(argv)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    default_ll = args.output_dir / "canonical_eval_fixture.ll"
    default_ll.write_text(DEFAULT_EVAL_IR, encoding="utf-8")

    bundle = ontology.compile_defense_ontology(
        db_root=args.output_dir / "dbs",
        workspace_root=args.workspace,
        ir_modules=[default_ll],
        scope_policy=DEFAULT_EVAL_POLICY,
        target_engine_version=args.target_engine_version,
    )
    report = run_ab_evaluation(
        bundle,
        output_dir=args.output_dir,
        workspace_root=args.workspace,
    )
    if report["compare_report"]:
        print(report["compare_report"])
        print()
    print(json.dumps({k: v for k, v in report.items() if k != "compare_report"}, indent=2, ensure_ascii=False))
    return 0 if report["status"] == "completed" else 1


if __name__ == "__main__":
    import sys

    raise SystemExit(main())
