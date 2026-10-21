"""Authored pure/mocked tests only: no compiler, Cargo, DLL or external process.

The module under test is the repository's antirea/rust_cargo_objects.py,
source-loaded without a private draft fallback. Filesystem fixtures are temporary.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = next(parent for parent in Path(__file__).resolve().parents
            if (parent / "antirea/projects.py").is_file())
MODULE = ROOT / "antirea/rust_cargo_objects.py"
m = types.ModuleType("cargo_object_production_under_test")
m.__file__ = str(MODULE)
sys.modules[m.__name__] = m
exec(compile(MODULE.read_bytes(), str(MODULE), "exec", dont_inherit=True), m.__dict__)


def put(target, raw=b"owned"):
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    return {"path": str(target), "sha256": m.sha(raw), "bytes": len(raw)}


def layer(name, *, applied=True):
    return {"function": name, "requested_passes": ["fla", "sub", "co"],
            "fla_dispatcher": applied, "substitution_instructions": int(applied),
            "constant_obfuscation_instructions": int(applied)}


def successful_process(argv, stdout, stderr, *, pid=43210):
    """Real process.py success shape; inert PID value, no process is launched."""
    return {"argv": list(argv), "returncode": 0, "pid": pid, "timed_out": False, "cancelled": False,
            "seconds": 0.001, "stdout": stdout, "stderr": stderr, "cleanup": {
                "parent_pid": pid, "status": "assigned_job_empty", "parent_exit_confirmed": True,
                "method": "windows_job", "job_assigned": True,
                "assignment_timing": "immediately_after_launch", "active_before": 0, "active_after": 0,
                "job_handle_closed": True,
                "limitations": ["Descendants created before job assignment may escape containment."]}}


def inventory(roots):
    roots = sorted(set(roots), key=str)
    directories, files = [], []
    for root in roots:
        for current, children, leaves in os.walk(root):
            directories.append(str(Path(current)))
            for name in sorted(leaves):
                p = Path(current) / name
                raw = p.read_bytes()
                files.append({"path": str(p), "sha256": m.sha(raw), "bytes": len(raw)})
    data = {"roots": list(map(str, roots)), "directories": sorted(directories),
            "files": sorted(files, key=lambda x: x["path"])}
    return {**data, "sha256": m.sha(m.canonical(data))}


@dataclass(frozen=True)
class FakeIRInput:
    path: Path
    sha256: str


@dataclass(frozen=True)
class FakeRequest:
    source_ir: FakeIRInput
    protection_ir: FakeIRInput
    selected_functions: tuple
    seed: int
    public_boundary_ir: object = None


class Fixture:
    def __init__(self, root):
        self.root, self.calls = root, []
        self.source = root / "owned_project"
        self.source.mkdir()
        self.prepare = root / ".runs/prepared"
        self.prepare.mkdir(parents=True)
        self.output = root / ".runs/objects"
        self.temp = root / ".runs/temporary"
        self.temp.mkdir()
        self.windows = root / "Windows"
        (self.windows / "System32").mkdir(parents=True)
        self.llvm = root / ".tools/llvm"
        (self.llvm / "bin").mkdir(parents=True)
        (self.llvm / "lib/clang/22/include").mkdir(parents=True)
        self.sdk = root / "SDK/include"
        self.sdk.mkdir(parents=True)
        put(self.sdk / "stdint.h")
        put(self.llvm / "lib/clang/22/include/stddef.h")
        self.config = {"target": m.TARGET, "llvm_root": str(self.llvm)}
        self.tools = {}
        for role, filename in (("optimizer", "kagura-opt.exe"), ("clang", "clang.exe"),
                               ("clangxx", "clang++.exe")):
            item = put(self.llvm / "bin" / filename, role.encode())
            self.config[role] = item["path"]
            self.tools[item["path"]] = item["sha256"]
        config_item = put(root / ".tools/kagura-toolchain.json", m.canonical(self.config))
        self.tools[config_item["path"]] = config_item["sha256"]
        self.pins = dict(self.tools)
        self.environment = {"SYSTEMROOT": str(self.windows), "WINDIR": str(self.windows),
            "PATH": str(self.llvm / "bin") + ";" + str(self.windows / "System32"),
            "TEMP": str(self.temp), "TMP": str(self.temp), "INCLUDE": str(self.sdk)}
        self.context = {"schema_version": 1, "configuration": config_item,
            "toolchain": copy.deepcopy(self.config), "tool_pins": dict(self.tools),
            "header_inventory": inventory([self.llvm / "lib/clang", self.sdk]),
            "compiler_environment": m.environment_receipt(self.environment)}
        self.source_ir = put(self.prepare / "module.qualified.ll", b"qualified raw baseline\r\n")
        self.protected_ir = put(self.prepare / "module.protection-input.ll", b"mapped normalized protection\n")
        owner = {"unit": "arbitrary-unit", "package_id": "local-package#1", "target_name": "owned-core",
                 "source": str(self.source / "lib.rs")}
        self.lineage = [{"owner": owner, "source_symbol": name, "qualified_symbol": name,
                         "surviving_symbols": [target], "protected_symbols": [target],
                         "inlined_not_a_separate_wrapper": name == "inlined"}
                        for name, target in (("api", "api"), ("helper", "mapped_helper"), ("inlined", "api"))]
        self.handoff = {"source_ir_kind": m.SOURCE_KIND, "source_ir": self.source_ir,
            "protection_ir": self.protected_ir, "selected_functions": ["api", "mapped_helper"],
            "public_exports": ["api"], "source_definition_lineage": copy.deepcopy(self.lineage),
            "object_pipeline_executed": False,
            "original_reference_kind": "separate_captured_original_Cargo_DLL_required"}
        self.report = {"status": "cargo_ir_prepared_unlinked_unvalidated", "inputs_unchanged": True,
            "object_handoff": self.handoff, "source_definition_lineage": copy.deepcopy(self.lineage),
            "lineage": {"qualified_linked_ir": self.source_ir, "mapped_ir": self.protected_ir}}
        self.preparation = put(self.prepare / "preparation.json", m.canonical(self.report))
        self.plan = put(root / ".runs/plan.json", m.canonical({"inspection": {
            "input_snapshot": {"roots": [str(self.source)]}}}))
        self.capture = put(root / ".runs/capture.json", b"{}")
        self.verified = {"status": "preparation_receipt_rechecked_unlinked_unvalidated",
            "receipt": {key: self.preparation[key] for key in ("path", "sha256")},
            "source_ir_kind": m.SOURCE_KIND, "selected_functions": ["api", "mapped_helper"],
            "public_exports": ["api"], "checked_inputs": [self.source_ir, self.protected_ir]}
        self.verify_count = 0
        self.after_finalize = None
        self.fail_phase = None
        self.command_mutation = None
        self.modules = {
            "rust_cargo_prepare": types.SimpleNamespace(verify_preparation_receipt=self.verify),
            "rust_cargo_build": types.SimpleNamespace(inventory_trees=inventory),
            "native_build": types.SimpleNamespace(_toolchain=lambda _: (copy.deepcopy(self.config), dict(self.tools)),
                _layer_evidence=lambda text, name: layer(name, applied=name != "api")),
            "native_objects": types.SimpleNamespace(IRInput=FakeIRInput, ObjectRequest=FakeRequest,
                ObjectPipeline=self.pipeline)}

    def verify(self, *args, **kwargs):
        self.verify_count += 1
        self.calls.append("verify")
        return copy.deepcopy(self.verified)

    @contextmanager
    def imported(self, *args):
        yield self.modules

    def kwargs(self):
        return dict(capture_path=self.capture["path"], capture_sha256=self.capture["sha256"],
            plan_path=self.plan["path"], plan_sha256=self.plan["sha256"], workspace_root=self.root,
            output_dir=self.output, trusted_engine_pins=self.pins, trusted_native_context=self.context,
            source_environment={}, preparation_environment={k: v for k, v in self.environment.items() if k != "INCLUDE"},
            compiler_environment=self.environment)

    def run(self):
        with patch.object(m, "_modules", self.imported):
            return m.build_prepared_objects(self.preparation["path"], self.preparation["sha256"], **self.kwargs())

    def pipeline(self, request, *, workspace_root, output_dir, command_records, environment, build_tool_hashes):
        fixture = self
        self.request = request
        self.calls.append("construct")
        class FakePipeline:
            dispatchers = ["antirea_dispatch_0123456789abcdef", "antirea_dispatch_fedcba9876543210"]
            pre_text = "owned mock IR"

            def event(self, label):
                fixture.calls.append(label)
                if fixture.fail_phase == label:
                    raise ValueError("injected stage failure")

            def prepare(self):
                self.event("prepare")
                for name, stage in m.STAGES.items():
                    if stage == "preparing":
                        put(output_dir / name, name.encode())

            def compile_runtime(self):
                self.event("runtime")
                put(output_dir / "runtime.obj", b"runtime object")

            def compile_arm(self, arm):
                self.event(arm)
                for suffix in (".codegen.ll", ".obj"):
                    put(output_dir / (arm + suffix), (arm + suffix).encode())

            def finalize(self):
                self.event("finalize")
                result = fixture.evidence(output_dir, request, self.dispatchers)
                recipes = m._command_recipes(fixture.config, output_dir, list(request.selected_functions),
                                              request.seed, self.dispatchers)
                for index, argv in enumerate(recipes, 1):
                    prefix = output_dir / "logs" / f"{index:03d}"
                    stdout = put(Path(str(prefix) + ".stdout.log"), b"")
                    stderr = put(Path(str(prefix) + ".stderr.log"), b"")
                    process = successful_process(argv, stdout["path"], stderr["path"], pid=43210 + index)
                    put(Path(str(prefix) + ".process.json"), m.canonical(process))
                    command_records.append({**process, "cwd": str(output_dir)})
                if fixture.command_mutation:
                    fixture.command_mutation(command_records)
                if fixture.after_finalize:
                    fixture.after_finalize(result)
                return result
        return FakePipeline()

    def evidence(self, output, request, dispatchers):
        watched = {}
        for name, stage in m.STAGES.items():
            raw = (output / name).read_bytes()
            watched[name] = {"path": str(output / name), "sha256": m.sha(raw), "bytes": len(raw), "observed_stage": stage}
        objects = {arm: {k: watched[arm + ".obj"][k] for k in ("path", "sha256", "bytes")}
                   for arm in ("baseline", "protected", "runtime")}
        selected = list(request.selected_functions)
        vm = {name: {"virtualized": True, "dispatcher": dispatchers[index]} for index, name in enumerate(selected)}
        return {"status": "native_objects_created_unlinked", "selected_functions": selected,
            "source_ir": {"path": str(request.source_ir.path), "sha256": request.source_ir.sha256},
            "protection_ir": {"path": str(request.protection_ir.path), "sha256": request.protection_ir.sha256},
            "original_vm": {name: {"virtualized": True, "dispatcher": "kagura_vm_execute"} for name in selected},
            "functions": copy.deepcopy(vm), "final_vm": copy.deepcopy(vm), "objects": objects,
            "runtime_evidence": {"engines": {name: layer(name) for name in dispatchers}},
            "hardening_evidence": {"qualification": "mock structural evidence"}, "watched_outputs": watched,
            "final_ir": {k: watched["protected.codegen.ll"][k] for k in ("path", "sha256", "bytes")}}


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.f = Fixture(Path(self.temp.name).resolve())

    def test_complete_fixed_stages_keep_raw_baseline_and_mapped_protection(self):
        result = self.f.run()
        self.assertEqual(result["status"], "native_objects_created_unlinked")
        self.assertEqual(self.f.calls, ["verify", "construct", "prepare", "runtime", "baseline", "protected", "finalize", "verify"])
        self.assertEqual(self.f.request.source_ir.path.read_bytes(), b"qualified raw baseline\r\n")
        self.assertEqual(self.f.request.protection_ir.path.read_bytes(), b"mapped normalized protection\n")
        self.assertEqual(self.f.request.selected_functions, ("api", "mapped_helper"))
        self.assertIsNone(self.f.request.public_boundary_ir)
        self.assertEqual(len(result["coverage"]["by_source_definition"]), 3)
        self.assertFalse(result["coverage"]["pre_vm_evidence"]["api"]["fla_dispatcher"])
        for key in ("native_linked", "target_executed", "published"):
            self.assertIs(result[key], False)
        self.assertEqual(json.loads((self.f.output / "report.json").read_text()), result)

    def test_stage_failure_is_retained_unlinked_failure(self):
        self.f.fail_phase = "protected"
        result = self.f.run()
        self.assertEqual(result["status"], "failed_native_objects_unlinked")
        self.assertNotIn("finalize", self.f.calls)
        self.assertIn("injected stage failure", result["error"])

    def test_terminal_preparation_drift_cannot_leave_success(self):
        original = self.f.verify
        def changed(*a, **kw):
            value = original(*a, **kw)
            if self.f.verify_count == 2:
                value["new_unverified_field"] = True
            return value
        self.f.modules["rust_cargo_prepare"].verify_preparation_receipt = changed
        self.assertEqual(self.f.run()["status"], "failed_native_objects_unlinked")

    def test_terminal_sdk_mutation_cannot_leave_success(self):
        self.f.after_finalize = lambda _: (self.f.sdk / "stdint.h").write_bytes(b"changed")
        result = self.f.run()
        self.assertEqual(result["status"], "failed_native_objects_unlinked")
        self.assertIn("inventory changed", result["error"])

    def test_final_import_pin_failure_cannot_leave_success(self):
        @contextmanager
        def fail_after(*args):
            yield self.f.modules
            raise ValueError("terminal imported source changed")
        with patch.object(m, "_modules", fail_after):
            result = m.build_prepared_objects(self.f.preparation["path"], self.f.preparation["sha256"], **self.f.kwargs())
        self.assertEqual(result["status"], "failed_native_objects_unlinked")

    def test_stage_output_mutation_is_not_hidden_by_cached_coverage(self):
        self.f.after_finalize = lambda _: (self.f.output / "protected.obj").write_bytes(b"tampered")
        self.assertEqual(self.f.run()["status"], "failed_native_objects_unlinked")

    def test_wrong_stage_label_is_rejected(self):
        self.f.after_finalize = lambda result: result["watched_outputs"]["runtime.obj"].update(observed_stage="preparing")
        self.assertEqual(self.f.run()["status"], "failed_native_objects_unlinked")

    def test_missing_final_wrapper_is_rejected(self):
        self.f.after_finalize = lambda result: result["final_vm"].pop("mapped_helper")
        self.assertEqual(self.f.run()["status"], "failed_native_objects_unlinked")

    def test_extra_vm_wrapper_is_rejected(self):
        self.f.after_finalize = lambda result: result["functions"].update(extra={"virtualized": True})
        self.assertEqual(self.f.run()["status"], "failed_native_objects_unlinked")

    def test_false_virtualization_is_rejected(self):
        self.f.after_finalize = lambda result: result["original_vm"]["api"].update(virtualized=1)
        self.assertEqual(self.f.run()["status"], "failed_native_objects_unlinked")

    def test_runtime_layers_are_required_for_each_dispatcher(self):
        self.f.after_finalize = lambda result: next(iter(result["runtime_evidence"]["engines"].values())).update(
            substitution_instructions=0)
        self.assertEqual(self.f.run()["status"], "failed_native_objects_unlinked")

    def test_command_order_or_flags_cannot_change(self):
        self.f.command_mutation = lambda rows: rows[0]["argv"].append("-extra")
        self.assertEqual(self.f.run()["status"], "failed_native_objects_unlinked")

    def test_command_cleanup_is_mandatory(self):
        self.f.command_mutation = lambda rows: rows[-1]["cleanup"].update(status="unverified")
        self.assertEqual(self.f.run()["status"], "failed_native_objects_unlinked")

    def test_process_json_mismatch_is_rejected(self):
        self.f.command_mutation = lambda rows: rows[-1].update(extra="not in process file")
        self.assertEqual(self.f.run()["status"], "failed_native_objects_unlinked")

    def test_current_toolchain_mismatch_blocks_before_output_or_pipeline(self):
        self.f.context["toolchain"]["optimizer"] = "different.exe"
        with self.assertRaises(ValueError):
            self.f.run()
        self.assertFalse(self.f.output.exists())
        self.assertEqual(self.f.calls, ["verify"])

    def test_missing_caller_tool_pin_blocks_before_output(self):
        self.f.pins.pop(self.f.config["optimizer"])
        with self.assertRaises(ValueError):
            self.f.run()
        self.assertFalse(self.f.output.exists())

    def test_ambient_flag_or_secret_environment_key_is_rejected(self):
        self.f.environment["CL"] = "/DSECRET=1"
        with self.assertRaises(ValueError):
            self.f.run()
        self.assertFalse(self.f.output.exists())

    def test_changed_environment_digest_is_rejected(self):
        self.f.context["compiler_environment"]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.f.run()

    def test_header_addition_is_not_ignored(self):
        put(self.f.sdk / "new.h")
        with self.assertRaises(ValueError):
            self.f.run()

    def test_sensitive_header_name_rejected_before_inventory_reads(self):
        put(self.f.sdk / "env.setting", b"inert forbidden-name fixture")
        with patch.object(self.f.modules["rust_cargo_build"], "inventory_trees") as scan:
            with self.assertRaises(ValueError):
                self.f.run()
            scan.assert_not_called()

    def test_existing_output_is_never_overwritten(self):
        self.f.output.mkdir()
        sentinel = put(self.f.output / "owned.txt")
        with self.assertRaises(ValueError):
            self.f.run()
        self.assertEqual((self.f.output / "owned.txt").read_bytes(), b"owned")

    def test_source_output_overlap_is_rejected(self):
        self.f.output = self.f.source / "child"
        with self.assertRaises(ValueError):
            self.f.run()

    def test_bool_seed_is_rejected(self):
        with patch.object(m, "_modules", self.f.imported), self.assertRaises(ValueError):
            m.build_prepared_objects(self.f.preparation["path"], self.f.preparation["sha256"],
                                    **self.f.kwargs(), seed=True)

    def test_stop_prevents_verification_and_pipeline(self):
        put(self.f.root / ".runs/defense-loop/STOP")
        with self.assertRaises(ValueError):
            self.f.run()
        self.assertFalse(self.f.output.exists())
        self.assertNotIn("construct", self.f.calls)

    def test_receipt_for_another_preparation_is_rejected(self):
        self.f.verified["receipt"]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.f.run()


class CompletionEvidenceTests(unittest.TestCase):
    """Exercise the real _bind_outputs path, not a replacement acceptance mock."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.f = Fixture(Path(self.temp.name).resolve())
        self.counter = 0

    def bind(self, mutate=None, *, mutate_saved=None):
        self.counter += 1
        output = self.f.root / ".runs" / ("completion-%03d" % self.counter)
        output.mkdir()
        for name in m.STAGES:
            put(output / name, name.encode())
        request = FakeRequest(FakeIRInput(Path(self.f.source_ir["path"]), self.f.source_ir["sha256"]),
                              FakeIRInput(Path(self.f.protected_ir["path"]), self.f.protected_ir["sha256"]),
                              tuple(self.f.handoff["selected_functions"]), 1729)
        result = self.f.evidence(output, request, ["dispatcher_a", "dispatcher_b"])
        prefix = output / "logs/001"
        stdout = put(Path(str(prefix) + ".stdout.log"), b"")
        stderr = put(Path(str(prefix) + ".stderr.log"), b"")
        argv = [self.f.config["clang"], "-owned-mocked-recipe"]
        raw = successful_process(argv, stdout["path"], stderr["path"])
        if mutate:
            mutate(raw)
        saved = copy.deepcopy(raw)
        if mutate_saved:
            mutate_saved(saved)
        put(Path(str(prefix) + ".process.json"), m.canonical(saved))
        return m._bind_outputs(m.Reader(self.f.root), output, result,
                               [{**raw, "cwd": str(output)}], [argv])

    def test_complete_real_contract_shape_is_accepted(self):
        evidence = self.bind()
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["command_index"], 0)

    def test_old_minimal_success_labels_are_not_complete_cleanup(self):
        def incomplete(row):
            row.pop("pid")
            row["cleanup"] = {"status": "assigned_job_empty", "parent_exit_confirmed": True,
                              "job_handle_closed": True}
        with self.assertRaises(ValueError):
            self.bind(incomplete)

    def test_missing_process_pid_is_rejected(self):
        with self.assertRaises(ValueError):
            self.bind(lambda row: row.pop("pid"))

    def test_nonpositive_or_noninteger_pid_is_rejected(self):
        for value in (0, -1, True, 43210.0, "43210", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.bind(lambda row: row.update(pid=value))

    def test_missing_cleanup_parent_pid_is_rejected(self):
        with self.assertRaises(ValueError):
            self.bind(lambda row: row["cleanup"].pop("parent_pid"))

    def test_parent_pid_must_be_same_strict_child_identity(self):
        for value in (0, 43211, True, 43210.0, "43210", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.bind(lambda row: row["cleanup"].update(parent_pid=value))

    def test_job_method_missing_or_fallback_is_rejected(self):
        with self.assertRaises(ValueError):
            self.bind(lambda row: row["cleanup"].pop("method"))
        for value in ("taskkill_fallback", "posix_process_group", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.bind(lambda row: row["cleanup"].update(method=value))

    def test_job_assignment_missing_false_or_integer_is_rejected(self):
        with self.assertRaises(ValueError):
            self.bind(lambda row: row["cleanup"].pop("job_assigned"))
        for value in (False, 1, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.bind(lambda row: row["cleanup"].update(job_assigned=value))

    def test_assignment_timing_missing_or_changed_is_rejected(self):
        with self.assertRaises(ValueError):
            self.bind(lambda row: row["cleanup"].pop("assignment_timing"))
        with self.assertRaises(ValueError):
            self.bind(lambda row: row["cleanup"].update(assignment_timing="before_launch"))

    def test_active_before_requires_nonnegative_integer(self):
        with self.assertRaises(ValueError):
            self.bind(lambda row: row["cleanup"].pop("active_before"))
        for value in (-1, False, 0.0, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.bind(lambda row: row["cleanup"].update(active_before=value))

    def test_active_after_requires_explicit_integer_zero(self):
        with self.assertRaises(ValueError):
            self.bind(lambda row: row["cleanup"].pop("active_after"))
        for value in (1, False, 0.0, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.bind(lambda row: row["cleanup"].update(active_after=value))

    def test_cleanup_errors_cannot_be_overridden_by_success_labels(self):
        for key in ("error", "parent_wait_error", "parent_kill_error", "job_close_error", "job_setup_error"):
            for value in ("recorded error", "", None):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    self.bind(lambda row: row["cleanup"].update({key: value}))

    def test_post_cleanup_wait_error_presence_is_failure(self):
        for value in ("TimeoutExpired", "", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.bind(lambda row: row.update(post_cleanup_wait_error=value))

    def test_top_level_error_presence_is_failure(self):
        for value in ("recorded error", "", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.bind(lambda row: row.update(error=value))

    def test_saved_json_integral_float_pid_cannot_hide_behind_dict_equality(self):
        with self.assertRaises(ValueError):
            self.bind(mutate_saved=lambda row: row.update(pid=float(row["pid"])))

    def test_saved_json_integer_assignment_cannot_hide_behind_dict_equality(self):
        with self.assertRaises(ValueError):
            self.bind(mutate_saved=lambda row: row["cleanup"].update(job_assigned=1))

    def test_saved_json_boolean_active_count_cannot_hide_behind_dict_equality(self):
        with self.assertRaises(ValueError):
            self.bind(mutate_saved=lambda row: row["cleanup"].update(active_after=False))

    def test_saved_json_different_valid_pid_pair_is_rejected(self):
        def changed(row):
            row["pid"] += 1
            row["cleanup"]["parent_pid"] = row["pid"]
        with self.assertRaises(ValueError):
            self.bind(mutate_saved=changed)

    def rewrite_last(self, rows, change):
        change(rows[-1])
        prefix = self.f.output / "logs" / f"{len(rows):03d}"
        raw = {key: value for key, value in rows[-1].items() if key != "cwd"}
        put(Path(str(prefix) + ".process.json"), m.canonical(raw))

    def test_consistently_missing_parent_pid_makes_full_adapter_fail(self):
        self.f.command_mutation = lambda rows: self.rewrite_last(rows,
            lambda row: row["cleanup"].pop("parent_pid"))
        result = self.f.run()
        self.assertEqual(result["status"], "failed_native_objects_unlinked")
        self.assertFalse(result["native_linked"])

    def test_consistent_late_wait_error_makes_full_adapter_fail(self):
        self.f.command_mutation = lambda rows: self.rewrite_last(rows,
            lambda row: row.update(post_cleanup_wait_error="TimeoutExpired"))
        result = self.f.run()
        self.assertEqual(result["status"], "failed_native_objects_unlinked")
        self.assertNotIn("inputs_unchanged", result)


class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.f = Fixture(Path(self.temp.name).resolve())

    def check(self):
        return m._handoff(m.Reader(self.f.root), self.f.report, self.f.verified)

    def test_qualified_source_is_not_substituted_with_normalized_or_mapped(self):
        self.f.handoff["source_ir"] = self.f.protected_ir
        with self.assertRaises(ValueError):
            self.check()

    def test_source_ir_bytes_must_match_descriptor(self):
        Path(self.f.source_ir["path"]).write_bytes(b"mutated")
        with self.assertRaises(ValueError):
            self.check()

    def test_inlined_source_maps_to_survivor_without_fabricating_wrapper(self):
        handoff, _, _ = self.check()
        self.assertEqual(handoff["source_definition_lineage"][-1]["protected_symbols"], ["api"])
        self.assertNotIn("inlined", handoff["selected_functions"])

    def test_owner_lineage_cannot_omit_a_selected_helper(self):
        self.f.handoff["source_definition_lineage"] = [self.f.lineage[0]]
        self.f.report["source_definition_lineage"] = copy.deepcopy(self.f.handoff["source_definition_lineage"])
        with self.assertRaises(ValueError):
            self.check()

    def test_duplicate_original_owner_symbol_is_rejected(self):
        self.f.handoff["source_definition_lineage"].append(copy.deepcopy(self.f.lineage[0]))
        self.f.report["source_definition_lineage"] = copy.deepcopy(self.f.handoff["source_definition_lineage"])
        with self.assertRaises(ValueError):
            self.check()

    def test_public_exports_are_not_used_as_complete_vm_selection(self):
        self.f.verified["selected_functions"] = ["api"]
        with self.assertRaises(ValueError):
            self.check()


class ReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def test_descriptor_boolean_size_and_unknown_fields_rejected(self):
        item = put(self.root / "input")
        for changed in ({**item, "bytes": True}, {**item, "observed_stage": "unadapted"}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                m.descriptor(changed)

    def test_duplicate_json_and_nonfinite_values_rejected(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                m.json_bytes(raw)

    def test_mutation_is_detected_by_terminal_recheck(self):
        item = put(self.root / "input")
        reader = m.Reader(self.root)
        reader.read(item)
        Path(item["path"]).write_bytes(b"changed")
        with self.assertRaises(ValueError):
            reader.recheck()

    def test_hardlinked_private_input_rejected(self):
        item = put(self.root / "input")
        try:
            os.link(self.root / "input", self.root / "alias")
        except OSError as exc:
            self.skipTest("OS cannot create fixture hardlink: " + str(exc))
        with self.assertRaises(ValueError):
            m.Reader(self.root).read(item)

    def test_sensitive_and_received_paths_rejected_before_read(self):
        for name in ("env.setting", "LINKREPRO/anything", "rea-analysis-reports/input"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                m.path(self.root / name)


class SourceImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.pins = {}
        for name in ("__init__", *m.ROLES):
            item = put(self.root / "antirea" / (name + ".py"), b"VALUE = 'reviewed source'\n")
            self.pins[item["path"]] = item["sha256"]
        self.pins[str(MODULE.resolve())] = m.sha(MODULE.read_bytes())
        self.old = {key: value for key, value in sys.modules.items() if key == "antirea" or key.startswith("antirea.")}
        for key in self.old:
            del sys.modules[key]
        self.addCleanup(self.restore)

    def restore(self):
        for key in list(sys.modules):
            if key == "antirea" or key.startswith("antirea."):
                del sys.modules[key]
        sys.modules.update(self.old)

    def test_fixed_roles_load_only_pinned_source(self):
        old_path, old_meta = list(sys.path), list(sys.meta_path)
        with m._modules(m.Reader(self.root), self.pins) as modules:
            self.assertEqual(set(modules), set(m.ROLES))
            self.assertTrue(all(x.VALUE == "reviewed source" for x in modules.values()))
            self.assertTrue(all(x.__cached__ is None for x in modules.values()))
        self.assertEqual(sys.path, old_path)
        self.assertEqual(sys.meta_path, old_meta)

    def test_missing_source_pin_blocks_before_import(self):
        self.pins.pop(str(self.root / "antirea/native_objects.py"))
        with self.assertRaises(ValueError), m._modules(m.Reader(self.root), self.pins):
            self.fail("must not enter")
        self.assertNotIn("antirea", sys.modules)

    def test_unknown_transitive_module_is_not_silently_imported(self):
        entry = self.root / "antirea/native_objects.py"
        self.pins[str(entry)] = put(entry, b"import antirea.unapproved\n")["sha256"]
        with self.assertRaises(ValueError), m._modules(m.Reader(self.root), self.pins):
            self.fail("must not enter")
        self.assertNotIn("antirea", sys.modules)

    def test_partial_preload_is_rejected_and_not_removed(self):
        sys.modules["antirea"] = None
        with self.assertRaises(ValueError), m._modules(m.Reader(self.root), self.pins):
            self.fail("must not enter")
        self.assertIn("antirea", sys.modules)
        self.assertIsNone(sys.modules["antirea"])



class SDKAuthorityTests(unittest.TestCase):
    """Only temporary owned trees; no installed SDK or process is accessed."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.f = Fixture(Path(self.temp.name).resolve())

    def context(self, roots=None):
        return m._native_context(m.Reader(self.f.root), self.f.context, self.f.environment,
                                 self.f.modules, self.f.pins, roots or [self.f.source])

    def approve(self, include, *, inventory_files=True):
        self.f.environment["INCLUDE"] = ";".join(map(str, include))
        self.f.context["compiler_environment"] = m.environment_receipt(self.f.environment)
        roots = [self.f.llvm / "lib/clang", *include]
        if inventory_files:
            self.f.context["header_inventory"] = inventory(roots)
        else:
            self.f.context["header_inventory"]["roots"] = sorted(map(str, roots))

    def test_generic_path_still_rejects_shared_even_when_sdk_is_approved(self):
        sdk = self.f.root / "SDK/shared"
        put(sdk / "owned.h")
        self.approve([sdk])
        with self.assertRaisesRegex(ValueError, "forbidden input path"):
            m.path(sdk)
        with self.assertRaisesRegex(ValueError, "forbidden input path"):
            m.path(sdk / "owned.h")

    def test_approved_shared_root_passes_full_mock_pipeline(self):
        sdk = self.f.root / "SDK/shared"
        put(sdk / "owned.h")
        self.approve([sdk])
        result = self.f.run()
        self.assertEqual(result["status"], "native_objects_created_unlinked")
        self.assertEqual(self.f.calls, ["verify", "construct", "prepare", "runtime",
                                       "baseline", "protected", "finalize", "verify"])

    def test_shared_descendants_in_sdk_and_resource_trees_are_inventoried(self):
        sdk_file = self.f.sdk / "shared/nested/owned.h"
        resource_file = self.f.llvm / "lib/clang/22/include/shared/owned.h"
        put(sdk_file)
        put(resource_file)
        self.approve([self.f.sdk])
        self.context()
        names = {row["path"] for row in self.f.context["header_inventory"]["files"]}
        self.assertIn(str(sdk_file), names)
        self.assertIn(str(resource_file), names)

    def test_changed_include_root_without_matching_approval_fails_before_scan(self):
        sdk = self.f.root / "SDK/shared"
        put(sdk / "owned.h")
        self.f.environment["INCLUDE"] = str(sdk)
        self.f.context["compiler_environment"] = m.environment_receipt(self.f.environment)
        with patch.object(self.f.modules["rust_cargo_build"], "inventory_trees") as scan:
            with self.assertRaisesRegex(ValueError, "exact caller-approved"):
                self.context()
            scan.assert_not_called()

    def test_scoped_checker_rejects_unapproved_sibling(self):
        shared = self.f.root / "SDK/shared"
        put(shared / "owned.h")
        with self.assertRaisesRegex(ValueError, "outside/ambiguous"):
            m._sdk_path(shared / "owned.h", [self.f.sdk])

    def test_shared_ancestor_outside_approved_root_is_still_forbidden(self):
        sdk = self.f.root / "shared/not-approved-parent/sdk"
        put(sdk / "owned.h")
        self.approve([sdk])
        with patch.object(self.f.modules["rust_cargo_build"], "inventory_trees") as scan:
            with self.assertRaisesRegex(ValueError, "forbidden input path"):
                self.context()
            scan.assert_not_called()

    def test_scoped_checker_rejects_duplicate_or_overlapping_authority(self):
        leaf = self.f.sdk / "stdint.h"
        for roots in ([self.f.sdk, self.f.sdk], [self.f.sdk.parent, self.f.sdk]):
            with self.subTest(roots=list(map(str, roots))), self.assertRaisesRegex(ValueError, "ambiguous"):
                m._sdk_path(leaf, roots)

    def test_context_rejects_overlapping_header_roots_before_inventory(self):
        nested = self.f.sdk / "nested"
        put(nested / "owned.h")
        self.approve([self.f.sdk, nested], inventory_files=False)
        with patch.object(self.f.modules["rust_cargo_build"], "inventory_trees") as scan:
            with self.assertRaisesRegex(ValueError, "exact caller-approved"):
                self.context()
            scan.assert_not_called()

    def test_inventory_authority_requires_exact_typed_root_list(self):
        approved = copy.deepcopy(self.f.context["header_inventory"])
        bad_roots = [None, "not-a-list", [False], [],
                     approved["roots"] + [approved["roots"][0]],
                     list(reversed(approved["roots"]))]
        for roots in bad_roots:
            with self.subTest(roots=roots):
                self.f.context["header_inventory"] = {**approved, "roots": roots}
                with patch.object(self.f.modules["rust_cargo_build"], "inventory_trees") as scan:
                    with self.assertRaisesRegex(ValueError, "exact caller-approved"):
                        self.context()
                    scan.assert_not_called()

    def test_sensitive_names_remain_forbidden_under_approved_shared_root(self):
        sdk = self.f.root / "SDK/shared"
        sdk.mkdir()
        for name in ("env.setting", "LINKREPRO/owned.h",
                     "rea-analysis-reports/owned.h", "attackerfolder/owned.h"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "forbidden input path"):
                m._sdk_path(sdk / name, [sdk])

    def test_sensitive_leaf_is_rejected_before_inventory_reads(self):
        sdk = self.f.root / "SDK/shared"
        put(sdk / "ordinary.h")
        self.approve([sdk])
        # Synthetic bytes, never an environment export or historical artifact.
        put(sdk / "env.setting", b"inert forbidden-name fixture")
        with patch.object(self.f.modules["rust_cargo_build"], "inventory_trees") as scan:
            with self.assertRaisesRegex(ValueError, "forbidden input path"):
                self.context()
            scan.assert_not_called()

    def test_scoped_checker_keeps_local_absolute_and_ads_controls(self):
        for candidate in (Path("relative/shared/header.h"), self.f.sdk / "file.h:stream",
                          self.f.sdk / ".." / "shared" / "header.h",
                          Path("//server/share/shared/header.h")):
            with self.subTest(path=str(candidate)), self.assertRaises(ValueError):
                m._sdk_path(candidate, [self.f.sdk])

    def test_sdk_symlink_and_reparse_entries_remain_forbidden(self):
        leaf = self.f.sdk / "stdint.h"
        original = Path.lstat
        for mode, attributes in ((m.stat.S_IFLNK, 0), (m.stat.S_IFREG, 0x400)):
            def fake_lstat(item, *args, **kwargs):
                if item == leaf:
                    return types.SimpleNamespace(st_mode=mode, st_file_attributes=attributes, st_nlink=1)
                return original(item, *args, **kwargs)
            with self.subTest(mode=mode, attributes=attributes), patch.object(Path, "lstat", fake_lstat):
                with self.assertRaisesRegex(ValueError, "symlink/reparse"):
                    m._sdk_path(leaf, [self.f.sdk])

    def test_sdk_regular_hardlinks_remain_allowed_but_private_paths_do_not(self):
        leaf = self.f.sdk / "stdint.h"
        original = Path.lstat
        def fake_lstat(item, *args, **kwargs):
            if item == leaf:
                return types.SimpleNamespace(st_mode=m.stat.S_IFREG, st_file_attributes=0, st_nlink=2)
            return original(item, *args, **kwargs)
        with patch.object(Path, "lstat", fake_lstat):
            self.assertEqual(m._sdk_path(leaf, [self.f.sdk]), leaf)
            with self.assertRaisesRegex(ValueError, "hardlinked private"):
                m.path(leaf)

    def test_approved_header_tree_cannot_overlap_source_in_either_direction(self):
        for header, source in ((self.f.sdk, self.f.sdk / "selected-source"),
                               (self.f.sdk, self.f.sdk.parent)):
            with self.subTest(source=str(source)):
                with patch.object(self.f.modules["rust_cargo_build"], "inventory_trees") as scan:
                    with self.assertRaisesRegex(ValueError, "overlap project"):
                        self.context([source])
                    scan.assert_not_called()

    def test_approved_header_tree_cannot_overlap_controller_in_either_direction(self):
        control = self.f.root / ".runs/defense-loop"
        child = control / "include"
        child.mkdir(parents=True)
        for header in (child, control.parent):
            self.approve([header], inventory_files=False)
            with self.subTest(header=str(header)):
                with patch.object(self.f.modules["rust_cargo_build"], "inventory_trees") as scan:
                    with self.assertRaisesRegex(ValueError, "controller"):
                        self.context()
                    scan.assert_not_called()

    def test_terminal_shared_header_drift_is_not_hidden_by_exception(self):
        sdk = self.f.root / "SDK/shared"
        put(sdk / "owned.h")
        self.approve([sdk])
        self.f.after_finalize = lambda _: put(sdk / "later.h")
        result = self.f.run()
        self.assertEqual(result["status"], "failed_native_objects_unlinked")
        self.assertIn("SDK/resource inventory changed", result["error"])


@unittest.skipUnless(os.name == "nt", "Windows filesystem path-identity regression")
class SDKWindowsCaseTests(unittest.TestCase):
    """Owned mock tree reproduces ATLMFC spelling; never reads installed SDK."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.f = Fixture(Path(self.temp.name).resolve())
        self.sdk = self.f.root / "SDK/atlmfc/include"
        put(self.sdk / "owned.h")
        self.alias = self.f.root / "SDK/ATLMFC/include"
        self.f.environment["INCLUDE"] = str(self.alias)
        self.f.context["compiler_environment"] = m.environment_receipt(self.f.environment)
        self.f.context["header_inventory"] = inventory([self.f.llvm / "lib/clang", self.sdk])
        # Production inventory_trees uses _path(...).resolve() after validation.
        # Mirror that canonical spelling behavior using only this owned tree.
        self.f.modules["rust_cargo_build"].inventory_trees = lambda roots: inventory(
            [root.resolve(strict=True) for root in roots])

    def context(self, module=m):
        return module._native_context(module.Reader(self.f.root), self.f.context,
            self.f.environment, self.f.modules, self.f.pins, [self.f.source])

    def reject_before_path_or_inventory(self):
        with patch.object(m, "_sdk_path") as paths, patch.object(
                self.f.modules["rust_cargo_build"], "inventory_trees") as scan:
            with self.assertRaisesRegex(ValueError, "exact caller-approved"):
                self.context()
            paths.assert_not_called()
            scan.assert_not_called()

    def test_production_accepts_windows_identity_without_changing_inventory_spelling(self):
        self.assertNotEqual(str(self.sdk), str(self.alias))
        self.assertEqual(self.sdk, self.alias)
        self.assertEqual(m.path(self.alias), self.sdk)
        self.assertEqual(m._sdk_path(self.alias, [self.sdk]), self.sdk)
        approved = copy.deepcopy(self.f.context["header_inventory"])
        config, tools = self.context()
        self.assertEqual(config, self.f.config)
        self.assertEqual(tools, self.f.tools)
        self.assertEqual(self.f.context["header_inventory"], approved)
        self.assertIn(str(self.sdk), approved["roots"])
        self.assertNotIn(str(self.alias), approved["roots"])

    def test_v4_same_windows_path_casing_passes_full_mock_pipeline(self):
        environment = copy.deepcopy(self.f.environment)
        approved = copy.deepcopy(self.f.context["header_inventory"])
        result = self.f.run()
        self.assertEqual(result["status"], "native_objects_created_unlinked")
        self.assertEqual(self.f.environment, environment)
        self.assertEqual(self.f.context["header_inventory"], approved)
        self.assertEqual(result["native_context"]["header_inventory"], approved)

    def test_include_alias_duplicates_are_rejected_before_filesystem_access(self):
        self.f.environment["INCLUDE"] = str(self.sdk) + ";" + str(self.alias)
        self.f.context["compiler_environment"] = m.environment_receipt(self.f.environment)
        self.reject_before_path_or_inventory()

    def test_approved_alias_duplicates_do_not_replace_missing_resource_root(self):
        self.f.context["header_inventory"]["roots"] = sorted([str(self.sdk), str(self.alias)])
        self.reject_before_path_or_inventory()

    def test_foreign_same_basename_and_case_are_not_authorized(self):
        foreign = self.f.root / "unapproved/ATLMFC/include"
        self.f.environment["INCLUDE"] = str(foreign)
        self.f.context["compiler_environment"] = m.environment_receipt(self.f.environment)
        self.reject_before_path_or_inventory()

    def test_canonical_inventory_root_order_is_still_required(self):
        self.f.context["header_inventory"]["roots"].reverse()
        self.reject_before_path_or_inventory()

    def test_noncanonical_inventory_root_spelling_still_fails_exact_recheck(self):
        approved = self.f.context["header_inventory"]
        approved["roots"] = sorted(str(self.alias) if value == str(self.sdk) else value
                                   for value in approved["roots"])
        approved["sha256"] = m.sha(m.canonical({k: v for k, v in approved.items() if k != "sha256"}))
        with self.assertRaisesRegex(ValueError, "SDK/resource inventory changed"):
            self.context()

    def test_file_record_casing_does_not_weaken_exact_inventory_equality(self):
        approved = self.f.context["header_inventory"]
        row = next(row for row in approved["files"] if row["path"] == str(self.sdk / "owned.h"))
        row["path"] = str(self.alias / "owned.h")
        approved["sha256"] = m.sha(m.canonical({k: v for k, v in approved.items() if k != "sha256"}))
        with self.assertRaisesRegex(ValueError, "SDK/resource inventory changed"):
            self.context()

if __name__ == "__main__":
    unittest.main()
