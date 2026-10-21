"""Mock-only commercial adapter checks. No vendor, target, network or attack runs."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from antirea import protectors as module
from antirea.protectors import ProtectorError, Service


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pe(tag=b"source", machine=0x8664):
    data = bytearray(512)
    data[:2] = b"MZ"
    data[60:64] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\0\0"
    data[68:70] = machine.to_bytes(2, "little")
    data[84:86] = (240 if machine == 0x8664 else 224).to_bytes(2, "little")
    data[88:90] = (0x20b if machine == 0x8664 else 0x10b).to_bytes(2, "little")
    count = 196 if machine == 0x8664 else 180
    data[count:count + 4] = (16).to_bytes(4, "little")
    return bytes(data) + tag


class ProtectorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="antirea-protectors-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "workspace"
        self.root.mkdir()
        self.source = self.root / "owned input.exe"
        self.source.write_bytes(pe())
        self.config_path = self.root / "protectors.json"
        self.config = {"schema_version": 1, "workspace_root": str(self.root), "providers": {}}
        for provider, definition in module.PROVIDERS.items():
            tool = self.base / definition["executable_name"]
            tool.write_bytes(pe(provider.encode()))
            project = self.root / (provider + definition["project_extensions"][0])
            project.write_text("trusted vendor project", encoding="utf-8")
            self.config["providers"][provider] = {
                "executable": str(tool), "version": "3.2.6", "edition": "licensed",
                "cli_profile": definition["profiles"][0], "allow_execution": True,
                "license_acknowledged": True, "sha256": digest(tool.read_bytes()),
                "approved_projects": [{"path": str(project), "sha256": digest(project.read_bytes())}],
            }
        self.windows = patch.object(module, "_windows_host", return_value=True)
        self.windows.start()
        self.addCleanup(self.windows.stop)
        self.runner = patch.object(module, "_native_run", side_effect=self.fake_run).start()
        self.addCleanup(patch.stopall)
        self.service = self.load()

    def load(self):
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")
        return Service.from_config(self.config_path)

    def project(self, provider="vmprotect"):
        return Path(self.config["providers"][provider]["approved_projects"][0]["path"])

    def plan(self, provider="vmprotect", **kwargs):
        return self.service.plan(provider, self.source, self.project(provider), **kwargs)

    def protect(self, plan):
        return self.service.protect(plan["plan_id"], plan["fingerprint"])

    def fake_run(self, argv, directory, log_prefix, *, timeout, cancel_file):
        output = Path(argv[2] if "-pf" in argv else argv[argv.index("/outputfile") + 1])
        output.write_bytes(pe(b"protected"))
        log_prefix.with_suffix(".stdout.log").write_text("mock vendor output", encoding="utf-8")
        return {"returncode": 0, "pid": 123, "cancelled": False, "timed_out": False,
                "cleanup": {"parent_exit_confirmed": True, "status": "assigned_job_empty",
                            "method": "windows_job", "job_assigned": True, "active_after": 0,
                            "job_handle_closed": True}}

    def test_registry_and_doctor_never_execute_or_create_jobs(self):
        registry = self.service.providers()
        self.assertEqual({entry["id"] for entry in registry["providers"]}, set(module.PROVIDERS))
        self.assertFalse(self.service.doctor()["executed_vendor"])
        self.assertFalse(self.service.output_root.exists())
        self.runner.assert_not_called()

    def test_plan_is_dry_run_and_records_private_json_markdown(self):
        plan = self.plan()
        self.assertEqual(plan["status"], "planned")
        self.assertEqual(plan["blockers"], [])
        self.assertFalse(Path(plan["copied_input"]).exists())
        self.assertFalse(Path(plan["output"]).exists())
        self.assertEqual(self.service.job(plan["job_id"]), plan)
        self.assertIn("not sandboxed", (Path(plan["job_directory"]) / "README.md").read_text())
        self.runner.assert_not_called()

    def test_exact_vmprotect_arguments(self):
        plan = self.plan()
        self.assertEqual(plan["argv"], [self.config["providers"]["vmprotect"]["executable"],
                                      plan["copied_input"], plan["output"], "-pf", str(self.project())])

    def test_exact_oreans_arguments(self):
        for provider in ("themida", "code_virtualizer"):
            with self.subTest(provider=provider):
                plan = self.plan(provider)
                self.assertEqual(plan["argv"], [self.config["providers"][provider]["executable"], "/protect",
                                              str(self.project(provider)), "/inputfile", plan["copied_input"],
                                              "/outputfile", plan["output"], "/shareconsole"])

    def test_cv4_profile_accepts_only_major_four(self):
        config = self.config["providers"]["code_virtualizer"]
        config["cli_profile"] = "code-virtualizer-4"
        for version, blocked in (("4.0", False), ("4.1.2", False), ("3.2", True), ("5.0", True), ("unknown", True)):
            with self.subTest(version=version):
                config["version"] = version
                self.service = self.load()
                self.assertEqual("version_not_supported_by_selected_cli_profile" in
                                 self.service.doctor("code_virtualizer")["blockers"], blocked)

    def test_cv_legacy_rejects_new_or_unknown_version(self):
        for version in ("4.0", "5.0", "unknown", "3 & unsafe"):
            self.config["providers"]["code_virtualizer"]["version"] = version
            self.assertIn("version_not_supported_by_selected_cli_profile",
                          self.load().doctor("code_virtualizer")["blockers"])

    def test_vmprotect_lite_is_blocked_but_trial_is_not(self):
        config = self.config["providers"]["vmprotect"]
        config["edition"] = "lite"
        self.assertIn("lite_has_no_supported_console_profile", self.load().doctor("vmprotect")["blockers"])
        config["edition"] = "trial"
        self.service = self.load()
        result = self.protect(self.plan())
        self.assertEqual(result["status"], "artifact_created_unvalidated")
        self.assertTrue(result["artifact"]["trial"])

    def test_defaults_are_nonexecuting_and_unknown(self):
        config = self.config["providers"]["vmprotect"]
        project = self.project()
        for key in ("allow_execution", "license_acknowledged", "edition", "version", "sha256", "approved_projects"):
            config.pop(key)
        self.service = self.load()
        blockers = self.service.plan("vmprotect", self.source, project)["blockers"]
        for expected in ("execution_not_enabled", "license_not_acknowledged", "edition_unverified",
                         "tool_hash_not_pinned", "project_hash_not_approved"):
            self.assertIn(expected, blockers)
        self.runner.assert_not_called()

    def test_missing_tool_is_reported_without_execution(self):
        Path(self.config["providers"]["vmprotect"]["executable"]).unlink()
        self.assertIn("executable_missing", self.service.doctor("vmprotect")["blockers"])
        self.assertEqual(self.protect(self.plan())["status"], "failed")
        self.runner.assert_not_called()

    def test_non_windows_host_blocks_run(self):
        with patch.object(module, "_windows_host", return_value=False):
            self.assertIn("windows_host_required", self.plan()["blockers"])
            self.assertEqual(self.protect(self.plan())["status"], "failed")
        self.runner.assert_not_called()

    def test_unknown_fields_reject_arbitrary_arguments_and_shell(self):
        for target, field in ((self.config, "shell"), (self.config["providers"]["vmprotect"], "arguments"),
                              (self.config["providers"]["vmprotect"]["approved_projects"][0], "script")):
            with self.subTest(field=field):
                target[field] = "arbitrary"
                with self.assertRaises(ProtectorError):
                    self.load()
                target.pop(field)

    def test_boolean_and_schema_types_are_strict(self):
        for key in ("allow_execution", "license_acknowledged"):
            value = self.config["providers"]["vmprotect"][key]
            self.config["providers"]["vmprotect"][key] = "true"
            with self.assertRaises(ProtectorError):
                self.load()
            self.config["providers"]["vmprotect"][key] = value
        self.config["schema_version"] = True
        with self.assertRaises(ProtectorError):
            self.load()

    def test_output_root_cannot_escape_fixed_jobs_directory(self):
        self.config["output_root"] = str(self.base / "elsewhere")
        with self.assertRaises(ProtectorError):
            self.load()

    def test_config_outside_declared_workspace_is_rejected(self):
        outside = self.base / "config.json"
        outside.write_text(json.dumps(self.config))
        with self.assertRaises(ProtectorError):
            Service.from_config(outside)

    def test_wrong_tool_basename_and_relative_paths_are_rejected(self):
        config = self.config["providers"]["vmprotect"]
        for value in ("VMProtect_Con.exe", str(self.base / "cmd.exe"), str(self.base / "tool.cmd")):
            config["executable"] = value
            with self.assertRaises(ProtectorError):
                self.load()

    def test_outside_and_incoming_inputs_are_rejected(self):
        for path in (self.base / "external.exe", self.root / "rea-analysis-reports/app.exe",
                     self.root / ".runs/defense-loop/inbox/snapshot/app.exe"):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(pe())
            with self.assertRaises(ProtectorError):
                self.service.plan("vmprotect", path, self.project())

    def test_untrusted_project_is_not_allowed_even_when_its_bytes_are_trusted(self):
        project = self.root / "rea-analysis-reports/project.vmp"
        project.parent.mkdir()
        project.write_text("trusted vendor project")
        with self.assertRaises(ProtectorError):
            self.service.plan("vmprotect", self.source, project)

    def test_hardlinked_source_is_rejected(self):
        linked = self.root / "linked.exe"
        os.link(self.source, linked)
        with self.assertRaises(ProtectorError):
            self.service.plan("vmprotect", linked, self.project())

    def test_reparse_path_is_rejected_before_following(self):
        original = Path.lstat
        fake = SimpleNamespace(st_mode=stat_mode_file(), st_file_attributes=module.REPARSE, st_nlink=1)
        with patch.object(Path, "lstat", lambda path: fake if path == self.source else original(path)):
            with self.assertRaises(ProtectorError):
                self.plan()

    def test_wrong_project_extension_and_non_pe_input_rejected(self):
        with self.assertRaises(ProtectorError):
            self.service.plan("vmprotect", self.source, self.project("themida"))
        self.source.write_text("not a PE")
        with self.assertRaises(ProtectorError):
            self.plan()

    def test_managed_clr_and_truncated_pe_headers_are_rejected(self):
        managed = bytearray(pe())
        managed[312:316] = (4096).to_bytes(4, "little")
        self.source.write_bytes(managed)
        with self.assertRaisesRegex(ProtectorError, "CLR"):
            self.plan()
        self.source.write_bytes(pe()[:128])
        with self.assertRaisesRegex(ProtectorError, "optional header"):
            self.plan()

    def test_timeout_must_be_bounded_finite_number(self):
        for timeout in (True, 0, -1, 3601, float("nan"), float("inf"), "600"):
            with self.subTest(timeout=timeout), self.assertRaises(ProtectorError):
                self.plan(timeout_seconds=timeout)

    def test_unapproved_project_can_plan_but_cannot_run(self):
        self.project().write_text("changed project script")
        plan = self.plan()
        self.assertIn("project_hash_not_approved", plan["blockers"])
        result = self.protect(plan)
        self.assertEqual(result["status"], "failed")
        self.runner.assert_not_called()

    def test_success_copies_input_preserves_original_and_never_claims_validation(self):
        original = self.source.read_bytes()
        plan = self.plan(timeout_seconds=12)
        result = self.protect(plan)
        self.assertEqual(result["status"], "artifact_created_unvalidated")
        self.assertEqual(result["artifact"]["sha256"], digest(pe(b"protected")))
        self.assertEqual(Path(plan["copied_input"]).read_bytes(), original)
        self.assertEqual(self.source.read_bytes(), original)
        self.assertTrue(all(item["unchanged"] for item in result["original_integrity"].values()))
        self.assertEqual(result["limits"]["protection_applied"], "not_evaluated")
        self.assertFalse(result["limits"]["target_execution"])
        self.assertFalse(result["limits"]["automatic_publication"])
        self.assertEqual(self.service.job(plan["plan_id"])["status"], "artifact_created_unvalidated")
        self.assertEqual(self.runner.call_args.kwargs["cancel_file"], self.service.stop_path)

    def test_fingerprint_required_and_plan_tampering_detected(self):
        plan = self.plan()
        with self.assertRaises(ProtectorError):
            self.service.protect(plan["plan_id"], "0" * 64)
        changed = copy.deepcopy(plan)
        changed["timeout_seconds"] = 3000
        (Path(plan["job_directory"]) / "plan.json").write_text(json.dumps(changed))
        with self.assertRaises(ProtectorError):
            self.protect(plan)
        self.runner.assert_not_called()

    def test_changed_inputs_project_and_tool_block_run(self):
        for name in ("input", "project", "tool"):
            with self.subTest(name=name):
                plan = self.plan()
                path = self.source if name == "input" else self.project() if name == "project" else Path(plan["tool"]["executable"])
                previous = path.read_bytes()
                path.write_bytes(previous + b"changed")
                self.assertEqual(self.protect(plan)["status"], "failed")
                path.write_bytes(previous)
        self.runner.assert_not_called()

    def test_changed_configuration_requires_new_plan(self):
        plan = self.plan()
        self.config_path.write_text(self.config_path.read_text() + "\n")
        self.assertEqual(self.protect(plan)["status"], "failed")
        self.runner.assert_not_called()

    def test_job_attempt_is_not_automatically_replayed(self):
        plan = self.plan()
        self.protect(plan)
        with self.assertRaises(ProtectorError):
            self.protect(plan)
        self.assertEqual(self.runner.call_count, 1)
        self.assertNotEqual(self.plan()["job_id"], plan["job_id"])

    def test_provider_lock_serializes_distinct_plans_without_consuming_busy_plan(self):
        first, second = self.plan(), self.plan()
        lock_directory = self.service.output_root / ".locks"
        lock_directory.mkdir()
        with module._job_lock(lock_directory, "vmprotect.lock"):
            with self.assertRaises(ProtectorError):
                self.protect(first)
            with self.assertRaises(ProtectorError):
                self.protect(second)
        self.assertEqual(self.service.job(second["job_id"])["status"], "planned")
        self.runner.assert_not_called()
        self.assertEqual(self.protect(second)["status"], "artifact_created_unvalidated")

    def test_stop_before_execution_is_audited_without_vendor(self):
        plan = self.plan()
        self.service.stop_path.parent.mkdir(parents=True, exist_ok=True)
        self.service.stop_path.touch()
        result = self.protect(plan)
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(self.service.job(plan["job_id"])["status"], "cancelled")
        self.runner.assert_not_called()

    def test_timeout_cancellation_and_vendor_failure_are_not_artifact_success(self):
        for field, expected in (("timed_out", "timed_out"), ("cancelled", "cancelled"),
                                ("interrupted", "interrupted"), ("error", "vendor_failed")):
            def run(*args, **kwargs):
                result = self.fake_run(*args, **kwargs)
                result[field] = True
                return result
            self.runner.side_effect = run
            result = self.protect(self.plan())
            self.assertEqual(result["status"], expected)
            self.assertNotIn("artifact", result)

    def test_stop_detected_after_process_return_overrides_success(self):
        def run(*args, **kwargs):
            result = self.fake_run(*args, **kwargs)
            self.service.stop_path.parent.mkdir(parents=True, exist_ok=True)
            self.service.stop_path.touch()
            return result
        self.runner.side_effect = run
        self.assertEqual(self.protect(self.plan())["status"], "cancelled")

    def test_original_modification_is_recorded_without_claiming_success(self):
        def run(*args, **kwargs):
            result = self.fake_run(*args, **kwargs)
            self.source.write_bytes(pe(b"modified by trusted vendor"))
            return result
        self.runner.side_effect = run
        result = self.protect(self.plan())
        self.assertEqual(result["status"], "original_input_changed")
        self.assertFalse(result["original_integrity"]["input"]["unchanged"])

    def test_missing_invalid_or_different_architecture_output_fails(self):
        for output_bytes in (None, b"not PE", pe(machine=0x14c)):
            def run(argv, directory, log_prefix, **kwargs):
                result = self.fake_run(argv, directory, log_prefix, **kwargs)
                output = Path(argv[2])
                if output_bytes is None:
                    output.unlink()
                else:
                    output.write_bytes(output_bytes)
                return result
            self.runner.side_effect = run
            self.assertEqual(self.protect(self.plan())["status"], "failed")

    def test_unconfirmed_parent_exit_blocks_success(self):
        def run(*args, **kwargs):
            result = self.fake_run(*args, **kwargs)
            result["cleanup"] = {"parent_exit_confirmed": False}
            return result
        self.runner.side_effect = run
        self.assertEqual(self.protect(self.plan())["status"], "cleanup_unverified")

    def test_unverified_descendants_quarantine_provider_despite_valid_output_and_exit(self):
        def run(*args, **kwargs):
            result = self.fake_run(*args, **kwargs)
            result["cleanup"] = {"parent_exit_confirmed": True, "status": "parent_exited_descendants_unverified",
                                 "method": "taskkill_fallback", "job_assigned": False}
            return result
        self.runner.side_effect = run
        original, next_plan = self.plan(), self.plan()
        result = self.protect(original)
        self.assertEqual(result["status"], "cleanup_unverified")
        self.assertNotIn("artifact", result)
        self.assertTrue(Path(result["output"]).exists())
        self.assertIn("provider_quarantined_operator_inspection_required", self.service.doctor("vmprotect")["blockers"])
        self.assertEqual(self.service.doctor("vmprotect")["quarantine"]["job_id"], original["job_id"])
        self.assertEqual(self.protect(next_plan)["status"], "failed")
        self.assertEqual(self.runner.call_count, 1)
        fresh_service = Service.from_config(self.config_path)
        self.assertIn("provider_quarantined_operator_inspection_required", fresh_service.doctor("vmprotect")["blockers"])

    def test_pending_job_termination_is_not_verified_cleanup(self):
        def run(*args, **kwargs):
            result = self.fake_run(*args, **kwargs)
            result["cleanup"].update(status="job_termination_pending", active_after=1)
            return result
        self.runner.side_effect = run
        self.assertEqual(self.protect(self.plan())["status"], "cleanup_unverified")

    def test_abandoned_running_provider_marker_blocks_new_work(self):
        marker = self.service.output_root / ".locks/vmprotect.quarantine.json"
        marker.parent.mkdir(parents=True)
        marker.write_text(json.dumps({"schema_version": 1, "status": "running", "job_id": "interrupted"}))
        self.assertIn("provider_quarantined_operator_inspection_required", self.plan()["blockers"])
        self.runner.assert_not_called()

    def test_job_identifier_cannot_escape_directory(self):
        for identifier in ("../outside", "", "C:/outside", "unknown"):
            with self.assertRaises(ProtectorError):
                self.service.job(identifier)

    def test_duplicate_json_keys_rejected(self):
        self.config_path.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaises(ProtectorError):
            Service.from_config(self.config_path)

    def test_unknown_provider_and_unconfigured_provider_are_explicit(self):
        with self.assertRaises(ProtectorError):
            self.service.doctor("invented")
        self.config["providers"].pop("themida")
        self.service = self.load()
        with self.assertRaises(ProtectorError):
            self.service.doctor("themida")

    def test_generate_project_creates_and_approves_vendor_projects_for_all_providers(self):
        for provider, ext in (("vmprotect", ".vmp"), ("themida", ".tmd"), ("code_virtualizer", ".cv")):
            with self.subTest(provider=provider):
                res = self.service.generate_project(
                    provider, self.source, functions=("antirea_score", "antirea_mix"),
                    defense_level="balanced", min_speed_percent=80,
                )
                self.assertEqual(res["status"], "completed")
                self.assertTrue(res["approved_in_config"])
                self.assertTrue(res["project_path"].endswith(ext))
                self.assertEqual(res["function_modes"], {"antirea_score": "virtualization", "antirea_mix": "mutation"})
                plan = self.service.plan(provider, self.source, res["project_path"])
                self.assertEqual(plan["blockers"], [])

    def test_benchmark_verifies_functional_match_and_speed_percent(self):
        candidate = self.root / "candidate.exe"
        candidate.write_bytes(pe(b"protected"))
        samples = [
            {"returncode": 0, "stdout": "42\n", "stderr": "", "timed_out": False, "ms": 10.0},
            {"returncode": 0, "stdout": "42\n", "stderr": "", "timed_out": False, "ms": 12.0},
        ] * 4
        with patch.object(module, "_run_binary_sample", side_effect=samples):
            bench = self.service.benchmark(self.source, candidate, test_inputs=["1 2\n"], min_speed_percent=80, repeats=3)
        self.assertEqual(bench["status"], "completed")
        self.assertTrue(bench["functional_match"])
        self.assertAlmostEqual(bench["speed_percent"], 83.33, places=1)
        self.assertTrue(bench["meets_speed_target"])

    def test_builtin_auto_protect_never_substitutes_an_existing_binary(self):
        for candidate_kind in ("none", "sibling", "unrelated_ledger"):
            candidate = None
            if candidate_kind == "sibling":
                candidate = self.source.with_name(self.source.stem + ".protected.exe")
            elif candidate_kind == "unrelated_ledger":
                candidate = self.root / ".runs/defense-loop/current/ledger.exe"
            if candidate is not None:
                candidate.parent.mkdir(parents=True, exist_ok=True)
                candidate.write_bytes(pe(b"unverified existing binary"))
            for provider in ("antirea", "antirea_engine", "kagura"):
                with self.subTest(candidate=candidate_kind, provider=provider), \
                        patch.object(self.service, "benchmark") as benchmark:
                    result = self.service.auto_protect(provider, self.source)
                    self.assertEqual(result["status"], "blocked")
                    self.assertEqual(result["reason"], "source_project_required")
                    self.assertFalse(result["protection_applied"])
                    self.assertFalse(result["executed_target"])
                    self.assertNotIn("output_path", result)
                    self.assertIn("protection_source_build", result["next_tools"])
                    benchmark.assert_not_called()
            if candidate is not None:
                candidate.unlink()
        self.runner.assert_not_called()
        self.assertFalse(self.service.output_root.exists())

    def test_auto_protect_steps_down_defense_level_when_speed_below_target(self):
        def fake_sample(executable, stdin_text, *, timeout):
            name_str = str(executable)
            if "owned input.exe" in name_str:
                return {"returncode": 0, "stdout": "ok\n", "stderr": "", "timed_out": False, "ms": 10.0}
            job_count = len(self.runner.call_args_list)
            ms = 20.0 if job_count == 1 else 11.0
            return {"returncode": 0, "stdout": "ok\n", "stderr": "", "timed_out": False, "ms": ms}

        with patch.object(module, "_run_binary_sample", side_effect=fake_sample):
            result = self.service.auto_protect(
                "vmprotect", self.source, functions=("antirea_score", "antirea_mix"),
                defense_level="max_vm", min_speed_percent=80, test_inputs=("1 2\n",),
            )
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["selected_defense_level"], "balanced")
        self.assertTrue(result["meets_speed_target"])
        self.assertEqual(len(result["attempts"]), 2)
        self.assertEqual(result["attempts"][0]["defense_level"], "max_vm")
        self.assertFalse(result["attempts"][0]["meets_speed_target"])
        self.assertEqual(result["attempts"][1]["defense_level"], "balanced")
        self.assertTrue(result["attempts"][1]["meets_speed_target"])

    def test_ensure_default_config_creates_valid_config(self):
        fresh_cfg = self.root / ".runs/fresh-protectors.json"
        svc = Service.ensure_default_config(fresh_cfg, workspace_root=self.root)
        self.assertTrue(fresh_cfg.is_file())
        self.assertEqual(svc.root, self.root.resolve())


def stat_mode_file():
    import stat
    return stat.S_IFREG


@unittest.skipUnless(os.name == "nt", "hidden startup applies to native Windows")
class HiddenRunnerTests(unittest.TestCase):
    def test_preexisting_hardlinked_logs_leave_unrelated_sentinel_unchanged(self):
        for suffix in (".stdout.log", ".stderr.log", ".process.json"):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as name:
                directory = Path(name)
                sentinel = directory / "unrelated-original.txt"
                sentinel.write_bytes(b"must never be truncated")
                os.link(sentinel, directory / ("vendor" + suffix))
                with patch.object(module.subprocess, "Popen") as popen:
                    with self.assertRaises(ProtectorError):
                        module._native_run(["trusted.exe"], directory, directory / "vendor",
                                           timeout=2, cancel_file=directory / "STOP")
                popen.assert_not_called()
                self.assertEqual(sentinel.read_bytes(), b"must never be truncated")

    def test_preexisting_regular_logs_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            existing = directory / "vendor.stderr.log"
            existing.write_bytes(b"previous evidence")
            with patch.object(module.subprocess, "Popen") as popen:
                with self.assertRaises(ProtectorError):
                    module._native_run(["trusted.exe"], directory, directory / "vendor",
                                       timeout=2, cancel_file=directory / "STOP")
            popen.assert_not_called()
            self.assertEqual(existing.read_bytes(), b"previous evidence")
            self.assertFalse((directory / "vendor.stdout.log").exists())

    def test_reparse_log_is_rejected_without_opening_or_truncating(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            log = directory / "vendor.stdout.log"
            log.write_bytes(b"untouched linked destination")
            original_lstat = Path.lstat
            link = SimpleNamespace(st_mode=stat_mode_file(), st_file_attributes=module.REPARSE, st_nlink=1)
            with patch.object(Path, "lstat", lambda path: link if path == log else original_lstat(path)), \
                    patch.object(module.subprocess, "Popen") as popen:
                with self.assertRaises(ProtectorError):
                    module._native_run(["trusted.exe"], directory, directory / "vendor",
                                       timeout=2, cancel_file=directory / "STOP")
            popen.assert_not_called()
            self.assertEqual(log.read_bytes(), b"untouched linked destination")

    def test_non_windows_runner_fails_closed_without_opening_logs(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            with patch.object(module, "_windows_host", return_value=False), \
                    patch.object(module.subprocess, "Popen") as popen:
                with self.assertRaises(ProtectorError):
                    module._native_run(["trusted.exe"], directory, directory / "vendor",
                                       timeout=2, cancel_file=directory / "STOP")
            popen.assert_not_called()
            self.assertEqual(list(directory.iterdir()), [])

    def test_hidden_shell_false_and_owned_cleanup_are_used(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            child = SimpleNamespace(pid=123, wait=lambda **_kwargs: 0, poll=lambda: 0)
            job = SimpleNamespace(error=None, assign=lambda _child: True, close=lambda: True)
            with patch.object(module, "_WindowsJob", return_value=job), \
                    patch.object(module.subprocess, "Popen", return_value=child) as popen, \
                    patch.object(module, "stop_tree", return_value={"parent_exit_confirmed": True}) as stop:
                result = module._native_run(["trusted.exe", "arg with space"], directory, directory / "vendor",
                                            timeout=2, cancel_file=directory / "STOP")
            options = popen.call_args.kwargs
            self.assertFalse(options["shell"])
            self.assertTrue(options["creationflags"] & subprocess.CREATE_NO_WINDOW)
            self.assertEqual(options["startupinfo"].wShowWindow, subprocess.SW_HIDE)
            self.assertEqual(popen.call_args.args[0], ["trusted.exe", "arg with space"])
            stop.assert_called_once_with(child)
            self.assertEqual(result["returncode"], 0)

    def test_stop_before_launch_does_not_create_child(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            (directory / "STOP").touch()
            with patch.object(module.subprocess, "Popen") as popen:
                result = module._native_run(["trusted.exe"], directory, directory / "vendor",
                                            timeout=2, cancel_file=directory / "STOP")
            popen.assert_not_called()
            self.assertTrue(result["cancelled"])
            self.assertTrue((directory / "vendor.process.json").exists())

    def test_stop_during_vendor_wait_cleans_only_owned_child(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            def wait(**_kwargs):
                (directory / "STOP").touch()
                raise subprocess.TimeoutExpired("trusted.exe", 0.25)
            child = SimpleNamespace(pid=456, wait=wait, poll=lambda: 1)
            job = SimpleNamespace(error=None, assign=lambda _child: True, close=lambda: True)
            with patch.object(module, "_WindowsJob", return_value=job), \
                    patch.object(module.subprocess, "Popen", return_value=child), \
                    patch.object(module, "stop_tree", return_value={"parent_exit_confirmed": True}) as stop:
                result = module._native_run(["trusted.exe"], directory, directory / "vendor",
                                            timeout=2, cancel_file=directory / "STOP")
            self.assertTrue(result["cancelled"])
            stop.assert_called_once_with(child)
            self.assertTrue(result["cleanup"]["job_handle_closed"])

    def test_keyboard_interrupt_keeps_process_manifest_and_cleans_child(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            def wait(**_kwargs):
                raise KeyboardInterrupt
            child = SimpleNamespace(pid=789, wait=wait, poll=lambda: 1)
            job = SimpleNamespace(error=None, assign=lambda _child: True, close=lambda: True)
            with patch.object(module, "_WindowsJob", return_value=job), \
                    patch.object(module.subprocess, "Popen", return_value=child), \
                    patch.object(module, "stop_tree", return_value={"parent_exit_confirmed": True}) as stop:
                result = module._native_run(["trusted.exe"], directory, directory / "vendor",
                                            timeout=2, cancel_file=directory / "STOP")
            self.assertTrue(result["interrupted"])
            self.assertTrue((directory / "vendor.process.json").exists())
            stop.assert_called_once_with(child)


if __name__ == "__main__":
    unittest.main()
