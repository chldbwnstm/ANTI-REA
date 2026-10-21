from __future__ import annotations

import copy
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from antirea.native_validate import make_cases, _artifact_path, _worker_command, validate_build, verify_integer_abi
from antirea import compile_database as cd


CONTRACT = {"schema_version": 1, "library_name": "testcore", "functions": [
    {"name": "core", "return_type": "u64", "parameters": [
        {"name": "signed_value", "type": "i64"}, {"name": "unsigned_value", "type": "u64"}]}]}


class NativeValidationTests(unittest.TestCase):
    def test_worker_import_is_fixed_despite_workspace_and_pythonpath_shadowing(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            shadow = root / "antirea"
            shadow.mkdir()
            (shadow / "__init__.py").write_text('raise RuntimeError("WORKSPACE_SHADOW")', encoding="utf-8")
            (root / "sitecustomize.py").write_text('raise RuntimeError("SITE_HOOK")', encoding="utf-8")
            command = _worker_command(root / "unused.request.json")
            self.assertIn("-I", command)
            self.assertIn("-S", command)
            # Help exercises real worker imports/argparse without loading a DLL.
            command[-2:] = ["--help"]
            result = subprocess.run(command, cwd=root, env={**os.environ, "PYTHONPATH": str(root)},
                                    capture_output=True, text=True, timeout=20,
                                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("--worker", result.stdout)
            self.assertNotIn("WORKSPACE_SHADOW", result.stderr)
            self.assertNotIn("SITE_HOOK", result.stderr)

    def test_machine_abi_widths_arity_and_convention(self):
        ir = 'define dso_local i64 @core(i64 noundef %a, i64 noundef %b) local_unnamed_addr #0 {\n ret i64 %a\n}\n'
        self.assertEqual(verify_integer_abi(ir, CONTRACT)["core"]["parameter_bits"], [64, 64])
        for invalid in (ir.replace("i64 @core", "i32 @core"),
                        ir.replace("i64 noundef %a, i64 noundef %b", "i64 %a"),
                        ir.replace("i64 noundef %a", "i32 noundef %a"),
                        ir.replace("dso_local", "dso_local fastcc"),
                        ir.replace("dso_local", "dso_local preserve_nonecc"),
                        ir.replace("i64 noundef %a", "i64 inreg %a")):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                verify_integer_abi(invalid, CONTRACT)

    def test_worker_reply_is_not_mixed_with_native_stdout(self):
        from antirea.native_validate import main
        with tempfile.TemporaryDirectory() as folder:
            request = Path(folder) / "baseline.request.json"
            request.write_text("{}", encoding="utf-8")
            def output_from_native(_request):
                print("native library diagnostic")
                return {"outputs": {"core": [2**64 - 1]}}
            capture = io.StringIO()
            with patch("sys.argv", ["native_validate", "--worker", str(request)]), \
                    patch("antirea.native_validate._worker_run", side_effect=output_from_native), redirect_stdout(capture):
                main()
            self.assertIn("native library diagnostic", capture.getvalue())
            result = json.loads(request.with_suffix(".reply.json").read_text())
            self.assertEqual(result["outputs"]["core"], [2**64 - 1])

    def test_wrong_contract_rejected_before_any_worker_is_started(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            build = root / ".runs" / "build"
            source = root / "source"
            build.mkdir(parents=True)
            source.mkdir()
            ir = 'define i64 @core(i64 %a, i64 %b) {\n ret i64 %a\n}\n'
            (build / "module.before.ll").write_text(ir, encoding="utf-8")
            report = {"status": "artifact_created_unvalidated", "coverage": {"functions": {"core": {"virtualized": True}}},
                      "artifact_hashes": {"module.before.ll": hashlib.sha256((build / "module.before.ll").read_bytes()).hexdigest()}}
            (build / "report.json").write_text(json.dumps(report), encoding="utf-8")
            contract = copy.deepcopy(CONTRACT)
            for change in ("return", "arity"):
                bad = copy.deepcopy(contract)
                if change == "return":
                    bad["functions"][0]["return_type"] = "u32"
                else:
                    bad["functions"][0]["parameters"].pop()
                contract_path = source / "contract.json"
                contract_path.write_text(json.dumps(bad), encoding="utf-8")
                with patch("antirea.native_validate.run_logged") as run:
                    with self.assertRaisesRegex(ValueError, "compiled ABI"):
                        validate_build(build / "report.json", contract_path, root / change,
                                       workspace_root=root, random_cases=1)
                    run.assert_not_called()

    def test_cases_are_deterministic_and_cover_width_boundaries(self):
        result = make_cases(CONTRACT, 20, 0)
        self.assertEqual(result, make_cases(CONTRACT, 20, 0))
        pairs = result["core"]
        self.assertIn([-(2**63), 0], pairs)
        self.assertIn([2**63 - 1, 2**64 - 1], pairs)
        for a, b in pairs:
            self.assertTrue(-(2**63) <= a < 2**63)
            self.assertTrue(0 <= b < 2**64)

    def test_scoped_public_export_and_nested_frontend_ir_are_validated(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            build = root / ".runs/build"
            nested = build / "native"
            nested.mkdir(parents=True)
            source = root / "source"
            source.mkdir()
            contract = source / "contract.json"
            contract.write_text(json.dumps(CONTRACT), encoding="utf-8")
            ir = nested / "module.before.ll"
            ir.write_text('define i64 @core(i64 %a, i64 %b) {\n ret i64 %a\n}\n', encoding="utf-8")
            artifacts = {}
            for arm in ("baseline", "protected"):
                path = nested / (arm + ".dll")
                path.write_bytes(b"non-executable transport test fixture")
                artifacts[arm] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            report = {"status": "artifact_created_unvalidated", "artifacts": artifacts,
                      "signature_ir": {"path": str(ir), "sha256": hashlib.sha256(ir.read_bytes()).hexdigest()},
                      "coverage": {"exported_functions": ["core"],
                                   "functions": {"private_helper": {"virtualized": True}},
                                   "public_boundaries": {"core": {"defined": True, "virtualized": False}}}}
            report_path = build / "report.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            with patch("antirea.native_validate.run_logged", side_effect=RuntimeError("reached validated launch boundary")) as runner:
                result = validate_build(report_path, contract, root / ".runs/check", workspace_root=root, random_cases=1)
                runner.assert_called_once()
                self.assertIn("reached validated launch", result["error"])
            report["coverage"]["functions"]["private_helper"]["virtualized"] = False
            report_path.write_text(json.dumps(report), encoding="utf-8")
            with patch("antirea.native_validate.run_logged") as runner:
                with self.assertRaisesRegex(ValueError, "internal functions"):
                    validate_build(report_path, contract, root / ".runs/rejected", workspace_root=root, random_cases=1)
                runner.assert_not_called()

    def test_void_functions_do_not_pass_by_returning_nothing(self):
        contract = copy.deepcopy(CONTRACT)
        contract["functions"][0]["return_type"] = "void"
        with self.assertRaisesRegex(ValueError, "state-observation"):
            make_cases(contract)

    def test_case_budget_validation(self):
        for count in (True, 0, -1, 8193, 1.5):
            with self.subTest(count=count), self.assertRaises(ValueError):
                make_cases(CONTRACT, count)
        with patch("antirea.native_validate.MAX_CASES", 1), self.assertRaises(ValueError):
            make_cases(CONTRACT, 1)

    def test_child_artifact_cannot_escape_reviewed_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            directory = root / "owned"
            directory.mkdir()
            path = root / "outside.dll"
            path.write_bytes(b"fixture")
            with self.assertRaisesRegex(ValueError, "reviewed build"):
                _artifact_path(root, directory, str(path))
            received = root / "rea-analysis-reports" / "built"
            received.mkdir(parents=True)
            path = received / "app.dll"
            path.write_bytes(b"fixture")
            with self.assertRaisesRegex(ValueError, "received"):
                _artifact_path(root, received, str(path))

    def test_existing_output_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            output = root / "existing"
            output.mkdir()
            with patch("antirea.native_validate.run_logged") as run:
                with self.assertRaisesRegex(ValueError, "fresh"):
                    validate_build(root / "report.json", root / "contract.json", output, workspace_root=root)
                run.assert_not_called()


class CompileDatabaseThreeArmTests(unittest.TestCase):
    """Mock only owned worker transport; no binary or compiler executes here."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="antirea-compile-db-validation-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.build = self.root / ".runs/build"
        self.build.mkdir(parents=True)
        source = self.root / "source"
        source.mkdir()
        self.contract = source / "contract.json"
        self.contract.write_text(json.dumps(CONTRACT), encoding="utf-8")
        self.ir = 'define dso_local i64 @core(i64 %a, i64 %b) {\n ret i64 %a\n}\n'
        original = self.build / "original.signature.ll"
        normalized = self.build / "module.before.ll"
        for path in (original, normalized):
            path.write_text(self.ir, encoding="utf-8")
        self.report = {"backend": "compile_database_native", "status": "artifact_created_unvalidated",
            "coverage": {"exported_functions": ["core"], "selected_functions": ["core"],
                         "functions": {"core": {"virtualized": True}}},
            "signature_ir": self.descriptor(normalized),
            "original_reference_signature_ir": self.descriptor(original), "artifacts": {}}
        for arm in ("original_reference", "baseline", "protected"):
            artifact = self.build / (arm + ".dll")
            artifact.write_bytes(("NONEXECUTABLE TEST TRANSPORT " + arm).encode())
            self.report["artifacts"][arm] = self.descriptor(artifact)
        compiler = self.root / "clang.exe"
        compiler.write_bytes(b"NONEXECUTABLE COMPILER TRANSPORT FIXTURE")
        source_file = source / "core.c"
        source_file.write_text("unsigned long long core(long long a,unsigned long long b){return b;}\n", encoding="utf-8")
        obj, tu_ir = self.build / "original.core.obj", self.build / "original.core.ll"
        obj.write_bytes(b"NONEXECUTABLE OBJECT TRANSPORT FIXTURE")
        tu_ir.write_text(self.ir, encoding="utf-8")
        compiler_hash = self.descriptor(compiler)["sha256"]
        self.report["original_reference_provenance"] = {
            "schema_version": 1, "method": "direct_source_compile",
            "source_semantics": "recorded_compilation_database_arguments", "uses_protection_normalized_ir": False,
            "exported_functions": ["core"], "compilation_database_sha256": "1" * 64,
            "compilation_plan_fingerprint": "2" * 64, "source_input_snapshot_sha256": "3" * 64,
            "header_context_sha256": "4" * 64, "compiler_inputs": {str(compiler): compiler_hash},
            "translation_units": [{"source": str(source_file), "source_operand": "core.c", "entry_sha256": "5" * 64,
                "compiler": str(compiler), "compiler_sha256": compiler_hash, "cwd": str(source),
                "object_path": str(obj), "signature_ir_path": str(tu_ir),
                "object_command_index": 0, "signature_ir_command_index": 1}],
            "link_command_index": 2, "link_contract": {"kind": "restricted_windows_shared_library",
                "target": "x86_64-pc-windows-msvc", "complete_application_link": False}}
        self.report["commands"] = []
        for argv in ([str(compiler), "-c", "core.c", "-o", str(obj)],
                     [str(compiler), "-S", "-emit-llvm", "core.c", "-o", str(tu_ir)],
                     [str(compiler), "-shared", str(obj), "-o", self.report["artifacts"]["original_reference"]["path"]]):
            self.report["commands"].append({"argv": argv, "cwd": str(source), "returncode": 0,
                "timed_out": False, "cancelled": False, "cleanup": {"job_assigned": True,
                    "active_after": 0, "parent_exit_confirmed": True, "job_handle_closed": True}})
        self.report_path = self.build / "report.json"
        self.install_reference_plan()
        self.save_report()
        self.requests = []
        self.counter = 0
        self.reply_mutation = None
        self.process_mutation = None
        self.skip_reply = False

    @staticmethod
    def descriptor(path):
        return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "bytes": path.stat().st_size}

    def save_report(self):
        self.report_path.write_text(json.dumps(self.report), encoding="utf-8")

    def install_reference_plan(self, *, operand="core.c", second=False, driver="clang"):
        """Real normalization/recipe rendering; compiler files remain inert."""
        source = self.contract.parent
        compiler = self.root / ("clang-cl.exe" if driver == "clangcl" else "clang.exe")
        if not compiler.exists():
            compiler.write_bytes(b"NONEXECUTABLE COMPILER TRANSPORT FIXTURE")
        (source / "forced.h").write_text("#define FORCED 19\n", encoding="utf-8")
        extra = source / "helper.c"
        if second:
            extra.write_text("int helper(void){return 7;}\n", encoding="utf-8")
        flags = (["/std:c11", "/O2", "/DVALUE=1", "/UVALUE", "/DVALUE=7", "/FIforced.h"]
                 if driver == "clangcl" else
                 ["-std=c11", "-O2", "-DVALUE=1", "-UVALUE", "-DVALUE=7", "-include", "forced.h"])
        entries = [{"directory": ".", "file": "core.c",
                    "arguments": [str(compiler), *flags, "-c", operand]}]
        if second:
            entries.append({"directory": ".", "file": "helper.c",
                            "arguments": [str(compiler), *flags, "-c", "helper.c"]})
        database = source / "compile_commands.json"
        database.write_text(json.dumps(entries), encoding="utf-8")
        tool = {"path": str(compiler), "sha256": self.descriptor(compiler)["sha256"]}
        plan = cd.normalize_database(database, workspace_root=self.root, project_root=source,
            toolchain={driver: tool}, selections=[{"file": entry["file"]} for entry in entries])
        self.report["compilation_database"] = plan
        saved = self.build / "compile-database-plan.json"
        saved.write_text(json.dumps(plan), encoding="utf-8")
        raw = self.build / "compile-database-raw.json"
        raw.write_bytes(database.read_bytes())
        self.report["compilation_database_source"] = self.descriptor(raw)
        inventory = self.build / "compile-database-inputs.json"
        inventory.write_text(json.dumps({"project": plan["inputs"],
            "trusted_headers": {"roots": [], "files": []}}), encoding="utf-8")
        self.report["header_inventory"] = self.descriptor(inventory)
        self.report["artifact_hashes"] = {path.name: self.descriptor(path)["sha256"]
                                           for path in (saved, raw, inventory)}
        provenance = self.report["original_reference_provenance"]
        provenance.update(compilation_database_sha256=plan["database_sha256"],
            compilation_plan_fingerprint=plan["fingerprint"],
            source_input_snapshot_sha256=cd._sha(cd._encoded(plan["inputs"])),
            header_context_sha256=cd._sha(cd._encoded(plan["trusted_headers"])),
            compiler_inputs={str(compiler): tool["sha256"]}, translation_units=[])
        self.report["commands"] = []
        objects = []
        for index, unit in enumerate(plan["translation_units"]):
            obj, ir = self.build / f"original-{index}.obj", self.build / f"original-{index}.ll"
            obj.write_bytes(b"NONEXECUTABLE OBJECT TRANSPORT FIXTURE")
            ir.write_text(self.ir, encoding="utf-8")
            for path in (obj, ir):
                self.report["artifact_hashes"][path.name] = self.descriptor(path)["sha256"]
            objects.append(str(obj))
            start = len(self.report["commands"])
            for path, emit_ir in ((obj, False), (ir, True)):
                recipe = cd.render_compile_argv(plan, index, path, emit_ir=emit_ir)
                self.report["commands"].append(self.successful_command(recipe["argv"], recipe["cwd"]))
            provenance["translation_units"].append({"source": unit["source"],
                "source_operand": unit["source_operand"], "entry_sha256": unit["entry_sha256"],
                "compiler": unit["compiler"]["path"], "compiler_sha256": unit["compiler"]["sha256"],
                "cwd": unit["directory"], "object_path": str(obj), "signature_ir_path": str(ir),
                "object_command_index": start, "signature_ir_command_index": start + 1})
        provenance["link_command_index"] = len(self.report["commands"])
        # The link driver is the pinned native toolchain's clang++, independent
        # of each TU's original clang/clang-cl frontend.
        tool_bin = self.root / ".tools/llvm/bin"
        tool_bin.mkdir(parents=True, exist_ok=True)
        tool_paths = [tool_bin / name for name in ("llvm-link.exe", "opt.exe", "clang++.exe", "LLVM-C.dll", "lld-link.exe")]
        for path in tool_paths:
            path.write_bytes(("NONEXECUTABLE LINK TOOL " + path.name).encode())
        config = self.root / ".tools/kagura-toolchain.json"
        config.write_text(json.dumps({"schema_version": 1, "target": "x86_64-pc-windows-msvc",
            "llvm_root": str(tool_bin.parent), "clangxx": str(tool_bin / "clang++.exe")}), encoding="utf-8")
        self.report["tool_hashes"] = {str(path): self.descriptor(path)["sha256"] for path in [config, *tool_paths]}
        definition = self.build / "exports.def"
        definition.write_bytes(b"EXPORTS\ncore\n")
        self.report["artifact_hashes"][definition.name] = self.descriptor(definition)["sha256"]
        self.report["commands"].append(self.successful_command(
            [str(tool_bin / "clang++.exe"), "-target", "x86_64-pc-windows-msvc", "-shared", "-fuse-ld=lld",
             *objects, f"-Wl,/DEF:{definition}", "-Wl,/DEBUG:NONE", "-Wl,/INCREMENTAL:NO",
             "-o", self.report["artifacts"]["original_reference"]["path"]], str(self.build)))
        signature = self.report["original_reference_signature_ir"]["path"]
        self.report["commands"].append(self.successful_command(
            [str(tool_bin / "llvm-link.exe"), "-S",
             *[unit["signature_ir_path"] for unit in provenance["translation_units"]], "-o", signature],
            str(self.build)))
        self.report["artifact_hashes"][Path(signature).name] = self.descriptor(Path(signature))["sha256"]

    @staticmethod
    def successful_command(argv, cwd):
        return {"argv": argv, "cwd": cwd, "returncode": 0, "timed_out": False, "cancelled": False,
                "cleanup": {"job_assigned": True, "active_after": 0,
                            "parent_exit_confirmed": True, "job_handle_closed": True}}

    def rebind_modified_plan_sidecars(self):
        """Adversarial fixture: update hashes too, to exercise raw-entry replay."""
        plan = self.report["compilation_database"]
        plan["fingerprint"] = cd._sha(cd._encoded({k: v for k, v in plan.items() if k != "fingerprint"}))
        path = self.build / "compile-database-plan.json"
        path.write_text(json.dumps(plan), encoding="utf-8")
        self.report["artifact_hashes"][path.name] = self.descriptor(path)["sha256"]
        self.report["original_reference_provenance"]["compilation_plan_fingerprint"] = plan["fingerprint"]

    def worker(self, argv, directory, log_prefix, timeout, *, cancel_file):
        request_path = Path(argv[-1])
        request = json.loads(request_path.read_text(encoding="utf-8"))
        arm = Path(request["library_path"]).stem
        self.requests.append((arm, request))
        cases = make_cases(request["contract"], request["random_cases"], request["seed"])
        reply = {"outputs": {name: [7] * len(vectors) for name, vectors in cases.items()},
                 "deterministic": {name: True for name in cases},
                 "timings": {name: {"samples_ns": [11] * 7, "median_ns": 11,
                                    "calls_per_batch": min(256, len(vectors)), "warmup_batches": 1}
                             for name, vectors in cases.items()}}
        if self.reply_mutation:
            replacement = self.reply_mutation(arm, reply)
            if replacement is not None:
                reply = replacement
        if not self.skip_reply:
            request_path.with_suffix(".reply.json").write_text(json.dumps(reply), encoding="utf-8")
        process = {"returncode": 0, "timed_out": False, "cancelled": False,
                   "cleanup": {"job_assigned": True, "active_after": 0,
                               "parent_exit_confirmed": True, "job_handle_closed": True}}
        if self.process_mutation:
            self.process_mutation(arm, process)
        self.assertEqual(Path(cancel_file), self.root / ".runs/defense-loop/STOP")
        self.assertEqual(timeout, 9)
        self.assertIn("-I", argv)
        self.assertIn("-S", argv)
        return process

    def validate(self):
        self.counter += 1
        with patch("antirea.native_validate.run_logged", side_effect=self.worker):
            return validate_build(self.report_path, self.contract, self.root / f".runs/validation-{self.counter}",
                                  workspace_root=self.root, random_cases=3, seed=19, timeout_seconds=9)

    def assert_preflight_rejects(self, pattern):
        self.save_report()
        with patch("antirea.native_validate.run_logged") as worker, self.assertRaisesRegex(ValueError, pattern):
            validate_build(self.report_path, self.contract, self.root / ".runs/rejected",
                           workspace_root=self.root, random_cases=3)
        worker.assert_not_called()

    def test_original_is_mandatory_and_all_three_arms_use_identical_cases(self):
        result = self.validate()
        self.assertEqual(result["status"], "functional_samples_passed")
        self.assertEqual(result["required_arms"], ["original_reference", "baseline", "protected"])
        self.assertTrue(result["original_reference_required"])
        self.assertEqual([name for name, request in self.requests], result["required_arms"])
        requested = [{key: request[key] for key in ("contract", "random_cases", "seed")}
                     for name, request in self.requests]
        self.assertEqual(requested[0], requested[1])
        self.assertEqual(requested[1], requested[2])
        count = len(make_cases(CONTRACT, 3, 19)["core"])
        comparisons = result["functions"]["core"]["original_reference_comparisons"]
        self.assertEqual(comparisons, {arm: {"matched": count, "total": count} for arm in ("baseline", "protected")})
        self.assertEqual(result["original_reference_abi_evidence"]["core"]["signedness"], "user_contract_not_encoded_in_llvm")
        self.assertTrue(result["inputs_unchanged"])

    def test_original_link_rejects_extra_object_library_or_override(self):
        good = copy.deepcopy(self.report)
        for extra in (str(self.build / "unknown.obj"), "unknown.lib", "-Wl,/FORCE", "-Wl,/ENTRY:other"):
            with self.subTest(extra=extra):
                self.report = copy.deepcopy(good)
                self.report["commands"][self.report["original_reference_provenance"]["link_command_index"]]["argv"].insert(5, extra)
                self.assert_preflight_rejects("original reference link")

    def test_original_link_requires_exact_trusted_driver_and_working_directory(self):
        good = copy.deepcopy(self.report)
        for mode in ("driver", "cwd", "target", "definition", "duplicate"):
            with self.subTest(mode=mode):
                self.report = copy.deepcopy(good)
                record = self.report["commands"][self.report["original_reference_provenance"]["link_command_index"]]
                if mode == "driver": record["argv"][0] = str(self.root / "other.exe")
                elif mode == "cwd": record["cwd"] = str(self.root)
                elif mode == "target": record["argv"][2] = "x86_64-unknown-linux-gnu"
                elif mode == "definition": record["argv"][-5] = "-Wl,/DEF:other.def"
                else: self.report["commands"].append(copy.deepcopy(record))
                self.assert_preflight_rejects("original reference link")

    def test_original_link_requires_exact_original_object_order(self):
        self.install_reference_plan(second=True)
        argv = self.report["commands"][self.report["original_reference_provenance"]["link_command_index"]]["argv"]
        argv[5:7] = list(reversed(argv[5:7]))
        self.assert_preflight_rejects("original reference link")

    def test_original_link_requires_trusted_config_driver_and_linker_pins(self):
        good = copy.deepcopy(self.report)
        paths = [str(self.root / ".tools/kagura-toolchain.json"),
                 str(self.root / ".tools/llvm/bin/clang++.exe"), str(self.root / ".tools/llvm/bin/lld-link.exe")]
        for path in paths:
            for mutation in ("missing", "wrong"):
                with self.subTest(path=path, mutation=mutation):
                    self.report = copy.deepcopy(good)
                    if mutation == "missing": self.report["tool_hashes"].pop(path)
                    else: self.report["tool_hashes"][path] = "0" * 64
                    self.assert_preflight_rejects("original reference link")

    def test_original_link_definition_is_hash_bound_and_has_no_extra_exports(self):
        definition = self.build / "exports.def"
        definition.write_bytes(b"EXPORTS\ncore\nextra\n")
        self.assert_preflight_rejects("original reference link")
        self.report["artifact_hashes"][definition.name] = self.descriptor(definition)["sha256"]
        self.assert_preflight_rejects("original reference link")

    def test_original_link_tool_and_definition_changes_during_worker_fail(self):
        for path in (self.root / ".tools/llvm/bin/lld-link.exe", self.build / "exports.def"):
            with self.subTest(path=path):
                raw = path.read_bytes()
                self.process_mutation = lambda arm, process: path.write_bytes(raw + b" changed") if arm == "original_reference" else None
                result = self.validate()
                self.assertEqual(result["status"], "failed")
                path.write_bytes(raw)

    def test_existing_two_arm_route_does_not_require_or_execute_original(self):
        self.report.pop("backend")
        self.report.pop("original_reference_signature_ir")
        self.report["artifacts"].pop("original_reference")
        self.save_report()
        result = self.validate()
        self.assertEqual(result["status"], "functional_samples_passed")
        self.assertFalse(result["original_reference_required"])
        self.assertEqual([name for name, request in self.requests], ["baseline", "protected"])

    def test_missing_original_artifact_rejected_before_execution(self):
        self.report["artifacts"].pop("original_reference")
        self.assert_preflight_rejects("required native artifact")

    def test_original_source_operand_spelling_is_preserved(self):
        good = copy.deepcopy(self.report)
        unit = good["original_reference_provenance"]["translation_units"][0]
        (Path(unit["cwd"]) / "sub").mkdir()
        for operand in ("core.c", "./core.c", "sub/../core.c", "../source/core.c", unit["source"]):
            with self.subTest(operand=operand):
                self.report = copy.deepcopy(good)
                self.install_reference_plan(operand=operand)
                self.save_report()
                result = self.validate()
                self.assertEqual(result["status"], "functional_samples_passed", result.get("error"))
                actual = result["original_reference_provenance"]["translation_units"][0]
                self.assertEqual(actual["source_operand"], operand)
                self.assertEqual(actual["source"], unit["source"])

    def test_rewriting_only_argv_source_spelling_is_rejected(self):
        good = copy.deepcopy(self.report)
        for command_index in (0, 1):
            with self.subTest(command_index=command_index):
                self.report = copy.deepcopy(good)
                record = self.report["commands"][command_index]
                source = self.report["original_reference_provenance"]["translation_units"][0]["source"]
                record["argv"] = [source if arg == "core.c" else arg for arg in record["argv"]]
                self.assert_preflight_rejects("exact preserved frontend recipe")

    def test_missing_illtyped_or_different_source_operand_is_rejected(self):
        good = copy.deepcopy(self.report)
        source = Path(good["original_reference_provenance"]["translation_units"][0]["source"])
        (source.parent / "different.c").write_text("int other(void){return 1;}\n", encoding="utf-8")
        for operand in (None, "", 7, "core.c\x00", "different.c", "missing.c"):
            with self.subTest(operand=operand):
                self.report = copy.deepcopy(good)
                unit = self.report["original_reference_provenance"]["translation_units"][0]
                if operand is None:
                    unit.pop("source_operand")
                else:
                    unit["source_operand"] = operand
                    for record in self.report["commands"][:2]:
                        record["argv"] = [operand if arg == "core.c" else arg for arg in record["argv"]]
                self.assert_preflight_rejects("original")

    def test_source_operand_resolves_against_recorded_cwd(self):
        alternate = self.root / "alternate"
        alternate.mkdir()
        (alternate / "core.c").write_text("int other(void){return 1;}\n", encoding="utf-8")
        self.report["original_reference_provenance"]["translation_units"][0]["cwd"] = str(alternate)
        for record in self.report["commands"][:2]:
            record["cwd"] = str(alternate)
        self.assert_preflight_rejects("exact selected database entry")

    def test_missing_original_signature_rejected_before_execution(self):
        self.report.pop("original_reference_signature_ir")
        self.assert_preflight_rejects("original reference signature")

    def test_fabricated_well_formed_provenance_digests_fail(self):
        for field in ("compilation_database_sha256", "compilation_plan_fingerprint",
                      "source_input_snapshot_sha256", "header_context_sha256"):
            with self.subTest(field=field):
                provenance = self.report["original_reference_provenance"]
                previous = provenance[field]
                provenance[field] = "9" * 64
                self.assert_preflight_rejects("digest differs")
                provenance[field] = previous

    def test_omitted_selected_translation_unit_is_rejected(self):
        self.install_reference_plan(second=True)
        self.report["original_reference_provenance"]["translation_units"].pop()
        self.assert_preflight_rejects("complete selected plan")

    def test_duplicate_or_wrong_entry_mapping_is_rejected(self):
        self.install_reference_plan(second=True)
        good = copy.deepcopy(self.report)
        for mutation in ("duplicate", "entry"):
            with self.subTest(mutation=mutation):
                self.report = copy.deepcopy(good)
                units = self.report["original_reference_provenance"]["translation_units"]
                if mutation == "duplicate":
                    units[1] = copy.deepcopy(units[0])
                else:
                    units[0]["entry_sha256"] = units[1]["entry_sha256"]
                self.assert_preflight_rejects("original")

    def test_missing_changed_or_disagreeing_private_plan_fails(self):
        good = copy.deepcopy(self.report)
        path = self.build / "compile-database-plan.json"
        raw = path.read_bytes()
        mutations = [lambda: self.report.pop("compilation_database"),
                     lambda: self.report["artifact_hashes"].pop(path.name),
                     lambda: self.report["compilation_database"].update(status="modified"),
                     lambda: path.write_bytes(raw + b" ")]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self.report = copy.deepcopy(good)
                path.write_bytes(raw)
                mutate()
                self.assert_preflight_rejects("original")
        path.write_bytes(raw)

    def test_frontend_flag_drop_change_order_or_append_never_passes(self):
        for driver in ("clang", "clangcl"):
            self.install_reference_plan(driver=driver)
            good = copy.deepcopy(self.report)
            for command_index in (0, 1):
                for change in ("drop_define", "change_opt", "reorder", "append_hook"):
                    with self.subTest(driver=driver, command_index=command_index, change=change):
                        self.report = copy.deepcopy(good)
                        argv = self.report["commands"][command_index]["argv"]
                        if change == "drop_define":
                            index = argv.index("VALUE=7")
                            del argv[index - 1:index + 1]
                        elif change == "change_opt":
                            index = argv.index("/O2" if driver == "clangcl" else "-O2")
                            argv[index] = "/Od" if driver == "clangcl" else "-O0"
                        elif change == "reorder":
                            index = argv.index("VALUE=1")
                            argv[index], argv[index + 4] = argv[index + 4], argv[index]
                        else:
                            argv.insert(1, "-fplugin=untrusted.dll")
                        self.assert_preflight_rejects("exact preserved frontend recipe")

    def test_consistently_rehashed_wrong_frontend_plan_cannot_bypass_raw_entry_replay(self):
        plan = self.report["compilation_database"]
        plan["translation_units"][0]["frontend_argv"].append("-fwrapv")
        self.rebind_modified_plan_sidecars()
        self.assert_preflight_rejects("recipe does not match the raw database")

    def test_matching_provenance_canonical_rewrite_still_differs_from_original_entry(self):
        plan = self.report["compilation_database"]
        original = plan["translation_units"][0]
        original["source_operand"] = original["source"]
        self.report["original_reference_provenance"]["translation_units"][0]["source_operand"] = original["source"]
        for record in self.report["commands"][:2]:
            record["argv"][-1] = original["source"]
        self.rebind_modified_plan_sidecars()
        self.assert_preflight_rejects("recipe does not match the raw database")

    def test_build_snapshot_not_changed_current_database_is_used_for_history(self):
        current = Path(self.report["compilation_database"]["database"])
        current.write_text("[]", encoding="utf-8")
        self.save_report()
        result = self.validate()
        self.assertEqual(result["status"], "functional_samples_passed", result.get("error"))

    def test_private_raw_snapshot_or_header_sidecar_tamper_fails(self):
        for field in ("compilation_database_source", "header_inventory"):
            with self.subTest(field=field):
                path = Path(self.report[field]["path"])
                raw = path.read_bytes()
                path.write_bytes(raw + b" ")
                self.assert_preflight_rejects("original")
                path.write_bytes(raw)

    def test_private_evidence_changed_during_workers_fails(self):
        path = self.build / "compile-database-plan.json"
        original = path.read_bytes()
        def mutate(arm, process):
            if arm == "protected":
                path.write_bytes(original + b" ")
        self.process_mutation = mutate
        self.assertEqual(self.validate()["status"], "failed")

    def test_missing_or_false_original_compilation_provenance_is_rejected(self):
        good = copy.deepcopy(self.report)
        mutations = [
            lambda r: r.pop("original_reference_provenance"),
            lambda r: r["original_reference_provenance"].update(uses_protection_normalized_ir=True),
            lambda r: r["original_reference_provenance"].update(exported_functions=[]),
            lambda r: r["original_reference_provenance"].update(exported_functions=["core", "core"]),
            lambda r: r["original_reference_provenance"].pop("compilation_plan_fingerprint"),
            lambda r: r["original_reference_provenance"]["translation_units"][0].update(compiler_sha256="9" * 64),
            lambda r: r["original_reference_provenance"]["translation_units"][0].update(object_command_index=99),
            lambda r: r["commands"][0]["argv"].remove(r["original_reference_provenance"]["translation_units"][0]["source_operand"]),
            lambda r: r["commands"][0]["argv"].append("-emit-llvm"),
            lambda r: r["commands"][1]["argv"].remove("-emit-llvm"),
            lambda r: r["commands"][1]["argv"].append("-disable-llvm-passes"),
            lambda r: r["commands"][0].update(returncode=1),
            lambda r: r["commands"][0].update(cwd=str(self.root)),
            lambda r: r["commands"][2]["argv"].remove(r["original_reference_provenance"]["translation_units"][0]["object_path"]),
            lambda r: r["commands"][2]["argv"].append(r["artifacts"]["baseline"]["path"]),
        ]
        for index, change in enumerate(mutations):
            with self.subTest(index=index):
                self.report = copy.deepcopy(good)
                change(self.report)
                self.assert_preflight_rejects("original")

    def test_original_artifact_cannot_escape_owned_build_directory(self):
        outside = self.root / "outside.dll"
        outside.write_bytes(b"not executable")
        self.report["artifacts"]["original_reference"] = self.descriptor(outside)
        self.assert_preflight_rejects("reviewed build")

    def test_original_signature_cannot_escape_owned_build_directory(self):
        outside = self.root / "outside.ll"
        outside.write_text(self.ir, encoding="utf-8")
        self.report["original_reference_signature_ir"] = self.descriptor(outside)
        self.assert_preflight_rejects("reviewed build")

    def test_original_artifact_hash_and_byte_count_are_verified(self):
        artifact = self.report["artifacts"]["original_reference"]
        original = Path(artifact["path"])
        old = original.read_bytes()
        original.write_bytes(old + b"changed")
        self.assert_preflight_rejects("artifact hash")
        original.write_bytes(old)
        artifact["bytes"] += 1
        self.assert_preflight_rejects("byte count")

    def test_original_signature_hash_abi_and_distinct_path_are_verified(self):
        path = Path(self.report["original_reference_signature_ir"]["path"])
        path.write_text(self.ir + "; changed\n", encoding="utf-8")
        self.assert_preflight_rejects("signature IR differs")
        for ir in (self.ir.replace("i64 @core", "i32 @core"),
                   self.ir.replace("i64 %a, i64 %b", "i64 %a"),
                   self.ir.replace("dso_local", "dso_local fastcc")):
            with self.subTest(ir=ir):
                path.write_text(ir, encoding="utf-8")
                self.report["original_reference_signature_ir"] = self.descriptor(path)
                self.assert_preflight_rejects("compiled ABI|calling convention")
        self.report["original_reference_signature_ir"] = self.report["signature_ir"]
        self.assert_preflight_rejects("separate source-compiled")

    def test_original_cannot_alias_baseline_artifact(self):
        self.report["artifacts"]["original_reference"] = self.report["artifacts"]["baseline"]
        self.assert_preflight_rejects("separate owned artifacts")

    def test_baseline_protected_agreement_does_not_hide_original_mismatch(self):
        def mutate(arm, reply):
            if arm == "original_reference":
                reply["outputs"]["core"][0] = 9
        self.reply_mutation = mutate
        result = self.validate()
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["functions"]["core"]["sampled_output_match"])
        self.assertFalse(result["functions"]["core"]["original_reference_match"])

    def test_original_nondeterminism_fails_even_when_first_outputs_match(self):
        def mutate(arm, reply):
            if arm == "original_reference":
                reply["deterministic"]["core"] = False
        self.reply_mutation = mutate
        result = self.validate()
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["functions"]["core"]["deterministic"])

    def test_empty_partial_extra_or_illtyped_original_reply_never_passes(self):
        mutations = [
            lambda r: r.clear(),
            lambda r: r["outputs"].clear(),
            lambda r: r["outputs"].update(extra=[7]),
            lambda r: r["outputs"].update(core=[]),
            lambda r: r["outputs"]["core"].pop(),
            lambda r: r["outputs"]["core"].__setitem__(0, True),
            lambda r: r["outputs"]["core"].__setitem__(0, "7"),
            lambda r: r["outputs"]["core"].__setitem__(0, 2**64),
            lambda r: r["deterministic"].update(core="yes"),
            lambda r: r["timings"].clear(),
            lambda r: r["timings"]["core"].update(samples_ns=[]),
            lambda r: r["timings"]["core"].update(calls_per_batch=0),
        ]
        for index, change in enumerate(mutations):
            with self.subTest(index=index):
                def mutate(arm, reply):
                    if arm == "original_reference":
                        change(reply)
                self.reply_mutation = mutate
                result = self.validate()
                self.assertEqual(result["status"], "failed")
                self.assertIn("worker", result["error"])

    def test_original_child_failures_timeouts_and_missing_replies_fail_closed(self):
        for changes, expected in (({"returncode": 1}, "failed"),
                                  ({"timed_out": True}, "timed_out"),
                                  ({"cancelled": True}, "cancelled")):
            with self.subTest(changes=changes):
                self.process_mutation = lambda arm, process: process.update(changes) if arm == "original_reference" else None
                result = self.validate()
                self.assertEqual(result["status"], expected)
                self.assertEqual(set(result["execution"]), {"original_reference"})
        self.process_mutation = None
        self.skip_reply = True
        self.assertEqual(self.validate()["status"], "failed")

    @unittest.skipUnless(os.name == "nt", "Windows job cleanup contract")
    def test_unverified_original_worker_cleanup_is_failure(self):
        def mutate(arm, process):
            if arm == "original_reference":
                process["cleanup"]["active_after"] = 1
        self.process_mutation = mutate
        result = self.validate()
        self.assertEqual(result["status"], "failed")
        self.assertIn("cleanup", result["error"])

    def test_original_binary_or_signature_changed_during_validation_fails(self):
        for descriptor in (self.report["artifacts"]["original_reference"], self.report["original_reference_signature_ir"]):
            path = Path(descriptor["path"])
            original = path.read_bytes()
            def mutate(arm, process):
                if arm == "protected":
                    path.write_bytes(original + b" changed")
            self.process_mutation = mutate
            result = self.validate()
            self.assertEqual(result["status"], "failed")
            self.assertFalse(result["inputs_unchanged"])
            path.write_bytes(original)

    def test_stop_before_or_after_workers_never_reports_pass(self):
        stop = self.root / ".runs/defense-loop/STOP"
        stop.parent.mkdir(parents=True)
        stop.write_text("stop", encoding="utf-8")
        self.assertEqual(self.validate()["status"], "cancelled")
        self.assertEqual(self.requests, [])
        stop.unlink()
        def mutate(arm, process):
            if arm == "protected":
                stop.write_text("stop", encoding="utf-8")
        self.process_mutation = mutate
        self.assertEqual(self.validate()["status"], "cancelled")


if __name__ == "__main__":
    unittest.main()
