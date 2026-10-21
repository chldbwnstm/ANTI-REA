"""Compilation database integration tests.

Mock cases never execute a target. Opt-in cases use owned generated C/C++ source
and the actual installed compiler/VM; they keep durable private evidence.
"""
import contextlib
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

from antirea import compile_database as cd
from antirea import native_build as nb
from antirea.projects import ProjectService


IR = 'target triple = "x86_64-pc-windows-msvc"\ndefine i64 @core(i32 %x, i32 %y) {\n ret i64 7\n}\n'


@unittest.skipUnless(os.name == "nt", "Windows installed metadata derivation")
class InstalledHeaderContextTests(unittest.TestCase):
    def test_auxiliary_headers_derive_from_pinned_vs_installation_only(self):
        import winreg
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            llvm, installation, sdk = root / "llvm", root / "vs", root / "sdk"
            compiler = llvm / "bin/clang.exe"
            shell = installation / "Common7/Tools/Launch-VsDevShell.ps1"
            version = installation / "VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt"
            for path, content in ((compiler, "not executable"), (shell, "not executable"), (version, "14.50.1")):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            auxiliary = installation / "VC/Auxiliary/VS/include"
            for path in (llvm / "lib/clang/22/include", installation / "VC/Tools/MSVC/14.50.1/include",
                         sdk / "Include", auxiliary):
                path.mkdir(parents=True, exist_ok=True)
            config = {"llvm_root": str(llvm), "llvm_version": "22.1.0", "clang": str(compiler), "developer_shell": str(shell)}

            def registry(hive, key, *args):
                if key != r"SOFTWARE\Microsoft\Windows Kits\Installed Roots":
                    raise FileNotFoundError(key)
                return contextlib.nullcontext("fake installed SDK key")

            with patch.object(winreg, "OpenKey", side_effect=registry), \
                    patch.object(winreg, "QueryValueEx", return_value=(str(sdk), winreg.REG_SZ)), \
                    patch.object(nb, "_devshell_selection_metadata", return_value={"files": {}, "referenced_environment_names": []}):
                result = nb._compile_database_environment(config)
            self.assertIn({"kind": "msvc_auxiliary", "path": str(auxiliary)}, result["roots"])
            self.assertEqual(result["metadata"]["files"], {str(version): nb._hash(version)})
            self.assertTrue(all(Path(row["path"]).is_relative_to(root) for row in result["roots"]))


class CompilationDatabaseIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.project_root = self.root / "owned"
        self.project_root.mkdir()
        self.project = self.project_root / "project.json"
        self.db = self.project_root / "compile_commands.json"
        self.sources = [self.project_root / "helper.c", self.project_root / "core.cpp"]
        for source in self.sources:
            source.write_text("/* owned mock input; never executed */", encoding="utf-8")
        (self.project_root / "forced.h").write_text("#define FORCED 19\n", encoding="utf-8")
        self.sdk = self.root / "trusted-sdk"
        self.sdk.mkdir()
        (self.sdk / "stdint.h").write_text("/* approved fake SDK */", encoding="utf-8")
        tools = self.root / ".tools"
        binary = tools / "llvm/bin"
        binary.mkdir(parents=True)
        self.config = {"llvm_version": "22.1.0", "llvm_root": str(binary.parent)}
        for key, name in (("clang", "clang.exe"), ("clangxx", "clang++.exe"),
                          ("llvm_link", "llvm-link.exe"), ("optimizer", "kagura-opt.exe"),
                          ("scope_optimizer", "opt.exe"), ("lld_link", "lld-link.exe"), ("developer_shell", "fixed.ps1"),
                          ("runtime_source", "runtime.c"), ("opcode_source", "opcodes.def")):
            path = binary / name
            path.write_bytes(("mock pinned input " + key).encode())
            self.config[key] = str(path)
        (binary / "LLVM-C.dll").write_bytes(b"mock parser never loaded")
        (tools / "kagura-toolchain.json").write_text(json.dumps(self.config), encoding="utf-8")
        self.hashes = {value: nb._hash(Path(value)) for key, value in self.config.items()
                       if key not in {"llvm_version", "llvm_root"}}
        self.hashes[str(tools / "kagura-toolchain.json")] = nb._hash(tools / "kagura-toolchain.json")
        self.environment = {"schema_version": 1, "roots": [{"kind": "test_only", "path": str(self.sdk)}],
                            "metadata": {"files": {}, "registry": [], "selection_context": {
                                "installation": str(self.root), "vswhere": str(binary / "fake-vswhere.exe"),
                                "referenced_environment_names": []}},
                            "environment_selection_inputs": nb._environment_selection_inputs()}
        self.entries = []
        for index, source in enumerate(self.sources):
            driver = self.config["clang" if index == 0 else "clangxx"]
            args = [driver, "-std=c11" if index == 0 else "-std=c++20", "-O2", "-DVALUE=1", "-UVALUE",
                    "-DVALUE=" + str(7 + index), "-include", "forced.h", "-c", source.name,
                    "-o", source.stem + ".obj"]
            self.entries.append({"directory": str(self.project_root), "file": source.name, "arguments": args})
        self.manifest = {"schema_version": 1, "name": "database-owned", "language": "cpp",
                         "compile_commands": {"path": self.db.name, "selections": [{"file": p.name} for p in self.sources]},
                         "functions": ["core"]}
        self.save()
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(nb, "_toolchain", side_effect=lambda root: (copy.deepcopy(self.config), dict(self.hashes))))
        self.stack.enter_context(patch.object(nb, "_compile_database_environment", return_value=self.environment))

    def save(self):
        self.db.write_text(json.dumps(self.entries), encoding="utf-8")
        self.project.write_text(json.dumps(self.manifest), encoding="utf-8")

    def inspect(self):
        return nb.inspect_project(self.project, workspace_root=self.root)

    def test_inspection_runs_no_compiler_and_preserves_ordered_mixed_settings(self):
        with patch.object(nb, "run_logged", side_effect=AssertionError("inspection must not execute")):
            info = self.inspect()
        self.assertEqual(info["backend"], "compile_database_native")
        units = info["compilation_database"]["translation_units"]
        self.assertEqual([u["language"] for u in units], ["c", "cpp"])
        self.assertEqual([u["source_operand"] for u in units], ["helper.c", "core.cpp"])
        self.assertEqual(units[0]["frontend_argv"][2:8], ["-D", "VALUE=1", "-U", "VALUE", "-D", "VALUE=7"])
        self.assertEqual(info["defines"], {})
        self.assertEqual(info["include_dirs"], [])
        self.assertFalse((self.root / ".runs").exists())

    def test_global_options_cannot_silently_override_translation_units(self):
        for key, value in (("sources", ["core.cpp"]), ("defines", {"VALUE": 0}), ("include_dirs", [])):
            with self.subTest(key=key):
                self.manifest[key] = value
                self.save()
                with self.assertRaisesRegex(nb.NativeBuildError, "cannot be combined"):
                    self.inspect()
                del self.manifest[key]

    def test_manifest_cannot_authorize_external_sdk_roots(self):
        self.manifest["compile_commands"]["trusted_header_roots"] = [str(self.sdk)]
        self.save()
        with self.assertRaisesRegex(nb.NativeBuildError, "requires path"):
            self.inspect()

    def test_explicit_workspace_required(self):
        with self.assertRaisesRegex(nb.NativeBuildError, "workspace_root"):
            nb.inspect_project(self.project)

    def test_new_owned_or_sdk_header_invalidates_snapshot(self):
        info = self.inspect()
        for directory in (self.project_root, self.sdk):
            path = directory / "new-header.h"
            path.write_text("#define NEW 1", encoding="utf-8")
            with self.subTest(directory=directory), self.assertRaisesRegex(ValueError, "snapshot changed|inventory changed"):
                cd.verify_snapshot(info["compilation_database"])
            path.unlink()

    def test_project_snapshot_includes_explicit_extra_owned_header_root(self):
        shared = self.root / "shared"
        shared.mkdir()
        header = shared / "shared.h"
        header.write_text("#define SHARED 2", encoding="utf-8")
        self.manifest["compile_commands"]["input_roots"] = ["shared"]
        self.save()
        info = self.inspect()
        snapshot = ProjectService(self.root)._snapshot(self.project, info)
        self.assertIn(str(header), {entry["path"] for entry in snapshot})
        header.write_text("#define SHARED 3", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "changed"):
            ProjectService(self.root)._snapshot(self.project, info)

    @unittest.skipUnless(os.name == "nt", "Windows native pipeline")
    def test_changed_compiler_input_rejected_before_output_creation(self):
        info = self.inspect()
        parser = Path(self.config["llvm_root"]) / "bin/LLVM-C.dll"
        parser.write_bytes(b"changed parser fixture")
        output = self.root / ".runs/no-build"
        with patch.object(nb, "run_logged", side_effect=AssertionError("must not execute")):
            with self.assertRaisesRegex(nb.NativeBuildError, "compiler input changed"):
                nb._build_project(info, output, workspace_root=self.root, seed=1729)
        self.assertFalse(output.exists())

    @unittest.skipUnless(os.name == "nt", "Windows native pipeline")
    def test_unrecorded_environment_override_is_rejected(self):
        info = self.inspect()
        with patch.dict(os.environ, {"CL": "/DUNRECORDED=1"}), self.assertRaisesRegex(nb.NativeBuildError, "ambient"):
            nb._build_project(info, self.root / ".runs/no-env-build", workspace_root=self.root, seed=1729)

    def mock_pipeline(self, *, unknown_dependency=False, assembly_rejected=False):
        """Wiring test only: fake nonexecutable artifact bytes and mocked VM gates."""
        info = self.inspect()
        output = self.root / ".runs/mock-build"
        unexpected = self.root / "unapproved.h"
        unexpected.write_text("/* not in approved roots */", encoding="utf-8")

        def runner(argv, cwd, logs, **kwargs):
            argv = list(map(str, argv))
            logs.parent.mkdir(parents=True, exist_ok=True)
            stdout, stderr = logs.with_suffix(".stdout"), logs.with_suffix(".stderr")
            text = ""
            if "-Command" in argv:
                text = json.dumps({"INCLUDE": str(self.sdk), "LIB": str(self.sdk)})
            elif "--version" in argv:
                text = "clang version 22.1.0\n"
            elif "-MF" in argv:
                dependency = unexpected if unknown_dependency else Path(cwd) / argv[-1]
                # Compiler-style escaping; keep drive colon and directory slash.
                escaped = str(dependency).replace("\\", "/").replace(" ", "\\ ")
                Path(argv[argv.index("-MF") + 1]).write_text(cd.DEPENDENCY_TARGET + ": " + escaped + "\n", encoding="utf-8")
            elif "-o" in argv:
                target = Path(argv[argv.index("-o") + 1])
                target.write_bytes(IR.encode() if target.suffix == ".ll" else b"MOCK-NOT-EXECUTABLE")
            stdout.write_text(text, encoding="utf-8")
            stderr.write_text("", encoding="utf-8")
            return {"argv": argv, "returncode": 0, "timed_out": False, "cancelled": False,
                    "stdout": str(stdout), "stderr": str(stderr), "seconds": 0.001,
                    "cleanup": {"method": "windows_job", "status": "assigned_job_empty", "job_assigned": True,
                                "active_after": 0, "parent_exit_confirmed": True, "job_handle_closed": True}}

        def retain(source, target, selected, llvm):
            target.write_text(IR, encoding="utf-8")
            return {"functions": [{"function": name, "added_attributes": ["noinline"]} for name in selected]}

        def diversify(after, runtime, opcodes, directory, seed):
            (directory / "core.diversified.ll").write_text(IR, encoding="utf-8")
            (directory / "runtime.generated.c").write_text("/* mock */", encoding="utf-8")
            (directory / "diversification.json").write_text("{}", encoding="utf-8")
            return {"dispatcher_symbol": "antirea_dispatch_0000000000000001"}

        with contextlib.ExitStack() as stack:
            for obj, attr, value in ((nb, "run_logged", runner), (nb, "_retain_database_scope", retain),
                                     (nb.diversify, "generate", diversify)):
                stack.enter_context(patch.object(obj, attr, side_effect=value))
            for obj, attr, value in ((nb.shutil, "which", "powershell.exe"),
                    (nb, "_vm_evidence", {"core": {"virtualized": True}}),
                    (nb, "_manifest_vm_evidence", {"core": {"virtualized": True}}),
                    (nb, "_runtime_evidence", {"mock_only": True}), (nb, "_layer_evidence", {}),
                    (nb.hardening, "inspect_hardening_artifact", {"mock_only": True})):
                stack.enter_context(patch.object(obj, attr, return_value=value))
            stack.enter_context(patch.object(nb, "_reject_assembly_before_original_codegen",
                side_effect=nb.NativeBuildError("module assembly rejected") if assembly_rejected else None,
                return_value={"status": "no_module_or_function_inline_assembly"}))
            return nb._build_project(info, output, workspace_root=self.root, seed=1729)

    @unittest.skipUnless(os.name == "nt", "Windows native pipeline")
    def test_mock_pipeline_has_three_independent_arms_and_original_cwd(self):
        result = self.mock_pipeline()
        self.assertEqual(result["status"], "artifact_created_unvalidated", result.get("error"))
        self.assertEqual(set(result["artifacts"]), {"original_reference", "baseline", "protected"})
        self.assertEqual(result["functional_evaluation"], "not_performed")
        self.assertFalse(result["original_reference_provenance"]["uses_protection_normalized_ir"])
        for unit in result["original_reference_provenance"]["translation_units"]:
            for key in ("object_command_index", "signature_ir_command_index"):
                command = result["commands"][unit[key]]
                self.assertEqual(command["cwd"], str(self.project_root))
                self.assertIn(unit["source_operand"], command["argv"])
                self.assertIn("-O2", command["argv"])
                self.assertNotIn("-disable-llvm-passes", command["argv"])
                self.assertNotIn("-fno-inline", command["argv"])
            self.assertNotIn("-emit-llvm", result["commands"][unit["object_command_index"]]["argv"])
            self.assertIn("-emit-llvm", result["commands"][unit["signature_ir_command_index"]]["argv"])
        transformed = [c["argv"] for c in result["commands"] if "-kagura-vm" in c["argv"]]
        self.assertEqual(len(transformed), 1)
        self.assertIn(str(Path(result["output_dir"]) / "module.protection-input.ll"), transformed[0])
        self.assertEqual(result["changed_inputs"], [])
        self.assertEqual(Path(result["compilation_database_source"]["path"]).read_bytes(), self.db.read_bytes())
        self.assertEqual(result["compilation_database_source"]["sha256"], result["compilation_database"]["database_sha256"])
        self.assertEqual(len(result["raw_ir_assembly_checks"]), 2)
        sdk_command = result["commands"][0]["argv"][-1]
        self.assertIn("-VsInstallationPath", sdk_command)
        self.assertIn("-VsWherePath", sdk_command)

    @unittest.skipUnless(os.name == "nt", "Windows native pipeline")
    def test_assembly_gate_stops_before_any_original_object_command(self):
        result = self.mock_pipeline(assembly_rejected=True)
        self.assertEqual(result["status"], "failed")
        self.assertIn("module assembly rejected", result["error"])
        self.assertFalse(any(any(str(arg).endswith("original-000.obj") for arg in command["argv"])
                             for command in result["commands"]))

    @unittest.skipUnless(os.name == "nt", "Windows native pipeline")
    def test_environment_selector_change_blocks_before_output(self):
        info = self.inspect()
        output = self.root / ".runs/no-selector-build"
        with patch.dict(os.environ, {"INCLUDE": "changed-order;different-header-root"}), \
                patch.object(nb, "run_logged", side_effect=AssertionError("must not run")), \
                self.assertRaisesRegex(nb.NativeBuildError, "selection environment changed"):
            nb._build_project(info, output, workspace_root=self.root, seed=1729)
        self.assertFalse(output.exists())

    @unittest.skipUnless(os.name == "nt", "Windows native pipeline")
    def test_unknown_consumed_dependency_fails_before_original_compilation(self):
        result = self.mock_pipeline(unknown_dependency=True)
        self.assertEqual(result["status"], "failed")
        self.assertRegex(result["error"], "outside the pinned input closure|omitted its source")
        self.assertNotIn("artifacts", result)


@unittest.skipUnless(os.environ.get("ANTIREA_RUN_COMPILE_DB_E2E") == "1" and os.name == "nt",
                     "explicit opt-in real owned-source compilation/validation")
class ActualCompilationDatabaseTests(unittest.TestCase):
    def exercise(self, optimization, random_cases, *, dialect="gnu"):
        root = Path(__file__).resolve().parents[1]
        if not (root / "antirea").is_dir():
            self.fail("Apply draft into tests/ before running the actual integration test")
        config, _ = nb._toolchain(root)
        source = root / ".runs" / ("compile-db-source-" + dialect + "-" + optimization.lower() + "-" + uuid.uuid4().hex[:12])
        source.mkdir(parents=True, exist_ok=False)
        (source / "include").mkdir()
        (source / "fallback-include").mkdir()
        (source / "include/local.h").write_text("#define HEADER_VALUE 23u\n#define INCLUDE_ORDER_VALUE 101u\n", encoding="utf-8")
        (source / "fallback-include/local.h").write_text("#define HEADER_VALUE 23u\n#define INCLUDE_ORDER_VALUE 202u\n", encoding="utf-8")
        (source / "forced.h").write_text("#define FORCED_VALUE 29u\n", encoding="utf-8")
        optimize_assert = ("#ifndef __OPTIMIZE__\n#error original optimization predefines changed\n#endif\n"
                           if optimization == "O2" else
                           "#ifdef __OPTIMIZE__\n#error original O0 predefines changed\n#endif\n")
        self.assertIn(dialect, {"gnu", "clangcl"})
        cpp_standard = "c++17" if dialect == "clangcl" else "c++20"
        cpp_minimum = "201703L" if dialect == "clangcl" else "202002L"
        if dialect == "clangcl":
            # /MD must affect source preprocessing, not merely appear in a log.
            optimize_assert += "#if !defined(_MT) || !defined(_DLL)\n#error recorded dynamic CRT preprocessing changed\n#endif\n"
        (source / "helper.c").write_text(
            '#include <stdint.h>\n#include "local.h"\n'
            '#if __STDC_VERSION__ != 201112L || TU_VALUE != 7 || FORCED_VALUE != 29 || INCLUDE_ORDER_VALUE != 101\n#error C TU settings changed\n#endif\n'
            + optimize_assert +
            'uint64_t c_helper(uint32_t x, uint32_t y) {\n'
            ' uint64_t v = (uint64_t)x * (TU_VALUE + HEADER_VALUE) + y + sizeof(__FILE__);\n'
            ' for (uint32_t i=0; i<3; ++i) { v = (v ^ (v >> 13)) * 131u + i; }\n'
            ' return v ^ ((uint64_t)y << 9);\n}\n', encoding="utf-8")
        (source / "core.cpp").write_text(
            '#include <cstdint>\n#include "local.h"\n'
            f'#if __cplusplus < {cpp_minimum} || TU_VALUE != 11 || FORCED_VALUE != 29 || INCLUDE_ORDER_VALUE != 202\n#error C++ TU settings changed\n#endif\n'
            + optimize_assert +
            'extern "C" std::uint64_t c_helper(std::uint32_t, std::uint32_t);\n'
            'extern "C" std::uint64_t core(std::uint32_t x, std::uint32_t y) {\n'
            ' auto v = c_helper(x, y);\n'
            ' if ((x ^ y) & 1u) v ^= (std::uint64_t)x << 31; else v += y * 17ull;\n'
            ' return v + TU_VALUE + FORCED_VALUE + HEADER_VALUE + sizeof(__FILE__);\n}\n', encoding="utf-8")
        entries = []
        for filename, driver, standard, macro in (("helper.c", "clang", "c11", 7), ("core.cpp", "clangxx", cpp_standard, 11)):
            includes = ["include", "fallback-include"] if driver == "clang" else ["fallback-include", "include"]
            if dialect == "clangcl":
                compiler = Path(config["clang"]).with_name("clang-cl.exe")
                self.assertTrue(compiler.is_file(), "Pinned distribution must contain clang-cl; no tool fallback")
                args = [str(compiler), "/TC" if driver == "clang" else "/TP", "/std:" + standard,
                        "/MD", "/" + optimization, "/Zc:__cplusplus", "/D", "TU_VALUE=999",
                        "/U", "TU_VALUE", "/D", "TU_VALUE=" + str(macro),
                        "/I", includes[0], "/I", includes[1], "/FI", "forced.h",
                        "/Fo" + filename + ".obj", "-c", "--", filename]
            else:
                args = [config[driver], "-std=" + standard, "-" + optimization,
                        "-DTU_VALUE=999", "-UTU_VALUE", "-DTU_VALUE=" + str(macro),
                        "-I", includes[0], "-I", includes[1], "-include", "forced.h", "-c", filename, "-o", filename + ".obj"]
            entries.append({"directory": str(source), "file": filename, "arguments": args})
        (source / "compile_commands.json").write_text(json.dumps(entries, indent=2), encoding="utf-8")
        policy = {"schema_version": 1, "core_roots": ["core"], "sensitive_functions": ["c_helper"],
                  "public_presentation": {}, "entry_points": ["core"], "max_functions": 16}
        (source / "scope.json").write_text(json.dumps(policy), encoding="utf-8")
        manifest = {"schema_version": 1, "name": "mixed-existing-settings", "language": "cpp",
                    "compile_commands": {"path": "compile_commands.json", "selections": [{"file": "helper.c"}, {"file": "core.cpp"}]},
                    "functions": ["core"], "scope_policy": "scope.json"}
        path = source / "project.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        contract = {"schema_version": 1, "library_name": "protected", "functions": [{"name": "core", "return_type": "u64",
                    "parameters": [{"name": "x", "type": "u32"}, {"name": "y", "type": "u32"}]}]}
        contract_path = source / "contract.json"
        contract_path.write_text(json.dumps(contract), encoding="utf-8")
        service = ProjectService(root)
        plan = service.plan(path, seed=1987)
        self.assertEqual(plan["status"], "planned", plan.get("blockers"))
        result = service.build(plan["plan_id"], plan["fingerprint"])
        self.assertEqual(result["status"], "artifact_created_unvalidated", result.get("error"))
        self.assertEqual(set(result["coverage"]["selected_functions"]), {"core", "c_helper"})
        self.assertTrue(all(item["virtualized"] for item in result["coverage"]["final_vm"].values()))
        self.assertEqual(result["changed_inputs"], [])
        self.assertEqual(result["original_reference_evaluation"], "not_performed")
        if dialect == "clangcl":
            self.assertEqual({unit["driver"] for unit in plan["inspection"]["compilation_database"]["translation_units"]}, {"clangcl"})
            self.assertEqual(len(result["dependency_evidence"]), 2)
            trusted_roots = [Path(row["path"]) for row in result["compilation_database"]["trusted_headers"]["roots"]]
            for row in result["dependency_evidence"]:
                command = result["commands"][row["command_index"]]
                for flag in ("/clang:-M", "/clang:-MF", "/clang:-MT", "/clang:ANTIREA_COMPDB_DEPENDENCIES"):
                    self.assertIn(flag, command["argv"])
                self.assertTrue(any(any(Path(value).is_relative_to(base) for base in trusted_roots) for value in row["files"]),
                                "Actual dependency scan must include a pinned compiler/SDK header")
            raw_commands = [record for record in result["commands"] if "/clang:-disable-llvm-passes" in record["argv"]]
            self.assertEqual(len(raw_commands), 2)
            for record in raw_commands:
                self.assertIn("/clang:-emit-llvm", record["argv"])
                self.assertIn("/MD", record["argv"])
                self.assertIn("/O2", record["argv"])
                self.assertEqual(record["cwd"], str(source))
            for unit in result["original_reference_provenance"]["translation_units"]:
                for kind in ("object", "signature_ir"):
                    record = result["commands"][unit[kind + "_command_index"]]
                    self.assertIn("/MD", record["argv"])
                    self.assertIn("/O2", record["argv"])
                    self.assertIn("/std:c11" if unit["source_operand"] == "helper.c" else "/std:c++17", record["argv"])
                    self.assertNotIn("/clang:-disable-llvm-passes", record["argv"])
                    self.assertEqual("/clang:-emit-llvm" in record["argv"], kind == "signature_ir")
                    self.assertEqual(record["argv"][-2:], ["--", unit["source_operand"]])
                    self.assertTrue(Path(unit[kind + "_path"]).is_file())
        validation = service.validate(plan["plan_id"], contract_path, random_cases=random_cases, timeout_seconds=180)
        self.assertEqual(validation["status"], "functional_samples_passed", validation.get("error"))
        self.assertTrue(validation["original_reference_required"])
        self.assertEqual(set(validation["required_arms"]), {"original_reference", "baseline", "protected"})
        for side in ("baseline", "protected"):
            evidence = validation["functions"]["core"]["original_reference_comparisons"][side]
            self.assertEqual(evidence["matched"], evidence["total"])
            self.assertGreaterEqual(evidence["total"], random_cases)
        if optimization == "O0":
            self.assertTrue(any("optnone" in row["removed_attributes"] for row in result["protection_ir_adjustments"]["functions"]))
        # The immutable build + validation records themselves are retained under
        # the source service job. No claim of arbitrary application linker parity.

    def test_actual_o2_mixed_tus_headers_and_unannotated_helper(self):
        self.exercise("O2", 8192)

    def test_actual_o0_optnone_is_protection_only_adjustment(self):
        self.exercise("O0", 256)

    def test_actual_cl_o2_dependency_ir_object_and_three_arm_comparison(self):
        self.exercise("O2", 256, dialect="clangcl")


if __name__ == "__main__":
    unittest.main()
