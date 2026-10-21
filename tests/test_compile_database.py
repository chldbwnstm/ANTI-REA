"""Parser tests use fake tools; actual preprocessing is explicit opt-in."""
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import uuid

from antirea import compile_database as cd


class WindowsCommandTests(unittest.TestCase):
    def test_crt_quoted_paths_and_literal_macro_quotes(self):
        args = [r"C:\Program Files\LLVM\bin\clang-cl.exe", "/DMSG=\"hello world\"", r"/IC:\owned path\headers", "-c", r"C:\owned path\source.cpp"]
        self.assertEqual(cd.split_windows_command(subprocess.list2cmdline(args)), args)

    def test_backslash_quote_and_empty_roundtrip(self):
        vectors = [["compiler", ""], ["compiler", "ends\\", 'a"b', 'a\\"b', "a b\\"],
                   ["compiler", "space\tword", '"quoted"', "'literal single quotes'"]]
        for args in vectors:
            self.assertEqual(cd.split_windows_command(subprocess.list2cmdline(args)), args)

    def test_bounded_generated_crt_roundtrips(self):
        rng = random.Random(1739)
        for _ in range(300):
            args = ["compiler"] + ["".join(rng.choice('abc \\"') for _ in range(rng.randrange(0, 30))) for _ in range(4)]
            self.assertEqual(cd.split_windows_command(subprocess.list2cmdline(args)), args)

    def test_unbalanced_quotes_and_control_characters_rejected(self):
        for text in ('compiler "unterminated', 'compiler\nfile', 'compiler\x00file', ''):
            with self.subTest(text=text), self.assertRaises(cd.CompilationDatabaseError):
                cd.split_windows_command(text)


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="unit-workspace-")
        self.addCleanup(temporary.cleanup)
        self.workspace = Path(temporary.name)
        self.project = self.workspace / "project"
        self.project.mkdir()
        self.source = self.project / "unit.cpp"
        self.source.write_text("int owned(int x) { return x; }", encoding="utf-8")
        self.includes = self.project / "include"
        self.includes.mkdir()
        self.header = self.includes / "owned.h"
        self.header.write_text("#define OWNED 1", encoding="utf-8")
        self.forced = self.project / "forced.h"
        self.forced.write_text("#define FORCED 1", encoding="utf-8")
        self.build = self.workspace / "existing-build"
        self.build.mkdir()
        self.database = self.build / "compile_commands.json"
        self.tool_dir = self.workspace / "pinned-tools"
        self.tool_dir.mkdir()
        self.tools = {}
        for key, name in (("clang", "clang.exe"), ("clangxx", "clang++.exe"), ("clangcl", "clang-cl.exe")):
            path = self.tool_dir / name
            path.write_bytes(b"fake compiler bytes never executed: " + key.encode())
            self.tools[key] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        self.entry = {"directory": str(self.project), "file": "unit.cpp", "output": str(self.build / "unit.obj"),
                      "arguments": [self.tools["clangxx"]["path"], "-std=c++17", "-O2", "-DNAME=1", "-U", "NAME", "-D", "NAME=2",
                                    "-I", "include", "-include", "forced.h", "-c", "unit.cpp", "-o", str(self.build / "unit.obj")]}
        self.write([self.entry])

    def write(self, entries):
        self.database.write_text(json.dumps(entries), encoding="utf-8")

    def plan(self, **kwargs):
        values = {"workspace_root": self.workspace, "project_root": self.project,
                  "toolchain": self.tools, "selections": [{"file": "unit.cpp"}]}
        values.update(kwargs)
        return cd.normalize_database(self.database, **values)

    def test_normalize_does_not_run_any_process_and_keeps_order(self):
        with patch("subprocess.Popen", side_effect=AssertionError("no process permitted")):
            plan = self.plan()
            action = cd.compile_ir_argv(plan, 0, self.workspace / ".runs/fresh/core.ll")
        unit = plan["translation_units"][0]
        self.assertEqual(unit["frontend_argv"], ["-std=c++17", "-O2", "-D", "NAME=1", "-U", "NAME", "-D", "NAME=2",
                                               "-I", "include", "-include", "forced.h"])
        self.assertEqual(unit["source_operand"], "unit.cpp")
        self.assertEqual(unit["source"], str(self.source))
        self.assertEqual(unit["ordered_options"][-1]["value"], str(self.forced))
        self.assertEqual(action["argv"][0], self.tools["clangxx"]["path"])
        self.assertEqual(action["cwd"], str(self.project))
        self.assertFalse(action["shell"])
        self.assertFalse(action["executed"])
        self.assertFalse(plan["application_linked"])
        self.assertIn("verify_actual_dependency_closure", plan["build_gates"])
        self.assertFalse((self.workspace / ".runs").exists())

    def test_original_object_and_signature_are_independent_from_raw_ir(self):
        plan = self.plan()
        raw = cd.compile_ir_argv(plan, 0, self.workspace / ".runs/fresh/raw.ll")
        original = cd.original_compile_argv(plan, 0, self.workspace / ".runs/fresh/original.obj")
        signature = cd.original_signature_ir_argv(plan, 0, self.workspace / ".runs/fresh/signature.ll")
        self.assertIn("-disable-llvm-passes", raw["argv"])
        self.assertNotIn("-disable-llvm-passes", original["argv"])
        self.assertNotIn("-disable-llvm-passes", signature["argv"])
        self.assertNotIn("-emit-llvm", original["argv"])
        self.assertIn("-emit-llvm", signature["argv"])
        for action in (raw, original, signature):
            self.assertIn("-O2", action["argv"])
            self.assertNotIn("-O0", action["argv"])
            self.assertNotIn("-fno-inline", action["argv"])
            self.assertNotIn("-fno-exceptions", action["argv"])

    def test_recipe_rendering_does_not_rehash_sdk_or_read_files(self):
        plan = self.plan()
        output = self.workspace / ".runs/existing.obj"
        output.parent.mkdir()
        output.write_bytes(b"existing validation artifact")
        with patch.object(cd, "_inventory", side_effect=AssertionError("no full scan")), \
                patch.object(cd, "_trusted_header_inventory", side_effect=AssertionError("no SDK scan")), \
                patch.object(Path, "read_bytes", side_effect=AssertionError("renderer must be pure")):
            rendered = cd.render_compile_argv(plan, 0, output, emit_ir=False)
        self.assertIn(str(output), rendered["argv"])
        self.assertEqual(rendered["cwd"], str(self.project))
        with self.assertRaisesRegex(cd.CompilationDatabaseError, "fresh"):
            cd.original_compile_argv(plan, 0, output)

    def test_builder_recipe_and_historical_renderer_are_identical(self):
        plan = self.plan()
        with patch.object(cd, "verify_snapshot", side_effect=AssertionError("caller owns full trust boundaries")):
            for index, (helper, emit_ir, preoptimization) in enumerate((
                    (cd.original_compile_argv, False, False), (cd.original_signature_ir_argv, True, False),
                    (cd.compile_ir_argv, True, True))):
                target = self.workspace / f".runs/recipe-{index}.out"
                self.assertEqual(helper(plan, 0, target), cd.render_compile_argv(
                    plan, 0, target, emit_ir=emit_ir, preoptimization=preoptimization))

    def test_recorded_recipe_replay_uses_private_db_bytes_not_changed_current_db(self):
        plan, original = self.plan(), self.database.read_bytes()
        self.database.write_bytes(b"current database changed after historical build")
        with patch.object(cd, "_trusted_header_inventory", side_effect=AssertionError("no SDK scan")), \
                patch.object(Path, "read_bytes", side_effect=AssertionError("use supplied private bytes")):
            cd.verify_recorded_plan(plan, database_bytes=original)
        with self.assertRaisesRegex(cd.CompilationDatabaseError, "bytes differ"):
            cd.verify_recorded_plan(plan)

    def test_recorded_recipe_replay_rejects_resigned_frontend_mismatch(self):
        plan, original = self.plan(), self.database.read_bytes()
        plan["translation_units"][0]["frontend_argv"].append("-DUNRECORDED=1")
        plan["fingerprint"] = cd._sha(cd._encoded({key: value for key, value in plan.items() if key != "fingerprint"}))
        with self.assertRaisesRegex(cd.CompilationDatabaseError, "differs from original entry"):
            cd.verify_recorded_plan(plan, database_bytes=original)

    def test_full_snapshot_still_detects_added_shadow_header_after_recipe_generation(self):
        plan = self.plan()
        (self.includes / "new-shadow.h").write_text("// changes header selection", encoding="utf-8")
        # Recipe generation is deliberately not a current-content validation.
        cd.original_compile_argv(plan, 0, self.workspace / ".runs/planned.obj")
        with self.assertRaisesRegex(cd.CompilationDatabaseError, "snapshot changed"):
            cd.verify_snapshot(plan)

    def test_full_snapshot_can_return_same_verified_sdk_inventory(self):
        plan = self.plan(trusted_header_roots=[self.includes])
        expected = cd.trusted_header_inventory(plan)
        with patch.object(cd, "_trusted_header_inventory", wraps=cd._trusted_header_inventory) as scanner:
            actual = cd.verify_snapshot(plan, return_trusted_inventory=True)
        self.assertEqual(actual, expected)
        self.assertEqual(scanner.call_count, 1)

    def test_windows_command_only_equals_arguments_form(self):
        arguments_plan = self.plan()
        command_entry = dict(self.entry)
        command_entry["command"] = subprocess.list2cmdline(command_entry.pop("arguments"))
        self.write([command_entry])
        command_plan = self.plan()
        self.assertEqual(command_plan["translation_units"][0]["frontend_argv"], arguments_plan["translation_units"][0]["frontend_argv"])

    def test_both_command_and_arguments_must_agree_exactly(self):
        self.entry["command"] = subprocess.list2cmdline(self.entry["arguments"])
        self.write([self.entry])
        self.plan()
        self.entry["command"] += " -DBAD=1"
        self.write([self.entry])
        with self.assertRaisesRegex(cd.CompilationDatabaseError, "disagree"):
            self.plan()

    def test_actual_cmake_ninja_clang_cl_shape_preserved(self):
        # Mirrors the local Kagura CMake/Ninja syntax, not its sources or build.
        self.entry.pop("arguments")
        argv = [self.tools["clangcl"]["path"], "/nologo", "-TP", "-DNOMINMAX", "-D_HAS_EXCEPTIONS=0", "-I" + str(self.includes),
                "/DWIN32", "/D_WINDOWS", "/EHsc", "/O2", "/Ob2", "/DNDEBUG", "-std:c++17", "-MT", "/utf-8", "/W3", "/WX-",
                "/EHsc", "/Zc:__cplusplus", "/wd4624", "/wd4244", "/EHs-c-", "/GR-",
                "/Fo" + str(self.build / "unit.obj"), "/Fd" + str(self.build / "target.pdb"), "-c", "--", str(self.source)]
        self.entry["command"] = subprocess.list2cmdline(argv)
        self.write([self.entry])
        plan = self.plan()
        unit = plan["translation_units"][0]
        self.assertEqual(unit["driver"], "clangcl")
        self.assertIn("/MT", unit["frontend_argv"])
        self.assertEqual(unit["frontend_argv"].count("/EHsc"), 2)
        self.assertLess(unit["frontend_argv"].index("/EHsc"), unit["frontend_argv"].index("/EHs-c-"))
        self.assertIn("/GR-", unit["frontend_argv"])
        self.assertIn("/std:c++17", unit["frontend_argv"])
        self.assertNotIn("/nologo", unit["frontend_argv"])
        action = cd.compile_ir_argv(plan, 0, self.workspace / ".runs/ir.ll")
        self.assertIn("/clang:-disable-llvm-passes", action["argv"])
        self.assertEqual(action["argv"][-2:], ["--", str(self.source)])
        original = cd.original_compile_argv(plan, 0, self.workspace / ".runs/original.obj")
        self.assertNotIn("/clang:-disable-llvm-passes", original["argv"])
        self.assertNotIn("/clang:-emit-llvm", original["argv"])

    def test_forced_include_cl_profile_and_macro_spaces(self):
        self.entry["arguments"] = [self.tools["clangcl"]["path"], "/TP", '/DMSG="hello world"', "/FIforced.h", "/Iinclude", "-c", "unit.cpp"]
        self.entry.pop("output")
        self.write([self.entry])
        args = self.plan()["translation_units"][0]["frontend_argv"]
        self.assertEqual(args, ["/TP", "/D", 'MSG="hello world"', "/FI", "forced.h", "/I", "include"])

    def test_directory_and_all_explicit_path_inputs_are_preserved(self):
        self.entry.update(directory=str(self.build), file="../project/unit.cpp")
        self.entry["arguments"] = [self.tools["clangxx"]["path"], "-I", "../project/include", "-include", "../project/forced.h", "-c", "../project/unit.cpp"]
        self.write([self.entry])
        plan = self.plan()
        action = cd.compile_ir_argv(plan, 0, self.workspace / ".runs/new.ll")
        self.assertEqual(action["cwd"], str(self.build))
        self.assertIn("../project/include", action["argv"])
        self.assertIn("../project/forced.h", action["argv"])
        self.assertIn("../project/unit.cpp", action["argv"])
        self.assertEqual(plan["translation_units"][0]["ordered_options"][0]["value"], str(self.includes))

    def test_lexical_source_and_header_spelling_survives_every_action(self):
        # Canonical ownership paths must not replace compiler operands: the
        # latter influence __FILE__, __BASE_FILE__ and sizeof their strings.
        for driver, prefix in (("clangxx", ["-I", "./include", "-include", "./forced.h"]),
                               ("clangcl", ["/I./include", "/FI./forced.h"])):
            with self.subTest(driver=driver):
                self.entry["arguments"] = [self.tools[driver]["path"], *prefix, "-c", "--", "./unit.cpp"]
                self.write([self.entry])
                plan = self.plan()
                unit = plan["translation_units"][0]
                self.assertEqual(unit["source"], str(self.source))
                self.assertEqual(unit["source_operand"], "./unit.cpp")
                self.assertEqual([o["lexical_value"] for o in unit["ordered_options"]], ["./include", "./forced.h"])
                self.assertEqual([o["value"] for o in unit["ordered_options"]], [str(self.includes), str(self.forced)])
                actions = (cd.compile_ir_argv, cd.original_compile_argv,
                           cd.original_signature_ir_argv, cd.dependency_scan_argv)
                for index, helper in enumerate(actions):
                    action = helper(plan, 0, self.workspace / f".runs/lexical-{driver}-{index}.out")
                    self.assertEqual(action["cwd"], str(self.project))
                    for lexical in ("./unit.cpp", "./include", "./forced.h"):
                        self.assertIn(lexical, action["argv"])
                    self.assertNotIn(str(self.source), action["argv"])
                    self.assertNotIn(str(self.includes), action["argv"])
                    self.assertNotIn(str(self.forced), action["argv"])

    def test_relative_database_directory_is_resolved_from_database_location(self):
        self.entry["directory"] = "../project"
        self.write([self.entry])
        self.assertEqual(self.plan()["translation_units"][0]["directory"], str(self.project))

    def test_dash_prefixed_source_remains_an_operand_not_a_compiler_option(self):
        source = self.project / "-unit.cpp"
        source.write_text("int owned(void) { return 1; }", encoding="utf-8")
        self.write([{"directory": str(self.project), "file": "-unit.cpp",
                     "arguments": [self.tools["clangxx"]["path"], "-c", "--", "-unit.cpp"]}])
        plan = self.plan(selections=[{"file": "-unit.cpp"}])
        for index, helper in enumerate((cd.compile_ir_argv, cd.original_compile_argv,
                                        cd.original_signature_ir_argv, cd.dependency_scan_argv)):
            action = helper(plan, 0, self.workspace / f".runs/dash-{index}.out")
            self.assertEqual(action["argv"][-2:], ["--", "-unit.cpp"])

    def test_per_tu_macro_order_does_not_collapse_into_global_dict(self):
        second = self.project / "second.c"
        second.write_text("int second(void) { return 0; }", encoding="utf-8")
        entry = {"directory": str(self.project), "file": "second.c", "arguments": [self.tools["clang"]["path"], "-std=c11", "-DNAME=9", "-c", "second.c"]}
        self.write([self.entry, entry])
        units = self.plan(selections=[{"file": "unit.cpp"}, {"file": "second.c"}])["translation_units"]
        self.assertIn("NAME=2", units[0]["frontend_argv"])
        self.assertNotIn("NAME=2", units[1]["frontend_argv"])
        self.assertEqual([u["language"] for u in units], ["cpp", "c"])

    def test_clangxx_c_suffix_still_uses_cpp_driver_semantics(self):
        source = self.project / "file.c"
        source.write_text("int f(void) { return 1; }", encoding="utf-8")
        self.write([{"directory": str(self.project), "file": "file.c", "arguments": [self.tools["clangxx"]["path"], "-c", "file.c"]}])
        self.assertEqual(self.plan(selections=[{"file": "file.c"}])["translation_units"][0]["language"], "cpp")

    def test_explicit_language_override(self):
        self.entry["arguments"][1:1] = ["-x", "c"]
        self.write([self.entry])
        self.assertEqual(self.plan()["translation_units"][0]["language"], "c")

    def test_multiple_configuration_requires_exact_entry_digest(self):
        other = copy.deepcopy(self.entry)
        other["arguments"][3] = "-DNAME=999"
        self.write([self.entry, other])
        with self.assertRaisesRegex(cd.CompilationDatabaseError, "ambiguous"):
            self.plan()
        digest = cd._sha(cd._encoded(other))
        plan = self.plan(selections=[{"file": "unit.cpp", "entry_sha256": digest}])
        self.assertEqual(plan["translation_units"][0]["entry_sha256"], digest)
        self.assertIn("NAME=999", plan["translation_units"][0]["frontend_argv"])

    def test_duplicate_selection_and_missing_configuration_fail(self):
        for selections in ([{"file": "unit.cpp"}, {"file": "unit.cpp"}], [{"file": "unit.cpp", "entry_sha256": "0"*64}]):
            with self.subTest(selections=selections), self.assertRaises(cd.CompilationDatabaseError):
                self.plan(selections=selections)

    def test_wrappers_other_compilers_shell_and_response_files_rejected(self):
        variants = [["cmd.exe", "/c", *self.entry["arguments"]], ["ccache", *self.entry["arguments"]],
                    ["cl.exe", *self.entry["arguments"][1:]], [self.tools["clangxx"]["path"], "@args.rsp"],
                    [*self.entry["arguments"], "&&", "anything"]]
        for argv in variants:
            with self.subTest(argv=argv):
                entry = dict(self.entry, arguments=argv)
                self.write([entry])
                with self.assertRaises(cd.CompilationDatabaseError):
                    self.plan()

    def test_plugins_passthrough_linkers_unknown_semantics_fail_closed(self):
        for flag in ("-Xclang", "-fplugin=owned.dll", "-fpass-plugin=owned.dll", "--config=owned.cfg", "-Wl,--thing",
                     "-Wp,-DTHING", "-march=native", "-pthread", "-funknown-option", "/link", "/RTC1", "/Yuowned.pch"):
            with self.subTest(flag=flag):
                entry = copy.deepcopy(self.entry)
                entry["arguments"].insert(1, flag)
                self.write([entry])
                with self.assertRaises(cd.CompilationDatabaseError):
                    self.plan()

    def test_different_compiler_path_is_not_silently_replaced(self):
        different = self.workspace / "other/clang++.exe"
        different.parent.mkdir()
        different.write_bytes(b"different tool")
        self.entry["arguments"][0] = str(different)
        self.write([self.entry])
        with self.assertRaisesRegex(cd.CompilationDatabaseError, "different compiler"):
            self.plan()

    def test_unknown_or_nonmatching_target_fails(self):
        for flag in ("--target=aarch64-apple-darwin", "-std=c++unknown"):
            entry = copy.deepcopy(self.entry)
            entry["arguments"].insert(1, flag)
            self.write([entry])
            with self.assertRaises(cd.CompilationDatabaseError):
                self.plan()

    def test_source_or_include_outside_roots_is_not_accepted_without_pin(self):
        generated = self.workspace / "generated"
        generated.mkdir()
        (generated / "generated.h").write_text("#define GENERATED 1", encoding="utf-8")
        self.entry["arguments"][1:1] = ["-I", str(generated)]
        self.write([self.entry])
        with self.assertRaisesRegex(cd.CompilationDatabaseError, "outside approved"):
            self.plan()
        plan = self.plan(extra_input_roots=[generated])
        self.assertIn(str(generated / "generated.h"), {row["path"] for row in plan["inputs"]["files"]})

    def test_forced_include_does_not_guess_search_path_resolution(self):
        (self.includes / "only-in-include.h").write_text("// header", encoding="utf-8")
        self.entry["arguments"][self.entry["arguments"].index("forced.h")] = "only-in-include.h"
        self.write([self.entry])
        with self.assertRaisesRegex(cd.CompilationDatabaseError, "Missing input"):
            self.plan()

    def test_header_source_database_scope_changes_invalidate_snapshot(self):
        scope = self.project / "policy.json"
        scope.write_text('{"core_roots":["owned"]}', encoding="utf-8")
        for path in (self.source, self.header, self.database, scope):
            with self.subTest(path=path):
                plan = self.plan(scope_policy=scope)
                original = path.read_bytes()
                path.write_bytes(original + b" ")
                with self.assertRaisesRegex(cd.CompilationDatabaseError, "snapshot changed"):
                    cd.verify_snapshot(plan)
                path.write_bytes(original)

    def test_new_earlier_search_header_is_caught_by_root_inventory(self):
        plan = self.plan()
        (self.includes / "new.h").write_text("// can change __has_include", encoding="utf-8")
        with self.assertRaisesRegex(cd.CompilationDatabaseError, "snapshot changed"):
            cd.verify_snapshot(plan)

    def test_tool_change_invalidates_plan(self):
        plan = self.plan()
        Path(self.tools["clangxx"]["path"]).write_bytes(b"changed pinned tool")
        with self.assertRaisesRegex(cd.CompilationDatabaseError, "Pinned driver changed"):
            cd.verify_snapshot(plan)

    def test_adapter_change_invalidates_plan(self):
        adapter = self.workspace / "adapter-copy.py"
        adapter.write_bytes(b"owned implementation snapshot")
        with patch.object(cd, "__file__", str(adapter)):
            plan = self.plan()
        adapter.write_bytes(b"changed implementation snapshot")
        with self.assertRaisesRegex(cd.CompilationDatabaseError, "implementation changed"):
            cd.verify_snapshot(plan)

    def test_plan_tampering_cannot_change_command(self):
        plan = self.plan()
        plan["translation_units"][0]["frontend_argv"].append("-DCHANGED=1")
        with self.assertRaisesRegex(cd.CompilationDatabaseError, "fingerprint changed"):
            cd.compile_ir_argv(plan, 0, self.workspace / ".runs/new.ll")

    def test_output_is_fresh_private_and_never_original_output(self):
        plan = self.plan()
        existing = self.workspace / ".runs/existing.ll"
        existing.parent.mkdir()
        existing.write_text("keep", encoding="utf-8")
        for path in (existing, self.source, self.build / "unit.obj", self.workspace.parent / "outside.ll"):
            with self.subTest(path=path), self.assertRaises(cd.CompilationDatabaseError):
                cd.compile_ir_argv(plan, 0, path)
        self.assertEqual(existing.read_text(), "keep")

    def test_conflicting_output_duplicate_source_and_wrong_action_rejected(self):
        variants = [dict(self.entry, output=str(self.build / "different.obj")),
                    dict(self.entry, arguments=[*self.entry["arguments"], "unit.cpp"]),
                    dict(self.entry, arguments=[x for x in self.entry["arguments"] if x != "-c"])]
        for entry in variants:
            self.write([entry])
            with self.assertRaises(cd.CompilationDatabaseError):
                self.plan()

    def test_semantic_flags_after_source_are_rejected_not_moved(self):
        self.entry["arguments"].extend(["-x", "c"])
        self.write([self.entry])
        with self.assertRaisesRegex(cd.CompilationDatabaseError, "after source"):
            self.plan()

    def test_malformed_database_schema_is_rejected(self):
        for value in ({}, [], None, [None], [dict(self.entry, arguments=None)], [dict(self.entry, directory=None)],
                      [dict(self.entry, unexpected="setting")]):
            self.database.write_text(json.dumps(value), encoding="utf-8")
            with self.subTest(value=value), self.assertRaises(cd.CompilationDatabaseError):
                self.plan()

    def test_duplicate_json_and_database_size_are_bounded(self):
        self.database.write_text('[{"file":"a","file":"b"}]', encoding="utf-8")
        with self.assertRaises(cd.CompilationDatabaseError):
            self.plan()
        self.write([self.entry])
        with patch.object(cd, "MAX_DATABASE_BYTES", 3), self.assertRaises(cd.CompilationDatabaseError):
            self.plan()

    def test_database_change_during_normalization_is_rejected(self):
        inventory = cd._inventory
        changed = False
        def mutate_before_snapshot(*args, **kwargs):
            nonlocal changed
            if not changed:
                changed = True
                self.database.write_text(self.database.read_text() + " ", encoding="utf-8")
            return inventory(*args, **kwargs)
        with patch.object(cd, "_inventory", side_effect=mutate_before_snapshot):
            with self.assertRaisesRegex(cd.CompilationDatabaseError, "database content"):
                self.plan()

    def test_nonfinite_json_is_rejected_even_in_unselected_entries(self):
        self.database.write_text(json.dumps([self.entry])[:-1] + ', {"extra": NaN}]', encoding="utf-8")
        with self.assertRaises(cd.CompilationDatabaseError):
            self.plan()

    def test_snapshot_size_is_bounded(self):
        with patch.object(cd, "MAX_INPUT_BYTES", 2), self.assertRaises(cd.CompilationDatabaseError):
            self.plan()
        with patch.object(cd, "MAX_FILES", 1), self.assertRaises(cd.CompilationDatabaseError):
            self.plan()

    def test_network_and_drive_relative_paths_rejected_before_io(self):
        for value in (r"\\server\share\input", r"\\?\C:\owned\input", "C:relative"):
            with self.subTest(value=value), self.assertRaisesRegex(cd.CompilationDatabaseError, "Network/device/drive-relative"):
                cd._path(value, self.workspace, exists=False)

    def test_trusted_header_roots_are_compactly_pinned_not_manifest_exceptions(self):
        sdk_temp = tempfile.TemporaryDirectory(prefix="trusted-sdk-")
        self.addCleanup(sdk_temp.cleanup)
        sdk = Path(sdk_temp.name)
        header = sdk / "standard.h"
        header.write_text("// owned SDK stand-in, not a real installation", encoding="utf-8")
        self.entry["arguments"][1:1] = ["-isystem", str(sdk)]
        self.write([self.entry])
        with self.assertRaises(cd.CompilationDatabaseError):
            self.plan()
        with self.assertRaises(cd.CompilationDatabaseError):
            self.plan(extra_input_roots=[sdk])
        plan = self.plan(trusted_header_roots=[sdk])
        summary = plan["trusted_headers"]["roots"][0]
        self.assertEqual(summary["path"], str(sdk))
        self.assertEqual(summary["files"], 1)
        self.assertNotIn("files", plan["trusted_headers"])
        self.assertEqual(cd.trusted_header_inventory(plan)["files"][0]["path"], str(header))
        header.write_text("// changed SDK header", encoding="utf-8")
        with self.assertRaisesRegex(cd.CompilationDatabaseError, "Trusted header inventory changed"):
            cd.verify_snapshot(plan)

    def test_trusted_header_addition_changes_compact_inventory(self):
        plan = self.plan(trusted_header_roots=[self.includes])
        (self.includes / "new-standard.h").write_text("// header", encoding="utf-8")
        with self.assertRaisesRegex(cd.CompilationDatabaseError, "Trusted header inventory changed"):
            cd.trusted_header_inventory(plan)

    def test_dependency_scan_uses_fixed_target_and_original_configuration(self):
        plan = self.plan()
        action = cd.dependency_scan_argv(plan, 0, self.workspace / ".runs/fresh/deps.d")
        self.assertIn("-M", action["argv"])
        self.assertIn("-MF", action["argv"])
        self.assertIn(cd.DEPENDENCY_TARGET, action["argv"])
        self.assertIn("-O2", action["argv"])
        self.assertNotIn("-disable-llvm-passes", action["argv"])
        self.assertFalse(action["executed"])
        self.entry["arguments"] = [self.tools["clangcl"]["path"], "/TP", "/O2", "-c", "unit.cpp"]
        self.write([self.entry])
        action = cd.dependency_scan_argv(self.plan(), 0, self.workspace / ".runs/fresh/cl-deps.d")
        self.assertIn("/clang:-M", action["argv"])
        self.assertIn("/clang:" + cd.DEPENDENCY_TARGET, action["argv"])
        self.assertEqual(action["cwd"], str(self.project))

    def test_dependency_parser_handles_continuations_escaped_paths_and_fixed_target(self):
        special = self.includes / "space # dollar$.h"
        special.write_text("// header", encoding="utf-8")
        escaped = str(special).replace("\\", "/").replace(" ", "\\ ").replace("#", "\\#").replace("$", "$$")
        dep = self.build / "dependency.d"
        dep.write_text(cd.DEPENDENCY_TARGET + ": unit.cpp " + "\\" + "\n  " + escaped + " unit.cpp\n", encoding="utf-8")
        self.assertEqual(cd.parse_dependencies(dep, self.project), [self.source, special])

    def test_dependency_parser_handles_drive_colons_and_backslashes(self):
        dep = self.build / "dependency.d"
        source = str(self.source).replace(":", "\\:")
        dep.write_text(cd.DEPENDENCY_TARGET + ": " + source, encoding="utf-8")
        self.assertEqual(cd.parse_dependencies(dep, self.project), [self.source])

    def test_dependency_parser_never_evaluates_variables_or_extra_rules(self):
        dep = self.build / "dependency.d"
        bad = ["other: unit.cpp", cd.DEPENDENCY_TARGET + ": $(shell command)",
               cd.DEPENDENCY_TARGET + ": ${HOME}", cd.DEPENDENCY_TARGET + ": unit.cpp # comment",
               cd.DEPENDENCY_TARGET + ": unit.cpp\nsecond: unit.cpp", cd.DEPENDENCY_TARGET + ": missing.h",
               cd.DEPENDENCY_TARGET + ":", cd.DEPENDENCY_TARGET + ": unit.cpp\\"]
        for text in bad:
            dep.write_text(text, encoding="utf-8")
            with self.subTest(text=text), self.assertRaises(cd.CompilationDatabaseError):
                cd.parse_dependencies(dep, self.project)

    def test_dependency_parser_returns_paths_but_does_not_claim_approved_closure(self):
        outside = self.workspace / "not-approved.h"
        outside.write_text("// not in any input snapshot", encoding="utf-8")
        dep = self.build / "dependency.d"
        dep.write_text(cd.DEPENDENCY_TARGET + ": " + str(outside), encoding="utf-8")
        paths = cd.parse_dependencies(dep, self.project)
        plan = self.plan()
        approved = {row["path"] for row in plan["inputs"]["files"]}
        self.assertEqual(paths, [outside])
        self.assertNotIn(str(paths[0]), approved)


@unittest.skipUnless(os.environ.get("ANTIREA_RUN_COMPDB_PREPROCESSOR_TESTS") == "1",
                     "Actual pinned-driver preprocessing requires explicit approval/opt-in")
class ActualPreprocessorPathTests(unittest.TestCase):
    """Authored owned fixture only; never run raw DB command or build hooks.

    Compare independently authored lexical arguments against normalized/raw-IR
    frontend arguments, with a negative canonicalization control. This gate is
    narrower than compilation or general functional-equivalence validation.
    """
    def _parity(self, driver):
        from antirea.process import run_logged

        repo = next((p for p in Path(__file__).resolve().parents
                     if (p / ".tools/kagura-toolchain.json").is_file()), None)
        self.assertIsNotNone(repo, "Pinned local toolchain manifest is required")
        config = json.loads((repo / ".tools/kagura-toolchain.json").read_text(encoding="utf-8-sig"))
        compiler = Path(config["clangxx"]) if driver == "clangxx" else Path(config["clang"]).with_name("clang-cl.exe")
        self.assertTrue(compiler.is_file())
        pin = {"path": str(compiler), "sha256": hashlib.sha256(compiler.read_bytes()).hexdigest()}
        # Preserve private compiler outputs/provenance after the test. Unlike
        # ordinary parser fixtures, this evidence must not disappear at cleanup.
        identity = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:10]
        workspace = repo / ".runs" / ("compile-db-preprocessor-" + driver + "-" + identity)
        workspace.mkdir(parents=True, exist_ok=False)
        stop = repo / ".runs/defense-loop/STOP"
        self.assertFalse(stop.exists(), "STOP prevents compiler preprocessing")
        project = workspace / "project"
        (project / "src").mkdir(parents=True)
        (project / "include").mkdir()
        (project / "forced.h").write_text('const char *forced_file = __FILE__;\nconst char *forced_base = __BASE_FILE__;\n', encoding="utf-8")
        (project / "include/owned.h").write_text('const char *header_file = __FILE__;\nconst char *header_base = __BASE_FILE__;\n', encoding="utf-8")
        (project / "src/source.cpp").write_text('#include "owned.h"\nconst char *source_file = __FILE__;\nconst char *source_base = __BASE_FILE__;\nconstexpr auto file_size = sizeof(__FILE__);\nconstexpr auto base_size = sizeof(__BASE_FILE__);\n#ifdef __OPTIMIZE__\nint optimized = 1;\n#else\nint optimized = 0;\n#endif\n', encoding="utf-8")
        source_operand = "./src/source.cpp"
        if driver == "clangxx":
            settings = ["-std=c++17", "-O2", "-I", "./include", "-include", "./forced.h"]
            preprocess, raw_request = ["-E", "-P"], ["-Xclang", "-disable-llvm-passes"]
            canonical_settings = ["-std=c++17", "-O2", "-I", str(project / "include"), "-include", str(project / "forced.h")]
        else:
            settings = ["/TP", "/std:c++17", "/O2", "/I./include", "/FI./forced.h"]
            preprocess, raw_request = ["/E", "/clang:-P"], ["/clang:-Xclang", "/clang:-disable-llvm-passes"]
            canonical_settings = ["/TP", "/std:c++17", "/O2", "/I", str(project / "include"), "/FI", str(project / "forced.h")]
        database = workspace / "compile_commands.json"
        database.write_text(json.dumps([{"directory": str(project), "file": source_operand,
                                        "arguments": [str(compiler), *settings, "-c", "--", source_operand]}]), encoding="utf-8")
        plan = cd.normalize_database(database, workspace_root=workspace, project_root=project,
                                     toolchain={driver: pin}, selections=[{"file": "src/source.cpp"}])
        unit = plan["translation_units"][0]
        (workspace / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
        # These are authored compiler-only invocations, not entry['command'].
        commands = {
            "original": [str(compiler), *settings, *preprocess, "--", source_operand],
            "normalized": [str(compiler), *unit["frontend_argv"], *preprocess, "--", unit["source_operand"]],
            "raw_request": [str(compiler), *unit["frontend_argv"], *raw_request, *preprocess, "--", unit["source_operand"]],
            "old_absolute_control": [str(compiler), *canonical_settings, *preprocess, "--", unit["source"]],
        }
        outputs, processes = {}, {}
        for name, argv in commands.items():
            cd.verify_snapshot(plan)
            result = run_logged(argv, project, workspace / ".runs" / name, timeout=30, cancel_file=stop)
            processes[name] = result
            self.assertEqual(result["returncode"], 0, result)
            self.assertFalse(result["timed_out"])
            self.assertFalse(result["cancelled"])
            self.assertTrue(result["cleanup"]["parent_exit_confirmed"])
            self.assertEqual(result["cleanup"]["method"], "windows_job", result)
            self.assertEqual(result["cleanup"]["status"], "assigned_job_empty", result)
            self.assertEqual(result["cleanup"]["active_after"], 0, result)
            self.assertTrue(result["cleanup"]["job_handle_closed"], result)
            outputs[name] = Path(result["stdout"]).read_text(encoding="utf-8")
        self.assertIn("source_file", outputs["original"])
        self.assertIn("forced_file", outputs["original"])
        self.assertIn("header_file", outputs["original"])
        self.assertEqual(outputs["original"], outputs["normalized"])
        self.assertEqual(outputs["original"], outputs["raw_request"])
        self.assertNotEqual(outputs["original"], outputs["old_absolute_control"])
        cd.verify_snapshot(plan)
        self.assertFalse(stop.exists(), "STOP appeared during preprocessing validation")
        evidence = {"status": "preprocessor_path_parity_passed", "driver": driver,
                    "compiler": pin, "plan_fingerprint": plan["fingerprint"],
                    "normalized_matches_original": True, "raw_request_matches_original": True,
                    "absolute_path_negative_control_differs": True,
                    "processes": processes, "target_application_executed": False,
                    "limitations": ["Owned path-macro fixture only; not general source compatibility.",
                                    "Windows job accounting cannot exclude children escaping before assignment."]}
        (workspace / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        print("COMPDB_PREPROCESSOR_EVIDENCE=" + str(workspace / "evidence.json"))

    def test_clangxx_preprocessed_path_macro_parity(self):
        self._parity("clangxx")

    def test_clangcl_preprocessed_path_macro_parity(self):
        self._parity("clangcl")


@unittest.skipUnless(os.name == "nt" and os.environ.get("ANTIREA_RUN_COMPDB_PREPROCESSOR_TESTS") == "1",
                     "explicit opt-in pinned compiler IR/object output checks; no target execution")
class ActualCompilerOutputTests(unittest.TestCase):
    def test_clangcl_outputs_are_private_and_source_inventory_is_unchanged(self):
        from antirea.process import run_logged

        repo = Path(__file__).resolve().parents[1]
        config = json.loads((repo / ".tools/kagura-toolchain.json").read_text(encoding="utf-8-sig"))
        compiler = Path(config["clang"]).with_name("clang-cl.exe")
        pin = {"path": str(compiler), "sha256": hashlib.sha256(compiler.read_bytes()).hexdigest()}
        identity = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:10]
        workspace = repo / ".runs" / ("compile-db-clangcl-outputs-" + identity)
        project = workspace / "project"
        project.mkdir(parents=True, exist_ok=False)
        source = project / "owned.c"
        source.write_text("unsigned core(unsigned x) { return (x ^ 19u) * 31u; }\n", encoding="utf-8")
        database = workspace / "compile_commands.json"
        database.write_text(json.dumps([{"directory": str(project), "file": "./owned.c",
            "arguments": [str(compiler), "/TC", "/std:c11", "/MD", "/O2", "-c", "--", "./owned.c"]}]), encoding="utf-8")
        plan = cd.normalize_database(database, workspace_root=workspace, project_root=project,
                                     toolchain={"clangcl": pin}, selections=[{"file": "owned.c"}])
        stop = repo / ".runs/defense-loop/STOP"
        evidence = {"compiler": pin, "plan_fingerprint": plan["fingerprint"], "target_executed": False, "cases": {}}
        try:
            for name, helper, suffix in (("raw_ir", cd.compile_ir_argv, ".ll"),
                    ("signature_ir", cd.original_signature_ir_argv, ".ll"),
                    ("original_object", cd.original_compile_argv, ".obj")):
                self.assertFalse(stop.exists())
                target = workspace / ".runs" / (name + suffix)
                target.parent.mkdir(exist_ok=True)
                action = helper(plan, 0, target)
                process = run_logged(action["argv"], action["cwd"], workspace / ".runs" / (name + "-command"),
                                     timeout=30, cancel_file=stop)
                row = {"process": process, "expected_output": str(target),
                       "expected_output_exists": target.is_file(),
                       "source_files_after": sorted(p.name for p in project.iterdir())}
                evidence["cases"][name] = row
                self.assertEqual(process["returncode"], 0, process)
                self.assertFalse(process["timed_out"] or process["cancelled"])
                self.assertTrue(process["cleanup"]["parent_exit_confirmed"])
                self.assertEqual(process["cleanup"]["status"], "assigned_job_empty")
                self.assertEqual(process["cleanup"]["active_after"], 0)
                self.assertTrue(process["cleanup"]["job_handle_closed"])
                self.assertTrue(target.is_file(), "Compiler exit 0 did not produce the requested private output")
                self.assertEqual(row["source_files_after"], ["owned.c"], "Compiler wrote into source input tree")
                row["output_sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
                self.assertGreater(target.stat().st_size, 0)
                if suffix == ".ll":
                    self.assertIn("@core(", target.read_text(encoding="utf-8"))
                cd.verify_snapshot(plan)
            evidence["status"] = "all_requested_outputs_private_inputs_unchanged"
        finally:
            (workspace / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
            print("COMPDB_COMPILER_OUTPUT_EVIDENCE=" + str(workspace / "evidence.json"))


if __name__ == "__main__":
    unittest.main()
