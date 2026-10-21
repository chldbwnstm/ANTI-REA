"""Fixed recipe/state equivalence checks. All process calls are mocked.

Apply with the companion native_build integration before running. These tests
do not establish real compiler byte equivalence, Rust ABI support or linking.
"""
import contextlib
from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from antirea import native_build as nb
from antirea import native_objects as no


class NativeObjectPipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="object-pipeline-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.out = self.root / ".runs/build"
        self.out.mkdir(parents=True)
        self.source, self.protection = self.out / "module.before.ll", self.out / "module.protection-input.ll"
        self.source.write_text("; unprotected original input\n", encoding="utf-8")
        self.protection.write_text("; separately prepared protection input\n", encoding="utf-8")
        self.config, self.pins = {}, {}
        for role in ("clang", "clangxx", "optimizer", "llvm_link", "runtime_source", "opcode_source"):
            path = self.root / (role + ".inert")
            path.write_bytes(("INERT: " + role).encode())
            self.config[role] = str(path)
            self.pins[str(path)] = nb._hash(path)
        for module in (no, nb, nb.diversify, nb.hardening):
            path = Path(module.__file__).resolve()
            self.pins[str(path)] = nb._hash(path)
        self.commands, self.events = [], []
        self.environment = {"PINNED_TEST_ENV": "fixture"}
        self.dispatcher = "antirea_dispatch_0000000000000001"
        self.evidence = {"core": {"defined": True, "virtualized": True}}
        self.fail_run = None
        self.baseline_text = "; baseline mock IR without a VM\n"
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(nb, "_toolchain", return_value=(self.config, self.pins)))
        self.stack.enter_context(patch.object(nb, "run_logged", side_effect=self.runner))
        self.stack.enter_context(patch.object(nb.diversify, "generate", side_effect=self.generate))
        self.stack.enter_context(patch.object(nb, "_vm_evidence", return_value=self.evidence))
        self.stack.enter_context(patch.object(nb, "_manifest_vm_evidence", return_value=self.evidence))
        self.stack.enter_context(patch.object(nb, "_runtime_evidence", return_value={"mock_runtime_evidence": True}))
        self.stack.enter_context(patch.object(nb.hardening, "inspect_hardening_artifact", side_effect=self.retained))

    def request(self, *, boundary=False):
        public = None
        if boundary:
            path = self.out / "module.public-boundaries.ll"
            path.write_text("; isolated reviewed public forwarding IR\n", encoding="utf-8")
            public = no.IRInput(path, nb._hash(path))
        return no.ObjectRequest(no.IRInput(self.source, nb._hash(self.source)),
                                no.IRInput(self.protection, nb._hash(self.protection)), ("core",), 1729, public)

    def pipeline(self, request=None, **changes):
        args = dict(workspace_root=self.root, output_dir=self.out, command_records=self.commands,
                    environment=self.environment, build_tool_hashes=self.pins)
        args.update(changes)
        return no.ObjectPipeline(request or self.request(), **args)

    def runner(self, argv, cwd, logs, **kwargs):
        argv = list(map(str, argv))
        self.assertEqual(cwd, self.out)
        self.assertEqual(kwargs["env"], self.environment)
        self.assertEqual(kwargs["cancel_file"], self.root / ".runs/defense-loop/STOP")
        self.assertEqual(kwargs["timeout"], 600)
        self.assertEqual(logs, self.out / "logs" / f"{len(self.commands) + 1:03d}")
        logs.parent.mkdir(exist_ok=True)
        stdout, stderr = logs.with_suffix(".stdout"), logs.with_suffix(".stderr")
        stdout.write_text("mock compiler output\n", encoding="utf-8")
        stderr.write_text("", encoding="utf-8")
        target = Path(argv[argv.index("-o") + 1]) if "-o" in argv else None
        if target is not None:
            payload = self.baseline_text.encode() if target.name == "baseline.ll" else b"INERT OUTPUT: " + target.name.encode()
            target.write_bytes(payload)
        self.events.append(target.name if target else "caller-only-marker")
        result = {"argv": argv, "returncode": 0, "timed_out": False, "cancelled": False,
                  "stdout": str(stdout), "stderr": str(stderr),
                  "cleanup": {"parent_exit_confirmed": True, "status": "assigned_job_empty", "job_handle_closed": True}}
        if self.fail_run:
            result.update(self.fail_run)
        return result

    def generate(self, after, runtime, opcodes, output, seed):
        self.assertEqual((after, runtime, opcodes, output, seed), (self.out / "module.after.ll",
            Path(self.config["runtime_source"]), Path(self.config["opcode_source"]), self.out, 1729))
        result = {"dispatcher_symbol": self.dispatcher}
        for name, payload in (("core.diversified.ll", "; diversified mock IR\n"),
                              ("runtime.generated.c", "/* inert generated source */\n"),
                              ("diversification.json", json.dumps(result))):
            (output / name).write_text(payload, encoding="utf-8")
        self.events.append("generate")
        return result

    def retained(self, manifest, runtime_ir, core_ir):
        self.events.append("retained-evidence")
        self.assertEqual(manifest, {"dispatcher_symbol": self.dispatcher})
        self.assertIn("runtime.after.ll", runtime_ir)
        self.assertIn("protected.codegen.ll", core_ir)
        return {"mock_retained_evidence": True}

    def link(self, arm):
        objects = [self.out / (arm + ".obj")]
        if arm == "protected":
            objects.append(self.out / "runtime.obj")
        nb._run_build_command(self.config["clangxx"], ["-target", nb.TARGET, "-shared", "-fuse-ld=lld", *objects,
            f"-Wl,/DEF:{self.out / 'exports.def'}", "-Wl,/DEBUG:NONE", "-Wl,/INCREMENTAL:NO",
            "-o", self.out / (arm + ".dll")], output=self.out, records=self.commands,
            stop=self.root / ".runs/defense-loop/STOP", environment=self.environment)

    def expected_recipes(self, boundary):
        """Independent frozen argv oracle for the pre-refactor object/link block."""
        out, tool = self.out, self.config
        flags = ["-O1", "-kagura-fla", "-kagura-sub", "-kagura-co", "-kagura-allow=core", "-kagura-seed=1729"]
        rows = [[tool["optimizer"], "-O1", "-S", self.source, "-o", out / "baseline.ll"],
                [tool["optimizer"], *flags, "-S", self.protection, "-o", out / "module.prevm.ll"],
                [tool["optimizer"], *flags, "-kagura-vm", "-S", self.protection, "-o", out / "module.after.ll"]]
        if boundary:
            rows.append([tool["llvm_link"], "-S", out / "core.diversified.ll", out / "module.public-boundaries.ll",
                         "-o", out / "core.public-joined.ll"])
        rows += [[tool["clang"], "-target", nb.TARGET, "-std=c11", "-O1", "-fno-inline", "-S", "-emit-llvm",
                  out / "runtime.generated.c", "-o", out / "runtime.before.ll"],
                 [tool["optimizer"], "-O1", "-kagura-fla", "-kagura-sub", "-kagura-co",
                  "-kagura-allow=" + self.dispatcher, "-kagura-seed=1729", "-S", out / "runtime.before.ll",
                  "-o", out / "runtime.after.ll"],
                 [tool["clang"], "-target", nb.TARGET, "-O0", "-c", out / "runtime.after.ll", "-o", out / "runtime.obj"]]
        for arm in ("baseline", "protected"):
            ir = out / ("baseline.ll" if arm == "baseline" else "core.public-joined.ll" if boundary else "core.diversified.ll")
            rows += [[tool["clangxx"], "-target", nb.TARGET, "-O1", "-S", "-emit-llvm", ir, "-o", out / (arm + ".codegen.ll")],
                     [tool["clangxx"], "-target", nb.TARGET, "-O0", "-c", out / (arm + ".codegen.ll"), "-o", out / (arm + ".obj")]]
            objects = [out / (arm + ".obj")] + ([out / "runtime.obj"] if arm == "protected" else [])
            rows.append([tool["clangxx"], "-target", nb.TARGET, "-shared", "-fuse-ld=lld", *objects,
                         f"-Wl,/DEF:{out / 'exports.def'}", "-Wl,/DEBUG:NONE", "-Wl,/INCREMENTAL:NO", "-o", out / (arm + ".dll")])
        return [list(map(str, row)) for row in rows]

    def exercise(self, boundary):
        request = self.request(boundary=boundary)
        source_before = {str(record.path): record.path.read_bytes() for record in
            (request.source_ir, request.protection_ir, request.public_boundary_ir) if record is not None}
        pipeline = self.pipeline(request)
        pipeline.prepare()
        self.assertFalse((self.out / "runtime.obj").exists())
        (self.out / "exports.def").write_bytes(b"EXPORTS\ncore\n")  # caller-owned, same historical point
        pipeline.compile_runtime()
        for arm in ("baseline", "protected"):
            pipeline.compile_arm(arm)
            self.link(arm)  # links are outside the object API, in original order
        self.events.append("caller-original-reference-link")
        result = pipeline.finalize()
        self.assertEqual([row["argv"] for row in self.commands], self.expected_recipes(boundary))
        self.assertTrue(all(row["cwd"] == str(self.out) for row in self.commands))
        self.assertLess(self.events.index("baseline.dll"), self.events.index("protected.codegen.ll"))
        self.assertLess(self.events.index("caller-original-reference-link"), self.events.index("retained-evidence"))
        self.assertEqual(result["status"], "native_objects_created_unlinked")
        self.assertEqual(result["original_vm"], self.evidence)
        self.assertEqual(result["functions"], self.evidence)
        self.assertEqual(result["final_vm"], self.evidence)
        self.assertEqual(result["hardening_evidence"], {"mock_retained_evidence": True})
        expected_outputs = set(no.ObjectPipeline._GENERATED)
        if not boundary:
            expected_outputs.remove("core.public-joined.ll")
        self.assertEqual(set(result["watched_outputs"]), expected_outputs)
        for name, record in result["watched_outputs"].items():
            self.assertEqual(record["sha256"], nb._hash(self.out / name))
            self.assertIn(record["observed_stage"], {"preparing", "runtime_compiling", "baseline_compiling", "protected_compiling"})
        for arm, record in result["objects"].items():
            self.assertEqual(Path(record["path"]).read_bytes(), b"INERT OUTPUT: " + (arm + ".obj").encode())
            self.assertEqual(record["sha256"], nb._hash(Path(record["path"])))
        self.assertEqual(source_before, {value: Path(value).read_bytes() for value in source_before})
        with self.assertRaises(nb.NativeBuildError):
            pipeline.finalize()

    def test_legacy_no_boundary_recipes_and_evidence_are_unchanged(self):
        self.exercise(False)

    def test_legacy_public_boundary_join_recipes_are_unchanged(self):
        self.exercise(True)

    def test_request_types_names_hashes_and_freshness_fail_closed(self):
        request = self.request()
        for value in (replace(request, seed=True), replace(request, selected_functions=("f*",)),
                      replace(request, selected_functions=("core", "core")),
                      replace(request, selected_functions=("kagura_owned",)),
                      replace(request, source_ir=no.IRInput(self.source, "0" * 64))):
            with self.subTest(value=value), self.assertRaises(nb.NativeBuildError):
                self.pipeline(value)
        (self.out / "protected.obj").write_bytes(b"previous output")
        with self.assertRaisesRegex(nb.NativeBuildError, "fresh"):
            self.pipeline(request)
        self.assertEqual(self.commands, [])

    def test_no_tool_callbacks_or_arbitrary_command_roles(self):
        pipeline = self.pipeline()
        with self.assertRaises(TypeError):
            pipeline.config["clang"] = "untrusted.exe"
        with self.assertRaisesRegex(nb.NativeBuildError, "role"):
            pipeline._run("arbitrary", "--execute")
        with self.assertRaises(FrozenInstanceError):
            pipeline.request.seed = 9
        self.assertEqual(self.commands, [])

    def test_stage_order_and_retries_are_rejected(self):
        pipeline = self.pipeline()
        for action in (pipeline.compile_runtime, lambda: pipeline.compile_arm("protected"), pipeline.finalize):
            with self.assertRaises(nb.NativeBuildError):
                action()
        self.fail_run = {"returncode": 1}
        with self.assertRaises(nb.NativeBuildError):
            pipeline.prepare()
        count = len(self.commands)
        with self.assertRaises(nb.NativeBuildError):
            pipeline.prepare()
        self.assertEqual(len(self.commands), count)

    def test_changed_input_stops_before_next_command(self):
        pipeline = self.pipeline()
        pipeline.prepare()
        count = len(self.commands)
        self.protection.write_text("changed input", encoding="utf-8")
        with self.assertRaisesRegex(nb.NativeBuildError, "changed"):
            pipeline.compile_runtime()
        self.assertEqual(len(self.commands), count)

    def test_changed_tool_stops_before_next_command(self):
        pipeline = self.pipeline()
        pipeline.prepare()
        count = len(self.commands)
        Path(self.config["optimizer"]).write_bytes(b"mutated inert tool")
        with self.assertRaisesRegex(nb.NativeBuildError, "changed"):
            pipeline.compile_runtime()
        self.assertEqual(len(self.commands), count)

    def test_codegen_mutation_before_object_consumption_is_rejected(self):
        pipeline = self.pipeline()
        pipeline.prepare()
        pipeline.compile_runtime()
        run = pipeline._run

        def mutate_after_codegen(role, *args):
            result = run(role, *args)
            if str(self.out / "baseline.codegen.ll") == str(args[-1]):
                (self.out / "baseline.codegen.ll").write_bytes(b"changed after observed codegen")
            return result

        with patch.object(pipeline, "_run", side_effect=mutate_after_codegen):
            with self.assertRaisesRegex(nb.NativeBuildError, "produced artifact changed"):
                pipeline.compile_arm("baseline")
        self.assertFalse((self.out / "baseline.obj").exists())

    def test_process_mutating_prior_output_is_rejected_on_return(self):
        pipeline = self.pipeline()
        pipeline.prepare()

        def corrupting_runner(*args, **kwargs):
            result = self.runner(*args, **kwargs)
            (self.out / "baseline.ll").write_bytes(b"unexpected side effect")
            return result

        with patch.object(nb, "run_logged", side_effect=corrupting_runner):
            with self.assertRaisesRegex(nb.NativeBuildError, "produced artifact changed"):
                pipeline.compile_runtime()
        self.assertNotEqual(pipeline.phase, "runtime_ready")

    def test_missing_original_build_tool_pin_rejected(self):
        pins = dict(self.pins)
        pins.pop(self.config["clangxx"])
        with self.assertRaisesRegex(nb.NativeBuildError, "pins"):
            self.pipeline(build_tool_hashes=pins)
        self.assertEqual(self.commands, [])

    def test_stop_is_observed_before_command_without_removing_marker(self):
        pipeline = self.pipeline()
        stop = self.root / ".runs/defense-loop/STOP"
        stop.parent.mkdir()
        stop.write_text("stop", encoding="utf-8")
        with self.assertRaisesRegex(nb.NativeBuildError, "STOP"):
            pipeline.prepare()
        self.assertTrue(stop.exists())
        self.assertEqual(self.commands, [])

    def test_protected_baseline_is_not_accepted(self):
        pipeline = self.pipeline()
        self.baseline_text = "@kagura_vm_execute(\n"
        with self.assertRaisesRegex(nb.NativeBuildError, "Baseline unexpectedly"):
            pipeline.prepare()
        self.assertNotIn("generate", self.events)

    @contextlib.contextmanager
    def dangling_entry(self, target, *, reparse_only=False):
        """No real link privilege is required; no compiler/target may run.

        Simulate an existing directory entry whose referent is absent. exists()
        remains False, while lstat sees it. reparse_only also models a dangling
        reparse kind that Path.is_symlink() does not recognize.
        """
        original_lstat, original_is_symlink = Path.lstat, Path.is_symlink
        entry = SimpleNamespace(st_mode=stat.S_IFREG if reparse_only else stat.S_IFLNK,
                                st_file_attributes=0x400)

        def lstat(path, *args, **kwargs):
            return entry if path == target else original_lstat(path, *args, **kwargs)

        def is_symlink(path):
            return (not reparse_only) if path == target else original_is_symlink(path)

        with patch.object(Path, "lstat", lstat), patch.object(Path, "is_symlink", is_symlink):
            self.assertFalse(target.exists())
            yield

    def test_dangling_symlink_output_rejected_at_construction(self):
        target = self.out / "baseline.ll"
        with self.dangling_entry(target):
            with self.assertRaises(nb.NativeBuildError):
                self.pipeline()
        self.assertEqual(self.commands, [])
        nb.run_logged.assert_not_called()

    def test_dangling_non_symlink_reparse_rejected_at_construction(self):
        target = self.out / "baseline.ll"
        with self.dangling_entry(target, reparse_only=True):
            with self.assertRaises(nb.NativeBuildError):
                self.pipeline()
        self.assertEqual(self.commands, [])
        nb.run_logged.assert_not_called()

    def test_dangling_output_planted_after_constructor_rejected_before_command(self):
        pipeline = self.pipeline()
        target = self.out / "baseline.ll"
        with self.dangling_entry(target, reparse_only=True):
            with self.assertRaises(nb.NativeBuildError):
                pipeline.prepare()
        self.assertEqual(self.commands, [])
        nb.run_logged.assert_not_called()
        self.assertFalse(target.exists())

    def test_existing_command_failure_cleanup_semantics_are_preserved(self):
        for failure in ({"cancelled": True}, {"timed_out": True}, {"returncode": 9},
                        {"error": "failed"}, {"cleanup": {"parent_exit_confirmed": False}}):
            self.fail_run = failure
            with self.subTest(failure=failure), self.assertRaises(nb.NativeBuildError):
                nb._run_build_command(self.config["clang"], [], output=self.out, records=self.commands,
                    stop=self.root / ".runs/defense-loop/STOP", environment=self.environment)


def _output_tamper_test(name):
    def test(self):
        pipeline = self.pipeline(self.request(boundary=True))
        pipeline.prepare()
        if name in {"runtime.obj", "baseline.codegen.ll", "baseline.obj", "protected.codegen.ll", "protected.obj"}:
            pipeline.compile_runtime()
        if name in {"baseline.codegen.ll", "baseline.obj", "protected.codegen.ll", "protected.obj"}:
            pipeline.compile_arm("baseline")
        if name in {"protected.codegen.ll", "protected.obj"}:
            pipeline.compile_arm("protected")
        count = len(self.commands)
        target = self.out / name
        payload = target.read_bytes()
        target.write_bytes(bytes([payload[0] ^ 1]) + payload[1:])  # same-length changes must fail too
        action = {"prepared": pipeline.compile_runtime,
                  "runtime_ready": lambda: pipeline.compile_arm("baseline"),
                  "baseline_ready": lambda: pipeline.compile_arm("protected"),
                  "protected_ready": pipeline.finalize}[pipeline.phase]
        with self.assertRaisesRegex(nb.NativeBuildError, "produced artifact changed"):
            action()
        self.assertEqual(len(self.commands), count)
    return test


for _output in no.ObjectPipeline._GENERATED:
    setattr(NativeObjectPipelineTests, "test_stage_output_tamper_" + _output.replace(".", "_"), _output_tamper_test(_output))

def _generator_output_guard_test(name):
    def test(self):
        pipeline = self.pipeline()
        target = self.out / name
        original_run = pipeline._run
        links = contextlib.ExitStack()
        self.addCleanup(links.close)

        def plant_after_vm(role, *args):
            result = original_run(role, *args)
            if str(args[-1]) == str(self.out / "module.after.ll"):
                links.enter_context(self.dangling_entry(target, reparse_only=True))
            return result

        with patch.object(pipeline, "_run", side_effect=plant_after_vm):
            with self.assertRaises(nb.NativeBuildError):
                pipeline.prepare()
        # The old implementation writes via generate(), only rejecting the
        # planted entry in _observe() afterwards. Rejection alone is not enough.
        nb.diversify.generate.assert_not_called()
        self.assertEqual(len(self.commands), 3)
        self.assertFalse(target.exists())
    return test


for _output in ("core.diversified.ll", "runtime.generated.c", "diversification.json"):
    setattr(NativeObjectPipelineTests, "test_generator_output_dangling_" + _output.replace(".", "_"),
            _generator_output_guard_test(_output))


if __name__ == "__main__":
    unittest.main()
