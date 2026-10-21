"""RED-first behavioral tests for the direct-source native independent reference.

Task 3 of docs/superpowers/plans/2026-10-21-supported-languages.md. These tests
pin the *direct-source* C / C++ / single-crate-Rust route (not the already-landed
``compile_database_native`` backend) to the same three-arm discipline the
database route has: a newly built direct artifact must carry a separately
source-compiled original DLL and a separate source-compiled signature IR, and
``validate_build`` must compare original vs baseline vs protected so that
baseline/protected agreement cannot conceal an original-vs-normalized mismatch.

Status when written: RED. Current ``native_validate.validate_build`` only
requires three arms when ``report["backend"] == "compile_database_native"``
(native_validate.py:823); a direct-source report takes the two-arm branch, so
every assertion here that depends on the third arm fails today. The intended
GREEN change makes the reference requirement derive from the *bound project
route* (a direct native source project: ``report["project"]["language"]`` in
{c, cpp, rust} bound to real inspected ``project_path`` / ``input_hashes``, not a
droppable/forgeable flag) and adds a direct-source provenance verifier that
reuses the existing link tail / generic signature-and-artifact gates.

The derivation must stay disjoint from the other routes. Composed reports
carrying a nested ``native_report`` (dotnet_il_native / jvm_bytecode_native /
go_typed_native / swift_llvm_native lowered through ``source_validate.
validate_lowered_build`` -> ``validate_build``) and the ``llvm_ir`` frontend
handoff keep their own existing two-native-arm + original-runtime-reference
behavior, and the ``compile_database_native`` backend keeps its own separate
three-arm verifier. Direct-source provenance must never be required on any of
those, and a forged ``native_report`` or spoofed ``backend`` must not exempt a
genuinely direct c/cpp/rust manifest (the verifier re-reads the bound manifest to
decide). These suites only build pure direct fixtures (no ``native_report``,
language in {c, cpp, rust}); Root's real Java/Kotlin/Go/Swift driver workflows
verify the composed-route non-regression after the final freeze.

Execution boundary: the worker (defender) does NOT run these. Root executes every
test/build/compiler/target. All compiler / object / DLL / tool files below are
inert ``NONEXECUTABLE ... FIXTURE`` bytes and the process boundary
(``run_logged``) is mocked, exactly like ``tests/test_native_validate.py`` — the
tests exercise the real gate logic, never a toolchain or a built library.

Direct-route report contract these tests pin (the shape the GREEN builder/
validator must agree on; mirrors native_build.py:1463-1474 minus the
compile-database-plan digests, plus an explicit reference-optimization note):

    report["project"]["language"] in {"c", "cpp", "rust"}  # route binding
    report["original_reference_signature_ir"]              # separate source IR
    report["artifacts"]["original_reference"]              # separate source DLL
    report["original_reference_provenance"] = {
        "schema_version": 1, "method": "direct_source_compile",
        "source_semantics": "recorded_direct_source_arguments",
        "uses_protection_normalized_ir": False,
        "reference_optimization": "normal_direct_recipe_no_scope_normalization",
        "language": <lang>, "exported_functions": [...],
        "compiler_inputs": {compiler: sha}, "translation_units": [{
            source, source_operand, entry_sha256, compiler, compiler_sha256,
            cwd, object_path, signature_ir_path,
            object_command_index, signature_ir_command_index}],
        "link_command_index": N,
        "link_contract": {kind: restricted_windows_shared_library, target, False}}

Report objects are hand-built fixtures (schema-1 coverage, no boundary transit)
to keep them inert, following the existing database harness convention.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from antirea import native_build
from antirea.native_validate import make_cases, validate_build


TARGET = "x86_64-pc-windows-msvc"

CONTRACT = {"schema_version": 1, "library_name": "testcore", "functions": [
    {"name": "core", "return_type": "u64", "parameters": [
        {"name": "signed_value", "type": "i64"}, {"name": "unsigned_value", "type": "u64"}]}]}

# Matches the database harness IR so verify_integer_abi accepts it (i64/i64 -> i64
# carries the u64/i64 contract widths; signedness stays in the user contract).
IR = 'define dso_local i64 @core(i64 %a, i64 %b) {\n ret i64 %a\n}\n'


class _DirectReferenceBase:
    """Mixin: one bound direct-source report + the three-arm behaviors.

    Concrete subclasses add ``unittest.TestCase`` and the per-language compiler
    recipe. This class is not a TestCase, so unittest does not discover it alone.
    """

    language = None
    compiler_name = None
    source_name = None
    source_text = None
    object_index = 0
    signature_index = 1
    link_index = 2

    # ----- per-language recipe hook ------------------------------------------
    def recipe_substitution_mutations(self):
        """List of (label, mutate(report)) that corrupt a recorded compile step."""
        raise NotImplementedError

    # ----- fixture ------------------------------------------------------------
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="antirea-direct-reference-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.build = self.root / ".runs/build"
        self.build.mkdir(parents=True)
        source_dir = self.root / "source"
        source_dir.mkdir()

        self.contract = source_dir / "contract.json"
        self.contract.write_text(json.dumps(CONTRACT), encoding="utf-8")

        normalized = self.build / "module.before.ll"
        normalized.write_text(IR, encoding="utf-8")

        # Owned source + a real v1 manifest. The project record is produced by the
        # actual inspector, so project_path / input_hashes / sources / defines bind
        # completely and the verifier's re-inspection matches byte for byte.
        self.source_file = source_dir / self.source_name
        self.source_file.write_text(self.source_text, encoding="utf-8")
        manifest = source_dir / "project.json"
        manifest.write_text(json.dumps({"schema_version": 1, "name": "direct-core",
            "language": self.language, "sources": [self.source_name], "functions": ["core"]}), encoding="utf-8")

        # Pinned link toolchain (consumed by cpp_symbols._trusted_link_tools) plus
        # the pinned clang/clang++ frontend drivers; identical layout to the
        # compilation-database harness. All inert transport fixtures.
        tool_bin = self.root / ".tools/llvm/bin"
        tool_bin.mkdir(parents=True, exist_ok=True)
        tool_paths = [tool_bin / name for name in
                      ("llvm-link.exe", "opt.exe", "clang++.exe", "LLVM-C.dll", "lld-link.exe")]
        for path in tool_paths:
            path.write_bytes(("NONEXECUTABLE LINK TOOL " + path.name).encode())
        clang = tool_bin / "clang.exe"
        clang.write_bytes(b"NONEXECUTABLE FRONTEND clang.exe")
        config = self.root / ".tools/kagura-toolchain.json"
        config.write_text(json.dumps({"schema_version": 1, "target": TARGET,
            "llvm_root": str(tool_bin.parent), "clang": str(clang),
            "clangxx": str(tool_bin / "clang++.exe")}), encoding="utf-8")

        inspected = native_build.inspect_project(manifest, workspace_root=self.root)
        self.ref_source = inspected["sources"][0]

        # Frontend compiler: pinned clang/clang++ by translation-unit suffix for
        # C/C++; external pinned rustc for Rust.
        if self.language == "rust":
            self.compiler = self.root / self.compiler_name
            self.compiler.write_bytes(("NONEXECUTABLE FRONTEND " + self.compiler_name).encode())
        else:
            self.compiler = tool_bin / ("clang.exe" if Path(self.ref_source).suffix.lower() == ".c" else "clang++.exe")
        compiler_sha = self.descriptor(self.compiler)["sha256"]

        obj = self.build / "original-000.obj"
        obj.write_bytes(b"NONEXECUTABLE OBJECT TRANSPORT FIXTURE")
        sig = self.build / "original-signature-000.ll"
        sig.write_text(IR, encoding="utf-8")
        definition = self.build / "exports.def"
        definition.write_bytes(b"EXPORTS\ncore\n")

        artifacts = {}
        for arm in ("original_reference", "baseline", "protected"):
            path = self.build / (arm + ".dll")
            path.write_bytes(("NONEXECUTABLE TEST TRANSPORT " + arm).encode())
            artifacts[arm] = self.descriptor(path)
        clangxx = tool_bin / "clang++.exe"
        link_argv = [str(clangxx), "-target", TARGET, "-shared", "-fuse-ld=lld", str(obj),
                     f"-Wl,/DEF:{definition}", "-Wl,/DEBUG:NONE", "-Wl,/INCREMENTAL:NO",
                     "-o", artifacts["original_reference"]["path"]]
        # Build the recorded compile commands with the shared producer recipe
        # helper so they are byte-identical to the verifier's reconstruction.
        object_argv, signature_argv = native_build._direct_reference_commands(
            inspected["language"], Path(self.ref_source), str(self.compiler), obj, sig,
            include_dirs=inspected["include_dirs"], defines=inspected["defines"])
        commands = [None, None, None]
        commands[self.object_index] = self.successful_command(object_argv, str(self.build))
        commands[self.signature_index] = self.successful_command(signature_argv, str(self.build))
        commands[self.link_index] = self.successful_command(link_argv, str(self.build))

        self.report = {
            "status": "artifact_created_unvalidated",
            "project": inspected,
            "coverage": {"exported_functions": ["core"], "selected_functions": ["core"],
                         "functions": {"core": {"virtualized": True}}},
            "signature_ir": self.descriptor(normalized),
            # Single source: the separate source-compiled signature IR is also the
            # per-translation-unit signature IR (distinct from module.before.ll).
            "original_reference_signature_ir": self.descriptor(sig),
            "artifacts": artifacts,
            "original_reference_provenance": {
                "schema_version": 1, "method": "direct_source_compile",
                "source_semantics": "recorded_direct_source_arguments",
                "uses_protection_normalized_ir": False,
                "reference_optimization": "normal_direct_recipe_no_scope_normalization",
                "language": inspected["language"], "exported_functions": list(inspected["exported_functions"]),
                "compiler_inputs": {str(self.compiler): compiler_sha},
                "translation_units": [{
                    "source": self.ref_source, "source_operand": self.ref_source,
                    "entry_sha256": inspected["input_hashes"][self.ref_source], "compiler": str(self.compiler),
                    "compiler_sha256": compiler_sha, "cwd": str(self.build),
                    "object_path": str(obj), "signature_ir_path": str(sig),
                    "object_command_index": self.object_index,
                    "signature_ir_command_index": self.signature_index}],
                "link_command_index": self.link_index,
                "link_contract": {"kind": "restricted_windows_shared_library",
                                  "target": TARGET, "complete_application_link": False}},
            "commands": commands,
            "tool_hashes": {str(path): self.descriptor(path)["sha256"] for path in [config, clang, *tool_paths]},
            "artifact_hashes": {path.name: self.descriptor(path)["sha256"] for path in (obj, sig, definition)},
        }
        self.report["tool_hashes"][str(self.compiler)] = compiler_sha
        if self.language == "rust":
            self.report["rustc_sha256"] = compiler_sha

        self.report_path = self.build / "report.json"
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

    @staticmethod
    def successful_command(argv, cwd):
        return {"argv": argv, "cwd": cwd, "returncode": 0, "timed_out": False, "cancelled": False,
                "cleanup": {"job_assigned": True, "active_after": 0,
                            "parent_exit_confirmed": True, "job_handle_closed": True}}

    def save_report(self):
        self.report_path.write_text(json.dumps(self.report), encoding="utf-8")

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
        """The reference gate must reject before any worker/library runs.

        Uses the real (inert) worker stub as the mock side effect so that, while
        the direct reference gate is still unimplemented, a non-rejecting run
        completes cleanly as a two-arm pass and ``assertRaisesRegex`` reports a
        clean "ValueError not raised" red rather than an incidental error.
        """
        self.counter += 1
        self.save_report()
        with patch("antirea.native_validate.run_logged", side_effect=self.worker) as worker:
            with self.assertRaisesRegex(ValueError, pattern):
                validate_build(self.report_path, self.contract, self.root / f".runs/rejected-{self.counter}",
                               workspace_root=self.root, random_cases=3, seed=19, timeout_seconds=9)
            worker.assert_not_called()

    # ----- behaviors ----------------------------------------------------------
    def test_honest_three_arm_direct_reference_passes(self):
        result = self.validate()
        self.assertEqual(result["status"], "functional_samples_passed", result.get("error"))
        self.assertEqual(result["required_arms"], ["original_reference", "baseline", "protected"])
        self.assertTrue(result["original_reference_required"])
        self.assertEqual([name for name, _ in self.requests], result["required_arms"])
        count = len(make_cases(CONTRACT, 3, 19)["core"])
        self.assertEqual(result["functions"]["core"]["original_reference_comparisons"],
                         {arm: {"matched": count, "total": count} for arm in ("baseline", "protected")})
        self.assertEqual(result["original_reference_abi_evidence"]["core"]["signedness"],
                         "user_contract_not_encoded_in_llvm")
        self.assertTrue(result["inputs_unchanged"])

    def test_baseline_protected_agreement_does_not_hide_original_mismatch(self):
        def mutate(arm, reply):
            if arm == "original_reference":
                reply["outputs"]["core"][0] = 9
        self.reply_mutation = mutate
        result = self.validate()
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["functions"]["core"]["sampled_output_match"])
        self.assertFalse(result["functions"]["core"]["original_reference_match"])

    def test_bound_direct_route_requires_complete_reference_evidence(self):
        def strip_all(report):
            report.pop("original_reference_signature_ir", None)
            report["artifacts"].pop("original_reference", None)
            report.pop("original_reference_provenance", None)

        def forge_backend(report):
            # A bound direct native route must not be downgradable by setting an
            # unrelated backend string; the requirement derives from the project
            # language, not a single removable/forgeable flag.
            report["backend"] = "unrelated_backend"
            strip_all(report)

        cases = [
            ("strip_all", strip_all, "original reference"),
            ("strip_signature", lambda r: r.pop("original_reference_signature_ir", None), "original reference"),
            ("strip_artifact", lambda r: r["artifacts"].pop("original_reference", None), "required native artifact"),
            ("strip_provenance", lambda r: r.pop("original_reference_provenance", None), "original reference"),
            ("forged_unrelated_backend", forge_backend, "original reference"),
        ]
        good = copy.deepcopy(self.report)
        for label, mutate, pattern in cases:
            with self.subTest(label=label):
                self.report = copy.deepcopy(good)
                mutate(self.report)
                self.assert_preflight_rejects(pattern)

    def test_reference_signature_must_be_separately_source_compiled(self):
        self.report["original_reference_signature_ir"] = self.report["signature_ir"]
        self.assert_preflight_rejects("separate source-compiled")

    def test_reference_signature_hash_and_abi_are_verified(self):
        path = Path(self.report["original_reference_signature_ir"]["path"])
        path.write_text(IR + "; changed\n", encoding="utf-8")
        self.assert_preflight_rejects("signature IR differs")
        for bad in (IR.replace("i64 @core", "i32 @core"),
                    IR.replace("i64 %a, i64 %b", "i64 %a"),
                    IR.replace("dso_local", "dso_local fastcc")):
            with self.subTest(bad=bad):
                path.write_text(bad, encoding="utf-8")
                self.report["original_reference_signature_ir"] = self.descriptor(path)
                self.assert_preflight_rejects("compiled ABI|calling convention")

    def test_reference_artifact_must_be_distinct_and_hash_bound(self):
        with self.subTest(case="alias_baseline"):
            report = copy.deepcopy(self.report)
            report["artifacts"]["original_reference"] = report["artifacts"]["baseline"]
            self.report = report
            self.assert_preflight_rejects("separate owned artifacts")
        with self.subTest(case="escape_build_dir"):
            self.report = copy.deepcopy(self.report)
            outside = self.root / "outside.dll"
            outside.write_bytes(b"not executable")
            self.report["artifacts"]["original_reference"] = self.descriptor(outside)
            self.assert_preflight_rejects("reviewed build")

    def test_reference_link_requires_fixed_trusted_recipe(self):
        good = copy.deepcopy(self.report)
        for extra in (str(self.build / "unknown.obj"), "unknown.lib", "-Wl,/FORCE", "-Wl,/ENTRY:other"):
            with self.subTest(extra=extra):
                self.report = copy.deepcopy(good)
                self.report["commands"][self.link_index]["argv"].insert(5, extra)
                self.assert_preflight_rejects("original reference")
        for mode in ("driver", "cwd", "target", "definition", "duplicate"):
            with self.subTest(mode=mode):
                self.report = copy.deepcopy(good)
                record = self.report["commands"][self.link_index]
                if mode == "driver":
                    record["argv"][0] = str(self.root / "other.exe")
                elif mode == "cwd":
                    record["cwd"] = str(self.root)
                elif mode == "target":
                    record["argv"][2] = "x86_64-unknown-linux-gnu"
                elif mode == "definition":
                    record["argv"][-5] = "-Wl,/DEF:other.def"
                else:
                    self.report["commands"].append(copy.deepcopy(record))
                self.assert_preflight_rejects("original reference")

    def test_reference_link_requires_trusted_tool_and_definition_pins(self):
        good = copy.deepcopy(self.report)
        tool_paths = [str(self.root / ".tools/kagura-toolchain.json"),
                      str(self.root / ".tools/llvm/bin/clang++.exe"),
                      str(self.root / ".tools/llvm/bin/lld-link.exe")]
        for path in tool_paths:
            for mutation in ("missing", "wrong"):
                with self.subTest(path=path, mutation=mutation):
                    self.report = copy.deepcopy(good)
                    if mutation == "missing":
                        self.report["tool_hashes"].pop(path, None)
                    else:
                        self.report["tool_hashes"][path] = "0" * 64
                    self.assert_preflight_rejects("original reference")
        definition = self.build / "exports.def"
        with self.subTest(case="extra_export"):
            self.report = copy.deepcopy(good)
            definition.write_bytes(b"EXPORTS\ncore\nextra\n")
            self.assert_preflight_rejects("original reference")
        with self.subTest(case="extra_export_rehashed"):
            self.report = copy.deepcopy(good)
            self.report["artifact_hashes"]["exports.def"] = self.descriptor(definition)["sha256"]
            self.assert_preflight_rejects("original reference")
        definition.write_bytes(b"EXPORTS\ncore\n")

    def test_reference_compile_command_substitution_is_rejected(self):
        good = copy.deepcopy(self.report)
        for label, mutate in self.recipe_substitution_mutations():
            with self.subTest(label=label):
                self.report = copy.deepcopy(good)
                mutate(self.report)
                self.assert_preflight_rejects("original reference")

    def test_false_or_missing_direct_provenance_is_rejected(self):
        good = copy.deepcopy(self.report)
        mutations = [
            lambda r: r["original_reference_provenance"].update(uses_protection_normalized_ir=True),
            lambda r: r["original_reference_provenance"].update(method="protection_normalized_compile"),
            lambda r: r["original_reference_provenance"].update(exported_functions=[]),
            lambda r: r["original_reference_provenance"].update(exported_functions=["core", "core"]),
            lambda r: r["original_reference_provenance"]["translation_units"][0].update(compiler_sha256="9" * 64),
            lambda r: r["original_reference_provenance"]["translation_units"][0].update(object_command_index=99),
            lambda r: r["original_reference_provenance"]["translation_units"][0].update(entry_sha256="9" * 64),
        ]
        for index, change in enumerate(mutations):
            with self.subTest(index=index):
                self.report = copy.deepcopy(good)
                change(self.report)
                self.assert_preflight_rejects("original")

    def test_reference_or_tool_drift_during_validation_fails_closed(self):
        targets = [self.build / "original_reference.dll",
                   self.build / "original-signature-000.ll",
                   self.source_file,
                   self.compiler,
                   self.root / ".tools/llvm/bin/lld-link.exe"]
        for path in targets:
            with self.subTest(path=path.name):
                raw = path.read_bytes()
                self.process_mutation = (lambda captured: (lambda arm, process:
                    captured.write_bytes(captured.read_bytes() + b" changed") if arm == "protected" else None))(path)
                result = self.validate()
                self.assertEqual(result["status"], "failed")
                self.assertFalse(result["inputs_unchanged"])
                path.write_bytes(raw)
        self.process_mutation = None

    def test_original_reference_child_failure_timeout_cancel_fail_closed(self):
        for changes, expected in (({"returncode": 1}, "failed"),
                                  ({"timed_out": True}, "timed_out"),
                                  ({"cancelled": True}, "cancelled")):
            with self.subTest(changes=changes):
                self.process_mutation = (lambda applied: (lambda arm, process:
                    process.update(applied) if arm == "original_reference" else None))(changes)
                result = self.validate()
                self.assertEqual(result["status"], expected)
                self.assertEqual(set(result["execution"]), {"original_reference"})

    @unittest.skipUnless(os.name == "nt", "Windows job cleanup contract")
    def test_unverified_original_reference_cleanup_is_failure(self):
        def mutate(arm, process):
            if arm == "original_reference":
                process["cleanup"]["active_after"] = 1
        self.process_mutation = mutate
        result = self.validate()
        self.assertEqual(result["status"], "failed")
        self.assertIn("cleanup", result["error"])

    def test_stop_before_or_during_original_reference_never_passes(self):
        stop = self.root / ".runs/defense-loop/STOP"
        stop.parent.mkdir(parents=True, exist_ok=True)
        stop.write_text("stop", encoding="utf-8")
        self.assertEqual(self.validate()["status"], "cancelled")
        self.assertEqual(self.requests, [])
        stop.unlink()

        def mutate(arm, process):
            if arm == "original_reference":
                stop.write_text("stop", encoding="utf-8")
        self.process_mutation = mutate
        self.assertEqual(self.validate()["status"], "cancelled")


class _ClangFamilyDirectReferenceTests(_DirectReferenceBase):
    """C and C++ share clang's ``-S -emit-llvm`` (IR) vs ``-c`` (object) recipe."""

    def recipe_substitution_mutations(self):
        def obj(report):
            return report["commands"][self.object_index]["argv"]

        def sig(report):
            return report["commands"][self.signature_index]["argv"]

        return [
            ("object_missing_dash_c", lambda r: obj(r).remove("-c")),
            ("object_also_emits_ir", lambda r: obj(r).insert(obj(r).index("-c"), "-emit-llvm")),
            ("signature_missing_emit_llvm", lambda r: sig(r).remove("-emit-llvm")),
            # The reference must use the normal direct recipe (O1), never the
            # scope-analysis O0 downgrade used for the protection path.
            ("object_scope_optimization", lambda r: obj(r).__setitem__(obj(r).index("-O1"), "-O0")),
            ("signature_scope_optimization", lambda r: sig(r).__setitem__(sig(r).index("-O1"), "-O0")),
            ("object_untrusted_plugin", lambda r: obj(r).insert(1, "-fplugin=untrusted.dll")),
            ("object_source_operand_rewritten",
             lambda r: obj(r).__setitem__(obj(r).index(self.ref_source), self.source_name)),
            ("object_command_failed",
             lambda r: r["commands"][self.object_index].update(returncode=1)),
        ]


class DirectCReferenceTests(_ClangFamilyDirectReferenceTests, unittest.TestCase):
    language = "c"
    compiler_name = "clang.exe"
    source_name = "core.c"
    source_text = "unsigned long long core(long long a,unsigned long long b){return b;}\n"


class DirectCppReferenceTests(_ClangFamilyDirectReferenceTests, unittest.TestCase):
    language = "cpp"
    compiler_name = "clang++.exe"
    source_name = "core.cpp"
    source_text = 'extern "C" unsigned long long core(long long a,unsigned long long b){return b;}\n'


class DirectRustReferenceTests(_DirectReferenceBase, unittest.TestCase):
    """Single-crate Rust reference: ``rustc --emit=obj`` for the object, kept
    distinct from the protection ``--emit=llvm-ir`` route and from blocked Cargo."""

    language = "rust"
    compiler_name = "rustc.exe"
    source_name = "core.rs"
    source_text = ('#![no_std]\n'
                   '#[no_mangle]\n'
                   'pub extern "C" fn core(_a: i64, b: u64) -> u64 { b }\n'
                   '#[panic_handler]\n'
                   'fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }\n')

    def recipe_substitution_mutations(self):
        def obj(report):
            return report["commands"][self.object_index]["argv"]

        def sig(report):
            return report["commands"][self.signature_index]["argv"]

        return [
            ("object_emits_ir_not_obj",
             lambda r: obj(r).__setitem__(obj(r).index("--emit=obj"), "--emit=llvm-ir")),
            ("signature_emits_obj_not_ir",
             lambda r: sig(r).__setitem__(sig(r).index("--emit=llvm-ir"), "--emit=obj")),
            # Reference uses opt-level 1 (normal), never the scope-analysis 0.
            ("object_scope_optimization",
             lambda r: obj(r).__setitem__(obj(r).index("-Copt-level=1"), "-Copt-level=0")),
            ("object_untrusted_llvm_args", lambda r: obj(r).insert(1, "-Cllvm-args=-enable-x")),
            ("object_source_operand_rewritten",
             lambda r: obj(r).__setitem__(obj(r).index(self.ref_source), self.source_name)),
            ("object_command_failed",
             lambda r: r["commands"][self.object_index].update(returncode=1)),
        ]


if __name__ == "__main__":
    unittest.main()
