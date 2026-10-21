"""Mocked orchestration tests; not compiler/target/defense qualification."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from antirea import native_app_integration as engine


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SwiftPrivateModuleMapTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.sdk = self.root / "sdk"
        self.output = self.root / "private"
        self.output.mkdir()
        self.compiler = {"sdk": str(self.sdk), "input_hashes": {}}
        self.includes = []
        self.original_bytes = {}
        for name, part, header in (
            ("ucrt.modulemap", "ucrt", "corecrt.h"),
            ("winsdk_shared.modulemap", "shared", "guiddef.h"),
            ("winsdk_um.modulemap", "um", "Windows.h"),
        ):
            directory = self.root / "headers" / part
            directory.mkdir(parents=True)
            (directory / header).write_bytes(b"// mock owned header\n")
            self.includes.append(str(directory))
            source = self.sdk / "usr/share" / name
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text('module ' + part + ' { header "' + header + '" }\n', encoding="utf-8")
            self.original_bytes[str(source)] = source.read_bytes()
            self.compiler["input_hashes"][str(source)] = sha(source)
        self.env = {"INCLUDE": os.pathsep.join(self.includes)}
        self.pins = {}

    def generate(self):
        return engine._swift_module_maps(self.compiler, self.env, self.output, self.pins)

    def test_private_maps_rebase_headers_pin_bytes_and_leave_installed_files_unchanged(self):
        value = self.generate()
        self.assertEqual(len(value["maps"]), 3)
        self.assertEqual(len(value["flags"]), 6)
        self.assertEqual(value["flags"][::2], ["-Xcc"] * 3)
        for row in value["maps"]:
            original, generated = Path(row["original"]), Path(row["private"])
            self.assertEqual(original.read_bytes(), self.original_bytes[str(original)])
            self.assertEqual(self.pins[str(original)], sha(original))
            self.assertEqual(self.pins[str(generated)], sha(generated))
            self.assertTrue(generated.is_relative_to(self.output))
            for header, digest in row["headers"].items():
                self.assertEqual(self.pins[header], digest)
                self.assertIn(Path(header).as_posix(), generated.read_text(encoding="utf-8"))

    def test_changed_template_is_rejected_before_writes(self):
        path = next(iter(self.original_bytes))
        Path(path).write_bytes(b"changed")
        with self.assertRaises(engine.NativeIntegrateError):
            self.generate()
        self.assertFalse((self.output / "swift-module-maps").exists())

    def test_missing_sdk_marker_rejected(self):
        self.env["INCLUDE"] = os.pathsep.join(self.includes[1:])
        with self.assertRaises(engine.NativeIntegrateError):
            self.generate()

    def test_ambiguous_header_roots_rejected(self):
        self.env["INCLUDE"] += os.pathsep + self.includes[0]
        with self.assertRaises(engine.NativeIntegrateError):
            self.generate()

    def test_header_escape_rejected_even_with_pinned_template(self):
        path = Path(next(iter(self.original_bytes)))
        path.write_text('module x { header "../outside.h" }\n', encoding="utf-8")
        self.compiler["input_hashes"][str(path)] = sha(path)
        with self.assertRaises(engine.NativeIntegrateError):
            self.generate()

    def test_missing_header_rejected(self):
        path = Path(next(iter(self.original_bytes)))
        path.write_text('module x { header "missing.h" }\n', encoding="utf-8")
        self.compiler["input_hashes"][str(path)] = sha(path)
        with self.assertRaises(engine.NativeIntegrateError):
            self.generate()

    def test_reviewed_um_shared_and_winrt_siblings_are_pinned(self):
        winrt = self.root / "headers/winrt"
        winrt.mkdir()
        (winrt / "roapi.h").write_bytes(b"// mock WinRT header\n")
        self.env["INCLUDE"] += os.pathsep + str(winrt)
        source = self.sdk / "usr/share/winsdk_um.modulemap"
        source.write_text('module um { header "../shared/guiddef.h" header "../winrt/roapi.h" }\n',
                          encoding="utf-8")
        self.compiler["input_hashes"][str(source)] = sha(source)
        value = self.generate()
        row = value["maps"][2]
        self.assertEqual(set(row["headers"]),
                         {str(self.root / "headers/shared/guiddef.h"), str(winrt / "roapi.h")})

    def test_sibling_from_different_sdk_version_is_rejected(self):
        wrong = self.root / "other-version/winrt"
        wrong.mkdir(parents=True)
        (wrong / "roapi.h").write_bytes(b"// not the selected SDK version\n")
        self.env["INCLUDE"] += os.pathsep + str(wrong)
        source = self.sdk / "usr/share/winsdk_um.modulemap"
        source.write_text('module um { header "../winrt/roapi.h" }\n', encoding="utf-8")
        self.compiler["input_hashes"][str(source)] = sha(source)
        with self.assertRaises(engine.NativeIntegrateError):
            self.generate()


class NativeEngineOrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = self.root / "app"
        self.app.mkdir()
        self.build = self.root / ".runs/build"
        self.build.mkdir(parents=True)
        self.core = self.app / "core.go"
        self.core.write_text("package main\n// original owned core\n", encoding="utf-8")
        self.main = self.app / "main.go"
        self.main.write_text("package main\n// ordinary application\n", encoding="utf-8")
        self.spec = self.app / "integration.json"
        write(self.spec, {"schema_version": 1, "kind": engine.SPEC_KIND, "language": "go",
                          "application_sources": ["main.go"]})
        self.cases = self.app / "application-contract.json"
        write(self.cases, {"schema_version": 1, "kind": engine.CASE_KIND,
            "cases": [{"label": "normal", "args": ["7"], "expect": {"returncode": 0, "stdout": "42\r\n"}},
                      {"label": "usage", "args": [], "expect": {"returncode": 2, "stdout": ""}}]})
        self.tool = self.root / ".tools/go.exe"
        self.tool.parent.mkdir()
        self.tool.write_bytes(b"mock compiler identity")
        self.compiler = {"go": str(self.tool), "go_root": str(self.tool.parent),
                         "input_hashes": {str(self.tool): sha(self.tool)}, "distribution": {"sha256": "a" * 64}}
        contract = {"schema_version": 1, "library_name": "protected",
                    "functions": [{"name": "go_fold", "return_type": "i32", "parameters": [{"name": "a0", "type": "i32"}]}]}
        self.contract_path = self.build / "frontend/contract.json"
        write(self.contract_path, contract)
        metadata = self.build / "frontend/metadata.json"
        write(metadata, {"package": "main"})
        artifacts = {}
        for arm in ("baseline", "protected"):
            file = self.build / "native" / (arm + ".dll")
            file.parent.mkdir(exist_ok=True)
            file.write_bytes(("mock " + arm).encode())
            artifacts[arm] = {"path": str(file), "sha256": sha(file), "bytes": file.stat().st_size}
        coverage = {"selected_functions": ["go_fold"], "functions": ["go_fold"],
                    "original_vm": {"present": True}, "final_vm": {"present": True}}
        native_path = self.build / "native/report.json"
        write(native_path, {"status": engine.OK_BUILD, "artifacts": artifacts, "coverage": coverage})
        source_hashes = {str(p): sha(p) for p in self.app.iterdir()}
        self.producer = {
            "schema_version": 1, "status": engine.OK_BUILD, "language": "go", "backend": engine.BACKENDS["go"],
            "project": {"language": "go", "project_root": str(self.app), "sources": [str(self.core)],
                        "input_hashes": source_hashes, "functions": ["go_fold"], "compiler": self.compiler},
            "source_hashes": source_hashes, "contract": contract, "contract_path": str(self.contract_path),
            "frontend_artifact_hashes": {"contract.json": sha(self.contract_path), "metadata.json": sha(metadata)},
            "methods": [{"name": "Fold", "export": "go_fold", "is_root": True}],
            "artifacts": artifacts, "coverage": {**coverage, "exported_functions": ["go_fold"]},
            "native_report": str(native_path), "native_report_sha256": sha(native_path)}
        self.report_path = self.build / "report.json"
        write(self.report_path, self.producer)
        self.calls = []
        self.bad_control = False
        self.unclean = False
        self.mutate = False

    def facade(self, producer, output):
        output.mkdir()
        source = output / "facade.go"
        source.write_bytes(b"package main\n// mock forwarding facade only")
        manifest = {"files": {"facade.go": sha(source)}, "compile_sources": ["facade.go"], "c_sources": [], "include_dirs": []}
        write(output / "facade.json", manifest)
        return manifest

    def child(self, argv, cwd, prefix, timeout, *, env, cancel_file):
        self.calls.append({"argv": argv, "cwd": cwd, "env": copy.deepcopy(env), "stop": cancel_file})
        prefix.parent.mkdir(parents=True, exist_ok=True)
        rc, output = 0, ""
        if argv[0] == str(self.tool):
            executable = Path(argv[argv.index("-o") + 1])
            executable.write_bytes(("mock " + executable.parent.name + " executable").encode())
        else:
            assert Path(argv[0]).name == "app.exe"
            if len(argv) == 1:
                rc = 2
            elif Path(cwd).name == "protected" and (
                    not env.get("ANTIREA_NATIVE_CORE") or not Path(env["ANTIREA_NATIVE_CORE"]).is_file()):
                rc = 0 if self.bad_control else 3
            else:
                output = "42\r\n"
        stdout, stderr = prefix.with_suffix(".stdout.log"), prefix.with_suffix(".stderr.log")
        stdout.write_bytes(output.encode())
        stderr.write_bytes(b"")
        pid = 100 + len(self.calls)
        proc = {"argv": argv, "pid": pid, "returncode": rc, "timed_out": False, "cancelled": False,
                "stdout": str(stdout), "stderr": str(stderr),
                "cleanup": {"method": "windows_job", "job_assigned": not self.unclean, "parent_pid": pid,
                            "parent_exit_confirmed": True, "active_after": 0,
                            "status": "assigned_job_empty", "job_handle_closed": True}}
        write(prefix.with_suffix(".process.json"), proc)
        if self.mutate:
            self.main.write_bytes(b"changed input during child")
        return proc

    def run_engine(self):
        with patch.object(engine, "_compiler", return_value=self.compiler), \
                patch.object(engine, "_facade_manifest", side_effect=self.facade), \
                patch.object(engine.process, "run_logged", side_effect=self.child):
            return engine.run_integration(producer_report_path=self.report_path, integration_spec_path=self.spec,
                application_contract_path=self.cases, output_dir=self.root / ".runs/integration", workspace_root=self.root)

    def test_mocked_flow_preserves_raw_crlf_and_exact_references(self):
        result = self.run_engine()
        self.assertEqual(result["status"], "native_application_samples_passed", result.get("error"))
        self.assertEqual(len(self.calls), 8)  # 2 compile + 4 case arms + 2 controls
        self.assertEqual(result["comparison"]["cases"][0]["baseline"]["stdout"], "42\r\n")
        expected = {"label", "kind", "arm", "case_label", "control",
                    "receipt_path", "receipt_sha256", "stdout_log", "stderr_log"}
        self.assertTrue(all(set(row) == expected for row in result["comparison"]["commands"]))
        self.assertEqual(result["deployment"]["allowlist"], ["app.exe", "protected.dll"])
        self.assertEqual(json.loads((self.root / ".runs/integration/integration.json").read_bytes()), result)

    def test_protected_compile_never_contains_core_and_uses_same_app_bytes(self):
        result = self.run_engine()
        self.assertEqual(result["status"], "native_application_samples_passed")
        original, protected = self.calls[:2]
        self.assertTrue(any(Path(v).name == "core.go" for v in original["argv"]))
        self.assertFalse(any(Path(v).name == "core.go" for v in protected["argv"]))
        app_inputs = [next(Path(v) for v in row["argv"] if Path(v).name == "main.go") for row in (original, protected)]
        self.assertEqual(app_inputs[0].read_bytes(), app_inputs[1].read_bytes())

    def test_control_cannot_succeed_without_core(self):
        self.bad_control = True
        result = self.run_engine()
        self.assertEqual(result["status"], "failed")
        self.assertIn("succeeded without native core", result["error"])

    def test_unclean_receipt_cannot_pass(self):
        self.unclean = True
        result = self.run_engine()
        self.assertEqual(result["status"], "failed")
        self.assertIn("unclean Windows Job", result["error"])

    def test_mutation_during_child_stops_before_next_command(self):
        self.mutate = True
        result = self.run_engine()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(len(self.calls), 1)
        self.assertIn("hash mismatch", result["error"])

    def test_compiler_environment_never_copies_ambient_injection(self):
        with patch.dict(os.environ, {"GOFLAGS": "-toolexec=evil", "CL": "evil", "LD_PRELOAD": "evil"}):
            result = self.run_engine()
        self.assertEqual(result["status"], "native_application_samples_passed")
        for row in self.calls:
            for name in ("GOFLAGS", "CL", "LD_PRELOAD"):
                self.assertNotIn(name, row["env"])
            self.assertEqual(row["stop"], self.root / ".runs/defense-loop/STOP")
            self.assertTrue(Path(row["env"]["TEMP"]).is_relative_to(self.root / ".runs/integration"))
        self.assertEqual(self.calls[0]["env"]["GOPROXY"], "off")
        self.assertEqual(self.calls[0]["env"]["CGO_ENABLED"], "0")

    def test_bad_timeout_is_rejected_before_filesystem_or_execution(self):
        with patch.object(engine, "_path") as path, patch.object(engine.process, "run_logged") as execute:
            for value in (True, 0, 601, "120", 1.1):
                with self.subTest(value=value), self.assertRaises(engine.NativeIntegrateError):
                    engine.run_integration(producer_report_path="unused", integration_spec_path="unused",
                        application_contract_path="unused", output_dir="unused", workspace_root="unused",
                        timeout_seconds=value)
            path.assert_not_called()
            execute.assert_not_called()

    def test_loader_rejects_added_project_file(self):
        (self.app / "new.go").write_bytes(b"package main")
        with self.assertRaisesRegex(engine.NativeIntegrateError, "membership"):
            engine.load_producer_report(self.report_path, workspace_root=self.root)

    def test_loader_rejects_native_origin_disagreement(self):
        self.producer["artifacts"]["protected"]["bytes"] += 1
        write(self.report_path, self.producer)
        with self.assertRaisesRegex(engine.NativeIntegrateError, "origin mismatch"):
            engine.load_producer_report(self.report_path, workspace_root=self.root)

    def test_source_mutation_before_copy_cannot_be_repinned(self):
        pins = {str(self.main): sha(self.main)}
        self.main.write_bytes(b"changed before staging")
        with self.assertRaisesRegex(engine.NativeIntegrateError, "changed before staging"):
            engine._copy(self.main, self.root / "copy.go", pins)


if __name__ == "__main__":
    unittest.main()
