"""Adversarial / fail-closed seam tests for the Go/Swift native application route.

AUDIT lane (Phase22). These are DIRECT pure negative tests of the REAL landed
engine seams in ``antirea.native_app_integration`` (loaders, facade-manifest gate,
deployment gate, and the ``_relative`` / ``_claim`` path/hash guards) and of the
real ``generate_facade`` guards in both facade modules. They build small on-disk
fixtures and assert the seam rejects malformed input by raising its lane error; a
handful of positive checks assert that a valid fixture is accepted so the negatives
cannot pass vacuously.

Scope and honesty (per the Phase22 brief and AGENTS.md):
- These are PURE tests: no compiler, target binary, or subprocess is executed. No
  owned application or producer is built. A mock stands in ONLY for the facade
  ``generate_facade`` collaborator inside the ``_facade_manifest`` test so the real
  engine validation gate is exercised; it is not a placeholder.
- They are AUTHORED here; the audit lane has NOT run them. Pure/mock tests are not
  a compiler/application qualification. Execution is gated on root's RUN-READY
  signal and the shared focused runner; this file is run only through that runner,
  never raw, and no ref-key assertion was invented (finding B1 was resolved by root
  in the engine draft: case children use kind ``case_arm`` and controls ``control``,
  each with the full None-filled key set).
- The reserved-path lexical guard (rea-analysis-reports / attackerfolder /
  env.setting / linkrepro) is verified by read-only review; this lane does NOT
  construct those path components in any fixture.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

import antirea.native_app_integration as nai
import antirea.go_application_facade as gof
import antirea.swift_application_facade as swf

_REMOVE = object()  # sentinel: drop a key from a base fixture dict
ZERO_DIGEST = "0" * 64


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _write(path: Path, text: str) -> str:
    """Write UTF-8 text with LF newlines; return its sha256 hex digest."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
    return _sha256_text(text)


def _key(path: Path) -> str:
    """Canonical pin key exactly as the engine computes it (abspath, no-links)."""
    return str(nai._path(path))


class RelativePathGuardTests(unittest.TestCase):
    """``_relative`` is the clean-relative-slash-path gate every seam depends on."""

    def test_rejects_backslash_colon_parent_absolute_and_blank(self):
        for bad in ("a\\b", "C:bad", "a/../b", "/abs", "a//b", "", "   ",
                    "trailing ", " leading", "a/./b", "x\x00y"):
            with self.subTest(bad=bad):
                with self.assertRaises(nai.NativeIntegrateError):
                    nai._relative(bad)

    def test_rejects_non_string(self):
        for bad in (None, 3, ["a"], Path("a")):
            with self.subTest(bad=bad):
                with self.assertRaises(nai.NativeIntegrateError):
                    nai._relative(bad)

    def test_accepts_clean_nested_relative_path(self):
        self.assertEqual(nai._relative("pkg/app.go"), Path("pkg/app.go"))


class ClaimHashGuardTests(unittest.TestCase):
    """``_claim`` authenticates a file by exact sha256 and authorized parent."""

    def test_rejects_malformed_digest(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "f.bin"
            digest = _write(target, "payload\n")
            for bad in ("", "xyz", digest.upper(), digest[:-1], digest + "0", 123, None):
                with self.subTest(bad=bad):
                    with self.assertRaises(nai.NativeIntegrateError):
                        nai._claim(target, bad)

    def test_rejects_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "f.bin"
            _write(target, "real-content\n")
            with self.assertRaises(nai.NativeIntegrateError):
                nai._claim(target, ZERO_DIGEST)

    def test_rejects_parent_escape(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            authorized = root / "inside"
            authorized.mkdir()
            outside = root / "outside.bin"
            digest = _write(outside, "x\n")
            with self.assertRaises(nai.NativeIntegrateError):
                nai._claim(outside, digest, parent=authorized)

    def test_accepts_authentic_file(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            target = root / "sub" / "f.bin"
            digest = _write(target, "authentic\n")
            self.assertEqual(nai._claim(target, digest, parent=root), nai._path(target))


class ApplicationContractTests(unittest.TestCase):
    """``load_application_contract`` — strict schema + reused case validator."""

    def _load(self, root: Path, payload) -> dict:
        contract = root / "application-contract.json"
        _write(contract, json.dumps(payload))
        return nai.load_application_contract(contract, workspace_root=root)

    def _ok_case(self, label="ok", rc=0, stdout="42\n", args=None):
        return {"label": label, "args": args or ["7", "3"], "expect": {"returncode": rc, "stdout": stdout}}

    def test_rejects_contract_outside_workspace(self):
        with tempfile.TemporaryDirectory() as ws, tempfile.TemporaryDirectory() as other:
            contract = Path(other) / "c.json"
            _write(contract, json.dumps({"schema_version": 1, "kind": "native_application_samples",
                                         "cases": [self._ok_case()]}))
            with self.assertRaises(nai.NativeIntegrateError):
                nai.load_application_contract(contract, workspace_root=Path(ws))

    def test_rejects_bad_top_level_shape(self):
        bad_payloads = [
            {"schema_version": 1, "kind": "native_application_samples"},            # missing cases
            {"schema_version": 1, "kind": "native_application_samples",
             "cases": [self._ok_case()], "extra": 1},                               # extra key
            {"schema_version": "1", "kind": "native_application_samples",
             "cases": [self._ok_case()]},                                           # non-int version
            {"schema_version": 2, "kind": "native_application_samples",
             "cases": [self._ok_case()]},                                           # wrong version
            {"schema_version": 1, "kind": "jvm_application_samples",
             "cases": [self._ok_case()]},                                           # wrong kind
        ]
        with tempfile.TemporaryDirectory() as ws:
            for payload in bad_payloads:
                with self.subTest(payload=payload):
                    with self.assertRaises(nai.NativeIntegrateError):
                        self._load(Path(ws), payload)

    def test_rejects_bad_cases(self):
        many = [self._ok_case(label="c%d" % i) for i in range(65)]                  # >64
        bad_case_sets = [
            [],                                                                     # empty
            many,
            [self._ok_case(), self._ok_case()],                                     # duplicate label
            [{"label": "x", "args": [], "expect": {"returncode": 0, "stdout": "", "stderr": ""}}],  # stderr key
            [{"label": "x", "args": [], "expect": {"returncode": True, "stdout": ""}}],             # bool rc
            [self._ok_case(rc=1)],                                                   # no success control
        ]
        with tempfile.TemporaryDirectory() as ws:
            for cases in bad_case_sets:
                with self.subTest(n=len(cases)):
                    with self.assertRaises(nai.NativeIntegrateError):
                        self._load(Path(ws), {"schema_version": 1,
                                              "kind": "native_application_samples", "cases": cases})

    def test_accepts_minimal_valid_contract(self):
        with tempfile.TemporaryDirectory() as ws:
            result = self._load(Path(ws), {"schema_version": 1,
                                           "kind": "native_application_samples",
                                           "cases": [self._ok_case()]})
            self.assertEqual([c["label"] for c in result["cases"]], ["ok"])
            self.assertTrue(result["sha256"])


class IntegrationSpecTests(unittest.TestCase):
    """``load_integration_spec`` — app source membership against the pinned snapshot."""

    def _pinned(self, project_root: Path, language: str, app_files, core_files):
        source_hashes = {}
        for rel, text in {**app_files, **core_files}.items():
            source_hashes[_key(project_root / rel)] = _write(project_root / rel, text)
        return {
            "project_root": str(nai._path(project_root)),
            "language": language,
            "core_sources": [_key(project_root / rel) for rel in core_files],
            "source_hashes": source_hashes,
        }

    def _spec(self, project_root: Path, payload):
        spec = project_root / "integration.json"
        _write(spec, json.dumps(payload))
        return spec

    def test_accepts_valid_go_spec(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            pinned = self._pinned(root, "go", {"main.go": "package main\n"}, {"core.go": "package core\n"})
            spec = self._spec(root, {"schema_version": 1, "kind": "native_application_integration",
                                     "language": "go", "application_sources": ["main.go"]})
            result = nai.load_integration_spec(spec, workspace_root=root, pinned=pinned)
            self.assertEqual([r["relative"] for r in result["application_sources"]], ["main.go"])

    def test_rejects_bad_spec_shape(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            pinned = self._pinned(root, "go", {"main.go": "package main\n"}, {"core.go": "package core\n"})
            bad = [
                {"schema_version": 1, "kind": "jvm_application_integration",
                 "language": "go", "application_sources": ["main.go"]},             # wrong kind
                {"schema_version": 1, "kind": "native_application_integration",
                 "language": "swift", "application_sources": ["main.go"]},          # language mismatch
                {"schema_version": 1, "kind": "native_application_integration",
                 "language": "go", "application_sources": ["main.go"], "x": 1},     # extra key
                {"schema_version": 1, "kind": "native_application_integration",
                 "language": "go", "application_sources": []},                      # empty
                {"schema_version": 1, "kind": "native_application_integration",
                 "language": "go", "application_sources": ["main.go", "main.go"]},  # duplicate
            ]
            for payload in bad:
                with self.subTest(payload=payload):
                    with self.assertRaises(nai.NativeIntegrateError):
                        nai.load_integration_spec(self._spec(root, payload), workspace_root=root, pinned=pinned)

    def test_rejects_core_overlap_and_unpinned_and_badsuffix(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            pinned = self._pinned(root, "go", {"main.go": "package main\n"}, {"core.go": "package core\n"})
            # an on-disk file that is NOT part of the pinned snapshot
            _write(root / "stray.go", "package main\n")
            # a wrong-suffix file that IS pinned (so only the suffix check can fire)
            pinned["source_hashes"][_key(root / "main.txt")] = _write(root / "main.txt", "x\n")
            for sources in (["core.go"], ["stray.go"], ["main.txt"]):
                with self.subTest(sources=sources):
                    payload = {"schema_version": 1, "kind": "native_application_integration",
                               "language": "go", "application_sources": sources}
                    with self.assertRaises(nai.NativeIntegrateError):
                        nai.load_integration_spec(self._spec(root, payload), workspace_root=root, pinned=pinned)

    def test_rejects_source_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            pinned = self._pinned(root, "go", {"main.go": "package main\n"}, {"core.go": "package core\n"})
            # mutate the file on disk so its content no longer matches the pinned hash
            _write(root / "main.go", "package main // tampered\n")
            payload = {"schema_version": 1, "kind": "native_application_integration",
                       "language": "go", "application_sources": ["main.go"]}
            with self.assertRaises(nai.NativeIntegrateError):
                nai.load_integration_spec(self._spec(root, payload), workspace_root=root, pinned=pinned)

    def test_swift_requires_exactly_one_main(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            pinned = self._pinned(root, "swift",
                                  {"main.swift": "print(1)\n", "other.swift": "let x = 1\n"},
                                  {"core.swift": "let c = 0\n"})
            # zero main.swift among the selected application sources
            payload0 = {"schema_version": 1, "kind": "native_application_integration",
                        "language": "swift", "application_sources": ["other.swift"]}
            with self.assertRaises(nai.NativeIntegrateError):
                nai.load_integration_spec(self._spec(root, payload0), workspace_root=root, pinned=pinned)


class ProducerReportFailClosedTests(unittest.TestCase):
    """``load_producer_report`` early authentication gates (fail closed).

    These exercise the gates reachable with a partial fixture; the deeper
    contract/coverage/artifact chain needs a near-complete authentic producer
    (root-owned fresh build) and is intentionally out of scope for the pure lane.
    Each payload carries ``schema_version: 1`` so the intended gate (not the
    schema-version gate) is the one that fires.
    """

    def _report(self, root: Path, payload, *, under_runs=True):
        directory = (root / ".runs" / "producer") if under_runs else (root / "elsewhere")
        report = directory / "report.json"
        _write(report, json.dumps(payload))
        return report

    def test_rejects_report_outside_runs(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            report = self._report(root, {"schema_version": 1, "language": "go"}, under_runs=False)
            with self.assertRaises(nai.NativeIntegrateError) as ctx:
                nai.load_producer_report(report, workspace_root=root)
            self.assertIn(".runs", str(ctx.exception))

    def test_rejects_non_go_or_swift_language(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            report = self._report(root, {"schema_version": 1, "language": "python"})
            with self.assertRaises(nai.NativeIntegrateError) as ctx:
                nai.load_producer_report(report, workspace_root=root)
            self.assertIn("Go or Swift", str(ctx.exception))

    def test_rejects_wrong_backend_or_status(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for payload in (
                {"schema_version": 1, "language": "go", "backend": "wrong", "status": nai.OK_BUILD},
                {"schema_version": 1, "language": "go", "backend": "go_typed_native", "status": "building"},
            ):
                with self.subTest(payload=payload):
                    report = self._report(root, payload)
                    with self.assertRaises(nai.NativeIntegrateError) as ctx:
                        nai.load_producer_report(report, workspace_root=root)
                    self.assertIn("successful matching source build", str(ctx.exception))

    def test_rejects_project_identity_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            payload = {"schema_version": 1, "language": "go", "backend": "go_typed_native",
                       "status": nai.OK_BUILD, "project": {"language": "swift"}}
            report = self._report(root, payload)
            with self.assertRaises(nai.NativeIntegrateError) as ctx:
                nai.load_producer_report(report, workspace_root=root)
            self.assertIn("project identity", str(ctx.exception))

    def test_rejects_contradictory_source_snapshot(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            project_root = root / "project"
            project_root.mkdir()
            payload = {"schema_version": 1, "language": "go", "backend": "go_typed_native",
                       "status": nai.OK_BUILD,
                       "project": {"language": "go", "project_root": str(project_root),
                                   "input_hashes": {str(project_root / "core.go"): ZERO_DIGEST}},
                       "source_hashes": {str(project_root / "core.go"): "1" * 64}}
            report = self._report(root, payload)
            with self.assertRaises(nai.NativeIntegrateError) as ctx:
                nai.load_producer_report(report, workspace_root=root)
            self.assertIn("source snapshot", str(ctx.exception))

    def test_rejects_project_root_inside_runs(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            project_root = root / ".runs" / "project"      # a core tree must be owned source, not .runs
            project_root.mkdir(parents=True)
            payload = {"schema_version": 1, "language": "go", "backend": "go_typed_native",
                       "status": nai.OK_BUILD,
                       "project": {"language": "go", "project_root": str(project_root),
                                   "input_hashes": {str(project_root / "core.go"): ZERO_DIGEST}},
                       "source_hashes": {str(project_root / "core.go"): ZERO_DIGEST}}
            report = self._report(root, payload)
            with self.assertRaises(nai.NativeIntegrateError) as ctx:
                nai.load_producer_report(report, workspace_root=root)
            self.assertIn("owned source tree", str(ctx.exception))


class DeploymentGateTests(unittest.TestCase):
    """``_deployment`` — exact allowlist, .exe/.dll suffixes, forbidden-hash reject."""

    def _bundle(self, root: Path, files: dict):
        directory = root / "deployment"
        directory.mkdir()
        shas = {name: _write(directory / name, text) for name, text in files.items()}
        return directory, shas

    def test_accepts_exact_allowlist(self):
        with tempfile.TemporaryDirectory() as d:
            directory, _ = self._bundle(Path(d), {"app.exe": "APP\n", "protected.dll": "DLL\n"})
            result = nai._deployment(directory, ["app.exe", "protected.dll"], set())
            self.assertEqual(result["executable"], "app.exe")
            self.assertEqual(result["native_core"], "protected.dll")
            self.assertEqual(result["runtime_files"], [])
            self.assertTrue(result["forbidden_absent"])

    def test_rejects_inventory_not_equal_allowlist(self):
        with tempfile.TemporaryDirectory() as d:
            directory, _ = self._bundle(Path(d), {"app.exe": "APP\n", "protected.dll": "DLL\n",
                                                  "stray.dll": "X\n"})
            with self.assertRaises(nai.NativeIntegrateError):
                nai._deployment(directory, ["app.exe", "protected.dll"], set())

    def test_rejects_duplicate_allowlist(self):
        with tempfile.TemporaryDirectory() as d:
            directory, _ = self._bundle(Path(d), {"app.exe": "APP\n", "protected.dll": "DLL\n"})
            with self.assertRaises(nai.NativeIntegrateError):
                nai._deployment(directory, ["app.exe", "protected.dll", "app.exe"], set())

    def test_rejects_non_exe_dll_suffix(self):
        with tempfile.TemporaryDirectory() as d:
            directory, _ = self._bundle(Path(d), {"app.exe": "APP\n", "protected.dll": "DLL\n",
                                                  "notes.txt": "N\n"})
            with self.assertRaises(nai.NativeIntegrateError):
                nai._deployment(directory, ["app.exe", "protected.dll", "notes.txt"], set())

    def test_rejects_forbidden_hash(self):
        with tempfile.TemporaryDirectory() as d:
            directory, shas = self._bundle(Path(d), {"app.exe": "APP\n", "protected.dll": "DLL\n"})
            with self.assertRaises(nai.NativeIntegrateError):
                nai._deployment(directory, ["app.exe", "protected.dll"], {shas["protected.dll"]})


class FacadeManifestGateTests(unittest.TestCase):
    """``_facade_manifest`` validation gate, driven through a mock generator.

    A stub stands in for ``<lang>_application_facade.generate_facade`` ONLY as the
    collaborator so the engine's REAL validation of the persisted ``facade.json``
    (including the current exact root ABI/name cross-check against the pinned
    ``contract_path`` and the producer methods/source_functions) is exercised
    against crafted-malformed output.
    """

    def _contract(self, language):
        name = "go_fold" if language == "go" else "swift_fold"
        return {"schema_version": 1, "library_name": "core",
                "functions": [{"name": name, "return_type": "i32",
                               "parameters": [{"name": "a0", "type": "i32"}]}]}

    def _fixture(self, language):
        """Return (producer, files_content, manifest) mutually consistent for ``language``."""
        if language == "go":
            files_content = {
                "go/native_core.go": "package nativecore\n",
                "go/native_core_windows_amd64.go": "package nativecore\n",
                "go/antirea_facade.go": "package main\n",
            }
            compile_sources = ["go/antirea_facade.go", "go/native_core_windows_amd64.go"]
            c_sources, include_dirs = [], []
            source_roots = [{"source_name": "Fold", "export": "go_fold", "return_type": "i32",
                             "parameters": [{"name": "a0", "type": "i32"}], "external_labels": []}]
            producer = {"language": "go",
                        "methods": [{"export": "go_fold", "name": "Fold", "is_root": True}]}
        else:
            files_content = {
                "bindings/common/antirea_bridge.c": "/* bridge */\n",
                "bindings/common/antirea_bridge.h": "/* header */\n",
                "bindings/swift/NativeCore.swift": "import Foundation\n",
                "bindings/swift/module.modulemap": "module AntireaBridge {}\n",
                "protected/NativeFacade.swift": "// facade\n",
            }
            compile_sources = ["bindings/swift/NativeCore.swift", "protected/NativeFacade.swift"]
            c_sources, include_dirs = ["bindings/common/antirea_bridge.c"], ["bindings/swift"]
            source_roots = [{"source_name": "fold", "export": "swift_fold", "return_type": "i32",
                             "parameters": [{"name": "a0", "type": "i32"}], "external_labels": ["_"]}]
            producer = {"language": "swift",
                        "source_functions": [{"name": "swift_fold", "swift_name": "fold"}]}
        manifest = {
            "schema_version": 1, "kind": "native_application_facade",
            "status": "generated_not_validated", "language": language,
            "files": {rel: _sha256_text(text) for rel, text in files_content.items()},
            "compile_sources": compile_sources, "c_sources": c_sources,
            "include_dirs": include_dirs, "source_roots": source_roots,
            "loader_environment": "ANTIREA_NATIVE_CORE",
            "original_core_sources_included": False, "limitations": [],
        }
        return producer, files_content, manifest

    def _run(self, language, files_content, manifest, producer, *, facade_json=None, extra_files=None):
        def generate_facade(prod, output):
            output = Path(output)
            output.mkdir(parents=True, exist_ok=False)
            for rel, text in files_content.items():
                _write(output / rel, text)
            for rel, text in (extra_files or {}).items():
                _write(output / rel, text)
            payload = manifest if facade_json is None else facade_json
            with (output / "facade.json").open("w", encoding="utf-8", newline="\n") as stream:
                json.dump(payload, stream, indent=2)
                stream.write("\n")
            return manifest
        stub = types.SimpleNamespace(generate_facade=generate_facade)
        with tempfile.TemporaryDirectory() as d:
            contract_path = Path(d) / "frontend" / "contract.json"
            _write(contract_path, json.dumps(self._contract(language)))
            prod = dict(producer)
            prod["contract_path"] = str(contract_path)
            output = Path(d) / "generated"
            with mock.patch.object(nai, "importlib") as imported:
                imported.import_module.return_value = stub
                return nai._facade_manifest(prod, output)

    def test_accepts_valid_go_and_swift_facade(self):
        for language in ("go", "swift"):
            with self.subTest(language=language):
                producer, files_content, manifest = self._fixture(language)
                result = self._run(language, files_content, manifest, producer)
                self.assertEqual(result["kind"], "native_application_facade")
                self.assertEqual(result["language"], language)
                self.assertEqual([r["export"] for r in result["source_roots"]],
                                 ["go_fold" if language == "go" else "swift_fold"])

    def test_rejects_return_differs_from_persisted(self):
        producer, files_content, manifest = self._fixture("go")
        divergent = {**manifest, "limitations": ["persisted copy was tampered"]}
        with self.assertRaises(nai.NativeIntegrateError):
            self._run("go", files_content, manifest, producer, facade_json=divergent)

    def test_rejects_bad_scalar_manifest_fields(self):
        producer, files_content, base = self._fixture("go")
        mutations = [
            {**base, "status": "validated"},                         # wrong status token
            {**base, "loader_environment": "PATH"},                  # wrong loader env
            {**base, "original_core_sources_included": True},        # must be False
            {**base, "kind": "jvm_application_facade"},              # wrong kind
            {k: v for k, v in base.items() if k != "limitations"},  # missing required key
            {**base, "unexpected": 1},                               # extra key
        ]
        for manifest in mutations:
            with self.subTest(status=manifest.get("status"), nkeys=len(manifest)):
                with self.assertRaises(nai.NativeIntegrateError):
                    self._run("go", files_content, manifest, producer)

    def test_rejects_unlisted_generated_file(self):
        producer, files_content, manifest = self._fixture("go")
        with self.assertRaises(nai.NativeIntegrateError):
            self._run("go", files_content, manifest, producer,
                      extra_files={"go/unlisted.go": "package main\n"})

    def test_rejects_file_hash_mismatch(self):
        producer, files_content, manifest = self._fixture("go")
        tampered = {**manifest, "files": {**manifest["files"], "go/antirea_facade.go": ZERO_DIGEST}}
        with self.assertRaises(nai.NativeIntegrateError):
            self._run("go", files_content, tampered, producer)

    def test_rejects_go_facade_with_native_bridge(self):
        producer, files_content, manifest = self._fixture("go")
        files_content = {**files_content, "common/bridge.c": "/* x */\n"}
        bad = {**manifest, "files": {**manifest["files"], "common/bridge.c": _sha256_text("/* x */\n")},
               "c_sources": ["common/bridge.c"]}
        with self.assertRaises(nai.NativeIntegrateError):
            self._run("go", files_content, bad, producer)

    def test_rejects_swift_facade_without_single_bridge(self):
        producer, files_content, manifest = self._fixture("swift")
        bad = {**manifest, "c_sources": []}                          # Swift needs exactly one C bridge
        with self.assertRaises(nai.NativeIntegrateError):
            self._run("swift", files_content, bad, producer)

    def test_rejects_root_metadata_mismatch_with_producer(self):
        # Exercises the current gate's exact-ABI/name cross-check against the producer.
        producer, files_content, manifest = self._fixture("go")
        bad = {**manifest, "source_roots": [{**manifest["source_roots"][0], "source_name": "NotFold"}]}
        with self.assertRaises(nai.NativeIntegrateError):
            self._run("go", files_content, bad, producer)


class GoGenerateFacadeFailClosedTests(unittest.TestCase):
    """Direct negative tests of the REAL ``go_application_facade.generate_facade``.

    Output-dir guards and the ``_validate_producer`` gates that run before any file
    is written. The reserved-path lexical guard is verified by read-only review; this
    lane does not construct those path components. The deeper pinned-read /
    cross-validation chain needs a full on-disk authentic producer (root-owned).
    """

    def _producer(self, **overrides):
        base = {
            "schema_version": 1, "status": "artifact_created_unvalidated",
            "backend": "go_typed_native", "language": "go",
            "project": {"selectors": [{"name": "Fold", "export": "go_fold"}]},
            "methods": [{"name": "Fold", "export": "go_fold", "is_root": True,
                         "parameters": ["int32"], "return_type": "int32"}],
            "contract": {"schema_version": 1, "library_name": "core",
                         "functions": [{"name": "go_fold", "return_type": "i32",
                                        "parameters": [{"name": "a0", "type": "i32"}]}]},
            "contract_path": "frontend/contract.json",
            "frontend_artifact_hashes": {"metadata.json": "a" * 64, "contract.json": "b" * 64},
        }
        for key, value in overrides.items():
            if value is _REMOVE:
                base.pop(key, None)
            else:
                base[key] = value
        return base

    def test_rejects_output_dir_that_exists(self):
        with tempfile.TemporaryDirectory() as d:
            existing = Path(d) / "out"
            existing.mkdir()
            with self.assertRaises(gof.GoAppFacadeError):
                gof.generate_facade(self._producer(), existing)

    def test_rejects_output_dir_in_intake_inbox(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "defense-loop" / "inbox" / "out"   # never created; lexical guard
            with self.assertRaises(gof.GoAppFacadeError):
                gof.generate_facade(self._producer(), target)

    def test_rejects_malformed_producer_before_any_write(self):
        cases = [
            (self._producer(schema_version=2), "schema_version must be 1"),
            (self._producer(status="building"), "artifact_created_unvalidated"),
            (self._producer(backend="other_native"), "go_typed_native"),
            (self._producer(language="rust"), "language must be go"),
            (self._producer(project=_REMOVE), "project must be the frontend inspection"),
            (self._producer(project={"selectors": []}), "selectors must be a 1.."),
            (self._producer(methods=_REMOVE), "methods must be the non-empty method"),
            (self._producer(contract=_REMOVE), "contract must be the inline"),
            (self._producer(contract_path=_REMOVE), "contract_path must be a non-empty"),
            (self._producer(frontend_artifact_hashes={"metadata.json": "a" * 64}), "contract.json'"),
        ]
        with tempfile.TemporaryDirectory() as d:
            for index, (producer, needle) in enumerate(cases):
                out = Path(d) / ("case%02d" % index)   # a fresh, non-existent output dir each time
                with self.subTest(needle=needle):
                    with self.assertRaises(gof.GoAppFacadeError) as ctx:
                        gof.generate_facade(producer, out)
                    self.assertIn(needle, str(ctx.exception))
                    self.assertFalse(out.exists(), "facade must not create output on a rejected producer")


class SwiftGenerateFacadeFailClosedTests(unittest.TestCase):
    """Direct negative tests of the REAL ``swift_application_facade.generate_facade``.

    Output-dir guards plus the ``_validate_producer`` gates that precede any write.
    Reserved-path lexical guard verified by review only (not constructed here); the
    pinned interface/contract authentication chain needs a full authentic producer.
    """

    def _producer(self, **overrides):
        base = {
            "schema_version": 1, "status": "artifact_created_unvalidated",
            "backend": "swift_llvm_native", "language": "swift",
            "project": {"language": "swift"},
            "source_functions": [{"export": "swift_fold", "swift_name": "fold",
                                  "parameters": [{"type": "i32"}], "return_type": "i32"}],
            "exported_functions": ["swift_fold"],
            "public_interface": {"path": "frontend/core.swiftinterface", "sha256": "a" * 64},
            "artifact_hashes": {"frontend/contract.json": "b" * 64},
            "contract_path": "frontend/contract.json",
        }
        for key, value in overrides.items():
            if value is _REMOVE:
                base.pop(key, None)
            else:
                base[key] = value
        return base

    def test_rejects_output_dir_that_exists(self):
        with tempfile.TemporaryDirectory() as d:
            existing = Path(d) / "out"
            existing.mkdir()
            with self.assertRaises(swf.SwiftFacadeError):
                swf.generate_facade(self._producer(), existing)

    def test_rejects_output_dir_in_intake_inbox(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "defense-loop" / "inbox" / "out"   # never created; lexical guard
            with self.assertRaises(swf.SwiftFacadeError):
                swf.generate_facade(self._producer(), target)

    def test_rejects_malformed_producer_before_any_write(self):
        cases = [
            (self._producer(schema_version=2), "schema_version must be 1"),
            (self._producer(status="building"), "successful Swift source build"),
            (self._producer(backend="x"), "swift_llvm_native"),
            (self._producer(language="go"), "language must be swift"),
            (self._producer(project=_REMOVE), "swift project description"),
            (self._producer(project={"language": "go"}), "swift project description"),
            (self._producer(source_functions=_REMOVE), "source_functions must be"),
            (self._producer(exported_functions=_REMOVE), "exported_functions must be"),
            (self._producer(public_interface=_REMOVE), "public_interface must be"),
            (self._producer(artifact_hashes=_REMOVE), "artifact_hashes must pin"),
            (self._producer(contract_path=_REMOVE), "contract_path must point"),
        ]
        with tempfile.TemporaryDirectory() as d:
            for index, (producer, needle) in enumerate(cases):
                out = Path(d) / ("case%02d" % index)
                with self.subTest(needle=needle):
                    with self.assertRaises(swf.SwiftFacadeError) as ctx:
                        swf.generate_facade(producer, out)
                    self.assertIn(needle, str(ctx.exception))
                    self.assertFalse(out.exists(), "facade must not create output on a rejected producer")


if __name__ == "__main__":
    unittest.main()
