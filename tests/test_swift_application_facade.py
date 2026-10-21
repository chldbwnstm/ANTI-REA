"""Pure, offline tests for antirea.swift_application_facade.

No compiler, target, application or subprocess runs here. A producer report is
synthesized in a private temporary directory together with a compiler-style
``.swiftinterface`` and the pinned ``frontend/contract.json`` (with real
SHA-256 digests), exactly as the facade module's authorized readers expect.
These exercise producer validation, pinned-metadata authentication, external
label parsing/preservation and source generation only. They are pure/mock unit
tests, not a compiler or application qualification.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from antirea import swift_application_facade as f
from antirea import bindings


SAMPLES = Path(__file__).resolve().parents[1] / "samples" / "multilang" / "swift_application"


# --- canonical 4-root fixture (mirrors samples/multilang/swift_application) ---
IFACE_4 = (
    "// swift-interface-format-version: 1.0\n"
    "// swift-module-flags: -module-name AntireaOwned -enable-library-evolution\n"
    "import Swift\n"
    '@_cdecl("swift_score")\n'
    "public func swift_score(_ x: Swift.UInt64, _ y: Swift.UInt64) -> Swift.UInt64\n"
    '@_cdecl("swift_signed")\n'
    "public func swift_signed(_ x: Swift.Int64, _ y: Swift.Int64) -> Swift.Int64\n"
    '@_cdecl("swift_unsigned32")\n'
    "public func swift_unsigned32(x: Swift.UInt32, y: Swift.UInt32) -> Swift.UInt32\n"
    '@_cdecl("swift_signed32")\n'
    "public func swift_signed32(x: Swift.Int32, y: Swift.Int32) -> Swift.Int32\n"
)

SF_4 = [
    {"name": "swift_score", "swift_name": "swift_score", "return_type": "u64",
     "parameters": [{"name": "x", "type": "u64"}, {"name": "y", "type": "u64"}]},
    {"name": "swift_signed", "swift_name": "swift_signed", "return_type": "i64",
     "parameters": [{"name": "x", "type": "i64"}, {"name": "y", "type": "i64"}]},
    {"name": "swift_unsigned32", "swift_name": "swift_unsigned32", "return_type": "u32",
     "parameters": [{"name": "x", "type": "u32"}, {"name": "y", "type": "u32"}]},
    {"name": "swift_signed32", "swift_name": "swift_signed32", "return_type": "i32",
     "parameters": [{"name": "x", "type": "i32"}, {"name": "y", "type": "i32"}]},
]
EXPORTS_4 = ["swift_score", "swift_signed", "swift_unsigned32", "swift_signed32"]


def _contract_from(source_functions):
    return {"schema_version": 1, "library_name": "protected",
            "functions": [{k: sf[k] for k in ("name", "return_type", "parameters")}
                          for sf in source_functions]}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_producer(base: Path, *, interface_text=IFACE_4, source_functions=None,
                   contract=None, exports=None, contract_sha=None, interface_sha=None,
                   overrides=None):
    """Write the pinned interface + contract into ``base/frontend`` and return a
    producer report dict referencing them with real (or overridden) digests."""
    source_functions = SF_4 if source_functions is None else source_functions
    exports = EXPORTS_4 if exports is None else exports
    contract = _contract_from(source_functions) if contract is None else contract
    frontend = base / "frontend"
    frontend.mkdir(parents=True, exist_ok=True)

    contract_bytes = (json.dumps(contract, indent=2) + "\n").encode("utf-8")
    contract_path = frontend / "contract.json"
    contract_path.write_bytes(contract_bytes)

    interface_bytes = interface_text.encode("utf-8")
    interface_path = frontend / "AntireaOwned.swiftinterface"
    interface_path.write_bytes(interface_bytes)

    producer = {
        "schema_version": 1,
        "status": f.PRODUCER_STATUS,
        "backend": f.PRODUCER_BACKEND,
        "language": "swift",
        "project": {"schema_version": 1, "name": "swift-app-core", "language": "swift",
                    "sources": ["core.swift"], "functions": list(exports)},
        "source_functions": source_functions,
        "exported_functions": list(exports),
        "public_interface": {"path": str(interface_path),
                             "sha256": interface_sha or _sha(interface_bytes)},
        "artifact_hashes": {"frontend/contract.json": contract_sha or _sha(contract_bytes),
                            "report.json": "00" * 32},
        "contract_path": str(contract_path),
    }
    if overrides:
        producer.update(overrides)
    return producer


class SwiftFacadeHappyPath(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="antirea-swiftfacade-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.out = self.base / "out"

    def _generate(self, **kwargs):
        producer = build_producer(self.base, **kwargs)
        return producer, f.generate_facade(producer, self.out)

    def test_schema_and_fixed_fields(self):
        _producer, report = self._generate()
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["kind"], "native_application_facade")
        self.assertEqual(report["status"], "generated_not_validated")
        self.assertEqual(report["language"], "swift")
        self.assertEqual(report["loader_environment"], "ANTIREA_NATIVE_CORE")
        self.assertIs(report["original_core_sources_included"], False)
        self.assertEqual(report["compile_sources"],
                         ["bindings/swift/NativeCore.swift", "protected/NativeFacade.swift"])
        self.assertEqual(report["c_sources"], ["bindings/common/antirea_bridge.c"])
        self.assertEqual(report["include_dirs"], ["bindings/swift"])
        self.assertIsInstance(report["limitations"], list)
        self.assertTrue(report["limitations"])
        # Exactly the fixed schema keys root depends on - no extra fields.
        self.assertEqual(set(report), {
            "schema_version", "kind", "status", "language", "files", "compile_sources",
            "c_sources", "include_dirs", "source_roots", "loader_environment",
            "original_core_sources_included", "limitations"})

    def test_source_roots_and_external_labels(self):
        _producer, report = self._generate()
        roots = {r["export"]: r for r in report["source_roots"]}
        self.assertEqual(list(roots), EXPORTS_4)  # producer-selected order preserved
        self.assertEqual(roots["swift_score"]["external_labels"], ["_", "_"])
        self.assertEqual(roots["swift_signed"]["external_labels"], ["_", "_"])
        self.assertEqual(roots["swift_unsigned32"]["external_labels"], ["x", "y"])
        self.assertEqual(roots["swift_signed32"]["external_labels"], ["x", "y"])
        self.assertEqual(roots["swift_score"]["source_name"], "swift_score")
        self.assertEqual(roots["swift_score"]["return_type"], "u64")
        self.assertEqual(roots["swift_score"]["parameters"],
                         [{"name": "x", "type": "u64"}, {"name": "y", "type": "u64"}])

    def test_generated_facade_source_preserves_labels_and_forwards(self):
        _producer, _report = self._generate()
        src = (self.out / "protected" / "NativeFacade.swift").read_text(encoding="utf-8")
        # underscore labels preserved
        self.assertIn("public func swift_score(_ x: UInt64, _ y: UInt64) -> UInt64", src)
        self.assertIn("return ProtectedBootstrap.core.call_swift_score(x, y)", src)
        # named labels preserved
        self.assertIn("public func swift_unsigned32(x: UInt32, y: UInt32) -> UInt32", src)
        self.assertIn("return ProtectedBootstrap.core.call_swift_unsigned32(x, y)", src)
        self.assertIn("public func swift_signed32(x: Int32, y: Int32) -> Int32", src)
        # fail-closed bootstrap from the loader environment, once per process
        self.assertIn("enum ProtectedBootstrap", src)
        # Swift 6 (-language-mode 6): non-Sendable NativeCore global needs the
        # narrow nonisolated(unsafe) escape; initialize-once/retained semantics kept.
        self.assertIn("nonisolated(unsafe) static let core: NativeCore", src)
        self.assertIn("ANTIREA_NATIVE_CORE", src)
        self.assertIn("fatalError", src)
        self.assertIn("import AntireaBridge", src)
        # no original algorithm body / helpers / constants leaked into the facade
        for leaked in ("0x9e3779b9", "0x85ebca6b", "mixUnsigned", "mixSigned", "@_cdecl"):
            self.assertNotIn(leaked, src)

    def test_bindings_bundle_materialized_without_original_core(self):
        _producer, report = self._generate()
        self.assertTrue((self.out / "bindings" / "swift" / "NativeCore.swift").is_file())
        self.assertTrue((self.out / "bindings" / "swift" / "module.modulemap").is_file())
        self.assertTrue((self.out / "bindings" / "common" / "antirea_bridge.c").is_file())
        self.assertTrue((self.out / "bindings" / "common" / "antirea_bridge.h").is_file())
        # the private bindings tree is inventoried in files, compile-subset is small
        self.assertIn("bindings/manifest.json", report["files"])
        self.assertIn("bindings/swift/NativeCore.swift", report["files"])
        # no generated file is the original core source
        self.assertNotIn("core.swift", {Path(rel).name for rel in report["files"]})

    def test_files_pin_matches_disk_and_excludes_facade_json(self):
        _producer, report = self._generate()
        self.assertNotIn("facade.json", report["files"])
        for rel, digest in report["files"].items():
            disk = (self.out / rel)
            self.assertTrue(disk.is_file(), rel)
            self.assertEqual(_sha(disk.read_bytes()), digest, rel)
        for rel in (*report["compile_sources"], *report["c_sources"]):
            self.assertIn(rel, report["files"])

    def test_returned_report_equals_persisted_facade_json(self):
        _producer, report = self._generate()
        on_disk = json.loads((self.out / "facade.json").read_text(encoding="utf-8"))
        self.assertEqual(on_disk, report)

    def test_third_label_form_and_zero_arity(self):
        iface = (
            "import Swift\n"
            '@_cdecl("ping")\n'
            "public func ping() -> Swift.Int32\n"
            '@_cdecl("mix")\n'
            "public func mix(first a: Swift.Int32, _ b: Swift.Int32) -> Swift.Int32\n"
        )
        sfs = [
            {"name": "ping", "swift_name": "ping", "return_type": "i32", "parameters": []},
            {"name": "mix", "swift_name": "mix", "return_type": "i32",
             "parameters": [{"name": "a", "type": "i32"}, {"name": "b", "type": "i32"}]},
        ]
        _producer, report = self._generate(interface_text=iface, source_functions=sfs,
                                           exports=["ping", "mix"])
        roots = {r["export"]: r for r in report["source_roots"]}
        self.assertEqual(roots["ping"]["external_labels"], [])
        self.assertEqual(roots["mix"]["external_labels"], ["first", "_"])
        src = (self.out / "protected" / "NativeFacade.swift").read_text(encoding="utf-8")
        self.assertIn("public func ping() -> Int32", src)
        self.assertIn("return ProtectedBootstrap.core.call_ping()", src)
        self.assertIn("public func mix(first a: Int32, _ b: Int32) -> Int32", src)
        self.assertIn("return ProtectedBootstrap.core.call_mix(a, b)", src)


class SwiftFacadeOutputGuards(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="antirea-swiftfacade-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def test_existing_output_dir_rejected(self):
        producer = build_producer(self.base)
        out = self.base / "out"
        out.mkdir()
        with self.assertRaises(f.SwiftFacadeError):
            f.generate_facade(producer, out)

    def test_reserved_output_path_rejected_lexically(self):
        producer = build_producer(self.base)
        for token in ("attackerfolder", "rea-analysis-reports", "env.setting", "LINKREPRO"):
            with self.assertRaises(f.SwiftFacadeError):
                f.generate_facade(producer, self.base / token / "out")

    def test_defense_loop_inbox_rejected(self):
        producer = build_producer(self.base)
        with self.assertRaises(f.SwiftFacadeError):
            f.generate_facade(producer, self.base / "defense-loop" / "inbox" / "out")


class SwiftFacadeProducerValidation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="antirea-swiftfacade-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.out = self.base / "out"

    def _expect_error(self, producer):
        with self.assertRaises(f.SwiftFacadeError):
            f.generate_facade(producer, self.out)
        # a rejected plan must not have created the output tree
        self.assertFalse(self.out.exists())

    def test_bad_status(self):
        self._expect_error(build_producer(self.base, overrides={"status": "failed"}))

    def test_bad_backend(self):
        self._expect_error(build_producer(self.base, overrides={"backend": "go_typed_native"}))

    def test_bad_language(self):
        self._expect_error(build_producer(self.base, overrides={"language": "go"}))

    def test_schema_version(self):
        self._expect_error(build_producer(self.base, overrides={"schema_version": 2}))

    def test_contract_hash_mismatch(self):
        self._expect_error(build_producer(self.base, contract_sha="11" * 32))

    def test_interface_hash_mismatch(self):
        self._expect_error(build_producer(self.base, interface_sha="22" * 32))

    def test_contract_path_not_frontend_contract(self):
        producer = build_producer(self.base)
        producer["contract_path"] = str(self.base / "frontend" / "other.json")
        self._expect_error(producer)

    def test_source_functions_disagree_with_contract_abi(self):
        bad = [dict(sf) for sf in SF_4]
        bad[0] = dict(bad[0])
        bad[0]["parameters"] = [{"name": "x", "type": "i64"}, {"name": "y", "type": "u64"}]
        # contract derived from the pristine SF_4 so it disagrees with source_functions
        self._expect_error(build_producer(self.base, source_functions=bad,
                                          contract=_contract_from(SF_4)))

    def test_swift_name_disagrees_with_interface(self):
        bad = [dict(sf) for sf in SF_4]
        bad[0] = dict(bad[0]); bad[0]["swift_name"] = "renamed"
        self._expect_error(build_producer(self.base, source_functions=bad))

    def test_exports_disagree_with_source_functions(self):
        self._expect_error(build_producer(
            self.base, exports=["swift_score", "swift_signed", "swift_unsigned32"]))

    def test_reserved_runtime_root_name(self):
        iface = (
            "import Swift\n"
            '@_cdecl("NativeCore")\n'
            "public func NativeCore(_ x: Swift.Int32) -> Swift.Int32\n"
        )
        sfs = [{"name": "NativeCore", "swift_name": "NativeCore", "return_type": "i32",
                "parameters": [{"name": "x", "type": "i32"}]}]
        self._expect_error(build_producer(self.base, interface_text=iface,
                                          source_functions=sfs, exports=["NativeCore"]))

    def test_duplicate_swift_name_overload_rejected(self):
        iface = (
            "import Swift\n"
            '@_cdecl("dup_a")\n'
            "public func dup(_ x: Swift.Int32) -> Swift.Int32\n"
            '@_cdecl("dup_b")\n'
            "public func dup(first x: Swift.Int32) -> Swift.Int32\n"
        )
        sfs = [
            {"name": "dup_a", "swift_name": "dup", "return_type": "i32",
             "parameters": [{"name": "x", "type": "i32"}]},
            {"name": "dup_b", "swift_name": "dup", "return_type": "i32",
             "parameters": [{"name": "x", "type": "i32"}]},
        ]
        self._expect_error(build_producer(self.base, interface_text=iface,
                                          source_functions=sfs, exports=["dup_a", "dup_b"]))

    def test_interface_missing_export_signature(self):
        iface = (
            "import Swift\n"
            '@_cdecl("swift_score")\n'
            "public func swift_score(_ x: Swift.UInt64, _ y: Swift.UInt64) -> Swift.UInt64\n"
        )
        # exports/source_functions claim four, interface only defines one
        self._expect_error(build_producer(self.base, interface_text=iface))

    def test_non_dict_producer(self):
        with self.assertRaises(f.SwiftFacadeError):
            f.generate_facade(["not", "a", "dict"], self.out)


class SwiftFacadeSampleFixture(unittest.TestCase):
    """The checked-in sample stays consistent with what the generator expects."""

    def test_sample_project_and_contract_align(self):
        project = json.loads((SAMPLES / "project.json").read_text(encoding="utf-8"))
        contract = json.loads((SAMPLES / "native-contract.json").read_text(encoding="utf-8"))
        self.assertEqual(project["language"], "swift")
        self.assertEqual(project["functions"], [fn["name"] for fn in contract["functions"]])
        # contract validates under the fixed bindings validator
        bindings.validate_contract(contract)

    def test_sample_integration_spec_shape(self):
        spec = json.loads((SAMPLES / "integration.json").read_text(encoding="utf-8"))
        self.assertEqual(spec["kind"], "native_application_integration")
        self.assertEqual(spec["language"], "swift")
        self.assertEqual(spec["application_sources"], ["main.swift"])

    def test_sample_cases_shape_and_native_first(self):
        samples = json.loads((SAMPLES / "application-contract.json").read_text(encoding="utf-8"))
        self.assertEqual(samples["kind"], "native_application_samples")
        cases = samples["cases"]
        labels = [c["label"] for c in cases]
        self.assertEqual(len(labels), len(set(labels)))
        self.assertTrue(1 <= len(cases) <= 64)
        for case in cases:
            self.assertEqual(set(case["expect"]), {"returncode", "stdout"})
        successes = [c for c in cases if c["expect"]["returncode"] == 0]
        self.assertTrue(successes)
        # first success exercises a native root op
        first = successes[0]
        self.assertIn(first["args"][0], {"score", "signed", "unsigned32", "signed32"})
        # usage failures present (nonzero, empty stdout)
        self.assertTrue(any(c["expect"]["returncode"] != 0 and c["expect"]["stdout"] == ""
                            for c in cases))

    def test_sample_core_matches_existing_fixture(self):
        existing = (SAMPLES.parent / "swift" / "core.swift").read_bytes()
        app_core = (SAMPLES / "core.swift").read_bytes()
        self.assertEqual(existing, app_core)

    def test_windows_sample_contract_preserves_observed_crlf(self):
        samples = json.loads((SAMPLES / "application-contract.json").read_text(encoding="utf-8"))
        for case in samples["cases"]:
            if case["expect"]["returncode"] == 0:
                self.assertTrue(case["expect"]["stdout"].endswith("\r\n"), case["label"])
                self.assertEqual(case["expect"]["stdout"].count("\r\n"), 1)


if __name__ == "__main__":
    unittest.main()
