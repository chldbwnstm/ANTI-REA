"""Pure/mock unit tests for antirea.go_application_facade (stdlib unittest).

These tests never compile Go, execute a target or run the real frontend. They
build a synthetic authenticated producer report plus a hash-pinned frontend
directory, exercise generate_facade, and assert the fixed facade.json contract,
the hash/ABI/path/metadata fail-closed controls, and that no original core or
helper body is ever emitted. They also check the owned sample fixture's shape.

They are written as unittest.TestCase (no pytest) so the root focused runner can
load them with unittest.defaultTestLoader under `python -I -S`. Real
compiler/application qualification is root's, through the bounded focused runner
after RUN-READY; these mock tests are not that qualification.
"""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from antirea import bindings  # noqa: F401  (ensures the reused generator imports)
from antirea import go_application_facade as gaf


REPO = Path(__file__).resolve().parents[1]
SAMPLE = REPO / "samples" / "multilang" / "go_application"
ORIGINAL_CORE = REPO / "samples" / "multilang" / "go" / "core.go"


CONTRACT = {
    "schema_version": 1,
    "library_name": "go_app_core",
    "calling_convention": "cdecl",
    "functions": [
        {"name": "go_fold", "return_type": "i32",
         "parameters": [{"name": "a0", "type": "i32"}, {"name": "a1", "type": "i32"}]},
        {"name": "go_wide", "return_type": "i64",
         "parameters": [{"name": "a0", "type": "i64"}, {"name": "a1", "type": "u64"}]},
        {"name": "go_mix", "return_type": "u64",
         "parameters": [{"name": "a0", "type": "u32"}, {"name": "a1", "type": "u32"}]},
        {"name": "go_narrow", "return_type": "u32",
         "parameters": [{"name": "a0", "type": "i64"}, {"name": "a1", "type": "u32"}]},
    ],
}

SELECTORS = [
    {"name": "Fold", "export": "go_fold"},
    {"name": "Wide", "export": "go_wide"},
    {"name": "Mix", "export": "go_mix"},
    {"name": "Narrow", "export": "go_narrow"},
]

METADATA_METHODS = [
    {"name": "Fold", "parameters": [{"id": "a", "type": "int32"}, {"id": "b", "type": "int32"}],
     "return_type": "int32", "calls": ["mixHelper"]},
    {"name": "Wide", "parameters": [{"id": "a", "type": "int64"}, {"id": "count", "type": "uint64"}],
     "return_type": "int64", "calls": []},
    {"name": "Mix", "parameters": [{"id": "a", "type": "uint32"}, {"id": "b", "type": "uint32"}],
     "return_type": "uint64", "calls": ["mixHelper"]},
    {"name": "Narrow", "parameters": [{"id": "a", "type": "int64"}, {"id": "b", "type": "uint32"}],
     "return_type": "uint32", "calls": []},
    {"name": "mixHelper", "parameters": [{"id": "a", "type": "uint32"}, {"id": "b", "type": "uint32"}],
     "return_type": "uint32", "calls": []},
]

PRODUCER_METHODS = [
    {"name": "Fold", "export": "go_fold", "is_root": True,
     "parameters": ["int32", "int32"], "return_type": "int32", "owned_calls": ["mixHelper"]},
    {"name": "Wide", "export": "go_wide", "is_root": True,
     "parameters": ["int64", "uint64"], "return_type": "int64", "owned_calls": []},
    {"name": "Mix", "export": "go_mix", "is_root": True,
     "parameters": ["uint32", "uint32"], "return_type": "uint64", "owned_calls": ["mixHelper"]},
    {"name": "Narrow", "export": "go_narrow", "is_root": True,
     "parameters": ["int64", "uint32"], "return_type": "uint32", "owned_calls": []},
    {"name": "mixHelper", "export": "go_owned_" + "a" * 16, "is_root": False,
     "parameters": ["uint32", "uint32"], "return_type": "uint32", "owned_calls": []},
]

FIXED_FIELDS = {
    "schema_version", "kind", "status", "language", "files", "compile_sources",
    "c_sources", "include_dirs", "source_roots", "loader_environment",
    "original_core_sources_included", "limitations",
}


def _write_json(path, value):
    data = (json.dumps(value, indent=2) + "\n").encode("utf-8")
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


class GoFacadeBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def make_frontend(self, *, package="main", contract=None, metadata_methods=None,
                      pin_metadata=True, pin_contract=True):
        frontend = self.tmp / "frontend"
        frontend.mkdir(parents=True, exist_ok=True)
        contract = CONTRACT if contract is None else contract
        metadata = {"package": package,
                    "methods": METADATA_METHODS if metadata_methods is None else metadata_methods}
        contract_hash = _write_json(frontend / "contract.json", contract)
        metadata_hash = _write_json(frontend / "metadata.json", metadata)
        hashes = {
            "contract.json": contract_hash if pin_contract else "0" * 64,
            "metadata.json": metadata_hash if pin_metadata else "0" * 64,
        }
        return frontend, hashes

    def make_producer(self, frontend, hashes, *, contract=None, methods=None,
                      selectors=None, **overrides):
        producer = {
            "schema_version": 1,
            "status": "artifact_created_unvalidated",
            "backend": "go_typed_native",
            "language": "go",
            "project": {"selectors": SELECTORS if selectors is None else selectors},
            "methods": PRODUCER_METHODS if methods is None else methods,
            "contract": CONTRACT if contract is None else contract,
            "contract_path": str(frontend / "contract.json"),
            "frontend_artifact_hashes": dict(hashes),
        }
        producer.update(overrides)
        return producer

    def generate(self, out_name="facade_out", **frontend_kwargs):
        frontend, hashes = self.make_frontend(**frontend_kwargs)
        producer = self.make_producer(frontend, hashes)
        return gaf.generate_facade(producer, self.tmp / out_name)


class GenerateFacadeHappyTests(GoFacadeBase):
    def test_generate_facade_fixed_schema(self):
        report = self.generate()
        self.assertEqual(set(report), FIXED_FIELDS)
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["kind"], "native_application_facade")
        self.assertEqual(report["status"], "generated_not_validated")
        self.assertEqual(report["language"], "go")
        self.assertEqual(report["c_sources"], [])
        self.assertEqual(report["include_dirs"], [])
        self.assertEqual(report["loader_environment"], "ANTIREA_NATIVE_CORE")
        self.assertIs(report["original_core_sources_included"], False)
        self.assertEqual(report["compile_sources"],
                         ["go/antirea_nativecore.go", "go/antirea_facade.go"])
        self.assertTrue(isinstance(report["limitations"], list) and report["limitations"])

    def test_source_roots_are_contract_public_roots(self):
        report = self.generate()
        self.assertEqual(
            [(r["source_name"], r["export"], r["return_type"]) for r in report["source_roots"]],
            [("Fold", "go_fold", "i32"), ("Wide", "go_wide", "i64"),
             ("Mix", "go_mix", "u64"), ("Narrow", "go_narrow", "u32")])
        fold = report["source_roots"][0]
        self.assertEqual(fold["parameters"],
                         [{"name": "a0", "type": "i32"}, {"name": "a1", "type": "i32"}])
        for root in report["source_roots"]:
            self.assertEqual(root["external_labels"], [])  # Go has no external labels

    def test_persisted_matches_returned_and_hashes(self):
        report = self.generate()
        out = self.tmp / "facade_out"
        saved = json.loads((out / "facade.json").read_text(encoding="utf-8"))
        self.assertEqual(saved, report)
        self.assertNotIn("facade.json", report["files"])
        for rel, digest in report["files"].items():
            self.assertEqual(hashlib.sha256((out / rel).read_bytes()).hexdigest(), digest)
        for src in report["compile_sources"]:
            self.assertIn(src, report["files"])
            self.assertFalse(src.startswith("_bindings/"))

    def test_private_bindings_inventoried_but_not_compiled(self):
        report = self.generate()
        self.assertIn("_bindings/go/native_core_windows_amd64.go", report["files"])
        self.assertIn("_bindings/manifest.json", report["files"])
        self.assertIn("_bindings/common/antirea_bridge.c", report["files"])
        self.assertTrue(any(rel.startswith("_bindings/") for rel in report["files"]))
        self.assertEqual(report["c_sources"], [])
        self.assertEqual(report["include_dirs"], [])

    def test_facade_forwards_and_loads_fail_closed(self):
        self.generate()
        facade = (self.tmp / "facade_out" / "go" / "antirea_facade.go").read_text(encoding="utf-8")
        self.assertTrue(facade.startswith("//go:build windows && amd64"))
        self.assertIn("package main", facade)
        self.assertIn('antireaNativeCoreEnv = "ANTIREA_NATIVE_CORE"', facade)
        self.assertIn("os.Getenv(antireaNativeCoreEnv)", facade)
        self.assertIn("sync.Once", facade)
        self.assertIn("panic(antireaCoreErr)", facade)
        for name, export in [("Fold", "go_fold"), ("Wide", "go_wide"),
                             ("Mix", "go_mix"), ("Narrow", "go_narrow")]:
            self.assertIn("func %s(" % name, facade)
            self.assertIn("antireaNativeCore().Call_%s(" % export, facade)

    def test_bridge_repackaged_to_main_no_cgo(self):
        self.generate()
        bridge = (self.tmp / "facade_out" / "go" / "antirea_nativecore.go").read_text(encoding="utf-8")
        self.assertIn("package main", bridge)
        self.assertNotIn("package nativecore", bridge)
        self.assertNotIn('import "C"', bridge)  # no cgo
        self.assertIn("syscall", bridge)
        self.assertIn("func Load(", bridge)

    def test_generated_go_has_no_original_algorithm(self):
        self.generate()
        out = self.tmp / "facade_out"
        blob = (out / "go" / "antirea_facade.go").read_text(encoding="utf-8")
        blob += (out / "go" / "antirea_nativecore.go").read_text(encoding="utf-8")
        for secret in ("0x9e3779b9", "0xd6e8feb86659fd93", "0x94d049bb133111eb",
                       "mixHelper", "blend", "&^"):
            self.assertNotIn(secret, blob,
                             "generated facade must not carry original core/helper: " + secret)

    def test_generation_is_deterministic(self):
        frontend, hashes = self.make_frontend()
        producer = self.make_producer(frontend, hashes)
        r1 = gaf.generate_facade(producer, self.tmp / "a")
        r2 = gaf.generate_facade(producer, self.tmp / "b")
        self.assertEqual(r1["source_roots"], r2["source_roots"])
        for rel in ("go/antirea_facade.go", "go/antirea_nativecore.go"):
            self.assertEqual(r1["files"][rel], r2["files"][rel])


class OutputDirGuardTests(GoFacadeBase):
    def test_rejects_existing_output_dir(self):
        frontend, hashes = self.make_frontend()
        producer = self.make_producer(frontend, hashes)
        out = self.tmp / "exists"
        out.mkdir()
        with self.assertRaises(gaf.GoAppFacadeError):
            gaf.generate_facade(producer, out)

    def test_rejects_reserved_output_dir(self):
        for reserved in ("attackerfolder", "rea-analysis-reports", "env.setting", "linkrepro"):
            with self.subTest(reserved=reserved):
                frontend, hashes = self.make_frontend()
                producer = self.make_producer(frontend, hashes)
                with self.assertRaises(gaf.GoAppFacadeError):
                    gaf.generate_facade(producer, self.tmp / reserved / "facade")

    def test_rejects_defense_loop_inbox_output(self):
        frontend, hashes = self.make_frontend()
        producer = self.make_producer(frontend, hashes)
        with self.assertRaises(gaf.GoAppFacadeError):
            gaf.generate_facade(producer, self.tmp / "defense-loop" / "inbox" / "facade")


class MetadataContractControlTests(GoFacadeBase):
    def test_rejects_tampered_metadata_hash(self):
        frontend, hashes = self.make_frontend()
        producer = self.make_producer(frontend, hashes)
        (frontend / "metadata.json").write_bytes(b'{"package":"main","methods":[]}\n')
        with self.assertRaises(gaf.GoAppFacadeError):
            gaf.generate_facade(producer, self.tmp / "o")

    def test_rejects_missing_metadata(self):
        frontend, hashes = self.make_frontend()
        producer = self.make_producer(frontend, hashes)
        (frontend / "metadata.json").unlink()
        with self.assertRaises(gaf.GoAppFacadeError):
            gaf.generate_facade(producer, self.tmp / "o")

    def test_rejects_tampered_contract_hash(self):
        frontend, hashes = self.make_frontend()
        producer = self.make_producer(frontend, hashes)
        (frontend / "contract.json").write_bytes(b"{}\n")
        with self.assertRaises(gaf.GoAppFacadeError):
            gaf.generate_facade(producer, self.tmp / "o")

    def test_rejects_non_main_package(self):
        with self.assertRaises(gaf.GoAppFacadeError):
            self.generate(package="protectedcore")

    def test_rejects_missing_hash_pin(self):
        frontend, hashes = self.make_frontend()
        hashes.pop("metadata.json")
        producer = self.make_producer(frontend, hashes)
        with self.assertRaises(gaf.GoAppFacadeError):
            gaf.generate_facade(producer, self.tmp / "o")

    def test_rejects_reserved_contract_path(self):
        frontend, hashes = self.make_frontend()
        producer = self.make_producer(
            frontend, hashes,
            contract_path=str(self.tmp / "rea-analysis-reports" / "contract.json"))
        with self.assertRaises(gaf.GoAppFacadeError):
            gaf.generate_facade(producer, self.tmp / "o")

    def test_rejects_inline_contract_disagreeing_with_disk(self):
        frontend, hashes = self.make_frontend()
        inline = json.loads(json.dumps(CONTRACT))
        inline["functions"][0]["parameters"][0]["name"] = "x0"  # valid but diverges from disk
        producer = self.make_producer(frontend, hashes, contract=inline)
        with self.assertRaises(gaf.GoAppFacadeError):
            gaf.generate_facade(producer, self.tmp / "o")


class ProducerAbiControlTests(GoFacadeBase):
    def test_rejects_wrong_producer_identity(self):
        for field, value in [("schema_version", 2), ("status", "failed"),
                             ("backend", "jvm_bytecode_native"), ("language", "rust")]:
            with self.subTest(field=field):
                frontend, hashes = self.make_frontend()
                producer = self.make_producer(frontend, hashes, **{field: value})
                with self.assertRaises(gaf.GoAppFacadeError):
                    gaf.generate_facade(producer, self.tmp / ("ident_" + field))

    def test_rejects_non_dict_producer(self):
        with self.assertRaises(gaf.GoAppFacadeError):
            gaf.generate_facade(["not", "a", "dict"], self.tmp / "o")

    def test_rejects_metadata_signature_mismatch(self):
        bad_meta = json.loads(json.dumps(METADATA_METHODS))
        bad_meta[0]["return_type"] = "int64"  # metadata Fold claims int64, producer says int32
        with self.assertRaises(gaf.GoAppFacadeError):
            self.generate(metadata_methods=bad_meta)

    def test_rejects_contract_abi_mismatch(self):
        methods = json.loads(json.dumps(PRODUCER_METHODS))
        methods[0]["return_type"] = "int64"
        meta = json.loads(json.dumps(METADATA_METHODS))
        meta[0]["return_type"] = "int64"
        frontend, hashes = self.make_frontend(metadata_methods=meta)
        producer = self.make_producer(frontend, hashes, methods=methods)
        # contract still says go_fold -> i32, so the ABI no longer matches the signature.
        with self.assertRaises(gaf.GoAppFacadeError):
            gaf.generate_facade(producer, self.tmp / "o")

    def test_rejects_extra_contract_export(self):
        contract = json.loads(json.dumps(CONTRACT))
        contract["functions"].append(
            {"name": "go_extra", "return_type": "i32", "parameters": [{"name": "a0", "type": "i32"}]})
        frontend, hashes = self.make_frontend(contract=contract)
        producer = self.make_producer(frontend, hashes, contract=contract)
        with self.assertRaises(gaf.GoAppFacadeError):
            gaf.generate_facade(producer, self.tmp / "o")

    def test_rejects_helper_export_in_contract(self):
        methods = json.loads(json.dumps(PRODUCER_METHODS))
        methods[-1]["export"] = "go_fold"  # helper now claims a deployed contract export
        frontend, hashes = self.make_frontend()
        producer = self.make_producer(frontend, hashes, methods=methods)
        with self.assertRaises(gaf.GoAppFacadeError):
            gaf.generate_facade(producer, self.tmp / "o")

    def test_rejects_duplicate_selector(self):
        selectors = SELECTORS + [{"name": "Fold", "export": "go_fold"}]
        frontend, hashes = self.make_frontend()
        producer = self.make_producer(frontend, hashes, selectors=selectors)
        with self.assertRaises(gaf.GoAppFacadeError):
            gaf.generate_facade(producer, self.tmp / "o")

    def test_rejects_reserved_or_invalid_root_name(self):
        for bad_name in ("NativeCore", "Load", "antireaNativeCore", "func", "has-dash"):
            with self.subTest(bad_name=bad_name):
                selectors = json.loads(json.dumps(SELECTORS))
                selectors[0]["name"] = bad_name
                frontend, hashes = self.make_frontend()
                producer = self.make_producer(frontend, hashes, selectors=selectors)
                with self.assertRaises(gaf.GoAppFacadeError):
                    gaf.generate_facade(producer, self.tmp / ("name_" + bad_name.replace("-", "_")))

    def test_rejects_non_scalar_contract_type(self):
        contract = json.loads(json.dumps(CONTRACT))
        contract["functions"][0]["return_type"] = "f32"  # not an integer scalar
        frontend, hashes = self.make_frontend(contract=contract)
        producer = self.make_producer(frontend, hashes, contract=contract)
        with self.assertRaises(ValueError):  # bindings.validate_contract rejects float/bool
            gaf.generate_facade(producer, self.tmp / "o")


class SampleFixtureTests(unittest.TestCase):
    def test_sample_core_unchanged_except_package(self):
        original = ORIGINAL_CORE.read_text(encoding="utf-8")
        sample = (SAMPLE / "core.go").read_text(encoding="utf-8")
        self.assertEqual(sample, original.replace("package protectedcore", "package main", 1))
        self.assertTrue(sample.startswith("package main\n"))

    def test_sample_app_calls_all_roots_without_helper_or_constant(self):
        main = (SAMPLE / "main.go").read_text(encoding="utf-8")
        for call in ("Fold(", "Wide(", "Mix(", "Narrow("):
            self.assertIn(call, main)
        self.assertNotIn("mixHelper", main)
        self.assertNotIn("blend", main)

    def test_sample_integration_spec_shape(self):
        spec = json.loads((SAMPLE / "integration.json").read_text(encoding="utf-8"))
        self.assertEqual(spec, {"schema_version": 1, "kind": "native_application_integration",
                                "language": "go", "application_sources": ["main.go"]})

    def test_sample_application_contract_shape(self):
        samples = json.loads((SAMPLE / "application-contract.json").read_text(encoding="utf-8"))
        self.assertEqual(samples["schema_version"], 1)
        self.assertEqual(samples["kind"], "native_application_samples")
        cases = samples["cases"]
        labels = [c["label"] for c in cases]
        self.assertEqual(len(labels), len(set(labels)))
        self.assertTrue(1 <= len(labels) <= 64)
        self.assertEqual(cases[0]["expect"]["returncode"], 0)  # first success exercises a root
        ops = {c["args"][0] for c in cases if c["args"] and c["expect"]["returncode"] == 0}
        self.assertTrue({"fold", "wide", "mix", "narrow"} <= ops)
        self.assertTrue(any(c["expect"]["returncode"] != 0 for c in cases))  # usage failures
        for c in cases:
            self.assertEqual(set(c["expect"]), {"returncode", "stdout"})  # rc/stdout only
            self.assertIsInstance(c["args"], list)

    def test_sample_native_contract_shape(self):
        contract = json.loads((SAMPLE / "native-contract.json").read_text(encoding="utf-8"))
        normalized = bindings.validate_contract(contract)  # must be a valid cdecl ABI
        self.assertEqual(normalized["calling_convention"], "cdecl")
        self.assertEqual([f["name"] for f in normalized["functions"]],
                         ["go_fold", "go_wide", "go_mix", "go_narrow"])
        self.assertEqual([(f["name"], f["return_type"]) for f in normalized["functions"]],
                         [("go_fold", "i32"), ("go_wide", "i64"),
                          ("go_mix", "u64"), ("go_narrow", "u32")])

    def test_sample_core_project_shape(self):
        proj = json.loads((SAMPLE / "project.json").read_text(encoding="utf-8"))
        self.assertEqual(set(proj), {"schema_version", "name", "language", "sources", "functions"})
        self.assertEqual(proj["language"], "go")
        self.assertEqual(proj["sources"], ["core.go"])
        self.assertEqual([f["export"] for f in proj["functions"]],
                         ["go_fold", "go_wide", "go_mix", "go_narrow"])
        self.assertEqual([f["name"] for f in proj["functions"]],
                         ["Fold", "Wide", "Mix", "Narrow"])


if __name__ == "__main__":
    unittest.main()
