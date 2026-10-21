"""Author tests for the phase24 Python application staging adapter.

These exercise the real ``prepare_application`` API against temporary source
trees and a synthetic producer report; they stage files only and never execute
the application, an interpreter or any child process. They are authored for root
to run after source freeze (no worker execution). Passing staging assertions are
not functional-preservation, performance or attack-resistance evidence.
"""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from antirea import script_python_application as adapter


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def normalize(raw: bytes) -> bytes:
    """Emulate the pure python_vm producer's UTF-8-sig + universal-newline read."""
    text = raw.decode("utf-8-sig")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.encode("utf-8")


ORIGINAL_BILLING = b"def net_settlement(a, b, c):\n    return a * b - c\n"
PROTECTED_BILLING = b"# protected artifact\ndef net_settlement(a, b, c):\n    return _vm(a, b, c)\n"

TREE = {
    "ledger_app/__init__.py": b'"""pkg"""\n',
    "ledger_app/__main__.py": b"from .billing import net_settlement\n",
    "ledger_app/billing.py": ORIGINAL_BILLING,
    "ledger_app/labels.py": b'CURRENCY = "USD"\n',
    "ledger_app/notes.txt": b"Thank you.\n",
}


class PrepareApplicationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.src = self.base / "tree"
        self.runs = self.base / "runs"
        self.runs.mkdir(parents=True)
        self.out = self.base / "out" / "adapter"       # fresh, adapter-owned
        self.input_files = {}
        for rel, data in TREE.items():
            path = self.src / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            self.input_files[rel] = sha_bytes(data)
        self.original_billing_sha = sha_bytes(ORIGINAL_BILLING)
        self.baseline_path = self.runs / "baseline.py"
        self.protected_path = self.runs / "protected.py"
        self.producer = self.make_producer()
        self.kwargs = dict(
            source_root=self.src,
            input_files=dict(self.input_files),
            protected_source="ledger_app/billing.py",
            entrypoint="ledger_app/__main__.py",
            producer=self.producer,
            output_dir=self.out,
            tools={"python_executable": {"path": "C:/py/python.exe", "sha256": "a" * 64}},
            trusted_inputs={str(Path(adapter.__file__)): sha_file(Path(adapter.__file__))},
            timeout_seconds=120,
            stop_file=self.base / "defense" / "STOP",      # absent
        )

    def make_producer(self, backend="python_mixed_module_vm", baseline_bytes=ORIGINAL_BILLING,
                      source_sha=None, raw_input_sha=None, **overrides):
        # The producer's artifacts must exist on disk with matching bytes.
        self.baseline_path.write_bytes(baseline_bytes)
        self.protected_path.write_bytes(PROTECTED_BILLING)
        source_sha = source_sha if source_sha is not None else sha_bytes(baseline_bytes)
        raw_input_sha = raw_input_sha if raw_input_sha is not None else self.original_billing_sha
        src_billing = str(self.runs / "src" / "ledger_app" / "billing.py")
        producer = {
            "schema_version": 1,
            "status": "artifact_created_unvalidated",
            "backend": backend,
            "artifacts": {
                "baseline": {"path": str(self.baseline_path),
                             "sha256": sha_bytes(baseline_bytes), "bytes": len(baseline_bytes)},
                "protected": {"path": str(self.protected_path),
                              "sha256": sha_bytes(PROTECTED_BILLING), "bytes": len(PROTECTED_BILLING)},
            },
            "project": {"language": "python", "sources": [src_billing],
                        "input_hashes": {src_billing: raw_input_sha}, "source_sha256": source_sha},
            "inspection": {"source_sha256": source_sha},
            "coverage": {"selected_functions": ["net_settlement"],
                         "helper_closure": ["net_settlement", "rounded_fee"], "format_version": 2},
        }
        producer.update(overrides)
        return producer

    def run_adapter(self, **changes):
        kwargs = dict(self.kwargs)
        kwargs.update(changes)
        return adapter.prepare_application(**kwargs)

    # ----------------------------------------------------------------- happy path
    def test_returns_exactly_the_eleven_brief_keys(self):
        result = self.run_adapter()
        self.assertEqual(set(result), {
            "language", "original_root", "protected_root", "runtime_entrypoint",
            "protected_relative", "preparation_commands", "file_maps",
            "protected_sha256", "original_core_sha256", "reference_evidence", "limitations"})
        self.assertEqual(result["language"], "python")
        self.assertEqual(result["preparation_commands"], [])

    def test_original_tree_is_byte_exact(self):
        result = self.run_adapter()
        root = Path(result["original_root"])
        for rel, data in TREE.items():
            self.assertEqual((root / rel).read_bytes(), data)
        self.assertEqual(result["file_maps"]["original"], self.input_files)

    def test_protected_tree_substitutes_only_the_selected_module(self):
        result = self.run_adapter()
        root = Path(result["protected_root"])
        self.assertEqual((root / "ledger_app/billing.py").read_bytes(), PROTECTED_BILLING)
        for rel, data in TREE.items():
            if rel != "ledger_app/billing.py":
                self.assertEqual((root / rel).read_bytes(), data)
        protected_map = result["file_maps"]["protected"]
        self.assertEqual(set(protected_map), set(self.input_files))
        self.assertEqual(protected_map["ledger_app/billing.py"], sha_bytes(PROTECTED_BILLING))
        for rel in TREE:
            if rel != "ledger_app/billing.py":
                self.assertEqual(protected_map[rel], self.input_files[rel])

    def test_hash_return_fields(self):
        result = self.run_adapter()
        self.assertEqual(result["protected_sha256"], sha_bytes(PROTECTED_BILLING))
        self.assertEqual(result["original_core_sha256"], self.original_billing_sha)
        self.assertEqual(result["protected_relative"], "ledger_app/billing.py")
        self.assertEqual(result["runtime_entrypoint"], "ledger_app/__main__.py")

    def test_module_execution_derivation(self):
        module = self.run_adapter()["reference_evidence"]["module_execution"]
        self.assertEqual(module["module"], "ledger_app.__main__")
        self.assertEqual(module["package_chain"], ["ledger_app"])
        self.assertTrue(module["is_package"])
        self.assertEqual(module["runtime_entrypoint"], "ledger_app/__main__.py")

    def test_top_level_entrypoint_has_no_package_requirement(self):
        tree = {"app.py": b"print(1)\n", "core.py": ORIGINAL_BILLING}
        src = self.base / "flat"
        inputs = {}
        for rel, data in tree.items():
            (src / rel).parent.mkdir(parents=True, exist_ok=True)
            (src / rel).write_bytes(data)
            inputs[rel] = sha_bytes(data)
        result = self.run_adapter(source_root=src, input_files=inputs,
                                  protected_source="core.py", entrypoint="app.py",
                                  output_dir=self.base / "flatout")
        module = result["reference_evidence"]["module_execution"]
        self.assertEqual(module["module"], "app")
        self.assertEqual(module["package_chain"], [])
        self.assertFalse(module["is_package"])

    def test_bootstrap_is_fixed_and_hashed(self):
        result = self.run_adapter()
        boot = result["reference_evidence"]["runpy_bootstrap"]
        path = Path(boot["path"])
        self.assertEqual(path.read_text(encoding="utf-8"), adapter.RUNPY_BOOTSTRAP)
        self.assertEqual(boot["sha256"], sha_file(path))
        self.assertFalse(boot["interpolates_program_source"])
        self.assertEqual(boot["run_name"], "__main__")
        self.assertEqual(boot["interpreter_flags"], ["-I", "-S", "-B"])
        # The runner lives beside the roots, never inside a staged/deployed tree.
        self.assertFalse(path.is_relative_to(Path(result["original_root"])))
        self.assertFalse(path.is_relative_to(Path(result["protected_root"])))

    def test_persisted_preparation_matches_return(self):
        result = self.run_adapter()
        persisted = json.loads((self.out / "preparation.json").read_text(encoding="utf-8"))
        self.assertEqual(persisted, result)

    def test_binding_evidence_records_producer(self):
        evidence = self.run_adapter()["reference_evidence"]
        self.assertEqual(evidence["producer"]["backend"], "python_mixed_module_vm")
        self.assertEqual(evidence["producer"]["baseline"]["sha256"], self.original_billing_sha)
        self.assertEqual(evidence["producer"]["normalization"], "raw_preserved")
        self.assertTrue(evidence["producer"]["binding"]["baseline_equals_raw_original"])
        self.assertTrue(evidence["original_source_binding"]["bound_via_project_input_hashes"])
        self.assertEqual(evidence["original_source_binding"]["raw_sha256"], self.original_billing_sha)
        self.assertEqual(evidence["producer"]["coverage"]["selected_functions"], ["net_settlement"])

    def test_pure_backend_is_accepted(self):
        result = self.run_adapter(producer=self.make_producer(backend="python_vm"))
        self.assertEqual(result["reference_evidence"]["producer"]["backend"], "python_vm")
        self.assertEqual(result["reference_evidence"]["producer"]["normalization"],
                         "utf8sig_universal_newline_normalized")

    def test_pure_backend_accepts_bom_crlf_with_normalized_baseline(self):
        raw = "\ufeff".encode("utf-8") + b"def net_settlement(a, b, c):\r\n    return a * b - c\r\n"
        normalized = normalize(raw)
        self.assertNotEqual(sha_bytes(raw), sha_bytes(normalized))   # normalization truly differs
        src = self.base / "bom"
        files = {"pkg/__init__.py": b'"""p"""\n',
                 "pkg/__main__.py": b"from .billing import net_settlement\n",
                 "pkg/billing.py": raw}
        inputs = {}
        for rel, data in files.items():
            (src / rel).parent.mkdir(parents=True, exist_ok=True)
            (src / rel).write_bytes(data)
            inputs[rel] = sha_bytes(data)
        runs = self.base / "bomruns"
        runs.mkdir()
        (runs / "baseline.py").write_bytes(normalized)      # pure baseline is NORMALIZED
        (runs / "protected.py").write_bytes(PROTECTED_BILLING)
        srcpath = str(runs / "src" / "pkg" / "billing.py")
        producer = {
            "schema_version": 1, "status": "artifact_created_unvalidated", "backend": "python_vm",
            "artifacts": {
                "baseline": {"path": str(runs / "baseline.py"),
                             "sha256": sha_bytes(normalized), "bytes": len(normalized)},
                "protected": {"path": str(runs / "protected.py"),
                              "sha256": sha_bytes(PROTECTED_BILLING), "bytes": len(PROTECTED_BILLING)},
            },
            "project": {"language": "python", "sources": [srcpath],
                        "input_hashes": {srcpath: sha_bytes(raw)}, "source_sha256": sha_bytes(normalized)},
            "inspection": {"source_sha256": sha_bytes(normalized)},
            "coverage": {"selected_functions": ["net_settlement"]},
        }
        result = self.run_adapter(source_root=src, input_files=inputs,
                                  protected_source="pkg/billing.py", entrypoint="pkg/__main__.py",
                                  producer=producer, output_dir=self.base / "bomout")
        # Original tree raw-byte-preserves the BOM + CRLF source.
        self.assertEqual((Path(result["original_root"]) / "pkg/billing.py").read_bytes(), raw)
        self.assertEqual(result["original_core_sha256"], sha_bytes(raw))
        producer_ev = result["reference_evidence"]["producer"]
        self.assertEqual(producer_ev["normalization"], "utf8sig_universal_newline_normalized")
        self.assertFalse(producer_ev["binding"]["baseline_equals_raw_original"])
        self.assertTrue(producer_ev["binding"]["raw_bound_via_project_input_hashes"])

    # --------------------------------------------------------------- fail closed
    def assert_rejected(self, **changes):
        with self.assertRaises(adapter.ScriptPythonApplicationError):
            self.run_adapter(**changes)

    def test_entrypoint_must_differ_from_protected_source(self):
        self.assert_rejected(entrypoint="ledger_app/billing.py")

    def test_protected_source_must_be_listed(self):
        self.assert_rejected(protected_source="ledger_app/missing.py")

    def test_entrypoint_must_be_listed(self):
        self.assert_rejected(entrypoint="ledger_app/missing.py")

    def test_wrong_raw_project_pin_rejected(self):
        producer = self.make_producer()
        key = producer["project"]["sources"][0]
        producer["project"]["input_hashes"][key] = "c" * 64     # not the raw original hash
        self.assert_rejected(producer=producer)

    def test_producer_without_project_rejected(self):
        producer = self.make_producer()
        del producer["project"]
        self.assert_rejected(producer=producer)

    def test_baseline_artifact_byte_mismatch_rejected(self):
        producer = self.make_producer()
        self.baseline_path.write_bytes(b"tampered baseline\n")   # on-disk != claimed sha
        self.assert_rejected(producer=producer)

    def test_baseline_bytes_field_mismatch_rejected(self):
        producer = self.make_producer()
        producer["artifacts"]["baseline"]["bytes"] = 999999
        self.assert_rejected(producer=producer)

    def test_baseline_not_matching_source_sha_rejected(self):
        producer = self.make_producer()
        producer["project"]["source_sha256"] = "d" * 64
        producer["inspection"]["source_sha256"] = "d" * 64
        self.assert_rejected(producer=producer)

    def test_pure_consistent_but_unrelated_baseline_rejected(self):
        # Metadata self-consistency does not bind an unrelated baseline to the
        # actual original source. Raw input pin is still correct in this fixture.
        producer = self.make_producer(
            backend="python_vm", baseline_bytes=b"def net_settlement(a, b, c):\n    return 123\n")
        self.assert_rejected(producer=producer)

    def test_mixed_backend_requires_raw_baseline(self):
        # A mixed producer whose baseline differs from the raw original is rejected.
        producer = self.make_producer(baseline_bytes=b"different\n")
        self.assert_rejected(producer=producer)

    def test_bad_backend_rejected(self):
        self.assert_rejected(producer=self.make_producer(backend="go_typed_native"))

    def test_bad_status_rejected(self):
        self.assert_rejected(producer=self.make_producer(status="failed"))

    def test_bad_schema_version_rejected(self):
        self.assert_rejected(producer=self.make_producer(schema_version=2))

    def test_missing_artifact_key_rejected(self):
        producer = self.make_producer()
        producer["artifacts"] = {"baseline": producer["artifacts"]["baseline"], "other": {}}
        self.assert_rejected(producer=producer)

    def test_disallowed_suffix_rejected(self):
        inputs = dict(self.input_files)
        data = b"cache\n"
        (self.src / "ledger_app/billing_data.bin").write_bytes(data)
        inputs["ledger_app/billing_data.bin"] = sha_bytes(data)
        self.assert_rejected(input_files=inputs)

    def test_absolute_path_rejected(self):
        inputs = dict(self.input_files)
        inputs["C:/evil.py"] = "d" * 64
        self.assert_rejected(input_files=inputs)

    def test_traversal_path_rejected(self):
        inputs = dict(self.input_files)
        inputs["../escape.py"] = "d" * 64
        self.assert_rejected(input_files=inputs)

    def test_reserved_component_rejected(self):
        inputs = dict(self.input_files)
        inputs["attackerfolder/x.py"] = "d" * 64
        self.assert_rejected(input_files=inputs)

    def test_trailing_dot_component_rejected(self):
        inputs = dict(self.input_files)
        inputs["ledger_app/weird./x.py"] = "d" * 64
        self.assert_rejected(input_files=inputs)

    def test_trailing_space_component_rejected(self):
        inputs = dict(self.input_files)
        inputs["ledger_app/space /y.py"] = "d" * 64
        self.assert_rejected(input_files=inputs)

    def test_control_char_component_rejected(self):
        inputs = dict(self.input_files)
        inputs["ledger_app/a\tb.py"] = "d" * 64
        self.assert_rejected(input_files=inputs)

    def test_dos_device_name_rejected(self):
        inputs = dict(self.input_files)
        inputs["ledger_app/con.py"] = "d" * 64
        self.assert_rejected(input_files=inputs)

    def test_pycache_component_rejected(self):
        inputs = dict(self.input_files)
        inputs["ledger_app/__pycache__/billing.pyc"] = "d" * 64
        self.assert_rejected(input_files=inputs)

    def test_node_modules_component_rejected(self):
        inputs = dict(self.input_files)
        inputs["ledger_app/node_modules/x.py"] = "d" * 64
        self.assert_rejected(input_files=inputs)

    def test_casefold_collision_rejected(self):
        inputs = dict(self.input_files)
        inputs["ledger_app/Billing.py"] = self.input_files["ledger_app/billing.py"]
        self.assert_rejected(input_files=inputs)

    def test_snapshot_hash_mismatch_rejected(self):
        inputs = dict(self.input_files)
        inputs["ledger_app/labels.py"] = "e" * 64
        self.assert_rejected(input_files=inputs)

    def test_missing_on_disk_input_rejected(self):
        inputs = dict(self.input_files)
        inputs["ledger_app/extra.py"] = "f" * 64
        self.assert_rejected(input_files=inputs)

    def test_missing_package_init_rejected(self):
        tree = {"pkg/cli.py": b"x = 1\n", "pkg/core.py": ORIGINAL_BILLING}
        src = self.base / "noinit"
        inputs = {}
        for rel, data in tree.items():
            (src / rel).parent.mkdir(parents=True, exist_ok=True)
            (src / rel).write_bytes(data)
            inputs[rel] = sha_bytes(data)
        with self.assertRaises(adapter.ScriptPythonApplicationError):
            self.run_adapter(source_root=src, input_files=inputs,
                             protected_source="pkg/core.py", entrypoint="pkg/cli.py",
                             output_dir=self.base / "noinitout")

    def test_protected_artifact_hash_mismatch_rejected(self):
        self.protected_path.write_bytes(b"tampered\n")
        self.assert_rejected()

    def test_protected_artifact_missing_rejected(self):
        self.protected_path.unlink()
        self.assert_rejected()

    def test_tools_missing_python_executable_rejected(self):
        self.assert_rejected(tools={})

    def test_tools_bad_sha_rejected(self):
        self.assert_rejected(tools={"python_executable": {"path": "p", "sha256": "nothex"}})

    def test_stop_marker_rejected(self):
        stop = self.base / "defense" / "STOP"
        stop.parent.mkdir(parents=True, exist_ok=True)
        stop.write_text("stop", encoding="utf-8")
        self.assert_rejected(stop_file=stop)

    def test_timeout_out_of_range_rejected(self):
        self.assert_rejected(timeout_seconds=0)
        self.assert_rejected(timeout_seconds=601)

    def test_non_py_protected_source_rejected(self):
        self.assert_rejected(protected_source="ledger_app/notes.txt")

    def test_non_empty_output_dir_rejected(self):
        self.out.mkdir(parents=True)
        (self.out / "stale.txt").write_text("old", encoding="utf-8")
        self.assert_rejected()

    def test_oversize_file_rejected(self):
        from unittest.mock import patch
        big = b"x" * 2000
        (self.src / "ledger_app/labels.py").write_bytes(big)
        inputs = dict(self.input_files)
        inputs["ledger_app/labels.py"] = sha_bytes(big)
        with patch.object(adapter, "MAX_FILE_BYTES", 1024):
            with self.assertRaises(adapter.ScriptPythonApplicationError):
                self.run_adapter(input_files=inputs)

    def test_too_many_files_rejected(self):
        inputs = dict(self.input_files)
        for i in range(adapter.MAX_APPLICATION_FILES):
            inputs["ledger_app/pad_%d.py" % i] = "0" * 64
        self.assert_rejected(input_files=inputs)


if __name__ == "__main__":
    unittest.main()
