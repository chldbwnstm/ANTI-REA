"""Author tests for the phase24 JavaScript/TypeScript application staging adapter.

Every test here is CHILD-FREE: the mixed-JavaScript raw-copy route and all
validation/refusal paths need no child at all, and the pure-JS / pure-TS transpile
route is exercised by patching ``antirea.process.run_logged`` with a deterministic
synthetic transpile-reference reply + Windows-Job receipt. The REAL adapter logic
(pin/STOP/deadline checks, request binding, export enforcement, specifier
rejection, staging and inventory) runs; no real Node/TypeScript, no subprocess and
no application/compiler execution occur in this unit suite. The actual
compiler/application qualification is exclusively root's reviewed public runner
with real STOP, private env, pins and receipts, after source freeze. Passing
staging assertions are not functional/performance/attack-resistance evidence.
"""
import base64
import hashlib
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from antirea import script_javascript_application as adapter

ERROR = adapter.ScriptJavaScriptApplicationError


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_file(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# --------------------------------------------------------------------------- #
# Deterministic synthetic transpile-reference child (replaces process.run_logged).
# It parses the stdin request, emits a byte-stable CommonJS rendering per file with
# the exported names / require specifiers scanned from the source, and writes the
# three run_logged evidence files plus a clean Windows-Job receipt it also returns.
# --------------------------------------------------------------------------- #
_EXPORT_RE = re.compile(r"export\s+function\s+([A-Za-z_$][\w$]*)")
_SPEC_RE = re.compile(r"""(?:\brequire\(|\bfrom)\s*['"]([^'"]+)['"]""")


def fake_run_logged(argv, directory, log_prefix, timeout=600, env=None, stdin=None, *, cancel_file=None):
    log_prefix = Path(log_prefix)
    log_prefix.parent.mkdir(parents=True, exist_ok=True)
    request = json.loads(stdin)
    results = []
    for entry in request["files"]:
        src = entry["source"]
        exported = _EXPORT_RE.findall(src)
        specs = _SPEC_RE.findall(src)
        output = ('"use strict";\nObject.defineProperty(exports, "__esModule", { value: true });\n'
                  + "".join('exports.%s = function %s() {};\n' % (n, n) for n in exported)
                  + "// synthetic commonjs rendering of %s\n" % entry["key"])
        ob = output.encode("utf-8")
        b64 = base64.b64encode(ob).decode("ascii")
        results.append({"key": entry["key"], "shebang_present": False, "shebang_bytes": 0,
                        "shebang_b64": "", "working_bytes": len(ob), "working_b64": b64,
                        "output_bytes": len(ob), "output_b64": b64,
                        "require_specifiers": specs, "exported_names": exported})
    reply = {"status": "ok", "compiler_version": "5.9.9-synthetic", "language": request["language"],
             "source_executed": False, "type_checking": "not_performed_whole_module_transpile_only",
             "pinned_compiler_options": {"target": "ES2022", "module": "CommonJS", "isolatedModules": True,
                                         "esModuleInterop": True},
             "results": results,
             "loaded_files": [str(adapter.REFERENCE_HELPER), str(argv[-1])]}
    log_prefix.with_suffix(".stdout.log").write_text(json.dumps(reply), encoding="utf-8")
    log_prefix.with_suffix(".stderr.log").write_text("", encoding="utf-8")
    result = {"argv": [str(a) for a in argv], "returncode": 0, "pid": 4242, "timed_out": False,
              "cancelled": False, "seconds": 0.01,
              "stdout": str(log_prefix.with_suffix(".stdout.log")),
              "stderr": str(log_prefix.with_suffix(".stderr.log")),
              "cleanup": {"method": "windows_job", "job_assigned": True, "parent_pid": 4242,
                          "parent_exit_confirmed": True, "active_after": 0,
                          "status": "assigned_job_empty", "job_handle_closed": True}}
    log_prefix.with_suffix(".process.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


# Fixtures ------------------------------------------------------------------- #
MIXED_CORE = b'"use strict";\nfunction compute(a, b) { return a + b; }\nmodule.exports = { compute };\n'
MIXED_APP = (b'#!/usr/bin/env node\n"use strict";\n'
             b'const core = require("./core.js");\nconst fmt = require("./format.js");\n'
             b'process.stdout.write(fmt.line(core.compute(1, 2)) + "\\n");\n')
MIXED_FORMAT = b'"use strict";\nexports.line = function line(v) { return "r=" + v; };\n'
MIXED_LABELS = b'{"compute": "adder"}\n'
PROTECTED_CJS = b'"use strict";\n// protected artifact\nfunction compute(a, b) { return _vm(a, b); }\nmodule.exports = { compute };\n'

PURE_JS_CORE = (b'"use strict";\nfunction scale(v, s) { return v + s; }\n'
                b'export function compute(a, b) { let t = a; for (let i = 1; i <= 2; i++) { t = scale(t, b * i); } return t; }\n'
                b'export function gate(a, b) { return a >= b; }\n')
PURE_JS_APP = (b'"use strict";\nconst core = require("./core.js");\n'
               b'process.stdout.write(String(core.compute(1, 2)) + "\\n");\n')
PURE_TS_CORE = (b'export function compute(a: number, b: number): number { return a + b; }\n'
                b'export function gate(a: number, b: number): boolean { return a >= b; }\n')
PURE_TS_APP = (b'import { compute } from "./core.js";\n'
               b'process.stdout.write(String(compute(1, 2)) + "\\n");\n')
PURE_TS_FORMAT = b'export function line(v: number): string { return "r=" + v; }\n'


class PureHelperFunctionTests(unittest.TestCase):
    """Pure in-process validators; no filesystem, no child process."""

    def test_relative_accepts_clean_paths(self):
        self.assertEqual(adapter._relative("a/b.js"), "a/b.js")
        self.assertEqual(adapter._relative("core.ts"), "core.ts")

    def test_relative_rejects(self):
        for bad in ("", " x.js", "x.js ", "/abs.js", "C:/x.js", "a\\b.js", "a:b.js", "../x.js",
                    "./x.js", "a//b.js", "a/./b.js", "attackerfolder/x.js",
                    "pkg/rea-analysis-reports/y.js", "a/defense-loop/b.js", "env.setting/x.js",
                    "linkrepro/x.js", "pkg/__pycache__/y.js", "pkg/node_modules/y.js",
                    "con.js", "pkg/prn.ts", "weird./a.js", "a/space /b.js", "a\tb.js"):
            with self.assertRaises(ERROR, msg=bad):
                adapter._relative(bad)

    def test_runtime_rel_maps_only_typescript_sources(self):
        self.assertEqual(adapter._runtime_rel("core.ts", "typescript"), "core.js")
        self.assertEqual(adapter._runtime_rel("a/b.ts", "typescript"), "a/b.js")
        self.assertEqual(adapter._runtime_rel("core.js", "javascript"), "core.js")
        self.assertEqual(adapter._runtime_rel("x.cjs", "javascript"), "x.cjs")
        self.assertEqual(adapter._runtime_rel("data.json", "typescript"), "data.json")

    def test_reject_name_blocks_declaration_jsx_esm_sourcemap(self):
        for bad in ("x.d.ts", "x.tsx", "x.mjs", "x.map", "x.mts", "x.cts"):
            with self.assertRaises(ERROR, msg=bad):
                adapter._reject_name(bad)
        adapter._reject_name("x.ts")   # ordinary TS is allowed
        adapter._reject_name("x.js")

    def test_reject_specifiers(self):
        adapter._reject_specifiers(["./core.js", "fs", "node:path", "./a/b.cjs", "./d.json"], "ok")
        for bad in (["./core.ts"], ["./x.tsx"], ["./x.mts"], ["./x.cts"], ["./x.d.ts"], ["pkg.mjs"],
                    ["./core.ts?v=1"], ["./core.ts#frag"]):
            with self.assertRaises(ERROR, msg=str(bad)):
                adapter._reject_specifiers(bad, "where")
        with self.assertRaises(ERROR):
            adapter._reject_specifiers("not-a-list", "where")
        with self.assertRaises(ERROR):
            adapter._reject_specifiers([123], "where")


def no_child(*args, **kwargs):
    raise AssertionError("mixed staging must not run a child")


@patch.object(adapter.process, "run_logged", no_child)
class MixedJavaScriptStagingTests(unittest.TestCase):
    """Full staging happy path + refusals for the mixed-JS raw-copy route (no child)."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.src = self.base / "tree"
        self.runs = self.base / "runs"
        self.runs.mkdir(parents=True)
        self.out = self.base / "out" / "staging"
        self.tree = {"app.js": MIXED_APP, "core.js": MIXED_CORE,
                     "format.js": MIXED_FORMAT, "labels.json": MIXED_LABELS}
        self.input_files = {}
        for rel, data in self.tree.items():
            path = self.src / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            self.input_files[rel] = sha_bytes(data)
        self.baseline_path = self.runs / "baseline.cjs"
        self.protected_path = self.runs / "protected.cjs"
        self.producer = self.make_producer()
        self.kwargs = dict(
            source_root=self.src, input_files=dict(self.input_files),
            protected_source="core.js", entrypoint="app.js", producer=self.producer,
            output_dir=self.out, tools={},
            trusted_inputs={str(Path(adapter.__file__)): sha_file(adapter.__file__)},
            timeout_seconds=120, stop_file=self.base / "defense" / "STOP")

    def make_producer(self, backend=adapter.MIXED_BACKEND, baseline_bytes=MIXED_CORE,
                      protected_bytes=PROTECTED_CJS, source_sha=None, **overrides):
        self.baseline_path.write_bytes(baseline_bytes)
        self.protected_path.write_bytes(protected_bytes)
        source_sha = source_sha if source_sha is not None else sha_bytes(MIXED_CORE)
        producer = {
            "schema_version": 1, "status": "artifact_created_unvalidated", "backend": backend,
            "artifacts": {
                "baseline": {"path": str(self.baseline_path), "sha256": sha_bytes(baseline_bytes),
                             "bytes": len(baseline_bytes)},
                "protected": {"path": str(self.protected_path), "sha256": sha_bytes(protected_bytes),
                              "bytes": len(protected_bytes)}},
            "project": {"language": "javascript", "sources": ["core.js"],
                        "source_sha256": source_sha, "functions": ["compute"]},
            "coverage": {"selected_functions": ["compute"], "exported_functions": ["compute"],
                         "original_selected_bodies_in_protected_artifact": False}}
        producer.update(overrides)
        return producer

    def run_adapter(self, **changes):
        kwargs = dict(self.kwargs)
        kwargs.update(changes)
        return adapter.prepare_application(**kwargs)

    def assert_rejected(self, **changes):
        with self.assertRaises(ERROR):
            self.run_adapter(**changes)

    # happy path ------------------------------------------------------------- #
    def test_returns_exactly_eleven_keys_no_child(self):
        result = self.run_adapter()
        self.assertEqual(set(result), {
            "language", "original_root", "protected_root", "runtime_entrypoint",
            "protected_relative", "preparation_commands", "file_maps",
            "protected_sha256", "original_core_sha256", "reference_evidence", "limitations"})
        self.assertEqual(result["language"], "javascript")
        self.assertEqual(result["preparation_commands"], [])
        self.assertEqual(result["runtime_entrypoint"], "app.js")
        self.assertEqual(result["protected_relative"], "core.js")

    def test_arms_core_substitution_and_sibling_preservation(self):
        result = self.run_adapter()
        original, protected = Path(result["original_root"]), Path(result["protected_root"])
        self.assertEqual((original / "core.js").read_bytes(), MIXED_CORE)
        self.assertEqual((protected / "core.js").read_bytes(), PROTECTED_CJS)
        for rel in ("app.js", "format.js", "labels.json"):
            self.assertEqual((original / rel).read_bytes(), self.tree[rel])
            self.assertEqual((protected / rel).read_bytes(), self.tree[rel])

    def test_hash_fields_and_file_maps(self):
        result = self.run_adapter()
        self.assertEqual(result["protected_sha256"], sha_bytes(PROTECTED_CJS))
        self.assertEqual(result["original_core_sha256"], sha_bytes(MIXED_CORE))
        fm = result["file_maps"]
        self.assertEqual(set(fm["original"]), set(fm["protected"]))
        self.assertEqual(fm["original"]["core.js"], sha_bytes(MIXED_CORE))
        self.assertEqual(fm["protected"]["core.js"], sha_bytes(PROTECTED_CJS))
        for rel in ("app.js", "format.js", "labels.json"):
            self.assertEqual(fm["original"][rel], self.input_files[rel])
            self.assertEqual(fm["protected"][rel], self.input_files[rel])
        self.assertEqual(fm["original"]["app.js"], fm["protected"]["app.js"])

    def test_reference_evidence_mixed_raw_strategy_and_producer_backend(self):
        evidence = self.run_adapter()["reference_evidence"]
        self.assertEqual(evidence["producer_backend"], adapter.MIXED_BACKEND)
        self.assertEqual(evidence["producer"]["mode"], "mixed")
        self.assertFalse(evidence["producer"]["baseline_reused_as_original_truth"])
        self.assertEqual(evidence["core"]["original_strategy"], "raw_commonjs_copy")
        self.assertEqual(evidence["core"]["original_core_sha256"], sha_bytes(MIXED_CORE))
        self.assertEqual(evidence["core"]["protected_overlay_sha256"], sha_bytes(PROTECTED_CJS))
        self.assertEqual(evidence["requests"], [])
        self.assertIsNone(evidence["compiler"])

    def test_protected_arm_excludes_original_core_bytes(self):
        result = self.run_adapter()
        self.assertNotIn(sha_bytes(MIXED_CORE), set(result["file_maps"]["protected"].values()))

    def test_persisted_preparation_matches_return(self):
        result = self.run_adapter()
        persisted = json.loads((self.out / "preparation.json").read_text(encoding="utf-8"))
        self.assertEqual(persisted, result)

    def test_inventory_matches_file_maps_on_disk(self):
        from antirea import jvm_app_integration as safe
        result = self.run_adapter()
        for arm in ("original", "protected"):
            root = Path(result[arm + "_root"])
            disk = {rel: e["sha256"] for rel, e in safe._tree_inventory(root).items()}
            self.assertEqual(disk, result["file_maps"][arm])

    # fail closed ------------------------------------------------------------ #
    def test_entrypoint_must_differ_from_protected_source(self):
        self.assert_rejected(entrypoint="core.js")

    def test_protected_source_must_be_listed(self):
        self.assert_rejected(protected_source="missing.js")

    def test_entrypoint_must_be_listed(self):
        self.assert_rejected(entrypoint="missing.js")

    def test_bad_backend_rejected(self):
        self.assert_rejected(producer=self.make_producer(backend="python_vm"))

    def test_bad_status_rejected(self):
        self.assert_rejected(producer=self.make_producer(status="failed"))

    def test_bad_schema_rejected(self):
        self.assert_rejected(producer=self.make_producer(schema_version=2))

    def test_identical_baseline_protected_rejected(self):
        self.assert_rejected(producer=self.make_producer(protected_bytes=MIXED_CORE))

    def test_protected_artifact_tampered_rejected(self):
        producer = self.make_producer()
        self.protected_path.write_bytes(b"tampered artifact\n")
        self.assert_rejected(producer=producer, output_dir=self.base / "o2")

    def test_protected_artifact_missing_rejected(self):
        producer = self.make_producer()
        self.protected_path.unlink()
        self.assert_rejected(producer=producer, output_dir=self.base / "o3")

    def test_baseline_bytes_field_mismatch_rejected(self):
        producer = self.make_producer()
        producer["artifacts"]["baseline"]["bytes"] = 999999
        self.assert_rejected(producer=producer, output_dir=self.base / "o4")

    def test_non_cjs_artifact_rejected(self):
        bad = self.runs / "protected.txt"
        bad.write_bytes(PROTECTED_CJS)
        producer = self.make_producer()
        producer["artifacts"]["protected"] = {"path": str(bad), "sha256": sha_bytes(PROTECTED_CJS),
                                               "bytes": len(PROTECTED_CJS)}
        self.assert_rejected(producer=producer, output_dir=self.base / "o5")

    def test_missing_project_rejected(self):
        producer = self.make_producer()
        del producer["project"]
        self.assert_rejected(producer=producer, output_dir=self.base / "o6")

    def test_project_language_not_js_ts_rejected(self):
        producer = self.make_producer()
        producer["project"]["language"] = "python"
        self.assert_rejected(producer=producer, output_dir=self.base / "o7")

    def test_coverage_missing_rejected(self):
        producer = self.make_producer()
        del producer["coverage"]
        self.assert_rejected(producer=producer, output_dir=self.base / "o8")

    def test_coverage_retains_original_bodies_rejected(self):
        producer = self.make_producer()
        producer["coverage"]["original_selected_bodies_in_protected_artifact"] = True
        self.assert_rejected(producer=producer, output_dir=self.base / "o9")

    def test_empty_roots_rejected(self):
        producer = self.make_producer()
        producer["project"]["functions"] = []
        self.assert_rejected(producer=producer, output_dir=self.base / "o10")

    def test_disallowed_suffix_rejected(self):
        data = b"declare const x: number;\n"
        (self.src / "types.d.ts").write_bytes(data)
        self.assert_rejected(input_files={**self.input_files, "types.d.ts": sha_bytes(data)})

    def test_absolute_path_rejected(self):
        self.assert_rejected(input_files={**self.input_files, "C:/evil.js": "d" * 64})

    def test_traversal_rejected(self):
        self.assert_rejected(input_files={**self.input_files, "../escape.js": "d" * 64})

    def test_reserved_component_rejected(self):
        self.assert_rejected(input_files={**self.input_files, "attackerfolder/x.js": "d" * 64})

    def test_dos_device_rejected(self):
        self.assert_rejected(input_files={**self.input_files, "nul.js": "d" * 64})

    def test_node_modules_component_rejected(self):
        self.assert_rejected(input_files={**self.input_files, "node_modules/x.js": "d" * 64})

    def test_casefold_collision_rejected(self):
        self.assert_rejected(input_files={**self.input_files, "Core.js": self.input_files["core.js"]})

    def test_snapshot_hash_mismatch_rejected(self):
        self.assert_rejected(input_files={**self.input_files, "format.js": "e" * 64})

    def test_missing_on_disk_input_rejected(self):
        self.assert_rejected(input_files={**self.input_files, "extra.js": "f" * 64})

    def test_protected_source_wrong_suffix_rejected(self):
        data = b"x\n"
        (self.src / "core.ts").write_bytes(data)
        self.assert_rejected(input_files={**self.input_files, "core.ts": sha_bytes(data)},
                             protected_source="core.ts")

    def test_entrypoint_wrong_suffix_rejected(self):
        self.assert_rejected(entrypoint="labels.json")

    def test_tools_not_a_mapping_rejected(self):
        self.assert_rejected(tools=["node"])

    def test_stop_marker_rejected(self):
        stop = self.base / "defense" / "STOP"
        stop.parent.mkdir(parents=True, exist_ok=True)
        stop.write_text("stop", encoding="utf-8")
        self.assert_rejected(stop_file=stop)

    def test_timeout_out_of_range_rejected(self):
        self.assert_rejected(timeout_seconds=0)
        self.assert_rejected(timeout_seconds=601)
        self.assert_rejected(timeout_seconds=True)

    def test_non_empty_output_dir_rejected(self):
        self.out.mkdir(parents=True)
        (self.out / "stale.txt").write_text("old", encoding="utf-8")
        self.assert_rejected()

    def test_too_many_files_rejected(self):
        inputs = dict(self.input_files)
        for i in range(adapter.MAX_APPLICATION_FILES):
            inputs["pad_%d.js" % i] = "0" * 64
        self.assert_rejected(input_files=inputs)

    def test_oversize_file_rejected(self):
        with patch.object(adapter, "MAX_FILE_BYTES", 8):
            self.assert_rejected(output_dir=self.base / "o_big")


@patch.object(adapter.process, "run_logged", fake_run_logged)
class MockedTranspileStagingTests(unittest.TestCase):
    """Pure JS/TS staging via a synthetic transpile-reference reply (no real child)."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.runs = self.base / "runs"
        self.runs.mkdir(parents=True)
        # Synthetic pinned tools (any files; the adapter hashes them from disk).
        self.node = self.runs / "node.exe"
        self.ts = self.runs / "typescript.js"
        self.node.write_bytes(b"\x4d\x5a synthetic node\n")
        self.ts.write_bytes(b"// synthetic typescript bundle\n")
        self.protected_path = self.runs / "protected.cjs"
        self.baseline_path = self.runs / "baseline.cjs"
        self.protected_path.write_bytes(PROTECTED_CJS)
        self.baseline_path.write_bytes(b'"use strict";\n// baseline\nmodule.exports = {};\n')
        self.tools = {"node": {"path": str(self.node), "sha256": sha_file(self.node)},
                      "typescript": {"path": str(self.ts), "sha256": sha_file(self.ts)}}
        # The helper is a planned trusted input (required by the adapter).
        self.trusted = {str(Path(adapter.__file__)): sha_file(adapter.__file__),
                        str(adapter.REFERENCE_HELPER): sha_file(adapter.REFERENCE_HELPER)}
        self._counter = 0

    def _write_tree(self, tree):
        self._counter += 1
        src = self.base / ("src_%d" % self._counter)
        inputs = {}
        for rel, data in tree.items():
            (src / rel).parent.mkdir(parents=True, exist_ok=True)
            (src / rel).write_bytes(data)
            inputs[rel] = sha_bytes(data)
        return src, inputs

    def _producer(self, language, source_sha, roots):
        ext = "ts" if language == "typescript" else "js"
        return {
            "schema_version": 1, "status": "artifact_created_unvalidated", "backend": adapter.PURE_BACKEND,
            "artifacts": {
                "baseline": {"path": str(self.baseline_path), "sha256": sha_file(self.baseline_path),
                             "bytes": self.baseline_path.stat().st_size},
                "protected": {"path": str(self.protected_path), "sha256": sha_bytes(PROTECTED_CJS),
                              "bytes": len(PROTECTED_CJS)}},
            "project": {"language": language, "sources": ["core." + ext],
                        "source_sha256": source_sha, "functions": roots},
            "coverage": {"selected_functions": roots, "exported_functions": roots,
                         "original_selected_bodies_in_protected_artifact": False}}

    def _run(self, *, src, inputs, protected_source, entrypoint, producer, out):
        return adapter.prepare_application(
            source_root=src, input_files=inputs, protected_source=protected_source, entrypoint=entrypoint,
            producer=producer, output_dir=out, tools=self.tools, trusted_inputs=self.trusted,
            timeout_seconds=120, stop_file=self.base / "nope" / "STOP")

    def test_pure_js_independent_transpile(self):
        src, inputs = self._write_tree({"core.js": PURE_JS_CORE, "app.js": PURE_JS_APP})
        producer = self._producer("javascript", sha_bytes(PURE_JS_CORE), ["compute", "gate"])
        result = self._run(src=src, inputs=inputs, protected_source="core.js", entrypoint="app.js",
                           producer=producer, out=self.base / "pjs")
        self.assertEqual(result["protected_relative"], "core.js")
        self.assertEqual(result["runtime_entrypoint"], "app.js")
        self.assertEqual(result["protected_sha256"], sha_bytes(PROTECTED_CJS))
        # One transpile receipt with exactly the engine-agreed wrapper keys present.
        self.assertEqual(len(result["preparation_commands"]), 1)
        prep = result["preparation_commands"][0]
        for key in ("receipt_path", "receipt_sha256", "stdout_log", "stderr_log", "label", "kind", "returncode"):
            self.assertIn(key, prep)
        self.assertEqual(prep["returncode"], 0)
        evidence = result["reference_evidence"]
        self.assertEqual(evidence["producer_backend"], adapter.PURE_BACKEND)
        self.assertEqual(evidence["core"]["original_strategy"], "independent_commonjs_transpile")
        self.assertEqual(len(evidence["requests"]), 1)
        self.assertEqual(evidence["requests"][0]["receipt_index"], 0)
        request_path = Path(evidence["requests"][0]["path"])
        self.assertTrue(request_path.is_file())
        self.assertEqual(sha_file(request_path), evidence["requests"][0]["sha256"])
        self.assertLessEqual({"compute", "gate"}, set(evidence["core"]["exported_names"]))
        # Original-arm core is an independent CJS rendering, NOT the raw export source.
        original_core = (Path(result["original_root"]) / "core.js").read_bytes()
        self.assertNotEqual(original_core, PURE_JS_CORE)
        self.assertIn(b"exports", original_core)
        self.assertEqual(result["original_core_sha256"], sha_bytes(original_core))
        self.assertEqual((Path(result["protected_root"]) / "core.js").read_bytes(), PROTECTED_CJS)
        self.assertNotEqual(result["original_core_sha256"], result["protected_sha256"])

    def test_pure_js_persisted_preparation_matches_return(self):
        src, inputs = self._write_tree({"core.js": PURE_JS_CORE, "app.js": PURE_JS_APP})
        producer = self._producer("javascript", sha_bytes(PURE_JS_CORE), ["compute", "gate"])
        out = self.base / "pjs2"
        result = self._run(src=src, inputs=inputs, protected_source="core.js", entrypoint="app.js",
                           producer=producer, out=out)
        self.assertEqual(json.loads((out / "preparation.json").read_text(encoding="utf-8")), result)

    def test_pure_js_missing_export_rejected(self):
        src, inputs = self._write_tree({"core.js": PURE_JS_CORE, "app.js": PURE_JS_APP})
        producer = self._producer("javascript", sha_bytes(PURE_JS_CORE), ["compute", "absent"])
        with self.assertRaises(ERROR):
            self._run(src=src, inputs=inputs, protected_source="core.js", entrypoint="app.js",
                      producer=producer, out=self.base / "pjsmiss")

    def test_pure_js_requires_helper_as_trusted_pin(self):
        src, inputs = self._write_tree({"core.js": PURE_JS_CORE, "app.js": PURE_JS_APP})
        producer = self._producer("javascript", sha_bytes(PURE_JS_CORE), ["compute", "gate"])
        trusted = {str(Path(adapter.__file__)): sha_file(adapter.__file__)}   # helper NOT planned
        with self.assertRaises(ERROR):
            adapter.prepare_application(
                source_root=src, input_files=inputs, protected_source="core.js", entrypoint="app.js",
                producer=producer, output_dir=self.base / "pjsnohelper", tools=self.tools,
                trusted_inputs=trusted, timeout_seconds=120, stop_file=self.base / "nope" / "STOP")

    def test_pure_js_requires_typescript_tool(self):
        src, inputs = self._write_tree({"core.js": PURE_JS_CORE, "app.js": PURE_JS_APP})
        producer = self._producer("javascript", sha_bytes(PURE_JS_CORE), ["compute", "gate"])
        with self.assertRaises(ERROR):
            adapter.prepare_application(
                source_root=src, input_files=inputs, protected_source="core.js", entrypoint="app.js",
                producer=producer, output_dir=self.base / "pjsnots",
                tools={"node": self.tools["node"]}, trusted_inputs=self.trusted,
                timeout_seconds=120, stop_file=self.base / "nope" / "STOP")

    def test_pure_ts_multifile(self):
        tree = {"core.ts": PURE_TS_CORE, "app.ts": PURE_TS_APP, "format.ts": PURE_TS_FORMAT}
        src, inputs = self._write_tree(tree)
        producer = self._producer("typescript", sha_bytes(PURE_TS_CORE), ["compute", "gate"])
        result = self._run(src=src, inputs=inputs, protected_source="core.ts", entrypoint="app.ts",
                           producer=producer, out=self.base / "pts")
        self.assertEqual(result["language"], "typescript")
        self.assertEqual(result["protected_relative"], "core.js")
        self.assertEqual(result["runtime_entrypoint"], "app.js")
        fm = result["file_maps"]
        self.assertEqual(set(fm["original"]), {"core.js", "app.js", "format.js"})
        self.assertEqual(set(fm["protected"]), {"core.js", "app.js", "format.js"})
        for arm in ("original", "protected"):
            self.assertNotIn("core.ts", fm[arm])
            self.assertNotIn("app.ts", fm[arm])
        self.assertFalse(result["reference_evidence"]["core"]["original_typescript_in_runtime_tree"])
        self.assertEqual(fm["original"]["app.js"], fm["protected"]["app.js"])   # fixed caller code
        self.assertEqual(fm["protected"]["core.js"], sha_bytes(PROTECTED_CJS))
        self.assertEqual(fm["original"]["core.js"], result["original_core_sha256"])

    def test_pure_ts_explicit_ts_specifier_rejected(self):
        app = b'import { compute } from "./core.ts";\nprocess.stdout.write(String(compute(1, 2)));\n'
        src, inputs = self._write_tree({"core.ts": PURE_TS_CORE, "app.ts": app})
        producer = self._producer("typescript", sha_bytes(PURE_TS_CORE), ["compute", "gate"])
        with self.assertRaises(ERROR):
            self._run(src=src, inputs=inputs, protected_source="core.ts", entrypoint="app.ts",
                      producer=producer, out=self.base / "ptsbad")

    def test_pure_js_stop_marker_before_child_rejected(self):
        src, inputs = self._write_tree({"core.js": PURE_JS_CORE, "app.js": PURE_JS_APP})
        producer = self._producer("javascript", sha_bytes(PURE_JS_CORE), ["compute", "gate"])
        stop = self.base / "stopdir" / "STOP"
        stop.parent.mkdir(parents=True, exist_ok=True)
        stop.write_text("stop", encoding="utf-8")
        with self.assertRaises(ERROR):
            adapter.prepare_application(
                source_root=src, input_files=inputs, protected_source="core.js", entrypoint="app.js",
                producer=producer, output_dir=self.base / "pjsstop", tools=self.tools,
                trusted_inputs=self.trusted, timeout_seconds=120, stop_file=stop)

    def test_preparation_deadline_includes_preflight_hashing(self):
        src, inputs = self._write_tree({"core.js": PURE_JS_CORE, "app.js": PURE_JS_APP})
        producer = self._producer("javascript", sha_bytes(PURE_JS_CORE), ["compute", "gate"])
        with patch.object(adapter.time, "monotonic", side_effect=[0.0, 121.0]), \
                patch.object(adapter.process, "run_logged") as child:
            with self.assertRaisesRegex(ERROR, "deadline"):
                self._run(src=src, inputs=inputs, protected_source="core.js", entrypoint="app.js",
                          producer=producer, out=self.base / "deadline")
            child.assert_not_called()

    def _reject_post_helper_drift(self, target):
        src, inputs = self._write_tree({"core.js": PURE_JS_CORE, "app.js": PURE_JS_APP})
        producer = self._producer("javascript", sha_bytes(PURE_JS_CORE), ["compute", "gate"])

        def drifting(argv, directory, log_prefix, timeout, env=None, stdin=None, *, cancel_file=None):
            result = fake_run_logged(argv, directory, log_prefix, timeout, env, stdin,
                                     cancel_file=cancel_file)
            path = {"tool": self.node, "source": src / "core.js",
                    "request": Path(directory) / "transpile.request.json"}[target]
            path.write_bytes(b"changed after synthetic helper\n")
            return result

        with patch.object(adapter.process, "run_logged", drifting):
            with self.assertRaisesRegex(ERROR, "pinned input changed"):
                self._run(src=src, inputs=inputs, protected_source="core.js", entrypoint="app.js",
                          producer=producer, out=self.base / ("drift-" + target))

    def test_tool_drift_after_helper_refused(self):
        self._reject_post_helper_drift("tool")

    def test_source_drift_after_helper_refused(self):
        self._reject_post_helper_drift("source")

    def test_request_drift_after_helper_refused(self):
        self._reject_post_helper_drift("request")


if __name__ == "__main__":
    unittest.main()
