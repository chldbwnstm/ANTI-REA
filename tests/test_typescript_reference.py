"""Tests for the independent pinned TypeScript transpile-reference helper.

Fixtures are owned literal TypeScript strings written under a per-test temporary
workspace; no .runs artifact or received analysis report is imported. The live
transpile/equivalence/STOP tests require an installed Node + TypeScript toolchain
and are skipped when one is not resolvable. Compiler/source/helper drift, timeout,
cancellation, malformed replies and cleanup-failure rejection are exercised
through mocks so they are deterministic and never execute a real attack or
received code.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from antirea import typescript_reference as tr
from antirea.process import run_logged as _real_run_logged


# ---------------------------------------------------------------------------
# Toolchain discovery (live tests only)
# ---------------------------------------------------------------------------

def _discover_toolchain_files():
    try:
        from antirea import javascript_frontend as jf
        toolchain = jf.discover_toolchain()
    except Exception:
        return None
    files = toolchain.get("files", {})
    if "node" not in files or "typescript" not in files:
        return None
    return {"node": {"path": files["node"]["path"], "sha256": files["node"]["sha256"]},
            "typescript": {"path": files["typescript"]["path"], "sha256": files["typescript"]["sha256"]}}


_TOOLCHAIN = _discover_toolchain_files()
_requires_toolchain = unittest.skipUnless(_TOOLCHAIN is not None,
                                          "installed Node + TypeScript toolchain not resolvable")

# A dummy toolchain whose pins are satisfied by pointing node/typescript at an
# owned fixture file (used only in mocked-child tests where no tool is executed).
_DUMMY = {"node": {"path": "x", "sha256": "0" * 64}, "typescript": {"path": "y", "sha256": "0" * 64}}


# ---------------------------------------------------------------------------
# Owned literal fixtures
# ---------------------------------------------------------------------------

# A single pure scalar function (compile_mixed-selectable), an enum, a namespace
# and a *used* JS-sibling import, with a shebang. BOM is added per test as bytes.
FIXTURE_TS = (
    "#!/usr/bin/env node\n"
    "import { helper } from \"./sib.js\";\n"
    "export enum Color { Red, Green = 2 }\n"
    "export namespace NS { export const K = 7; }\n"
    "export const used = helper(1);\n"
    "function add(a: number, b: number): number { return a + b; }\n"
    "export { add };\n"
)

INVALID_TS = "export function broken(a: number): number { return a + ; }\n"


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _compile_mixed_working(work_dir, raw):
    """Independent builder baseline: compile_mixed.cjs working_source + shebang.

    The compiler child is driven through the SAME bounded wrapper the helper uses
    (antirea.process.run_logged with a real STOP cancel_file, an allow-listed clean
    environment and a private TEMP), so this qualifying evidence is never an
    unwrapped shell invocation.
    """
    mixed = ROOT / "tools" / "javascript_frontend" / "compile_mixed.cjs"
    req = json.dumps({"source": raw.decode("utf-8-sig"), "language": "typescript", "functions": ["add"]})
    work_dir.mkdir(parents=True, exist_ok=True)
    env = tr._child_env(work_dir / "tmp")
    stop = ROOT / ".runs" / "defense-loop" / "STOP"
    proc = _real_run_logged(
        [_TOOLCHAIN["node"]["path"], "--no-addons", mixed.as_posix(), _TOOLCHAIN["typescript"]["path"]],
        work_dir, work_dir / "baseline", 60, env=env, stdin=req, cancel_file=stop)
    assert proc["returncode"] == 0 and not proc["cancelled"] and not proc["timed_out"], proc
    assert tr._cleanup_ok(proc), proc
    data = json.loads(Path(proc["stdout"]).read_text(encoding="utf-8"))
    assert data.get("status") == "ok", data
    return data["result"]["shebang"], data["result"]["working_source"]


def _fake_process(stdout_path, *, returncode=0, cancelled=False, timed_out=False, cleanup=None):
    return {"argv": ["node"], "returncode": returncode, "pid": 123, "timed_out": timed_out,
            "cancelled": cancelled, "seconds": 0.01, "stdout": str(stdout_path),
            "stderr": str(stdout_path) + ".err",
            "cleanup": cleanup if cleanup is not None else {
                "status": "assigned_job_empty", "job_assigned": True, "active_after": 0,
                "parent_exit_confirmed": True, "job_handle_closed": True}}


class _Base(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.ws = Path(self._td.name)

    def write_source(self, text, *, bom=False, name="core.ts"):
        raw = (("﻿" + text) if bom else text).encode("utf-8")
        src_dir = self.ws / "pkg"
        src_dir.mkdir(parents=True, exist_ok=True)
        src = src_dir / name
        src.write_bytes(raw)
        return src, raw

    def build(self, src, raw, *, out_name="reference", toolchain=None, expected=None, timeout=60):
        # Output is always a fresh dir under <workspace>/.runs (required by the helper).
        return tr.build_reference(
            src, self.ws / ".runs" / "orca-wave5-ts-reference" / out_name, workspace_root=self.ws,
            toolchain_files=toolchain if toolchain is not None else _TOOLCHAIN,
            expected_source_sha256=expected if expected is not None else _sha(raw),
            timeout_seconds=timeout)

    def out_dir(self, out_name="reference"):
        return self.ws / ".runs" / "orca-wave5-ts-reference" / out_name

    def dummy_toolchain_pointing_at(self, src, raw):
        """A toolchain whose node/typescript pins resolve to an owned fixture file,
        so pre-launch pinning passes while the child itself is mocked."""
        return {"node": {"path": str(src), "sha256": _sha(raw)},
                "typescript": {"path": str(src), "sha256": _sha(raw)}}


# ---------------------------------------------------------------------------
# helper_tool_pins
# ---------------------------------------------------------------------------

class HelperToolPinsTests(unittest.TestCase):
    def test_shape(self):
        pins = tr.helper_tool_pins()
        self.assertIsInstance(pins, list)
        self.assertEqual(len(pins), 2)
        names = set()
        for pin in pins:
            self.assertEqual(set(pin), {"path", "sha256"})
            self.assertIsInstance(pin["path"], str)
            self.assertTrue(tr._hex64(pin["sha256"]))
            names.add(Path(pin["path"]).name)
        self.assertEqual(names, {"typescript_reference.py", "mixed_reference.cjs"})


# ---------------------------------------------------------------------------
# Live: creation, runtime-JS preservation, shebang/BOM, baseline equivalence
# ---------------------------------------------------------------------------

@_requires_toolchain
class LiveReferenceTests(_Base):
    def test_reference_created_and_runtime_constructs_preserved(self):
        src, raw = self.write_source(FIXTURE_TS)
        res = self.build(src, raw)
        self.assertEqual(res["status"], "reference_created", res.get("error"))
        self.assertEqual(res["source_sha256"], _sha(raw))
        self.assertEqual(res["process"]["returncode"], 0)
        self.assertIs(res["process"]["cancelled"], False)
        self.assertIs(res["process"]["timed_out"], False)
        self.assertTrue(res["pin_recheck"]["ok"])

        ref = res["reference"]
        ref_path = Path(ref["path"])
        self.assertEqual(ref_path.suffix, ".cjs")
        self.assertTrue(ref_path.is_relative_to(self.out_dir()))
        data = ref_path.read_bytes()
        self.assertEqual(_sha(data), ref["sha256"])
        self.assertEqual(len(data), ref["bytes"])

        emitted = data.decode("utf-8")
        # enum and namespace become ordinary runtime JS (IIFEs), not erased types.
        self.assertIn("var Color;", emitted)
        self.assertIn("(function (Color)", emitted)
        self.assertIn("var NS;", emitted)
        self.assertIn("NS.K = 7;", emitted)
        # a used JS-sibling import survives as a runtime require.
        self.assertIn('require("./sib.js")', emitted)
        # type annotations are erased from the scalar function body.
        self.assertIn("function add(a, b)", emitted)

    def test_shebang_held_out_and_bom_stripped(self):
        src, raw = self.write_source(FIXTURE_TS, bom=True)
        res = self.build(src, raw)
        self.assertEqual(res["status"], "reference_created", res.get("error"))
        # RAW digest includes the BOM; normalized digest is BOM-stripped (utf-8-sig).
        self.assertEqual(res["source_sha256"], _sha(raw))
        self.assertEqual(res["normalized_source_sha256"], _sha(raw.decode("utf-8-sig").encode("utf-8")))
        self.assertNotEqual(res["source_sha256"], res["normalized_source_sha256"])
        self.assertIs(res["shebang_present"], True)

        data = Path(res["reference"]["path"]).read_bytes()
        # The shebang is re-attached at the very start; no BOM leaks into the output.
        self.assertTrue(data.startswith(b"#!/usr/bin/env node\n"))
        self.assertFalse(data.startswith(b"\xef\xbb\xbf"))
        # working_source_sha256 is the emitted JS WITHOUT the shebang.
        working = data[data.index(b"\n") + 1:]
        self.assertEqual(res["working_source_sha256"], _sha(working))

    def test_exact_baseline_equivalence_with_compile_mixed(self):
        src, raw = self.write_source(FIXTURE_TS, bom=True)
        res = self.build(src, raw)
        self.assertEqual(res["status"], "reference_created", res.get("error"))
        shebang, working = _compile_mixed_working(self.ws / ".runs" / "baseline", raw)
        # Same emitted working source as the existing mixed builder path.
        self.assertEqual(res["working_source_sha256"], _sha(working.encode("utf-8")))
        # And the reference file equals the builder's baseline.cjs (shebang + working).
        self.assertEqual(Path(res["reference"]["path"]).read_bytes(), (shebang + working).encode("utf-8"))

    def test_invalid_typescript_fails_and_persists_report(self):
        src, raw = self.write_source(INVALID_TS)
        res = self.build(src, raw)
        self.assertEqual(res["status"], "failed")
        self.assertIsNone(res["reference"])
        self.assertTrue(res.get("error"))
        # reference.json is persisted even on child rejection; no .cjs is produced.
        self.assertTrue((self.out_dir() / "reference.json").is_file())
        self.assertFalse((self.out_dir() / "reference.cjs").exists())

    def test_stop_cancels_before_launch(self):
        src, raw = self.write_source(FIXTURE_TS)
        stop = self.ws / ".runs" / "defense-loop" / "STOP"
        stop.parent.mkdir(parents=True)
        stop.write_text("stop", encoding="utf-8")
        res = self.build(src, raw)
        self.assertEqual(res["status"], "cancelled")
        self.assertIsNone(res["process"])  # no child was launched
        self.assertTrue((self.out_dir() / "reference.json").is_file())

    def test_source_drift_raises(self):
        src, raw = self.write_source(FIXTURE_TS)
        with self.assertRaises(ValueError):
            self.build(src, raw, expected=_sha(raw + b"x"))

    def test_compiler_drift_raises(self):
        src, raw = self.write_source(FIXTURE_TS)
        drifted = {"node": dict(_TOOLCHAIN["node"]),
                   "typescript": {"path": _TOOLCHAIN["typescript"]["path"], "sha256": "0" * 64}}
        with self.assertRaises(ValueError):
            self.build(src, raw, toolchain=drifted)

    def test_helper_drift_during_child_fails(self):
        src, raw = self.write_source(FIXTURE_TS)
        real = tr._pin_snapshot
        state = {"n": 0}

        def fake_pin_snapshot(source_path, node_path, ts_path):
            snap = dict(real(source_path, node_path, ts_path))
            state["n"] += 1
            if state["n"] >= 2:  # the post-child snapshot: pretend the helper changed
                snap["helper"] = "deadbeef" * 8
            return snap

        with mock.patch.object(tr, "_pin_snapshot", fake_pin_snapshot):
            res = self.build(src, raw)
        self.assertEqual(res["status"], "failed")
        self.assertIn("helper", res["error"])
        self.assertIsNone(res["reference"])

    @unittest.skipUnless(sys.platform == "win32", "Windows-Job cleanup gate is Windows-only")
    def test_cleanup_failure_fails_closed(self):
        """On Windows the helper itself refuses reference_created when run_logged could
        not verify an empty, closed kill-on-close Job for the child, and still surfaces
        the failing cleanup verbatim for the caller."""
        src, raw = self.write_source(FIXTURE_TS)

        def wrapping_run_logged(command, directory, log_prefix, timeout, **kwargs):
            process = _real_run_logged(command, directory, log_prefix, timeout, **kwargs)
            process["cleanup"] = {"status": "job_termination_pending", "job_assigned": True,
                                  "active_after": 1, "parent_exit_confirmed": True, "job_handle_closed": False}
            return process

        with mock.patch.object(tr, "run_logged", wrapping_run_logged):
            res = self.build(src, raw)
        self.assertEqual(res["status"], "failed")
        self.assertIn("cleanup", res["error"])
        self.assertIsNone(res["reference"])
        # The failing cleanup is surfaced verbatim for the caller/auditor.
        self.assertEqual(res["process"]["cleanup"]["status"], "job_termination_pending")
        self.assertIs(res["cleanup_verified"], False)


# ---------------------------------------------------------------------------
# Malformed inputs -> ValueError before any child (no toolchain required)
# ---------------------------------------------------------------------------

class MalformedInputTests(_Base):
    def test_bad_expected_hash_raises(self):
        src, raw = self.write_source(FIXTURE_TS)
        with self.assertRaises(ValueError):
            self.build(src, raw, toolchain=_DUMMY, expected="not-a-hash")

    def test_bad_timeout_raises(self):
        src, raw = self.write_source(FIXTURE_TS)
        with self.assertRaises(ValueError):
            self.build(src, raw, toolchain=_DUMMY, timeout=0)

    def test_missing_toolchain_entry_raises(self):
        src, raw = self.write_source(FIXTURE_TS)
        with self.assertRaises(ValueError):
            self.build(src, raw, toolchain={"node": {"path": "x", "sha256": "0" * 64}})

    def test_non_ts_source_raises(self):
        src, raw = self.write_source(FIXTURE_TS, name="core.js")
        with self.assertRaises(ValueError):
            self.build(src, raw, toolchain=_DUMMY)

    def test_output_not_under_runs_raises(self):
        src, raw = self.write_source(FIXTURE_TS)
        with self.assertRaises(ValueError):
            tr.build_reference(src, self.ws / "reference", workspace_root=self.ws,
                               toolchain_files=_DUMMY, expected_source_sha256=_sha(raw), timeout_seconds=60)

    def test_output_inside_source_tree_raises(self):
        # Place the source under .runs so the output can be under .runs *and* inside
        # the source tree, isolating the source-tree rule from the .runs rule.
        src_dir = self.ws / ".runs" / "pkg"
        src_dir.mkdir(parents=True)
        src = src_dir / "core.ts"
        raw = FIXTURE_TS.encode("utf-8")
        src.write_bytes(raw)
        with self.assertRaises(ValueError):
            tr.build_reference(src, src.parent / "ref", workspace_root=self.ws,
                               toolchain_files=_DUMMY, expected_source_sha256=_sha(raw), timeout_seconds=60)

    def test_existing_output_dir_raises(self):
        src, raw = self.write_source(FIXTURE_TS)
        out = self.out_dir()
        out.mkdir(parents=True)
        with self.assertRaises(ValueError):
            tr.build_reference(src, out, workspace_root=self.ws,
                               toolchain_files=_DUMMY, expected_source_sha256=_sha(raw), timeout_seconds=60)

    def test_non_utf8_source_raises(self):
        src_dir = self.ws / "pkg"
        src_dir.mkdir(parents=True)
        src = src_dir / "core.ts"
        raw = b"\xff\xfe not valid utf-8 \xff"
        src.write_bytes(raw)
        with self.assertRaises(ValueError):
            tr.build_reference(src, self.out_dir(), workspace_root=self.ws,
                               toolchain_files=self.dummy_toolchain_pointing_at(src, raw),
                               expected_source_sha256=_sha(raw), timeout_seconds=60)


# ---------------------------------------------------------------------------
# Child outcome handling with a mocked child (no toolchain required)
# ---------------------------------------------------------------------------

class MockedChildTests(_Base):
    def _run_with(self, src, raw, fake):
        with mock.patch.object(tr, "run_logged", fake):
            return tr.build_reference(src, self.out_dir(), workspace_root=self.ws,
                                      toolchain_files=self.dummy_toolchain_pointing_at(src, raw),
                                      expected_source_sha256=_sha(raw), timeout_seconds=5)

    def test_timeout_reports_timed_out(self):
        src, raw = self.write_source(FIXTURE_TS)

        def fake(command, directory, log_prefix, timeout, **kwargs):
            log_prefix.parent.mkdir(parents=True, exist_ok=True)
            out = log_prefix.with_suffix(".stdout.log")
            out.write_text("", encoding="utf-8")
            return _fake_process(out, returncode=None, timed_out=True)

        res = self._run_with(src, raw, fake)
        self.assertEqual(res["status"], "timed_out")
        self.assertTrue((self.out_dir() / "reference.json").is_file())

    def test_cancel_during_child_reports_cancelled(self):
        src, raw = self.write_source(FIXTURE_TS)

        def fake(command, directory, log_prefix, timeout, **kwargs):
            log_prefix.parent.mkdir(parents=True, exist_ok=True)
            out = log_prefix.with_suffix(".stdout.log")
            out.write_text("", encoding="utf-8")
            return _fake_process(out, returncode=None, cancelled=True)

        res = self._run_with(src, raw, fake)
        self.assertEqual(res["status"], "cancelled")

    def test_malformed_reply_fails(self):
        src, raw = self.write_source(FIXTURE_TS)

        def fake(command, directory, log_prefix, timeout, **kwargs):
            log_prefix.parent.mkdir(parents=True, exist_ok=True)
            out = log_prefix.with_suffix(".stdout.log")
            out.write_text("this is {{{ not json", encoding="utf-8")
            return _fake_process(out, returncode=0)

        res = self._run_with(src, raw, fake)
        self.assertEqual(res["status"], "failed")
        self.assertIn("child reply", res["error"])

    def test_nonzero_exit_fails(self):
        src, raw = self.write_source(FIXTURE_TS)

        def fake(command, directory, log_prefix, timeout, **kwargs):
            log_prefix.parent.mkdir(parents=True, exist_ok=True)
            out = log_prefix.with_suffix(".stdout.log")
            out.write_text(json.dumps({"status": "rejected", "error": "boom"}), encoding="utf-8")
            return _fake_process(out, returncode=2)

        res = self._run_with(src, raw, fake)
        self.assertEqual(res["status"], "failed")
        self.assertIn("boom", res["error"])

    def test_schema_valid_but_inconsistent_reply_fails(self):
        """A well-formed reply whose reference bytes are NOT shebang+working is rejected."""
        src, raw = self.write_source(FIXTURE_TS)
        working = b"function x(){}"
        bad_reference = b"TAMPERED" + working  # not equal to shebang(empty)+working
        reply = {"status": "ok", "language": "typescript", "transpiled": True, "source_executed": False,
                 "compiler_version": "5.9.2", "shebang_present": False, "shebang_bytes": 0,
                 "shebang_b64": "", "working_b64": base64.b64encode(working).decode(),
                 "working_bytes": len(working), "reference_b64": base64.b64encode(bad_reference).decode(),
                 "reference_bytes": len(bad_reference)}

        def fake(command, directory, log_prefix, timeout, **kwargs):
            log_prefix.parent.mkdir(parents=True, exist_ok=True)
            out = log_prefix.with_suffix(".stdout.log")
            out.write_text(json.dumps(reply), encoding="utf-8")
            return _fake_process(out, returncode=0)

        res = self._run_with(src, raw, fake)
        self.assertEqual(res["status"], "failed")
        self.assertTrue("reference bytes" in res["error"] or "malformed" in res["error"])


class RootReviewRegressionTests(_Base):
    def test_reserved_paths_rejected_before_any_filesystem_guard(self):
        # No private input is created, stat-ed or read; only synthetic temp paths.
        for name in ("env.setting", "LINKREPRO", "rea-analysis-reports", "attackerfolder", "defense-loop"):
            path = self.ws / name / "tool.exe"
            with self.subTest(name=name), mock.patch.object(tr, "_frontend_no_links") as guard:
                for operation in (lambda: tr._hash(path), lambda: tr._read(path, 16),
                                  lambda: tr._pin_installed({"path": str(path), "sha256": "0" * 64}, "tool")):
                    with self.assertRaisesRegex(ValueError, "reserved"):
                        operation()
                guard.assert_not_called()

    def test_missing_pin_after_child_persists_failed_reference(self):
        src, raw = self.write_source(FIXTURE_TS)
        original = tr._pin_snapshot
        calls = 0

        def snapshot(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise FileNotFoundError("owned fixture pin disappeared")
            return original(*args)

        with mock.patch.object(tr, "_pin_snapshot", snapshot), mock.patch.object(
                tr, "run_logged", return_value=_fake_process(self.out_dir() / "worker.stdout.log")) as child:
            result = self.build(src, raw, toolchain=self.dummy_toolchain_pointing_at(src, raw))
        child.assert_called_once()
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["pin_recheck"]["ok"])
        self.assertIsNone(result["reference"])
        self.assertEqual(json.loads((self.out_dir() / "reference.json").read_text(encoding="utf-8")), result)

    def test_read_to_snapshot_drift_refused_before_child(self):
        src, raw = self.write_source(FIXTURE_TS)
        original = tr._pin_snapshot

        def snapshot(*args):
            result = original(*args)
            result["source"] = "0" * 64
            return result

        with mock.patch.object(tr, "_pin_snapshot", snapshot), mock.patch.object(tr, "run_logged") as child:
            with self.assertRaisesRegex(ValueError, "pre-launch pin snapshot"):
                self.build(src, raw, toolchain=self.dummy_toolchain_pointing_at(src, raw))
        child.assert_not_called()


if __name__ == "__main__":
    unittest.main()
