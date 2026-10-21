"""Cargo capture helper regressions using temporary files and mocked processes.

No test starts Cargo, rustc, a linker, a recorder, or a target. Synthetic process
receipts below are test data, not evidence of a real Windows Job or build.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from antirea import rust_cargo_build as subject


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def process_record(original_argv, prefix, **changes):
    result = {
        "argv": list(original_argv), "returncode": 0, "pid": 31415,
        "timed_out": False, "cancelled": False, "seconds": 0.01,
        "stdout": str(prefix) + ".stdout.log",
        "stderr": str(prefix) + ".stderr.log",
        "cleanup": {
            "method": "windows_job", "status": "assigned_job_empty",
            "job_assigned": True, "active_after": 0, "parent_pid": 31415,
            "parent_exit_confirmed": True, "job_handle_closed": True,
        },
    }
    result.update(changes)
    return result


class FileFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="antirea-cargo-build-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.never_run = self.stack.enter_context(mock.patch.object(
            subject, "run_logged", side_effect=AssertionError("unexpected process request")))
        self.stack.enter_context(mock.patch.object(
            subprocess, "Popen", side_effect=AssertionError("tests must not create processes")))

    def file(self, relative, raw=b"owned fixture"):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def fake_native(self):
        linker = self.file("sdk/bin/link.exe", b"fake linker, never executable")
        self.file("sdk/bin/link-helper.dll", b"fake helper")
        library = self.file("sdk/lib/runtime.lib", b"fake library")
        config = {
            "schema_version": 1, "linker": str(linker),
            "library_directories": [str(library.parent)],
        }
        config_path = self.file(".tools/rust-cargo-build-toolchain.json", encoded(config))
        return config_path, config

    def fake_environment_inputs(self):
        config_path, _ = self.fake_native()
        native = subject.native_link_context(config_path, workspace_root=self.root)
        rustc = self.file("rust/bin/rustc.exe", b"fake rustc, never executable")
        windows = self.root / "fake-windows"
        (windows / "System32").mkdir(parents=True)
        private = self.root / "private"
        private.mkdir()
        tools = {"selection": {"rustc": str(rustc)}}
        host = {"SYSTEMROOT": str(windows), "WINDIR": str(windows),
                "PATH": "ambient-path-is-not-forwarded"}
        return tools, native, host, private


class PathTests(FileFixture):
    def test_absolute_regular_path_and_fresh_leaf(self):
        path = self.file("owned/input.rs")
        self.assertEqual(subject._path(path), path)
        fresh = path.parent / "fresh.json"
        self.assertEqual(subject._path(fresh, existing=False), fresh)
        self.assertFalse(fresh.exists())

    def test_relative_traversal_missing_ancestor_and_stream_rejected(self):
        paths = [Path("relative.rs"), self.root / ".." / "foreign.rs",
                 self.root / "missing-parent" / "output.json", self.root / "file:stream"]
        for path in paths:
            with self.subTest(path=path), self.assertRaises(ValueError):
                subject._path(path, existing=False)

    def test_environment_dump_name_rejected_before_open(self):
        # This nonexistent synthetic name is never opened, hashed or written.
        with mock.patch.object(Path, "open", side_effect=AssertionError("must not open")):
            with self.assertRaisesRegex(ValueError, "environment dump"):
                subject._path(self.root / "env.setting", existing=False)

    def test_symlink_and_reparse_ancestors_rejected(self):
        leaf = self.file("ordinary/leaf.bin")
        original = Path.lstat
        for mode, attributes in ((stat.S_IFLNK, 0), (stat.S_IFDIR, 0x400)):
            def fake_lstat(path, *args, **kwargs):
                if path == leaf.parent:
                    return SimpleNamespace(st_mode=mode, st_file_attributes=attributes, st_nlink=1)
                return original(path, *args, **kwargs)
            with self.subTest(attributes=attributes), mock.patch.object(Path, "lstat", fake_lstat):
                with self.assertRaisesRegex(ValueError, "linked capture path"):
                    subject._path(leaf)

    def test_trusted_input_hardlink_rejected_but_explicit_inventory_mode_allows(self):
        path = self.file("one.bin")
        alias = self.root / "two.bin"
        os.link(path, alias)
        with self.assertRaisesRegex(ValueError, "hardlinked trusted input"):
            subject._file(path)
        item = subject._file(path, hardlinks=True)
        self.assertEqual(item["sha256"], sha(b"owned fixture"))
        self.assertEqual(item["bytes"], len(b"owned fixture"))


class ReadTests(FileFixture):
    def test_file_descriptor_hash_bytes_and_identity(self):
        path = self.file("input.bin", b"\x00\xffowned")
        self.assertEqual(subject._file(path), {
            "path": str(path), "sha256": sha(b"\x00\xffowned"), "bytes": 7,
        })

    def test_file_size_and_nonregular_type_rejected(self):
        path = self.file("large.bin", b"12345")
        with mock.patch.object(subject, "MAX_FILE_BYTES", 4):
            with self.assertRaisesRegex(ValueError, "type/size"):
                subject._file(path)
        with self.assertRaisesRegex(ValueError, "type/size"):
            subject._file(self.root)

    def test_file_mutation_during_hash_rejected(self):
        path = self.file("changing.bin", b"before")
        original = subject.hashlib.file_digest
        def mutate(stream, algorithm):
            digest = original(stream, algorithm)
            path.write_bytes(b"after, a different length")
            return digest
        with mock.patch.object(subject.hashlib, "file_digest", side_effect=mutate):
            with self.assertRaisesRegex(ValueError, "changed during capture hash"):
                subject._file(path)

    def test_read_valid_json_and_duplicate_or_nonfinite_json_rejected(self):
        path = self.file("document.json", b'{"schema_version":1}')
        self.assertEqual(subject._read(path), {"schema_version": 1})
        for raw in (b'{"key":1,"key":2}', b'{"key":NaN}', b'not-json', b'\xff'):
            path.write_bytes(raw)
            with self.subTest(raw=raw), self.assertRaises((ValueError, UnicodeError)):
                subject._read(path)

    def test_structured_read_limit_applies_before_read_bytes(self):
        path = self.file("document.json", b'{"key":1}')
        with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("over-limit read")):
            with self.assertRaisesRegex(ValueError, "exceeds limit"):
                subject._read(path, limit=3)

    def test_structured_read_hash_checked_after_consumption(self):
        path = self.file("document.json", b'{"key":1}')
        with mock.patch.object(Path, "read_bytes", return_value=b'{"key":2}'):
            with self.assertRaisesRegex(ValueError, "changed while reading"):
                subject._read(path)

    def test_bound_bytes_accepts_complete_and_hash_only_descriptors(self):
        path = self.file("evidence.bin", b"evidence")
        item = subject._file(path)
        self.assertEqual(subject._bound_bytes(item), b"evidence")
        self.assertEqual(subject._bound_bytes({"path": item["path"], "sha256": item["sha256"]}), b"evidence")

    def test_bound_bytes_rejects_changed_hash_size_and_file(self):
        path = self.file("evidence.bin", b"evidence")
        item = subject._file(path)
        for changed in ({**item, "sha256": "0" * 64}, {**item, "bytes": 999}):
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, "descriptor changed"):
                subject._bound_bytes(changed)
        path.write_bytes(b"mutated")
        with self.assertRaisesRegex(ValueError, "descriptor changed"):
            subject._bound_bytes(item)

    def test_bound_bytes_rejects_boolean_negative_noninteger_size(self):
        path = self.file("one.bin", b"1")
        item = subject._file(path)
        for size in (True, -1, 1.0, "1"):
            with self.subTest(size=size), self.assertRaises(ValueError):
                subject._bound_bytes({**item, "bytes": size})

    def test_bound_bytes_limit_and_during_read_mutation(self):
        path = self.file("evidence.bin", b"evidence")
        item = subject._file(path)
        with self.assertRaisesRegex(ValueError, "read limit"):
            subject._bound_bytes(item, limit=2)
        with mock.patch.object(Path, "read_bytes", return_value=b"different"):
            with self.assertRaisesRegex(ValueError, "changed during consumption"):
                subject._bound_bytes(item)

    def test_write_is_exclusive_and_preserves_existing_file(self):
        path = self.root / "new.json"
        subject._write(path, {"z": 2, "a": 1})
        before = path.read_bytes()
        with self.assertRaises(FileExistsError):
            subject._write(path, {"different": True})
        self.assertEqual(path.read_bytes(), before)


class InventoryTests(FileFixture):
    def test_inventory_is_name_and_content_bound_and_deterministic(self):
        self.file("tree/b.bin", b"bb")
        self.file("tree/sub/a.bin", b"a")
        (self.root / "tree/empty").mkdir()
        tree = self.root / "tree"
        first = subject.inventory_trees([tree])
        self.assertEqual(first, subject.inventory_trees([tree]))
        self.assertEqual(len(first["files"]), 2)
        self.assertIn(str(tree / "empty"), first["directories"])
        self.assertEqual(first["sha256"], subject.metadata._hash({
            key: first[key] for key in ("roots", "directories", "files")}))
        (tree / "empty").rename(tree / "renamed")
        self.assertNotEqual(first["sha256"], subject.inventory_trees([tree])["sha256"])

    def test_inventory_rejects_empty_file_roots_and_overlap(self):
        path = self.file("tree/sub/a.bin")
        for roots in ([], [path], [path.parent.parent, path.parent]):
            with self.subTest(roots=roots), self.assertRaises(ValueError):
                subject.inventory_trees(roots)

    def test_inventory_file_and_total_byte_bounds(self):
        self.file("tree/a.bin", b"aa")
        self.file("tree/b.bin", b"bb")
        for name, limit in (("MAX_FILES", 1), ("MAX_BYTES", 3)):
            with self.subTest(name=name), mock.patch.object(subject, name, limit):
                with self.assertRaisesRegex(ValueError, "inventory limit"):
                    subject.inventory_trees([self.root / "tree"])

    def test_empty_directory_tree_has_a_bound(self):
        (self.root / "tree/one").mkdir(parents=True)
        (self.root / "tree/two").mkdir()
        with mock.patch.object(subject, "MAX_DIRECTORIES", 2):
            with self.assertRaisesRegex(ValueError, "directory inventory limit"):
                subject.inventory_trees([self.root / "tree"])

    def test_output_inventory_hardlinks_are_content_bound_not_identity_proof(self):
        path = self.file("tree/one.bin", b"same")
        os.link(path, path.parent / "two.bin")
        result = subject.inventory_trees([path.parent])
        self.assertEqual(len(result["files"]), 2)
        self.assertEqual({row["sha256"] for row in result["files"]}, {sha(b"same")})
        self.assertNotIn("filesystem_no_links_verified", result)

    def test_inventory_does_not_follow_reparse_directory(self):
        path = self.file("tree/nested/input.bin")
        original = Path.lstat
        def fake_lstat(value, *args, **kwargs):
            if value == path.parent:
                return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400, st_nlink=1)
            return original(value, *args, **kwargs)
        with mock.patch.object(Path, "lstat", fake_lstat):
            with self.assertRaisesRegex(ValueError, "linked capture path"):
                subject.inventory_trees([self.root / "tree"])


class NativeLinkTests(FileFixture):
    def test_fixed_configuration_and_complete_fake_sdk_inventory(self):
        path, config = self.fake_native()
        result = subject.native_link_context(path, workspace_root=self.root)
        self.assertEqual(result["selection"], {
            "linker": config["linker"], "library_directories": config["library_directories"]})
        self.assertEqual(result["configuration"], subject._file(path))
        self.assertEqual(len(result["inventory"]["files"]), 3)
        self.assertIn("not the full OS", result["qualification"])
        self.never_run.assert_not_called()

    def test_other_configuration_location_and_unknown_fields_rejected(self):
        path, config = self.fake_native()
        other = self.file("project-config.json", encoded(config))
        with self.assertRaisesRegex(ValueError, "fixed operator"):
            subject.native_link_context(other, workspace_root=self.root)
        for changed in ({**config, "command": "arbitrary"}, {**config, "schema_version": True}):
            path.write_bytes(encoded(changed))
            with self.assertRaisesRegex(ValueError, "schema"):
                subject.native_link_context(path, workspace_root=self.root)

    def test_missing_wrong_linker_or_duplicate_library_directory_rejected(self):
        path, config = self.fake_native()
        wrong = self.file("sdk/bin/other.exe")
        for changed in ({**config, "linker": str(wrong)},
                        {**config, "linker": str(wrong.parent / "missing.exe")},
                        {**config, "library_directories": config["library_directories"] * 2},
                        {**config, "library_directories": []}):
            path.write_bytes(encoded(changed))
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                subject.native_link_context(path, workspace_root=self.root)

    def test_synthetic_received_path_component_cannot_select_linker(self):
        path, config = self.fake_native()
        # An owned temporary directory models a forbidden name; no received
        # workspace folder or received bytes are read by this test.
        received_named = self.file("attackerfolder/link.exe", b"synthetic")
        path.write_bytes(encoded({**config, "linker": str(received_named)}))
        with self.assertRaisesRegex(ValueError, "received paths"):
            subject.native_link_context(path, workspace_root=self.root)

    def test_library_path_environment_separator_rejected(self):
        path, config = self.fake_native()
        library = self.root / "sdk/semicolon;library"
        library.mkdir()
        path.write_bytes(encoded({**config, "library_directories": [str(library)]}))
        with self.assertRaisesRegex(ValueError, "environment separators"):
            subject.native_link_context(path, workspace_root=self.root)

    def test_library_content_change_changes_context(self):
        path, config = self.fake_native()
        before = subject.native_link_context(path, workspace_root=self.root)
        (Path(config["library_directories"][0]) / "runtime.lib").write_bytes(b"different")
        after = subject.native_link_context(path, workspace_root=self.root)
        self.assertNotEqual(before["inventory"]["sha256"], after["inventory"]["sha256"])


class EnvironmentTests(FileFixture):
    def test_exact_sixteen_controls_and_explicit_linker(self):
        tools, native, host, private = self.fake_environment_inputs()
        result = subject.build_environment(tools, native, host_environment=host, private_root=private)
        expected_keys = {
            "SYSTEMROOT", "WINDIR", "PATH", "LIB", "RUSTC", "CARGO_NET_OFFLINE",
            "CARGO_TERM_COLOR", "CARGO_TARGET_DIR", "CARGO_HOME", "USERPROFILE", "HOME",
            "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", subject.LINKER_VARIABLE,
        }
        self.assertEqual(set(result), expected_keys)
        self.assertEqual(len(result), 16)
        self.assertEqual(result[subject.LINKER_VARIABLE], native["selection"]["linker"])
        self.assertEqual(result["LIB"], ";".join(native["selection"]["library_directories"]))
        self.assertEqual(result["PATH"].split(";"), [
            str(Path(tools["selection"]["rustc"]).parent),
            str(Path(native["selection"]["linker"]).parent),
            str(Path(host["SYSTEMROOT"]) / "System32"),
        ])
        self.assertEqual(result["CARGO_NET_OFFLINE"], "true")

    def test_ambient_secret_wrapper_and_flags_never_enter_child_map(self):
        tools, native, host, private = self.fake_environment_inputs()
        ambient = {"TOKEN": "test-only-token", "RUSTC_WRAPPER": "test-only-wrapper",
                   "RUSTFLAGS": "test-only-flags", "PATH": "test-only-path"}
        with mock.patch.dict(os.environ, ambient, clear=False):
            result = subject.build_environment(tools, native, host_environment=host, private_root=private)
        for key in ("TOKEN", "RUSTC_WRAPPER", "RUSTFLAGS"):
            self.assertNotIn(key, result)
        self.assertNotIn("test-only", json.dumps(result))

    def test_extra_missing_or_case_ambiguous_host_controls_rejected(self):
        tools, native, host, private = self.fake_environment_inputs()
        for bad in ({**host, "TOKEN": "fixture"}, {**host, "RUSTC_WRAPPER": "fixture"},
                    {key: value for key, value in host.items() if key != "PATH"},
                    {**host, "Path": "duplicate"}):
            with self.subTest(keys=list(bad)), self.assertRaises(ValueError):
                subject.build_environment(tools, native, host_environment=bad, private_root=private)

    def test_conflicting_windows_directories_rejected(self):
        tools, native, host, private = self.fake_environment_inputs()
        other = self.root / "other-windows"
        other.mkdir()
        with self.assertRaisesRegex(ValueError, "ambiguous Windows"):
            subject.build_environment(tools, native, host_environment={**host, "WINDIR": str(other)}, private_root=private)


class CommandTests(FileFixture):
    def invoke(self, *, changes=None, saved_changes=None):
        prefix, stop = self.root / "fake-command", self.root / "STOP"
        argv, environment = [str(self.root / "fake.exe"), "--fixed"], {"EXPLICIT": "fixture"}
        def runner(actual_argv, cwd, actual_prefix, **kwargs):
            self.assertEqual(actual_argv, argv)
            self.assertEqual(cwd, self.root)
            self.assertEqual(actual_prefix, prefix)
            self.assertEqual(kwargs, {"timeout": 17, "env": environment, "cancel_file": stop})
            result = process_record(argv, prefix, **(changes or {}))
            Path(str(prefix) + ".stdout.log").write_bytes(b"synthetic stdout")
            Path(str(prefix) + ".stderr.log").write_bytes(b"synthetic stderr")
            saved = {**result, **(saved_changes or {})}
            Path(str(prefix) + ".process.json").write_bytes(encoded(saved))
            return result
        with mock.patch.object(subject, "run_logged", side_effect=runner) as run:
            result = subject._command(argv, self.root, prefix, environment, stop, timeout=17)
            self.assertEqual(run.call_count, 1)
        return result

    def test_fixed_command_environment_timeout_and_log_bindings(self):
        result = self.invoke()
        self.assertTrue(result["clean"])
        for descriptor in result["files"].values():
            self.assertEqual(subject._file(descriptor["path"]), descriptor)

    def test_stop_prevents_even_mock_process_request(self):
        stop = self.file("STOP", b"stop")
        with self.assertRaisesRegex(ValueError, "STOP"):
            subject._command(["not-run"], self.root, self.root / "prefix", {}, stop, timeout=1)
        self.never_run.assert_not_called()

    def test_saved_process_record_mismatch_rejected(self):
        with self.assertRaisesRegex(ValueError, "saved command"):
            self.invoke(saved_changes={"pid": 999})

    def test_wrong_command_or_output_path_rejected(self):
        for changes in ({"argv": ["unexpected"]}, {"stdout": str(self.root / "foreign.stdout.log")},
                        {"stderr": str(self.root / "foreign.stderr.log")}):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "recipe/log"):
                self.invoke(changes=changes)

    def test_failed_cancelled_timeout_and_unverified_cleanup_never_clean(self):
        for changes in ({"returncode": 2}, {"timed_out": True}, {"cancelled": True},
                        {"error": "synthetic failure"}, {"cleanup": {"status": "unverified"}},
                        {"post_cleanup_wait_error": "synthetic cleanup failure"}):
            with self.subTest(changes=changes):
                self.assertFalse(self.invoke(changes=changes)["clean"])


class CaptureFailureTests(FileFixture):
    def capture_fixture(self):
        plan_path = self.file(".runs/inspection/plan.json", b"{}")
        source = self.file("owned/src/lib.rs", b"// never compiled")
        config_path, _ = self.fake_native()
        rustc = self.file("rust/bin/rustc.exe", b"not an executable")
        tools = {"selection": {"rustc": str(rustc)},
                 "compiler_inputs": {str(rustc): sha(b"not an executable")},
                 "inventory": {"files": [subject._file(rustc)]}}
        plan = {"inspection": {"toolchain": tools, "blockers": [],
                "input_snapshot": {"roots": [str(source.parent.parent)], "files": [subject._file(source)]}}}
        output = self.root / ".runs" / "new-capture"
        windows = self.root / "fake-windows"
        (windows / "System32").mkdir(parents=True)
        self.file("tools/rust_cargo_recorder/wrapper.rs", b"// trusted test fixture, never compiled")
        host = {"SYSTEMROOT": str(windows), "WINDIR": str(windows), "PATH": "discarded"}
        return plan, plan_path, output, config_path, host

    def guards(self, *, verification=None):
        stack = ExitStack()
        stack.enter_context(mock.patch.object(subject, "os", SimpleNamespace(
            name="nt", environ={}, walk=os.walk)))
        verify = stack.enter_context(mock.patch.object(subject.metadata, "verify_plan", return_value=(
            verification if verification is not None else {"metadata_succeeded": True, "status": "unchanged"})))
        original_file = subject._file
        def owned_file(path, **kwargs):
            value = Path(path).resolve()
            if value.is_relative_to(self.root):
                return original_file(value, **kwargs)
            # Only engine/interpreter descriptor calls are faked. This avoids
            # hashing any installed tools or SDK outside this temporary tree.
            return {"path": str(value), "sha256": sha(b"mock engine input"), "bytes": 17}
        stack.enter_context(mock.patch.object(subject, "_file", side_effect=owned_file))
        return stack, verify

    def call_capture(self, plan, plan_path, output, **kwargs):
        return subject.capture_project(plan, plan_path=plan_path, workspace_root=self.root,
                                       output_dir=output, env={}, **kwargs)

    def test_nonwindows_and_invalid_timeouts_rejected_before_process(self):
        with mock.patch.object(subject, "os", SimpleNamespace(name="posix")):
            with self.assertRaisesRegex(ValueError, "requires Windows"):
                self.call_capture({}, self.root / "none", self.root / "unused")
        for timeout in (True, 0, 3601, "600"):
            with mock.patch.object(subject, "os", SimpleNamespace(name="nt")):
                with self.subTest(timeout=timeout), self.assertRaisesRegex(ValueError, "bounded integer"):
                    self.call_capture({}, self.root / "none", self.root / "unused", timeout=timeout)
        self.never_run.assert_not_called()

    def test_failed_metadata_prevents_native_discovery_and_output_creation(self):
        plan, plan_path, output, _, _ = self.capture_fixture()
        guards, _ = self.guards(verification={"metadata_succeeded": False})
        with guards, mock.patch.object(subject, "native_link_context", side_effect=AssertionError("must not inspect SDK")):
            with self.assertRaisesRegex(ValueError, "successful unblocked metadata"):
                self.call_capture(plan, plan_path, output)
        self.assertFalse(output.exists())
        self.never_run.assert_not_called()

    def test_metadata_blockers_are_not_ignored(self):
        plan, plan_path, output, _, _ = self.capture_fixture()
        plan["inspection"]["blockers"] = ["unsupported_hook"]
        guards, _ = self.guards()
        with guards, self.assertRaisesRegex(ValueError, "successful unblocked metadata"):
            self.call_capture(plan, plan_path, output)
        self.assertFalse(output.exists())

    def test_existing_outside_and_defense_loop_output_rejected(self):
        plan, plan_path, output, _, _ = self.capture_fixture()
        output.mkdir()
        (self.root / ".runs/defense-loop").mkdir()
        for candidate in (output, self.root / "outside-runs", self.root / ".runs/defense-loop/job"):
            guards, _ = self.guards()
            with guards, self.subTest(candidate=candidate), self.assertRaisesRegex(ValueError, "fresh private"):
                self.call_capture(plan, plan_path, candidate)
        self.never_run.assert_not_called()

    def test_source_output_overlap_rejected_before_sdk_scan(self):
        plan, plan_path, output, _, _ = self.capture_fixture()
        plan["inspection"]["input_snapshot"]["roots"] = [str(self.root / ".runs")]
        guards, _ = self.guards()
        with guards, mock.patch.object(subject, "native_link_context", side_effect=AssertionError("must not inspect SDK")):
            with self.assertRaisesRegex(ValueError, "overlap"):
                self.call_capture(plan, plan_path, output)
        self.assertFalse(output.exists())

    def test_stop_blocks_capture_before_sdk_scan(self):
        plan, plan_path, output, _, _ = self.capture_fixture()
        self.file(".runs/defense-loop/STOP", b"synthetic test stop")
        guards, _ = self.guards()
        with guards, mock.patch.object(subject, "native_link_context", side_effect=AssertionError("must not inspect SDK")):
            with self.assertRaisesRegex(ValueError, "STOP"):
                self.call_capture(plan, plan_path, output)
        self.never_run.assert_not_called()

    def test_post_creation_environment_failure_returns_unprotected_failure_receipt(self):
        plan, plan_path, output, _, host = self.capture_fixture()
        guards, verify = self.guards()
        with guards, mock.patch.object(subject.metadata, "_metadata_environment", return_value=(
                {}, {}, host, ["unsupported_environment_selector:RUSTC_WRAPPER"])):
            result = self.call_capture(plan, plan_path, output)
        self.assertEqual(result["status"], "failed_capture")
        self.assertFalse(result["target_executed"])
        self.assertFalse(result["vm_applied"])
        self.assertFalse(result["published"])
        self.assertEqual(result["commands"], [])
        self.assertEqual(result["functional_validation"], "not_performed")
        self.assertIn("unsupported compiler environment selectors", result["error"])
        self.assertEqual(json.loads((output / "capture.json").read_bytes()), result)
        self.assertGreaterEqual(verify.call_count, 2)
        self.never_run.assert_not_called()

    def test_failed_first_mocked_command_retains_logs_and_never_continues(self):
        plan, plan_path, output, _, host = self.capture_fixture()
        guards, _ = self.guards()
        def fail_runner(argv, cwd, prefix, **kwargs):
            self.assertEqual(argv[-1], "-vV")
            self.assertEqual(set(kwargs["env"]), {
                "SYSTEMROOT", "WINDIR", "PATH", "LIB", "RUSTC", "CARGO_NET_OFFLINE",
                "CARGO_TERM_COLOR", "CARGO_TARGET_DIR", "CARGO_HOME", "USERPROFILE", "HOME",
                "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", subject.LINKER_VARIABLE,
            })
            result = process_record(argv, prefix, returncode=9)
            Path(str(prefix) + ".stdout.log").write_bytes(b"synthetic failed probe")
            Path(str(prefix) + ".stderr.log").write_bytes(b"synthetic compiler error")
            Path(str(prefix) + ".process.json").write_bytes(encoded(result))
            return result
        with guards, mock.patch.object(subject.metadata, "_metadata_environment", return_value=({}, {}, host, [])), \
                mock.patch.object(subject, "run_logged", side_effect=fail_runner) as run:
            result = self.call_capture(plan, plan_path, output)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(result["status"], "failed_capture")
        self.assertEqual(len(result["commands"]), 1)
        self.assertEqual(result["commands"][0]["process"]["returncode"], 9)
        self.assertFalse(result["commands"][0]["clean"])
        self.assertEqual(result["arms"], {})
        self.assertNotIn("recorder", result)
        self.assertEqual(json.loads((output / "capture.json").read_bytes()), result)
        self.assertEqual(Path(result["commands"][0]["files"]["stderr"]["path"]).read_bytes(), b"synthetic compiler error")


if __name__ == "__main__":
    unittest.main()
