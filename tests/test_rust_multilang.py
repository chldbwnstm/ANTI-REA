"""Unit tests for the Pure-Rust multi-language bridge (antirea.rust_multilang)."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from antirea import projects
from antirea import rust_multilang


class RustMultilangBridgeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_resolve_native_stage_dir_supports_direct_and_lowered_layouts(self):
        direct = self.root / "direct"
        direct.mkdir()
        (direct / "module.after.ll").write_text("; ir\n", encoding="utf-8")
        self.assertEqual(rust_multilang.resolve_native_stage_dir(direct), direct.resolve())

        lowered = self.root / "lowered"
        (lowered / "native").mkdir(parents=True)
        (lowered / "native" / "module.after.ll").write_text("; ir\n", encoding="utf-8")
        self.assertEqual(rust_multilang.resolve_native_stage_dir(lowered), (lowered / "native").resolve())

        empty = self.root / "empty"
        empty.mkdir()
        with self.assertRaises(FileNotFoundError):
            rust_multilang.resolve_native_stage_dir(empty)

    def test_compile_and_link_rejects_incomplete_stage_dir(self):
        stage = self.root / "incomplete"
        stage.mkdir()
        (stage / "module.after.ll").write_text("; ir\n", encoding="utf-8")
        with self.assertRaises(FileNotFoundError):
            rust_multilang.compile_and_link_rust_multilang(stage, workspace_root=self.root)

    def test_project_service_build_rust_engine_attaches_rust_engine_summary(self):
        service = projects.ProjectService(self.root)
        plan_id = "source-20261021T122128Z-46c4bc3e8fd8"
        plan_dir = service.output_root / plan_id
        plan_dir.mkdir(parents=True, exist_ok=True)
        fake_rust = {"status": "passed", "engine": "antirea-rust-v8", "format_version": 8}
        with patch("antirea.rust_multilang.compile_and_link_rust_multilang", return_value=fake_rust) as mock_rust:
            res = service.build_rust_engine(plan_id, seed=42, replace_protected_dll=True)
            mock_rust.assert_called_once_with(
                plan_dir / "build",
                workspace_root=self.root,
                seed=42,
                replace_protected_dll=True,
            )
            self.assertEqual(res, fake_rust)

    def test_cross_os_naming_helpers(self):
        self.assertEqual(rust_multilang.rust_cli_binary_name("nt"), "antirea-cli.exe")
        self.assertEqual(rust_multilang.rust_cli_binary_name("posix"), "antirea-cli")
        self.assertEqual(
            rust_multilang.staticlib_filename("antirea_multilang_runtime", os_name="nt"),
            "antirea_multilang_runtime.lib",
        )
        self.assertEqual(
            rust_multilang.staticlib_filename("antirea_multilang_runtime", os_name="posix"),
            "libantirea_multilang_runtime.a",
        )
        self.assertEqual(
            rust_multilang.shared_library_filename("protected.rust", os_name="win32"),
            "protected.rust.dll",
        )
        self.assertEqual(
            rust_multilang.shared_library_filename("protected.rust", os_name="darwin"),
            "libprotected.rust.dylib",
        )
        self.assertEqual(
            rust_multilang.shared_library_filename("protected.rust", os_name="linux"),
            "libprotected.rust.so",
        )

    def test_compile_cargo_crate_vm_with_auto_ontology_scope_excludes_hot_loop(self):
        repo_root = Path(__file__).resolve().parents[1]
        crate_dir = self.root / "sample-cargo-crate"
        (crate_dir / "src").mkdir(parents=True)
        (crate_dir / "Cargo.toml").write_text(
            '[package]\nname = "sample-cargo-crate"\nversion = "0.1.0"\nedition = "2021"\n\n[lib]\ncrate-type = ["rlib"]\n',
            encoding="utf-8",
        )
        (crate_dir / "src" / "lib.rs").write_text(
            """#![no_std]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[inline(never)]
pub extern "C" fn boundary_tag_mix(a: u64, b: u64) -> u64 {
    let x = a.wrapping_mul(0x9e3779b97f4a7c15) ^ b.rotate_left(19);
    (x ^ (x >> 29)).wrapping_mul(0xbf58476d1ce4e5b9)
}

#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn hot_inner_loop(ptr: *const u64, len: u64) -> u64 {
    let mut i = 0u64;
    let mut acc = 0xcbf29ce484222325u64;
    while i < len {
        acc = (acc ^ *ptr.add(i as usize)).wrapping_mul(0x100000001b3);
        i += 1;
    }
    acc
}
""",
            encoding="utf-8",
        )
        out_dir = self.root / "cargo-vm-out"
        res = rust_multilang.compile_cargo_crate_vm(
            crate_dir / "Cargo.toml",
            out_dir,
            workspace_root=repo_root,
            seed=0x20261111,
        )
        self.assertEqual(res["status"], "passed")
        self.assertEqual(res["engine"], "antirea-rust-v20")
        self.assertEqual(res["format_version"], 20)
        self.assertEqual(res["selected_functions"], ["boundary_tag_mix"])
        self.assertIn("hot_inner_loop", res["ontology_scope"]["excluded_hot_loop_ir_functions"])
        self.assertTrue(Path(res["staticlib_path"]).is_file())
        self.assertEqual(res["seed_leakage_hits"], 0)
        self.assertEqual(res["external_attack_evaluation"], "not_evaluated")


if __name__ == "__main__":
    unittest.main()
