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


if __name__ == "__main__":
    unittest.main()
