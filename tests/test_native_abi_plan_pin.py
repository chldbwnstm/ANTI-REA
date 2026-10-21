"""Source-plan ABI module pins; only temporary inert fixture files are mutated.

The real planner and stale-plan checks run. Inspection/build are mocked and
subprocess creation is blocked. No production source is modified or reloaded.
"""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from antirea import projects


class NativeAbiPlanPinTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        source = self.root / "owned"
        source.mkdir()
        self.project = source / "project.json"
        self.project.write_text('{"schema_version":1}', encoding="utf-8")
        (source / "core.c").write_text("int core(int x) { return x + 1; }", encoding="utf-8")
        tools = self.root / ".tools"
        tools.mkdir()
        (tools / "kagura-toolchain.json").write_text('{"llvm_version":"22.1.0"}', encoding="utf-8")

        # Relocate only the engine-inventory lookup. These inert bytes are never
        # imported; the actual ProjectService implementation remains under test.
        engine = self.root / "inert-engine"
        engine.mkdir()
        self.engine_files = {}
        for name in ("projects", "native_validate", "native_abi"):
            path = engine / (name + ".py")
            path.write_bytes(("INERT ENGINE INVENTORY FIXTURE: " + name + "\n").encode())
            self.engine_files[name] = path
        self.abi = self.engine_files["native_abi"]
        self._patch("antirea.projects.__file__", str(self.engine_files["projects"]))
        self._patch("antirea.projects._inspect", return_value={"language": "c", "blockers": []})
        self._patch("antirea.projects.shutil.which", return_value=None)
        self.no_process = self._patch("subprocess.Popen", side_effect=AssertionError("No subprocess is permitted"))
        self.service = projects.ProjectService(self.root)

    def _patch(self, target, *args, **kwargs):
        selected = patch(target, *args, **kwargs)
        value = selected.start()
        self.addCleanup(selected.stop)
        return value

    @staticmethod
    def successful_builder(source, output, **kwargs):
        output.mkdir(parents=True)
        result = {"status": "artifact_created_unvalidated", "artifacts": {}, "coverage": {}}
        (output / "report.json").write_text(json.dumps(result), encoding="utf-8")
        return result

    def test_plan_pins_native_abi_as_a_distinct_engine_dependency(self):
        with patch("antirea.projects._build") as build:
            plan = self.service.plan(self.project)
        self.assertEqual(plan["status"], "planned")
        self.assertIn("engine_native_abi", plan["toolchain"]["tools"])
        row = plan["toolchain"]["tools"]["engine_native_abi"]
        raw = self.abi.read_bytes()
        self.assertEqual(row["path"], str(self.abi))
        self.assertEqual(row["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(row["bytes"], len(raw))
        self.assertNotEqual(row["path"], plan["toolchain"]["tools"]["engine_native_validate"]["path"])
        build.assert_not_called()
        self.no_process.assert_not_called()

    def test_native_abi_only_drift_reaches_existing_stale_plan_gate_before_build(self):
        plan = self.service.plan(self.project)
        # Deliberately do not pre-assert the pin's presence: without the proposed
        # inventory fix, this test reaches the mock builder and fails for lack of
        # the expected stale-plan exception, demonstrating the actual behavior.
        before = {name: path.read_bytes() for name, path in self.engine_files.items()}
        self.abi.write_bytes(before["native_abi"] + b"ABI CHECKER CHANGED\n")
        with patch("antirea.projects._build", side_effect=self.successful_builder) as build:
            with self.assertRaisesRegex(ValueError, "project or toolchain changed after planning"):
                self.service.build(plan["plan_id"], plan["fingerprint"])
            build.assert_not_called()
        output = Path(plan["output_dir"])
        self.assertFalse(output.exists())
        self.assertFalse((output.parent / "started.json").exists())
        self.assertFalse((output.parent / "result.json").exists())
        self.assertEqual(self.engine_files["projects"].read_bytes(), before["projects"])
        self.assertEqual(self.engine_files["native_validate"].read_bytes(), before["native_validate"])
        self.no_process.assert_not_called()

    def test_unchanged_engine_inventory_preserves_normal_mock_build(self):
        plan = self.service.plan(self.project)
        before = {name: path.read_bytes() for name, path in self.engine_files.items()}
        with patch("antirea.projects._build", side_effect=self.successful_builder) as build:
            result = self.service.build(plan["plan_id"], plan["fingerprint"])
        self.assertEqual(result["status"], "artifact_created_unvalidated")
        self.assertEqual(result["external_attack_evaluation"], "not_evaluated")
        self.assertFalse(result["published"])
        build.assert_called_once()
        self.assertEqual({name: path.read_bytes() for name, path in self.engine_files.items()}, before)
        self.no_process.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
