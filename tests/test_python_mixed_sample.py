"""Owned public sample integration; never import an arbitrary user package.

The fixed repository quote_app sources are copied into fresh private test trees.
Plan/build never execute them; explicit behavior tests below execute only these
reviewed sample files. This is not a general mixed application execution API.
"""
import ast
from contextlib import contextmanager, redirect_stdout
import importlib
import io
import json
from pathlib import Path
import random
import runpy
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

from antirea.projects import ProjectService


SAMPLE = Path(__file__).resolve().parents[1] / "samples/multilang/python_mixed"
PACKAGE_FILES = ("__init__.py", "__main__.py", "settings.py", "pricing.py")


@contextmanager
def owned_package(directory):
    with patch.dict(sys.modules), patch.dict(sys.path_importer_cache), \
            patch.object(sys, "path", [str(directory), *sys.path]), \
            patch.object(sys, "dont_write_bytecode", True):
        for name in list(sys.modules):
            if name == "quote_app" or name.startswith("quote_app."):
                del sys.modules[name]
        importlib.invalidate_caches()
        module = importlib.import_module("quote_app.pricing")
        if Path(module.__file__) != directory / "quote_app/pricing.py":
            raise AssertionError("Sample did not load from its exact fresh owned path")
        for name in ("quote_app", "quote_app.settings", "quote_app.pricing"):
            loaded = sys.modules[name]
            if not Path(loaded.__file__).is_relative_to(directory / "quote_app"):
                raise AssertionError("Sample dependency escaped its copied package")
        yield module


class MixedPublicSampleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project_root = self.root / "source"
        package = self.project_root / "quote_app"
        package.mkdir(parents=True)
        self.originals = {name: (SAMPLE / "quote_app" / name).read_bytes() for name in PACKAGE_FILES}
        for name, raw in self.originals.items():
            (package / name).write_bytes(raw)
        self.manifest_bytes = (SAMPLE / "project.json").read_bytes()
        self.project = self.project_root / "project.json"
        self.project.write_bytes(self.manifest_bytes)
        self.service = ProjectService(self.root)

    def build(self):
        with patch("subprocess.Popen", side_effect=AssertionError("Sample plan/build must not launch children")):
            plan = self.service.plan(self.project, seed=1729)
            report = self.service.build(plan["plan_id"], plan["fingerprint"])
        self.assertEqual(plan["status"], "planned")
        self.assertEqual(report["status"], "artifact_created_unvalidated")
        self.assertFalse(report["source_executed"])
        self.assertFalse(report["execution_authorized"])
        self.assertEqual(report["coverage"]["helper_closure"], ["quote_cents", "rounded_discount"])
        self.assertEqual(report["coverage"]["codec_count"], 2)
        self.assertFalse(report["coverage"]["kagura_passes_applied"])
        return plan, report

    def deploy(self, report, arm):
        directory = self.root / arm
        package = directory / "quote_app"
        package.mkdir(parents=True)
        for name, raw in self.originals.items():
            (package / name).write_bytes(raw)
        shutil.copyfile(report[arm], package / "pricing.py")
        self.assertEqual(sorted(p.name for p in package.iterdir()), sorted(PACKAGE_FILES))
        return directory

    def test_public_sample_plan_build_keeps_sources_and_removes_selected_bodies(self):
        _, report = self.build()
        self.assertEqual(Path(report["baseline"]).read_bytes(), self.originals["pricing.py"])
        for name, raw in self.originals.items():
            self.assertEqual((self.project_root / "quote_app" / name).read_bytes(), raw)
        self.assertEqual(self.project.read_bytes(), self.manifest_bytes)
        text = Path(report["protected"]).read_text(encoding="utf-8")
        self.assertIn("from .settings import CURRENCY, TITLE", text)
        self.assertIn("def render_quote", text)
        self.assertNotIn("return (subtotal * basis_points + 5000) // 10000", text)
        functions = {node.name: node for node in ast.parse(text).body if isinstance(node, ast.FunctionDef)}
        for name in ("quote_cents", "rounded_discount"):
            self.assertEqual(len(functions[name].body), 1)
            self.assertIsInstance(functions[name].body[0], ast.Return)
            self.assertEqual(functions[name].body[0].value.func.id, "_arm_enter")

    def test_public_package_original_and_vm_match_8217_inputs_twice_and_cli(self):
        _, report = self.build()
        vectors = [(price, quantity, (index % 5) * 2500)
                   for index, (price, quantity) in enumerate(
                       (p, q) for p in (0, 1, 99, 100, 1 << 40) for q in (0, 1, 2, 17, 999))]
        seen = set(vectors)
        rng = random.Random(20261020)
        while len(vectors) < 8217:
            value = (rng.randrange(10**8), rng.randrange(1001), rng.randrange(10001))
            if value not in seen:
                seen.add(value)
                vectors.append(value)
        expected = []
        for price, quantity, discount in vectors:
            subtotal = price * quantity
            total = subtotal - (subtotal * discount + 5000) // 10000
            expected.append(f"Quote: {quantity} items, total USD {total // 100}.{total % 100:02d}")
        for arm in ("baseline", "protected"):
            directory = self.deploy(report, arm)
            with owned_package(directory) as module:
                for repeat in range(2):
                    self.assertEqual([module.render_quote(*value) for value in vectors], expected, (arm, repeat))
                for args, error in (((-1, 2, 0), ValueError), ((1, -2, 0), ValueError),
                                    ((1, 2, 10001), ValueError), ((True, 2, 0), TypeError),
                                    ((1.5, 2, 0), TypeError)):
                    with self.subTest(arm=arm, args=args), self.assertRaises(error):
                        module.render_quote(*args)
                stdout = io.StringIO()
                with patch.object(sys, "argv", ["quote_app", "--unit-cents", "2500", "--quantity", "3", "--discount-bps", "1000"]), redirect_stdout(stdout):
                    runpy.run_module("quote_app", run_name="__main__")
                self.assertEqual(stdout.getvalue(), "Quote: 3 items, total USD 67.50\n")
            self.assertFalse(list(directory.rglob("*.pyc")))

    def test_public_sample_scalar_contract_does_not_authorize_package_execution(self):
        plan, _ = self.build()
        contract = self.root / "scalar-contract.json"
        contract.write_text(json.dumps({"kind": "python_integer_samples", "functions": []}), encoding="utf-8")
        with patch("subprocess.Popen", side_effect=AssertionError("Mixed scalar validation must not execute")):
            with self.assertRaisesRegex(ValueError, "mixed application contract requires"):
                self.service.validate(plan["plan_id"], contract)

    def test_public_application_contract_reaches_real_validation_route(self):
        contract = self.root / "application-contract.json"
        contract.write_bytes((SAMPLE / "application-contract.json").read_bytes())
        plan, _ = self.build()
        result = self.service.validate(plan["plan_id"], contract, random_cases=32, timeout_seconds=30)
        self.assertEqual(result["status"], "mixed_application_samples_passed", result)
        self.assertEqual(result["module"], "quote_app.pricing")
        self.assertEqual(result["selected_entrypoints"], ["quote_cents"])
        self.assertTrue(result["functions"]["quote_cents"]["sampled_output_match"])
        self.assertEqual(result["preserved_entrypoints"], [])
        self.assertEqual(result["external_attack_evaluation"], "not_evaluated")


if __name__ == "__main__":
    unittest.main()
