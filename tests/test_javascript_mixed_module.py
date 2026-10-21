"""Structural inspect/build tests for the JavaScript mixed-module candidate.

Owned fixed fixtures only. Inspection/build parse the module and never import or
execute it; these tests assert that invariant (including modules whose unselected
top-level code would throw/fail on execution) and the splice/hoisting contract.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

from antirea import javascript_mixed_module as mixed
from js_mixed_support import build_sample, SAMPLE_JS


class StructureTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.tmp = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()

    def test_build_js_sample_closure_and_preservation(self):
        report, out, _ = build_sample(mixed, self.tmp, SAMPLE_JS, ("app.js", "labels.js", "project.json"))
        self.assertEqual(report["status"], "artifact_created_unvalidated")
        self.assertEqual(report["backend"], "javascript_mixed_module_vm")
        self.assertIs(report["source_executed"], False)
        self.assertIs(report["execution_authorized"], False)
        cov = report["coverage"]
        self.assertEqual(cov["helper_closure"], ["checksum", "mix", "rotate"])
        self.assertEqual(cov["selected_functions"], ["checksum"])
        self.assertEqual(sorted(cov["exported_functions"]), ["checksum", "mix", "rotate"])
        self.assertEqual(cov["preserved_unprotected_functions"], ["digitSum", "preview", "render"])
        self.assertFalse(cov["original_selected_bodies_in_protected_artifact"])
        protected = (out / "protected.cjs").read_text(encoding="utf-8")
        # Public names/signatures/order preserved as delegating declarations.
        self.assertIn("function checksum(seed, salt) { return _arm_enter(", protected)
        self.assertIn("function mix(x, y) { return _arm_enter(", protected)
        self.assertIn("function rotate(value, by) { return _arm_enter(", protected)
        # Unselected code preserved verbatim, including a caller of a virtualized helper.
        self.assertIn("function digitSum(value) {", protected)
        self.assertIn("total = mix(total, n % 10)", protected)
        self.assertIn('const labels = require("./labels.js");', protected)
        self.assertIn("module.exports = { checksum, mix, render, preview, digitSum, bootstrap: BOOTSTRAP };", protected)
        # Original body tokens are gone; no eval/Function/original-source fallback.
        self.assertNotIn("2654435761", protected)
        self.assertNotIn("eval(", protected)
        self.assertNotIn("Function(", protected)
        self.assertNotIn("new Function", protected)

    def test_shebang_and_directive_prologue_preserved_with_hoisted_vm(self):
        report, out, _ = build_sample(mixed, self.tmp, SAMPLE_JS, ("app.js", "labels.js", "project.json"))
        protected = (out / "protected.cjs").read_text(encoding="utf-8").splitlines()
        self.assertEqual(protected[0], "#!/usr/bin/env node")
        self.assertEqual(protected[1], '"use strict";')
        text = "\n".join(protected)
        # VM is injected as hoisted function declarations AFTER the directive
        # prologue, before the first require, so require/startup order is intact.
        vm_at = text.index("function _arm_factory()")
        enter_at = text.index("function _arm_enter(")
        require_at = text.index('require("./labels.js")')
        self.assertLess(text.index('"use strict";'), vm_at)
        self.assertLess(vm_at, require_at)
        self.assertLess(enter_at, require_at)

    def test_inspect_does_not_execute_even_failing_top_level_code(self):
        # Unselected top-level code that would throw / fail on execution still
        # inspects and builds, proving build parses but never runs the module.
        source = ('"use strict";\n'
                  'const dead = require("./definitely-not-a-real-module-xyz");\n'
                  'throw new Error("module top-level must not execute during build");\n'
                  'function pick(a, b) { let r = a; for (let i=0;i<2;i++){ r = r + b; } return r; }\n')
        proj = self.tmp / "p"
        proj.mkdir()
        (proj / "mod.js").write_text(source, encoding="utf-8")
        (proj / "project.json").write_text(
            '{"schema_version":1,"name":"nox","language":"javascript","sources":["mod.js"],'
            '"functions":["pick"],"protection_mode":"mixed_module"}', encoding="utf-8")
        inspection = mixed.inspect_project(proj / "project.json")
        self.assertIs(inspection["source_executed"], False)
        self.assertEqual(inspection["protected_functions"], ["pick"])
        report = mixed.build_project(proj / "project.json", self.tmp / ".runs" / "o",
                                     workspace_root=self.tmp, seed=1)
        self.assertEqual(report["status"], "artifact_created_unvalidated")

    def test_inspect_build_agree_and_pin_inputs(self):
        proj = self.tmp / "project"
        proj.mkdir()
        for name in ("app.js", "labels.js", "project.json"):
            (proj / name).write_bytes((SAMPLE_JS / name).read_bytes())
        inspection = mixed.inspect_project(proj / "project.json")
        self.assertEqual(inspection["backend"], "javascript_mixed_module_vm")
        self.assertEqual(inspection["language"], "javascript")
        self.assertIn(str(proj / "app.js"), inspection["input_hashes"])
        report = mixed.build_project(proj / "project.json", self.tmp / ".runs" / "o",
                                     workspace_root=self.tmp, seed=5)
        self.assertEqual(report["changed_inputs"], [])
        self.assertEqual(report["coverage"]["original_module_source_sha256"], inspection["source_sha256"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
