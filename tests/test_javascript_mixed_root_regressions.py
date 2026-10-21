"""Failing-before / passing-after regressions for root's two owned reproductions.

Source of truth: ``.runs/orca-wave1-root-review/check_javascript_v1.py`` and
``.runs/orca-wave1-root-review/js-repro-32bffaa3dd21/root-report.json``.

Root reproduced two SILENT scalar behavior regressions in the wave1 candidate:

  for_of_rebind:  function helper(x) { return x + 1; }
                  for (helper of [function(x) { return x + 100; }]) {}
                  function core(x) { return helper(x); }
                  module.exports = {core};
                  -> baseline core(5) = 105 , protected core(5) = 6    (WRONG)

  shadowed_nan:   const NaN = 7;
                  function core(x) { return x + NaN; }
                  module.exports = {core};
                  -> baseline core(5) = 12  , protected core(5) = NaN  (WRONG)

The wave1 candidate silently FROZE the pre-rebind `helper` body and the global
`NaN` intrinsic, emitting a protected artifact whose scalar result differs from
the original. The contract already forbids both (a protected name may not be
rebound anywhere; selected code may not load a module-global value). The wave1
build missed the for-of assignment target and the module-level intrinsic shadow.

The corrected candidate detects both and REJECTS the build (conservative
explicit rejection), instead of producing a silently-wrong artifact. These tests
assert that corrected behavior:
  * run against the wave1 candidate -> build SUCCEEDS  -> these tests FAIL (before)
  * run against the wave2 candidate -> build REJECTS   -> these tests PASS  (after)

These are rejection tests; independent original-vs-protected EXECUTION evidence
for both reproductions (reproducing 105/6 and 12/NaN under the wave1 candidate,
and the rejection under the wave2 candidate) is captured by the separate
clean-env, per-arm acceptance driver in ``../evidence/acceptance.py``; this file
never runs the module in-process.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from antirea import javascript_mixed_module as mixed
from js_mixed_support import build_sample, SAMPLE_JS

FOR_OF_SOURCE = ("function helper(x) { return x + 1; }\n"
                 "for (helper of [function(x) { return x + 100; }]) {}\n"
                 "function core(x) { return helper(x); }\n"
                 "module.exports = {core};\n")
SHADOWED_NAN_SOURCE = ("const NaN = 7;\n"
                       "function core(x) { return x + NaN; }\n"
                       "module.exports = {core};\n")


class RootReproductionRegressions(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.tmp = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()

    def _build(self, name, source, functions):
        proj = self.tmp / name
        proj.mkdir()
        (proj / "app.js").write_text(source, encoding="utf-8")
        (proj / "project.json").write_text(json.dumps(
            {"schema_version": 1, "name": name, "language": "javascript",
             "sources": ["app.js"], "functions": functions,
             "protection_mode": "mixed_module"}), encoding="utf-8")
        return mixed.build_project(proj / "project.json", self.tmp / ".runs" / name,
                                   workspace_root=self.tmp, seed=4142)

    def test_for_of_helper_rebinding_rejected_not_silently_frozen(self):
        # Before fix: build_project returned 'artifact_created_unvalidated' and the
        # protected arm silently returned 6 instead of the baseline's 105.
        with self.assertRaises(mixed.MixedModuleError) as ctx:
            self._build("for_of_rebind", FOR_OF_SOURCE, ["core"])
        self.assertIn("rebound/redeclared", str(ctx.exception))

    def test_parse_level_for_of_rebinding_rejected(self):
        tc = mixed.discover_toolchain()
        with self.assertRaises(mixed.MixedModuleError) as ctx:
            mixed._parse(FOR_OF_SOURCE, "javascript", ["core"], tc)
        self.assertIn("rebound/redeclared", str(ctx.exception))

    def test_module_shadowed_nan_rejected_not_frozen(self):
        # Before fix: build_project returned 'artifact_created_unvalidated' and the
        # protected arm silently returned NaN instead of the baseline's 12.
        with self.assertRaises(mixed.MixedModuleError) as ctx:
            self._build("shadowed_nan", SHADOWED_NAN_SOURCE, ["core"])
        self.assertIn("freeze module-global values", str(ctx.exception))

    def test_parse_level_shadowed_nan_rejected(self):
        tc = mixed.discover_toolchain()
        with self.assertRaises(mixed.MixedModuleError) as ctx:
            mixed._parse(SHADOWED_NAN_SOURCE, "javascript", ["core"], tc)
        self.assertIn("freeze module-global values", str(ctx.exception))

    def test_for_in_assignment_target_rebinding_rejected(self):
        # Sibling of for-of: a for-in head assigning to an existing protected name.
        source = ("function helper(x) { return x + 1; }\n"
                  "for (helper in {a: 1}) {}\n"
                  "function core(x) { return helper(x); }\n"
                  "module.exports = {core};\n")
        with self.assertRaises(mixed.MixedModuleError) as ctx:
            self._build("for_in_rebind", source, ["core"])
        self.assertIn("rebound/redeclared", str(ctx.exception))

    def test_destructuring_assignment_rebinding_rejected(self):
        # Destructuring assignment target (array pattern) rebinding a protected name.
        source = ("function helper(x) { return x + 1; }\n"
                  "[helper] = [function(x) { return x + 100; }];\n"
                  "function core(x) { return helper(x); }\n"
                  "module.exports = {core};\n")
        with self.assertRaises(mixed.MixedModuleError) as ctx:
            self._build("destructure_rebind", source, ["core"])
        self.assertIn("rebound/redeclared", str(ctx.exception))

    def test_runtime_free_name_shadow_rejected_even_when_unused(self):
        # Root follow-up: `const JSON = {}` shadows a free global the INJECTED
        # runtime depends on (JSON.stringify), even though selected `core` never
        # names JSON. Before this fix the protected arm threw a TypeError at
        # runtime; the build must reject instead of emitting a breaking artifact.
        source = ("const JSON = {};\n"
                  "function core(x) { return x + 1; }\n"
                  "module.exports = {core};\n")
        with self.assertRaises(mixed.MixedModuleError) as ctx:
            self._build("json_shadow", source, ["core"])
        self.assertIn("shadows a global the injected runtime depends on", str(ctx.exception))

    def test_annex_b_block_function_runtime_shadow_rejected(self):
        # Root follow-up #3: a sloppy-mode Annex B block function declaration
        # creates an OUTER module-scope binding. `if(true){function JSON(){}}`
        # shadows the injected runtime's JSON; before this fix the hoisted-scope
        # walk collected only `var`, so the protected arm threw at runtime.
        source = ("if (true) { function JSON() {} }\n"
                  "function core(x) { return x + 1; }\n"
                  "module.exports = {core};\n")
        with self.assertRaises(mixed.MixedModuleError) as ctx:
            self._build("annex_b_block_fn", source, ["core"])
        self.assertIn("shadows a global the injected runtime depends on", str(ctx.exception))

    def test_block_hoisted_var_intrinsic_shadow_rejected(self):
        # Root follow-up: `var NaN` inside a top-level block hoists to module
        # scope. Before this fix the file.statements-only scan missed it and the
        # protected arm silently returned NaN (baseline 12); the build must reject.
        source = ("if (true) { var NaN = 7; }\n"
                  "function core(x) { return x + NaN; }\n"
                  "module.exports = {core};\n")
        with self.assertRaises(mixed.MixedModuleError) as ctx:
            self._build("block_hoisted_nan", source, ["core"])
        self.assertIn("freeze module-global values", str(ctx.exception))

    def test_parenthesized_direct_eval_rejected(self):
        # Root review hypothesis: `(eval)(...)` is still a *direct* eval and can
        # rebind a module-scoped helper; the bare-identifier check alone missed it.
        source = ("function helper(x) { return x + 1; }\n"
                  "(eval)(\"helper = function (x) { return x + 100; }\");\n"
                  "function core(x) { return helper(x); }\n"
                  "module.exports = {core};\n")
        with self.assertRaises(mixed.MixedModuleError) as ctx:
            self._build("paren_eval", source, ["core"])
        self.assertIn("Direct eval", str(ctx.exception))

    def test_bare_direct_eval_rejected(self):
        source = ("function core(x) { return x + 1; }\n"
                  "eval(\"globalThis.x = 1\");\n"
                  "module.exports = {core};\n")
        with self.assertRaises(mixed.MixedModuleError) as ctx:
            self._build("bare_eval", source, ["core"])
        self.assertIn("Direct eval", str(ctx.exception))

    def test_shadowed_builtin_receiver_module_binding_rejected(self):
        # A module-level binding shadowing a captured builtin receiver (Math) must
        # be rejected, not silently resolved to the global Math. Math is both a
        # cached builtin and a free global the injected runtime relies on, so the
        # module-level runtime-free-name guard rejects it first.
        source = ("const Math = { imul: function(a, b) { return 0; } };\n"
                  "function core(x) { return Math.imul(x, 3); }\n"
                  "module.exports = {core};\n")
        with self.assertRaises(mixed.MixedModuleError) as ctx:
            self._build("shadowed_math", source, ["core"])
        self.assertIn("shadows a global the injected runtime depends on", str(ctx.exception))

    def test_local_builtin_receiver_shadow_rejected(self):
        # Defense-in-depth: a selected body's own LOCAL shadow of a builtin
        # receiver (not a module binding, so the runtime-free-name guard does not
        # fire) is rejected by the compiler's builtin-receiver guard.
        source = ("function core(x) { const Math = 5; return Math.imul(x, 3); }\n"
                  "module.exports = {core};\n")
        with self.assertRaises(mixed.MixedModuleError) as ctx:
            self._build("local_math_shadow", source, ["core"])
        self.assertIn("Builtin receiver is shadowed", str(ctx.exception))

    def test_commonjs_require_assignment_rejected(self):
        source = ('"use strict"; require = function () { return {}; };\n'
                  'function core(x) { return x + 1; } module.exports = {core};\n')
        with self.assertRaisesRegex(mixed.MixedModuleError, 'CommonJS require binding cannot be assigned'):
            self._build('require_assignment', source, ['core'])

    def test_commonjs_require_compound_and_update_rejected(self):
        for index, mutation in enumerate(('require &&= function () { return {}; };',
                                           'require++;', '++require;', 'require = require;')):
            source = mutation + '\nfunction core(x) { return x + 1; } module.exports = {core};\n'
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                    mixed.MixedModuleError, 'CommonJS require binding cannot be assigned'):
                self._build('require_update_' + str(index), source, ['core'])

    def test_commonjs_require_loop_assignment_rejected(self):
        for index, mutation in enumerate(('for (require of [function () { return {}; }]) {}',
                                          'for (require in {key: 1}) {}')):
            source = mutation + '\nfunction core(x) { return x + 1; } module.exports = {core};\n'
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                    mixed.MixedModuleError, 'CommonJS require binding cannot be assigned'):
                self._build('require_loop_' + str(index), source, ['core'])

    def test_commonjs_require_destructuring_assignment_rejected(self):
        for index, mutation in enumerate(('[require] = [function () { return {}; }];',
                                          '({loader: require} = {loader: function () { return {}; }});',
                                          '[...require] = [];')):
            source = mutation + '\nfunction core(x) { return x + 1; } module.exports = {core};\n'
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                    mixed.MixedModuleError, 'CommonJS require binding cannot be assigned'):
                self._build('require_destructure_' + str(index), source, ['core'])

    def test_commonjs_require_write_in_unselected_closure_rejected(self):
        source = ('function changeLoader() { require = function () { return {}; }; }\n'
                  'changeLoader(); function core(x) { return x + 1; } module.exports = {core};\n')
        with self.assertRaisesRegex(mixed.MixedModuleError, 'CommonJS require binding cannot be assigned'):
            self._build('require_closure_write', source, ['core'])

    def test_unselected_require_parameter_without_assignment_stays_allowed(self):
        source = ('function passthrough(require) { return require; }\n'
                  'function core(x) { return x + 1; } module.exports = {core};\n')
        report = self._build('require_local_read', source, ['core'])
        self.assertEqual(report['status'], 'artifact_created_unvalidated')


if __name__ == "__main__":
    unittest.main(verbosity=2)
