"""Scope / shadowing / rebinding / freeze negatives for the JS mixed candidate.

Each selection that would silently freeze a module value, cross into unselected
code, capture a closure, or make a protected name ambiguous must be rejected,
not quietly accepted.
"""
import os
import sys
import unittest

from antirea import javascript_mixed_module as mixed
from js_mixed_support import build_sample, SAMPLE_JS


class NegativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tc = mixed.discover_toolchain()

    def reject(self, source, functions, needle):
        with self.assertRaises(mixed.MixedModuleError) as ctx:
            mixed._parse(source, "javascript", functions, self.tc)
        self.assertIn(needle, str(ctx.exception))

    def accept(self, source, functions):
        result = mixed._parse(source, "javascript", functions, self.tc)
        self.assertIs(result["source_executed"], False)
        return result

    def test_module_global_value_load_rejected_not_frozen(self):
        self.reject("const K = 5;\nfunction f(x) { return x + K; }\n", ["f"],
                    "cannot freeze module-global values")

    def test_selected_closure_rejected(self):
        self.reject("function f(x) { const g = () => x; return g(); }\n", ["f"], "ArrowFunction")
        self.reject("function f(x) { function g() { return x; } return g(); }\n", ["f"], "line")

    def test_reassigned_selected_name_rejected(self):
        self.reject("function f(x) { return x; }\nf = 3;\n", ["f"],
                    "cannot be rebound/redeclared/imported/deleted/shadowed")

    def test_shadowing_and_redeclaration_rejected(self):
        self.reject("function f(f) { return f; }\n", ["f"], "rebound/redeclared")
        self.reject("function f(x) { return x; }\nfunction other() { let f = 2; return f; }\n", ["f"], "rebound/redeclared")
        self.reject("function f(x){return x;}\nfunction f(y){return y+1;}\n", ["f"], "exactly one top-level definition")
        self.reject("import { f } from './x.js';\nfunction use() { return f; }\nfunction f(x){return x;}\n", ["f"], "rebound/redeclared")

    def test_cross_into_unselected_or_unknown_call_rejected(self):
        self.reject("function f(x) { return helper(x); }\n", ["f"], "Unsupported call helper")
        self.reject("function f(x) { return g(x); }\nfunction g(x) { return globalThis.z; }\n", ["f"],
                    "PropertyAccessExpression")

    def test_recursion_rejected(self):
        self.reject("function f(x) { return x <= 0 ? 0 : f(x - 1); }\n", ["f"], "Recursive helper cycles")
        self.reject("function f(x){return g(x);}\nfunction g(x){return f(x);}\n", ["f"], "Recursive helper cycles")

    def test_unsupported_lexical_forms_rejected(self):
        self.reject("function f(x) { var y = x; return y; }\n", ["f"], "var is unsupported")
        self.reject("function f(x, y = 1) { return x + y; }\n", ["f"], "Defaults/rest/optional")
        self.reject("async function f(x) { return x; }\n", ["f"], "modifiers")

    def test_reserved_prefix_anywhere_rejected(self):
        self.reject("const _arm_x = 1;\nfunction f(x) { return x; }\n", ["f"],
                    "_ar_/_arm_ generated-runtime identifier prefix is reserved")
        self.reject("function f(x) { return _ar_sneak(x); }\n", ["f"], "reserved")

    def test_missing_selection_rejected(self):
        self.reject("function g(x) { return x; }\n", ["f"], "Selected top-level function not found")

    def test_supported_control_flow_accepted(self):
        result = self.accept(
            "function f(x, y) { let a = x; for (let i=0;i<3;i++){ a = (a + y) ^ i; if (a % 2) a += 1; } return a % 7; }\n",
            ["f"])
        self.assertEqual(result["helper_closure"], ["f"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
