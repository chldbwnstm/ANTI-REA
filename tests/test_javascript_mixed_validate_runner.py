"""Trusted per-arm PRODUCTION runner behaviour over OWNED fixtures in separate
clean, bounded processes (run via antirea.process.run_logged with the real repo
STOP cancel marker and verified Windows Job cleanup).

Covers the strict value protocol (NaN / negative-zero / Infinity / BigInt / throw),
refusal of unsupported return types and function shapes, missing exports, the
staged-tree require bound, the pinned-target-hash check and clean-environment
isolation.

Run: C:/Python313/python.exe -I -S -B test_javascript_mixed_validate_runner.py
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import js_mixed_validate_support as H

V = H.load_validate()

POS_ZERO = V._NUMBER_SPECIAL_BITS["pos_zero"]
NEG_ZERO = V._NUMBER_SPECIAL_BITS["neg_zero"]
POS_INF = V._NUMBER_SPECIAL_BITS["pos_inf"]
NEG_INF = V._NUMBER_SPECIAL_BITS["neg_inf"]
NAN = V._NUMBER_SPECIAL_BITS["nan"]


def write_module(directory, text, *, relative="index.js"):
    directory = Path(directory)
    (directory / Path(relative).parent).mkdir(parents=True, exist_ok=True)
    (directory / relative).write_text(text, encoding="utf-8")
    (directory / "package.json").write_text('{"type":"commonjs"}', encoding="utf-8")
    return directory / relative


class RunnerSemanticsTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.tmp = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()

    def _run(self, module_text, functions, cases, *, relative="index.js", env=None, target_sha256=None):
        stage = self.tmp / "stage"
        target = write_module(stage, module_text, relative=relative)
        return H.run_runner(stage, target, functions, cases, self.tmp / "work", env=env,
                            target_sha256=target_sha256)

    def test_number_bigint_boolean_throw_semantics(self):
        module = (
            "'use strict';\n"
            "function fadd(a,b){return a+b;}\n"
            "function isposz(x){return x===0 && 1/x>0;}\n"
            "function bigmul(a,b){return a*b;}\n"
            "function mix(a,b){return a+b;}\n"
            "module.exports={fadd,isposz,bigmul,mix};\n")
        functions = [
            {"name": "fadd", "parameters": [{"name": "a"}, {"name": "b"}]},
            {"name": "isposz", "parameters": [{"name": "x"}]},
            {"name": "bigmul", "parameters": [{"name": "a"}, {"name": "b"}]},
            {"name": "mix", "parameters": [{"name": "a"}, {"name": "b"}]},
        ]
        cases = {
            "fadd": [[H.arg_num_bits(POS_INF), H.arg_num_bits(NEG_INF)], [H.arg_num(1), H.arg_num(2)]],
            "isposz": [[H.arg_num_bits(POS_ZERO)], [H.arg_num_bits(NEG_ZERO)]],
            "bigmul": [[H.arg_big(10 ** 18), H.arg_big(10 ** 18)]],
            "mix": [[H.arg_num(1), H.arg_big(2)]],
        }
        result = self._run(module, functions, cases)
        self.assertEqual(result["returncode"], 0, result["stderr"])
        out = result["reply"]["outputs"]
        # NaN (Inf + -Inf) vs 3.0 are distinct number bit patterns.
        self.assertEqual(out["fadd"][0]["type"], "number")
        self.assertNotEqual(out["fadd"][0]["bits"], out["fadd"][1]["bits"])
        self.assertTrue(out["fadd"][0]["bits"].startswith("fff8") or out["fadd"][0]["bits"].startswith("7ff8"))
        # Positive zero and negative zero are distinguished in behaviour.
        self.assertEqual(out["isposz"][0], {"kind": "return", "type": "boolean", "value": True})
        self.assertEqual(out["isposz"][1], {"kind": "return", "type": "boolean", "value": False})
        self.assertEqual(out["bigmul"][0], {"kind": "return", "type": "bigint", "value": str(10 ** 36)})
        self.assertEqual(out["mix"][0], {"kind": "throw", "thrown": "TypeError"})
        # Isolation evidence: a sentinel never passed into the clean env is absent.
        self.assertNotIn("WAVE4_RUNNER_SENTINEL", result["reply"]["module_origin"]["env_keys"])
        # The second pass is retained for parent-side determinism recomputation.
        self.assertEqual(result["reply"]["outputs_second"]["fadd"], out["fadd"])

    def test_clean_env_excludes_injected_secret(self):
        os.environ["WAVE4_RUNNER_SENTINEL"] = "leak"
        try:
            module = "'use strict';\nfunction f(x){return x;}\nmodule.exports={f};\n"
            result = self._run(module, [{"name": "f", "parameters": [{"name": "x"}]}],
                               {"f": [[H.arg_num(1)]]})
            self.assertEqual(result["returncode"], 0, result["stderr"])
            self.assertNotIn("WAVE4_RUNNER_SENTINEL", result["reply"]["module_origin"]["env_keys"])
        finally:
            del os.environ["WAVE4_RUNNER_SENTINEL"]

    def _expect_error(self, module, functions, cases, needle):
        result = self._run(module, functions, cases)
        self.assertNotEqual(result["returncode"], 0)
        self.assertEqual(result["reply"]["status"], "error")
        self.assertIn(needle, result["reply"]["error"])

    def test_refuses_unsupported_return_type(self):
        self._expect_error("'use strict';\nfunction f(x){return 'str';}\nmodule.exports={f};\n",
                           [{"name": "f", "parameters": [{"name": "x"}]}], {"f": [[H.arg_num(1)]]},
                           "unsupported")

    def test_refuses_missing_export(self):
        self._expect_error("'use strict';\nmodule.exports={};\n",
                           [{"name": "f", "parameters": [{"name": "x"}]}], {"f": [[H.arg_num(1)]]},
                           "missing or not a function")

    def test_refuses_async_function(self):
        self._expect_error("'use strict';\nasync function f(x){return 1;}\nmodule.exports={f};\n",
                           [{"name": "f", "parameters": [{"name": "x"}]}], {"f": [[H.arg_num(1)]]},
                           "async/generator")

    def test_refuses_class_export(self):
        self._expect_error("'use strict';\nclass C{}\nmodule.exports={f:C};\n",
                           [{"name": "f", "parameters": []}], {"f": [[]]},
                           "class")

    def test_refuses_arity_mismatch(self):
        self._expect_error("'use strict';\nfunction f(a,b){return a;}\nmodule.exports={f};\n",
                           [{"name": "f", "parameters": [{"name": "a"}]}], {"f": [[H.arg_num(1)]]},
                           "arity")

    def test_refuses_require_outside_stage(self):
        # An existing module one level ABOVE the stage; a relative require to it must
        # be refused by the staged-tree require bound (not merely fail to resolve).
        (self.tmp / "outside.js").write_text("module.exports={};\n", encoding="utf-8")
        module = "'use strict';\nrequire('../outside.js');\nfunction f(x){return x;}\nmodule.exports={f};\n"
        self._expect_error(module, [{"name": "f", "parameters": [{"name": "x"}]}],
                           {"f": [[H.arg_num(1)]]}, "outside the staged tree")

    def test_detects_target_sha_pin_mismatch(self):
        # A request whose pinned target sha256 is wrong must fail the arm. Run through
        # the same bounded run_logged lifecycle as every other child, overriding only
        # the pinned hash.
        module = "'use strict';\nfunction f(x){return x;}\nmodule.exports={f};\n"
        result = self._run(module, [{"name": "f", "parameters": [{"name": "x"}]}],
                           {"f": [[H.arg_num(1)]]}, target_sha256="0" * 64)
        self.assertNotEqual(result["returncode"], 0)
        self.assertEqual(result["reply"]["status"], "error")
        self.assertIn("sha256", result["reply"]["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
