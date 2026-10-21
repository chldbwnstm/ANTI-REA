"""Unexecuted owned-fixture tests; stage candidate as antirea.python_mixed_module.

Only these fixed fixtures may be executed by a separately reviewed runner. There
is deliberately no arbitrary mixed-module execution/validation entry point.
"""
import ast
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import random
import sys
import tempfile
import unittest
from unittest.mock import patch

from antirea import python_frontend as pure
from antirea import python_mixed_module as mixed


def load_owned(path, name="owned_mixed_fixture"):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def outcome(callback, arguments):
    try:
        value = callback(*arguments)
        return ("value", type(value).__name__, value)
    except Exception as exc:
        return ("exception", type(exc).__name__)


class MixedModuleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.counter = 0

    def tearDown(self):
        self.temp.cleanup()

    def build(self, source, selected=None, *, execute=True, seed=5731):
        self.counter += 1
        output = self.root / f"fixture-{self.counter}"
        report = mixed.protect_python_source(source, selected or ["core"], output, seed=seed)
        if execute:
            return report, load_owned(output / "baseline.py"), load_owned(output / "protected.py")
        return report

    def test_build_and_inspect_never_import_source_or_run_top_level_effects(self):
        source = "raise RuntimeError('unexecuted application startup')\ndef core(x):\n    return x + 9\n"
        with patch.object(importlib.util, "spec_from_file_location", side_effect=AssertionError("must not import")):
            inspection = mixed.inspect_python_source(source, ["core"])
            report = self.build(source, execute=False)
        self.assertFalse(inspection["source_executed"])
        self.assertEqual(report["status"], "artifact_created_unvalidated")
        self.assertFalse(report["source_executed"])
        self.assertFalse(report["execution_authorized"])
        self.assertEqual(report["backend"], "python_mixed_module_vm")
        self.assertEqual(report["functional_evaluation"], "not_performed")
        report_path = Path(report["protected"]).parent / "report.json"
        self.assertEqual(report, json.loads(report_path.read_text()))

    def test_import_ui_class_and_same_module_calls_keep_order_and_behavior(self):
        source = '''"""ordinary owned UI module"""
from __future__ import annotations
import math
events = ["before"]

def ui(value):
    events.append("ui")
    return "answer=" + str(core(value))

class View:
    def render(self, value):
        return {"text": ui(value), "square_root": math.sqrt(16)}

def helper(value: int) -> int:
    return value * 37 - 11

events.append("between")

def core(value: int) -> int:
    return helper(value) ^ 7291

events.append("after")
initial = View().render(5)
'''
        report, baseline, protected = self.build(source)
        self.assertEqual(protected.events, baseline.events)
        self.assertEqual(protected.initial, baseline.initial)
        self.assertEqual(protected.View().render(-7), baseline.View().render(-7))
        self.assertEqual(protected.events, baseline.events)
        self.assertEqual(protected.__doc__, baseline.__doc__)
        self.assertEqual(protected.core.__annotations__, baseline.core.__annotations__)
        self.assertEqual(str(inspect.signature(protected.core)), str(inspect.signature(baseline.core)))
        self.assertEqual(report["coverage"]["helper_closure"], ["core", "helper"])
        self.assertEqual(report["coverage"]["exported_functions"], ["core", "helper"])
        self.assertEqual(report["coverage"]["preserved_unprotected_functions"], ["ui"])

    def test_all_protected_helpers_remain_callable_from_unselected_code(self):
        source = '''def helper(x, y):
    return (x * x + y) // 3
def core(x, y):
    return helper(x, y) ^ x
def ordinary(x, y):
    return [core(x, y), helper(x, y), str(x)]
'''
        _, baseline, protected = self.build(source)
        for arguments in [(7, 4), (-12, 2), (True, 8), (1 << 800, -9)]:
            self.assertEqual(protected.ordinary(*arguments), baseline.ordinary(*arguments))
            self.assertEqual(str(inspect.signature(protected.helper)), str(inspect.signature(baseline.helper)))

    def test_imported_consumer_calls_original_public_names(self):
        source = "def helper(x):\n    return x * 31\ndef core(x):\n    return helper(x) - 17\n"
        report = self.build(source, execute=False)
        consumer = self.root / "consumer.py"
        consumer.write_text("from owned_mixed_subject import core, helper\nresult = (core(7), helper(8))\n", encoding="utf-8")
        outcomes = []
        for arm in ("baseline", "protected"):
            subject = load_owned(Path(report[arm]), "owned_mixed_subject")
            with patch.dict(sys.modules, {"owned_mixed_subject": subject}):
                outcomes.append(load_owned(consumer, "owned_mixed_consumer").result)
        self.assertEqual(outcomes, [(200, 248), (200, 248)])

    def test_unrelated_mutable_globals_remain_live_but_selected_values_are_rejected(self):
        source = "STATE = [4]\ndef core(x):\n    return x + 3\ndef ui(x):\n    return core(x) + STATE[0]\n"
        _, baseline, protected = self.build(source)
        baseline.STATE[0] = protected.STATE[0] = 31
        self.assertEqual(protected.ui(5), baseline.ui(5))
        for declaration in ("BIAS = 17", "BIAS = True", "BIAS = []", "from math import pi as BIAS"):
            with self.subTest(declaration=declaration), self.assertRaisesRegex(mixed.MixedModuleError, "module-global"):
                mixed.inspect_python_source(declaration + "\ndef core(x):\n    return x + BIAS\n", ["core"])

    def test_selected_body_and_helper_plaintext_are_removed_not_fallbacks(self):
        source = "def helper(x):\n    return x * 139579 + 17429 # helper secret\ndef core(x):\n    return helper(x) ^ 97153 # core secret\ndef ui(x):\n    return f'visible {core(x)}'\n"
        report = self.build(source, execute=False)
        protected = Path(report["protected"]).read_text(encoding="utf-8")
        for text in ("x * 139579", "helper secret", "core secret", "return helper(x)"):
            self.assertNotIn(text, protected)
        tree = ast.parse(protected)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertFalse(any(isinstance(node.func, ast.Name) and node.func.id in {"exec", "eval", "compile"}
                             for node in calls))
        self.assertIn("return f'visible {core(x)}'", protected)
        self.assertFalse(report["coverage"]["original_selected_bodies_in_protected_artifact"])
        self.assertEqual(report["coverage"]["format_version"], 2)
        self.assertEqual(report["coverage"]["decode_scope"], "current_instruction")
        self.assertFalse(report["coverage"]["decoded_instruction_cache"])
        self.assertFalse(report["coverage"]["kagura_passes_applied"])

    def test_lexical_runtime_does_not_collide_with_existing_vm_like_names(self):
        source = "bytes = 'UI label'\n_ar_enter = 'ordinary UI state'\n_ar_functions = [1, 2]\ndef core(x):\n    return abs(x) + 13\ndef ui(x):\n    return bytes, _ar_enter, _ar_functions, core(x)\n"
        _, baseline, protected = self.build(source)
        self.assertEqual(protected.ui(-7), baseline.ui(-7))
        self.assertEqual(protected._ar_enter, baseline._ar_enter)
        self.assertFalse(hasattr(protected, "_ar_blob"))
        self.assertFalse(hasattr(protected, "_arm_factory"))

    def test_preserved_text_segments_are_byte_exact_with_utf8_and_crlf(self):
        source = "# 사용자 UI\r\nTITLE = '기능'\r\n\r\ndef core(x):\r\n    return x + 17 # selected\r\n\r\ndef ui(x):\r\n    return TITLE + str(core(x))\r\n"
        protected, coverage, _, _ = mixed._generate(source, ["core"], 33)
        self.assertTrue(protected.startswith("# 사용자 UI\r\nTITLE = '기능'\r\n\r\n"))
        self.assertTrue(protected.endswith("\r\ndef ui(x):\r\n    return TITLE + str(core(x))\r\n"))
        span = coverage["replacements"][0]
        original = source.encode("utf-8")[span["original_utf8_start"]:span["original_utf8_end"]]
        self.assertEqual(hashlib.sha256(original).hexdigest(), span["original_body_sha256"])
        self.assertNotIn("# selected", protected)

    def test_utf8_bom_is_preserved_when_first_line_is_selected_definition(self):
        source = "\ufeffdef core(x):\r\n    return x + 9\r\nLABEL = '한글'\r\n"
        protected, coverage, _, _ = mixed._generate(source, ["core"], 37)
        self.assertTrue(protected.startswith("\ufeff"))
        self.assertTrue(protected.endswith("LABEL = '한글'\r\n"))
        self.assertEqual(coverage["replacements"][0]["original_utf8_start"], 3)
        ast.parse(protected.removeprefix("\ufeff"))

    def test_function_order_and_before_helper_definition_nameerror_are_preserved(self):
        source = '''events = []
def core(x):
    return helper(x)
try:
    core(2)
except NameError:
    events.append("helper not yet defined")
def helper(x):
    return x + 7
events.append(core(2))
'''
        _, baseline, protected = self.build(source)
        self.assertEqual(protected.events, baseline.events)
        self.assertEqual(protected.events, ["helper not yet defined", 9])

    def test_runtime_helper_rebinding_fails_explicitly_only_on_reached_call(self):
        source = "def helper(x):\n    return x + 7\ndef core(x):\n    if x:\n        return helper(x)\n    return 0\n"
        _, baseline, protected = self.build(source)
        baseline.helper = protected.helper = lambda value: value + 99
        self.assertEqual(baseline.core(2), 101)
        with self.assertRaisesRegex(RuntimeError, "unsupported helper rebinding: helper"):
            protected.core(2)
        self.assertEqual(protected.core(0), baseline.core(0))

    def test_missing_reached_helper_binding_preserves_nameerror(self):
        _, baseline, protected = self.build("def helper(x):\n    return x + 5\ndef core(x):\n    return helper(x)\n")
        del baseline.helper
        del protected.helper
        self.assertEqual(outcome(baseline.core, [2]), outcome(protected.core, [2]))
        self.assertEqual(outcome(protected.core, [2]), ("exception", "NameError"))

    def test_module_builtin_rebinding_fails_explicitly_including_range(self):
        for source, name in [("def core(x):\n    return abs(x)\n", "abs"),
                             ("def core(x):\n    n = 0\n    for i in range(x):\n        n += i\n    return n\n", "range")]:
            with self.subTest(name=name):
                _, _, protected = self.build(source)
                setattr(protected, name, lambda value: 123)
                with self.assertRaisesRegex(RuntimeError, "unsupported builtin rebinding: " + name):
                    protected.core(4)

    def test_preexisting_builtin_shadow_is_not_silently_ignored(self):
        _, baseline, protected = self.build("abs = lambda value: value + 100\ndef core(x):\n    return abs(x)\n")
        self.assertEqual(baseline.core(3), 103)
        with self.assertRaisesRegex(RuntimeError, "unsupported builtin rebinding: abs"):
            protected.core(3)

    def test_regular_supported_builtin_alias_to_same_object_is_equivalent(self):
        _, baseline, protected = self.build("import builtins\nabs = builtins.abs\ndef core(x):\n    return abs(x)\n")
        self.assertEqual(protected.core(-11), baseline.core(-11))

    def test_direct_module_and_declared_global_protected_rebindings_are_rejected(self):
        tail_cases = ["helper = lambda x: x", "del helper", "from math import floor as helper",
                      "if True:\n    def helper(x):\n        return x",
                      "def update():\n    global helper\n    helper = lambda x: x",
                      "class Update:\n    global helper\n    helper = 2",
                      "try:\n    pass\nexcept Exception as helper:\n    pass",
                      "match 1:\n    case helper:\n        pass"]
        prefix = "def helper(x):\n    return x + 7\ndef core(x):\n    return helper(x)\n"
        for tail in tail_cases:
            with self.subTest(tail=tail), self.assertRaises(mixed.MixedModuleError):
                mixed.inspect_python_source(prefix + tail + "\n", ["core"])

    def test_unrelated_local_names_are_not_mistaken_for_global_rebinding(self):
        source = "def helper(x):\n    return x + 5\ndef core(x):\n    return helper(x)\ndef ui():\n    helper = ['ordinary local']\n    return helper\n"
        _, baseline, protected = self.build(source)
        self.assertEqual(protected.ui(), baseline.ui())
        self.assertEqual(protected.core(3), baseline.core(3))

    def test_selected_unsupported_forms_and_closure_cycles_fail_before_output(self):
        cases = ["@staticmethod\ndef core(x):\n    return x\n",
                 "def core(x=3):\n    return x\n", "def core(x, /):\n    return x\n",
                 "def core(*x):\n    return 3\n", "def core(x: str):\n    return x\n",
                 "async def core(x):\n    return x\n", "def core(x):\n    yield x\n",
                 "def core(x):\n    return globals()['BIAS'] + x\n",
                 "def core(x):\n    return helper(x)\ndef helper(x):\n    return core(x)\n",
                 "def core(x):\n    return helper(x)\n@staticmethod\ndef helper(x):\n    return x\n"]
        for index, source in enumerate(cases):
            output = self.root / f"rejected-{index}"
            with self.subTest(source=source), self.assertRaises(mixed.MixedModuleError):
                mixed.protect_python_source(source, ["core"], output, seed=1)
            self.assertFalse(output.exists())

    def test_unrelated_unsupported_python_forms_are_retained(self):
        source = '''def core(x):
    return x * 7
async def network_ui(value):
    return {"result": core(value)}
def generator_ui(values):
    for value in values:
        yield core(value)
def decorated(callback):
    return callback
@decorated
def flexible_ui(value=3, *, suffix="!"):
    return str(core(value)) + suffix
'''
        _, baseline, protected = self.build(source)
        self.assertEqual(list(protected.generator_ui([2, 7])), list(baseline.generator_ui([2, 7])))
        self.assertEqual(protected.flexible_ui(), baseline.flexible_ui())
        self.assertTrue(inspect.iscoroutinefunction(protected.network_ui))

    def test_private_prefix_star_import_and_duplicate_protected_definition_rejected(self):
        for source in ["_arm_enter = 3\ndef core(x):\n    return x\n",
                       "from math import *\ndef core(x):\n    return x\n",
                       "def core(x):\n    return x\ndef core(x):\n    return x + 1\n",
                       "def core(x):\n    return x\ntry:\n    pass\nexcept Exception as _arm_enter:\n    pass\n",
                       "def core(x):\n    return x\nmatch 1:\n    case _arm_register:\n        pass\n"]:
            with self.subTest(source=source), self.assertRaises(mixed.MixedModuleError):
                mixed.inspect_python_source(source, ["core"])

    def test_exact_integer_bool_domains_and_broad_deterministic_values(self):
        source = '''def helper(x, y):
    return ((x * x) << 17) + x // y - x % y
def core(x, y):
    if not y:
        return x < 0
    total = helper(x, y)
    for i in range(abs(y) % 7):
        total ^= x >> i
    return total
def ui(x, y):
    return str(core(x, y))
'''
        _, baseline, protected = self.build(source)
        rng = random.Random(109)
        vectors = [(rng.randint(-(1 << 80), 1 << 80), rng.randint(-31, 31)) for _ in range(512)]
        vectors += [(1 << 4096, -7), (-(1 << 6000), 9), (True, False), (False, True), (0, 0)]
        for arguments in vectors:
            self.assertEqual(outcome(baseline.core, arguments), outcome(protected.core, arguments))
        for name in ("core", "helper"):
            with self.assertRaisesRegex(TypeError, "exact Python int/bool"):
                getattr(protected, name)(1.5, 2)

    def test_multiple_roots_reproducibility_and_distinct_seeds(self):
        source = "def a(x):\n    return x + 13\ndef b(x):\n    return a(x) * 5\n"
        first = mixed._generate(source, ["b", "a"], 17)
        second = mixed._generate(source, ["b", "a"], 17)
        third = mixed._generate(source, ["b", "a"], 18)
        self.assertEqual(first, second)
        self.assertNotEqual(first[0], third[0])
        self.assertEqual(first[1]["selected_functions"], ["b", "a"])
        self.assertEqual(first[1]["helper_closure"], ["a", "b"])
        self.assertEqual(first[1]["codec_count"], 2)
        for seed in (True, -1, 1 << 256):
            with self.subTest(seed=seed), self.assertRaises(pure.PythonFrontendError):
                mixed._generate(source, ["a"], seed)

    def test_existing_pure_route_remains_strict_and_cannot_claim_mixed_validation(self):
        source = "import math\ndef core(x):\n    return x + 3\n"
        with self.assertRaises(pure.PythonFrontendError):
            pure.inspect_python_source(source, ["core"])
        report = self.build(source, execute=False)
        self.assertNotEqual(report["backend"], "python_vm")
        self.assertEqual(report["coverage"]["validation_exports"], [])
        self.assertFalse(report["execution_authorized"])

    def test_upstream_runtime_shape_changes_fail_closed(self):
        # The helper rebinding guard hook now lives in each generated per-function
        # engine. A corrupted hook must break the adapter's per-engine count and
        # fail closed, never slip an unguarded helper call through.
        original = pure._prh.render_engine

        def broken(identifier, plan):
            return original(identifier, plan).replace(
                "_ar_invoke(instruction[1], arguments)", "_ar_invoke(0, arguments)")

        with patch.object(pure._prh, "render_engine", broken):
            with self.assertRaisesRegex(mixed.MixedModuleError, "adapter shape changed"):
                mixed._generate("def core(x):\n    return x + 3\n", ["core"], 17)
        with patch.object(pure, "FORMAT_VERSION", 3):
            with self.assertRaisesRegex(mixed.MixedModuleError, "requires upstream format 2"):
                mixed._generate("def core(x):\n    return x + 3\n", ["core"], 17)


class MixedProjectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source_root = self.root / "app"
        self.source_root.mkdir()
        self.source = self.source_root / "ui.py"
        self.source.write_text("import math\ndef core(x):\n    return x + 17\ndef ui(x):\n    return str(core(x))\n", encoding="utf-8")
        self.project = self.source_root / "project.json"
        self.value = {"schema_version": 1, "name": "mixed_ui", "language": "python",
                      "sources": ["ui.py"], "functions": ["core"], "protection_mode": "mixed_module"}
        self.project.write_text(json.dumps(self.value), encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_project_opt_in_is_required_and_does_not_change_pure_schema(self):
        self.assertEqual(mixed.inspect_project(self.project)["protection_mode"], "mixed_module")
        with self.assertRaises(pure.PythonFrontendError):
            pure.inspect_project(self.project)
        for alteration in ({"protection_mode": "pure"}, {"unknown": 1}):
            self.project.write_text(json.dumps({**self.value, **alteration}), encoding="utf-8")
            with self.subTest(alteration=alteration), self.assertRaises(mixed.MixedModuleError):
                mixed.inspect_project(self.project)
        self.value.pop("protection_mode")
        self.project.write_text(json.dumps(self.value), encoding="utf-8")
        with self.assertRaises(mixed.MixedModuleError):
            mixed.inspect_project(self.project)

    def test_project_build_pins_both_frontends_and_preserves_source(self):
        before = self.source.read_bytes()
        output = self.root / ".runs" / "mixed-build"
        report = mixed.build_project(self.project, output, workspace_root=self.root, seed=71)
        self.assertEqual(report["status"], "artifact_created_unvalidated")
        self.assertFalse(report["source_executed"])
        self.assertEqual(report["commands"], [])
        self.assertEqual(report["changed_inputs"], [])
        self.assertEqual(set(report["tool_hashes"]), {str(Path(mixed.__file__).resolve()),
                                                      str(Path(pure.__file__).resolve()),
                                                      str(Path(pure._prh.__file__).resolve())})
        self.assertEqual(self.source.read_bytes(), before)
        self.assertEqual((output / "baseline.py").read_bytes(), before)
        self.assertEqual(json.loads((output / "report.json").read_text()), report)

    def test_project_preserves_original_bom_and_crlf_bytes_in_baseline(self):
        before = "\ufeff# ordinary UI\r\ndef core(x):\r\n    return x + 7\r\nLABEL = '한글'\r\n".encode("utf-8")
        self.source.write_bytes(before)
        output = self.root / ".runs" / "bom-crlf"
        report = mixed.build_project(self.project, output, workspace_root=self.root, seed=73)
        self.assertEqual(report["status"], "artifact_created_unvalidated")
        self.assertEqual((output / "baseline.py").read_bytes(), before)
        self.assertEqual(report["inspection"]["source_sha256"], hashlib.sha256(before).hexdigest())
        protected = (output / "protected.py").read_bytes()
        self.assertTrue(protected.startswith("\ufeff# ordinary UI\r\n".encode("utf-8")))
        self.assertTrue(protected.endswith("LABEL = '한글'\r\n".encode("utf-8")))

    def test_stop_and_unsafe_or_reused_outputs_are_rejected(self):
        for output in (self.root, self.root / ".runs", self.source_root / "output", self.root / "elsewhere"):
            with self.subTest(output=output), self.assertRaises(mixed.MixedModuleError):
                mixed.build_project(self.project, output, workspace_root=self.root, seed=11)
        stop = self.root / ".runs" / "defense-loop" / "STOP"
        stop.parent.mkdir(parents=True)
        stop.write_text("owned test stop", encoding="utf-8")
        with self.assertRaisesRegex(mixed.MixedModuleError, "STOP"):
            mixed.build_project(self.project, self.root / ".runs" / "stopped", workspace_root=self.root, seed=11)

    def test_source_traversal_and_shared_handoff_paths_are_rejected(self):
        for value in ("../ui.py", "C:/outside/ui.py", "ui.py:stream", "../../attackerfolder/app.py"):
            self.project.write_text(json.dumps({**self.value, "sources": [value]}), encoding="utf-8")
            with self.subTest(value=value), self.assertRaises(pure.PythonFrontendError):
                mixed.inspect_project(self.project)
        shared = self.root / "attackerfolder"
        shared.mkdir()
        with self.assertRaises(pure.PythonFrontendError):
            mixed.protect_python_source("def core(x):\n    return x\n", ["core"], shared / "output", seed=1)


if __name__ == "__main__":
    unittest.main()
