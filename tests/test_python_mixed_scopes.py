"""Twelve fixed-owned scope regressions; execution needs reviewed qualification.

V1's separately run inspection-only reproduction established the four failing
categories. These tests qualify v2 behavior without importing v1 or user apps.
Only the literal fixtures below may execute; rejected fixtures are compiled for
syntax validity, inspected and built-to-rejection, never imported or executed.
"""
import importlib.util
from pathlib import Path
import tempfile
import unittest

from antirea import python_mixed_module as mixed


PREFIX = "def helper(x):\n    return x + 7\ndef core(x):\n    return helper(x) * 3\n"


def load_owned(path):
    spec = importlib.util.spec_from_file_location("owned_scope_fixture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MixedScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.counter = 0

    def tearDown(self):
        self.temp.cleanup()

    def build(self, source):
        compile(source, "fixed_owned_scope_fixture", "exec", dont_inherit=True)
        self.counter += 1
        output = self.root / ("fixture-" + str(self.counter))
        report = mixed.protect_python_source(source, ["core"], output, seed=10317)
        self.assertFalse(report["source_executed"])
        self.assertFalse(report["execution_authorized"])
        self.assertEqual(report["coverage"]["helper_closure"], ["core", "helper"])
        return load_owned(output / "baseline.py"), load_owned(output / "protected.py")

    def reject(self, source):
        # Ensure this is valid Python, not rejection accidentally caused by an
        # invalid fixture. Creating a code object does not execute its statements.
        compile(source, "fixed_rejected_scope_fixture", "exec", dont_inherit=True)
        self.counter += 1
        output = self.root / ("rejected-" + str(self.counter))
        with self.assertRaisesRegex(mixed.MixedModuleError, "rebound|rebinding"):
            mixed.inspect_python_source(source, ["core"])
        with self.assertRaisesRegex(mixed.MixedModuleError, "rebound|rebinding"):
            mixed.protect_python_source(source, ["core"], output, seed=10317)
        self.assertFalse(output.exists())

    def test_comprehension_iteration_names_are_local_for_all_forms(self):
        source = PREFIX + '''labels = [str(helper) for helper in range(3)]
items = {helper for helper in range(3)}
mapping = {core: helper for core in range(2) for helper in range(3)}
nested = [[helper + core for helper in range(2)] for core in range(3)]
unpacked = [core + helper[0] for core, *helper in [(2, 3), (5, 7)]]
'''
        baseline, protected = self.build(source)
        for name in ("labels", "items", "mapping", "nested", "unpacked"):
            self.assertEqual(getattr(protected, name), getattr(baseline, name))
        self.assertTrue(callable(protected.helper))
        self.assertTrue(callable(protected.core))
        self.assertEqual(protected.core(11), baseline.core(11))

    def test_generator_local_targets_keep_eager_and_deferred_evaluation_order(self):
        source = PREFIX + '''events = []
stream = (
    (events.append(("value", helper)), core(helper))[1]
    for helper in (events.append("outer-iter") or range(3))
    for unused in (events.append(("inner-iter", helper)) or range(1))
    if (events.append(("filter", helper)) or True)
)
events.append("created")
def consume():
    return list(stream)
'''
        baseline, protected = self.build(source)
        self.assertEqual(baseline.events, ["outer-iter", "created"])
        self.assertEqual(protected.events, baseline.events)
        self.assertEqual(protected.consume(), baseline.consume())
        self.assertEqual(protected.events, baseline.events)
        self.assertEqual(protected.events, ["outer-iter", "created"] + [
            (phase, value) for value in range(3) for phase in ("inner-iter", "filter", "value")])
        self.assertEqual(protected.consume(), baseline.consume())
        self.assertEqual(protected.core(9), baseline.core(9))

    def test_vararg_annotation_rebinding_is_rejected_without_execution(self):
        for target in ("core", "helper"):
            with self.subTest(target=target):
                self.reject(PREFIX + f"def ui(*args: ({target} := (lambda value: 999))):\n    return args\n")

    def test_kwarg_annotation_rebinding_is_rejected_without_execution(self):
        for target in ("core", "helper"):
            with self.subTest(target=target):
                self.reject(PREFIX + f"def ui(**kwargs: ({target} := (lambda value: 999))):\n    return kwargs\n")

    def test_async_variadic_annotation_rebinding_is_also_rejected(self):
        for parameter in ("*args", "**kwargs"):
            with self.subTest(parameter=parameter):
                self.reject(PREFIX + f"async def ui({parameter}: (core := (lambda value: 999))):\n    return 1\n")

    def test_comprehension_walrus_still_writes_to_enclosing_module(self):
        expressions = ["[(core := (lambda value: 999)) for item in range(3)]",
                       "{(helper := (lambda value: 999)) for item in range(3)}",
                       "{item: (core := (lambda value: 999)) for item in range(3)}",
                       "[[(core := (lambda value: 999)) for inner in range(2)] for outer in range(2)]"]
        for expression in expressions:
            with self.subTest(expression=expression):
                self.reject(PREFIX + "values = " + expression + "\n")

    def test_deferred_generator_walrus_rebinding_is_rejected_even_if_unconsumed(self):
        expressions = ["((core := (lambda value: 999)) for item in range(3))",
                       "(item for item in range(3) if (helper := (lambda value: 999)))",
                       "(((core := (lambda value: 999)) for inner in range(2)) for outer in range(2))"]
        for expression in expressions:
            with self.subTest(expression=expression):
                self.reject(PREFIX + "stream = " + expression + "\n")

    def test_lambda_body_scope_and_enclosing_default_scope_are_distinct(self):
        source = PREFIX + '''values = [(lambda helper=helper: (core := helper + 1))() for helper in range(3)]
stream = (core(item) for item in (lambda: range(2))())
def consume():
    return list(stream)
'''
        baseline, protected = self.build(source)
        self.assertEqual(protected.values, baseline.values)
        self.assertEqual(protected.consume(), baseline.consume())
        self.assertEqual(protected.core(5), baseline.core(5))
        self.reject(PREFIX + "values = [(lambda callback=(core := (lambda value: 999)): callback) for item in range(2)]\n")

    def test_global_declaration_does_not_turn_comprehension_targets_into_globals(self):
        source = PREFIX + '''def ui():
    global core, helper
    return [core + helper for core in range(2) for helper in range(2)]
'''
        baseline, protected = self.build(source)
        self.assertEqual(protected.ui(), baseline.ui())
        self.assertEqual(protected.ui(), [0, 1, 1, 2])
        self.assertEqual(protected.core(5), baseline.core(5))

    def test_declared_global_comprehension_and_generator_walrus_writes_are_rejected(self):
        for expression in ("[(core := (lambda value: 999)) for item in range(3)]",
                           "((core := (lambda value: 999)) for item in range(3))"):
            with self.subTest(expression=expression):
                self.reject(PREFIX + "def ui():\n    global core\n    return " + expression + "\n")

    def test_unselected_function_local_walrus_does_not_rebind_protected_global(self):
        source = PREFIX + '''def ui():
    values = [(core := value) for value in range(3)]
    return values, core
'''
        baseline, protected = self.build(source)
        self.assertEqual(protected.ui(), baseline.ui())
        self.assertEqual(protected.ui(), ([0, 1, 2], 2))
        self.assertEqual(protected.core(5), baseline.core(5))

    def test_unrelated_variadic_annotations_keep_order_and_callable_behavior(self):
        source = PREFIX + '''events = ["before-ui"]
def ui(*args: (events.append("args") or int), **kwargs: (events.append("kwargs") or str)):
    return core(len(args)), args, kwargs
events.append("after-ui")
'''
        baseline, protected = self.build(source)
        self.assertEqual(protected.events, baseline.events)
        self.assertEqual(protected.events, ["before-ui", "args", "kwargs", "after-ui"])
        self.assertEqual(protected.ui.__annotations__, baseline.ui.__annotations__)
        self.assertEqual(protected.ui(1, 2, label="three"), baseline.ui(1, 2, label="three"))


if __name__ == "__main__":
    unittest.main()
