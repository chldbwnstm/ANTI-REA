"""Four fixed-owned annotation regressions; execution requires reviewed runner.

Root's pinned v2 inspection-only reproduction confirmed the annotation-only
false rejection and three correctly rejected write controls. Rejected fixtures
below are compiled for syntax and inspected/built-to-rejection, never executed.
"""
import importlib.util
from pathlib import Path
import tempfile
import unittest

from antirea import python_mixed_module as mixed


PREFIX = "def helper(x):\n    return x + 1\ndef core(x):\n    return helper(x) * 7\n"


def load_owned(path):
    spec = importlib.util.spec_from_file_location("owned_annotation_fixture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MixedAnnotationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.counter = 0

    def tearDown(self):
        self.temp.cleanup()

    def reject(self, source):
        compile(source, "owned_rejected_annotation_syntax", "exec", dont_inherit=True)
        self.counter += 1
        output = self.root / ("rejected-" + str(self.counter))
        with self.assertRaisesRegex(mixed.MixedModuleError, "rebound|rebinding"):
            mixed.inspect_python_source(source, ["core"])
        with self.assertRaisesRegex(mixed.MixedModuleError, "rebound|rebinding"):
            mixed.protect_python_source(source, ["core"], output, seed=10319)
        self.assertFalse(output.exists())

    def test_bare_function_annotations_preserve_module_annotations_and_ui_calls(self):
        source = PREFIX + '''events = []
core: object
helper: (events.append("helper-annotation") or object)
LABEL: str = "Total"
def ui(value):
    return LABEL + ": " + str(core(value)), helper(value)
'''
        compile(source, "owned_positive_annotation_syntax", "exec", dont_inherit=True)
        inspection = mixed.inspect_python_source(source, ["core"])
        self.assertFalse(inspection["source_executed"])
        report = mixed.protect_python_source(source, ["core"], self.root / "build", seed=10319)
        self.assertFalse(report["execution_authorized"])
        self.assertEqual(report["coverage"]["helper_closure"], ["core", "helper"])
        baseline = load_owned(Path(report["baseline"]))
        protected = load_owned(Path(report["protected"]))
        self.assertEqual(protected.__annotations__, baseline.__annotations__)
        self.assertEqual(protected.__annotations__, {"core": object, "helper": object, "LABEL": str})
        self.assertEqual(protected.events, baseline.events)
        self.assertEqual(protected.events, ["helper-annotation"])
        self.assertTrue(callable(protected.core))
        self.assertTrue(callable(protected.helper))
        for value in (-31, 0, 1, 273, 1 << 250):
            self.assertEqual(protected.ui(value), baseline.ui(value))

    def test_annotation_expression_writes_still_rejected_without_running_source(self):
        for target in ("metadata", "core"):
            with self.subTest(target=target):
                self.reject(PREFIX + f"{target}: (helper := (lambda value: 999))\n")

    def test_annotated_assignments_to_protected_names_still_rejected(self):
        for target in ("core", "helper"):
            with self.subTest(target=target):
                self.reject(PREFIX + f"{target}: object = (lambda value: 999)\n")

    def test_annotation_target_receiver_and_index_writes_are_not_skipped(self):
        tails = ["bucket = {}\nbucket[(helper := (lambda value: 999))]: int\n",
                 "bucket = object()\n(helper := bucket).field: int\n"]
        for tail in tails:
            with self.subTest(tail=tail):
                self.reject(PREFIX + tail)


if __name__ == "__main__":
    unittest.main()
