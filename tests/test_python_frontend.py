import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import random
import tempfile
import time
import unittest
from unittest.mock import patch

from antirea import python_frontend as pf


SAMPLES = Path(__file__).resolve().parents[1] / "samples" / "multilang" / "python"


def load_owned(path):
    """Explicit test execution of our own fixture, never compiler input evaluation."""
    spec = importlib.util.spec_from_file_location("owned_fixture_" + path.parent.name + path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def outcome(function, args):
    try:
        result = function(*args)
    except Exception as exc:
        return ("exception", type(exc).__name__)
    return ("value", type(result).__name__, result)


class PythonFrontendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.counter = 0

    def tearDown(self):
        self.temp.cleanup()

    def build(self, source, functions=None, seed=1729):
        self.counter += 1
        output = self.root / f"out-{self.counter}"
        report = pf.protect_python_source(source, functions or ["core"], output, seed=seed)
        return report, load_owned(output / "baseline.py"), load_owned(output / "protected.py")

    def compare(self, source, cases, functions=None):
        report, baseline, protected = self.build(source, functions)
        for name in functions or ["core"]:
            for args in cases:
                with self.subTest(function=name, args=args):
                    self.assertEqual(outcome(getattr(baseline, name), args), outcome(getattr(protected, name), args))
        return report

    def test_compilation_is_nonexecuting_and_report_is_exact(self):
        output = self.root / "nonexecuting"
        with patch.object(importlib.util, "spec_from_file_location", side_effect=AssertionError("must not import")):
            report = pf.protect_python_source("def core(x):\n    return x + 17\n", ["core"], output, seed=12)
        self.assertEqual(report, json.loads((output / "report.json").read_text()))
        self.assertEqual(report["status"], "artifact_created_unvalidated")
        self.assertFalse(report["source_executed"])
        self.assertFalse(report["coverage"]["kagura_passes_applied"])
        self.assertEqual(report["functional_evaluation"], "not_performed")

    def test_helpers_selected_transitively_and_no_original_body(self):
        source = "SECRET_BIAS = 371593\ndef helper(x):\n    return x * SECRET_BIAS + 19\ndef core(x):\n    return helper(x) ^ 731\ndef unused(x):\n    return x - 7\n"
        report, baseline, protected = self.build(source)
        self.assertEqual(report["coverage"]["helper_closure"], ["core", "helper"])
        self.assertEqual(report["coverage"]["functions"]["core"]["parameters"], ["x"])
        self.assertFalse(hasattr(protected, "helper"))
        self.assertFalse(hasattr(protected, "unused"))
        artifact = Path(report["protected"]).read_text()
        self.assertNotIn("SECRET_BIAS", artifact)
        self.assertNotIn("return helper(x)", artifact)
        self.assertNotIn("x * SECRET_BIAS", artifact)
        tree = ast.parse(artifact)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertFalse(any(isinstance(node.func, ast.Name) and node.func.id in {"exec", "eval", "compile"} for node in calls))
        self.assertEqual(protected.core(99), baseline.core(99))

    def test_large_integer_negative_floor_mod_and_bool_types(self):
        self.compare("def core(x, y):\n    return ((x * x) << 91) + x // y - x % y + (x >> 7)\n",
                     [(2 ** 900, -7), (-2 ** 800, 7), (-17, -3), (-17, 3), (True, 2)])
        self.compare("def core(x, y):\n    return (x & y) or (x < y)\n", [(True, True), (False, True), (1, 1), (2, 5)])

    def test_short_circuit_preserves_values_and_does_not_evaluate_error(self):
        self.compare("def core(x, y):\n    return (x and (10 // y)) or x\n", [(0, 0), (7, 2), (-4, 0)])
        self.compare("def core(x, y):\n    return x or (1 << y)\n", [(2, -1), (0, -1), (0, 12)])

    def test_chained_comparison_short_circuits_later_error(self):
        self.compare("def core(x, y):\n    return x < y <= (10 // x) < 30\n", [(0, 0), (0, 2), (2, 3), (-3, -2)])
        # A helper call occurs once in the instruction stream for the middle value.
        report = pf.inspect_python_source("def helper(x):\n    return x + 1\ndef core(x):\n    return 0 < helper(x) < 10\n", ["core"])
        self.assertEqual(report["functions"]["core"]["helpers"], ["helper"])

    def test_loops_nested_break_continue_else_and_assignment_order(self):
        source = """def core(x, y):
    first = second = x
    total = 0
    for outer in range(abs(x) % 5):
        for inner in range(5, -1, -1):
            if inner == y:
                break
            if inner == 2:
                continue
            total += inner
        else:
            total += 99
    else:
        total += first + second
    while y > 0:
        y -= 1
        if y == x:
            break
        if y % 2:
            continue
        total ^= y
    else:
        total += 31
    return total
"""
        self.compare(source, [(x, y) for x in range(-3, 6) for y in range(-2, 8)])

    def test_empty_range_keeps_previous_target_or_unbound(self):
        self.compare("def core(x, y):\n    for target in range(x):\n        pass\n    return target\n", [(0, 1), (3, 1), (-4, 0)])
        self.compare("def core(x, y):\n    target = y\n    for target in range(x):\n        pass\n    return target\n", [(0, 17), (3, 9)])

    def test_error_classes_negative_shift_division_range_and_unbound(self):
        self.compare("def core(x, y):\n    return x << y\n", [(5, -1), (-3, 8)])
        self.compare("def core(x, y):\n    return x // y + x % y\n", [(5, 0), (-5, 2)])
        self.compare("def core(x, y):\n    for k in range(x, y, 0):\n        pass\n    return 3\n", [(1, 2)])
        self.compare("def core(x, y):\n    if x:\n        z = y\n    return z\n", [(0, 8), (1, 8)])
        self.compare("def core(x, y):\n    x += z\n    z = y\n    return x\n", [(3, 4)])

    def test_public_keyword_arguments_and_builtin_shadowing_runtime(self):
        for name in ("any", "type", "len", "next", "iter", "range", "getattr", "RuntimeError", "StopIteration", "UnboundLocalError"):
            with self.subTest(name=name):
                source = f"def {name}(x, y):\n    return x + y * 2\n"
                _, _, protected = self.build(source, [name])
                self.assertEqual(getattr(protected, name)(y=3, x=2), 8)

    def test_helper_none_and_zero_arity_are_preserved(self):
        source = "def helper(x):\n    return not x\ndef constant():\n    return 3\ndef core(x):\n    return helper(None) + constant() + x\n"
        self.compare(source, [(0,), (-10,), (True,)])
        self.compare("def core():\n    return True\n", [()])

    def test_supported_builtins_and_annotations(self):
        source = "def core(x: int, y: int) -> int:\n    return max(x, y, 0) - min(x, y) + int(bool(x)) + abs(y)\n"
        self.compare(source, [(-4, 7), (0, 0), (True, False)])

    def test_new_seed_changes_encoding_same_seed_reproducible(self):
        source = "def core(x):\n    return x * 19 + 11\n"
        first, _, protected1 = self.build(source, seed=2)
        second, _, protected2 = self.build(source, seed=3)
        third, _, _ = self.build(source, seed=2)
        self.assertNotEqual(first["artifacts"]["protected"]["sha256"], second["artifacts"]["protected"]["sha256"])
        self.assertEqual(first["artifacts"]["protected"]["sha256"], third["artifacts"]["protected"]["sha256"])
        self.assertEqual(protected1.core(51), protected2.core(51))

    def test_encoded_data_corruption_is_rejected_at_import(self):
        report, _, _ = self.build("def core(x):\n    return x + 1\n")
        path = Path(report["protected"])
        source = path.read_text()
        start = source.index("_ar_blob = bytes.fromhex('") + len("_ar_blob = bytes.fromhex('")
        source = source[:start] + ("0" if source[start] != "0" else "1") + source[start + 1:]
        path.write_text(source, encoding="utf-8")
        # Prevent stale same-second import bytecode; explicit source bytes compilation
        # here tests owned generated code and is not part of the frontend compiler.
        with self.assertRaisesRegex(RuntimeError, "integrity"):
            exec(compile(path.read_text(), str(path), "exec"), {})

    def test_noninteger_public_inputs_are_explicitly_unsupported(self):
        _, _, protected = self.build("def core(x):\n    return x + 1\n")
        class IntegerSubclass(int):
            pass
        for value in (1.5, "3", None, [], IntegerSubclass(5)):
            with self.assertRaisesRegex(TypeError, "exact Python int/bool"):
                protected.core(value)

    def test_unsupported_constructs_rejected_before_output(self):
        sources = [
            "import os\ndef core(x):\n    return x\n",
            "open('sentinel', 'w')\ndef core(x):\n    return x\n",
            "@int\ndef core(x):\n    return x\n",
            "def core(x=1):\n    return x\n",
            "def core(*x):\n    return 1\n",
            "def core(x):\n    return x / 2\n",
            "def core(x):\n    return x ** 2\n",
            "def core(x):\n    return x.real\n",
            "def core(x):\n    return [x][0]\n",
            "def core(x):\n    return eval(x)\n",
            "def core(x):\n    yield x\n",
            "def core(x):\n    global value\n    value = x\n    return x\n",
            "def core(x):\n    def inner(y):\n        return y\n    return inner(x)\n",
            "def core(x):\n    return helper(x=x)\ndef helper(x):\n    return x\n",
            "VALUE = 2 + 3\ndef core(x):\n    return x\n",
            "def core(x: side_effect()):\n    return x\n",
            "def core(x):\n    __debug__ = x\n    return x\n",
            "# coding: latin-1\ndef core(x):\n    return x\n",
        ]
        for i, source in enumerate(sources):
            with self.subTest(source=source):
                path = self.root / f"rejected-{i}"
                with self.assertRaises(pf.PythonFrontendError):
                    pf.protect_python_source(source, ["core"], path)
                self.assertFalse(path.exists())

    def test_duplicate_definitions_globals_and_recursive_calls_rejected(self):
        sources = [
            "def core(x):\n    return x\ndef core(y):\n    return y + 1\n",
            "VALUE = 1\nVALUE = 2\ndef core(x):\n    return x\n",
            "def core(x):\n    return core(x - 1)\n",
            "def core(x):\n    return helper(x)\ndef helper(x):\n    return core(x)\n",
            "def core(x):\n    return x\ndef unused(x):\n    return open(x)\n",
        ]
        for source in sources:
            with self.subTest(source=source), self.assertRaises(pf.PythonFrontendError):
                pf.inspect_python_source(source, ["core"])

    def test_range_shadowing_rejected_for_all_scopes(self):
        sources = [
            "range = 3\ndef core(x):\n    for i in range(x):\n        pass\n    return x\n",
            "def range(x):\n    return x\ndef core(x):\n    for i in range(x):\n        pass\n    return x\n",
            "def core(range):\n    for i in range(3):\n        pass\n    return 1\n",
            "def core(x):\n    for i in range(x):\n        pass\n    range = 2\n    return x\n",
        ]
        for source in sources:
            with self.assertRaisesRegex(pf.PythonFrontendError, "unshadowed range"):
                pf.inspect_python_source(source, ["core"])

    def test_differential_8192_random_plus_25_edges_three_fixtures_twice(self):
        evidence = {"schema_version": 1, "backend": "python_vm", "status": "passed",
                    "kind": "owned_original_python_vs_generated_vm", "fixtures": [],
                    "attack_evaluation": "not_performed", "performance_acceptance": "not_evaluated"}
        for fixture, function in (("arithmetic", "integer_score"), ("control", "control_value"), ("exceptional", "exceptional_value")):
            source = (SAMPLES / (fixture + ".py")).read_text(encoding="utf-8")
            report, baseline, protected = self.build(source, [function], seed=20261020)
            original, generated = getattr(baseline, function), getattr(protected, function)
            rng = random.Random(20261020)
            values = [-(2 ** 96), -1, 0, 1, 2 ** 96 - 1]
            ys = [-5, -1, 0, 1, 5] if fixture == "exceptional" else values
            cases = [(x, y) for x in values for y in ys]
            seen = set(cases)
            while len(cases) < 8217:
                pair = (rng.randrange(-(2 ** 96), 2 ** 96),
                        rng.randrange(-12, 13) if fixture == "exceptional" else rng.randrange(-(2 ** 64), 2 ** 64))
                if pair not in seen:
                    cases.append(pair)
                    seen.add(pair)
            counts, durations = [], []
            for repeat in range(2):
                counts_this = {"values": 0, "exceptions": 0}
                stamp = time.perf_counter()
                for pair in cases:
                    expected, actual = outcome(original, pair), outcome(generated, pair)
                    if expected != actual:
                        self.fail(f"{fixture} repeat {repeat} pair {pair}: {expected} != {actual}")
                    counts_this["values" if expected[0] == "value" else "exceptions"] += 1
                durations.append(time.perf_counter() - stamp)
                counts.append(counts_this)
            evidence["fixtures"].append({"fixture": fixture, "function": function,
                "source_sha256": report["inspection"]["source_sha256"],
                "protected_sha256": report["artifacts"]["protected"]["sha256"],
                "random_unique_cases": 8192, "edge_cases": 25, "cases": len(cases), "repeats": 2,
                "matched_each_repeat": len(cases), "outcomes": counts, "comparison_seconds": durations,
                "seed": 20261020, "qualification": "Original Python execution reference, not an independent mathematical oracle; seeded public cases, not attack tests."})
        if os.environ.get("ANTIREA_PYTHON_EVIDENCE"):
            target = Path(os.environ["ANTIREA_PYTHON_EVIDENCE"])
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("x", encoding="utf-8") as stream:
                json.dump(evidence, stream, indent=2)


class PythonProjectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source_dir = self.root / "source"
        self.source_dir.mkdir()
        self.source = self.source_dir / "core.py"
        self.source.write_text("def helper(x):\n    return x + 2\ndef core(x, y):\n    return helper(x) + y\n", encoding="utf-8")
        self.project = self.source_dir / "project.json"
        self.data = {"schema_version": 1, "name": "owned", "language": "python", "sources": ["core.py"], "functions": ["core"]}
        self.save()

    def tearDown(self):
        self.temp.cleanup()

    def save(self):
        self.project.write_text(json.dumps(self.data), encoding="utf-8")

    def test_project_inspection_signatures_and_hashes(self):
        result = pf.inspect_project(self.project)
        self.assertEqual(result["function_signatures"]["core"]["parameters"], ["x", "y"])
        self.assertEqual(result["exported_functions"], ["core"])
        self.assertEqual(result["protected_functions"], ["core", "helper"])
        self.assertEqual(set(result["input_hashes"]), {str(self.project), str(self.source)})
        self.assertFalse((self.root / ".runs").exists())

    def test_build_project_paths_hashes_and_exact_report(self):
        output = self.root / ".runs" / "first"
        report = pf.build_project(self.project, output, workspace_root=self.root, seed=42)
        self.assertEqual(report, json.loads((output / "report.json").read_text()))
        self.assertEqual(report["status"], "artifact_created_unvalidated")
        self.assertEqual(report["changed_inputs"], [])
        for value in report["artifacts"].values():
            self.assertEqual(value["sha256"], hashlib.sha256(Path(value["path"]).read_bytes()).hexdigest())
        self.assertEqual(report["coverage"]["exported_functions"], ["core"])
        self.assertEqual(report["coverage"]["functions"]["core"]["parameters"], ["x", "y"])
        self.assertEqual(load_owned(output / "protected.py").core(3, 7), 12)

    def test_project_output_fresh_workspace_and_source_boundary(self):
        for output in (self.root / "outside-runs", self.root / ".runs", self.source_dir / "output"):
            with self.assertRaises(pf.PythonFrontendError):
                pf.build_project(self.project, output, workspace_root=self.root)
        output = self.root / ".runs" / "fresh"
        pf.build_project(self.project, output, workspace_root=self.root)
        with self.assertRaises(pf.PythonFrontendError):
            pf.build_project(self.project, output, workspace_root=self.root)

    def test_stop_marker_prevents_output(self):
        stop = self.root / ".runs" / "defense-loop" / "STOP"
        stop.parent.mkdir(parents=True)
        stop.touch()
        with self.assertRaisesRegex(pf.PythonFrontendError, "STOP"):
            pf.build_project(self.project, self.root / ".runs" / "stopped", workspace_root=self.root)
        self.assertFalse((self.root / ".runs" / "stopped").exists())

    def test_unknown_fields_and_duplicate_json_rejected(self):
        self.data["build_command"] = "unsafe"
        self.save()
        with self.assertRaisesRegex(pf.PythonFrontendError, "Unknown"):
            pf.inspect_project(self.project)
        self.project.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
        with self.assertRaisesRegex(pf.PythonFrontendError, "Duplicate"):
            pf.inspect_project(self.project)

    def test_source_escape_and_intake_paths_rejected(self):
        for value in ("../core.py", "C:/outside.py", "\\\\server\\core.py", "core.py:stream"):
            self.data["sources"] = [value]
            self.save()
            with self.assertRaises(pf.PythonFrontendError):
                pf.inspect_project(self.project)
        with self.assertRaisesRegex(pf.PythonFrontendError, "Incoming/shared"):
            pf.protect_python_source("def core(x):\n    return x\n", ["core"], self.root / "rea-analysis-reports" / "new")

    def test_source_hardlink_rejected(self):
        alias = self.source_dir / "alias.py"
        try:
            os.link(self.source, alias)
        except OSError as exc:
            self.skipTest(f"Hardlink unavailable: {exc}")
        with self.assertRaisesRegex(pf.PythonFrontendError, "Hardlinked"):
            pf.inspect_project(self.project)

    def test_source_changes_during_generation_fail_closed(self):
        original = pf._generate
        def mutate(*args, **kwargs):
            result = original(*args, **kwargs)
            self.source.write_text("def core(x, y):\n    return x - y\n", encoding="utf-8")
            return result
        with patch.object(pf, "_generate", side_effect=mutate):
            report = pf.build_project(self.project, self.root / ".runs" / "changed", workspace_root=self.root)
        self.assertEqual(report["status"], "failed")
        self.assertIn(str(self.source), report["changed_inputs"])

    def test_partial_write_failure_is_recorded_not_success(self):
        original = pf._write
        def fail_protected(path, text):
            if path.name == "protected.py":
                raise OSError("simulated output failure")
            original(path, text)
        output = self.root / ".runs" / "write-failure"
        with patch.object(pf, "_write", side_effect=fail_protected):
            report = pf.build_project(self.project, output, workspace_root=self.root)
        self.assertEqual(report["status"], "failed")
        self.assertIn("simulated output failure", report["error"])
        self.assertEqual(report, json.loads((output / "report.json").read_text()))


if __name__ == "__main__":
    unittest.main()
