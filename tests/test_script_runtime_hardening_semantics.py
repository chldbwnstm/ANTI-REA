"""Independent SEMANTICS tests for Phase23 script runtime-hardening (lane 3).

This lane asserts BEHAVIOR PRESERVATION ONLY. For the pure and mixed Python and
JavaScript/TypeScript routes, the generated protected artifact must reproduce the
owned baseline's scalar outcomes and exception classes, under TWO distinct seeds,
despite the per-function engine diversification (seed-diversified handler order
and encoded-state control-flow flattening) the shared Phase23 brief introduces.

Deliberate NON-goals (owned by other lanes / root, per the brief):
  * No assertion on emitted dispatcher/table structure, handler-order permutation,
    state ids/masks or the ``runtime_hardening`` coverage block -- that is the
    STRUCTURAL reviewer lane's scope.
  * No assertion on the ``dispatcher`` coverage token or on validator "second
    repeat array" evidence -- the coordinator confirmed those are changing and
    that independent tests must not assume the old shared dispatcher.
  * No claim of attack resistance, performance or Kagura/native parity.
These checks are therefore robust to the dispatcher rename: they pass for any
engine (shared or per-function flattened) that preserves user semantics, which is
exactly the invariant the implementers must not regress.

Execution model (this file is UNEXECUTED by its author; root runs it under its
own outer bounded Job once RUN-READY):
  * Python routes build protected/baseline modules with the production
    ``protect_python_source`` APIs and import the OWNED generated modules in
    process; no draft/candidate/received file is ever loaded.
  * JavaScript/TypeScript routes build protected/baseline with the production
    ``_parse``/``_generate`` APIs and compare them with an OWNED comparison
    driver run as a separate child ONLY through ``antirea.process.run_logged``,
    with the real workspace ``.runs/defense-loop/STOP`` as the read-only cancel
    marker, a strict allow-listed environment with a private TEMP, a timeout, raw
    logs and verified Windows Job process-tree cleanup. No new ``subprocess.run``
    is introduced for generated-target execution and no owned target is run here
    by a direct ``node``/``unittest`` invocation.

Seeds are two fixed, distinct values in ``0..2**256-1``; the tests additionally
assert the two seeds yield DISTINCT generated source (genuine diversification)
while producing IDENTICAL behavior -- a semantic-robustness claim, not a
structural one.
"""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

from antirea import python_frontend as pf
from antirea import python_mixed_module as pmm
from antirea import javascript_frontend as jf
from antirea import javascript_mixed_module as jmm
from antirea.process import run_logged


REPO = Path(__file__).resolve().parents[1]
# Real repository defender STOP marker. run_logged only ever READS this path
# (cancel_file.exists()); this lane never creates, removes or writes it.
STOP = REPO / ".runs" / "defense-loop" / "STOP"

# Two fixed distinct seeds, both inside 0..2**256-1.
SEED_A = 20261020
SEED_B = 1734100099


def load_owned(path, tag):
    """Import an OWNED generated module from an explicit path in a fresh module
    object. Never used on a draft/candidate/received file -- only on baseline.py
    / protected.py this test just produced with the production builders."""
    name = "owned_sem_" + tag
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def py_outcome(function, arguments):
    """Canonical Python outcome: value type-name + value, or exception class.

    Recording ``type(value).__name__`` distinguishes bool from int (True vs 1),
    so bool-vs-int preservation is checked, not merely numeric equality."""
    try:
        value = function(*arguments)
        return ("value", type(value).__name__, value)
    except Exception as error:  # noqa: BLE001 - exception CLASS is the contract
        return ("exception", type(error).__name__)


# Strict allow-listed child environment with a private TEMP, mirroring the
# reviewed clean environment in tests/js_mixed_validate_support.clean_env so JS
# comparison children run bounded and isolated.
_ENV_ALLOW = ("SystemRoot", "SystemDrive", "windir", "NUMBER_OF_PROCESSORS",
              "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "COMSPEC", "PATHEXT",
              "LANG", "LC_ALL", "LC_CTYPE", "TZ")


def _clean_env(private_temp):
    Path(private_temp).mkdir(parents=True, exist_ok=True)
    env = {key: os.environ[key] for key in _ENV_ALLOW if key in os.environ}
    if os.name == "nt":
        system_root = env.get("SystemRoot") or env.get("windir") or "C:\\Windows"
        env["PATH"] = os.pathsep.join([str(Path(system_root) / "System32"), str(Path(system_root))])
    else:
        env["PATH"] = "/usr/bin:/bin"
    env["TEMP"] = env["TMP"] = env["TMPDIR"] = str(private_temp)
    return env


# OWNED Node comparison driver. It requires the baseline module and each protected
# arm by absolute path, canonicalizes each scalar outcome (binary64 hex preserves
# NaN/Infinity/negative-zero distinctly; BigInt kept as decimal; boolean kept
# distinct) and asserts deep-equality of protected vs baseline for every function
# and case, twice per case to catch any cross-call state leakage. It never decodes
# instructions or inspects engine structure -- outcomes only.
_DRIVER_BODY = r'''
function observed(fn, args) {
  try {
    const value = fn(...args);
    if (typeof value === "number") {
      if (Number.isNaN(value)) return ["number", "NaN"];
      const bytes = Buffer.alloc(8); bytes.writeDoubleBE(value);
      return ["number", bytes.toString("hex")];
    }
    if (typeof value === "bigint") return ["bigint", value.toString()];
    if (typeof value === "boolean") return ["boolean", value];
    if (value === undefined) return ["undefined"];
    if (value === null) return ["null"];
    throw new Error("unsupported owned outcome type: " + typeof value);
  } catch (error) {
    return ["exception", Object.getPrototypeOf(error).constructor.name];
  }
}

try {
  const baseline = require(BASELINE_PATH);
  const subjects = SUBJECT_PATHS.map((p) => require(p));
  const names = NAMES;
  const cases = CASES;
  for (let s = 0; s < subjects.length; ++s) {
    const subject = subjects[s];
    for (const name of names) {
      assert.equal(typeof baseline[name], "function", "baseline missing export " + name);
      assert.equal(typeof subject[name], "function", "subject[" + s + "] missing export " + name);
      for (const args of cases) {
        const expected = observed(baseline[name], args);
        const got = observed(subject[name], args);
        assert.deepEqual(got, expected,
          "seed#" + s + " " + name + "(" + args.map(String).join(", ") + ") => "
          + JSON.stringify(got) + " vs baseline " + JSON.stringify(expected));
        // Re-run: a correct engine must not cache a decoded result or leak state.
        assert.deepEqual(observed(subject[name], args), expected,
          "seed#" + s + " " + name + " unstable across repeated calls");
      }
    }
  }
  console.log("OK");
} catch (error) {
  console.error("SEMANTIC_MISMATCH: " + (error && error.stack ? error.stack : error));
  process.exit(1);
}
'''


def _driver_text(baseline_path, subject_paths, names, cases_expr):
    header = ('"use strict";\n'
              'const assert = require("node:assert/strict");\n'
              "const BASELINE_PATH = " + json.dumps(str(baseline_path)) + ";\n"
              "const SUBJECT_PATHS = " + json.dumps([str(p) for p in subject_paths]) + ";\n"
              "const NAMES = " + json.dumps(list(names)) + ";\n"
              "const CASES = " + cases_expr + ";\n")
    return header + _DRIVER_BODY


# Shared JS case expressions (raw JS array literals so NaN/Infinity/-0/BigInt are
# expressible). They are owned fixtures, not produced by any attack path.
NUM_CASES = ("[[-0, 0], [0, -0], [NaN, 2], [Infinity, 2], [-Infinity, Infinity], "
             "[Number.MIN_VALUE, 2], [Number.MAX_VALUE, 2], [2 ** 53, 1], [-3, 2], "
             "[1.5, 0.25], [true, false], [17, -4]]")
BIG_CASES = ("[[0n, 0n], [1n, 1n], [-(1n << 5000n), 3n], [(1n << 6000n) + 19n, 5n], "
             "[7n, -2n], [17n, 3n], [-17n, 3n], [1n, 0n]]")
INT_PAIRS = ("[" + ", ".join("[" + str(x) + ", " + str(y) + "]"
                             for x in (-5, 0, 3, 8, 15) for y in (-1, 0, 1, 2, 4)) + "]")


class _JsCompareMixin:
    """Build protected/baseline with production APIs and compare outcomes through
    a bounded run_logged child. Requires a discoverable Node toolchain."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.counter = 0

    def _fresh(self, label):
        self.counter += 1
        directory = self.root / (label + "-" + str(self.counter))
        directory.mkdir(parents=True, exist_ok=False)
        return directory

    def run_js_compare(self, baseline_path, subject_paths, names, cases_expr, *, timeout=120):
        workdir = self._fresh("compare")
        driver = workdir / "compare.cjs"
        driver.write_text(_driver_text(baseline_path, subject_paths, names, cases_expr),
                          encoding="utf-8", newline="\n")
        env = _clean_env(workdir / "tmp")
        command = [self.node, "--no-addons", "--max-old-space-size=256", str(driver)]
        proc = run_logged(command, workdir, workdir / "compare", timeout, env=env, cancel_file=STOP)
        cleanup = proc.get("cleanup", {})
        if os.name == "nt":
            self.assertTrue(
                cleanup.get("job_assigned") and cleanup.get("parent_exit_confirmed")
                and cleanup.get("job_handle_closed") and cleanup.get("active_after") == 0
                and cleanup.get("status") == "assigned_job_empty",
                "bounded comparison child cleanup was not verified: " + json.dumps(cleanup))
        self.assertFalse(proc.get("cancelled"), "comparison child was cancelled by STOP")
        self.assertFalse(proc.get("timed_out"), "comparison child timed out")
        stdout = Path(proc["stdout"]).read_text(encoding="utf-8")
        stderr = Path(proc["stderr"]).read_text(encoding="utf-8")
        self.assertEqual(proc["returncode"], 0,
                         "node comparison failed\nSTDOUT:\n" + stdout + "\nSTDERR:\n" + stderr)
        self.assertIn("OK", stdout)


class JavaScriptPureSemanticsTests(_JsCompareMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.tools = jf.discover_toolchain()
        except jf.JavaScriptFrontendError as error:
            raise unittest.SkipTest("JavaScript toolchain unavailable: " + str(error))
        cls.node = cls.tools["files"]["node"]["path"]

    def emit_pure(self, source, names, language="javascript", seeds=(SEED_A, SEED_B)):
        parsed = jf._parse(source, language, list(names), self.tools, build=True)
        directory = self._fresh("pure")
        baseline_path = directory / "baseline.cjs"
        baseline_path.write_text(parsed["baseline"], encoding="utf-8", newline="\n")
        subjects, sources = [], set()
        for index, seed in enumerate(seeds):
            runtime, _coverage = jf._generate(parsed, seed)
            sources.add(runtime)
            path = directory / ("protected_" + str(index) + ".cjs")
            path.write_text(runtime, encoding="utf-8", newline="\n")
            subjects.append(path)
        self.assertEqual(len(sources), len(seeds),
                         "distinct seeds must yield distinct generated pure-route source")
        return baseline_path, subjects, parsed["exported_functions"]

    def test_number_special_values_and_operators_two_seeds(self):
        source = ("function core(x, y) { return x === y ? -x : (Math.fround(x) + x / y) % 7; }\n"
                  "function diff(x, y) { return (x ** y) - Math.sign(y); }")
        baseline, subjects, names = self.emit_pure(source, ["core", "diff"])
        self.run_js_compare(baseline, subjects, names, NUM_CASES)

    def test_bigint_values_shifts_and_conversion_exceptions_two_seeds(self):
        source = ("const C = " + hex((1 << 4095) + 17) + "n;\n"
                  "function helper(x) { return x * C; }\n"
                  "function core(x, y) { return (helper(x) + C) << y; }\n"
                  "function rem(x, y) { return x / y; }")
        baseline, subjects, names = self.emit_pure(source, ["core", "rem"])
        self.run_js_compare(baseline, subjects, names, BIG_CASES)

    def test_loops_break_continue_helper_recursionless_two_seeds(self):
        source = ("function helper(x) { return (x ^ 31) - 7; }\n"
                  "function core(x, y) {\n"
                  "  let total = 0;\n"
                  "  for (let i = 0; i < (x & 7); ++i) {\n"
                  "    if (i === y) continue;\n"
                  "    let j = 0;\n"
                  "    while (j < 3) { j++; if (j === y) break; total += helper(i * j); }\n"
                  "    if (total > 500) break;\n"
                  "  }\n"
                  "  do { total++; } while (total < -10);\n"
                  "  return total;\n"
                  "}")
        baseline, subjects, names = self.emit_pure(source, ["core"])
        self.run_js_compare(baseline, subjects, names, INT_PAIRS)

    def test_builtin_name_shadow_typescript_two_seeds(self):
        names = ["Object", "Math", "Number", "BigInt", "Boolean", "JSON", "Array"]
        source = "\n".join(
            "export function " + name + "(x: number, y: number): number { return x + y; }"
            for name in names)
        baseline, subjects, exported = self.emit_pure(source, names, language="typescript")
        self.run_js_compare(baseline, subjects, exported, NUM_CASES)

    def test_zero_arg_helper_nullish_and_boolean_short_circuit_two_seeds(self):
        source = ("function empty() { return undefined; }\n"
                  "function missing() { return null; }\n"
                  "function flag(x) { return !x; }\n"
                  "function core(x, y) { return x ? (empty() ?? missing() ?? flag(y)) : (x && y); }")
        baseline, subjects, names = self.emit_pure(source, ["core"])
        cases = "[[false, 0], [true, 0], [true, 1], [0, 5], [1, 0], [-0, 1], [NaN, 2]]"
        self.run_js_compare(baseline, subjects, names, cases)


class JavaScriptMixedSemanticsTests(_JsCompareMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.tools = jmm.discover_toolchain()
        except jmm.MixedModuleError as error:
            raise unittest.SkipTest("JavaScript mixed toolchain unavailable: " + str(error))
        cls.node = cls.tools["files"]["node"]["path"]

    def emit_mixed(self, source, language, functions, seeds=(SEED_A, SEED_B)):
        directory = self._fresh("mixed")
        baseline_path = directory / "baseline.cjs"
        baseline_text, subjects, sources = None, [], set()
        for index, seed in enumerate(seeds):
            protected, baseline, _coverage, _inspection, _parsed = jmm._generate(
                source, language, list(functions), self.tools, seed)
            if baseline_text is None:
                baseline_text = baseline
                baseline_path.write_text(baseline, encoding="utf-8", newline="\n")
            else:
                self.assertEqual(baseline, baseline_text,
                                 "mixed baseline must be seed-independent (original module text)")
            sources.add(protected)
            path = directory / ("protected_" + str(index) + ".cjs")
            path.write_text(protected, encoding="utf-8", newline="\n")
            subjects.append(path)
        self.assertEqual(len(sources), len(seeds),
                         "distinct seeds must yield distinct generated mixed-route source")
        return baseline_path, subjects

    # Owned sample: pure scalar functions + a reachable helper (sq) that is also
    # exported, a BigInt function, and a NON-selected function (describe) that the
    # mixed route must preserve verbatim and keep behaviorally identical.
    MIXED_SOURCE = (
        "'use strict';\n"
        "const THRESHOLD = 100;\n"
        "function sq(x) { return x * x; }\n"
        "function core(x, y) {\n"
        "  let total = 0;\n"
        "  for (let i = 0; i < 4; i++) { if (i === y) continue; total += sq(x) + i; if (total > 1000) break; }\n"
        "  return total;\n"
        "}\n"
        "function bmul(a, b) { return a * b + 1n; }\n"
        "function describe(n) { return n < THRESHOLD; }\n"
        "module.exports = { core, bmul, sq, describe };\n"
    )

    def test_mixed_number_route_and_preserved_function_two_seeds(self):
        baseline, subjects = self.emit_mixed(self.MIXED_SOURCE, "javascript", ["core"])
        # core/sq are virtualized (core selected, sq reachable helper); describe is
        # preserved plaintext. All three must match baseline on number inputs.
        self.run_js_compare(baseline, subjects, ["core", "sq", "describe"], NUM_CASES)

    def test_mixed_bigint_route_two_seeds(self):
        baseline, subjects = self.emit_mixed(self.MIXED_SOURCE, "javascript", ["bmul"])
        self.run_js_compare(baseline, subjects, ["bmul"], BIG_CASES)


class PythonPureSemanticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.counter = 0

    def _build(self, source, roots, seed):
        self.counter += 1
        directory = self.root / ("pp-" + str(self.counter))
        report = pf.protect_python_source(source, list(roots), directory, seed=seed)
        self.assertEqual(report["status"], "artifact_created_unvalidated")
        self.assertFalse(report["source_executed"])
        return directory

    def assert_equivalent(self, source, roots, cases=None, *, cases_by_name=None, seeds=(SEED_A, SEED_B)):
        # ``cases`` applies one case list to every root; ``cases_by_name`` gives
        # each function its own list so functions of different arity are each
        # exercised at their real arity with meaningful (non-exception) outputs.
        if (cases is None) == (cases_by_name is None):
            raise ValueError("pass exactly one of cases or cases_by_name")
        baseline, sources = None, set()
        for index, seed in enumerate(seeds):
            directory = self._build(source, roots, seed)
            if baseline is None:
                baseline = load_owned(directory / "baseline.py", "pp_base_" + str(self.counter))
            protected = load_owned(directory / "protected.py", "pp_prot_" + str(self.counter))
            sources.add((directory / "protected.py").read_text(encoding="utf-8"))
            for name in roots:
                base_fn, prot_fn = getattr(baseline, name), getattr(protected, name)
                name_cases = cases_by_name[name] if cases_by_name is not None else cases
                for args in name_cases:
                    expected = py_outcome(base_fn, args)
                    got = py_outcome(prot_fn, args)
                    self.assertEqual(got, expected,
                                     "seed#%d %s%r => %r vs baseline %r" % (index, name, args, got, expected))
                    self.assertEqual(py_outcome(prot_fn, args), expected,
                                     "seed#%d %s unstable across repeated calls" % (index, name))
        self.assertEqual(len(sources), len(seeds),
                         "distinct seeds must yield distinct protected source")

    def test_root_and_helper_arithmetic_two_seeds(self):
        # core takes two arguments; helper takes exactly one. Previously helper was
        # compared with two-argument cases, so it only ever matched TypeError vs
        # TypeError and proved nothing about its real output. Each function is now
        # exercised at its own arity with real (non-exception) int/bool outputs,
        # including bool-vs-int coercion through the single-argument helper.
        source = ("def helper(x):\n    return (x ^ 31) - 7\n"
                  "def core(x, y):\n    return helper(x) * 3 + helper(y)\n")
        helper_cases = [(-7,), (0,), (1,), (42,), (True,), (False,), (-(1 << 300),), ((1 << 300) + 5,)]
        core_cases = [(a, b) for a in (-7, 0, 1, 42) for b in (-3, 0, 5)]
        self.assert_equivalent(source, ["core", "helper"],
                               cases_by_name={"core": core_cases, "helper": helper_cases})

    def test_unbounded_integers_and_shift_exceptions_two_seeds(self):
        literal = (1 << 4095) + 17
        source = ("C = " + hex(literal) + "\n"
                  "def core(x, y):\n    return ((x + C) * (x - C)) << y\n")
        self.assert_equivalent(source, ["core"],
                               [(0, 0), (True, 1), (-(1 << 5000), 3), ((1 << 6000) + 19, 5), (1, -1)])

    def test_bool_vs_int_and_short_circuit_two_seeds(self):
        source = ("def core(x, y):\n    return (x and (10 // y)) or (not x)\n")
        self.assert_equivalent(source, ["core"],
                               [(False, 0), (True, 2), (True, 0), (2, -3), (0, 0), (1, 1)])

    def test_loops_break_continue_and_loop_else_two_seeds(self):
        source = ("def helper(x):\n    return (x ^ 31) - 7\n"
                  "def core(x, y):\n"
                  "    total = 0\n"
                  "    for i in range(-3, x, 2):\n"
                  "        if i == y:\n"
                  "            continue\n"
                  "        j = 0\n"
                  "        while j < 3:\n"
                  "            j += 1\n"
                  "            if j == y:\n"
                  "                break\n"
                  "            total += helper(i * j)\n"
                  "        else:\n"
                  "            total ^= 123\n"
                  "        if total > 500:\n"
                  "            break\n"
                  "    else:\n"
                  "        total += 79\n"
                  "    return total\n")
        self.assert_equivalent(source, ["core"],
                               [(x, y) for x in (-5, 0, 3, 8, 15) for y in (-1, 0, 1, 2, 4)])

    def test_builtin_name_shadow_runtime_two_seeds(self):
        names = ["len", "min", "next", "range", "type", "list", "dict", "bytes"]
        source = "\n".join("def " + name + "(x):\n    return x + 1\n" for name in names)
        self.assert_equivalent(source, names, [(0,), (41,), (True,), (-7,), ((1 << 300) + 5,)])

    def test_zero_arg_helper_internal_none_and_public_bool_two_seeds(self):
        source = ("def empty():\n    return None\n"
                  "def helper(x):\n    return not x\n"
                  "def core(x):\n    return helper(empty()) if x else helper(x)\n")
        self.assert_equivalent(source, ["core"], [(False,), (True,), (0,), (1,), (-7,)])

    def test_exception_classes_preserved_two_seeds(self):
        source = ("def core(x, y):\n"
                  "    if y < 0:\n"
                  "        return x << y\n"
                  "    return (x // y) * 101 + x % y\n")
        self.assert_equivalent(source, ["core"],
                               [(-19, 4), (19, 4), (0, 4), (-19, 0), (19, -1), (True, 1), (-(1 << 200), 17)])


class PythonMixedSemanticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.counter = 0

    def _build(self, source, selected, seed):
        self.counter += 1
        directory = self.root / ("pm-" + str(self.counter))
        report = pmm.protect_python_source(source, list(selected), directory, seed=seed)
        self.assertEqual(report["status"], "artifact_created_unvalidated")
        self.assertFalse(report["source_executed"])
        return directory

    def assert_equivalent(self, source, selected, compare_names, cases, *, seeds=(SEED_A, SEED_B)):
        baseline, sources = None, set()
        for index, seed in enumerate(seeds):
            directory = self._build(source, selected, seed)
            if baseline is None:
                baseline = load_owned(directory / "baseline.py", "pm_base_" + str(self.counter))
            protected = load_owned(directory / "protected.py", "pm_prot_" + str(self.counter))
            sources.add((directory / "protected.py").read_text(encoding="utf-8"))
            for name in compare_names:
                base_fn, prot_fn = getattr(baseline, name), getattr(protected, name)
                for args in cases:
                    expected = py_outcome(base_fn, args)
                    got = py_outcome(prot_fn, args)
                    self.assertEqual(got, expected,
                                     "seed#%d %s%r => %r vs baseline %r" % (index, name, args, got, expected))
                    self.assertEqual(py_outcome(prot_fn, args), expected,
                                     "seed#%d %s unstable across repeated calls" % (index, name))
        self.assertEqual(len(sources), len(seeds),
                         "distinct seeds must yield distinct protected source")

    # Owned mixed sample: core (selected) reaches helpers h1/h2 (closure); describe
    # is a NON-selected top-level function preserved verbatim and still callable;
    # THRESHOLD is a module global referenced only by the preserved function.
    MIXED_SOURCE = (
        "THRESHOLD = 100\n"
        "def h1(x):\n    return x * 3\n"
        "def h2(x):\n    return (x ^ 5) - 1\n"
        "def core(x):\n    return h1(x) + h2(x)\n"
        "def describe(n):\n    return n < THRESHOLD\n"
    )

    def test_selected_closure_and_preserved_functions_two_seeds(self):
        self.assert_equivalent(self.MIXED_SOURCE, ["core"], ["core", "h1", "h2", "describe"],
                               [(0,), (1,), (True,), (-7,), (41,), ((1 << 300) + 9,)])

    def test_closure_loops_bigint_bool_and_exceptions_two_seeds(self):
        source = ("def helper(x):\n    return x ^ 31\n"
                  "def core(x, y):\n"
                  "    total = 0\n"
                  "    for i in range(x):\n"
                  "        if i == y:\n"
                  "            continue\n"
                  "        total += helper(i)\n"
                  "    return (total // y) if y else total\n")
        self.assert_equivalent(source, ["core"], ["core"],
                               [(0, 0), (5, 2), (5, 0), (True, 1), (7, 3), (12, -1)])

    def test_reached_helper_rebinding_guard_covers_every_engine(self):
        # Build once; load fresh module instances so each rebind is independent.
        directory = self._build(self.MIXED_SOURCE, ["core"], SEED_A)
        baseline = load_owned(directory / "baseline.py", "pm_rebase")
        # Normal (unrebound) behavior matches baseline for the reached helpers.
        normal = load_owned(directory / "protected.py", "pm_rb_normal")
        for args in [(0,), (3,), (-5,)]:
            self.assertEqual(py_outcome(normal.core, args), py_outcome(baseline.core, args))
        # Rebinding the SECOND reached helper (h2) must still fail closed, proving
        # the identity guard covers non-first engines, not just the first call.
        for target in ("h1", "h2"):
            with self.subTest(rebound=target):
                module = load_owned(directory / "protected.py", "pm_rb_" + target)
                setattr(module, target, lambda *a, **k: 0)
                with self.assertRaisesRegex(RuntimeError, "rebinding"):
                    module.core(3)

    def test_reached_builtin_rebinding_guard(self):
        source = ("def core(n):\n"
                  "    total = 0\n"
                  "    for i in range(n):\n"
                  "        total += i\n"
                  "    return total\n")
        directory = self._build(source, ["core"], SEED_A)
        baseline = load_owned(directory / "baseline.py", "pm_bb_base")
        normal = load_owned(directory / "protected.py", "pm_bb_normal")
        for args in [(0,), (1,), (5,)]:
            self.assertEqual(py_outcome(normal.core, args), py_outcome(baseline.core, args))
        rebound = load_owned(directory / "protected.py", "pm_bb_rebound")
        setattr(rebound, "range", lambda *a, **k: [])
        with self.assertRaisesRegex(RuntimeError, "rebinding"):
            rebound.core(5)


if __name__ == "__main__":
    unittest.main()
