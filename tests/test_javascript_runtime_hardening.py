"""Owned structural tests for the JavaScript per-function flattened VM engines.

These tests exercise the JavaScript runtime-hardening generator
(antirea.javascript_runtime_hardening) and assert the ACTUAL emitted runtime
source shape and the coverage ``runtime_hardening`` metadata that must mirror it,
for BOTH the pure (antirea.javascript_frontend._generate) and mixed
(antirea.javascript_mixed_module._encode_program) production routes.

Scope and safety: this suite is pure Python. It builds synthetic parsed inputs
and inspects generated source text and metadata only; it never spawns a Node
child, never runs the TypeScript parser, a compiler, a build or any generated or
owned target program, and reads no env.setting/LINKREPRO/attackerfolder/
rea-analysis-reports path. Runtime semantic equivalence under Node is the
semantics lane's responsibility, executed under the root bounded harness. As of
this worker's handoff these tests are written but NOT executed here; the parent
qualification runner executes them.
"""
import re
import unittest
from unittest import mock

from antirea import javascript_frontend as jf
from antirea import javascript_mixed_module as jmm
from antirea import javascript_runtime_hardening as jrh


ENGINE_PREFIX = {"pure": "_ar_engine_", "mixed": "_arm_engine_"}
TABLE_SYMBOL = {"pure": "_ar_dispatch", "mixed": "_arm_dispatch"}


def synthetic_parsed(names):
    """A minimal valid parsed program: every named function gets its own engine.

    Instruction contents are irrelevant to engine structure (every engine emits
    all 17 opcode handlers regardless of which opcodes a function uses), so a
    tiny valid body per function suffices.
    """
    functions = {}
    for index, name in enumerate(names):
        functions[name] = {"slots": ["parameter"], "parameters": ["x"], "helpers": [],
                           "code": [["load", 0], ["return"]]}
    return {"helper_closure": list(names), "exported_functions": list(names), "functions": functions}


def engine_case_labels(source):
    """Opcode indices of every `case tokens[n]:` in textual order."""
    return [int(value) for value in re.findall(r"case tokens\[(\d+)\]:", source)]


class EngineGeneratorContractTests(unittest.TestCase):
    def test_duplicate_state_signature_fails_closed(self):
        plan = jrh._engine_plan(19, 0)
        with mock.patch.object(jrh, "_engine_plan", return_value=plan):
            with self.assertRaisesRegex(jrh.EngineGenerationError, "state collision"):
                jrh.emit_engines(19, 2, "pure")

    def test_emit_engines_is_deterministic_and_seed_sensitive(self):
        for variant in ("pure", "mixed"):
            block, meta = jrh.emit_engines(20261021, 3, variant)
            again, meta_again = jrh.emit_engines(20261021, 3, variant)
            self.assertEqual(block, again)
            self.assertEqual(meta, meta_again)
            other, _ = jrh.emit_engines(20261022, 3, variant)
            self.assertNotEqual(block, other)
        pure_block, _ = jrh.emit_engines(5, 2, "pure")
        mixed_block, _ = jrh.emit_engines(5, 2, "mixed")
        self.assertNotEqual(pure_block, mixed_block)

    def test_metadata_fixed_profile_and_honest_flags(self):
        _, meta = jrh.emit_engines(7, 4, "pure")
        self.assertEqual(meta["schema_version"], 1)
        self.assertEqual(meta["profile"], "per_function_flattened_dispatch_v1")
        self.assertEqual(meta["stage"], "generated_source")
        self.assertEqual(meta["engine_count"], 4)
        self.assertEqual(meta["dispatch_table_symbol"], "_ar_dispatch")
        self.assertIs(meta["shared_fetch_and_operator_helpers"], True)
        self.assertIs(meta["kagura_passes_applied"], False)
        self.assertEqual(meta["external_resistance"], "not_evaluated")

    def test_state_ids_are_distinct_nonzero_30bit_per_engine(self):
        _, meta = jrh.emit_engines((1 << 200) + 3, 6, "pure")
        for engine in meta["engines"]:
            states = engine["state_ids"]
            values = [states["fetch"], states["execute"], states["return"]]
            self.assertEqual(len(set(values)), 3)
            for value in values:
                self.assertTrue(1 <= value < (1 << 30))
            self.assertEqual(engine["state_mask"], (1 << 30) - 1)
            self.assertEqual(jrh.STATE_MASK, (1 << 30) - 1)

    def test_handler_order_is_a_full_permutation_with_adjacent_call_builtin(self):
        _, meta = jrh.emit_engines(99, 5, "mixed")
        for engine in meta["engines"]:
            order = engine["handler_order"]
            self.assertEqual(sorted(order), list(range(len(jrh.JS_OPS))))
            self.assertEqual(order.index(jrh.BUILTIN_OP), order.index(jrh.CALL_OP) + 1)

    def test_symbols_and_table_follow_the_variant(self):
        for variant in ("pure", "mixed"):
            _, meta = jrh.emit_engines(3, 3, variant)
            self.assertEqual(meta["dispatch_table_symbol"], TABLE_SYMBOL[variant])
            self.assertEqual([engine["symbol"] for engine in meta["engines"]],
                             [ENGINE_PREFIX[variant] + str(i) for i in range(3)])
            self.assertEqual(len({engine["symbol"] for engine in meta["engines"]}), 3)

    def test_encoded_transitions_land_on_the_declared_state_ids(self):
        block, meta = jrh.emit_engines(451, 3, "pure")
        mask = (1 << 30) - 1
        for engine in meta["engines"]:
            fetch, execute, ret = (engine["state_ids"]["fetch"], engine["state_ids"]["execute"],
                                   engine["state_ids"]["return"])
            to_execute = (execute - fetch) % (1 << 30)
            to_fetch = (fetch - execute) % (1 << 30)
            to_return = (ret - execute) % (1 << 30)
            # Masked modular-add transitions reproduce the next state id exactly.
            self.assertEqual((fetch + to_execute) & mask, execute)
            self.assertEqual((execute + to_fetch) & mask, fetch)
            self.assertEqual((execute + to_return) & mask, ret)
            self.assertIn("case %d: current = fetch(fn, pc++); state = (state + %d) & %d; break;"
                          % (fetch, to_execute, mask), block)
            self.assertIn("state = (state + %d) & %d; break;" % (to_fetch, mask), block)
            self.assertIn("result = stack.pop(); state = (state + %d) & %d; break;" % (to_return, mask), block)
            self.assertIn("case %d: return result;" % ret, block)

    def test_emit_engines_rejects_invalid_requests(self):
        for bad in ("native", "", "PURE"):
            with self.assertRaises(jrh.EngineGenerationError):
                jrh.emit_engines(1, 1, bad)
        for count in (0, -1, 1.0, True):
            with self.assertRaises(jrh.EngineGenerationError):
                jrh.emit_engines(1, count, "pure")
        for seed in (-1, 2 ** 256, 1.5, None):
            with self.assertRaises(jrh.EngineGenerationError):
                jrh.emit_engines(seed, 1, "pure")


class _EmittedSourceChecks:
    """Shared assertions over a generated runtime and its coverage metadata."""

    variant = None

    def assert_engine_structure(self, runtime, coverage):
        hardening = coverage["runtime_hardening"]
        count = hardening["engine_count"]
        self.assertEqual(count, coverage["codec_count"])
        self.assertEqual(coverage["dispatcher"], "per_function_flattened_indirect_dispatch")
        self.assertIs(hardening["kagura_passes_applied"], False)
        self.assertIs(coverage.get("kagura_passes_applied"), False)
        self.assertEqual(hardening["external_resistance"], "not_evaluated")
        prefix, table = ENGINE_PREFIX[self.variant], TABLE_SYMBOL[self.variant]
        self.assertEqual(hardening["dispatch_table_symbol"], table)

        # Each protected function has its OWN engine declaration (exactly once),
        # and there is no shared opcode interpreter or decode loop any more.
        for identifier in range(count):
            self.assertEqual(runtime.count("function %s%d(args) {" % (prefix, identifier)), 1)
        self.assertNotIn("while (true)", runtime)
        self.assertEqual(runtime.count("switch (state)"), count)
        self.assertEqual(runtime.count("switch (current[0])"), count)
        # One fail-closed invalid-state branch per engine. The invalid-opcode
        # text also occurs once in the shared fetch token-membership guard, so
        # the per-engine inner-switch defaults total engine_count + 1.
        self.assertEqual(runtime.count('throw new Error("Invalid VM state")'), count)
        self.assertEqual(runtime.count('throw new Error("Invalid VM opcode")'), count + 1)

        # Indirect dispatch table lists every engine in id order; the invoke seam
        # only range-checks and forwards -- it carries no opcode switch.
        table_line = "const %s = [%s];" % (table, ", ".join("%s%d" % (prefix, i) for i in range(count)))
        self.assertIn(table_line, runtime)
        self.assertIn("return %s[identifier](args);" % table, runtime)
        invoke_start = runtime.index("function invoke(identifier, args) {")
        invoke_body = runtime[invoke_start:invoke_start + 400]
        self.assertNotIn("switch", invoke_body)
        self.assertNotIn("case tokens[", invoke_body)

        # Shared helpers appear once and are reported as shared.
        for helper in ("function readByte(fn, position) {", "function fetch(fn, instructionPC) {",
                       "function constant(value) {", "function binary(operator, left, right) {",
                       "function loadSlot(fn, slots, slot) {", "function assignSlot(fn, slots, slot, value) {"):
            self.assertEqual(runtime.count(helper), 1, helper)

        # The emitted per-engine handler order matches the metadata exactly, with
        # the call/builtin pair adjacent in the real source.
        labels = engine_case_labels(runtime)
        self.assertEqual(len(labels), 17 * count)
        for engine in hardening["engines"]:
            identifier = engine["vm_function_id"]
            window = labels[identifier * 17:(identifier + 1) * 17]
            self.assertEqual(window, engine["handler_order"])
            self.assertEqual(sorted(window), list(range(17)))
            self.assertEqual(window.index(jrh.BUILTIN_OP), window.index(jrh.CALL_OP) + 1)
            self.assertIn("function %s(args) {" % engine["symbol"], runtime)
            self.assertIn("let pc = 0, state = %d, current = null, result;" % engine["state_ids"]["fetch"], runtime)

        self.assertNotIn("eval(", runtime)
        self.assertNotIn("Function(", runtime)
        self.assertNotIn("new Function", runtime)


class PureEmittedSourceTests(_EmittedSourceChecks, unittest.TestCase):
    variant = "pure"

    def generate(self, names, seed=20261021):
        return jf._generate(synthetic_parsed(names), seed)

    def test_single_function_engine_structure(self):
        runtime, coverage = self.generate(["core"])
        self.assert_engine_structure(runtime, coverage)

    def test_multi_function_engine_structure(self):
        runtime, coverage = self.generate(["core", "helper", "aux"])
        self.assert_engine_structure(runtime, coverage)
        self.assertEqual(coverage["runtime_hardening"]["engine_count"], 3)

    def test_pure_runtime_keeps_entry_and_wrapper_seams(self):
        runtime, _ = self.generate(["core", "helper"])
        self.assertIn("function _ar_enter(identifier, args) {", runtime)
        self.assertIn("return exported;", runtime)
        self.assertIn("return _ar_enter(0, [x]);", runtime)

    def test_generated_runtime_substitutes_every_placeholder(self):
        runtime, _ = self.generate(["core", "helper"])
        self.assertEqual(re.findall(r"@[A-Za-z_]+@", runtime), [])


class MixedEmittedSourceTests(_EmittedSourceChecks, unittest.TestCase):
    variant = "mixed"

    def generate(self, names, seed=20261021):
        template = (jmm.MIXED_TOOLS / "runtime.mixed.cjs.in").read_text(encoding="utf-8")
        runtime, coverage, _ = jmm._encode_program(synthetic_parsed(names), seed, template)
        return runtime, coverage

    def test_single_function_engine_structure(self):
        runtime, coverage = self.generate(["core"])
        self.assert_engine_structure(runtime, coverage)

    def test_multi_function_engine_structure(self):
        runtime, coverage = self.generate(["core", "helper", "aux"])
        self.assert_engine_structure(runtime, coverage)
        self.assertEqual(coverage["runtime_hardening"]["engine_count"], 3)

    def test_mixed_keeps_hoisted_factory_and_per_engine_rebinding_guard(self):
        runtime, coverage = self.generate(["core", "helper"])
        self.assertIn("function _arm_factory()", runtime)
        self.assertIn("const registered = getters.map(", runtime)
        self.assertIn("function enter(identifier, args) {", runtime)
        # Every engine's call handler re-checks the live helper binding identity.
        self.assertEqual(runtime.count("getters[current[1]]() !== registered[current[1]]"),
                         coverage["runtime_hardening"]["engine_count"])

    def test_mixed_runtime_substitutes_every_placeholder(self):
        runtime, _ = self.generate(["core", "helper"])
        self.assertEqual(re.findall(r"@[A-Za-z_]+@", runtime), [])


if __name__ == "__main__":
    unittest.main()
