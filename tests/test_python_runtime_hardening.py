"""Structure/metadata tests for the per-function flattened Python VM engines.

These tests check the flattening plan, the actually emitted engine source and the
``runtime_hardening`` coverage block -- not program outcomes, which the shared
semantics suite owns. They parse the generated module text statically with
``ast`` and never import, compile or run a generated target. The reviewed harness
runs them; this lane reports them as NOT RUN.
"""
import ast
import unittest
from unittest import mock

from antirea import python_frontend as pf
from antirea import python_mixed_module as mixed
from antirea import python_runtime_hardening as prh


TWO = "def helper(x):\n    return x * 3\ndef core(x):\n    return helper(x) + 1\n"
SEED = 20261021


def pure_runtime(source, roots, seed=SEED):
    runtime, coverage, inspection, used = pf._generate(source, roots, seed)
    return runtime, coverage, ast.parse(runtime)


def function_defs(tree):
    return {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}


def int_constants(node):
    return {child.value for child in ast.walk(node)
            if isinstance(child, ast.Constant) and isinstance(child.value, int)
            and not isinstance(child.value, bool)}


class EnginePlanTests(unittest.TestCase):
    def test_plan_is_deterministic_per_seed_and_identifier(self):
        for seed in (0, 1, SEED, (1 << 256) - 1):
            for identifier in range(5):
                self.assertEqual(prh.engine_plan(seed, identifier),
                                 prh.engine_plan(seed, identifier))

    def test_states_mask_and_handler_order_invariants(self):
        for seed in (0, 7, SEED):
            for identifier in range(6):
                plan = prh.engine_plan(seed, identifier)
                states = (plan["fetch"], plan["execute"], plan["return"])
                self.assertEqual(len(set(states)), 3, "states must be mutually distinct")
                for value in states:
                    self.assertTrue(1 <= value <= prh.MASK)
                self.assertTrue(1 <= plan["mask"] <= prh.MASK, "mask must be nonzero and 30-bit")
                order = plan["handler_order"]
                self.assertEqual(sorted(order), list(range(16)), "all 16 opcodes exactly once")
                # Canonical paired groups stay adjacent in canonical within-pair order.
                self.assertEqual(order.index(7) - order.index(5), 1)
                self.assertEqual(order.index(12) - order.index(11), 1)

    def test_distinct_identifiers_get_distinct_structure(self):
        plans = [prh.engine_plan(SEED, identifier) for identifier in range(8)]
        signatures = {(p["fetch"], p["execute"], p["return"], p["mask"]) for p in plans}
        self.assertEqual(len(signatures), 8, "each engine must have a distinct state signature")

    def test_seed_change_changes_plan(self):
        self.assertNotEqual(prh.engine_plan(1, 0), prh.engine_plan(2, 0))

    def test_rejects_out_of_range_seed_or_identifier(self):
        for bad in (-1, 1 << 256, True, 1.0):
            with self.assertRaises(ValueError):
                prh.engine_plan(bad, 0)
        for bad in (-1, 1 << 32, True):
            with self.assertRaises(ValueError):
                prh.engine_plan(0, bad)


class PureEmittedEngineTests(unittest.TestCase):
    def test_each_function_has_its_own_engine_and_dispatch_table(self):
        runtime, coverage, tree = pure_runtime(TWO, ["core"])
        defs = function_defs(tree)
        engines = sorted(name for name in defs if name.startswith("_ar_engine_"))
        self.assertEqual(engines, ["_ar_engine_0", "_ar_engine_1"])
        dispatch = [node for node in tree.body
                    if isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id == "_ar_dispatch"]
        self.assertEqual(len(dispatch), 1, "exactly one dispatch table")
        self.assertIsInstance(dispatch[0].value, ast.Tuple)
        names = [element.id for element in dispatch[0].value.elts if isinstance(element, ast.Name)]
        self.assertEqual(names, ["_ar_engine_0", "_ar_engine_1"])

    def test_ar_invoke_is_forwarding_seam_without_opcode_dispatch(self):
        runtime, coverage, tree = pure_runtime(TWO, ["core"])
        invoke = function_defs(tree)["_ar_invoke"]
        self.assertFalse(any(isinstance(node, (ast.While, ast.For)) for node in ast.walk(invoke)),
                         "forwarding seam must not loop")
        name_calls = [node.func.id for node in ast.walk(invoke)
                      if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
        self.assertNotIn("_ar_fetch", name_calls, "seam must not decode instructions")
        subscripts = [node.value.id for node in ast.walk(invoke)
                      if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name)]
        self.assertIn("_ar_dispatch", subscripts, "seam forwards through the dispatch table")
        # The seam must not itself compare an opcode against per-function tokens.
        self.assertNotIn("tokens", {name.id for name in ast.walk(invoke) if isinstance(name, ast.Name)})

    def test_engines_are_flattened_state_machines_over_the_shared_decoder(self):
        runtime, coverage, tree = pure_runtime(TWO, ["core"])
        defs = function_defs(tree)
        for identifier in (0, 1):
            engine = defs["_ar_engine_%d" % identifier]
            self.assertTrue(any(isinstance(node, ast.While) for node in ast.walk(engine)),
                            "each engine is a dispatch loop")
            name_calls = [node.func.id for node in ast.walk(engine)
                          if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
            self.assertIn("_ar_fetch", name_calls, "engine uses the shared current-instruction decoder")
            self.assertTrue(any(isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitXor)
                                for node in ast.walk(engine)),
                            "encoded state flow uses an xor-masked transition")

    def test_no_eval_exec_cache_or_original_bodies_are_emitted(self):
        source = ("def secret_helper(x):\n    secret_local = x * 777\n    return secret_local\n"
                  "def core(x):\n    return secret_helper(x)\n")
        runtime, coverage, tree = pure_runtime(source, ["core"])
        for forbidden in ("secret_helper", "secret_local", "x * 777", "_ar_plain", "_ar_program"):
            self.assertNotIn(forbidden, runtime)
        name_calls = {node.func.id for node in ast.walk(tree)
                      if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        self.assertTrue({"eval", "exec", "compile", "__import__"}.isdisjoint(name_calls))
        self.assertIs(coverage["original_selected_bodies_in_protected_artifact"], False)

    def test_generated_runtime_is_deterministic_and_seed_sensitive(self):
        first = pf._generate(TWO, ["core"], 17)[0]
        again = pf._generate(TWO, ["core"], 17)[0]
        other = pf._generate(TWO, ["core"], 18)[0]
        self.assertEqual(first, again)
        self.assertNotEqual(first, other)


class RuntimeHardeningCoverageTests(unittest.TestCase):
    def test_dispatcher_label_and_runtime_hardening_block(self):
        runtime, coverage, tree = pure_runtime(TWO, ["core"])
        self.assertEqual(coverage["dispatcher"], "per_function_flattened_indirect_dispatch")
        hardening = coverage["runtime_hardening"]
        self.assertEqual(hardening["schema_version"], 1)
        self.assertEqual(hardening["profile"], "per_function_flattened_dispatch_v1")
        self.assertEqual(hardening["stage"], "generated_source")
        self.assertEqual(hardening["engine_count"], 2)
        self.assertEqual(hardening["dispatch_table_symbol"], "_ar_dispatch")
        self.assertIs(hardening["shared_fetch_and_operator_helpers"], True)
        self.assertIs(hardening["kagura_passes_applied"], False)
        self.assertEqual(hardening["external_resistance"], "not_evaluated")
        self.assertEqual([engine["vm_function_id"] for engine in hardening["engines"]], [0, 1])

    def test_engine_metadata_matches_emitted_symbols_and_is_distinct(self):
        runtime, coverage, tree = pure_runtime(TWO, ["core"])
        defs = function_defs(tree)
        signatures = set()
        for engine in coverage["runtime_hardening"]["engines"]:
            self.assertIn(engine["symbol"], defs)
            self.assertEqual(engine["symbol"], "_ar_engine_%d" % engine["vm_function_id"])
            states = engine["state_ids"]
            values = (states["fetch"], states["execute"], states["return"])
            self.assertEqual(len(set(values)), 3)
            for value in values:
                self.assertTrue(1 <= value <= prh.MASK)
            self.assertTrue(1 <= engine["state_mask"] <= prh.MASK)
            self.assertEqual(sorted(engine["handler_order"]), list(range(16)))
            self.assertEqual(engine["handler_order"].index(7) - engine["handler_order"].index(5), 1)
            self.assertEqual(engine["handler_order"].index(12) - engine["handler_order"].index(11), 1)
            signatures.add((*values, engine["state_mask"]))
        self.assertEqual(len(signatures), 2, "every engine has a distinct state signature")

    def test_reported_state_ids_and_mask_appear_in_the_engine_source(self):
        runtime, coverage, tree = pure_runtime(TWO, ["core"])
        defs = function_defs(tree)
        for engine in coverage["runtime_hardening"]["engines"]:
            constants = int_constants(defs[engine["symbol"]])
            for key in ("fetch", "execute", "return"):
                self.assertIn(engine["state_ids"][key], constants,
                              "reported %s id must be a real literal in the engine" % key)
            self.assertIn(engine["state_mask"], constants)


class MixedEmittedEngineTests(unittest.TestCase):
    def test_mixed_rewrites_rebinding_guards_in_every_engine(self):
        source = ("import math\n"
                  "def helper(x):\n    return x * 3\n"
                  "def core(x):\n    n = 0\n    for i in range(x):\n"
                  "        n += helper(i)\n    return n\n")
        protected, coverage, inspection, seed = mixed._generate(source, ["core"], SEED)
        tree = ast.parse(protected)
        engines = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
                   and node.name.startswith("_ar_engine_")]
        self.assertEqual(len(engines), 2)
        arm_calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                     and isinstance(node.func, ast.Name) and node.func.id == "_arm_call"]
        self.assertEqual(len(arm_calls), 2, "helper rebinding guard rewritten once per engine")
        arm_builtins = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name) and node.func.id == "_arm_builtin"]
        self.assertEqual(len(arm_builtins), 4, "builtin and range guards rewritten once per engine")
        # No leftover unguarded helper/table/range forwarding inside the engines.
        self.assertNotIn("_ar_invoke(instruction[1]", protected)
        self.assertNotIn("_ar_builtins_table[instruction[1]]", protected)

    def test_mixed_count_adaptation_is_fail_closed_on_shape_change(self):
        # A per-engine guard site that the adapter cannot recognise must abort the
        # build rather than silently drop a reached-call rebinding check.
        source = "def core(x):\n    return x + 1\n"
        original = prh.render_engine

        def broken(identifier, plan):
            return original(identifier, plan).replace(
                "_ar_invoke(instruction[1], arguments)", "_ar_invoke(0, arguments)")

        with mock.patch.object(prh, "render_engine", broken):
            with self.assertRaisesRegex(mixed.MixedModuleError, "adapter shape changed"):
                mixed._generate(source, ["core"], SEED)


if __name__ == "__main__":
    unittest.main()
