"""Phase23 STRUCTURAL evidence lane: verify the per-function flattened script VM
against ACTUAL emitted source, not coverage metadata alone.

Scope (defender structural-review lane; owns only this file and
.runs/phase23-workers/evidence/README.md). Reconciled to the landed
``antirea.python_runtime_hardening`` and ``antirea.javascript_runtime_hardening``
generators.

Method:

* Python pure (``antirea.python_frontend._generate``) and Python mixed
  (``antirea.python_mixed_module._generate``) produce runtime SOURCE TEXT by pure
  string / AST assembly -- no subprocess, no compiler, no target execution. These
  tests generate in-process and inspect the emitted module with the standard
  ``ast`` library: real per-function engines (``_ar_engine_<id>``), the indirect
  dispatch table (``_ar_dispatch``), the ``_ar_invoke`` forwarding seam (no opcode
  loop), live encoded transitions (state ids + mask literals reassigned inside the
  loop), the complete permuted ``tokens[k]`` handler set, fail-closed invalid-state
  branches, thin wrappers (no original body), and no eval/exec/program cache. Mixed
  additionally proves the reached helper/builtin/range rebinding guards were
  applied to EVERY engine.

* JavaScript and TypeScript, pure and mixed, are generated as owned fixtures
  THROUGH the production frontends (``javascript_frontend.build_project`` and
  ``javascript_mixed_module.build_project``), which invoke the pinned parser. The
  emitted ``protected.cjs`` is then grounded (engines ``_ar_engine_<id>`` /
  ``_arm_engine_<id>``, dispatch table ``_ar_dispatch`` / ``_arm_dispatch``,
  ``switch (state)`` with 30-bit masked transitions, every opcode handled, state
  id/mask literals, per-engine mixed helper-rebinding guard, no eval/Function). The
  only child process is the frontend's pinned parser; these tests never execute a
  generated target. They SKIP only when the pinned toolchain is genuinely absent
  (the standard repo-wide pattern), never behind a bespoke opt-in.

These tests are authored for ROOT's bounded shared harness and are reported NOT
RUN by this worker: this worker executes no test, compiler, or generated target.

Nothing here reads, hashes, copies or inventories any path component named
env.setting, LINKREPRO, attackerfolder or rea-analysis-reports.
"""
import ast
import json
import re
import tempfile
import unittest
from pathlib import Path

from antirea import python_frontend as pf
from antirea import python_mixed_module as pmm
from antirea import javascript_frontend as jf
from antirea import javascript_mixed_module as jmm
from js_mixed_support import build_sample

# ---------------------------------------------------------------------------
# Fixed contract constants (see .runs/phase23-root/brief.md).
# ---------------------------------------------------------------------------
PY_OPCODES = 16
PY_PAIRS = ((5, 7), (11, 12))          # binary/compare, call/builtin
JS_OPCODES = 17
JS_PAIRS = ((14, 15),)                 # call/builtin
RUNTIME_PROFILE = "per_function_flattened_dispatch_v1"
DISPATCH_COVERAGE_VALUE = "per_function_flattened_indirect_dispatch"
STATE_BITS = 30
STATE_LIMIT = 1 << STATE_BITS          # 30-bit domain; mask constant is 2**30-1

REPO_ROOT = Path(__file__).resolve().parents[1]
JS_TOOLS = REPO_ROOT / "tools" / "javascript_frontend"
SAMPLE_JS_MIXED = REPO_ROOT / "samples" / "multilang" / "javascript_mixed"
SAMPLE_TS_MIXED = REPO_ROOT / "samples" / "multilang" / "typescript_mixed"

# Owned Python fixtures: two protected functions (root + leaf helper) so engine
# distinctness and seed diversity are observable (N == 2).
PY_SOURCE = (
    "def leaf(x):\n"
    "    acc = x + 3\n"
    "    if acc > 10:\n"
    "        acc = acc - 2\n"
    "    return acc\n"
    "\n"
    "def root(n, k):\n"
    "    total = 0\n"
    "    for i in range(n):\n"
    "        total = total + leaf(k)\n"
    "    return total\n"
)
PY_SELECTED = ["root", "leaf"]

# Dynamic-execution / network constructs that must never appear in generated JS.
JS_FORBIDDEN = [
    r"\beval\s*\(",
    r"\bnew\s+Function\s*\(",
    r"(?<![.\w])Function\s*\(",
    r"require\(\s*['\"]vm['\"]\s*\)",
    r"\brunInContext\b",
    r"\brunInNewContext\b",
    r"\brunInThisContext\b",
    r"require\(\s*['\"]child_process['\"]\s*\)",
    r"\bexecSync\b",
    r"\bspawnSync\b",
    r"require\(\s*['\"](?:https?|net|dgram|dns|tls)['\"]\s*\)",
    r"(?<![.\w])import\s*\(",
]


# ---------------------------------------------------------------------------
# Shared metadata helpers.
# ---------------------------------------------------------------------------
def assert_permuted_handlers(tc, order, opcode_count, pairs):
    tc.assertIsInstance(order, list, "handler_order must be a list")
    tc.assertEqual(sorted(order), list(range(opcode_count)),
                   "handler_order must list every opcode index exactly once")
    pos = {op: i for i, op in enumerate(order)}
    for a, b in pairs:
        tc.assertEqual(abs(pos[a] - pos[b]), 1,
                       "canonical paired opcodes %d/%d must remain adjacent" % (a, b))


def assert_runtime_hardening_schema(tc, coverage, opcode_count, pairs):
    tc.assertEqual(coverage.get("dispatcher"), DISPATCH_COVERAGE_VALUE,
                   "coverage dispatcher must be %r" % DISPATCH_COVERAGE_VALUE)
    rh = coverage.get("runtime_hardening")
    tc.assertIsInstance(rh, dict, "coverage must carry a runtime_hardening block")
    tc.assertEqual(rh.get("schema_version"), 1)
    tc.assertEqual(rh.get("profile"), RUNTIME_PROFILE)
    tc.assertEqual(rh.get("stage"), "generated_source")
    tc.assertIs(rh.get("shared_fetch_and_operator_helpers"), True)
    tc.assertIs(rh.get("kagura_passes_applied"), False)
    tc.assertEqual(rh.get("external_resistance"), "not_evaluated")

    engines = rh.get("engines")
    tc.assertIsInstance(engines, list)
    n = rh.get("engine_count")
    tc.assertEqual(n, len(engines), "engine_count must equal len(engines)")
    tc.assertEqual(n, coverage.get("codec_count"),
                   "engine_count must equal the protected-function count")
    tc.assertGreaterEqual(n, 1)

    dts = rh.get("dispatch_table_symbol")
    tc.assertTrue(isinstance(dts, str) and dts.isidentifier(),
                  "dispatch_table_symbol must be a real identifier")

    tc.assertEqual(sorted(e["vm_function_id"] for e in engines), list(range(n)),
                   "vm ids must cover 0..N-1 exactly, each once")
    symbols, state_tuples = [], []
    for e in engines:
        sym = e.get("symbol")
        tc.assertTrue(isinstance(sym, str) and sym.isidentifier(),
                      "engine symbol must be a real identifier")
        symbols.append(sym)
        states = e.get("state_ids")
        tc.assertIsInstance(states, dict)
        tc.assertEqual(set(states), {"fetch", "execute", "return"})
        values = [states["fetch"], states["execute"], states["return"]]
        for v in values:
            tc.assertIs(type(v), int, "state id must be a plain int (not bool)")
            tc.assertTrue(0 < v < STATE_LIMIT, "state id must be nonzero and inside 30 bits")
        tc.assertEqual(len(set(values)), 3, "fetch/execute/return must be distinct")
        mask = e.get("state_mask")
        tc.assertIs(type(mask), int)
        tc.assertTrue(0 < mask < STATE_LIMIT, "state_mask must be nonzero and 30-bit")
        assert_permuted_handlers(tc, e.get("handler_order"), opcode_count, pairs)
        state_tuples.append(tuple(values) + (mask,))

    tc.assertEqual(len(set(symbols)), n, "every engine must have a distinct symbol")
    tc.assertEqual(len(set(state_tuples)), n,
                   "every engine must have a distinct state set (no shared/aliased engine)")
    return rh


# ---------------------------------------------------------------------------
# Python AST grounding helpers.
# ---------------------------------------------------------------------------
def funcdefs(tree):
    return {node.name: node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)}


def module_assign_value(tree, name):
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name):
            return node.value
    return None


def literal_named(tree, name):
    value = module_assign_value(tree, name)
    return None if value is None else ast.literal_eval(value)


def table_mapping(value_node):
    if isinstance(value_node, (ast.List, ast.Tuple)):
        out = {}
        for index, element in enumerate(value_node.elts):
            if not isinstance(element, ast.Name):
                return None
            out[index] = element.id
        return out
    if isinstance(value_node, ast.Dict):
        out = {}
        for key, element in zip(value_node.keys, value_node.values):
            if (not isinstance(key, ast.Constant) or type(key.value) is not int
                    or not isinstance(element, ast.Name)):
                return None
            out[key.value] = element.id
        return out
    return None


def int_consts(node):
    return {c.value for c in ast.walk(node)
            if isinstance(c, ast.Constant) and type(c.value) is int}


def token_indices(node):
    out = set()
    for sub in ast.walk(node):
        if (isinstance(sub, ast.Subscript) and isinstance(sub.value, ast.Name)
                and sub.value.id == "tokens" and isinstance(sub.slice, ast.Constant)
                and type(sub.slice.value) is int):
            out.add(sub.slice.value)
    return out


def calls_fetch(node):
    for call in ast.walk(node):
        if not isinstance(call, ast.Call):
            continue
        func = call.func
        if isinstance(func, ast.Name) and "fetch" in func.id.lower():
            return True
        if isinstance(func, ast.Attribute) and "fetch" in func.attr.lower():
            return True
    return False


def assert_no_dynamic_exec_python(tc, tree):
    banned = {"eval", "exec", "compile", "__import__"}
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call):
            continue
        func = call.func
        if isinstance(func, ast.Name):
            tc.assertNotIn(func.id, banned, "generated runtime must not call %s" % func.id)
        if isinstance(func, ast.Attribute):
            tc.assertNotIn(func.attr, {"eval", "exec", "compile"},
                           "generated runtime must not call .%s" % func.attr)


def ground_python_runtime(tc, source, coverage, *, seam, entry, wrapper_names):
    tree = ast.parse(source.removeprefix("﻿"))
    rh = coverage["runtime_hardening"]
    funcs = funcdefs(tree)
    meta = literal_named(tree, "_ar_functions")
    tc.assertIsInstance(meta, list, "emitted _ar_functions metadata literal required")
    id_to_symbol = {e["vm_function_id"]: e["symbol"] for e in rh["engines"]}

    # (1) Separate, real engines.
    for symbol in id_to_symbol.values():
        tc.assertIn(symbol, funcs,
                    "engine %r claimed in metadata but not defined in emitted source" % symbol)

    # (2) Correct table routing.
    table_value = module_assign_value(tree, rh["dispatch_table_symbol"])
    tc.assertIsNotNone(table_value, "dispatch table symbol not assigned in emitted source")
    mapping = table_mapping(table_value)
    if mapping is not None:
        tc.assertEqual(mapping, id_to_symbol,
                       "dispatch table must map each vm id to its own engine function")
    else:
        referenced = {n.id for n in ast.walk(table_value) if isinstance(n, ast.Name)}
        for symbol in id_to_symbol.values():
            tc.assertIn(symbol, referenced, "every engine must be referenced by the dispatch table")

    # (3) Forwarding seam only.
    tc.assertIn(seam, funcs, "forwarding seam %r must remain" % seam)
    seam_node = funcs[seam]
    seam_names = {n.id for n in ast.walk(seam_node) if isinstance(n, ast.Name)}
    tc.assertIn(rh["dispatch_table_symbol"], seam_names, "seam must forward through the dispatch table")
    tc.assertFalse(any(isinstance(n, ast.While) for n in ast.walk(seam_node)),
                   "seam must not implement an opcode dispatch loop")
    tc.assertNotIn("_ar_operator", seam_names,
                   "seam must not apply operators -- dispatch belongs in the engines")

    # (4) Per-engine handlers, encoded live state flow, fail-closed state branch.
    for engine in rh["engines"]:
        symbol = engine["symbol"]
        node = funcs[symbol]
        consts = int_consts(node)
        states = engine["state_ids"]
        for key in ("fetch", "execute", "return"):
            tc.assertIn(states[key], consts,
                        "%s: %s state id must appear as a literal in the engine body" % (symbol, key))
        tc.assertIn(engine["state_mask"], consts, "%s: state_mask must appear in the engine body" % symbol)
        whiles = [w for w in ast.walk(node) if isinstance(w, ast.While)]
        tc.assertTrue(whiles, "%s: flattened engine must contain a dispatch loop" % symbol)
        # Live transition: the state variable is reassigned inside the loop.
        in_loop_state_assign = any(
            isinstance(a, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "state" for t in a.targets)
            for w in whiles for a in ast.walk(w))
        tc.assertTrue(in_loop_state_assign, "%s: engine must reassign state inside the loop" % symbol)
        # Fail-closed invalid-state branch.
        tc.assertIn("Invalid VM state", ast.unparse(node),
                    "%s: engine must have a fail-closed invalid-state branch" % symbol)
        tc.assertTrue(any(calls_fetch(w) for w in whiles),
                      "%s: engine must decode the current instruction inside the loop" % symbol)
        # Complete handler set grounded in THIS engine's source: every opcode
        # indexed, and in exactly the permuted order the metadata claims.
        tc.assertEqual(token_indices(node), set(range(PY_OPCODES)),
                       "%s: engine must dispatch on every opcode via tokens[k]" % symbol)
        seen = []
        for raw in re.findall(r"tokens\[(\d+)\]", ast.unparse(node)):
            value = int(raw)
            if value not in seen:
                seen.append(value)
        tc.assertEqual(seen, engine["handler_order"],
                       "%s: emitted handler order must equal metadata handler_order" % symbol)

    # (5) No original bodies.
    for name in wrapper_names:
        if name in funcs:
            body = funcs[name].body
            tc.assertEqual(len(body), 1, "wrapper %r must carry no original body" % name)
            tc.assertIsInstance(body[0], ast.Return)
            call = body[0].value
            tc.assertIsInstance(call, ast.Call)
            tc.assertIsInstance(call.func, ast.Name)
            tc.assertIn(call.func.id, {entry, "_ar_enter", "_arm_enter"},
                        "wrapper %r must forward to the VM entry seam" % name)

    # (6) No dynamic execution / program cache.
    assert_no_dynamic_exec_python(tc, tree)
    tc.assertIs(coverage.get("decoded_instruction_cache"), False)
    tc.assertEqual(coverage.get("decode_scope"), "current_instruction")
    return tree, funcs


# ---------------------------------------------------------------------------
# JavaScript/TypeScript source grounding (regex over emitted protected.cjs).
# ---------------------------------------------------------------------------
def js_engine_bodies(tc, protected, symbols, table_symbol):
    """Slice each named engine's own source body out of the emitted JS.

    The generator emits engines in vm-id order, each ``function <symbol>(args)``,
    followed by ``const <table> = [...]``; relying on that fixed formatting, each
    engine body runs from its own anchor up to the next engine (or the table).
    """
    positions = []
    for symbol in symbols:
        anchor = "function %s(args)" % symbol
        idx = protected.find(anchor)
        tc.assertNotEqual(idx, -1, "engine anchor %r not found in emitted JS" % anchor)
        positions.append(idx)
    table_idx = protected.find("const %s" % table_symbol)
    tc.assertNotEqual(table_idx, -1, "dispatch table %r not found in emitted JS" % table_symbol)
    boundaries = positions[1:] + [table_idx]
    bodies = {}
    for symbol, start, end in zip(symbols, positions, boundaries):
        tc.assertLess(start, end, "engines must appear in vm-id order before the dispatch table")
        bodies[symbol] = protected[start:end]
    return bodies


def ground_js_source(tc, protected, coverage, *, opcode_count, pairs, mixed):
    rh = assert_runtime_hardening_schema(tc, coverage, opcode_count, pairs)
    for pattern in JS_FORBIDDEN:
        tc.assertIsNone(re.search(pattern, protected), "protected JS must not contain %r" % pattern)
    tc.assertIs(coverage.get("original_selected_bodies_in_protected_artifact"), False)
    tc.assertIs(coverage.get("decoded_instruction_cache"), False)
    tc.assertEqual(coverage.get("decode_scope"), "current_instruction")
    tc.assertIn("switch (state)", protected, "flattened engines must switch on the encoded state")
    tc.assertRegex(protected, r"&\s*1073741823\b", "30-bit masked state transitions expected")

    table_symbol = rh["dispatch_table_symbol"]
    engines = sorted(rh["engines"], key=lambda e: e["vm_function_id"])
    symbols = [e["symbol"] for e in engines]

    # Dispatch-table member order must match vm-id order.
    table = re.search(r"const\s+%s\s*=\s*\[([^\]]*)\]" % re.escape(table_symbol), protected)
    tc.assertIsNotNone(table, "dispatch table declaration not found in emitted JS")
    members = [m.strip() for m in table.group(1).split(",") if m.strip()]
    tc.assertEqual(members, symbols, "dispatch table must list engines in vm-id order")

    # invoke seam forwards only: range-check + table[id](args); no opcode dispatch.
    invoke_at = protected.find("function invoke(")
    tc.assertNotEqual(invoke_at, -1, "forwarding invoke seam not found in emitted JS")
    open_brace = protected.index("{", invoke_at)
    invoke_body = protected[invoke_at:protected.index("}", open_brace) + 1]
    tc.assertIn("%s[identifier](args)" % table_symbol, invoke_body,
                "invoke must forward through the dispatch table")
    tc.assertNotIn("switch", invoke_body, "invoke seam must not contain an opcode switch")
    tc.assertNotIn("tokens[", invoke_body, "invoke seam must not perform opcode dispatch")

    # Per-engine grounding: each engine's OWN body carries its full handler order,
    # its own state/mask literals, and (mixed) its own rebinding guard. Checking
    # each body in isolation prevents one correct engine masking another's gap.
    bodies = js_engine_bodies(tc, protected, symbols, table_symbol)
    for engine in engines:
        symbol = engine["symbol"]
        body = bodies[symbol]
        order = [int(m) for m in re.findall(r"tokens\[(\d+)\]", body)]
        tc.assertEqual(order, engine["handler_order"],
                       "%s: emitted case-token order must equal this engine's handler_order" % symbol)
        for value in (engine["state_ids"]["fetch"], engine["state_ids"]["execute"],
                      engine["state_ids"]["return"], engine["state_mask"]):
            tc.assertRegex(body, r"(?<![\w.])%d\b" % value,
                           "%s: own state/mask literal %d must appear in this engine body" % (symbol, value))
        if mixed:
            tc.assertEqual(body.count("unsupported helper rebinding"), 1,
                           "%s: mixed engine must carry exactly one per-engine rebinding guard" % symbol)
    return rh


# ---------------------------------------------------------------------------
# Opcode-layout guards.
# ---------------------------------------------------------------------------
class OpcodeContractGuards(unittest.TestCase):
    def test_python_opcode_layout(self):
        self.assertEqual(len(pf._OPS), PY_OPCODES)
        self.assertEqual((pf._OPS[5], pf._OPS[7]), ("binary", "compare"))
        self.assertEqual((pf._OPS[11], pf._OPS[12]), ("call", "builtin"))

    def test_javascript_opcode_layout(self):
        self.assertEqual(len(jf.OPS), JS_OPCODES)
        self.assertEqual((jf.OPS[14], jf.OPS[15]), ("call", "builtin"))


# ---------------------------------------------------------------------------
# Python PURE route (generated in-process; pure, no subprocess/target).
# ---------------------------------------------------------------------------
class PythonPureRuntimeHardening(unittest.TestCase):
    SEED = 0x51A1B2C3D4E5F6071213141516171819

    def _generate(self, seed=None):
        runtime, coverage, _inspection, _used = pf._generate(
            PY_SOURCE, list(PY_SELECTED), self.SEED if seed is None else seed)
        return runtime, coverage

    def test_runtime_hardening_block_valid(self):
        _runtime, coverage = self._generate()
        assert_runtime_hardening_schema(self, coverage, PY_OPCODES, PY_PAIRS)

    def test_metadata_grounded_in_emitted_source(self):
        runtime, coverage = self._generate()
        assert_runtime_hardening_schema(self, coverage, PY_OPCODES, PY_PAIRS)
        ground_python_runtime(self, runtime, coverage,
                              seam="_ar_invoke", entry="_ar_enter", wrapper_names=PY_SELECTED)

    def test_two_engines_for_two_functions(self):
        _runtime, coverage = self._generate()
        self.assertEqual(coverage["runtime_hardening"]["engine_count"], 2)

    def test_deterministic_for_same_seed(self):
        a_runtime, a_cov = self._generate(seed=self.SEED)
        b_runtime, b_cov = self._generate(seed=self.SEED)
        self.assertEqual(a_runtime, b_runtime, "same seed/source must be byte-identical")
        self.assertEqual(a_cov["runtime_hardening"], b_cov["runtime_hardening"])

    def test_seed_diversifies_engines(self):
        _r1, cov1 = self._generate(seed=1)
        _r2, cov2 = self._generate(seed=2)

        def signature(cov):
            return [(tuple(sorted(e["state_ids"].items())), e["state_mask"], tuple(e["handler_order"]))
                    for e in cov["runtime_hardening"]["engines"]]

        self.assertNotEqual(signature(cov1), signature(cov2),
                            "different seeds must diversify engine states/handler order")


# ---------------------------------------------------------------------------
# Python MIXED-MODULE route.
# ---------------------------------------------------------------------------
class PythonMixedRuntimeHardening(unittest.TestCase):
    SEED = 0x1A2B3C4D5E6F70818283848586878889

    def _generate(self, seed=None):
        try:
            protected, coverage, _inspection, _used = pmm._generate(
                PY_SOURCE, list(PY_SELECTED), self.SEED if seed is None else seed)
        except pmm.MixedModuleError as exc:
            self.fail("mixed adapter rejected the generated runtime (expected the helper/builtin/range "
                      "rewrites to adapt to N engines, fail-closed): %s" % exc)
        return protected, coverage

    def test_runtime_hardening_propagated(self):
        _protected, coverage = self._generate()
        assert_runtime_hardening_schema(self, coverage, PY_OPCODES, PY_PAIRS)
        self.assertEqual(coverage.get("helper_binding"), "identity_checked_at_reached_call")
        self.assertEqual(coverage.get("builtin_binding"), "identity_checked_at_reached_call")

    def test_metadata_grounded_in_emitted_mixed_source(self):
        protected, coverage = self._generate()
        assert_runtime_hardening_schema(self, coverage, PY_OPCODES, PY_PAIRS)
        ground_python_runtime(self, protected, coverage,
                              seam="_ar_invoke", entry="_arm_enter", wrapper_names=PY_SELECTED)

    def test_rebinding_guards_applied_to_every_engine(self):
        protected, _coverage = self._generate()
        tree = ast.parse(protected.removeprefix("﻿"))
        defined = funcdefs(tree)
        for guard in ("_arm_call", "_arm_builtin", "_arm_register"):
            self.assertIn(guard, defined, "mixed guard %r must be present" % guard)

        residual_helper = residual_builtin = residual_range = 0
        used_arm_call = used_arm_builtin = 0
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call):
                continue
            func = call.func
            if (isinstance(func, ast.Name) and func.id == "_ar_invoke" and call.args
                    and isinstance(call.args[0], ast.Subscript)
                    and isinstance(call.args[0].value, ast.Name)
                    and call.args[0].value.id == "instruction"):
                residual_helper += 1
            if isinstance(func, ast.Subscript) and isinstance(func.value, ast.Name) \
                    and func.value.id == "_ar_builtins_table":
                residual_builtin += 1
            if (isinstance(func, ast.Attribute) and func.attr == "range"
                    and isinstance(func.value, ast.Name) and func.value.id == "_ar_builtins"
                    and any(isinstance(a, ast.Starred) for a in call.args)):
                residual_range += 1
            if isinstance(func, ast.Name) and func.id == "_arm_call":
                used_arm_call += 1
            if isinstance(func, ast.Name) and func.id == "_arm_builtin":
                used_arm_builtin += 1

        self.assertEqual(residual_helper, 0,
                         "every engine's helper call site must be rewritten to _arm_call")
        self.assertEqual(residual_builtin, 0,
                         "every engine's builtin call site must be rewritten to _arm_builtin")
        self.assertEqual(residual_range, 0,
                         "every engine's range call site must be rewritten to _arm_builtin")
        # One guarded helper + one guarded builtin + one guarded range per engine.
        n = _coverage["runtime_hardening"]["engine_count"]
        self.assertEqual(used_arm_call, n, "each engine's helper call must be guarded")
        self.assertEqual(used_arm_builtin, 2 * n, "each engine's builtin and range calls must be guarded")


# ---------------------------------------------------------------------------
# JavaScript / TypeScript generated-source evidence (pure + mixed).
#
# Owned fixtures are built THROUGH the production frontends, which invoke the
# pinned parser. This worker never runs these; they run under root's bounded
# suite. They SKIP only when the pinned toolchain is absent (standard pattern).
# ---------------------------------------------------------------------------
class JavaScriptGeneratedSourceEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Only the expected tool-unavailable signal skips; JavaScriptFrontendError
        # and MixedModuleError are ValueError subclasses. Programming errors
        # (AttributeError, TypeError, ...) must fail, never skip.
        try:
            jf.discover_toolchain()
            jmm.discover_toolchain()
        except ValueError as exc:
            raise unittest.SkipTest("pinned JS/TS toolchain unavailable: %s" % exc)

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.root = Path(self._t.name)
        self.index = 0

    def _build_pure(self, source, functions, language):
        self.index += 1
        directory = self.root / ("pure-src-%d" % self.index)
        directory.mkdir()
        suffix = ".ts" if language == "typescript" else ".js"
        (directory / ("core" + suffix)).write_text(source, encoding="utf-8")
        project = directory / "project.json"
        project.write_text(json.dumps({"schema_version": 1, "name": "owned", "language": language,
                                       "sources": ["core" + suffix], "functions": functions}),
                           encoding="utf-8")
        output = self.root / ".runs" / ("pure-out-%d" % self.index)
        build = jf.build_project(project, output, workspace_root=self.root, seed=20261020)
        self.assertEqual(build["status"], "artifact_created_unvalidated", build)
        protected = Path(build["protected"]).read_text(encoding="utf-8")
        return build["coverage"], protected

    def _build_mixed(self, sample_dir, files):
        self.index += 1
        workspace = self.root / ("mixed-%d" % self.index)
        workspace.mkdir()
        report, output, _project = build_sample(jmm, workspace, sample_dir, files)
        self.assertEqual(report["status"], "artifact_created_unvalidated", report)
        protected = (Path(output) / "protected.cjs").read_text(encoding="utf-8")
        return report["coverage"], protected

    def test_js_pure_generated_source(self):
        source = ("const SECRET_BIAS_7919 = 97;\n"
                  "function helperFn(value) { return value * SECRET_BIAS_7919 + 13; }\n"
                  "function core(x, y) { return helperFn(x) + y; }\n")
        coverage, protected = self._build_pure(source, ["core"], "javascript")
        self.assertGreaterEqual(coverage["runtime_hardening"]["engine_count"], 2)
        self.assertNotIn("SECRET_BIAS_7919", protected, "no original body constant in protected artifact")
        self.assertNotIn("value * SECRET_BIAS_7919", protected, "no original body expression in protected artifact")
        ground_js_source(self, protected, coverage,
                         opcode_count=JS_OPCODES, pairs=JS_PAIRS, mixed=False)

    def test_ts_pure_generated_source(self):
        source = ("function helperFn(value: number): number { return value * 31 + 13; }\n"
                  "export function core(x: number, y: number): number { return helperFn(x) + y; }\n")
        coverage, protected = self._build_pure(source, ["core"], "typescript")
        self.assertGreaterEqual(coverage["runtime_hardening"]["engine_count"], 2)
        self.assertNotIn("helperFn(x) + y", protected, "no original body expression in protected artifact")
        ground_js_source(self, protected, coverage,
                         opcode_count=JS_OPCODES, pairs=JS_PAIRS, mixed=False)

    def test_js_mixed_generated_source(self):
        coverage, protected = self._build_mixed(SAMPLE_JS_MIXED, ("app.js", "labels.js", "project.json"))
        self.assertIn("_arm_enter(", protected, "mixed artifact must delegate wrappers to the VM entry")
        ground_js_source(self, protected, coverage,
                         opcode_count=JS_OPCODES, pairs=JS_PAIRS, mixed=True)

    def test_ts_mixed_generated_source(self):
        coverage, protected = self._build_mixed(SAMPLE_TS_MIXED, ("app.ts", "project.json"))
        self.assertIn("_arm_enter(", protected, "mixed artifact must delegate wrappers to the VM entry")
        ground_js_source(self, protected, coverage,
                         opcode_count=JS_OPCODES, pairs=JS_PAIRS, mixed=True)


# ---------------------------------------------------------------------------
# Supplementary template invariants (NOT generated-source evidence; a cheap
# always-runnable sanity layer on the owned templates). Generated-source proof
# lives in JavaScriptGeneratedSourceEvidence above.
# ---------------------------------------------------------------------------
class JavaScriptTemplateInvariants(unittest.TestCase):
    def _read(self, name):
        path = JS_TOOLS / name
        self.assertTrue(path.is_file(), "expected owned JS template %s" % path)
        self.assertFalse(path.is_symlink(), "JS template must not be a symlink")
        return path.read_text(encoding="utf-8")

    def test_pure_template_anchors_and_generated_engines(self):
        text = self._read("runtime.cjs.in")
        for anchor in ("@BLOB@", "@FUNCTIONS@", "@DIGEST@", "@WRAPPERS@", "@ENGINES@"):
            self.assertIn(anchor, text, "pure JS template must keep the %s anchor" % anchor)
        self.assertIn("_ar_enter", text, "pure JS template must keep the entry seam")
        self.assertNotIn("switch (opcode)", text,
                         "opcode dispatch must live in generated engines, not the static template")

    def test_templates_contain_no_dynamic_execution(self):
        for name in ("runtime.cjs.in", "runtime.mixed.cjs.in"):
            text = self._read(name)
            for pattern in JS_FORBIDDEN:
                self.assertIsNone(re.search(pattern, text),
                                  "%s must not contain dynamic-exec/network construct %r" % (name, pattern))


if __name__ == "__main__":  # pragma: no cover - executed only by root's harness
    unittest.main()
