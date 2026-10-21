"""Owned-fixture tests for format-2 instruction-local Python VM decoding.

The reviewed runner stages the candidate as antirea.python_frontend. This file
never loads a draft by path or executes an arbitrary supplied source program.
Only static test fixtures and their generated modules execute during tests.
"""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from antirea import python_frontend as pf


def load_owned(path):
    spec = importlib.util.spec_from_file_location("owned_context_" + path.parent.name + path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def outcome(function, arguments):
    try:
        value = function(*arguments)
        return ("value", type(value).__name__, value)
    except Exception as error:
        return ("exception", type(error).__name__)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def artifact_metadata(source):
    assignments = {node.targets[0].id: node for node in ast.parse(source).body
                   if isinstance(node, ast.Assign) and len(node.targets) == 1
                   and isinstance(node.targets[0], ast.Name)}
    node = assignments["_ar_functions"]
    functions = ast.literal_eval(node.value)
    blob_node = assignments["_ar_blob"].value
    if not isinstance(blob_node, ast.Call) or len(blob_node.args) != 1:
        raise AssertionError("unexpected generated blob declaration")
    blob = bytes.fromhex(ast.literal_eval(blob_node.args[0]))
    return node, functions, blob


def rewrite_metadata(source, mutate, *, repair_checksum=False):
    """Mutate only trusted generated data; never accept an arbitrary expression."""
    node, functions, blob = artifact_metadata(source)
    if node.lineno != node.end_lineno:
        raise AssertionError("expected single-line literal metadata")
    old_digest = hashlib.sha256(canonical(functions) + blob).hexdigest()
    mutate(functions)
    lines = source.splitlines(keepends=True)
    lines[node.lineno - 1] = "_ar_functions = " + repr(functions) + "\n"
    changed = "".join(lines)
    if repair_checksum:
        if changed.count(repr(old_digest)) != 1:
            raise AssertionError("expected one checksum literal")
        new_digest = hashlib.sha256(canonical(functions) + blob).hexdigest()
        changed = changed.replace(repr(old_digest), repr(new_digest), 1)
    return changed


def independent_fetch_inverse(codec, position, encoded):
    """Invert the documented byte permutation using division/modulo operations."""
    word = (position * codec["multiply"] + codec["add"]) % (1 << 32)
    word ^= word // (1 << 13)
    word = word * codec["mix"] % (1 << 32)
    word ^= word // (1 << 17)
    rotation = (position + codec["rotate"]) % 7 + 1
    value = encoded ^ ((word // 256) % 256)
    unrotated = value // (1 << rotation) + (value % (1 << rotation)) * (1 << (8 - rotation))
    key_byte = (codec["key"] // (1 << (8 * (position % 8)))) % 256
    return (unrotated - ((word ^ key_byte) % 256)) % 256


class PythonContextVMTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.counter = 0

    def tearDown(self):
        self.temp.cleanup()

    def emit(self, source, roots=None, seed=20261021):
        self.counter += 1
        directory = self.root / ("generated-" + str(self.counter))
        report = pf.protect_python_source(source, roots or ["core"], directory, seed=seed)
        self.assertEqual(report["status"], "artifact_created_unvalidated")
        self.assertFalse(report["source_executed"])
        return report, directory

    def build(self, source, roots=None, seed=20261021):
        report, directory = self.emit(source, roots, seed)
        return report, load_owned(directory / "baseline.py"), load_owned(directory / "protected.py"), directory

    def compare(self, source, arguments, roots=None):
        report, baseline, protected, directory = self.build(source, roots)
        for name in roots or ["core"]:
            for case_index, values in enumerate(arguments):
                with self.subTest(function=name, case_index=case_index):
                    self.assertTrue(outcome(getattr(protected, name), values) ==
                                    outcome(getattr(baseline, name), values),
                                    "owned original/protected outcome differs")
        return report, baseline, protected, directory

    def import_changed(self, directory, source):
        self.counter += 1
        path = directory / ("mutated_" + str(self.counter) + ".py")
        path.write_text(source, encoding="utf-8")
        return load_owned(path)

    def test_codec_seed_and_function_identity_are_deterministic(self):
        for seed in (0, 1, 20261021, (1 << 256) - 1):
            codecs = [pf._function_codec(seed, identifier) for identifier in range(4)]
            self.assertEqual(codecs, [pf._function_codec(seed, identifier) for identifier in range(4)])
            self.assertEqual(len({canonical(codec) for codec in codecs}), 4)
            self.assertEqual(len({tuple(codec["tokens"]) for codec in codecs}), 4)
            for codec in codecs:
                self.assertEqual(len(codec["tokens"]), 16)
                self.assertEqual(len(set(codec["tokens"])), 16)
                self.assertTrue(all(type(token) is int and 256 <= token <= 65535 for token in codec["tokens"]))
                self.assertTrue(all(codec[name] & 1 for name in ("multiply", "mix", "operand_multiply")))
        self.assertNotEqual(pf._function_codec(1, 0), pf._function_codec(2, 0))

    def test_fetch_permutation_roundtrips_every_byte_at_multiple_positions(self):
        for identifier in (0, 1, 7):
            codec = pf._function_codec(20261021, identifier)
            for position in (0, 1, 7, 8, 255, 256, (1 << 31) + 3, (1 << 32) + 9):
                encoded = [pf._encode_fetch_byte(codec, position, value) for value in range(256)]
                self.assertEqual(len(set(encoded)), 256)
                self.assertEqual([independent_fetch_inverse(codec, position, value) for value in encoded],
                                 list(range(256)))

    def test_operand_context_binds_record_pc_opcode_and_both_key_halves(self):
        codec = {"key": 0x1122334455667788, "operand_multiply": 9, "operand_add": 17}
        expected = ((23 * 9) ^ 0x1234 ^ 0x1122334455667788 ^ 0x11223344 ^ 17) & 0xffffffff
        self.assertEqual(pf._operand_context(codec, 23, 0x1234), expected)
        self.assertNotEqual(pf._operand_context(codec, 24, 0x1234), expected)
        self.assertNotEqual(pf._operand_context(codec, 23, 0x1235), expected)
        self.assertNotEqual(pf._operand_context({**codec, "key": codec["key"] ^ 1}, 23, 0x1234), expected)
        self.assertNotEqual(pf._operand_context({**codec, "key": codec["key"] ^ (1 << 40)}, 23, 0x1234), expected)

    def test_operand_feedback_uses_plaintext_and_is_fixed_width(self):
        codec = {"operand_multiply": 0xfffffffb, "operand_add": 29}
        # ROTL32(0x80000001, 5) is 0x30, independently fixed here.
        for value in (0, 1, 127, 255):
            expected = (0x30 * 0xfffffffb + value + 29) % (1 << 32)
            self.assertEqual(pf._operand_step(codec, 0x80000001, value), expected)
        left = pf._operand_step(codec, 0x80000001, 0)
        right = pf._operand_step(codec, 0x80000001, 1)
        self.assertEqual((right - left) % (1 << 32), 1)
        self.assertNotEqual(pf._operand_step(codec, left, 65), pf._operand_step(codec, right, 65))

    def test_all_instruction_record_shapes_roundtrip_without_execution(self):
        _, _, runtime, _ = self.build("def core(x):\n    return x\n")
        instructions = [["const", (1 << 4095) + 7], ["const", True], ["const", None],
                        ["load", 2], ["store", 1], ["pop"], ["dup"], ["binary", "lshift"],
                        ["unary", "not_"], ["compare", "lt"], ["jump", 0], ["false", 3],
                        ["true", 4], ["call", "owned_helper", 2], ["builtin", "min", 2],
                        ["return"], ["iter", 3, 5], ["next", 5, 6, 2]]
        snapshot = copy.deepcopy(instructions)
        codec = pf._function_codec(417, 9)
        encoded, positions = pf._encode_function({"code": instructions}, {"owned_helper": 3}, codec)
        function = {"slots": 7, "offset": 0, "bytes": len(encoded), "positions": positions, "codec": codec}
        with patch.object(runtime, "_ar_blob", encoded):
            for index, (operation, *operands) in enumerate(instructions):
                if operation == "call":
                    operands[0] = 3
                decoded = runtime._ar_fetch(function, index)
                self.assertTrue(decoded == [codec["tokens"][pf._OPS.index(operation)], *operands],
                                "instruction record roundtrip differs")
                if operation == "const":
                    self.assertIs(type(decoded[1]), type(operands[0]))
        self.assertEqual(instructions, snapshot)
        self.assertEqual(positions[0], 0)
        self.assertEqual(positions[-1], len(encoded))
        self.assertTrue(all(right - left >= 4 for left, right in zip(positions, positions[1:])))

    def test_import_never_decodes_instruction_json_or_retains_plain_program(self):
        _, directory = self.emit("def core(x):\n    return (x + 17) * 3\n")
        with patch.object(json, "loads", side_effect=AssertionError("instruction decode at import")):
            runtime = load_owned(directory / "protected.py")
        self.assertFalse(hasattr(runtime, "_ar_plain"))
        self.assertFalse(hasattr(runtime, "_ar_program"))
        self.assertFalse(hasattr(runtime, "_ar_metadata"))
        self.assertTrue(all(set(function) == {"slots", "offset", "bytes", "positions", "codec"}
                            for function in runtime._ar_functions))
        original_loads = json.loads
        with patch.object(json, "loads", wraps=original_loads) as decoded:
            self.assertEqual(runtime.core(2), 57)
        self.assertGreater(decoded.call_count, 0)
        self.assertTrue(all(isinstance(call.args[0], bytearray) for call in decoded.call_args_list))

    def test_fetch_reads_exact_current_record_span_only(self):
        _, _, runtime, _ = self.build("def core(x):\n    if x:\n        return 71\n    return 93\n")
        function = runtime._ar_functions[0]
        for index in (0, 2, len(function["positions"]) - 2):
            with patch.object(runtime, "_ar_read_byte", wraps=runtime._ar_read_byte) as reads:
                runtime._ar_fetch(function, index)
            self.assertEqual([call.args[1] for call in reads.call_args_list],
                             list(range(function["positions"][index], function["positions"][index + 1])))
            self.assertTrue(all(call.args[0] is function for call in reads.call_args_list))

    def test_unvisited_branch_is_not_decoded(self):
        source = "def core(x):\n    if x:\n        return 71\n    return 93\n"
        _, _, runtime, _ = self.build(source)
        _, compiled = pf._analyze(source, ["core"])
        constant_93 = next(i for i, row in enumerate(compiled["core"]["code"]) if row == ["const", 93])
        constant_71 = next(i for i, row in enumerate(compiled["core"]["code"]) if row == ["const", 71])
        with patch.object(runtime, "_ar_fetch", wraps=runtime._ar_fetch) as fetch:
            self.assertEqual(runtime.core(1), 71)
        visited = [call.args[1] for call in fetch.call_args_list]
        self.assertIn(constant_71, visited)
        self.assertNotIn(constant_93, visited)
        self.assertLess(len(visited), len(compiled["core"]["code"]))

    def test_loop_refetches_records_and_no_decoded_result_is_cached(self):
        source = "def core(x):\n    total = 0\n    for i in range(x):\n        total += i\n    return total\n"
        _, _, runtime, _ = self.build(source)
        with patch.object(runtime, "_ar_fetch", wraps=runtime._ar_fetch) as fetch:
            self.assertEqual(runtime.core(5), 10)
        visited = [call.args[1] for call in fetch.call_args_list]
        self.assertGreater(len(visited), len(set(visited)))
        function = runtime._ar_functions[0]
        first = runtime._ar_fetch(function, 0)
        expected = first[:]
        first.append("owned mutation must not persist")
        self.assertEqual(runtime._ar_fetch(function, 0), expected)
        self.assertIsNot(runtime._ar_fetch(function, 0), runtime._ar_fetch(function, 0))

    def test_invalid_instruction_addresses_fail_before_reading_blob(self):
        _, _, runtime, _ = self.build("def core(x):\n    return x\n")
        function = runtime._ar_functions[0]
        for address in (-1, True, False, 1.0, "0", None, len(function["positions"]) - 1):
            with self.subTest(address=address), patch.object(runtime, "_ar_read_byte", side_effect=AssertionError("read")):
                with self.assertRaisesRegex(RuntimeError, "instruction address"):
                    runtime._ar_fetch(function, address)

    def test_each_function_uses_its_own_codec_and_opcode_table(self):
        source = "def first(x):\n    return x + 7\ndef second(x):\n    return x + 7\ndef core(x):\n    return first(x) + second(x)\n"
        report, _, runtime, _ = self.build(source)
        functions = runtime._ar_functions
        self.assertEqual(len(functions), 3)
        self.assertEqual(len({canonical(item["codec"]) for item in functions}), 3)
        self.assertEqual(len({tuple(item["codec"]["tokens"]) for item in functions}), 3)
        self.assertEqual(report["coverage"]["codec_count"], 3)
        with patch.object(runtime, "_ar_fetch", wraps=runtime._ar_fetch) as fetch:
            self.assertEqual(runtime.core(5), 24)
        self.assertEqual({id(call.args[0]) for call in fetch.call_args_list}, {id(item) for item in functions})

    def test_seed_reproducibility_and_seed_change_bind_artifacts(self):
        source = "def helper(x):\n    return x ^ 31\ndef core(x):\n    return helper(x) + 3\n"
        first = pf._generate(source, ["core"], 17)
        again = pf._generate(source, ["core"], 17)
        other = pf._generate(source, ["core"], 18)
        self.assertEqual(first, again)
        self.assertNotEqual(first[0], other[0])
        self.assertNotEqual(first[1]["encoded_sha256"], other[1]["encoded_sha256"])
        self.assertNotEqual(first[1]["metadata_sha256"], other[1]["metadata_sha256"])

    def test_checksum_binds_every_function_codec_offsets_and_slot_metadata(self):
        _, directory = self.emit("def helper(x):\n    return x + 3\ndef core(x):\n    return helper(x)\n")
        source = (directory / "protected.py").read_text(encoding="utf-8")
        mutations = [lambda rows: rows[0].__setitem__("slots", rows[0]["slots"] + 1),
                     lambda rows: rows[0]["positions"].__setitem__(1, rows[0]["positions"][1] + 1),
                     lambda rows: rows[1].__setitem__("offset", rows[1]["offset"] + 1),
                     lambda rows: rows[1]["codec"].__setitem__("key", rows[1]["codec"]["key"] ^ 1),
                     lambda rows: rows[0]["codec"]["tokens"].__setitem__(0, rows[0]["codec"]["tokens"][0] ^ 1),
                     lambda rows: rows[1]["codec"].__setitem__("operand_add", rows[1]["codec"]["operand_add"] ^ 1)]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index), self.assertRaisesRegex(RuntimeError, "integrity"):
                self.import_changed(directory, rewrite_metadata(source, mutate))

    def test_checksum_binds_encoded_blob_without_disclosing_source_data(self):
        _, directory = self.emit("def core(x):\n    return x + 17\n")
        source = (directory / "protected.py").read_text(encoding="utf-8")
        anchor = "_ar_blob = bytes.fromhex('"
        position = source.index(anchor) + len(anchor)
        replacement = "1" if source[position] == "0" else "0"
        changed = source[:position] + replacement + source[position + 1:]
        with self.assertRaisesRegex(RuntimeError, "integrity"):
            self.import_changed(directory, changed)

    def test_repaired_checksum_does_not_bypass_metadata_shape_checks(self):
        _, directory = self.emit("def helper(x):\n    return x + 3\ndef core(x):\n    return helper(x)\n")
        source = (directory / "protected.py").read_text(encoding="utf-8")
        mutations = [lambda rows: rows[0]["positions"].__setitem__(0, False),
                     lambda rows: rows[0]["positions"].__setitem__(1, 0),
                     lambda rows: rows[0]["positions"].__setitem__(-1, rows[0]["bytes"] - 1),
                     lambda rows: rows[1].__setitem__("offset", rows[1]["offset"] + 1),
                     lambda rows: rows[0].__setitem__("slots", True),
                     lambda rows: rows[0]["codec"].__setitem__("key", False),
                     lambda rows: rows[0]["codec"].__setitem__("rotate", 7),
                     lambda rows: rows[0]["codec"].__setitem__("multiply", 2),
                     lambda rows: rows[0]["codec"]["tokens"].__setitem__(0, True),
                     lambda rows: rows[0]["codec"]["tokens"].__setitem__(0, rows[0]["codec"]["tokens"][1]),
                     lambda rows: rows[0]["codec"].__setitem__("unexpected", 1)]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index), self.assertRaisesRegex(RuntimeError, "metadata"):
                self.import_changed(directory, rewrite_metadata(source, mutate, repair_checksum=True))

    def test_coverage_hashes_match_actual_encoded_slices_and_metadata(self):
        report, _, runtime, _ = self.build("def helper(x):\n    return x + 4\ndef core(x):\n    return helper(x) - 1\n")
        coverage = report["coverage"]
        self.assertEqual(coverage["format_version"], 2)
        self.assertEqual(coverage["decode_scope"], "current_instruction")
        self.assertIs(coverage["decoded_instruction_cache"], False)
        self.assertEqual(coverage["opcode_scope"], "per_function")
        self.assertEqual(coverage["codec_scope"], "per_function")
        self.assertEqual(coverage["dispatcher"], "per_function_flattened_indirect_dispatch")
        self.assertIs(coverage["kagura_passes_applied"], False)
        self.assertEqual(coverage["requested_core_passes"], [])
        self.assertIs(coverage["integrity"]["covers_codec_and_offsets"], True)
        self.assertIs(coverage["integrity"]["covers_runtime_code"], False)
        self.assertIs(coverage["integrity"]["authenticated"], False)
        self.assertEqual(coverage["encoded_sha256"], hashlib.sha256(runtime._ar_blob).hexdigest())
        self.assertEqual(coverage["metadata_sha256"], hashlib.sha256(canonical(runtime._ar_functions)).hexdigest())
        for evidence in coverage["functions"].values():
            function = runtime._ar_functions[evidence["vm_function_id"]]
            encoded = runtime._ar_blob[function["offset"]:function["offset"] + function["bytes"]]
            self.assertEqual(evidence["encoded_sha256"], hashlib.sha256(encoded).hexdigest())
            self.assertEqual(evidence["encoded_bytes"], len(encoded))
            self.assertEqual(evidence["codec_sha256"], hashlib.sha256(canonical(function["codec"])).hexdigest())
            self.assertEqual(evidence["instruction_offsets_sha256"], hashlib.sha256(canonical(function["positions"])).hexdigest())
            self.assertEqual(evidence["instruction_count"], len(function["positions"]) - 1)

    def test_codec_collision_is_rejected_before_any_output(self):
        source = "def helper(x):\n    return x + 1\ndef core(x):\n    return helper(x)\n"
        output = self.root / "collision"
        with patch.object(pf, "_function_codec", return_value=pf._function_codec(17, 0)):
            with self.assertRaisesRegex(pf.PythonFrontendError, "codec collision"):
                pf.protect_python_source(source, ["core"], output, seed=17)
        self.assertFalse(output.exists())

    def test_generated_runtime_survives_all_new_builtin_name_shadows(self):
        names = ["bytes", "bytearray", "dict", "list", "set", "object", "any", "type", "len", "next",
                 "iter", "range", "getattr", "RuntimeError", "StopIteration", "UnboundLocalError"]
        source = "\n".join("def " + name + "(x):\n    return x + 1\n" for name in names)
        _, _, runtime, _ = self.build(source, names)
        for name in names:
            self.assertEqual(getattr(runtime, name)(41), 42)
        runtime._ar_validate_metadata()
        with self.assertRaisesRegex(RuntimeError, "instruction address"):
            runtime._ar_fetch(runtime._ar_functions[0], -1)

    def test_unbounded_integer_operands_results_and_shift_errors_preserved(self):
        literal = (1 << 4095) + 17
        source = "C = " + hex(literal) + "\ndef core(x, y):\n    return ((x + C) * (x - C)) << y\n"
        _, _, runtime, _ = self.compare(source, [(0, 0), (True, 1), (-(1 << 5000), 3),
                                                ((1 << 6000) + 19, 5), (1, -1)])
        self.assertTrue(runtime.core(0, 0) == -literal * literal, "unbounded integer result differs")
        self.assertGreater(runtime.core((1 << 6000) + 19, 5).bit_length(), 12000)
        self.assertIs(type(runtime.core(True, 0)), int)

    def test_boolean_values_short_circuit_and_exception_classes_preserved(self):
        source = "def core(x, y):\n    return (x and (10 // y)) or (not x)\n"
        _, _, runtime, _ = self.compare(source, [(False, 0), (True, 2), (True, 0), (2, -3), (0, 0)])
        self.assertIs(runtime.core(False, 0), True)
        self.assertIs(type(runtime.core(True, 2)), int)
        self.assertEqual(outcome(runtime.core, (True, 0)), ("exception", "ZeroDivisionError"))

    def test_negative_division_modulo_and_shift_exception_semantics(self):
        source = "def core(x, y):\n    if y < 0:\n        return x << y\n    return (x // y) * 101 + x % y\n"
        self.compare(source, [(-19, 4), (19, 4), (0, 4), (-19, 0), (19, -1), (True, 1),
                              (-(1 << 200), 17)])

    def test_nested_loops_branches_helpers_and_loop_else_preserved(self):
        source = """def helper(x):
    return (x ^ 31) - 7
def core(x, y):
    total = 0
    for i in range(-3, x, 2):
        if i == y:
            continue
        j = 0
        while j < 3:
            j += 1
            if j == y:
                break
            total += helper(i * j)
        else:
            total ^= 123
        if total > 500:
            break
    else:
        total += 79
    return total
"""
        self.compare(source, [(x, y) for x in (-5, 0, 3, 8, 15) for y in (-1, 0, 1, 2, 4)])

    def test_helper_internal_none_zero_arity_and_public_bool_are_preserved(self):
        source = "def empty():\n    return None\ndef helper(x):\n    return not x\ndef core(x):\n    return helper(empty()) if x else helper(x)\n"
        _, _, runtime, _ = self.compare(source, [(False,), (True,), (0,), (1,), (-7,)])
        self.assertIs(runtime.core(True), True)
        self.assertIs(runtime.core(False), True)

    def test_comparison_middle_helper_evaluates_once_and_unvisited_helper_not_called(self):
        source = "def middle(x):\n    return x + 1\ndef unreachable(x):\n    return x // 0\ndef core(x):\n    return (0 < middle(x) < 10) or (False and unreachable(x))\n"
        report, baseline, runtime, _ = self.build(source)
        identifiers = {name: row["vm_function_id"] for name, row in report["coverage"]["functions"].items()}
        for value in (-2, 3, 20):
            with patch.object(runtime, "_ar_invoke", wraps=runtime._ar_invoke) as invoke:
                self.assertEqual(outcome(runtime.core, (value,)), outcome(baseline.core, (value,)))
            calls = [call.args[0] for call in invoke.call_args_list]
            self.assertEqual(calls.count(identifiers["middle"]), 1)
            self.assertNotIn(identifiers["unreachable"], calls)

    def test_encoded_blob_and_metadata_stay_unchanged_across_calls(self):
        source = "def helper(x):\n    return x * 3\ndef core(x):\n    total = 0\n    for i in range(5):\n        total += helper(x + i)\n    return total\n"
        _, baseline, runtime, _ = self.build(source)
        before_blob = runtime._ar_blob
        before_metadata = copy.deepcopy(runtime._ar_functions)
        for value in (-17, 0, True, (1 << 500) + 9):
            self.assertEqual(runtime.core(value), baseline.core(value))
        self.assertIs(runtime._ar_blob, before_blob)
        self.assertEqual(runtime._ar_functions, before_metadata)

    def test_no_original_bodies_or_executable_source_fallback_are_emitted(self):
        source = "def private_business_helper(x):\n    peculiar_local = x * 991\n    return peculiar_local + 17\ndef core(x):\n    return private_business_helper(x)\n"
        report, _, runtime, directory = self.build(source)
        generated = (directory / "protected.py").read_text(encoding="utf-8")
        self.assertNotIn("private_business_helper", generated)
        self.assertNotIn("peculiar_local", generated)
        self.assertNotIn("x * 991", generated)
        calls = [node.func.id for node in ast.walk(ast.parse(generated))
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
        self.assertTrue({"eval", "exec", "compile", "__import__"}.isdisjoint(calls))
        self.assertEqual(runtime.core(3), 2990)
        self.assertIs(report["coverage"]["original_selected_bodies_in_protected_artifact"], False)


if __name__ == "__main__":
    unittest.main()
