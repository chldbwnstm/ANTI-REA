"""Owned-fixture tests for instruction-local JS/TS VM decoding.

The parent qualification runner stages the candidate as antirea.javascript_frontend
and its template as tools/javascript_frontend/runtime.cjs.in. No draft import,
download, ambient npm resolution, or externally supplied program is used here.
Runtime inspection hooks are inserted only into a separate test-only module.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from antirea import javascript_frontend as jf


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def metadata(source):
    rows = re.search(r"^  const functions = (.+);$", source, re.MULTILINE)
    blob = re.search(r'^  const blob = Buffer_\.from\("([0-9a-f]+)", "hex"\);$', source, re.MULTILINE)
    if not rows or not blob:
        raise AssertionError("expected literal metadata/blob declarations")
    return rows, json.loads(rows.group(1)), bytes.fromhex(blob.group(1))


def rewrite_metadata(source, mutate, repair=False):
    match, functions, blob = metadata(source)
    old = hashlib.sha256(canonical(functions) + blob).hexdigest()
    mutate(functions)
    changed = source[:match.start(1)] + canonical(functions).decode("ascii") + source[match.end(1):]
    if repair:
        if changed.count(json.dumps(old)) != 1:
            raise AssertionError("expected one checksum literal")
        new = hashlib.sha256(canonical(functions) + blob).hexdigest()
        changed = changed.replace(json.dumps(old), json.dumps(new), 1)
    return changed


def inverse_fetch(codec, position, encoded):
    """Independent modulo/division form of the documented byte permutation."""
    word = (position * codec["multiply"] + codec["add"]) % (1 << 32)
    word ^= word // (1 << 13)
    word = word * codec["mix"] % (1 << 32)
    word ^= word // (1 << 17)
    rotation = (position + codec["rotate"]) % 7 + 1
    value = encoded ^ ((word // 256) % 256)
    unrotated = value // (1 << rotation) + (value % (1 << rotation)) * (1 << (8 - rotation))
    key = codec["key"][0] + (codec["key"][1] << 32)
    key_byte = (key // (1 << (8 * (position % 8)))) % 256
    return (unrotated - ((word ^ key_byte) % 256)) % 256


INSPECT_HOOK = """
  Object.defineProperty(exported, "__owned", {value: {
    functions, blob, fetch: (fn, pc) => fetch(fn, pc), readByte: (fn, pc) => readByte(fn, pc),
    validateMetadata,
    observeFetch(callback) {
      const old = fetch;
      fetch = (fn, pc) => { callback(fn, pc); return old(fn, pc); };
      return () => { fetch = old; };
    },
    observeReads(callback) {
      const old = readByte;
      readByte = (fn, pc) => { callback(fn, pc); return old(fn, pc); };
      return () => { readByte = old; };
    }
  }});
"""

OBSERVE = """
function observed(callback, args) {
  try {
    const value = callback(...args);
    if (typeof value === "number") {
      if (Number.isNaN(value)) return ["number", "NaN"];
      const bytes = Buffer.alloc(8); bytes.writeDoubleBE(value);
      return ["number", bytes.toString("hex")];
    }
    if (typeof value === "bigint") return ["bigint", value.toString()];
    if (typeof value === "boolean") return ["boolean", value];
    if (value === undefined) return ["undefined"];
    if (value === null) return ["null"];
    throw new Error("unsupported owned outcome");
  } catch (error) {
    return ["exception", Object.getPrototypeOf(error).constructor.name];
  }
}
"""


class JavaScriptContextCodecTests(unittest.TestCase):
    def test_function_codec_is_deterministic_and_function_seed_scoped(self):
        codec = jf._function_codec(117, 3)
        self.assertEqual(codec, jf._function_codec(117, 3))
        self.assertNotEqual(codec, jf._function_codec(117, 4))
        self.assertNotEqual(codec, jf._function_codec(118, 3))
        self.assertEqual(len(codec["tokens"]), len(jf.OPS))
        self.assertEqual(len(set(codec["tokens"])), len(jf.OPS))
        self.assertTrue(all(256 <= token <= 65535 for token in codec["tokens"]))
        self.assertEqual(len(codec["key"]), 2)
        self.assertTrue(all(type(word) is int and 0 <= word < 2**32 for word in codec["key"]))
        self.assertTrue(all(codec[name] & 1 for name in ("multiply", "mix", "operand_multiply")))

    def test_fetch_byte_permutation_roundtrips_every_byte_at_edge_positions(self):
        for seed in (0, 17, (1 << 255) + 9):
            codec = jf._function_codec(seed, 7)
            for position in (0, 1, 3, 4, 7, 8, 31, 255, 65537, 0x7fffffff, 0xfffffffe):
                encoded = [jf._encode_fetch_byte(codec, position, byte) for byte in range(256)]
                self.assertEqual(len(set(encoded)), 256)
                self.assertEqual([inverse_fetch(codec, position, byte) for byte in encoded], list(range(256)))

    def test_operand_context_includes_pc_opcode_and_both_key_words(self):
        codec = jf._function_codec(41, 7)
        expected = ((23 * codec["operand_multiply"]) ^ 0x1234 ^ codec["key"][0]
                    ^ codec["key"][1] ^ codec["operand_add"]) & 0xffffffff
        self.assertEqual(jf._operand_context(codec, 23, 0x1234), expected)
        self.assertNotEqual(jf._operand_context(codec, 24, 0x1234), expected)
        self.assertNotEqual(jf._operand_context(codec, 23, 0x1235), expected)
        for index in (0, 1):
            changed = copy.deepcopy(codec); changed["key"][index] ^= 1
            self.assertNotEqual(jf._operand_context(changed, 23, 0x1234), expected)

    def test_operand_feedback_is_plaintext_dependent_and_exact_uint32(self):
        codec = {"operand_multiply": 0xfffffffb, "operand_add": 29}
        for value in (0, 1, 127, 255):
            self.assertEqual(jf._operand_step(codec, 0x80000001, value),
                             (0x30 * 0xfffffffb + value + 29) % (1 << 32))
        left = jf._operand_step(codec, 0x80000001, 0)
        right = jf._operand_step(codec, 0x80000001, 1)
        self.assertEqual((right - left) % (1 << 32), 1)
        self.assertNotEqual(jf._operand_step(codec, left, 65), jf._operand_step(codec, right, 65))


class JavaScriptContextVMTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.tools = jf.discover_toolchain()
        except ValueError as error:
            raise unittest.SkipTest(str(error))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root, self.counter = Path(self.temp.name), 0

    def emit(self, source, names=None, language="javascript", seed=20261021):
        names = names or ["core"]
        parsed = jf._parse(source, language, names, self.tools, build=True)
        runtime, coverage = jf._generate(parsed, seed)
        self.counter += 1
        directory = self.root / str(self.counter); directory.mkdir()
        for name, data in (("protected", runtime), ("baseline", parsed["baseline"]),
                           ("inspected", runtime.replace("  return exported;\n", INSPECT_HOOK + "  return exported;\n", 1))):
            (directory / (name + ".cjs")).write_text(data, encoding="utf-8")
        self.assertIn("__owned", (directory / "inspected.cjs").read_text(encoding="utf-8"))
        return directory, parsed, coverage, runtime

    def node(self, code):
        prefix = '"use strict";\nconst assert = require("node:assert/strict");\n'
        process = subprocess.run([self.tools["files"]["node"]["path"], "--no-addons",
                                  "--max-old-space-size=256", "-e", prefix + code],
                                 cwd=self.root, env=jf.clean_node_environment(), capture_output=True,
                                 text=True, encoding="utf-8", errors="strict", timeout=20, check=False)
        self.assertEqual(process.returncode, 0, process.stderr[:8192])
        self.assertLess(len(process.stdout.encode("utf-8")), 1024 * 1024)
        return process.stdout

    def require(self, path):
        return "require(" + json.dumps(str(path)) + ")"

    def compare(self, source, cases, names=None, language="javascript"):
        directory, parsed, coverage, runtime = self.emit(source, names, language)
        names = names or ["core"]
        code = ("const baseline = " + self.require(directory / "baseline.cjs") + ";\n"
                "const subject = " + self.require(directory / "protected.cjs") + ";\n" + OBSERVE
                + "const cases = " + cases + ";\n"
                + "for (const name of " + json.dumps(names) + ") for (const args of cases) {\n"
                " assert.deepEqual(observed(subject[name], args), observed(baseline[name], args));\n"
                " assert.deepEqual(observed(subject[name], args), observed(baseline[name], args));\n}\n")
        self.node(code)
        return directory, parsed, coverage, runtime

    def test_runtime_fetch_roundtrips_every_instruction_operand_shape(self):
        instructions = [["const", ["number", "8000000000000000"]], ["const", ["number", "7ff8000000000000"]],
                        ["const", ["number", "7ff0000000000000"]], ["const", ["bigint", str(2**4095 + 17)]],
                        ["const", ["boolean", True]], ["const", ["undefined"]], ["const", ["null"]],
                        ["reset", [1, 3]], ["load", 0], ["init", 2], ["set", 1], ["update", 2, "++", True],
                        ["pop"], ["dup"], ["unary", "!"], ["binary", "**"], ["jump", 2], ["false", 1],
                        ["true", 0], ["nonnull", 1], ["call", "helper", 0], ["builtin", "BigInt.asIntN", 2], ["return"]]
        snapshot = copy.deepcopy(instructions)
        parsed = {"helper_closure": ["core", "helper"], "exported_functions": ["core"], "functions": {
            "core": {"slots": ["parameter", "let", "const", "let"], "parameters": ["x"], "helpers": ["helper"], "code": instructions},
            "helper": {"slots": [], "parameters": [], "helpers": [], "code": [["const", ["undefined"]], ["return"]]}}}
        runtime, _ = jf._generate(parsed, 417)
        path = self.root / "records.cjs"
        path.write_text(runtime.replace("  return exported;\n", INSPECT_HOOK + "  return exported;\n", 1), encoding="utf-8")
        expected = []
        _, functions, _ = metadata(runtime)
        for operation, *operands in instructions:
            if operation == "call": operands[0] = 1
            expected.append([functions[0]["codec"]["tokens"][jf.OPS.index(operation)], *operands])
        self.node("const api = " + self.require(path) + ".__owned;\n"
                  "const expected = " + json.dumps(expected) + ";\n"
                  "for (let i = 0; i < expected.length; ++i) assert.deepEqual(api.fetch(api.functions[0], i), expected[i]);")
        self.assertEqual(instructions, snapshot)

    def test_runtime_fetch_math_matches_reference_at_uint32_edge_positions(self):
        directory, _, _, _ = self.emit("function core(x) { return x; }")
        codec = jf._function_codec((1 << 255) + 9, 3)
        # Mock only the ciphertext read through a Proxy; real codec arithmetic runs.
        vectors = [{"position": position, "plain": byte, "encoded": jf._encode_fetch_byte(codec, position, byte)}
                   for position in (0, 4, 7, 8, 65537, 0x7fffffff, 0xfffffffe) for byte in (0, 1, 127, 128, 255)]
        runtime = (directory / "inspected.cjs").read_text(encoding="utf-8")
        # A test-only injected function reuses the production readByte implementation
        # with a lexical blob parameter, without decoding an impossible huge buffer.
        read_body = re.search(r"  function readByte\(fn, position\) \{(.+?)\n  \}\n  function fetch", runtime, re.DOTALL)
        self.assertIsNotNone(read_body)
        self.node("const codec = " + json.dumps(codec) + ";\n"
                  "const vectors = " + json.dumps(vectors) + ";\n"
                  "for (const vector of vectors) {\n"
                  " const blob = new Proxy({}, {get: (_target, key) => {assert.equal(Number(key), vector.position); return vector.encoded;}});\n"
                  " function readByte(fn, position) {" + read_body.group(1) + "\n}\n"
                  " assert.equal(readByte({codec, offset: 0}, vector.position), vector.plain);\n}")

    def test_import_does_not_decode_instruction_json(self):
        directory, _, _, runtime = self.emit("function core(x) { return (x + 17) * 3; }")
        # Observe the decoder in a separate owned module. A local scalar named
        # "plain" says nothing about eager whole-program decoding or caching.
        read_anchor = "  function readByte(fn, position) {\n"
        self.assertEqual(runtime.count(read_anchor), 1)
        instrumented = runtime.replace(
            read_anchor,
            read_anchor + "    globalThis.__ownedImportProbe.reads++;\n"
            "    if (globalThis.__ownedImportProbe.importing) throw new Error('owned eager instruction read');\n",
            1)
        export_anchor = "  return exported;\n"
        self.assertEqual(instrumented.count(export_anchor), 1)
        instrumented = instrumented.replace(export_anchor, INSPECT_HOOK + export_anchor, 1)
        import_anchor = "  validateMetadata();\n"
        self.assertEqual(instrumented.count(import_anchor), 1)
        paths = {}
        for name, injected in (
                ("observed-import", ""),
                ("eager-fetch", "  fetch(functions[0], 0);\n"),
                ("eager-json", "  JSON.parse('[]');\n")):
            path = directory / (name + ".cjs")
            path.write_text(instrumented.replace(import_anchor, import_anchor + injected, 1), encoding="utf-8")
            paths[name] = path
        self.node(
            "const parse = JSON.parse;\n"
            "const probe = {importing: true, reads: 0, parses: 0};\n"
            "globalThis.__ownedImportProbe = probe;\n"
            "JSON.parse = function(...args) {\n"
            " probe.parses++;\n"
            " if (probe.importing) throw new Error('owned eager instruction JSON parse');\n"
            " return Reflect.apply(parse, this, args);\n"
            "};\n"
            "try {\n"
            " const unmodified = " + self.require(directory / "protected.cjs") + ";\n"
            " const subject = " + self.require(paths["observed-import"]) + ";\n"
            " assert.equal(probe.reads, 0); assert.equal(probe.parses, 0);\n"
            " for (const fn of subject.__owned.functions) assert.deepEqual(Object.keys(fn).sort(), ['bytes','codec','offset','positions','slots']);\n"
            " probe.importing = false;\n"
            " assert.equal(subject.core(2), 57);\n"
            " assert.ok(probe.reads > 0); assert.ok(probe.parses > 0);\n"
            " assert.equal(unmodified.core(2), 57);\n"
            " Object.assign(probe, {importing: true, reads: 0, parses: 0});\n"
            " assert.throws(() => " + self.require(paths["eager-fetch"]) + ", /owned eager instruction read/);\n"
            " assert.equal(probe.reads, 1); assert.equal(probe.parses, 0);\n"
            " Object.assign(probe, {importing: true, reads: 0, parses: 0});\n"
            " assert.throws(() => " + self.require(paths["eager-json"]) + ", /owned eager instruction JSON parse/);\n"
            " assert.equal(probe.reads, 0); assert.equal(probe.parses, 1);\n"
            "} finally { JSON.parse = parse; delete globalThis.__ownedImportProbe; }\n"
            "assert.equal(JSON.parse, parse);\n"
            "assert.equal(Object.prototype.hasOwnProperty.call(globalThis, '__ownedImportProbe'), false);\n")
        self.assertNotIn("const program =", runtime)
        self.assertNotIn("fn.code[", runtime)

    def test_fetch_reads_only_exact_current_record_and_never_caches_result(self):
        directory, _, _, _ = self.emit("function core(x) { if (x) return 71; return 93; }")
        self.node("const api = " + self.require(directory / "inspected.cjs") + ".__owned;\n"
                  "const fn = api.functions[0];\n"
                  "for (const index of [0, 2, fn.positions.length - 2]) {\n"
                  " const reads = []; const restore = api.observeReads((other, pc) => {assert.equal(other, fn); reads.push(pc);});\n"
                  " const first = api.fetch(fn, index); restore();\n"
                  " assert.deepEqual(reads, Array.from({length: fn.positions[index + 1] - fn.positions[index]}, (_, i) => fn.positions[index] + i));\n"
                  " const expected = first.slice(); first.push('owned mutation');\n"
                  " assert.deepEqual(api.fetch(fn, index), expected);\n"
                  " assert.notEqual(api.fetch(fn, index), api.fetch(fn, index));\n}")

    def test_unvisited_branch_never_decodes_and_loops_refetch(self):
        source = "function core(x) { let total = 0; if (x < 0) return 93; for (let i=0; i<x; i++) total += 71; return total; }"
        directory, parsed, _, _ = self.emit(source)
        tag_93 = ["const", ["number", struct.pack(">d", 93).hex()]]
        unvisited = parsed["functions"]["core"]["code"].index(tag_93)
        self.node("const subject = " + self.require(directory / "inspected.cjs") + ";\n"
                  "const visits = []; const restore = subject.__owned.observeFetch((_fn, pc) => visits.push(pc));\n"
                  "assert.equal(subject.core(5), 355); restore();\n"
                  "assert.ok(!visits.includes(" + str(unvisited) + "));\n"
                  "assert.ok(visits.length > new Set(visits).size);")

    def test_invalid_addresses_fail_before_any_byte_read(self):
        directory, _, _, _ = self.emit("function core(x) { return x; }")
        self.node("const api = " + self.require(directory / "inspected.cjs") + ".__owned;\n"
                  "api.observeReads(() => {throw new Error('unexpected read');});\n"
                  "for (const pc of [-1, true, false, 1.5, '0', null, undefined, NaN, Infinity, api.functions[0].positions.length - 1])\n"
                  " assert.throws(() => api.fetch(api.functions[0], pc), /instruction address/);")

    def test_each_function_has_distinct_codec_and_opcode_table(self):
        directory, _, coverage, runtime = self.emit("function first(x) { return x + 7; } function second(x) { return x + 7; } function core(x) { return first(x) + second(x); }")
        _, functions, _ = metadata(runtime)
        self.assertEqual(len(functions), 3)
        self.assertEqual(len({canonical(fn["codec"]) for fn in functions}), 3)
        self.assertEqual(len({tuple(fn["codec"]["tokens"]) for fn in functions}), 3)
        self.assertEqual(coverage["codec_count"], 3)
        self.node("const subject = " + self.require(directory / "inspected.cjs") + ";\n"
                  "const seen = new Set(); subject.__owned.observeFetch(fn => seen.add(fn));\n"
                  "assert.equal(subject.core(5), 24);\nassert.equal(seen.size, 3);")

    def test_seed_reproducibility_and_codec_collision_failure(self):
        _, parsed, _, _ = self.emit("function helper(x) { return x ^ 31; } function core(x) { return helper(x) + 3; }")
        first = jf._generate(parsed, 17); again = jf._generate(parsed, 17); other = jf._generate(parsed, 18)
        self.assertEqual(first, again)
        self.assertNotEqual(first[0], other[0])
        self.assertNotEqual(first[1]["encoded_sha256"], other[1]["encoded_sha256"])
        self.assertNotEqual(first[1]["metadata_sha256"], other[1]["metadata_sha256"])
        with patch.object(jf, "_function_codec", return_value=jf._function_codec(17, 0)):
            with self.assertRaisesRegex(jf.JavaScriptFrontendError, "codec collision"):
                jf._generate(parsed, 17)
        for seed in (-1, True, None, 1.5, 2**256):
            with self.subTest(seed=seed), self.assertRaises(ValueError): jf._generate(parsed, seed)

    def test_checksum_binds_codec_offsets_slots_and_blob(self):
        directory, _, _, runtime = self.emit("function helper(x) { return x + 3; } function core(x) { return helper(x); }")
        changes = [
            lambda rows: rows[0]["slots"].append("let"),
            lambda rows: rows[0]["positions"].__setitem__(1, rows[0]["positions"][1] + 1),
            lambda rows: rows[1].__setitem__("offset", rows[1]["offset"] + 1),
            lambda rows: rows[1]["codec"]["key"].__setitem__(1, rows[1]["codec"]["key"][1] ^ 1),
            lambda rows: rows[0]["codec"]["tokens"].__setitem__(0, rows[0]["codec"]["tokens"][0] ^ 1),
            lambda rows: rows[1]["codec"].__setitem__("operand_add", rows[1]["codec"]["operand_add"] ^ 1),
        ]
        paths = []
        for index, mutate in enumerate(changes):
            path = directory / ("changed-" + str(index) + ".cjs")
            path.write_text(rewrite_metadata(runtime, mutate), encoding="utf-8"); paths.append(path)
        anchor = 'const blob = Buffer_.from("'
        offset = runtime.index(anchor) + len(anchor)
        changed = runtime[:offset] + ("1" if runtime[offset] == "0" else "0") + runtime[offset + 1:]
        path = directory / "changed-blob.cjs"; path.write_text(changed, encoding="utf-8"); paths.append(path)
        self.node("\n".join("assert.throws(() => " + self.require(path) + ", /integrity/);" for path in paths))

    def test_repaired_checksum_does_not_skip_metadata_validation(self):
        directory, _, _, runtime = self.emit("function helper(x) { return x + 3; } function core(x) { return helper(x); }")
        changes = [
            lambda rows: rows[0]["positions"].__setitem__(0, False),
            lambda rows: rows[0]["positions"].__setitem__(1, 0),
            lambda rows: rows[0]["positions"].__setitem__(-1, rows[0]["bytes"] - 1),
            lambda rows: rows[1].__setitem__("offset", rows[1]["offset"] + 1),
            lambda rows: rows[0].__setitem__("slots", True),
            lambda rows: rows[0]["slots"].append("invalid"),
            lambda rows: rows[0]["codec"].__setitem__("key", [0, 2**32]),
            lambda rows: rows[0]["codec"].__setitem__("key", [True, 0]),
            lambda rows: rows[0]["codec"].__setitem__("rotate", 7),
            lambda rows: rows[0]["codec"].__setitem__("multiply", 2),
            lambda rows: rows[0]["codec"]["tokens"].__setitem__(0, True),
            lambda rows: rows[0]["codec"]["tokens"].__setitem__(0, rows[0]["codec"]["tokens"][1]),
            lambda rows: rows[0]["codec"].__setitem__("unexpected", 1),
        ]
        paths = []
        for index, mutate in enumerate(changes):
            path = directory / ("malformed-" + str(index) + ".cjs")
            path.write_text(rewrite_metadata(runtime, mutate, repair=True), encoding="utf-8"); paths.append(path)
        self.node("\n".join("assert.throws(() => " + self.require(path) + ", /metadata/);" for path in paths))

    def test_coverage_hashes_bind_actual_function_slices_and_metadata(self):
        _, _, coverage, runtime = self.emit("function helper(x) { return x + 4; } function core(x) { return helper(x) - 1; }")
        _, functions, blob = metadata(runtime)
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
        self.assertEqual(coverage["encoded_sha256"], hashlib.sha256(blob).hexdigest())
        self.assertEqual(coverage["metadata_sha256"], hashlib.sha256(canonical(functions)).hexdigest())
        for evidence in coverage["functions"].values():
            fn = functions[evidence["vm_function_id"]]
            segment = blob[fn["offset"]:fn["offset"] + fn["bytes"]]
            self.assertEqual(evidence["encoded_sha256"], hashlib.sha256(segment).hexdigest())
            self.assertEqual(evidence["encoded_bytes"], len(segment))
            self.assertEqual(evidence["codec_sha256"], hashlib.sha256(canonical(fn["codec"])).hexdigest())
            self.assertEqual(evidence["instruction_offsets_sha256"], hashlib.sha256(canonical(fn["positions"])).hexdigest())
            self.assertEqual(evidence["instruction_count"], len(fn["positions"]) - 1)

    def test_number_special_values_negative_zero_and_ieee_arithmetic(self):
        cases = "[[-0,0],[0,-0],[NaN,2],[Infinity,2],[-Infinity,Infinity],[Number.MIN_VALUE,2],[Number.MAX_VALUE,2],[2**53,1],[-3,2]]"
        self.compare("function core(x,y) { return x === y ? -x : x / y; }", cases)
        self.compare("function core(x,y) { return Math.fround(x) + Math.sign(y); }", cases)
        self.compare("function core(x,y) { return (x ** y) % 7; }", cases)

    def test_number_tagged_literals_preserve_nan_infinity_negative_zero(self):
        self.compare("function core(x) { if (x === 0) return -0; if (x === 1) return NaN; if (x === 2) return Infinity; return -Infinity; }",
                     "[[0],[1],[2],[3]]")

    def test_bigint_large_values_helpers_shifts_and_conversion_exceptions(self):
        literal = hex((1 << 4095) + 17) + "n"
        source = "const C = " + literal + "; function helper(x) { return x * C; } function core(x,y) { return (helper(x) + C) << y; }"
        self.compare(source, "[[0n,0n],[1n,1n],[-(1n<<5000n),3n],[(1n<<6000n)+19n,5n],[7n,-2n]]")
        self.compare("function core(x,y) { return x / y; }", "[[17n,3n],[-17n,3n],[1n,0n],[1n,2],[2,1n]]")
        self.compare("function core(x,y) { return x >>> y; }", "[[1n,0n],[1,0],[1,1n]]")
        self.compare("function core(x,y) { return BigInt(x) + y; }", "[[1,2n],[1.5,2n],[Infinity,2n],[NaN,2n],[true,2n]]")
        self.compare("function core(x,y) { return +x; }", "[[1n,0],[1,0],[false,0]]")

    def test_boolean_short_circuit_nullish_and_helper_arity(self):
        self.compare("function empty() { return undefined; } function missing() { return null; } function helper(x) { return !x; } function core(x,y) { return x ? (empty() ?? missing() ?? helper(y)) : (x && (1n / 0n)); }",
                     "[[false,0],[true,0],[true,1],[0,false],[1,true],[-0,1]]")
        directory, _, _, _ = self.emit("function empty() { return null; } function core(x) { return empty() ?? x; }")
        self.node("const subject = " + self.require(directory / "protected.cjs") + ";\n"
                  "assert.equal(subject.core.length, 1);\nassert.equal(subject.core(true), true);\n"
                  "assert.throws(() => subject.core(null), TypeError);\nassert.throws(() => subject.core({}), TypeError);")

    def test_nested_loops_updates_lexical_scope_and_exception_classes(self):
        source = """function helper(x) { return (x ^ 31) - 7; }
function core(x,y) {
  let total = 0;
  for (let i=0; i<(x&7); ++i) {
    if (i === y) continue;
    let j = 0;
    while (j < 3) { j++; if (j === y) break; total += helper(i*j); }
    if (total > 500) break;
  }
  do { total++; } while (total < -10);
  return total;
}"""
        cases = "[" + ",".join(json.dumps([x, y]) for x in (-5, 0, 3, 8, 15) for y in (-1, 0, 1, 2, 4)) + "]"
        self.compare(source, cases)
        self.compare("function core(x,y) { if (x>0) { const value=y; value += 1; } return y; }", "[[-1,0],[1,7]]")
        self.compare("function core(x,y) { if (x>0) { return value; let value=y; } return x; }", "[[-1,0],[1,7]]")
        self.compare("function core(x,y) { let value=x; if(y) { let value=y; value++; } return value; }", "[[-1,0],[1,7]]")

    def test_all_native_binary_operator_and_builtin_cases_preserved(self):
        cases = "[[-17,3],[17,-3],[-0,0],[true,false],[2**40,31],[2**53,1],[NaN,1],[Infinity,2]]"
        for operator in ("+", "-", "*", "/", "%", "**", "<<", ">>", ">>>", "&", "|", "^",
                         "==", "!=", "===", "!==", "<", "<=", ">", ">="):
            with self.subTest(operator=operator):
                self.compare("function core(x,y) { return x " + operator + " y; }", cases)
        self.compare("function core(x,y) { return BigInt.asIntN(8,x) + BigInt.asUintN(8,y); }",
                     "[[1n,2n],[-999n,999n],[(1n<<100n)+7n,-(1n<<100n)+9n]]")
        self.compare("function core(x,y) { return Number.isFinite(x) && Number.isNaN(y); }", cases)
        self.compare("function core(x,y) { return Math.imul(x,y); }", cases)

    def test_typescript_and_exported_builtin_names_do_not_shadow_runtime(self):
        names = ["Object", "Math", "Number", "BigInt", "Boolean", "JSON", "Buffer", "Array", "Error", "Set", "process", "enter"]
        source = "\n".join("export function " + name + "(x: number,y: number): number { return x+y; }" for name in names)
        self.compare(source, "[[1,2],[-0,-0],[NaN,1],[Infinity,-Infinity]]", names, "typescript")
        self.compare("export function helper(x: bigint): bigint { return x*3n; } export function core(x: bigint,y: bigint): bigint { return helper(x)^y; }",
                     "[[1n,2n],[-7n,3n],[(1n<<100n)+17n,19n]]", language="typescript")

    def test_metadata_and_blob_unchanged_across_nested_calls(self):
        directory, _, _, _ = self.emit("function helper(x) { return x*3; } function core(x) { let total=0; for(let i=0;i<5;i++) total+=helper(x+i); return total; }")
        self.node("const subject = " + self.require(directory / "inspected.cjs") + ";\n"
                  "const api = subject.__owned, bytes = api.blob.toString('hex'), data = JSON.stringify(api.functions);\n"
                  "for(const value of [-17,0,true,NaN,Infinity,-0]) subject.core(value);\n"
                  "assert.equal(api.blob.toString('hex'), bytes);\nassert.equal(JSON.stringify(api.functions), data);")

    def test_no_original_body_helper_names_or_executable_source_fallback(self):
        _, _, coverage, runtime = self.emit("function private_business_helper(x) { let peculiar_local=x*991; return peculiar_local+17; } function core(x) { return private_business_helper(x); }")
        for fragment in ("private_business_helper", "peculiar_local", "x*991", "eval(", "Function(", "new Function"):
            self.assertNotIn(fragment, runtime)
        self.assertFalse(coverage["original_selected_bodies_in_protected_artifact"])


if __name__ == "__main__":
    unittest.main()
