"""Private build-format transformation tests; no attacks or model execution."""

import ctypes
import copy
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

from antirea import diversify as d


TABLE = {0x02: "OP_PUSH_IMM32", 0x04: "OP_PUSH_REG", 0x05: "OP_POP_REG",
         0x10: "OP_ADD", 0x40: "OP_JMP", 0x44: "OP_RET", 0x60: "OP_ZEXT",
         0x70: "OP_LOAD_ARG", 0xff: "OP_NOP"}
KEY = 0x0123456789abcdef
ROOT = Path(__file__).resolve().parents[1]
CLANG = ROOT / ".tools/clang+llvm-22.1.0-x86_64-pc-windows-msvc/bin/clang.exe"
RUNTIME = ROOT / ".tools/kagura/runtime/core/vm_interpreter.c"


def stock(data, key=KEY):
    return bytes(value ^ ((key >> (8 * (i & 7))) & 255) for i, value in enumerate(data))


def decode_generated_fetch(data, key, params):
    """Test inverse of the byte codec only, not a VM/target reimplementation."""
    result = bytearray()
    for position, byte in enumerate(data[4:], 4):
        mixed = (position * params["multiply"] + params["add"]) & 0xffffffff
        mixed ^= mixed >> 13
        mixed = (mixed * params["mix"]) & 0xffffffff
        mixed ^= mixed >> 17
        mask = (mixed ^ (key >> (8 * (position & 7)))) & 255
        r = ((position + params["rotate"]) % 7) + 1
        value = byte ^ ((mixed >> 8) & 255)
        value = ((value >> r) | (value << (8 - r))) & 255
        result.append((value - mask) & 255)
    return bytes(result)


def ir_fixture(data, key=KEY):
    return (f'@kagura_vm_bc_1 = private constant [{len(data)} x i8] c"{d.llvm_string(data)}"\n'
            f'@kagura_vm_key_1 = private constant i64 {key}\n'
            'define i64 @antirea_score(i32 %a, i32 %b) {\n'
            f'  %r = call i64 @kagura_vm_execute(ptr @kagura_vm_bc_1, i32 {len(data)}, ptr null, i32 0, ptr null, i32 0, i64 %key)\n'
            '  ret i64 %r\n}\n'
            'declare i64 @kagura_vm_execute(ptr, i32, ptr, i32, ptr, i32, i64)\n')


def two_function_ir(first_data, second_data=None):
    second = ir_fixture(first_data if second_data is None else second_data)
    second = second.replace('_bc_1', '_bc_22').replace('_key_1', '_key_22').replace('@antirea_score', '@antirea_other')
    second = second[:second.index('declare i64')]
    return ir_fixture(first_data) + second


def read_instruction_operands(decoded, offset, widths, key, params):
    """Read one codec record in isolation, including a direct branch entry."""
    token = int.from_bytes(decoded[offset - 4:offset - 2], "big")
    state = ((offset * params["operand_multiply"]) ^ token ^ key ^ (key >> 32)
             ^ params["operand_add"]) & 0xffffffff
    cursor = offset - 2
    values = []
    for width in widths:
        value = 0
        for _ in range(width):
            byte = decoded[cursor] ^ ((state ^ (state >> 11) ^ (state >> 23)) & 255)
            value = (value << 8) | byte
            state = (((((state << 5) | (state >> 27)) & 0xffffffff)
                      * params["operand_multiply"]) + byte + params["operand_add"]) & 0xffffffff
            cursor += 1
        values.append(value)
    return tuple(values)


class DiversificationTests(unittest.TestCase):
    RR = bytes([0x04, 0, 0x04, 1, 0x10, 64, 0x05, 2, 0x04, 2, 0x44])

    def test_llvm_escape_roundtrip_all_bytes_and_rejects_bad_escape(self):
        data = bytes(range(256))
        self.assertEqual(d.llvm_bytes(d.llvm_string(data)), data)
        self.assertEqual(d.llvm_bytes('a\\00\\22'), b'a\0"')
        self.assertEqual(d.llvm_bytes(r'\\\1A'), b'\\\x1a')
        for text in ('\\', '\\A', '\\XX', '한'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                d.llvm_bytes(text)

    def test_decode_rejects_unknown_truncated_width_and_bad_branch_boundary(self):
        for plain in (b'\xfe', b'\x02\x01', b'\x10\x00', b'\x10\x41',
                      b'\x40\x01\x00\x00\x00\x44'):
            with self.subTest(plain=plain), self.assertRaises(ValueError):
                d.decode_stock(stock(plain), KEY, TABLE)

    def test_real_arithmetic_fusion_removes_three_dispatches(self):
        before = d.decode_stock(stock(self.RR), KEY, TABLE)
        after = d.fuse(before)
        self.assertEqual([item.name for item in after], ["F_RR_ADD", "OP_PUSH_REG", "OP_RET"])
        self.assertEqual(after[0].values, (2, 0, 64, 1))
        self.assertEqual(after[0].originals, 4)
        handler = d.fused_handler("F_RR_ADD")
        self.assertIn("f.regs[d]=vm_zext(a + b,w)", handler)
        self.assertNotIn("vm_push", handler)
        self.assertNotIn("vm_pop", handler)

    def test_immediate_fusion_preserves_unsigned_immediate_and_operand_order(self):
        plain = bytes([4, 9, 2]) + (0xffffffff).to_bytes(4, "little") + bytes([0x10, 32, 5, 7, 4, 7, 0x44])
        fused = d.fuse(d.decode_stock(stock(plain), KEY, TABLE))
        self.assertEqual(fused[0].name, "F_RI_ADD")
        self.assertEqual(fused[0].values, (7, 9, 32, 0xffffffff))
        self.assertEqual(fused[0].widths, (1, 1, 1, 8))

    def test_argument_zext_and_move_fusions_are_direct(self):
        plain = bytes([0x70, 1, 0x60, 5, 9, 4, 9, 5, 10, 4, 10, 0x44])
        fused = d.fuse(d.decode_stock(stock(plain), KEY, TABLE))
        self.assertEqual([x.name for x in fused[:2]], ["F_ARG", "F_MOV"])
        self.assertEqual(fused[0].values, (9, 1))
        self.assertEqual(fused[0].originals, 3)

    def test_never_fuses_across_a_branch_target(self):
        # Jump enters ADD inside an otherwise fusible four-instruction group.
        plain = b'\x40' + (9).to_bytes(4, "little") + self.RR
        fused = d.fuse(d.decode_stock(stock(plain), KEY, TABLE))
        self.assertFalse(any(x.name == "F_RR_ADD" for x in fused))
        self.assertIn(9, [x.offset for x in fused])

    def test_chain_preserves_aliasing_write_order_and_branch_entry(self):
        # First writes reg 2; second reads/writes reg 2 and uses it again as RHS.
        plain = self.RR[:8] + bytes([4, 2, 4, 2, 0x10, 32, 5, 2, 4, 2, 0x44])
        items = d.decode_stock(stock(plain), KEY, TABLE)
        paired = d.fuse(items)
        self.assertEqual(paired[0].name, 'F_CHAIN_RR_ADD__RR_ADD')
        self.assertEqual(paired[0].originals, 8)
        self.assertEqual(paired[0].values, (2, 0, 64, 1, 2, 2, 32, 2))
        handler = d.fused_handler(paired[0].name)
        self.assertEqual(handler.count('f.regs[d]='), 2)
        self.assertEqual(handler.count('{ uint8_t d='), 2)
        self.assertNotIn('bc_opcode', handler)
        # The second group remains independently reachable when a branch enters it.
        jumped = b'\x40' + (13).to_bytes(4, 'little') + plain
        separate = d.fuse(d.decode_stock(stock(jumped), KEY, TABLE))
        self.assertFalse(any(x.name.startswith('F_CHAIN_') for x in separate))
        self.assertIn(13, [x.offset for x in separate])

    def test_chain_codec_and_metadata_bind_both_operand_sequences(self):
        plain = self.RR[:8] * 2 + bytes([4, 2, 0x44])
        items = d.fuse(d.decode_stock(stock(plain), KEY, TABLE))
        params = d.parameters(17, {x.name for x in items})
        encoded, mapping = d.emit(items, KEY, params)
        decoded = decode_generated_fetch(encoded, KEY, params)
        self.assertEqual(read_instruction_operands(decoded, mapping[0], items[0].widths, KEY, params),
                         items[0].values)
        _, manifest = d.transform_ir(ir_fixture(stock(plain)), TABLE, 17)
        self.assertEqual(manifest['chained_register_fusion']['groups'], 1)
        self.assertEqual(manifest['blobs'][0]['absorbed_dispatches'], 7)

    def test_branch_to_first_fused_instruction_is_relocated_exactly(self):
        plain = b'\x40' + (5).to_bytes(4, "little") + self.RR
        fused = d.fuse(d.decode_stock(stock(plain), KEY, TABLE))
        params = d.parameters(1729, {x.name for x in fused})
        encoded, mapping = d.emit(fused, KEY, params)
        decoded = decode_generated_fetch(encoded, KEY, params)
        self.assertEqual(mapping[0], 4)
        self.assertEqual(mapping[5], 10)
        self.assertEqual(read_instruction_operands(decoded, 4, (4,), KEY, params), (mapping[5],))
        self.assertEqual(int.from_bytes(decoded[6:8], "big"), params["tokens"]["F_RR_ADD"])
        self.assertEqual(read_instruction_operands(decoded, mapping[5], (1, 1, 1, 1), KEY, params),
                         fused[1].values)

    def test_operand_context_resets_for_back_edges_and_all_operand_widths(self):
        # Codec records only: no target algorithm or VM execution.
        items = [d.Instruction(0, "F_CONST", (17, 0xffffffffffffffff), (1, 8)),
                 d.Instruction(10, "OP_PUSH_IMM16", (0xabcd,), (2,)),
                 d.Instruction(13, "OP_JMP", (0,), (4,))]
        for seed in (1, 7, 1729, 0x7fffffff):
            params = d.parameters(seed, {item.name for item in items})
            encoded, mapping = d.emit(items, KEY, params)
            decoded = decode_generated_fetch(encoded, KEY, params)
            for item in reversed(items):
                expected = (mapping[0],) if item.name == "OP_JMP" else item.values
                self.assertEqual(read_instruction_operands(decoded, mapping[item.offset], item.widths,
                                                           KEY, params), expected)
            # Same instruction can be re-entered after another record without stale state.
            self.assertEqual(read_instruction_operands(decoded, mapping[0], items[0].widths,
                                                       KEY, params), items[0].values)

    def test_position_codec_roundtrips_and_header_is_only_format_guard(self):
        params = d.parameters(123, {"OP_RET"})
        plain = bytes(range(256)) * 3
        encoded = bytes([(KEY & 255) ^ 0xfe] + params["header"]) + d.encode_fetch(plain, KEY, params)
        self.assertEqual(decode_generated_fetch(encoded, KEY, params), plain)
        self.assertEqual(encoded[0] ^ (KEY & 255), 0xfe)
        self.assertNotEqual(encoded[4:260], encoded[260:516])

    def test_seed_changes_contract_but_same_seed_is_reproducible(self):
        ir = ir_fixture(stock(self.RR))
        one, first = d.transform_ir(ir, TABLE, 7)
        repeated, second = d.transform_ir(ir, TABLE, 7)
        other, third = d.transform_ir(ir, TABLE, 8)
        self.assertEqual(one, repeated)
        self.assertEqual(first, second)
        self.assertNotEqual(one, other)
        self.assertNotEqual(first["parameters"]["tokens"], third["parameters"]["tokens"])
        self.assertNotIn("@kagura_vm_execute", one)
        self.assertIn("@" + first["dispatcher_symbol"], one)
        self.assertEqual(first["blobs"][0]["absorbed_dispatches"], 3)
        self.assertEqual(first["external_attack_evaluation"], "not_evaluated")

    def test_no_fusion_empty_blob_and_unsupported_key_fail_closed(self):
        for ir in (ir_fixture(stock(bytes([0x70, 0, 0x44]))), "",
                   ir_fixture(stock(self.RR)).replace("private constant i64", "private global i64")):
            with self.subTest(ir=ir[:60]), self.assertRaises(ValueError):
                d.transform_ir(ir, TABLE, 1)

    def test_duplicate_or_reserved_stock_opcode_table_is_rejected(self):
        for source in ("", "KAGURA_VM_OP(OP_ONE, 0xfe)",
                       "KAGURA_VM_OP(OP_ONE, 0x01)\nKAGURA_VM_OP(OP_TWO, 0x01)"):
            with self.subTest(source=source), self.assertRaises(ValueError):
                d.opcode_table(source)

    def test_multiple_blobs_rewrite_all_sizes_and_calls_without_offset_drift(self):
        first = ir_fixture(stock(self.RR))
        second = ir_fixture(stock(self.RR, 3), key=3).replace("_bc_1", "_bc_22").replace("_key_1", "_key_22")
        second = second.replace("@antirea_score", "@antirea_other")
        second = second[:second.index("declare i64")]
        transformed, manifest = d.transform_ir(first + second, TABLE, 71)
        self.assertEqual([x["global"] for x in manifest["blobs"]], ["kagura_vm_bc_1", "kagura_vm_bc_22"])
        self.assertEqual(manifest["engine_mode"], "per_function_indirect")
        self.assertEqual(len(d.inspect_vm_bindings(transformed, manifest)), 2)
        for record in manifest["blobs"]:
            self.assertIn(f'@{record["global"]} = private constant [{record["encoded_bytes"]} x i8]', transformed)
            self.assertIn(f'ptr @{record["global"]}, i32 {record["encoded_bytes"]}', transformed)

    def test_multi_vm_distinct_contracts_same_input_and_reproducible_seed(self):
        source = two_function_ir(stock(self.RR))
        ir, manifest = d.transform_ir(source, TABLE, 1729)
        again, repeated = d.transform_ir(source, TABLE, 1729)
        self.assertEqual((ir, manifest), (again, repeated))
        first, second = manifest['engines']
        self.assertNotEqual(first['parameters']['tokens'], second['parameters']['tokens'])
        for field in ('multiply', 'add', 'mix', 'operand_multiply', 'operand_add'):
            self.assertNotEqual(first['parameters'][field], second['parameters'][field])
        self.assertNotEqual(first['codec_sha256'], second['codec_sha256'])
        self.assertNotEqual(manifest['blobs'][0]['encoded_sha256'], manifest['blobs'][1]['encoded_sha256'])
        self.assertEqual(manifest['blobs'][0]['original_sha256'], manifest['blobs'][1]['original_sha256'])
        self.assertEqual(manifest['hardening_capabilities']['independent_vm_parameter_sets'], 2)
        self.assertFalse(manifest['hardening_capabilities']['layers']['multi_vm_indirect_dispatch']['source_emitted'])
        self.assertEqual(ir.count('load volatile ptr'), 2)
        self.assertEqual(ir.count('call i64 %antirea_vm_target_'), 2)
        self.assertNotIn('call i64 @antirea_dispatch_', ir)

    def test_single_or_disabled_multi_vm_preserves_legacy_direct_shape(self):
        for source, options, count in ((ir_fixture(stock(self.RR)), {}, 1),
                                       (two_function_ir(stock(self.RR)), {'enable_hardening': False}, 2),
                                       (two_function_ir(stock(self.RR)), {'enabled_layers': []}, 2)):
            with self.subTest(options=options, count=count):
                ir, manifest = d.transform_ir(source, TABLE, 1, **options)
                self.assertNotIn('engines', manifest)
                self.assertNotIn('engine_mode', manifest)
                self.assertEqual(ir.count('call i64 @' + manifest['dispatcher_symbol']), count)
                self.assertEqual(manifest['hardening_capabilities']['independent_vm_parameter_sets'], 1)

    def test_transform_disabled_hardening_still_validates_explicit_selection(self):
        for source in (ir_fixture(stock(self.RR)), two_function_ir(stock(self.RR))):
            for layers in (['anti_tamper'], ['multi_vm_indirect_dispatch'], ['unknown'], 'anti_tamper', [1]):
                with self.subTest(layers=layers), self.assertRaises(ValueError):
                    d.transform_ir(source, TABLE, 17, enable_hardening=False, enabled_layers=layers)
            disabled, _ = d.transform_ir(source, TABLE, 17, enable_hardening=False)
            explicit_empty, _ = d.transform_ir(source, TABLE, 17, enable_hardening=False, enabled_layers=[])
            self.assertEqual(disabled, explicit_empty)

    @unittest.skipUnless(RUNTIME.exists(), 'pinned runtime needed for generate selection regression')
    def test_generate_rejects_conflicting_selection_before_writing_artifacts(self):
        opcodes = ROOT / '.tools/kagura/include/kagura/VMOpcodes.def'
        with tempfile.TemporaryDirectory(prefix='antirea-selection-test-') as temporary:
            base = Path(temporary)
            input_ir = base / 'input.ll'
            input_ir.write_text(ir_fixture(stock(self.RR)), encoding='utf-8')
            output = base / 'generated'
            with self.assertRaisesRegex(ValueError, 'conflicts'):
                d.generate(input_ir, RUNTIME, opcodes, output, 17,
                           enable_hardening=False, enabled_layers=['anti_tamper'])
            self.assertFalse(output.exists())

    def test_multi_vm_keeps_trivial_function_without_claiming_fusion_there(self):
        source = two_function_ir(stock(self.RR), stock(bytes([0x70, 0, 0x44])))
        ir, manifest = d.transform_ir(source, TABLE, 19)
        self.assertEqual(len(d.inspect_vm_bindings(ir, manifest)), 2)
        self.assertEqual(manifest['blobs'][1]['fused_groups'], 0)
        self.assertGreater(manifest['blobs'][0]['fused_groups'], 0)

    def test_multi_vm_binding_rejects_changed_slot_call_blob_and_codec(self):
        ir, manifest = d.transform_ir(two_function_ir(stock(self.RR)), TABLE, 71)
        first, second = manifest['engines']
        broken = [ir.replace('load volatile ptr', 'load ptr', 1),
                  ir.replace('ptr @' + first['dispatch_slot'], 'ptr @' + second['dispatch_slot'], 1),
                  ir.replace('global ptr @' + first['dispatcher_symbol'], 'global ptr @' + second['dispatcher_symbol'], 1),
                  ir.replace('i32 ' + str(manifest['blobs'][0]['encoded_bytes']) + ',', 'i32 999,', 1),
                  ir.replace(d.llvm_string(d.llvm_bytes(d._BLOB.search(ir).group(4))), r'\00', 1)]
        for altered in broken:
            with self.subTest(altered=altered[-150:]), self.assertRaises(ValueError):
                d.inspect_vm_bindings(altered, manifest)
        for field in ('parameters', 'dispatch_slot', 'function', 'blob_global', 'dispatcher_symbol'):
            changed = copy.deepcopy(manifest)
            changed['engines'][1][field] = changed['engines'][0][field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                d.inspect_vm_bindings(ir, changed)

    @unittest.skipUnless(RUNTIME.exists(), 'pinned runtime needed for multi-engine emission')
    def test_multi_vm_runtime_has_namespaced_helpers_and_per_engine_checksum(self):
        ir, manifest = d.transform_ir(two_function_ir(stock(self.RR)), TABLE, 71)
        runtime = d.runtime_for_manifest(RUNTIME.read_text(encoding='utf-8'), manifest)
        for engine in manifest['engines']:
            self.assertEqual(runtime.count('uint64_t ' + engine['dispatcher_symbol'] + '('), 1)
            self.assertEqual(runtime.count(engine['integrity_checker_symbol'] + '('), 2)
            self.assertIn(engine['namespace_prefix'] + 'bc_require', runtime)
            self.assertIn(engine['namespace_prefix'] + 'VMFrame', runtime)
            self.assertEqual(len(engine['parameters']['hardening']['bytecode_integrity']), 1)
        self.assertNotIn('uint64_t kagura_vm_execute(', runtime)
        self.assertNotIn('} VMFrame;', runtime)
        from antirea.hardening import hardening_capabilities
        caps = hardening_capabilities(manifest['parameters']['hardening'], runtime_source=runtime,
                                      core_ir=ir, blob_count=2, vm_engines=manifest['engines'])
        self.assertTrue(caps['layers']['multi_vm_indirect_dispatch']['source_emitted'])
        self.assertEqual(caps['verified_retained_components'], [])

    @unittest.skipUnless(CLANG.exists() and RUNTIME.exists(), 'portable Clang and pinned runtime required')
    def test_compiled_multi_vm_retains_indirect_calls_and_each_checksum(self):
        from antirea.hardening import inspect_hardening_artifact
        original = two_function_ir(stock(self.RR)).replace('i64 %key)', f'i64 {KEY})')
        core, manifest = d.transform_ir(original, TABLE, 17,
                                        enabled_layers=['multi_vm_indirect_dispatch', 'anti_tamper'])
        runtime = d.runtime_for_manifest(RUNTIME.read_text(encoding='utf-8'), manifest)
        # Header-independent compile: use the same generated runtime, supplying
        # only standard typedefs/prototypes so the test needs no installed SDK.
        prelude = ('typedef unsigned char uint8_t; typedef unsigned short uint16_t; '
                   'typedef unsigned int uint32_t; typedef unsigned long long uint64_t; '
                   'typedef int int32_t; typedef long long int64_t; '
                   'typedef unsigned long long uintptr_t; typedef unsigned long long size_t; '
                   'void abort(void); void *memset(void *,int,size_t); void *memcpy(void *,const void *,size_t);\n')
        runtime = prelude + re.sub(r'(?m)^#include[^\n]*', '', runtime)
        compiled = []
        for language, source in (('c', runtime), ('ir', core)):
            result = subprocess.run([str(CLANG), '-O1', '-fno-inline', '-S', '-emit-llvm',
                                     '-x', language, '-', '-o', '-'], input=source,
                                    text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            compiled.append(result.stdout)
        runtime_ir, core_ir = compiled
        self.assertEqual(len(d.inspect_vm_bindings(core_ir, manifest)), 2)
        evidence = inspect_hardening_artifact(manifest, runtime_ir, core_ir)
        self.assertTrue(evidence['layers']['multi_vm_indirect_dispatch']['runtime_component_retained'])
        self.assertTrue(evidence['layers']['anti_tamper']['runtime_component_retained'])
        checks = evidence['layers']['anti_tamper']['retained_ir_evidence']['engines']
        self.assertEqual(len(checks), 2)
        self.assertTrue(all(item['observed'] for item in checks))
        self.assertEqual(evidence['external_resistance'], 'not_evaluated')
        second = manifest['engines'][1]
        changed = runtime_ir.replace('@' + second['integrity_checker_symbol'] + '(', '@missing_checksum(')
        self.assertFalse(inspect_hardening_artifact(manifest, changed, core_ir)['layers']['anti_tamper']['runtime_component_retained'])
        altered = core_ir.replace('load volatile ptr', 'load ptr', 1)
        self.assertFalse(inspect_hardening_artifact(manifest, runtime_ir, altered)['layers']['multi_vm_indirect_dispatch']['runtime_component_retained'])

    def test_missing_or_duplicate_wrapper_call_refuses_to_transform(self):
        original = ir_fixture(stock(self.RR))
        call = next(line for line in original.splitlines() if "call i64" in line)
        for value in (original.replace(call, ""), original.replace(call, call + "\n" + call)):
            with self.subTest(value=value[:50]), self.assertRaises(ValueError):
                d.transform_ir(value, TABLE, 17)

    def test_runtime_specialization_prunes_unused_base_handlers(self):
        source = '''#include "../internal.h"
enum vm_opcode {
#include "kagura/VMOpcodes.def"
};
#define KAGURA_VM_LIMIT(CppName, CName, Value) CName = Value,
enum vm_limit {
#include "kagura/VMOpcodes.def"
};
typedef struct {
    uint32_t pc;
} VMFrame;
static inline uint8_t bc_u8(VMFrame *f) { return 0; }
/* ── Width helpers */
static inline void vm_push(VMFrame *f, uint64_t v) { }
static inline uint64_t vm_pop(VMFrame *f) { return 0; }
static inline uint64_t vm_peek(VMFrame *f) { return 0; }
static inline unsigned vm_width(VMFrame *f) { return 64; }
static inline uint64_t vm_mask(unsigned w) { return 0; }
static inline uint64_t vm_zext(uint64_t v, unsigned w) { return v; }
static inline int64_t vm_sext(uint64_t v, unsigned w) { return v; }
static inline unsigned vm_shamt(uint64_t v, unsigned w) { return 0; }
uint64_t kagura_vm_execute(void) {
    VMFrame f;
    f.key     = key;
    f.pc      = 0;
    uint8_t op = bc_u8(&f);
        switch (op) {
        case OP_PUSH_REG: vm_push(&f, f.regs[bc_u8(&f)]); break;
        case OP_RET: return vm_pop(&f);
        case OP_NOP: break;
        default: abort();
        }
}
'''
        params = d.parameters(7, {"F_RR_ADD", "OP_RET"})
        generated = d.specialize_runtime(source, params, "antirea_test")
        self.assertIn("uint64_t antirea_test(", generated)
        self.assertIn("uint16_t op = bc_opcode(&f)", generated)
        self.assertIn("uint32_t operand_state;", generated)
        self.assertIn("always_inline", generated)
        self.assertIn("case F_RR_ADD:", generated)
        self.assertIn("case OP_RET:", generated)
        self.assertNotIn("case OP_PUSH_REG:", generated)
        self.assertNotIn("case OP_NOP:", generated)
        self.assertNotIn('#include "kagura/VMOpcodes.def"', generated)
        self.assertIn("f.pc      = 4;", generated)
        self.assertIn("static inline unsigned vm_width(", generated)
        for name in d.INTEGRATED_HELPERS:
            self.assertRegex(generated, r"always_inline\)\) inline \w+ vm_" + name + r"\(")
        self.assertEqual(generated.count("static __attribute__((always_inline)) inline "), 13)
        self.assertIn("f->pc > f->bc_size || width > f->bc_size-f->pc", generated)
        for width, function in ((1, "bc_u8"), (2, "bc_u16"), (4, "bc_u32"), (8, "bc_u64"), (2, "bc_opcode")):
            body = re.search(r"inline uint\d+_t " + function + r"\(VMFrame \*f\) \{(.*?)\n\}", generated, re.S)[1]
            self.assertIn(f"bc_require(f, {width}u);", body)
            self.assertLess(body.index("bc_require"), body.index("_unchecked"))
        # Checked multi-byte reads only use unchecked scalar internals after
        # the complete span check, rather than nesting per-byte branches.
        self.assertIn("bc_require(f, 8u);\n    uint64_t hi=bc_u32_unchecked(f);", generated)

    def test_enabled_layers_propagate_and_legacy_applied_list_is_not_requested_list(self):
        original = ir_fixture(stock(self.RR))
        none, no_manifest = d.transform_ir(original, TABLE, 7, enabled_layers=[])
        selected, manifest = d.transform_ir(original, TABLE, 7, enabled_layers=["anti_tamper"])
        self.assertNotIn("__antirea_decoy", none)
        self.assertNotIn("__antirea_decoy", selected)
        self.assertEqual(no_manifest["requested_hardening_layers"], [])
        self.assertEqual(manifest["requested_hardening_layers"], ["anti_tamper"])
        self.assertEqual(manifest["hardening_layers"], [])
        self.assertTrue(manifest["parameters"]["hardening"]["bytecode_integrity"])
        self.assertIn("bytecode_integrity_tag", manifest["blobs"][0])
        self.assertNotIn("header_integrity_tag", no_manifest["blobs"][0])
        self.assertFalse(manifest["hardening_capabilities"]["layers"]["iat_api_hiding"]["requested"])

    def test_disable_hardening_cannot_silently_override_specific_requests(self):
        with self.assertRaises(ValueError):
            d.parameters(1, {"OP_RET"}, enable_hardening=False, enabled_layers=["anti_tamper"])
        self.assertNotIn("hardening", d.parameters(1, {"OP_RET"}, enable_hardening=False))

    def test_ambiguous_key_length_integrity_bindings_fail_closed(self):
        one = ir_fixture(stock(self.RR))
        changed = bytearray(self.RR)
        changed[1] = 3
        two = ir_fixture(stock(changed)).replace("_bc_1", "_bc_2").replace("_key_1", "_key_2")
        two = two.replace("@antirea_score", "@antirea_other")
        two = two[:two.index("declare i64")]
        with self.assertRaisesRegex(ValueError, "Ambiguous"):
            d.transform_ir(one + two, TABLE, 7, enabled_layers=["anti_tamper"])
        # The format conversion itself remains available without this unsupported binding.
        _, manifest = d.transform_ir(one + two, TABLE, 7, enabled_layers=[])
        self.assertEqual(len(manifest["blobs"]), 2)


@unittest.skipUnless(os.name == "nt" and CLANG.exists() and RUNTIME.exists(), "local pinned Windows codec compiler required")
class CompiledScalarFetchTests(unittest.TestCase):
    """Execute the emitted fetch helpers, not a replacement VM or target algorithm."""

    def test_real_fetch_widths_feedback_positions_and_rejected_spans(self):
        original = RUNTIME.read_bytes()
        self.assertEqual(d.sha256(original), d.RUNTIME_SHA256)
        params = d.parameters(1739, {"F_CONST", "OP_RET"}, enable_hardening=False)
        runtime = d.specialize_runtime(original.decode(), params, "test_dispatch")
        readers = runtime[runtime.index("/* Check a complete scalar read"):runtime.index("/* ── Width helpers")]
        prelude = """typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
__declspec(noreturn) void abort(void) { __builtin_trap(); }
typedef struct { uint32_t pc,bc_size,operand_state; const uint8_t *bc; uint64_t key; } VMFrame;
"""
        wrapper = """
__declspec(dllexport) uint64_t read_scalar(const uint8_t *bytes, uint32_t size,
    uint64_t key, uint32_t position, uint32_t state, uint32_t width, uint32_t *out) {
    VMFrame f; f.bc=bytes; f.bc_size=size; f.key=key; f.pc=position; f.operand_state=state;
    uint64_t value;
    switch(width) { case 0: value=bc_opcode(&f); break; case 1: value=bc_u8(&f); break;
      case 2: value=bc_u16(&f); break; case 4: value=bc_u32(&f); break;
      case 8: value=bc_u64(&f); break; default: abort(); }
    out[0]=f.pc; out[1]=f.operand_state; return value;
}
"""
        with tempfile.TemporaryDirectory(prefix="antirea-scalar-codec-") as directory:
            dll_path = Path(directory) / "codec.dll"
            compiled = subprocess.run([str(CLANG), "-O1", "-x", "c", "-", "-shared", "-nostdlib",
                                       "-fuse-ld=lld", "-Wl,/NOENTRY", "-o", str(dll_path)],
                                      input=prelude + readers + wrapper, text=True, capture_output=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            dll = ctypes.CDLL(str(dll_path))
            try:
                read = dll.read_scalar
                read.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint32, ctypes.c_uint64,
                                 ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
                read.restype = ctypes.c_uint64
                # Multiple instruction positions exercise position/key-byte indexing;
                # sequential feedback is checked after every completed scalar.
                items = [d.Instruction(i, "F_CONST", ((i * 7919 + 255) & ((1 << (8 * width)) - 1),), (width,))
                         for i, width in enumerate([1, 2, 4, 8] * 8)]
                encoded, positions = d.emit(items, KEY, params)
                buffer = (ctypes.c_uint8 * len(encoded)).from_buffer_copy(encoded)
                out = (ctypes.c_uint32 * 2)()
                for item in reversed(items):
                    pos = positions[item.offset]
                    token = params["tokens"][item.name]
                    state = d.operand_context(pos, token, KEY, params)
                    self.assertEqual(read(buffer, len(encoded), KEY, pos, 0, 0, out), token)
                    self.assertEqual(list(out), [pos + 2, state])
                    value, width = item.values[0], item.widths[0]
                    self.assertEqual(read(buffer, len(encoded), KEY, pos + 2, state, width, out), value)
                    for byte in value.to_bytes(width, "big"):
                        state = d.operand_step(state, byte, params)
                    self.assertEqual(list(out), [pos + 2 + width, state])
            finally:
                import _ctypes
                _ctypes.FreeLibrary(dll._handle)
            # A trap is distinct from an access violation. Passing NULL ensures
            # invalid spans reach abort before any byte is fetched, even at u32 wrap.
            child = """import ctypes,sys
ctypes.windll.kernel32.SetErrorMode(0x8003)
d=ctypes.CDLL(sys.argv[1]); f=d.read_scalar
f.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_uint64,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p]
f.restype=ctypes.c_uint64
try:
    f(None,int(sys.argv[2]),0,int(sys.argv[3]),0,int(sys.argv[4]),None)
except OSError as error:
    if (error.winerror & 0xffffffff) == 0xc000001d:
        print('span_rejected_before_null_read')
        sys.exit(0)
    raise
sys.exit(3)
"""
            bad = [(width - 1, 0, width) for width in (1, 2, 4, 8)]
            bad += [(1, 0, 0), (0, 0xffffffff, 1), (0xffffffff, 0xffffffff, 2)]
            for size, position, width in bad:
                with self.subTest(size=size, position=position, width=width):
                    child_result = subprocess.run([sys.executable, "-I", "-S", "-c", child, str(dll_path),
                                                   str(size), str(position), str(width)],
                                                  capture_output=True, timeout=15)
                    self.assertEqual(child_result.returncode, 0, child_result.stderr)
                    self.assertIn(b"span_rejected_before_null_read", child_result.stdout)


if __name__ == "__main__":
    unittest.main()
