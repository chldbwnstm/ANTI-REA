"""SELECT/register fusion regressions; no compiler or target execution."""
import copy
import random
import unittest

from antirea import diversify as d

KEY = 0x0123456789ABCDEF
MASK = (1 << 64) - 1
TABLE = {0x0A: 'OP_SELECT', 0x05: 'OP_POP_REG', 0x04: 'OP_PUSH_REG',
         0x40: 'OP_JMP', 0x41: 'OP_JZ', 0x42: 'OP_JNZ', 0x44: 'OP_RET', 0x70: 'OP_LOAD_ARG'}


def stock_bytes(data, key=KEY):
    return bytes(byte ^ ((key >> (8 * (index & 7))) & 255) for index, byte in enumerate(data))


def decode(data):
    return d.decode_stock(stock_bytes(data), KEY, TABLE)


def tiny_ir(data):
    return (f'@kagura_vm_bc_1 = private constant [{len(data)} x i8] c"{d.llvm_string(data)}"\n'
            f'@kagura_vm_key_1 = private constant i64 {KEY}\n'
            'define i64 @owned_test(i64 %a) {\n'
            '  %key = load i64, ptr @kagura_vm_key_1\n'
            f'  %r = call i64 @kagura_vm_execute(ptr @kagura_vm_bc_1, i32 {len(data)}, '
            'ptr null, i32 0, ptr null, i32 0, i64 %key)\n'
            '  ret i64 %r\n}\n'
            'declare i64 @kagura_vm_execute(ptr, i32, ptr, i32, ptr, i32, i64)\n')


def original_pair(stack, registers, destination):
    stack, registers = list(stack), list(registers)
    false_value, true_value, condition = stack.pop(), stack.pop(), stack.pop()
    stack.append(true_value if condition else false_value)
    registers[destination] = stack.pop()
    return stack, registers


def fused_model(stack, registers, destination):
    stack, registers = list(stack), list(registers)
    condition, true_value, false_value = stack[-3:]
    del stack[-3:]
    # Independent mathematical selection, not a copied pop/push implementation.
    registers[destination] = int(condition != 0) * true_value + int(condition == 0) * false_value
    return stack, registers


class SelectFusionTests(unittest.TestCase):
    def test_minimal_two_instruction_group_preserves_destination_and_original_count(self):
        before = decode(bytes([0x0A, 5, 255, 4, 255, 0x44]))
        after = d.fuse(before)
        self.assertEqual([item.name for item in after], ['F_SELECT', 'OP_PUSH_REG', 'OP_RET'])
        self.assertEqual((after[0].offset, after[0].values, after[0].widths, after[0].originals), (0, (255,), (1,), 2))
        self.assertEqual(len(before) - len(after), 1)

    def test_handler_preserves_false_true_condition_pop_order_without_intermediate_push(self):
        body = d.fused_body('F_SELECT')
        self.assertEqual(body, 'uint8_t d=bc_u8(&f); uint64_t fv=vm_pop(&f), tv=vm_pop(&f), c=vm_pop(&f); f.regs[d]=c?tv:fv;')
        self.assertEqual(body.count('vm_pop(&f)'), 3)
        self.assertNotIn('vm_push', body)
        self.assertNotIn('bc_opcode', body)
        self.assertIn('case F_SELECT:', d.fused_handler('F_SELECT'))

    def test_zero_and_nonboolean_conditions_distinct_64bit_operands(self):
        for condition in (0, 1, 2, 255, 1 << 63, MASK):
            for true_value, false_value in ((0, MASK), (MASK, 0), (1 << 63, (1 << 63) - 1), (17, 17)):
                with self.subTest(condition=condition, operands=(true_value, false_value)):
                    stack = [987654321, condition, true_value, false_value]
                    registers = [MASK] * 256
                    old = original_pair(stack, registers, 29)
                    new = fused_model(stack, registers, 29)
                    self.assertEqual(old, new)
                    self.assertEqual(new[0], [987654321])
                    self.assertEqual(new[1][29], true_value if condition != 0 else false_value)

    def test_destination_may_alias_any_preloaded_operand_register(self):
        registers = list(range(256))
        for condition in (0, 2, MASK):
            registers[0:3] = [condition, MASK - 17, 0x123456789ABCDEF0]
            for destination in (0, 1, 2, 255):
                stack = [0xCAFE, *registers[:3]]
                before = copy.deepcopy((stack, registers))
                self.assertEqual(original_pair(stack, registers, destination), fused_model(stack, registers, destination))
                self.assertEqual((stack, registers), before)

    def test_independent_random_stack_register_states(self):
        rng = random.Random(20261031)
        for index in range(2048):
            registers = [rng.getrandbits(64) for _ in range(256)]
            condition = 0 if index % 3 == 0 else rng.getrandbits(64)
            stack = [rng.getrandbits(64), condition, rng.getrandbits(64), rng.getrandbits(64)]
            destination = rng.randrange(256)
            self.assertEqual(original_pair(stack, registers, destination), fused_model(stack, registers, destination))

    def test_branch_into_pop_inhibits_fusion(self):
        for jump in (0x40, 0x41, 0x42):
            plain = bytes([jump]) + (6).to_bytes(4, 'little') + bytes([0x0A, 5, 9, 4, 9, 0x44])
            with self.subTest(jump=jump):
                after = d.fuse(decode(plain))
                self.assertNotIn('F_SELECT', [item.name for item in after])
                self.assertIn(6, [item.offset for item in after])

    def test_branch_to_select_start_allows_group_and_keeps_relocation(self):
        plain = b'\x40' + (5).to_bytes(4, 'little') + bytes([0x0A, 5, 9, 4, 9, 0x44])
        after = d.fuse(decode(plain))
        self.assertEqual(after[1].name, 'F_SELECT')
        self.assertEqual(after[1].offset, 5)
        params = d.parameters(1729, {item.name for item in after})
        encoded, positions = d.emit(after, KEY, params)
        self.assertEqual(positions[0], 4)
        self.assertEqual(positions[5], 10)
        self.assertNotIn(6, positions)
        self.assertEqual(positions[8], 13)
        self.assertGreater(len(encoded), positions[8])

    def test_select_without_pop_does_not_fuse(self):
        after = d.fuse(decode(bytes([0x0A, 0x44])))
        self.assertEqual([item.name for item in after], ['OP_SELECT', 'OP_RET'])

    def test_no_fusion_gate_remains_fail_closed(self):
        ir = tiny_ir(stock_bytes(bytes([0x70, 0, 0x44])))
        with self.assertRaisesRegex(ValueError, 'No meaningful fusion'):
            d.transform_ir(ir, TABLE, 1729)

    def test_all_nonfusible_multi_function_module_still_fails(self):
        one = tiny_ir(stock_bytes(bytes([0x70, 0, 0x44])))
        two = one[:one.index('declare i64')].replace('_bc_1', '_bc_2').replace('_key_1', '_key_2').replace('@owned_test', '@second_test')
        with self.assertRaisesRegex(ValueError, 'No meaningful fusion'):
            d.transform_ir(one + two, TABLE, 1729)

    def test_select_fusion_manifest_counts_are_actual_not_requested(self):
        plain = bytes([0x70, 0, 0x70, 1, 0x70, 2, 0x0A, 5, 7, 4, 7, 0x44])
        _, manifest = d.transform_ir(tiny_ir(stock_bytes(plain)), TABLE, 1729)
        row = manifest['blobs'][0]
        self.assertEqual(row['fusion_counts'], {'F_SELECT': 1})
        self.assertEqual(row['fused_groups'], 1)
        self.assertEqual(row['absorbed_dispatches'], 1)
        self.assertEqual(row['original_instructions'] - row['emitted_instructions'], 1)
        self.assertEqual(set(manifest['requested_hardening_layers']), set(d.HARDENING_LAYERS))
        self.assertEqual(manifest['hardening_layers'], [])
        self.assertEqual(manifest['external_attack_evaluation'], 'not_evaluated')


if __name__ == '__main__':
    unittest.main()
