"""Pure scalar ABI regressions; no filesystem, compiler, DLL or subprocess.

The test module is intended for the ordinary project unittest suite after
production adoption of antirea.native_abi.
"""
import unittest

from antirea import native_abi as abi


def contract(return_type='u64', parameters=('u64', 'u64')):
    return {'schema_version': 1, 'library_name': 'owned', 'functions': [
        {'name': 'core', 'return_type': return_type,
         'parameters': [{'name': 'arg' + str(i), 'type': value} for i, value in enumerate(parameters)]}]}


def source(prefix='', result='i64', arguments='i64 %a, i64 %b', suffix=''):
    return f'define {prefix} {result} @core({arguments}) {suffix} {{\n  ret {result} 0\n}}\n'


def expected(return_bits=64, parameters=(64, 64), name='core'):
    return {name: {'return_bits': return_bits, 'parameter_bits': list(parameters),
                   'calling_convention': 'default_c',
                   'signedness': 'user_contract_not_encoded_in_llvm'}}


class IntegerRangeAbiTests(unittest.TestCase):
    def test_typed_return_range_retains_exact_evidence_shape(self):
        ir = source('range(i64 0, 256)')
        self.assertEqual(abi.verify_integer_abi(ir, contract()), expected())

    def test_existing_unattributed_and_allowed_qualifier_semantics_unchanged(self):
        for prefix in ('', 'dso_local', 'dso_local dllexport', 'external ccc noundef',
                       'weak_odr hidden zeroext', 'linkonce_odr protected signext'):
            with self.subTest(prefix=prefix):
                ir = source(prefix)
                self.assertEqual(abi.verify_integer_abi(ir, contract()), expected())

    def test_existing_return_qualifier_allowlist_is_exactly_preserved(self):
        self.assertEqual(abi._ALLOWED_RETURN, {
            "external", "dso_local", "dso_preemptable", "dllexport", "default", "hidden",
            "protected", "weak", "weak_odr", "linkonce", "linkonce_odr", "ccc",
            "noundef", "zeroext", "signext"})

    def test_signed_and_unsigned_32_and_64_contracts(self):
        for width in (32, 64):
            for signedness in ('u', 'i'):
                with self.subTest(width=width, signedness=signedness):
                    c = contract(signedness + str(width), (signedness + str(width),))
                    ir = source(f'noundef range(i{width} 0, 17)', f'i{width}', f'i{width} noundef %x')
                    evidence = abi.verify_integer_abi(ir, c)['core']
                    self.assertEqual((evidence['return_bits'], evidence['parameter_bits']), (width, [width]))
                    self.assertEqual(evidence['signedness'], 'user_contract_not_encoded_in_llvm')

    def test_signed_bounds_unsigned_maximum_and_wrapping_intervals(self):
        for width in (32, 64):
            for lower, upper in ((-(1 << (width - 1)), -1), ((1 << width) - 1, 1), (9, 3)):
                with self.subTest(width=width, bounds=(lower, upper)):
                    c = contract('u' + str(width), ())
                    ir = source(f'range(i{width} {lower}, {upper})', f'i{width}', '')
                    self.assertEqual(abi.verify_integer_abi(ir, c)['core']['parameter_bits'], [])

    def test_range_combines_with_existing_qualifiers_in_either_order(self):
        for prefix in ('dso_local noundef range(i64 0, 256)',
                       'range(i64 0, 256) dso_local noundef', 'ccc range ( i64 -4 , 9 ) zeroext'):
            with self.subTest(prefix=prefix):
                self.assertEqual(abi.verify_integer_abi(source(prefix), contract())['core']['return_bits'], 64)

    def test_two_parameter_ranges_do_not_change_arity(self):
        ir = source('range(i64 0, 16)', arguments='i64 noundef range(i64 0, 8) %a, i64 range(i64 -2, 9) %b')
        self.assertEqual(abi.verify_integer_abi(ir, contract())['core']['parameter_bits'], [64, 64])

    def test_parameter_attribute_comma_cannot_supply_a_missing_argument(self):
        with self.assertRaisesRegex(ValueError, 'parameter count'):
            abi.verify_integer_abi(source(arguments='i64 range(i64 0, 8) %a'), contract())

    def test_parameter_attribute_comma_does_not_create_an_extra_argument(self):
        ir = source(arguments='i64 range(i64 0, 8) %a')
        self.assertEqual(abi.verify_integer_abi(ir, contract(parameters=('u64',)))['core']['parameter_bits'], [64])

    def test_suffix_attribute_parentheses_and_commas_are_not_parameters(self):
        ir = source('range(i64 0, 16)', suffix='memory(argmem: read, inaccessiblemem: read) #0')
        self.assertEqual(abi.verify_integer_abi(ir, contract())['core']['parameter_bits'], [64, 64])

    def test_crlf_and_lf_return_identical_evidence(self):
        ir = source('range(i64 0, 16)', arguments='i64 range(i64 -2, 8) %a, i64 %b')
        self.assertEqual(abi.verify_integer_abi(ir, contract()), abi.verify_integer_abi(ir.replace('\n', '\r\n'), contract()))

    def test_parameter_named_range_is_not_an_attribute(self):
        ir = source(arguments='i64 %range, i64 %range.next')
        self.assertEqual(abi.verify_integer_abi(ir, contract()), expected())

    def test_existing_ordinary_parameter_attributes_remain_accepted(self):
        for width in (32, 64):
            for attributes in ('noundef', 'zeroext', 'signext', 'returned', 'noundef returned'):
                with self.subTest(width=width, attributes=attributes):
                    ir = source(result=f'i{width}', arguments=f'i{width} {attributes} %a, i{width} noundef %b')
                    c = contract('u' + str(width), ('u' + str(width), 'u' + str(width)))
                    self.assertEqual(abi.verify_integer_abi(ir, c), expected(width, (width, width)))

    def test_quoted_parameter_punctuation_is_not_abi_syntax(self):
        ir = source(arguments='i64 noundef %"arg)name", i64 %"other,([{}<>*"')
        self.assertEqual(abi.verify_integer_abi(ir, contract())['core']['parameter_bits'], [64, 64])

    def test_quoted_closing_parenthesis_cannot_hide_a_second_parameter(self):
        ir = source(arguments='i64 %"arg)name", i64 %b')
        with self.assertRaisesRegex(ValueError, 'parameter count'):
            abi.verify_integer_abi(ir, contract(parameters=('u64',)))

    def test_quoted_comma_cannot_invent_a_second_parameter(self):
        ir = source(arguments='i64 %"arg,i64 second"')
        self.assertEqual(abi.verify_integer_abi(ir, contract(parameters=('u64',)))['core']['parameter_bits'], [64])
        with self.assertRaisesRegex(ValueError, 'parameter count'):
            abi.verify_integer_abi(ir, contract())

    def test_quoted_attribute_words_remain_identifier_contents(self):
        ir = source(arguments='i64 range(i64 0, 8) %"range(i32 0, 1)", i64 %"inreg swiftself"')
        self.assertEqual(abi.verify_integer_abi(ir, contract())['core']['parameter_bits'], [64, 64])
        with self.assertRaisesRegex(ValueError, 'default C calling convention'):
            abi.verify_integer_abi(source('"range(i64 0, 8)"'), contract())

    def test_llvm_escaped_quote_and_backslash_keep_delimiters_inside_name(self):
        ir = source(arguments=r'i64 %"a\22),b\5C", i64 %other')
        self.assertEqual(abi.verify_integer_abi(ir, contract())['core']['parameter_bits'], [64, 64])
        with self.assertRaisesRegex(ValueError, 'parameter count'):
            abi.verify_integer_abi(ir, contract(parameters=('u64',)))

    def test_unterminated_quoted_token_is_rejected(self):
        for arguments in ('i64 %"arg)name, i64 %b', 'i64 %a, i64 %"other'):
            with self.subTest(arguments=arguments), self.assertRaisesRegex(ValueError, 'unterminated LLVM quoted'):
                abi.verify_integer_abi(source(arguments=arguments), contract())

    def test_noncanonical_quoted_escape_is_rejected(self):
        for arguments in (r'i64 %"a\q", i64 %b', r'i64 %"a\2", i64 %b'):
            with self.subTest(arguments=arguments), self.assertRaisesRegex(ValueError, 'unsupported LLVM quoted escape'):
                abi.verify_integer_abi(source(arguments=arguments), contract())

    def test_quoted_suffix_delimiters_do_not_reopen_the_parameter_list(self):
        ir = source(suffix='"note"="),(range(i64 0, 8)"')
        self.assertEqual(abi.verify_integer_abi(ir, contract())['core']['parameter_bits'], [64, 64])

    def test_return_range_width_must_match_result_not_parameters(self):
        for prefix in ('range(i32 0, 16)', 'range(i8 0, 16)', 'range(i128 0, 16)'):
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                abi.verify_integer_abi(source(prefix), contract())

    def test_parameter_range_width_must_match_its_own_type(self):
        with self.assertRaisesRegex(ValueError, 'range attribute syntax/type'):
            abi.verify_integer_abi(source(arguments='i64 range(i32 0, 16) %a, i64 %b'), contract())

    def test_range_endpoints_cannot_overflow_the_declared_width(self):
        for lower, upper in ((-(1 << 63) - 1, 1), (0, 1 << 64)):
            with self.subTest(bounds=(lower, upper)), self.assertRaisesRegex(ValueError, 'endpoint exceeds'):
                abi.verify_integer_abi(source(f'range(i64 {lower}, {upper})'), contract())

    def test_malformed_return_range_rejected(self):
        for value in ('range(i64 0 16)', 'range(i64 0, 16, 32)', 'range(i64 0, i64 16)',
                      'range(ptr 0, 16)', 'range(i64 %a, 16)', 'range(i64 0, poison)',
                      'range(i64 0, 1.0)', 'range(i64 0, +16)', 'range(i64 0, 0x10)',
                      'range(i64 0, (16))', 'range(i64 0, 16', 'range'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                abi.verify_integer_abi(source(value), contract())

    def test_malformed_parameter_range_rejected(self):
        for value in ('range(i64 0 16)', 'range(i64 0, 16, 32)', 'range(i64 0, i64 16)',
                      'range(i64 0, (16))', 'range(i64 0, 16', 'range'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                abi.verify_integer_abi(source(arguments=f'i64 {value} %a, i64 %b'), contract())

    def test_duplicate_return_or_parameter_range_rejected(self):
        for ir in (source('range(i64 0, 8) range(i64 0, 16)'),
                   source(arguments='i64 range(i64 0, 8) range(i64 0, 16) %a, i64 %b')):
            with self.subTest(ir=ir), self.assertRaisesRegex(ValueError, 'duplicate range'):
                abi.verify_integer_abi(ir, contract())

    def test_range_cannot_hide_special_calling_conventions(self):
        for cc in ('fastcc', 'coldcc', 'swiftcc', 'preserve_nonecc', 'cc 10', 'cc 0'):
            with self.subTest(cc=cc), self.assertRaisesRegex(ValueError, 'default C calling convention'):
                abi.verify_integer_abi(source(f'range(i64 0, 16) {cc}'), contract())

    def test_unknown_return_qualifiers_are_not_stripped(self):
        for qualifier in ('bogus', 'align(8)', 'dereferenceable(8)', 'nofpclass(nan)', 'internal'):
            with self.subTest(qualifier=qualifier), self.assertRaises(ValueError):
                abi.verify_integer_abi(source(f'range(i64 0, 16) {qualifier}'), contract())

    def test_range_token_boundaries_do_not_absorb_adjacent_qualifiers(self):
        for prefix in ('noundefrange(i64 0, 16)', 'range(i64 0, 16)noundef', 'range(i64 0, 16), noundef'):
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                abi.verify_integer_abi(source(prefix), contract())

    def test_pointer_return_and_parameter_rejected(self):
        for ir in (source(result='ptr'), source(result='i64*'), source(arguments='ptr %a, i64 %b'),
                   source(arguments='i64* %a, i64 %b'), source(arguments='i64 * %a, i64 %b')):
            with self.subTest(ir=ir), self.assertRaises(ValueError):
                abi.verify_integer_abi(ir, contract())

    def test_variadic_signatures_rejected(self):
        for arguments in ('i64 %a, ...', 'i64 %a, i64 %b, ...', '...'):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                abi.verify_integer_abi(source(arguments=arguments), contract())

    def test_all_existing_special_parameter_abi_rejections_remain(self):
        for attribute in ('inreg', 'swiftself', 'swifterror', 'swiftasync', 'sret(i64)',
                          'byval(i64)', 'byref(i64)', 'inalloca(i64)', 'preallocated(i64)', 'nest'):
            with self.subTest(attribute=attribute), self.assertRaisesRegex(ValueError, 'special ABI parameter'):
                abi.verify_integer_abi(source(arguments=f'i64 range(i64 0, 16) {attribute} %a, i64 %b'), contract())

    def test_other_parenthesized_parameter_syntax_is_not_ignored(self):
        for value in ('foo(1, 2)', '(i64, i64)*', 'align(8)'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                abi.verify_integer_abi(source(arguments=f'i64 {value} %a, i64 %b'), contract())

    def test_return_and_parameter_width_mismatch_remain_rejected(self):
        for ir in (source('range(i32 0, 16)', result='i32'),
                   source('range(i64 0, 16)', arguments='i32 %a, i64 %b')):
            with self.subTest(ir=ir), self.assertRaisesRegex(ValueError, 'width differs'):
                abi.verify_integer_abi(ir, contract())

    def test_non_supported_integer_width_and_void_rejected(self):
        for result in ('i1', 'i8', 'i16', 'i128', 'void', '<2 x i32>'):
            with self.subTest(result=result), self.assertRaises(ValueError):
                abi.verify_integer_abi(source(result=result), contract())
        with self.assertRaises(ValueError):
            abi.verify_integer_abi(source(), contract(return_type='void'))

    def test_duplicate_or_missing_definition_rejected(self):
        for ir in (source() + source('range(i64 0, 16)'), source().replace('@core', '@different')):
            with self.subTest(ir=ir), self.assertRaisesRegex(ValueError, 'missing or ambiguous'):
                abi.verify_integer_abi(ir, contract())

    def test_empty_trailing_and_unbalanced_parameters_rejected(self):
        for arguments in ('i64 %a,', ',i64 %b', 'i64 %a,,i64 %b', 'i64 range(i64 0, 8 %a, i64 %b'):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                abi.verify_integer_abi(source(arguments=arguments), contract())

    def test_machine_abi_widths_arity_and_convention(self):
        ir = 'define dso_local i64 @core(i64 noundef %a, i64 noundef %b) local_unnamed_addr #0 {\n ret i64 %a\n}\n'
        c = contract(parameters=('i64', 'u64'))
        self.assertEqual(abi.verify_integer_abi(ir, c), expected())
        for invalid in (ir.replace("i64 @core", "i32 @core"),
                        ir.replace("i64 noundef %a, i64 noundef %b", "i64 %a"),
                        ir.replace("i64 noundef %a", "i32 noundef %a"),
                        ir.replace("dso_local", "dso_local fastcc"),
                        ir.replace("dso_local", "dso_local preserve_nonecc"),
                        ir.replace("i64 noundef %a", "i64 inreg %a")):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                abi.verify_integer_abi(invalid, c)

    def test_observed_compiler_range_and_vm_headers_preserve_abi(self):
        # Exact relevant LLVM scalar headers, independent of any local artifact.
        headers = (
            'define range(i64 0, 256) i64 @funnel_fshl_i8_distinct(i64 %a, i64 %b, i64 %count) local_unnamed_addr #1 {',
            'define i64 @funnel_fshl_i8_distinct(i64 %a, i64 %b, i64 %count) local_unnamed_addr #0 !kagura_obfuscated !0 {',
        )
        c = contract(parameters=('u64', 'u64', 'u64'))
        c['functions'][0]['name'] = 'funnel_fshl_i8_distinct'
        wanted = expected(parameters=(64, 64, 64), name='funnel_fshl_i8_distinct')
        for header in headers:
            for newline in ('\n', '\r\n'):
                with self.subTest(header=header, newline=repr(newline)):
                    ir = newline.join((header, '  ret i64 0', '}', ''))
                    self.assertEqual(abi.verify_integer_abi(ir, c), wanted)


if __name__ == '__main__':
    unittest.main(verbosity=2)
