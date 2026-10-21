"""Pure archive regressions adopted from the qualified wave3 candidate; no file or process access."""
import unittest
from antirea import rust_cargo_link as link


def ar_header(name, size):
    return (name.ljust(16, b" ") + b"0".ljust(12, b" ") + b"0".ljust(6, b" ")
            + b"0".ljust(6, b" ") + b"644".ljust(8, b" ")
            + str(size).encode().ljust(10, b" ") + b"`\n")


def build_archive(members):
    """members: list of (name16_bytes, payload_bytes). Minimal, no index needed."""
    out = b"!<arch>\n"
    for name, data in members:
        out += ar_header(name, len(data)) + data + (b"\n" if len(data) & 1 else b"")
    return out


def longname_member(payload):
    return (b"//", payload)


def even_name(stem):
    """A long member name of even byte length, so 'stem\\x00\\n' is an even table.

    Real LLVM/rustc rlibs append the '\\n' alignment pad only when name+NUL is odd,
    i.e. when the name length is even (the real word_mix name is 80 bytes).
    """
    return stem if len(stem) % 2 == 0 else stem + b"x"


class RealFormatTests(unittest.TestCase):
    """The LLVM/rustc shape: NUL-terminated name + a trailing even-align newline."""

    def test_single_name_with_trailing_newline_pad_accepted(self):
        name = even_name(b"an_ordinary_long_crate_cgu.0.rcgu.o")
        table = name + b"\x00\n"              # odd content (name+NUL) padded even
        self.assertEqual(len(table) % 2, 0)
        raw = build_archive([longname_member(table), (b"/0", b"payloadbytes!")])
        parsed = link.parse_archive(raw)
        self.assertEqual(parsed["members"][-1]["name"], name.decode())

    def test_two_long_names_with_trailing_pad(self):
        a = b"first_long_member_name_one.o"
        b = b"second_long_member_name_two.o"
        off_b = len(a) + 1
        table = a + b"\x00" + b + b"\x00"
        if len(table) % 2:
            table += b"\n"                    # even-align pad only when needed
        raw = build_archive([longname_member(table),
                             (b"/0", b"aa"), (b"/" + str(off_b).encode(), b"bb")])
        parsed = link.parse_archive(raw)
        names = [m["name"] for m in parsed["members"] if m["kind"] == "member"]
        self.assertEqual(names, [a.decode(), b.decode()])


class MaliciousAndBoundaryTests(unittest.TestCase):
    """The pad tolerance must not widen acceptance of anything malformed."""

    def _reject(self, table, pattern, members_extra=()):
        raw = build_archive([longname_member(table), *members_extra])
        with self.assertRaisesRegex(link.LinkError, pattern):
            link.parse_archive(raw)

    def test_mid_table_newline_not_swallowed(self):
        # 'A\x00\nB\x00': after A\x00 the offset lands on an interior newline that
        # begins the next name -> control char rejected, never treated as a pad.
        self._reject(b"longname_aaaaaaaa\x00\nlongname_bbbbbbbb\x00", "control in name",
                     members_extra=[(b"/0", b"xx")])

    def test_odd_length_table_ending_in_newline_rejected(self):
        # Odd total length => the trailing '\n' is NOT an even-alignment pad.
        table = b"oddnm\x00\n"                # o d d n m \0 \n = 7 bytes (odd)
        self.assertEqual(len(table) % 2, 1)
        self._reject(table, "unterminated archive long name", members_extra=[(b"/0", b"xx")])

    def test_trailing_non_newline_garbage_even_length_rejected(self):
        # Even length, ends in non-newline bytes that are not a valid terminator.
        table = b"realname1\x00QQ"            # 9 + NUL + QQ = 12 bytes (even)
        self.assertEqual(len(table) % 2, 0)
        self._reject(table, "unterminated archive long name", members_extra=[(b"/0", b"xx")])

    def test_pad_byte_offset_is_not_an_entry_boundary(self):
        name = even_name(b"paddedname_unit.o")
        table = name + b"\x00\n"
        self.assertEqual(len(table) % 2, 0)
        pad_off = len(name) + 1               # offset of the trailing '\n'
        raw = build_archive([longname_member(table), (b"/" + str(pad_off).encode(), b"xx")])
        with self.assertRaisesRegex(link.LinkError, "entry boundary"):
            link.parse_archive(raw)

    def test_middle_offset_into_name_rejected(self):
        name = even_name(b"long_long_long_member.o")
        table = name + b"\x00\n"
        self.assertEqual(len(table) % 2, 0)
        raw = build_archive([longname_member(table), (b"/1", b"xx")])
        with self.assertRaisesRegex(link.LinkError, "entry boundary"):
            link.parse_archive(raw)

    def test_duplicate_longname_table_rejected(self):
        t = b"aname\x00\n"
        raw = build_archive([longname_member(t), longname_member(t), (b"/0", b"xx")])
        with self.assertRaisesRegex(link.LinkError, "duplicate long-name table"):
            link.parse_archive(raw)

    def test_single_newline_only_table_rejected(self):
        self._reject(b"\n", "unterminated archive long name", members_extra=[(b"shortnm/", b"xx")])

    def test_two_trailing_newlines_rejected(self):
        # 'name\x00\n\n' (even total) must still fail: only ONE trailing pad byte
        # is tolerated, and the second newline leaves an unterminated remainder.
        table = b"evenname.oX\x00\n\n"        # 11 + NUL + \n + \n = 14 bytes (even)
        self.assertEqual(len(table) % 2, 0)
        self._reject(table, "unterminated archive long name", members_extra=[(b"/0", b"xx")])

    def test_offset_past_pad_into_void_rejected(self):
        name = even_name(b"paddedname_unit.o")
        table = name + b"\x00\n"
        self.assertEqual(len(table) % 2, 0)
        raw = build_archive([longname_member(table), (b"/" + str(len(table)).encode(), b"xx")])
        with self.assertRaisesRegex(link.LinkError, "entry boundary"):
            link.parse_archive(raw)


class PreservedFormatTests(unittest.TestCase):
    """Formats accepted before the fix must still be accepted (no regression)."""

    def test_gnu_slash_newline_terminator_accepted(self):
        name = b"an_ordinary_long_crate_cgu.o"
        raw = build_archive([longname_member(name + b"/\n"), (b"/0", b"xx")])
        parsed = link.parse_archive(raw)
        self.assertEqual(parsed["members"][-1]["name"], name.decode())

    def test_coff_nul_terminator_no_pad_accepted(self):
        # Even-length NUL-terminated table with no trailing pad (classic MS/COFF).
        name = b"evenlen_member.o"             # 16 chars; +NUL = 17 odd -> add 2nd name
        n2 = b"second_member_x.o"
        table = name + b"\x00" + n2 + b"\x00"
        if len(table) % 2:
            name = b"evenlen_memberX.o"
            table = name + b"\x00" + n2 + b"\x00"
        self.assertEqual(len(table) % 2, 0)
        off2 = len(name) + 1
        raw = build_archive([longname_member(table),
                             (b"/0", b"aa"), (b"/" + str(off2).encode(), b"bb")])
        parsed = link.parse_archive(raw)
        names = [m["name"] for m in parsed["members"] if m["kind"] == "member"]
        self.assertEqual(names, [name.decode(), n2.decode()])

    def test_short_names_without_longname_table(self):
        raw = build_archive([(b"shortnm/", b"aa"), (b"othernm/", b"bb")])
        parsed = link.parse_archive(raw)
        names = [m["name"] for m in parsed["members"] if m["kind"] == "member"]
        self.assertEqual(names, ["shortnm", "othernm"])

    def test_empty_longname_table_with_only_short_members(self):
        # A zero-length // member payload: loop does not run; no entries indexed.
        raw = build_archive([longname_member(b""), (b"shortnm/", b"aa")])
        parsed = link.parse_archive(raw)
        names = [m["name"] for m in parsed["members"] if m["kind"] == "member"]
        self.assertEqual(names, ["shortnm"])



if __name__ == "__main__":
    unittest.main()
