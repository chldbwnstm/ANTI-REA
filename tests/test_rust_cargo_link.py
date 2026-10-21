"""Authored pure byte-fixture regressions. No files/processes/tools/targets."""
from __future__ import annotations

import copy
import hashlib
import json
import struct
import unittest

from antirea import rust_cargo_link as link


def descriptor(path, raw):
    return {"path": path, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def coff(functions=("score",), *, undefined=(), data=None, relocations=(), aux=False,
         text_flags=0x60000020, storage=2, data_name=".data", absolute_symbols=()):
    """Synthetic ordinary AMD64 object; never executed."""
    sections = [(".text", bytes([0x90]) * max(16, 16 * len(functions)), text_flags)]
    if data is not None:
        sections.append((data_name, data, 0xC0000040))
    header_end = 20 + 40 * len(sections)
    data_bytes = b"".join(x[1] for x in sections)
    relocation_offset = header_end + len(data_bytes)
    rel = b"".join(struct.pack("<IIH", *row) for row in relocations)
    symoff = relocation_offset + len(rel)
    strings = bytearray(b"\0\0\0\0")

    def symbol_name(name):
        encoded = name.encode("utf-8")
        if len(encoded) <= 8:
            return encoded.ljust(8, b"\0")
        offset = len(strings)
        strings.extend(encoded + b"\0")
        return b"\0" * 4 + struct.pack("<I", offset)

    symbols = []
    for index, name in enumerate(functions):
        symbols.append(symbol_name(name) + struct.pack("<IhHBB", index * 16, 1, 0x20, storage, int(aux)))
        if aux:
            symbols.append(b"\0" * 18)
    for name in undefined:
        symbols.append(symbol_name(name) + struct.pack("<IhHBB", 0, 0, 0, 2, 0))
    for name, value, symbol_storage in absolute_symbols:
        symbols.append(symbol_name(name) + struct.pack("<IhHBB", value, -1, 0, symbol_storage, 0))
    struct.pack_into("<I", strings, 0, len(strings))
    header = struct.pack("<HHIIIHH", 0x8664, len(sections), 0, symoff, len(symbols), 0, 0)
    records, cursor = [], header_end
    for index, (name, raw, flags) in enumerate(sections):
        records.append(name.encode().ljust(8, b"\0") + struct.pack("<IIIIIIHHI", 0, 0, len(raw), cursor,
                        relocation_offset if index == 0 and rel else 0, 0,
                        len(relocations) if index == 0 else 0, 0, flags))
        cursor += len(raw)
    return header + b"".join(records) + data_bytes + rel + b"".join(symbols) + bytes(strings)


def ar_header(name, size):
    return name.ljust(16, b" ") + b"0".ljust(12, b" ") + b"0".ljust(6, b" ") + b"0".ljust(6, b" ") + b"644".ljust(8, b" ") + str(size).encode().ljust(10, b" ") + b"`\n"


def archive(items, symbol_targets=(), *, second=False, long_style="gnu"):
    """items are ordered (name,payload); symbol targets use item ordinal."""
    longnames, encoded_names = bytearray(), []
    for name, _ in items:
        nr = name.encode("utf-8")
        if len(nr) <= 15:
            encoded_names.append(nr + b"/")
        else:
            encoded_names.append(b"/" + str(len(longnames)).encode())
            longnames.extend(nr + (b"/\n" if long_style == "gnu" else b"\0"))
    n = len(symbol_targets)
    first_size = 4 + n * 4 + sum(len(name.encode()) + 1 for name, _ in symbol_targets)
    second_size = 8 + len(items) * 4 + n * 2 + sum(len(name.encode()) + 1 for name, _ in symbol_targets)
    special = [(b"/", b"\0" * first_size)]
    if second:
        special.append((b"/", b"\0" * second_size))
    if longnames:
        special.append((b"//", bytes(longnames)))
    cursor = 8 + sum(60 + len(data) + (len(data) & 1) for _, data in special)
    offsets = []
    for _, data in items:
        offsets.append(cursor)
        cursor += 60 + len(data) + (len(data) & 1)
    first = struct.pack(">I", n) + b"".join(struct.pack(">I", offsets[index]) for _, index in symbol_targets)
    first += b"".join(name.encode() + b"\0" for name, _ in symbol_targets)
    special[0] = (b"/", first)
    if second:
        sorted_targets = sorted(symbol_targets, key=lambda row: row[0].encode())
        data = struct.pack("<I", len(items)) + b"".join(struct.pack("<I", off) for off in offsets) + struct.pack("<I", n)
        data += b"".join(struct.pack("<H", index + 1) for _, index in sorted_targets)
        data += b"".join(name.encode() + b"\0" for name, _ in sorted_targets)
        special[1] = (b"/", data)
    rows = special + [(name, data) for name, (_, data) in zip(encoded_names, items)]
    return b"!<arch>\n" + b"".join(ar_header(name, len(data)) + data + (b"\n" if len(data) & 1 else b"") for name, data in rows)


def response(path, raw):
    return {path: {"descriptor": descriptor(path, raw), "content": raw}}


def owner(unit="root"):
    return {"unit": unit, "package_id": "path+file:///owned/" + unit + "#0.1.0",
            "target_name": unit, "source": "C:\\owned\\" + unit + "\\src\\lib.rs"}


def input_record(path, raw, who=None, staged=None):
    return {"path": path, "descriptor": descriptor(staged or path, raw), "content": raw, "owner": who}


def replacement(raw, role):
    return {"descriptor": descriptor("C:\\generated\\" + role + ".obj", raw), "content": raw}


def selection(path, names=("score",), member=None, who=None):
    return {"input_path": path, "member_index": member, "owner": who or owner(),
            "symbols": {name: {"baseline": name, "protected": name} for name in names},
            "lineage": descriptor("C:\\evidence\\preparation.json", b"upstream authenticated elsewhere")}


def plan_arguments():
    return {"argv": ["/DLL", "C:\\owned\\allocator.obj", "C:\\owned\\core.obj", "/OUT:C:\\old\\app.dll"],
            "cwd": "C:\\owned", "response_files": {},
            "inputs": [input_record("C:\\owned\\allocator.obj", coff(("allocator",))),
                       input_record("C:\\owned\\core.obj", coff(), owner())],
            "selections": [selection("C:\\owned\\core.obj")],
            "replacement_objects": {"baseline": replacement(coff(), "baseline"),
                                    "protected": replacement(coff(), "protected"),
                                    "runtime": replacement(coff(("vm_run",)), "runtime")},
            "public_exports": ["score"]}


class CoffTests(unittest.TestCase):
    def test_function_offset_type_hash_and_section_bytes(self):
        raw = coff(("score", "long_namespace_helper"))
        result = link.parse_coff(raw)
        self.assertEqual(result["sha256"], link.digest(raw))
        self.assertEqual([(x["name"], x["value"], x["type"]) for x in result["symbols"]],
                         [("score", 0, 32), ("long_namespace_helper", 16, 32)])
        self.assertEqual(result["sections"][0]["raw_offset"], 60)
        self.assertEqual(result["sections"][0]["raw_sha256"], link.digest(b"\x90" * 32))

    def test_relocation_binds_primary_symbol_and_write_offset(self):
        raw = coff(undefined=("external_helper",), relocations=((4, 1, 4),))
        result = link.parse_coff(raw)
        row = result["sections"][0]["relocations"][0]
        self.assertEqual((row["symbol"], row["width"], row["address"]), ("external_helper", 4, 4))
        self.assertEqual(row["record_sha256"], link.digest(raw[row["offset"]:row["offset"] + 10]))

    def test_auxiliary_slot_not_a_symbol_target(self):
        with self.assertRaisesRegex(link.LinkError, "auxiliary/missing"):
            link.parse_coff(coff(aux=True, relocations=((0, 1, 4),)))

    def test_relocation_write_outside_section(self):
        with self.assertRaisesRegex(link.LinkError, "exceeds"):
            link.parse_coff(coff(relocations=((15, 0, 1),)))

    def test_unknown_relocation_not_guessed(self):
        with self.assertRaisesRegex(link.LinkError, "relocation type"):
            link.parse_coff(coff(relocations=((0, 0, 0xFFFF),)))

    def test_symbol_entry_outside_section(self):
        raw = bytearray(coff())
        symoff = struct.unpack_from("<I", raw, 8)[0]
        struct.pack_into("<I", raw, symoff + 8, 17)
        with self.assertRaisesRegex(link.LinkError, "value outside"):
            link.parse_coff(bytes(raw))

    def test_function_entry_exactly_at_end_is_invalid(self):
        raw = bytearray(coff())
        symoff = struct.unpack_from("<I", raw, 8)[0]
        struct.pack_into("<I", raw, symoff + 8, 16)
        with self.assertRaisesRegex(link.LinkError, "section end"):
            link.parse_coff(bytes(raw))

    def test_auxiliary_extent_checked(self):
        raw = bytearray(coff())
        symoff = struct.unpack_from("<I", raw, 8)[0]
        raw[symoff + 17] = 250
        with self.assertRaisesRegex(link.LinkError, "auxiliary bounds"):
            link.parse_coff(bytes(raw))

    def test_overlapping_sections_and_symbols_reject(self):
        raw = bytearray(coff())
        struct.pack_into("<I", raw, 20 + 20, struct.unpack_from("<I", raw, 8)[0])
        with self.assertRaisesRegex(link.LinkError, "overlapping"):
            link.parse_coff(bytes(raw))

    def test_string_offsets_and_unterminated_strings(self):
        raw = bytearray(coff(("long_name_for_string_table",)))
        symoff = struct.unpack_from("<I", raw, 8)[0]
        struct.pack_into("<I", raw, symoff + 4, 1)
        with self.assertRaisesRegex(link.LinkError, "string table offset"):
            link.parse_coff(bytes(raw))
        raw = bytearray(coff(("long_name_for_string_table",)))
        raw[-1] = 65
        with self.assertRaisesRegex(link.LinkError, "unterminated"):
            link.parse_coff(bytes(raw))

    def test_truncated_header_and_symbol_table(self):
        for raw in (b"a" * 19, coff()[:-2]):
            with self.subTest(size=len(raw)), self.assertRaises(link.LinkError):
                link.parse_coff(raw)

    def test_bigobj_import_machine_and_optional_header_reject(self):
        for raw in (b"\0\0\xff\xff" + b"\0" * 60, b"MZ" + b"\0" * 60):
            with self.assertRaises(link.LinkError):
                link.parse_coff(raw)
        raw = bytearray(coff())
        struct.pack_into("<H", raw, 16, 1)
        with self.assertRaises(link.LinkError):
            link.parse_coff(bytes(raw))

    def test_uninterpreted_trailing_bytes_are_retained(self):
        result = link.parse_coff(coff() + b"extra")
        self.assertEqual(result["uninterpreted_ranges"][-1]["sha256"], link.digest(b"extra"))
        self.assertFalse(result["uninterpreted_ranges"][-1]["all_zero"])

    def test_comdat_flag_and_aux_bytes_are_not_lost(self):
        result = link.parse_coff(coff(aux=True, text_flags=0x60001020))
        self.assertTrue(result["sections"][0]["comdat"])
        self.assertEqual(result["symbols"][0]["auxiliary_hex"], "00" * 18)

    def test_extended_relocation_and_nonzero_virtual_address_reject(self):
        with self.assertRaisesRegex(link.LinkError, "extended"):
            link.parse_coff(coff(text_flags=0x61000020))
        raw = bytearray(coff())
        struct.pack_into("<I", raw, 32, 4096)
        with self.assertRaisesRegex(link.LinkError, "virtual address"):
            link.parse_coff(bytes(raw))


class AbsoluteDefinitionTests(unittest.TestCase):
    def test_external_absolute_is_defined_constant_not_code_or_reference(self):
        raw = coff(absolute_symbols=(("absolute_limit", 0x12345678, 2),))
        row = next(s for s in link.parse_coff(raw)["symbols"] if s["name"] == "absolute_limit")
        self.assertEqual((row["section"], row["value"], row["definition_kind"]), (-1, 0x12345678, "absolute"))
        self.assertIs(row["defined"], True)
        self.assertIs(row["absolute"], True)
        self.assertIs(row["external"], True)
        self.assertIs(row["executable"], False)
        self.assertIs(row["common"], False)
        self.assertEqual(row["record_sha256"], link.digest(raw[row["offset"]:row["offset"] + 18]))

    def test_zero_absolute_value_is_still_a_definition(self):
        row = link.parse_coff(coff(absolute_symbols=(("zero", 0, 2),)))["symbols"][-1]
        self.assertEqual(row["definition_kind"], "absolute")
        self.assertIs(row["defined"], True)
        self.assertEqual(row["value"], 0)

    def test_static_absolute_has_distinct_classification(self):
        row = link.parse_coff(coff(absolute_symbols=(("@feat.00", 0x800, 3),)))["symbols"][-1]
        self.assertIs(row["absolute"], True)
        self.assertIs(row["defined"], True)
        self.assertIs(row["external"], False)

    def test_undefined_common_and_debug_do_not_become_absolute_definitions(self):
        for section, value, expected, common in ((0, 0, "undefined", False), (0, 4, "common", True), (-2, 0, "debug", False)):
            raw = bytearray(coff(undefined=("not_absolute",)))
            offset = struct.unpack_from("<I", raw, 8)[0] + 18
            struct.pack_into("<Ih", raw, offset + 8, value, section)
            row = link.parse_coff(bytes(raw))["symbols"][-1]
            with self.subTest(section=section, value=value):
                self.assertEqual(row["definition_kind"], expected)
                self.assertIs(row["defined"], False)
                self.assertIs(row["absolute"], False)
                self.assertIs(row["common"], common)

    def test_selected_external_absolute_blocks_whole_object_removal(self):
        args = plan_arguments()
        args["inputs"][1] = input_record("C:\\owned\\core.obj", coff(absolute_symbols=(("absolute_limit", 99, 2),)), owner())
        result = link.plan_replacement(**args)
        self.assertEqual(result["status"], "needs_review")
        self.assertIn("unregenerated_absolute_definition:absolute_limit", [x["kind"] for x in result["blockers"]])
        symbol = result["selected"][0]["coff"]["symbols"][-1]
        self.assertEqual((symbol["definition_kind"], symbol["value"]), ("absolute", 99))
        self.assertFalse(result["target_executed"])

    def test_selected_static_feature_absolute_also_requires_retention_proof(self):
        args = plan_arguments()
        args["inputs"][1] = input_record("C:\\owned\\core.obj", coff(absolute_symbols=(("@feat.00", 0x800, 3),)), owner())
        result = link.plan_replacement(**args)
        self.assertIn("unregenerated_absolute_definition:@feat.00", [x["kind"] for x in result["blockers"]])

    def test_selected_archive_member_absolute_cannot_be_silently_omitted(self):
        args = plan_arguments()
        raw = archive([("core.o", coff(absolute_symbols=(("absolute_limit", 7, 2),))),
                       ("keep.o", coff(("keep",)))], [("score", 0), ("absolute_limit", 0), ("keep", 1)])
        index = next(m["index"] for m in link.parse_archive(raw)["members"] if m["name"] == "core.o")
        args["argv"][2] = "C:\\owned\\local.rlib"
        args["inputs"][1] = input_record("C:\\owned\\local.rlib", raw, owner())
        args["selections"] = [selection("C:\\owned\\local.rlib", member=index)]
        result = link.plan_replacement(**args)
        self.assertEqual(result["status"], "needs_review")
        self.assertIn("unregenerated_absolute_definition:absolute_limit", [x["kind"] for x in result["blockers"]])

    def test_retained_external_absolute_collides_with_generated_runtime(self):
        args = plan_arguments()
        args["inputs"][0] = input_record("C:\\owned\\allocator.obj", coff(("allocator",), absolute_symbols=(("vm_run", 1, 2),)))
        result = link.plan_replacement(**args)
        collisions = [x for x in result["blockers"] if x["kind"] == "replacement_external_definition_collides_with_retained"]
        self.assertEqual([x["symbol"] for x in collisions], ["vm_run"])

    def test_generated_absolute_collides_with_retained_external_function(self):
        args = plan_arguments()
        args["replacement_objects"]["protected"] = replacement(coff(absolute_symbols=(("allocator", 1, 2),)), "protected")
        result = link.plan_replacement(**args)
        collisions = [x for x in result["blockers"] if x["kind"] == "replacement_external_definition_collides_with_retained"]
        self.assertEqual([x["symbol"] for x in collisions], ["allocator"])

    def test_generated_absolute_and_runtime_absolute_collision_rejected(self):
        args = plan_arguments()
        args["replacement_objects"]["protected"] = replacement(coff(absolute_symbols=(("shared_constant", 3, 2),)), "protected")
        args["replacement_objects"]["runtime"] = replacement(coff(("vm_run",), absolute_symbols=(("shared_constant", 3, 2),)), "runtime")
        with self.assertRaisesRegex(link.LinkError, "runtime/generated definition collision"):
            link.plan_replacement(**args)

    def test_noncolliding_retained_absolute_is_preserved_not_renamed(self):
        args = plan_arguments()
        raw = coff(("allocator",), absolute_symbols=(("retained_constant", 7, 2),))
        args["inputs"][0] = input_record("C:\\owned\\allocator.obj", raw)
        result = link.plan_replacement(**args)
        self.assertEqual(result["status"], "structural_replacement_plan_not_executable")
        self.assertEqual(result["retained"][0]["descriptor"]["sha256"], link.digest(raw))
        self.assertFalse(any(x["index"] == 1 for x in result["edits"]))


class ArchiveTests(unittest.TestCase):
    def test_duplicate_names_kept_by_index_and_offset(self):
        raw = archive([("same.o", coff(("a",))), ("same.o", coff(("b",)))], [("a", 0), ("b", 1)])
        parsed = link.parse_archive(raw)
        members = [m for m in parsed["members"] if m["kind"] == "member"]
        self.assertEqual([m["name"] for m in members], ["same.o", "same.o"])
        self.assertNotEqual(members[0]["header_offset"], members[1]["header_offset"])
        self.assertNotEqual(members[0]["sha256"], members[1]["sha256"])

    def test_gnu_and_coff_long_names(self):
        for style in ("gnu", "coff"):
            with self.subTest(style=style):
                parsed = link.parse_archive(archive([("an_ordinary_long_crate_cgu.o", coff())], [("score", 0)], long_style=style))
                self.assertEqual(parsed["members"][-1]["name"], "an_ordinary_long_crate_cgu.o")

    def test_second_coff_index_crosschecks_first(self):
        parsed = link.parse_archive(archive([("a.o", coff(("z",))), ("b.o", coff(("a",)))], [("z", 0), ("a", 1)], second=True))
        self.assertEqual(len(parsed["indices"]), 2)
        self.assertEqual([x["symbol"] for x in parsed["indices"][1]["entries"]], ["a", "z"])

    def test_index_header_offset_not_member_body(self):
        raw = bytearray(archive([("a.o", coff())], [("score", 0)]))
        actual = struct.unpack_from(">I", raw, 72)[0]
        struct.pack_into(">I", raw, 72, actual + 60)
        with self.assertRaisesRegex(link.LinkError, "member header"):
            link.parse_archive(bytes(raw))

    def test_disagreeing_second_index_rejected(self):
        raw = bytearray(archive([("a.o", coff())], [("score", 0)], second=True))
        parsed = link.parse_archive(bytes(raw))
        second = parsed["members"][1]
        raw[second["data_offset"] + second["bytes"] - 6] = ord("S")
        with self.assertRaisesRegex(link.LinkError, "disagree"):
            link.parse_archive(bytes(raw))

    def test_longname_middle_offset_rejected(self):
        raw = bytearray(archive([("long_long_long_crate_member.o", coff())]))
        parsed = link.parse_archive(bytes(raw))
        offset = parsed["members"][-1]["header_offset"]
        raw[offset:offset + 16] = b"/1".ljust(16, b" ")
        with self.assertRaisesRegex(link.LinkError, "entry boundary"):
            link.parse_archive(bytes(raw))

    def test_truncation_padding_and_size_invalid(self):
        raw = archive([("meta", b"abc")])
        with self.assertRaises(link.LinkError):
            link.parse_archive(raw[:-1])
        mutated = bytearray(raw)
        mutated[-1] = 0
        with self.assertRaisesRegex(link.LinkError, "padding"):
            link.parse_archive(bytes(mutated))
        mutated = bytearray(raw)
        mutated[56:66] = b"-1".ljust(10, b" ")
        with self.assertRaisesRegex(link.LinkError, "size"):
            link.parse_archive(bytes(mutated))

    def test_thin_bsd_and_64bit_indices_not_silently_accepted(self):
        for raw in (b"!<thin>\n", b"!<arch>\n" + ar_header(b"#1/4", 4) + b"name", b"!<arch>\n" + ar_header(b"/SYM64/", 0)):
            with self.subTest(raw=raw[:16]), self.assertRaises(link.LinkError):
                link.parse_archive(raw)

    def test_omit_preserves_metadata_unselected_bytes_order(self):
        items = [("lib.rmeta", b"rust-metadata"), ("core.o", coff()), ("allocator.o", coff(("alloc",)))]
        raw = archive(items, [("score", 1), ("alloc", 2)], second=True)
        before = link.parse_archive(raw)
        removed = next(m["index"] for m in before["members"] if m["name"] == "core.o")
        new = archive([items[0], items[2]], [("alloc", 1)], second=True)
        evidence = link.verify_rewritten_archive(raw, new, [removed])
        self.assertEqual([x["name"] for x in evidence["retained"]], ["lib.rmeta", "allocator.o"])
        self.assertFalse(evidence["rustc_metadata_semantics_verified"])

    def test_archive_rewrite_removed_extra_or_changed_retained_fails(self):
        items = [("meta", b"metadata"), ("core.o", coff()), ("keep.o", coff(("keep",)))]
        raw = archive(items, [("score", 1), ("keep", 2)])
        index = next(m["index"] for m in link.parse_archive(raw)["members"] if m["name"] == "core.o")
        bad_variants = [[items[0]], [items[2], items[0]], [("meta", b"changed"), items[2]], [items[0], items[2], ("extra", b"x")]]
        for items2 in bad_variants:
            with self.subTest(items=[x[0] for x in items2]), self.assertRaises(link.LinkError):
                link.verify_rewritten_archive(raw, archive(items2), [index])

    def test_rewritten_index_cannot_claim_removed_symbol(self):
        raw = archive([("core.o", coff()), ("keep.o", coff(("keep",)))], [("score", 0), ("keep", 1)])
        index = next(m["index"] for m in link.parse_archive(raw)["members"] if m["name"] == "core.o")
        with self.assertRaisesRegex(link.LinkError, "symbol index"):
            link.verify_rewritten_archive(raw, archive([("keep.o", coff(("keep",)))], [("score", 0)]), [index])

    def test_remove_index_member_or_bool_rejected(self):
        raw = archive([("a.o", coff())], [("score", 0)])
        for removed in ([0], [True], [1, 1], []):
            with self.subTest(removed=removed), self.assertRaises(link.LinkError):
                link.verify_rewritten_archive(raw, raw, removed)


class RecipeTests(unittest.TestCase):
    def test_direct_and_response_every_occurrence_preserved(self):
        path = "C:\\owned\\link.rsp"
        raw = b'"C:\\owned\\a.obj"\r\n"/OUT:C:\\out\\a.dll"\r\n'
        parsed = link.parse_link_recipe(["/DLL", "@link.rsp", "C:\\owned\\a.obj"], "C:\\owned", response(path, raw))
        self.assertEqual([x["index"] for x in parsed["expanded"]], [0, 1, 2, 3])
        self.assertEqual(parsed["expanded"][1]["occurrence"], {"argv_index": 1, "response_path": path.lower(), "response_line": 0})
        self.assertEqual(parsed["expanded"][3]["occurrence"]["response_line"], None)
        self.assertTrue(parsed["token_coverage_complete"])
        self.assertFalse(parsed["native_dependency_closure_verified"])

    def test_utf16le_unicode_response(self):
        raw = b"\xff\xfe" + '"C:\\경로\\x.obj"\n"/OUT:C:\\out\\x.dll"\n'.encode("utf-16-le")
        rows = link.response_tokens(raw)
        self.assertIn("경로", rows[0]["token"])

    def test_nested_ambiguous_quote_encoding_and_missing_newline_reject(self):
        for raw in (b"@nested.rsp\n", b'"a"b.obj"\n', b"a.obj", b"a b.obj\n", b"\xff\xfe\0", b"\xef\xbb\xbfa.obj\n"):
            with self.subTest(raw=raw), self.assertRaises(link.LinkError):
                link.response_tokens(raw)

    def test_defaultlibs_recorded_not_inferred(self):
        parsed = link.parse_link_recipe(["a.obj", "/DEFAULTLIB:kernel32.lib", "/LIBPATH:C:\\SDK\\lib", "/OUT:a.dll"], "C:\\owned", {})
        self.assertEqual(parsed["unresolved_default_libraries"], ["kernel32.lib"])

    def test_explicit_absolute_defaultlib_is_an_input(self):
        result = link.parse_link_recipe(["a.obj", "/DEFAULTLIB:C:\\SDK\\kernel32.lib", "/OUT:a.dll"], "C:\\owned", {})
        self.assertEqual(result["expanded"][1]["role"], "defaultlib_explicit")
        self.assertEqual(result["unresolved_default_libraries"], [])
        with self.assertRaisesRegex(link.LinkError, "default-library spelling"):
            link.parse_link_recipe(["a.obj", "/DEFAULTLIB:sub\\a.lib", "/OUT:a.dll"], "C:\\owned", {})

    def test_unknown_option_force_dump_and_unclassified_input_reject(self):
        for token in ("/FORCE:MULTIPLE", "/LINKREPRO:C:\\secret", "/UNKNOWN:thing", "evil.dll", "/MAP"):
            with self.subTest(token=token), self.assertRaises(link.LinkError):
                link.parse_link_recipe(["a.obj", token, "/OUT:a.dll"], "C:\\owned", {})

    def test_missing_extra_changed_response_reject(self):
        path = "C:\\owned\\link.rsp"
        raw = b"a.obj\n/OUT:a.dll\n"
        with self.assertRaisesRegex(link.LinkError, "missing bound"):
            link.parse_link_recipe(["@link.rsp"], "C:\\owned", {})
        with self.assertRaisesRegex(link.LinkError, "unused response"):
            link.parse_link_recipe(["a.obj", "/OUT:a.dll"], "C:\\owned", response(path, raw))
        changed = response(path, raw)
        changed[path]["content"] += b"/DLL\n"
        with self.assertRaisesRegex(link.LinkError, "descriptor/content"):
            link.parse_link_recipe(["@link.rsp"], "C:\\owned", changed)

    def test_output_roles_and_input_alias_checked(self):
        for argv in (["a.obj"], ["a.obj", "/OUT:a.dll", "/OUT:b.dll"], ["a.obj", "/OUT:a.obj"]):
            with self.assertRaises(link.LinkError):
                link.parse_link_recipe(argv, "C:\\owned", {})

    def test_path_devices_ads_sensitive_and_drive_relative_reject(self):
        for path in ("C:a.obj", "C:\\a.obj:stream", "\\\\server\\share\\a.obj", "C:\\env.setting", "C:\\LINKREPRO\\a.obj"):
            with self.subTest(path=path), self.assertRaises(link.LinkError):
                link.path_key(path, "C:\\owned")

    def test_descriptor_boolean_bytes_and_extra_fields_reject(self):
        desc = descriptor("C:\\a.obj", b"x")
        for modified in ({**desc, "bytes": True}, {**desc, "extra": 1}, {**desc, "sha256": "0" * 64}):
            with self.assertRaises(link.LinkError):
                link.descriptor(modified, b"x")

    def test_inventory_missing_extra_collision_and_mutation_reject(self):
        recipe = link.parse_link_recipe(["a.obj", "/OUT:a.dll"], "C:\\owned", {})
        record = input_record("C:\\owned\\a.obj", coff())
        for records in ([], [record, copy.deepcopy(record)], [input_record("C:\\owned\\b.obj", coff())]):
            with self.assertRaises(link.LinkError):
                link.inventory_inputs(recipe, records)
        record["content"] += b"x"
        with self.assertRaisesRegex(link.LinkError, "descriptor/content"):
            link.inventory_inputs(recipe, [record])


class RecorderBindingTests(unittest.TestCase):
    def fixture(self):
        obj, rsp = coff(), b"core.obj\n/OUT:app.dll\n"
        start = {"schema_version": 1, "status": "explicit_inputs_staged_not_full_link_closure",
                 "full_native_link_closure_verified": False, "cwd": "C:\\owned",
                 "original_argv": ["/DLL", "@link.rsp"],
                 "staged_inputs": [
                     {"original": "C:\\owned\\link.rsp", "staged": "C:\\event\\input-0000.bin", "sha256": link.digest(rsp), "bytes": len(rsp), "identity": "volume:1", "links": 1, "first_role": "response"},
                     {"original": "C:\\owned\\core.obj", "staged": "C:\\event\\input-0001.bin", "sha256": link.digest(obj), "bytes": len(obj), "identity": "volume:2", "links": 1, "first_role": "object_or_archive"}],
                 "expanded_arguments": [{"argv_index": 0, "response_line": None, "token": "/DLL"},
                                        {"argv_index": 1, "response_line": 0, "token": "core.obj"},
                                        {"argv_index": 1, "response_line": 1, "token": "/OUT:app.dll"}],
                 "ordered_input_occurrences": [{"argv_index": 1, "kind": "response", "staged_index": 0},
                                               {"argv_index": 1, "response_line": 0, "kind": "object_or_archive", "staged_index": 1, "token": "core.obj"}],
                 "explicit_outputs": {"out": "C:\\owned\\app.dll"},
                 "ordered_argument_libpath": [], "unresolved_default_library_names": []}
        return start, [rsp, obj]

    def test_actual_recorder_shape_uses_zero_based_response_lines(self):
        start, content = self.fixture()
        result = link.bind_recorded_recipe(start, content)
        self.assertEqual(result["status"], "recorded_recipe_bytes_bound_not_authenticated")
        self.assertEqual(result["input_bindings"][0]["descriptor"]["path"], "C:\\event\\input-0001.bin")
        self.assertFalse(result["cargo_unit_authenticity_verified"])
        self.assertEqual(result, link.bind_recorded_recipe(json.loads(json.dumps(start, sort_keys=True)), content))

    def test_modified_expansion_or_occurrence_fails(self):
        for field in ("expanded_arguments", "ordered_input_occurrences"):
            start, content = self.fixture()
            start[field][-1]["response_line"] += 1
            with self.subTest(field=field), self.assertRaises(link.LinkError):
                link.bind_recorded_recipe(start, content)

    def test_changed_staged_bytes_or_first_role_fails(self):
        start, content = self.fixture()
        with self.assertRaisesRegex(link.LinkError, "descriptor/content"):
            link.bind_recorded_recipe(start, [content[0], content[1] + b"changed"])
        start["staged_inputs"][1]["first_role"] = "response"
        with self.assertRaisesRegex(link.LinkError, "first-role"):
            link.bind_recorded_recipe(start, content)

    def test_unused_foreign_staged_file_and_wrong_outputs_fail(self):
        start, content = self.fixture()
        extra = copy.deepcopy(start["staged_inputs"][1])
        extra["original"] = "C:\\owned\\foreign.obj"
        extra["staged"] = "C:\\event\\input-0002.bin"
        start["staged_inputs"].append(extra)
        with self.assertRaisesRegex(link.LinkError, "unused staged"):
            link.bind_recorded_recipe(start, content + [content[1]])
        start, content = self.fixture()
        start["explicit_outputs"]["out"] = "C:\\foreign\\app.dll"
        with self.assertRaisesRegex(link.LinkError, "outputs differ"):
            link.bind_recorded_recipe(start, content)

    def test_boolean_schema_or_linkcount_reject(self):
        for field in ("schema", "links"):
            start, content = self.fixture()
            if field == "schema":
                start["schema_version"] = True
            else:
                start["staged_inputs"][0]["links"] = True
            with self.subTest(field=field), self.assertRaises(link.LinkError):
                link.bind_recorded_recipe(start, content)


class PlanningTests(unittest.TestCase):
    def test_structural_plan_not_success_and_allocator_preserved(self):
        args = plan_arguments()
        result = link.plan_replacement(**args)
        self.assertEqual(result["status"], "structural_replacement_plan_not_executable")
        self.assertEqual(result["blockers"], [])
        self.assertEqual(result["retained"][0]["descriptor"], args["inputs"][0]["descriptor"])
        self.assertEqual(result["aggregate_object_insertion_before_expanded_index"], 2)
        for key in ("target_executed", "cargo_unit_authenticity_verified", "source_to_object_semantics_verified", "native_dependency_closure_verified", "link_order_behavior_verified"):
            self.assertIs(result[key], False)

    def test_arbitrary_input_position_and_count_not_fixed(self):
        for count in (0, 3, 19):
            args = plan_arguments()
            prefix = ["C:\\owned\\extra" + str(i) + ".obj" for i in range(count)]
            args["argv"][0:0] = prefix
            args["inputs"].extend(input_record(path, coff(("extra" + str(i),))) for i, path in enumerate(prefix))
            result = link.plan_replacement(**args)
            self.assertEqual(result["aggregate_object_insertion_before_expanded_index"], count + 2)
            self.assertEqual([x["token"] for x in result["recipe"]["expanded"]], args["argv"])

    def test_function_count_and_names_are_not_fixture_constants(self):
        args = plan_arguments()
        names = ("entry_one", "namespace_helper", "entry_three")
        args["inputs"][1] = input_record("C:\\owned\\core.obj", coff(names), owner())
        args["selections"] = [selection("C:\\owned\\core.obj", names)]
        args["public_exports"] = ["entry_one", "entry_three"]
        for arm in ("baseline", "protected"):
            args["replacement_objects"][arm] = replacement(coff(names), arm)
        self.assertEqual(link.plan_replacement(**args)["blockers"], [])

    def test_mixed_function_carrier_is_review_not_silent_drop(self):
        args = plan_arguments()
        args["inputs"][1] = input_record("C:\\owned\\core.obj", coff(("score", "unselected")), owner())
        result = link.plan_replacement(**args)
        self.assertEqual(result["status"], "needs_review")
        self.assertIn("mixed_or_missing_native_function_definitions", [x["kind"] for x in result["blockers"]])

    def test_data_directives_unwind_and_comdat_need_evidence(self):
        for name in (".data", ".drectve", ".pdata", ".xdata"):
            args = plan_arguments()
            args["inputs"][1] = input_record("C:\\owned\\core.obj", coff(data=b"keep", data_name=name), owner())
            result = link.plan_replacement(**args)
            self.assertEqual(result["status"], "needs_review")
            self.assertTrue(any(name in x["kind"] for x in result["blockers"]))
        args = plan_arguments()
        args["inputs"][1] = input_record("C:\\owned\\core.obj", coff(text_flags=0x60001020), owner())
        self.assertTrue(any("comdat" in x["kind"] for x in link.plan_replacement(**args)["blockers"]))

    def test_generated_directive_never_implicitly_approved(self):
        args = plan_arguments()
        args["replacement_objects"]["protected"] = replacement(coff(data=b"/DEFAULTLIB:extra", data_name=".drectve"), "protected")
        result = link.plan_replacement(**args)
        self.assertIn("generated_linker_directives_require_review", [x["kind"] for x in result["blockers"]])

    def test_unknown_trailing_payload_needs_review(self):
        args = plan_arguments()
        args["inputs"][1] = input_record("C:\\owned\\core.obj", coff() + b"unknown", owner())
        self.assertIn("uninterpreted_nonzero_object_bytes", [x["kind"] for x in link.plan_replacement(**args)["blockers"]])

    def test_selected_repeated_operand_not_deduplicated(self):
        args = plan_arguments()
        args["argv"].insert(1, "C:\\owned\\core.obj")
        result = link.plan_replacement(**args)
        self.assertIn("selected_carrier_repeated_operand_requires_link_resolution", [x["kind"] for x in result["blockers"]])
        self.assertEqual(sum(e["action"] == "omit_direct_selected_object" for e in result["edits"]), 2)

    def test_wrong_owner_duplicate_selection_and_member_boolean_reject(self):
        for mutation in ("owner", "duplicate", "bool"):
            args = plan_arguments()
            if mutation == "owner":
                args["selections"][0]["owner"] = owner("foreign")
            elif mutation == "duplicate":
                args["selections"].append(copy.deepcopy(args["selections"][0]))
            else:
                args["selections"][0]["member_index"] = True
            with self.subTest(mutation=mutation), self.assertRaises(link.LinkError):
                link.plan_replacement(**args)

    def test_missing_wrong_or_extra_generated_function_reject(self):
        for names in ((), ("wrong",), ("score", "extra")):
            args = plan_arguments()
            args["replacement_objects"]["protected"] = replacement(coff(names), "protected")
            with self.subTest(names=names), self.assertRaisesRegex(link.LinkError, "coverage"):
                link.plan_replacement(**args)

    def test_public_name_and_storage_identity_mandatory(self):
        args = plan_arguments()
        args["selections"][0]["symbols"]["score"]["protected"] = "renamed"
        args["replacement_objects"]["protected"] = replacement(coff(("renamed",)), "protected")
        with self.assertRaisesRegex(link.LinkError, "identity"):
            link.plan_replacement(**args)
        args = plan_arguments()
        args["inputs"][1] = input_record("C:\\owned\\core.obj", coff(storage=3), owner())
        with self.assertRaisesRegex(link.LinkError, "external definition"):
            link.plan_replacement(**args)

    def test_duplicate_original_retained_blocks_selected_code_coverage(self):
        args = plan_arguments()
        args["inputs"][0] = input_record("C:\\owned\\allocator.obj", coff())
        self.assertIn("selected_symbol_retained_or_ambiguous", [x["kind"] for x in link.plan_replacement(**args)["blockers"]])

    def test_generated_runtime_collision_with_retained_input_blocks(self):
        args = plan_arguments()
        args["inputs"][0] = input_record("C:\\owned\\allocator.obj", coff(("vm_run",)))
        self.assertIn("replacement_external_definition_collides_with_retained", [x["kind"] for x in link.plan_replacement(**args)["blockers"]])

    def test_retained_reference_to_renamed_helper_blocks(self):
        args = plan_arguments()
        args["inputs"][0] = input_record("C:\\owned\\allocator.obj", coff(("allocator",), undefined=("helper",), relocations=((0, 1, 4),)))
        args["inputs"][1] = input_record("C:\\owned\\core.obj", coff(("score", "helper")), owner())
        args["selections"] = [selection("C:\\owned\\core.obj", ("score", "helper"))]
        args["selections"][0]["symbols"]["helper"] = {"baseline": "qualified_helper", "protected": "mapped_helper"}
        args["replacement_objects"]["baseline"] = replacement(coff(("score", "qualified_helper")), "baseline")
        args["replacement_objects"]["protected"] = replacement(coff(("score", "mapped_helper")), "protected")
        result = link.plan_replacement(**args)
        self.assertIn("retained_reference_to_renamed_symbol", [x["kind"] for x in result["blockers"]])

    def test_archive_metadata_is_preserved_but_not_assumed_noncode(self):
        args = plan_arguments()
        ar = archive([("lib.rmeta", b"metadata"), ("core.o", coff()), ("keep.o", coff(("keep",)))], [("score", 1), ("keep", 2)])
        index = next(m["index"] for m in link.parse_archive(ar)["members"] if m["name"] == "core.o")
        args["argv"][2] = "C:\\owned\\local.rlib"
        args["inputs"][1] = input_record("C:\\owned\\local.rlib", ar, owner())
        args["selections"] = [selection("C:\\owned\\local.rlib", member=index)]
        result = link.plan_replacement(**args)
        rewrite = result["archive_rewrites"][0]
        self.assertEqual([m["name"] for m in rewrite["retained_members"]], ["lib.rmeta", "keep.o"])
        self.assertTrue(rewrite["writer_required"])
        self.assertIn("unparsed_owned_member_requires_classification", [x["kind"] for x in result["blockers"]])

    def test_runtime_collision_and_replacement_input_alias_reject(self):
        args = plan_arguments()
        args["replacement_objects"]["runtime"] = replacement(coff(), "runtime")
        with self.assertRaisesRegex(link.LinkError, "collision"):
            link.plan_replacement(**args)
        args = plan_arguments()
        args["replacement_objects"]["baseline"]["descriptor"]["path"] = "C:\\owned\\core.obj"
        with self.assertRaisesRegex(link.LinkError, "aliases"):
            link.plan_replacement(**args)

    def test_replacement_must_not_alias_staged_snapshot(self):
        args = plan_arguments()
        args["inputs"][1]["descriptor"]["path"] = "C:\\event\\staged-core.bin"
        args["replacement_objects"]["protected"]["descriptor"]["path"] = "C:\\event\\staged-core.bin"
        with self.assertRaisesRegex(link.LinkError, "aliases"):
            link.plan_replacement(**args)

    def test_json_roundtrip_preserves_fingerprint_and_exact_recipe(self):
        result = link.plan_replacement(**plan_arguments())
        loaded = json.loads(json.dumps(result, sort_keys=True))
        self.assertEqual(loaded, result)
        self.assertEqual(loaded["recipe"]["original_argv"], plan_arguments()["argv"])
        body = {k: v for k, v in loaded.items() if k != "fingerprint"}
        self.assertEqual(link._json_hash(body), result["fingerprint"])


if __name__ == "__main__":
    unittest.main()
