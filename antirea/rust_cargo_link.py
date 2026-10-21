"""Pure, bounded native-link inventory and structural replacement planning.

No filesystem, environment, subprocess, LLVM loading or target execution. The
caller must authenticate Cargo/unit/event provenance and snapshot supplied bytes.
Plans are NOT executable approvals or proofs of source-to-object equivalence.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import ntpath
import re
import struct

MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAX_MEMBERS = 16384
MAX_SYMBOLS = 1000000
MAX_ARGS = 16384
HEX = re.compile(r"[0-9a-f]{64}\Z")
RELOC_WIDTH = {0: 0, 1: 8, 2: 4, 3: 4, 4: 4, 5: 4, 6: 4,
               7: 4, 8: 4, 9: 4, 10: 2, 11: 4}


class LinkError(ValueError):
    pass


def _require(ok, message):
    if not ok:
        raise LinkError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _json_hash(value):
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("utf-8"))


def _bytes(raw, minimum=0, maximum=MAX_FILE):
    _require(type(raw) is bytes and minimum <= len(raw) <= maximum,
             "bounded immutable bytes required")
    return raw


def _text(value, label="text"):
    _require(type(value) is str and 0 < len(value) <= 32768
             and all(ord(c) >= 32 and c not in '\"\x7f' for c in value), label)
    return value


def _exact(value, keys, label):
    _require(type(value) is dict and set(value) == set(keys), label)


def path_key(value, cwd=None):
    """Lexical Windows identity only: caller owns realpath/reparse/link gates."""
    _text(value, "invalid path")
    _require(not value.startswith(("\\\\", "//")), "UNC/device path unsupported")
    drive, tail = ntpath.splitdrive(value)
    if not drive:
        _require(cwd is not None and not tail.startswith(("/", "\\")),
                 "absolute drive path or cwd-relative operand required")
        value = ntpath.join(cwd, value)
        drive, tail = ntpath.splitdrive(value)
    _require(re.fullmatch(r"[A-Za-z]:", drive) is not None
             and tail.startswith(("/", "\\")) and ":" not in tail,
             "drive-relative path/alternate stream unsupported")
    normalized = ntpath.normpath(value)
    parts = normalized.replace("/", "\\").split("\\")
    _require(all(part.casefold() not in ("env.setting", "linkrepro") for part in parts),
             "sensitive path forbidden")
    _require(all(not part.endswith((" ", ".")) for part in parts[1:] if part),
             "ambiguous Windows path")
    return ntpath.normcase(normalized)


def descriptor(value, raw=None):
    _exact(value, ("path", "sha256", "bytes"), "descriptor shape")
    path_key(value["path"])
    _require(type(value["sha256"]) is str and HEX.fullmatch(value["sha256"]), "SHA256")
    _require(type(value["bytes"]) is int and 0 <= value["bytes"] <= MAX_FILE,
             "descriptor byte count")
    if raw is not None:
        _bytes(raw)
        _require(value["bytes"] == len(raw) and value["sha256"] == digest(raw),
                 "descriptor/content mismatch")
    return dict(value)


def _name(raw):
    _require(0 < len(raw) <= 32768 and b"\0" not in raw,
             "empty/oversized/NUL symbol or member name")
    try:
        value = raw.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise LinkError("unsupported non-UTF8 name") from exc
    _require(all(ord(c) >= 32 and c != "\x7f" for c in value), "control in name")
    return value


def parse_coff(raw):
    """Ordinary AMD64 COFF; inventory does not disassemble or infer ABI.

    Header/section/symbol/relocation layouts follow installed LLVM 22.1.0
    Object/COFF.h. Unsupported bigobj/import/LTO forms are never treated as
    ordinary objects. Weak/common/COMDAT are recorded, not approved for removal.
    """
    _bytes(raw, 20)
    machine, count, stamp, symoff, nsyms, optional, flags = struct.unpack_from("<HHIIIHH", raw)
    _require(machine == 0x8664 and optional == 0 and 1 <= count <= 4096,
             "ordinary AMD64 COFF required (bigobj/import/PE unsupported)")
    _require(nsyms <= MAX_SYMBOLS, "symbol bound")
    header_end = 20 + count * 40
    _require(header_end <= len(raw), "truncated section table")
    spans = [(0, header_end, "headers")]

    def span(offset, size, label):
        _require(type(offset) is int and type(size) is int and offset >= header_end
                 and size > 0 and offset <= len(raw) - size, "out-of-bounds " + label)
        spans.append((offset, offset + size, label))
        return raw[offset:offset + size]

    strings = b""
    if symoff:
        _require(symoff >= header_end and symoff + nsyms * 18 + 4 <= len(raw),
                 "truncated symbol/string table")
        stroff = symoff + nsyms * 18
        strlen = struct.unpack_from("<I", raw, stroff)[0]
        _require(strlen >= 4, "string table length")
        table = span(symoff, nsyms * 18 + strlen, "symbols_and_strings")
        strings = table[nsyms * 18:]
    else:
        _require(nsyms == 0, "symbols without table")

    def string_at(offset):
        _require(4 <= offset < len(strings), "string table offset")
        end = strings.find(b"\0", offset)
        _require(end >= 0, "unterminated string")
        return _name(strings[offset:end])

    sections = []
    for i in range(count):
        offset = 20 + i * 40
        name_raw = raw[offset:offset + 8]
        short = name_raw.split(b"\0", 1)[0]
        _require(b"\0" not in name_raw or name_raw[len(short):] == b"\0" * (8 - len(short)),
                 "nonzero section name padding")
        name = string_at(int(short[1:])) if re.fullmatch(rb"/[0-9]+", short) else _name(short)
        _require(not name.startswith("/"), "unsupported long section name encoding")
        virtual_size, virtual_address, size, pointer, relptr, lineptr, nrel, nline, sf = struct.unpack_from(
            "<IIIIIIHHI", raw, offset + 8)
        _require(virtual_address == 0, "object section virtual address unsupported")
        _require(nline == 0 and lineptr == 0, "legacy COFF line table unsupported")
        _require(not sf & 0x01000000, "extended relocation counts unsupported")
        bss = bool(sf & 0x80)
        if size and not (bss and pointer == 0):
            data = span(pointer, size, "section:" + str(i + 1))
        else:
            _require(pointer == 0 or size == 0, "invalid empty section pointer")
            data = b""
        if nrel:
            span(relptr, nrel * 10, "relocations:" + str(i + 1))
        else:
            _require(relptr == 0, "nonzero empty relocation pointer")
        sections.append({"index": i + 1, "name": name, "header_offset": offset,
                         "virtual_size": virtual_size, "virtual_address": virtual_address,
                         "bytes": size, "raw_offset": pointer, "raw_sha256": digest(data),
                         "flags": sf, "code": bool(sf & 0x20), "executable": bool(sf & 0x20000000),
                         "uninitialized": bss, "comdat": bool(sf & 0x1000),
                         "relocation_offset": relptr, "relocation_count": nrel, "relocations": []})
    ordered_spans = sorted(spans)
    for previous, current in zip(ordered_spans, ordered_spans[1:]):
        _require(previous[1] <= current[0], "overlapping COFF ranges")
    symbols, by_index = [], {}
    i = 0
    while i < nsyms:
        offset = symoff + i * 18
        nr = raw[offset:offset + 8]
        name = string_at(struct.unpack_from("<I", nr, 4)[0]) if nr[:4] == b"\0" * 4 else _name(nr.rstrip(b"\0"))
        value, section, typ, storage, naux = struct.unpack_from("<IhHBB", raw, offset + 8)
        _require(-2 <= section <= count and i + 1 + naux <= nsyms, "symbol section/auxiliary bounds")
        aux = raw[offset + 18:offset + 18 * (1 + naux)]
        is_code = section > 0 and sections[section - 1]["executable"]
        if section > 0:
            _require(value <= sections[section - 1]["bytes"], "symbol value outside section")
            if is_code and typ == 0x20:
                _require(value < sections[section - 1]["bytes"], "function entry at/after section end")
        # IMAGE_SYM_ABSOLUTE (-1) is a definition without a section, not an
        # undefined reference. Its Value is the constant itself, not a code
        # offset; preserve it and include external absolutes in collision sets.
        absolute_definition = section == -1
        common_definition = section == 0 and value != 0 and storage == 2
        definition_kind = ("section" if section > 0 else "absolute" if absolute_definition
                           else "debug" if section == -2 else "common" if common_definition
                           else "undefined")
        row = {"index": i, "offset": offset, "name": name, "value": value,
               "section": section, "type": typ, "storage_class": storage,
               "auxiliary_count": naux, "auxiliary_hex": aux.hex(), "record_sha256": digest(raw[offset:offset + 18 * (1 + naux)]),
               "defined": section > 0 or absolute_definition, "definition_kind": definition_kind,
               "absolute": absolute_definition, "external": storage == 2, "executable": is_code,
               "common": common_definition, "weak": storage == 105}
        if storage == 105:
            _require(naux == 1, "weak symbol auxiliary count")
            row["weak_target_index"], row["weak_characteristics"] = struct.unpack_from("<II", aux)
        if storage == 3 and section > 0 and naux == 1 and name == sections[section - 1]["name"]:
            length, relocations, lines, checksum, number, selection, unused, high = struct.unpack("<IHHIHBBH", aux)
            row["section_definition"] = {"length": length, "relocations": relocations,
                "lines": lines, "checksum": checksum, "associated_section": number,
                "selection": selection, "unused": unused, "high_number": high}
        symbols.append(row)
        by_index[i] = row
        i += 1 + naux
    for row in symbols:
        if row["weak"]:
            _require(row["weak_target_index"] in by_index, "weak target points outside primary symbols")
    for section in sections:
        for j in range(section["relocation_count"]):
            offset = section["relocation_offset"] + j * 10
            address, symbol_index, typ = struct.unpack_from("<IIH", raw, offset)
            _require(symbol_index in by_index, "relocation points at auxiliary/missing symbol")
            _require(typ in RELOC_WIDTH, "unsupported AMD64 relocation type")
            width = RELOC_WIDTH[typ]
            _require(address <= section["bytes"] - width, "relocation write exceeds section")
            section["relocations"].append({"offset": offset, "address": address, "type": typ,
                "width": width, "symbol_index": symbol_index, "symbol": by_index[symbol_index]["name"],
                "record_sha256": digest(raw[offset:offset + 10])})
    gaps, cursor = [], 0
    for start, end, _ in ordered_spans:
        if start > cursor:
            gaps.append({"offset": cursor, "bytes": start - cursor, "sha256": digest(raw[cursor:start]),
                         "all_zero": not any(raw[cursor:start])})
        cursor = end
    if cursor < len(raw):
        gaps.append({"offset": cursor, "bytes": len(raw) - cursor, "sha256": digest(raw[cursor:]),
                     "all_zero": not any(raw[cursor:])})
    return {"schema_version": 1, "kind": "coff_amd64", "sha256": digest(raw), "bytes": len(raw),
            "timestamp": stamp, "flags": flags, "sections": sections, "symbols": symbols,
            "symbol_slots": nsyms, "symbol_table_offset": symoff, "uninterpreted_ranges": gaps}


def _index_names(data, offset, count):
    names = []
    for _ in range(count):
        end = data.find(b"\0", offset)
        _require(end >= offset, "archive index unterminated symbol")
        names.append(_name(data[offset:end]))
        offset = end + 1
    _require(offset == len(data), "archive index extra bytes")
    return names


def parse_archive(raw):
    """Regular ar with GNU/COFF linker tables; thin/BSD/64-bit indices reject.

    Every physical member is retained, including metadata and duplicate names.
    Index offsets bind to real member headers, not names. No member is extracted.
    """
    _bytes(raw, 8)
    _require(raw.startswith(b"!<arch>\n"), "regular archive magic required")
    members, cursor, longnames = [], 8, None
    while cursor < len(raw):
        _require(len(members) < MAX_MEMBERS and cursor + 60 <= len(raw), "archive member count/header")
        header = raw[cursor:cursor + 60]
        _require(header[58:] == b"`\n", "archive header terminator")
        rawname = header[:16].rstrip(b" ")
        _require(rawname and not rawname.startswith(b"#1/") and rawname != b"/SYM64/",
                 "BSD/64-bit archive variant unsupported")
        size_text = header[48:58].strip()
        _require(re.fullmatch(rb"[0-9]+", size_text) is not None, "archive member size")
        size = int(size_text)
        start, end = cursor + 60, cursor + 60 + size
        _require(end <= len(raw), "truncated archive member")
        if size & 1:
            _require(end < len(raw) and raw[end:end + 1] == b"\n", "archive padding")
        payload = raw[start:end]
        metadata = {}
        for key, a, b, pattern in (("timestamp", 16, 28, rb"[0-9]*"), ("uid", 28, 34, rb"[0-9]*"),
                                   ("gid", 34, 40, rb"[0-9]*"), ("mode", 40, 48, rb"[0-7]*")):
            field = header[a:b].strip()
            _require(re.fullmatch(pattern, field) is not None, "archive numeric metadata")
            metadata[key] = field.decode("ascii")
        kind = "linker_index" if rawname == b"/" else "longnames" if rawname == b"//" else "member"
        if kind == "longnames":
            _require(longnames is None, "duplicate long-name table")
            longnames = payload
        members.append({"index": len(members), "header_offset": cursor, "data_offset": start,
                        "bytes": size, "sha256": digest(payload), "header_sha256": digest(header),
                        "raw_name_hex": rawname.hex(), "name": None, "kind": kind, "metadata": metadata})
        cursor = end + (size & 1)
    long_lookup = {}
    if longnames is not None:
        table_len = len(longnames)
        offset = 0
        while offset < table_len:
            # GNU/COFF long-name tables pad the member payload to even length with
            # a single trailing '\n'. LLVM-produced rustc rlibs end 'name\x00\n': a
            # NUL-terminated name plus that one alignment byte. The pad is never a
            # name entry and never an offset boundary, so consume a lone final
            # newline here instead of mis-reading it as an unterminated name. Any
            # other leftover (non-newline, mid-table, or odd-length) still fails.
            if offset == table_len - 1 and table_len % 2 == 0 and longnames[offset:] == b"\n":
                offset = table_len
                break
            nul, gnu = longnames.find(b"\0", offset), longnames.find(b"/\n", offset)
            ends = [(n, extra) for n, extra in ((nul, 1), (gnu, 2)) if n >= 0]
            _require(ends, "unterminated archive long name")
            end, extra = min(ends)
            long_lookup[offset] = _name(longnames[offset:end])
            offset = end + extra
        _require(offset == table_len, "archive long-name table trailing bytes")
    ordinary = {}
    index_members = []
    for m in members:
        nr = bytes.fromhex(m["raw_name_hex"])
        if m["kind"] == "member":
            if nr.startswith(b"/"):
                _require(re.fullmatch(rb"/[0-9]+", nr) is not None and int(nr[1:]) in long_lookup,
                         "archive long-name offset is not an entry boundary")
                m["name"] = long_lookup[int(nr[1:])]
            else:
                _require(nr.endswith(b"/"), "unsupported short archive name")
                m["name"] = _name(nr[:-1])
            ordinary[m["header_offset"]] = m
        else:
            m["name"] = nr.decode("ascii")
            if m["kind"] == "linker_index":
                index_members.append(m)
    _require(len(index_members) <= 2, "too many archive linker indices")
    _require(not index_members or index_members[0]["index"] == 0,
             "first archive index must precede ordinary members")
    if len(index_members) == 2:
        _require(index_members[1]["index"] == 1, "second COFF index must immediately follow first")
    indices = []
    for ordinal, m in enumerate(index_members):
        data = raw[m["data_offset"]:m["data_offset"] + m["bytes"]]
        _require(len(data) >= 4, "short archive index")
        if ordinal == 0:
            n = struct.unpack_from(">I", data)[0]
            _require(n <= MAX_SYMBOLS and 4 + n * 4 <= len(data), "archive index bounds")
            offsets = list(struct.unpack_from(">" + str(n) + "I", data, 4)) if n else []
            names = _index_names(data, 4 + n * 4, n)
            fmt = "big_endian_32"
        else:
            n = struct.unpack_from("<I", data)[0]
            _require(n <= MAX_MEMBERS and 8 + n * 4 <= len(data), "COFF member-index bounds")
            offsets_all = list(struct.unpack_from("<" + str(n) + "I", data, 4)) if n else []
            _require(len(set(offsets_all)) == n and all(x in ordinary for x in offsets_all),
                     "COFF index invalid/duplicate member offset")
            count = struct.unpack_from("<I", data, 4 + n * 4)[0]
            p = 8 + n * 4
            _require(count <= MAX_SYMBOLS and p + count * 2 <= len(data), "COFF symbol-index bounds")
            numbers = list(struct.unpack_from("<" + str(count) + "H", data, p)) if count else []
            _require(all(1 <= x <= n for x in numbers), "COFF member-index range")
            offsets = [offsets_all[x - 1] for x in numbers]
            names = _index_names(data, p + count * 2, count)
            _require(names == sorted(names, key=lambda x: x.encode("utf-8")), "unsorted COFF second index")
            fmt = "coff_little_endian_32_16"
        _require(all(x in ordinary for x in offsets), "archive index points outside ordinary member header")
        indices.append({"member_index": m["index"], "format": fmt,
                        "entries": [{"symbol": name, "member_index": ordinary[off]["index"],
                                     "member_offset": off} for name, off in zip(names, offsets)]})
    if len(indices) == 2:
        keyed = lambda ix: Counter((e["symbol"], e["member_index"]) for e in ix["entries"])
        _require(keyed(indices[0]) == keyed(indices[1]), "archive linker indices disagree")
    return {"schema_version": 1, "kind": "archive", "sha256": digest(raw), "bytes": len(raw),
            "members": members, "indices": indices, "index_symbol_semantics_verified": False}


def response_tokens(raw):
    _bytes(raw, 1, 1024 * 1024)
    try:
        text = raw[2:].decode("utf-16-le", "strict") if raw.startswith(b"\xff\xfe") else raw.decode("ascii", "strict")
    except UnicodeError as exc:
        raise LinkError("response encoding: ASCII or UTF16LE BOM required") from exc
    _require(text.endswith("\n") and "\0" not in text, "response terminal newline/NUL")
    result = []
    # Matches recorder.rs enumerate(): response_line is ZERO based.
    for number, line in enumerate(text[:-1].split("\n")):
        line = line[:-1] if line.endswith("\r") else line
        _require(line and all(ord(c) >= 32 for c in line), "response empty/control line")
        if line.startswith('"') and line.endswith('"') and len(line) > 2:
            token = line[1:-1]
        else:
            _require(not any(c.isspace() for c in line), "unquoted response whitespace")
            token = line
        _text(token, "response token")
        _require(not token.endswith("\\") and not token.startswith("@"), "ambiguous escape/nested response")
        result.append({"line": number, "token": token})
    _require(len(result) <= MAX_ARGS, "response token bound")
    return result


def _classify(token):
    _text(token, "link argument")
    upper = token.upper()
    _require(not upper.startswith(("/FORCE", "/LINKREPRO", "-FORCE", "-LINKREPRO")), "unsafe link override/dump")
    for prefix, kind, role in (("/OUT:", "output", "out"), ("/IMPLIB:", "output", "implib"),
                               ("/PDB:", "output", "pdb"), ("/MAP:", "output", "map"),
                               ("/DEF:", "input", "def"), ("/NATVIS:", "input", "natvis"),
                               ("/WHOLEARCHIVE:", "input", "wholearchive"),
                               ("/LIBPATH:", "search", "libpath"), ("/DEFAULTLIB:", "default", "defaultlib")):
        if upper.startswith(prefix):
            _require(len(token) > len(prefix), "empty link operand")
            operand = token[len(prefix):]
            if kind == "default":
                if ntpath.isabs(operand):
                    return {"kind": "input", "role": "defaultlib_explicit", "operand": operand, "prefix": token[:len(prefix)]}
                _require(not any(c in operand for c in "\\/:") and operand.lower().endswith(".lib"),
                         "unclassified default-library spelling")
            return {"kind": kind, "role": role, "operand": operand, "prefix": token[:len(prefix)]}
    controls = {"/NOLOGO", "/NXCOMPAT", "/DYNAMICBASE", "/DLL", "/DEBUG", "/DEBUG:FULL",
                "/OPT:REF,ICF", "/OPT:REF", "/OPT:ICF", "/INCREMENTAL:NO", "/PDBALTPATH:%_PDB%",
                "/MACHINE:X64", "/LARGEADDRESSAWARE", "/NOENTRY"}
    if upper in controls or re.fullmatch(r"/SUBSYSTEM:(CONSOLE|WINDOWS)(,[0-9]+(\.[0-9]+)?)?", upper):
        return {"kind": "control", "role": "control"}
    _require(not token.startswith(("/", "-", "@")), "unsupported linker option")
    _require(upper.endswith((".OBJ", ".O", ".LIB", ".RLIB")), "unclassified explicit input")
    return {"kind": "input", "role": "object_or_archive", "operand": token, "prefix": ""}


def parse_link_recipe(argv, cwd, response_files):
    """argv excludes linker executable; all supplied responses must be consumed.

    Input occurrences are NEVER deduplicated. Search/default-lib coverage remains
    explicitly unresolved; this is token coverage, not native linker closure.
    """
    cwd_key = path_key(cwd)
    _require(type(argv) is list and 0 < len(argv) <= MAX_ARGS, "argv bound")
    _require(type(response_files) is dict and len(response_files) <= 128, "response map bound")
    responses = {}
    total = 0
    for path, item in response_files.items():
        key = path_key(path)
        _require(key not in responses, "response path identity collision")
        _exact(item, ("descriptor", "content"), "response record")
        desc = descriptor(item["descriptor"], item["content"])
        _require(path_key(desc["path"]) == key, "response descriptor path mismatch")
        total += len(item["content"])
        _require(total <= 16 * 1024 * 1024, "response total bound")
        responses[key] = (desc, response_tokens(item["content"]))
    expanded, used = [], set()
    for index, token in enumerate(argv):
        _text(token, "argv token")
        if token.startswith("@"):
            key = path_key(token[1:], cwd_key)
            _require(key in responses, "missing bound response bytes")
            used.add(key)
            rows = [(r["token"], {"argv_index": index, "response_path": key, "response_line": r["line"]})
                    for r in responses[key][1]]
        else:
            rows = [(token, {"argv_index": index, "response_path": None, "response_line": None})]
        for value, occurrence in rows:
            info = _classify(value)
            row = {"index": len(expanded), "token": value, "occurrence": occurrence, **info}
            if info["kind"] in ("input", "output", "search"):
                row["path"] = path_key(info["operand"], cwd_key)
            expanded.append(row)
            _require(len(expanded) <= MAX_ARGS, "expanded argument bound")
    _require(used == set(responses), "unused response evidence")
    outputs = [row for row in expanded if row["kind"] == "output"]
    _require(sum(row["role"] == "out" for row in outputs) == 1, "exactly one explicit output required")
    _require(len({row["role"] for row in outputs}) == len(outputs)
             and len({row["path"] for row in outputs}) == len(outputs), "duplicate output role/path")
    inputs = [row for row in expanded if row["kind"] == "input"]
    _require(not set(r["path"] for r in inputs) & set(r["path"] for r in outputs), "input/output alias")
    result = {"schema_version": 1, "cwd": cwd, "original_argv": list(argv), "expanded": expanded,
              "responses": [responses[key][0] for key in sorted(used)], "token_coverage_complete": True,
              "native_dependency_closure_verified": False,
              "unresolved_default_libraries": [r["operand"] for r in expanded if r["kind"] == "default"]}
    result["fingerprint"] = _json_hash(result)
    return result

def _owner(value):
    if value is None:
        return None
    _exact(value, ("unit", "package_id", "target_name", "source"), "owner shape")
    for field in ("unit", "package_id", "target_name"):
        _text(value[field], "owner field")
    path_key(value["source"])
    return dict(value)


def bind_recorded_recipe(start, staged_contents):
    """Re-derive accepted native-recorder v1 start fields from supplied bytes.

    Does not read paths, authenticate event origin, inspect finish/cleanup, or
    bind rustc identity. These remain mandatory caller gates. Descriptor paths
    below refer to retained staged bytes; original operand spelling is separate.
    All start fields (including not interpreted fields) are bound by its digest.
    """
    _require(type(start) is dict and type(start.get("schema_version")) is int
             and start["schema_version"] == 1, "recorder schema 1 required")
    _require(start.get("status") == "explicit_inputs_staged_not_full_link_closure"
             and start.get("full_native_link_closure_verified") is False, "recorder start status")
    observed = start.get("staged_inputs")
    _require(type(observed) is list and len(observed) <= 1024
             and type(staged_contents) is list and len(staged_contents) == len(observed),
             "exact staged byte list required")
    by_original, bindings, total = {}, [], 0
    for index, (row, raw) in enumerate(zip(observed, staged_contents)):
        _exact(row, ("original", "staged", "bytes", "sha256", "identity", "links", "first_role"), "recorder staged shape")
        key = path_key(row["original"])
        _require(key not in by_original, "recorder original identity collision")
        _text(row["identity"], "file identity")
        _text(row["first_role"], "staged role")
        _require(type(row["links"]) is int and row["links"] >= 1, "recorded link count")
        desc = descriptor({"path": row["staged"], "sha256": row["sha256"], "bytes": row["bytes"]}, raw)
        total += len(raw)
        _require(total <= MAX_TOTAL, "staged byte total")
        by_original[key] = index
        bindings.append({"path": key, "descriptor": desc, "staged_index": index})
    argv, cwd = start.get("original_argv"), start.get("cwd")
    _require(type(argv) is list and 0 < len(argv) <= MAX_ARGS, "recorded argv")
    path_key(cwd)
    response_map, expected_occurrences = {}, []
    for index, token in enumerate(argv):
        _text(token, "recorded argument")
        if not token.startswith("@"):
            continue
        key = path_key(token[1:], cwd)
        _require(key in by_original, "recorded response missing staged bytes")
        at = by_original[key]
        row = observed[at]
        response_map[key] = {"descriptor": {"path": key, "sha256": row["sha256"], "bytes": row["bytes"]},
                             "content": staged_contents[at]}
        expected_occurrences.append({"argv_index": index, "kind": "response", "staged_index": at})
    recipe = parse_link_recipe(argv, cwd, response_map)
    expected_expanded, input_bindings, outputs, searches = [], {}, {}, []
    for row in recipe["expanded"]:
        location = {"argv_index": row["occurrence"]["argv_index"], "response_line": row["occurrence"]["response_line"]}
        expected_expanded.append({**location, "token": row["token"]})
        if row["kind"] == "input":
            _require(row["path"] in by_original, "recorded input missing staged bytes")
            at = by_original[row["path"]]
            expected_occurrences.append({**location, "kind": row["role"], "staged_index": at, "token": row["token"]})
            input_bindings[at] = bindings[at]
        elif row["kind"] == "output":
            outputs[row["role"]] = row["path"]
        elif row["kind"] == "search":
            searches.append(row["path"])
    _require(start.get("expanded_arguments") == expected_expanded, "recorded expanded argv differs")
    _require(start.get("ordered_input_occurrences") == expected_occurrences, "recorded input occurrence order/coverage differs")
    _require({x["staged_index"] for x in expected_occurrences} == set(range(len(observed))), "unused staged input")
    first_roles = {}
    for item in expected_occurrences:
        first_roles.setdefault(item["staged_index"], item["kind"])
    _require(all(row["first_role"] == first_roles[index] for index, row in enumerate(observed)), "staged first-role mismatch")
    _require(type(start.get("explicit_outputs")) is dict
             and {k: path_key(v) for k, v in start["explicit_outputs"].items()} == outputs,
             "recorded outputs differ")
    _require(type(start.get("ordered_argument_libpath")) is list
             and [path_key(v) for v in start["ordered_argument_libpath"]] == searches,
             "recorded search order differs")
    _require(start.get("unresolved_default_library_names") == recipe["unresolved_default_libraries"],
             "recorded default library names differ")
    return {"schema_version": 1, "status": "recorded_recipe_bytes_bound_not_authenticated",
            "start_document_sha256": _json_hash(start), "recipe": recipe,
            "staged_inputs": bindings, "input_bindings": list(input_bindings.values()),
            "cargo_unit_authenticity_verified": False, "native_process_cleanup_verified": False,
            "native_dependency_closure_verified": False}


def _payload_kind(raw):
    if raw.startswith(b"!<arch>\n"):
        return "archive"
    if raw.startswith(b"\x64\x86"):
        return "coff_amd64"
    if raw.startswith(b"\x00\x00\xff\xff"):
        return "unsupported_bigobj_or_import"
    if raw.startswith((b"BC\xc0\xde", b"\xde\xc0\x17\x0b")):
        return "unsupported_llvm_bitcode"
    return "opaque"


def inventory_inputs(recipe, records):
    """Bind exact input paths to supplied staged bytes; owner is caller assertion.

    records: [{path (original operand), descriptor (staged), content, owner|null}].
    Repeated recipe occurrences share bytes but remain separate in the recipe.
    """
    _require(type(records) is list and len(records) <= 1024, "input record bound")
    result, seen, staged, total = [], set(), {}, 0
    wanted = {r["path"] for r in recipe["expanded"] if r["kind"] == "input"}
    for record in records:
        _exact(record, ("path", "descriptor", "content", "owner"), "input record shape")
        key = path_key(record["path"])
        _require(key not in seen and key in wanted, "duplicate/foreign input path")
        seen.add(key)
        desc = descriptor(record["descriptor"], record["content"])
        staged_key = path_key(desc["path"])
        observed = (desc["sha256"], desc["bytes"])
        _require(staged_key not in staged or staged[staged_key] == observed,
                 "staged path has conflicting content descriptors")
        staged[staged_key] = observed
        total += len(record["content"])
        _require(total <= MAX_TOTAL, "input total bound")
        owner = _owner(record["owner"])
        raw = record["content"]
        kind = _payload_kind(raw)
        parsed = parse_archive(raw) if kind == "archive" else parse_coff(raw) if kind == "coff_amd64" else None
        members = []
        if kind == "archive":
            for member in parsed["members"]:
                if member["kind"] != "member":
                    continue
                data = raw[member["data_offset"]:member["data_offset"] + member["bytes"]]
                mkind = _payload_kind(data)
                members.append({"member": member, "payload_kind": mkind,
                                "coff": parse_coff(data) if mkind == "coff_amd64" else None})
        result.append({"path": key, "descriptor": desc, "owner": owner, "kind": kind,
                       "parsed": parsed, "members": members,
                       "occurrences": [r["index"] for r in recipe["expanded"] if r["kind"] == "input" and r["path"] == key]})
    _require(seen == wanted, "missing input bytes")
    return result


def _carrier_issues(coff, selected_names):
    issues = []
    code = [s for s in coff["symbols"] if s["defined"] and s["executable"] and s["type"] == 0x20]
    if Counter(s["name"] for s in code) != Counter(list(selected_names)):
        issues.append("mixed_or_missing_native_function_definitions")
    for symbol in coff["symbols"]:
        if symbol["weak"] or symbol["common"]:
            issues.append("weak_or_common_symbol")
        # A selected whole object can carry an absolute definition alongside its
        # functions. This planner has no regeneration/retention proof for it,
        # including static feature symbols; do not silently discard the value.
        if symbol["absolute"]:
            issues.append("unregenerated_absolute_definition:" + symbol["name"])
        if symbol["defined"] and symbol["executable"] and symbol["type"] == 0x20:
            sec = coff["sections"][symbol["section"] - 1]
            if not sec["code"] or sec["uninitialized"] or not 0 <= symbol["value"] < sec["bytes"]:
                issues.append("invalid_function_entry_offset")
        elif symbol["defined"] and symbol["storage_class"] == 2:
            issues.append("unregenerated_external_data_or_nontyped_definition")
    for sec in coff["sections"]:
        if sec["comdat"]:
            issues.append("comdat_requires_explicit_ownership_proof")
        if sec["bytes"] and not (sec["code"] and sec["executable"] and not sec["uninitialized"]):
            issues.append("data_directive_unwind_or_metadata_section_requires_preservation:" + sec["name"])
        if sec["bytes"] and sec["executable"] and not any(s["section"] == sec["index"] for s in code):
            issues.append("anonymous_executable_section")
    if any(not gap["all_zero"] for gap in coff["uninterpreted_ranges"]):
        issues.append("uninterpreted_nonzero_object_bytes")
    return sorted(set(issues))


def verify_rewritten_archive(original, rewritten, removed_member_indices):
    """Verify OMIT-only archive rewrite. New code objects are separate operands.

    Pinned external archive writer is future work; never edits bytes here.
    Names/payload/order/metadata of every retained member must survive. Linker
    tables may move/reorder but must describe exactly the retained old entries.
    """
    before, after = parse_archive(original), parse_archive(rewritten)
    _require(type(removed_member_indices) is list and removed_member_indices
             and all(type(x) is int for x in removed_member_indices)
             and len(set(removed_member_indices)) == len(removed_member_indices), "removal indices")
    ordinary = {m["index"]: m for m in before["members"] if m["kind"] == "member"}
    _require(set(removed_member_indices) <= set(ordinary), "remove ordinary members only")
    kept = [m for m in before["members"] if m["kind"] == "member" and m["index"] not in removed_member_indices]
    actual = [m for m in after["members"] if m["kind"] == "member"]
    signature = lambda m: (m["name"], m["sha256"], m["bytes"], m["metadata"])
    _require([signature(m) for m in kept] == [signature(m) for m in actual], "retained archive member bytes/name/order/metadata differ")
    _require(bool(before["indices"]) == bool(after["indices"]), "archive index presence changed")
    if before["indices"]:
        old_positions = {m["index"]: i for i, m in enumerate(kept)}
        new_positions = {m["index"]: i for i, m in enumerate(actual)}
        expected = Counter((e["symbol"], old_positions[e["member_index"]])
                           for e in before["indices"][0]["entries"] if e["member_index"] in old_positions)
        observed = Counter((e["symbol"], new_positions[e["member_index"]]) for e in after["indices"][0]["entries"])
        _require(expected == observed, "rewritten archive symbol index differs from retained entries")
    return {"status": "retained_archive_payloads_verified", "original_sha256": digest(original),
            "rewritten_sha256": digest(rewritten), "removed_member_indices": list(removed_member_indices),
            "retained": [{"before_index": a["index"], "after_index": b["index"], "name": a["name"],
                          "sha256": a["sha256"], "bytes": a["bytes"]} for a, b in zip(kept, actual)],
            "rustc_metadata_semantics_verified": False}


def plan_replacement(argv, cwd, response_files, inputs, selections, replacement_objects, public_exports):
    """Return structural plan + blockers, never executable commands.

    Selection exact shape: input_path, member_index|null, owner, symbols
    ({native_name:{baseline,protected}}), lineage (authenticated upstream JSON
    descriptor). Every selected carrier must be entirely accounted, not merely
    have one matching public export. This module does not authenticate lineage.
    """
    recipe = parse_link_recipe(argv, cwd, response_files)
    inventory = inventory_inputs(recipe, inputs)
    _require(type(selections) is list and 0 < len(selections) <= MAX_MEMBERS, "selection bound")
    _require(type(public_exports) is list and public_exports and all(type(x) is str for x in public_exports)
             and len(set(public_exports)) == len(public_exports), "public exports")
    by_path = {row["path"]: row for row in inventory}
    chosen, issues, maps = {}, [], {"baseline": {}, "protected": {}}
    for selection in selections:
        _exact(selection, ("input_path", "member_index", "owner", "symbols", "lineage"), "selection shape")
        key = path_key(selection["input_path"])
        _require(key in by_path, "selection input not in recipe")
        item = by_path[key]
        owner = _owner(selection["owner"])
        _require(owner is not None and owner == item["owner"], "selected carrier owner mismatch")
        descriptor(selection["lineage"])
        member_index = selection["member_index"]
        _require(member_index is None or type(member_index) is int, "member index type")
        identity = (key, member_index)
        _require(identity not in chosen, "duplicate selected carrier")
        if member_index is None:
            _require(item["kind"] == "coff_amd64", "direct selected input must be ordinary COFF")
            coff = item["parsed"]
            member = None
        else:
            _require(item["kind"] == "archive", "selected member needs archive")
            candidates = [m for m in item["members"] if m["member"]["index"] == member_index]
            _require(len(candidates) == 1 and candidates[0]["coff"] is not None, "selected member must be ordinary COFF")
            coff, member = candidates[0]["coff"], candidates[0]["member"]
        symbols = selection["symbols"]
        _require(type(symbols) is dict and 0 < len(symbols) <= MAX_SYMBOLS, "selection symbol map")
        for source, targets in symbols.items():
            _text(source, "native symbol")
            _exact(targets, ("baseline", "protected"), "arm symbol map")
            for arm in maps:
                _text(targets[arm], "generated symbol")
                _require(targets[arm] not in maps[arm].values(), "generated symbol collision")
                maps[arm][(key, member_index, source)] = targets[arm]
        carrier_issues = _carrier_issues(coff, symbols)
        issues.extend({"kind": reason, "input": key, "member_index": member_index} for reason in carrier_issues)
        if len(item["occurrences"]) != 1:
            issues.append({"kind": "selected_carrier_repeated_operand_requires_link_resolution", "input": key})
        chosen[identity] = {"input": item, "member": member, "coff": coff, "selection": selection}
    _exact(replacement_objects, ("baseline", "protected", "runtime"), "replacement objects")
    replacement = {}
    consumed_paths = set(by_path) | {path_key(item["descriptor"]["path"]) for item in inventory}
    consumed_paths.update(path_key(item["path"]) for item in recipe["responses"])
    for role, item in replacement_objects.items():
        _exact(item, ("descriptor", "content"), "replacement object record")
        desc = descriptor(item["descriptor"], item["content"])
        _require(path_key(desc["path"]) not in consumed_paths, "replacement aliases original/staged input")
        replacement[role] = {"descriptor": desc, "coff": parse_coff(item["content"])}
        if any(s["name"] == ".drectve" and s["bytes"] for s in replacement[role]["coff"]["sections"]):
            issues.append({"kind": "generated_linker_directives_require_review", "arm": role})
        if any(s["weak"] or s["common"] for s in replacement[role]["coff"]["symbols"]):
            issues.append({"kind": "generated_weak_or_common_symbol_requires_review", "arm": role})
    _require(len({path_key(r["descriptor"]["path"]) for r in replacement.values()}) == 3,
             "replacement output paths collide")
    for arm in maps:
        names = [s["name"] for s in replacement[arm]["coff"]["symbols"] if s["defined"] and s["type"] == 0x20 and s["executable"]]
        _require(Counter(names) == Counter(maps[arm].values()), "generated function coverage mismatch")
    selected_names = Counter(name for row in chosen.values() for name in row["selection"]["symbols"])
    for name in public_exports:
        _text(name, "public export")
        _require(selected_names[name] == 1, "public export must have exactly one selected definition")
        row = next(row for row in chosen.values() if name in row["selection"]["symbols"])
        _require(row["selection"]["symbols"][name] == {"baseline": name, "protected": name}, "public export must remain identity")
        original = [s for s in row["coff"]["symbols"] if s["name"] == name and s["defined"] and s["external"]]
        _require(len(original) == 1, "public export is not one external definition")
        for arm in maps:
            _require(sum(s["name"] == name and s["defined"] and s["external"] for s in replacement[arm]["coff"]["symbols"]) == 1,
                     "generated public export not external")
    retained, archives = [], []
    generated_external_names = {s["name"] for generated in replacement.values()
                                for s in generated["coff"]["symbols"] if s["defined"] and s["external"]}
    for item in inventory:
        if item["owner"] is not None and item["kind"] not in ("coff_amd64", "archive"):
            issues.append({"kind": "unparsed_owned_input_requires_classification", "input": item["path"]})
        carriers = [(None, item["parsed"])] if item["kind"] == "coff_amd64" else [(m["member"]["index"], m["coff"]) for m in item["members"]]
        for index, coff in carriers:
            if (item["path"], index) in chosen:
                continue
            if coff is None:
                if item["owner"] is not None:
                    member = next((m for m in item["members"] if m["member"]["index"] == index), None)
                    if member:
                        issues.append({"kind": "unparsed_owned_member_requires_classification", "input": item["path"], "member_index": index,
                                       "name": member["member"]["name"], "payload_kind": member["payload_kind"]})
                continue
            for symbol in coff["symbols"]:
                if symbol["defined"] and symbol["external"] and symbol["name"] in generated_external_names:
                    issues.append({"kind": "replacement_external_definition_collides_with_retained", "input": item["path"],
                                   "member_index": index, "symbol": symbol["name"]})
                if symbol["defined"] and symbol["name"] in selected_names:
                    issues.append({"kind": "selected_symbol_retained_or_ambiguous", "input": item["path"], "member_index": index, "symbol": symbol["name"]})
                if not symbol["defined"]:
                    matching = [r for r in chosen.values() if symbol["name"] in r["selection"]["symbols"]]
                    if any(any(t != symbol["name"] for t in r["selection"]["symbols"][symbol["name"]].values()) for r in matching):
                        issues.append({"kind": "retained_reference_to_renamed_symbol", "input": item["path"], "symbol": symbol["name"]})
        removed = [index for path, index in chosen if path == item["path"] and index is not None]
        if removed:
            kept = [m for m in item["parsed"]["members"] if m["kind"] == "member" and m["index"] not in removed]
            archives.append({"input": item["descriptor"], "path": item["path"], "removed_member_indices": removed,
                             "retained_members": kept, "writer_required": True,
                             "verification_required": "verify_rewritten_archive"})
        if (item["path"], None) not in chosen:
            retained.append({"path": item["path"], "descriptor": item["descriptor"],
                             "archive_rewrite_required": bool(removed), "occurrences": item["occurrences"]})
    # Runtime is linked only with protected; baseline is a separate final arm.
    runtime_definitions = {s["name"] for s in replacement["runtime"]["coff"]["symbols"] if s["defined"] and s["external"]}
    protected_definitions = {s["name"] for s in replacement["protected"]["coff"]["symbols"] if s["defined"] and s["external"]}
    _require(not runtime_definitions & protected_definitions, "runtime/generated definition collision")
    edits = []
    anchor = min(row["input"]["occurrences"][0] for row in chosen.values())
    for row in recipe["expanded"]:
        if row["kind"] == "output":
            edits.append({"index": row["index"], "occurrence": row["occurrence"], "original_token": row["token"], "action": "rebase_output_required"})
        elif row["kind"] == "input" and (row["path"], None) in chosen:
            edits.append({"index": row["index"], "occurrence": row["occurrence"], "original_token": row["token"], "action": "omit_direct_selected_object"})
        elif row["kind"] == "input" and any(a["path"] == row["path"] for a in archives):
            edits.append({"index": row["index"], "occurrence": row["occurrence"], "original_token": row["token"], "action": "substitute_verified_archive"})
    selected = [{"input_path": path, "input_descriptor": row["input"]["descriptor"], "member_index": index,
                 "member": row["member"], "owner": row["input"]["owner"],
                 "symbols": {name: dict(targets) for name, targets in row["selection"]["symbols"].items()},
                 "lineage": descriptor(row["selection"]["lineage"]), "coff": row["coff"]} for (path, index), row in chosen.items()]
    result = {"schema_version": 1, "status": "needs_review" if issues else "structural_replacement_plan_not_executable",
              "recipe": recipe, "inventory": inventory, "selected": selected, "retained": retained,
              "archive_rewrites": archives, "replacement_objects": replacement, "public_exports": list(public_exports),
              "edits": edits, "aggregate_object_insertion_before_expanded_index": anchor,
              "arm_insertion_order": {"baseline": ["baseline"], "protected": ["protected", "runtime"]},
              "blockers": issues, "original_bytes_modified": False, "target_executed": False,
              "cargo_unit_authenticity_verified": False, "source_to_object_semantics_verified": False,
              "native_dependency_closure_verified": False, "link_order_behavior_verified": False,
              "required_followup": ["authenticated compiler-unit/native-event connection", "source/native carrier lineage proof",
                  "pinned archive writer and independent rewrite verification", "fresh path/response rendering and no-op replay",
                  "actual symbol/link gates", "original/baseline/protected behavior comparison"]}
    result["fingerprint"] = _json_hash(result)
    return result

