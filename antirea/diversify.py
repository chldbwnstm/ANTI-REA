"""Defense-only build-time VM format diversification for pinned Kagura IR.

This translates already-protected private build IR, not an attack artifact. It
does not recover a target algorithm or evaluate reverse-engineering resistance.
The generated ISA, fused handlers and fetch encoding are recoverable from the
delivered executable: this is diversification, not cryptographic secrecy.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import random
import re
import sys
from typing import Iterable

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from antirea.hardening import (
    HARDENING_LAYERS,
    compute_bytecode_integrity_tag,
    compute_header_integrity_tag,
    derive_multi_vm_seeds,
    emit_llvm_ir_honeypot,
    emit_runtime_hardening_helpers,
    hardening_parameters,
    hardening_capabilities,
    selected_layers,
)


PINNED_COMMIT = "ac2136ee0408677cf7cdee55307e9b16edd5f4d5"
RUNTIME_SHA256 = "0b4040ce1354d59173a20f655e18919e40b6217af602db1f8c935cfb4c23fcca"
OPCODES_SHA256 = "64b6555b693ae6797561f83b31e6595615bc16eaa71de44b1031d3c65c573aec"
FORMAT_VERSION = 2
HEADER_SIZE = 4
INTEGRATED_HELPERS = ("push", "pop", "peek")

OPERANDS = {
    "OP_PUSH_IMM8": (1,), "OP_PUSH_IMM16": (2,), "OP_PUSH_IMM32": (4,),
    "OP_PUSH_IMM64": (8,), "OP_PUSH_REG": (1,), "OP_POP_REG": (1,),
    "OP_PUSH_POOL": (2,), "OP_PUSH_FRAME": (2,), "OP_JMP": (4,),
    "OP_JZ": (4,), "OP_JNZ": (4,), "OP_CALL": (1, 1),
    "OP_SEXT": (1,), "OP_TRUNC": (1,), "OP_LOAD_ARG": (1,),
}
WIDTH_OPS = {
    "OP_ADD", "OP_SUB", "OP_MUL", "OP_UDIV", "OP_SDIV", "OP_UREM", "OP_SREM",
    "OP_AND", "OP_OR", "OP_XOR", "OP_NOT", "OP_SHL", "OP_LSHR", "OP_ASHR",
    "OP_ICMP_EQ", "OP_ICMP_NE", "OP_ICMP_ULT", "OP_ICMP_ULE", "OP_ICMP_UGT",
    "OP_ICMP_UGE", "OP_ICMP_SLT", "OP_ICMP_SLE", "OP_ICMP_SGT", "OP_ICMP_SGE",
}
OPERANDS.update({name: (1,) for name in WIDTH_OPS})
JUMPS = {"OP_JMP", "OP_JZ", "OP_JNZ"}
IMMEDIATES = {"OP_PUSH_IMM8", "OP_PUSH_IMM16", "OP_PUSH_IMM32", "OP_PUSH_IMM64"}
FUSED_EXPRESSIONS = {
    "OP_ADD": "a + b", "OP_SUB": "a - b", "OP_MUL": "a * b",
    "OP_AND": "a & b", "OP_OR": "a | b", "OP_XOR": "a ^ b",
    "OP_SHL": "a << vm_shamt(b, w)",
    "OP_LSHR": "vm_zext(a, w) >> vm_shamt(b, w)",
    "OP_ASHR": "(uint64_t)(vm_sext(a, w) >> vm_shamt(b, w))",
}


@dataclass(frozen=True)
class Instruction:
    offset: int
    name: str
    values: tuple[int, ...]
    widths: tuple[int, ...]
    originals: int = 1


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def opcode_table(text: str) -> dict[int, str]:
    entries = re.findall(r"^KAGURA_VM_OP\((OP_\w+),\s*(0x[0-9A-Fa-f]+)\)", text, re.M)
    table = {int(value, 16): name for name, value in entries}
    if not entries or len(table) != len(entries) or len(set(table.values())) != len(table):
        raise ValueError("Missing or duplicate stock opcodes")
    if 0xfe in table:
        raise ValueError("Format guard requires stock opcode 0xfe to be undefined")
    return table


def llvm_bytes(text: str) -> bytes:
    values = bytearray()
    i = 0
    while i < len(text):
        if text[i] == "\\":
            if text[i:i + 2] == "\\\\":
                values.append(0x5c)
                i += 2
                continue
            if not re.fullmatch(r"[0-9A-Fa-f]{2}", text[i + 1:i + 3]):
                raise ValueError("Unsupported LLVM byte-string escape")
            values.append(int(text[i + 1:i + 3], 16))
            i += 3
        else:
            if ord(text[i]) > 127:
                raise ValueError("Non-ASCII unescaped LLVM byte")
            values.append(ord(text[i]))
            i += 1
    return bytes(values)


def llvm_string(data: bytes) -> str:
    return "".join(f"\\{byte:02X}" for byte in data)


def decode_stock(data: bytes, key: int, table: dict[int, str]) -> list[Instruction]:
    """Read the pinned compiler's private build output, validating boundaries."""
    plain = bytes(value ^ ((key >> (8 * (i & 7))) & 255) for i, value in enumerate(data))
    result = []
    offset = 0
    while offset < len(plain):
        start = offset
        name = table.get(plain[offset])
        if name is None:
            raise ValueError(f"Unknown stock opcode at {offset}")
        offset += 1
        widths = OPERANDS.get(name, ())
        values = []
        for width in widths:
            if offset + width > len(plain):
                raise ValueError("Truncated stock operand")
            values.append(int.from_bytes(plain[offset:offset + width], "little"))
            offset += width
        if name in WIDTH_OPS | {"OP_SEXT", "OP_TRUNC"} and not 1 <= values[0] <= 64:
            raise ValueError("Invalid operand width")
        if name == "OP_CALL" and (values[0] > 8 or values[1] > 64):
            raise ValueError("Invalid native-call operands")
        result.append(Instruction(start, name, tuple(values), widths))
    boundaries = {item.offset for item in result}
    if any(item.values[0] not in boundaries for item in result if item.name in JUMPS):
        raise ValueError("Branch target is not an instruction boundary")
    return result


def fuse(instructions: list[Instruction]) -> list[Instruction]:
    """Fuse straight-line dataflow; never absorb a branch destination."""
    targets = {item.values[0] for item in instructions if item.name in JUMPS}
    result = []
    i = 0
    while i < len(instructions):
        tail = instructions[i:]
        candidate = None
        count = 1
        if (len(tail) >= 4 and tail[0].name == "OP_PUSH_REG"
                and tail[1].name in IMMEDIATES | {"OP_PUSH_REG"}
                and tail[2].name in FUSED_EXPRESSIONS and tail[3].name == "OP_POP_REG"):
            reg = tail[1].name == "OP_PUSH_REG"
            mode = "RR" if reg else "RI"
            values = (tail[3].values[0], tail[0].values[0], tail[2].values[0], tail[1].values[0])
            candidate = Instruction(tail[0].offset, f"F_{mode}_{tail[2].name[3:]}",
                                    values, (1, 1, 1, 1 if reg else 8), 4)
            count = 4
        elif (len(tail) >= 3 and tail[0].name == "OP_LOAD_ARG"
              and tail[1].name == "OP_ZEXT" and tail[2].name == "OP_POP_REG"):
            candidate = Instruction(tail[0].offset, "F_ARG", (tail[2].values[0], tail[0].values[0]), (1, 1), 3)
            count = 3
        elif len(tail) >= 2 and tail[1].name == "OP_POP_REG":
            if tail[0].name == "OP_SELECT":
                candidate = Instruction(tail[0].offset, "F_SELECT", (tail[1].values[0],), (1,), 2)
                count = 2
            elif tail[0].name in {"OP_PUSH_REG", "OP_LOAD_ARG"}:
                name = "F_MOV" if tail[0].name == "OP_PUSH_REG" else "F_ARG"
                candidate = Instruction(tail[0].offset, name, (tail[1].values[0], tail[0].values[0]), (1, 1), 2)
                count = 2
            elif tail[0].name in IMMEDIATES:
                candidate = Instruction(tail[0].offset, "F_CONST", (tail[1].values[0], tail[0].values[0]), (1, 8), 2)
                count = 2
        if candidate is not None and not any(item.offset in targets for item in tail[1:count]):
            result.append(candidate)
            i += count
        else:
            result.append(tail[0])
            i += 1
    return fuse_chains(result, targets)


def fuse_chains(instructions: list[Instruction], targets: set[int]) -> list[Instruction]:
    """Pair direct register expressions without losing intermediate writes/entries."""
    result = []
    index = 0
    while index < len(instructions):
        first = instructions[index]
        second = instructions[index + 1] if index + 1 < len(instructions) else None
        if (second is not None and second.offset not in targets
                and first.name.startswith(("F_RR_", "F_RI_"))
                and second.name.startswith(("F_RR_", "F_RI_"))):
            result.append(Instruction(first.offset,
                                      "F_CHAIN_" + first.name[2:] + "__" + second.name[2:],
                                      first.values + second.values, first.widths + second.widths,
                                      first.originals + second.originals))
            index += 2
        else:
            result.append(first)
            index += 1
    return result


def parameters(seed: int, names: set[str], *, enable_hardening: bool = True,
               enabled_layers: Iterable[str] | None = None) -> dict:
    chosen = selected_layers(HARDENING_LAYERS if enabled_layers is None else enabled_layers)
    if not enable_hardening and enabled_layers is not None and chosen:
        raise ValueError("enable_hardening=False conflicts with nonempty enabled_layers")
    rng = random.Random(seed)
    tokens = rng.sample(range(0x100, 0xffff), len(names))
    result = {"tokens": dict(zip(sorted(names), tokens)), "multiply": rng.getrandbits(32) | 1,
              "add": rng.getrandbits(32), "mix": rng.getrandbits(32) | 1,
              "rotate": rng.randrange(7), "header": [rng.randrange(256) for _ in range(3)],
              "operand_multiply": rng.getrandbits(32) | 1, "operand_add": rng.getrandbits(32)}
    if enable_hardening:
        result["hardening"] = hardening_parameters(seed, enabled_layers=chosen)
    return result


def operand_context(position: int, token: int, key: int, params: dict) -> int:
    return ((position * params["operand_multiply"]) ^ token ^ key ^ (key >> 32)
            ^ params["operand_add"]) & 0xffffffff


def operand_step(state: int, plain: int, params: dict) -> int:
    rotated = ((state << 5) | (state >> 27)) & 0xffffffff
    return (rotated * params["operand_multiply"] + plain + params["operand_add"]) & 0xffffffff


def encode_fetch(plain: bytes, key: int, params: dict, start=HEADER_SIZE) -> bytes:
    result = bytearray()
    for position, byte in enumerate(plain, start):
        mixed = (position * params["multiply"] + params["add"]) & 0xffffffff
        mixed ^= mixed >> 13
        mixed = (mixed * params["mix"]) & 0xffffffff
        mixed ^= mixed >> 17
        mask = (mixed ^ (key >> (8 * (position & 7)))) & 255
        rotation = ((position + params["rotate"]) % 7) + 1
        value = (byte + mask) & 255
        result.append((((value << rotation) | (value >> (8 - rotation))) & 255) ^ ((mixed >> 8) & 255))
    return bytes(result)


def emit(instructions: list[Instruction], key: int, params: dict) -> tuple[bytes, dict[int, int]]:
    relocations = {}
    length = HEADER_SIZE
    for item in instructions:
        relocations[item.offset] = length
        length += 2 + sum(item.widths)
    data = bytearray()
    for item in instructions:
        token = params["tokens"][item.name]
        state = operand_context(relocations[item.offset], token, key, params)
        data.extend(token.to_bytes(2, "big"))
        values = (relocations[item.values[0]],) if item.name in JUMPS else item.values
        for value, width in zip(values, item.widths):
            for byte in value.to_bytes(width, "big"):
                mask = (state ^ (state >> 11) ^ (state >> 23)) & 255
                data.append(byte ^ mask)
                state = operand_step(state, byte, params)
    header = bytes([(key & 255) ^ 0xfe] + params["header"])
    return header + encode_fetch(bytes(data), key, params), relocations


def fused_body(name: str) -> str:
    if name.startswith("F_CHAIN_"):
        parts = name.removeprefix("F_CHAIN_").split("__")
        if len(parts) != 2 or any(not re.fullmatch(r"R[RI]_[A-Z]+", part) for part in parts):
            raise ValueError("Invalid chained register handler")
        # Keep the scopes and writes sequential: a second read may alias the first destination.
        return " ".join("{ " + fused_body("F_" + part) + " }" for part in parts)
    if name == "F_MOV":
        body = "uint8_t d=bc_u8(&f), s=bc_u8(&f); f.regs[d]=f.regs[s];"
    elif name == "F_ARG":
        body = "uint8_t d=bc_u8(&f), s=bc_u8(&f); f.regs[d]=(s<f.nargs)?f.args[s]:0;"
    elif name == "F_CONST":
        body = "uint8_t d=bc_u8(&f); f.regs[d]=bc_u64(&f);"
    elif name == "F_SELECT":
        body = ("uint8_t d=bc_u8(&f); "
                "uint64_t fv=vm_pop(&f), tv=vm_pop(&f), c=vm_pop(&f); f.regs[d]=c?tv:fv;")
    else:
        mode, operation = name[2:].split("_", 1)
        expression = FUSED_EXPRESSIONS["OP_" + operation]
        rhs = "f.regs[bc_u8(&f)]" if mode == "RR" else "bc_u64(&f)"
        body = (f"uint8_t d=bc_u8(&f), s=bc_u8(&f); unsigned w=vm_width(&f); "
                f"uint64_t a=f.regs[s], b={rhs}; f.regs[d]=vm_zext({expression},w);")
    return body


def fused_handler(name: str) -> str:
    return f"        case {name}: {{ {fused_body(name)} break; }}\n"


def specialize_runtime(source: str, params: dict, symbol: str) -> str:
    """Specialize pinned source, retaining semantics of unfused handlers."""
    source = source.replace('#include "../internal.h"', '/* Standalone generated runtime; original internal declarations are unnecessary. */')
    enum = "enum vm_opcode {\n" + "".join(f"    {name} = {token},\n" for name, token in params["tokens"].items()) + "};"
    source, count = re.subn(r"enum vm_opcode \{.*?\};", lambda _: enum, source, count=1, flags=re.S)
    if count != 1:
        raise ValueError("Pinned runtime opcode declaration not found")
    source, count = re.subn(r"#define KAGURA_VM_LIMIT\([^\n]+\n.*?enum vm_limit \{.*?\};",
                            "enum vm_limit { VM_NUM_REGS=256, VM_STACK_SIZE=128, VM_FRAME_SIZE=1024, VM_MAX_CALL_ARGS=8 };",
                            source, count=1, flags=re.S)
    if count != 1:
        raise ValueError("Pinned runtime limits not found")
    source, count = re.subn(r"(?m)^(\s*)uint32_t pc;", r"\1uint32_t operand_state;\n\1uint32_t pc;", source, count=1)
    if count != 1:
        raise ValueError("Pinned runtime frame pc field not found")
    hardening_prelude = ""
    if isinstance(params.get("hardening"), dict):
        hardening_prelude = emit_runtime_hardening_helpers(params["hardening"]) + "\n"
    fetch = hardening_prelude + f"""/* Check a complete scalar read before touching its first byte. Subtraction is
 * guarded against underflow; no unchecked reader is an external entry point. */
static __attribute__((always_inline)) inline void bc_require(VMFrame *f, uint32_t width) {{
    if (__builtin_expect(f->pc > f->bc_size || width > f->bc_size-f->pc, 0)) abort();
}}

static __attribute__((always_inline)) inline uint8_t bc_raw8_unchecked(VMFrame *f) {{
    uint32_t p=f->pc;
    f->pc=p+1;
    uint32_t t=p*{params['multiply']}u+{params['add']}u;
    t ^= t >> 13; t *= {params['mix']}u; t ^= t >> 17;
    uint8_t m=(uint8_t)(t ^ (f->key >> (8u*(p&7u))));
    unsigned r=((p+{params['rotate']}u)%7u)+1u;
    uint8_t v=(uint8_t)(f->bc[p] ^ (uint8_t)(t >> 8));
    v=(uint8_t)((v >> r) | ((unsigned)v << (8u-r)));
    return (uint8_t)(v-m);
}}

static __attribute__((always_inline)) inline uint16_t bc_opcode(VMFrame *f) {{
    bc_require(f, 2u);
    uint32_t start=f->pc;
    uint16_t hi=bc_raw8_unchecked(f);
    uint16_t op=(uint16_t)((hi << 8) | bc_raw8_unchecked(f));
    f->operand_state=(start*{params['operand_multiply']}u) ^ op ^ (uint32_t)f->key
                     ^ (uint32_t)(f->key >> 32) ^ {params['operand_add']}u;
    return op;
}}

static __attribute__((always_inline)) inline uint8_t bc_u8_unchecked(VMFrame *f) {{
    uint32_t s=f->operand_state;
    uint8_t v=(uint8_t)(bc_raw8_unchecked(f) ^ (uint8_t)(s ^ (s >> 11) ^ (s >> 23)));
    uint32_t rotated=(s << 5) | (s >> 27);
    f->operand_state=rotated*{params['operand_multiply']}u+v+{params['operand_add']}u;
    return v;
}}

static __attribute__((always_inline)) inline uint8_t bc_u8(VMFrame *f) {{
    bc_require(f, 1u); return bc_u8_unchecked(f);
}}
static __attribute__((always_inline)) inline uint16_t bc_u16_unchecked(VMFrame *f) {{
    uint16_t hi=bc_u8_unchecked(f); return (uint16_t)((hi << 8) | bc_u8_unchecked(f));
}}
static __attribute__((always_inline)) inline uint32_t bc_u32_unchecked(VMFrame *f) {{
    uint32_t hi=bc_u16_unchecked(f); return (hi << 16) | bc_u16_unchecked(f);
}}
static __attribute__((always_inline)) inline uint16_t bc_u16(VMFrame *f) {{
    bc_require(f, 2u); return bc_u16_unchecked(f);
}}
static __attribute__((always_inline)) inline uint32_t bc_u32(VMFrame *f) {{
    bc_require(f, 4u); return bc_u32_unchecked(f);
}}
static __attribute__((always_inline)) inline uint64_t bc_u64(VMFrame *f) {{
    bc_require(f, 8u);
    uint64_t hi=bc_u32_unchecked(f); return (hi << 32) | bc_u32_unchecked(f);
}}
"""
    start = source.index("static inline uint8_t bc_u8")
    end = source.index("/* ── Width helpers", start)
    source = source[:start] + fetch + "\n" + source[end:]
    source = source.replace("uint64_t kagura_vm_execute(", f"uint64_t {symbol}(")
    integrity_call = ("    if (!antirea_check_bytecode_integrity(bytecode, bc_size, key)) abort();\n"
                      if "antirea_check_bytecode_integrity" in hardening_prelude else "")
    count = source.count("    VMFrame f;")
    source = source.replace("    VMFrame f;", (
        "    /* A format-version guard, not an authenticity or secrecy claim. */\n"
        f"    if (bc_size<4 || bytecode[0]!=(uint8_t)(key^0xfeu) || bytecode[1]!={params['header'][0]}u"
        f" || bytecode[2]!={params['header'][1]}u || bytecode[3]!={params['header'][2]}u) abort();\n"
        + integrity_call + "    VMFrame f;"))
    if count != 1:
        raise ValueError("Pinned runtime frame initialization not found exactly once")
    source = source.replace("f.pc      = 0;", "f.pc      = 4;")
    if "antirea_env_and_tamper_guard" in hardening_prelude:
        source, count = re.subn(
            re.escape("f.key     = key;"),
            "f.key     = key ^ (uint64_t)antirea_env_and_tamper_guard(bytecode, bc_size, (uint32_t)key);",
            source,
        )
        if count != 1:
            raise ValueError("Pinned runtime key initialization not found exactly once")
    source = source.replace("uint8_t op = bc_u8(&f);", "uint16_t op = bc_opcode(&f);")
    loop = source.index("        switch (op) {")
    end = source.index("        default: abort();", loop)
    section = source[loop:end]
    cases = list(re.finditer(r"(?m)^        case (OP_\w+):", section))
    found = {match.group(1) for match in cases}
    wanted = {name for name in params["tokens"] if name.startswith("OP_")}
    if not wanted.issubset(found):
        raise ValueError("Missing runtime handlers")
    kept = "        switch (op) {\n"
    for index, match in enumerate(cases):
        if match.group(1) in wanted:
            stop = cases[index + 1].start() if index + 1 < len(cases) else len(section)
            kept += section[match.start():stop]
    kept += "".join(fused_handler(name) for name in sorted(params["tokens"]) if name.startswith("F_"))
    source = source[:loop] + kept + source[end:]
    # Put semantic primitives inside the dispatcher before its protection passes.
    # Native-call thunks remain separate; this changes no VM value semantics.
    source = re.sub(
        r"(?m)^static inline (?=(?:void|unsigned|u?int64_t) vm_(?:" + "|".join(INTEGRATED_HELPERS) + r")\()",
        "static __attribute__((always_inline)) inline ", source)
    return ("/* Generated private build artifact: diversified VM v2.\n"
            " * Based on pinned Kagura runtime; opcode/fetch contract below supersedes\n"
            " * the upstream descriptive comments. Not cryptographic secrecy. */\n" + source)


def _transform_shared_ir(ir: str, table: dict[int, str], seed: int, *, enable_hardening: bool = True,
                         enabled_layers: Iterable[str] | None = None,
                         require_fusion: bool = True) -> tuple[str, dict]:
    blobs = list(re.finditer(r'^@(kagura_vm_bc_(\d+)) = private constant \[(\d+) x i8\] c"([^"\n]*)"', ir, re.M))
    if not blobs:
        raise ValueError("No supported Kagura bytecode globals")
    plans = []
    for match in blobs:
        name, suffix, size, text = match.groups()
        data = llvm_bytes(text)
        if len(data) != int(size):
            raise ValueError("Bytecode size does not match LLVM declaration")
        key_match = re.search(r"^@kagura_vm_key_" + suffix + r" = private constant i64 (-?\d+)$", ir, re.M)
        if key_match is None:
            raise ValueError("Unsupported key expression")
        key = int(key_match.group(1)) & 0xffffffffffffffff
        instructions = decode_stock(data, key, table)
        fused = fuse(instructions)
        plans.append((match, data, key, instructions, fused))
    names = {item.name for _, _, _, _, items in plans for item in items}
    params = parameters(seed, names, enable_hardening=enable_hardening, enabled_layers=enabled_layers)
    chosen = params.get("hardening", {}).get("enabled_layers", [])
    symbol = f"antirea_dispatch_{seed & 0xffffffffffffffff:016x}"
    records = []
    integrity_bindings = {}
    for match, data, key, instructions, fused in reversed(plans):
        encoded, relocations = emit(fused, key, params)
        name = match.group(1)
        replacement = f'@{name} = private constant [{len(encoded)} x i8] c"{llvm_string(encoded)}"'
        ir = ir[:match.start()] + replacement + ir[match.end():]
        call_pattern = r"(@kagura_vm_execute\(ptr @" + name + r", i32 )" + str(len(data)) + r"\b"
        ir, calls = re.subn(call_pattern, lambda m: m.group(1) + str(len(encoded)), ir)
        if calls != 1:
            raise ValueError("Each bytecode blob must have exactly one supported wrapper call")
        counts = Counter(item.name for item in fused if item.originals > 1)
        blob_record = {"global": name, "original_bytes": len(data), "encoded_bytes": len(encoded),
                       "original_instructions": len(instructions), "emitted_instructions": len(fused),
                       "fused_groups": sum(counts.values()), "fusion_counts": dict(sorted(counts.items())),
                       "absorbed_dispatches": sum(item.originals - 1 for item in fused),
                       "original_sha256": sha256(data), "encoded_sha256": sha256(encoded),
                       "relocated_branch_targets": sum(item.name in JUMPS for item in fused),
                       "stock_first_opcode_after_original_xor": encoded[0] ^ (key & 255)}
        if "anti_tamper" in chosen:
            blob_record["header_integrity_tag"] = compute_header_integrity_tag(
                encoded, params["hardening"]["tamper_seed"], params["hardening"]["tamper_prime"]
            )
            blob_record["header_integrity_tag_role"] = "diagnostic only; runtime binds full encoded bytecode and length"
            blob_record["bytecode_integrity_tag"] = compute_bytecode_integrity_tag(
                encoded, params["hardening"]["tamper_seed"], params["hardening"]["tamper_prime"])
            identity = (key, len(encoded))
            if identity in integrity_bindings and integrity_bindings[identity]["encoded_sha256"] != sha256(encoded):
                raise ValueError("Ambiguous bytecode integrity binding: same key/length for different blobs")
            integrity_bindings[identity] = {"key": key, "bytes": len(encoded),
                                            "tag": blob_record["bytecode_integrity_tag"], "encoded_sha256": sha256(encoded)}
        records.append(blob_record)
    if require_fusion and not any(record["fused_groups"] for record in records):
        raise ValueError("No meaningful fusion applied; refusing diversification claim")
    ir = ir.replace("@kagura_vm_execute", "@" + symbol)
    if "anti_tamper" in chosen:
        params["hardening"]["bytecode_integrity"] = [integrity_bindings[key] for key in sorted(integrity_bindings)]
    if "anti_llm_honeypot" in chosen:
        ir = ir.rstrip() + "\n" + emit_llvm_ir_honeypot(seed)
    manifest = {"schema_version": 1, "format_version": FORMAT_VERSION, "seed": seed,
                "dispatcher_symbol": symbol, "parameters": params, "blobs": list(reversed(records)),
                "opcode_bits": 16, "operand_byte_order": "big", "header_bytes": HEADER_SIZE,
                "used_handlers": sorted(names), "stock_format_directly_compatible": False,
                "instruction_fusion": "direct register operations, not replay of original stack opcodes",
                "fetch_encoding": "position/key-dependent rotate/add/xor; reversible, not encryption security",
                "operand_encoding": "instruction-position/opcode/key context with plaintext feedback; resets at every instruction",
                "fetch_inlined_in_dispatcher": True,
                "fetch_bounds_check": "overflow-safe complete scalar span before byte decoding; same per-byte codec and feedback",
                "semantic_helpers_inlined_in_dispatcher": list(INTEGRATED_HELPERS),
                "hardening_layers": [],
                "hardening_layers_semantics": "Legacy applied-layer list; generation alone verifies no applied layer.",
                "requested_hardening_layers": list(chosen),
                "external_attack_evaluation": "not_evaluated",
                "limitations": ["Generated ISA and decoder remain present in the delivered executable.",
                                "No cryptographic secrecy, anti-analysis guarantee or resistance result is claimed.",
                                "Only the pinned supported Kagura IR/bytecode format is accepted."]}
    manifest["hardening_capabilities"] = hardening_capabilities(params.get("hardening"), core_ir=ir,
                                                                dispatcher_symbol=symbol, blob_count=len(records))
    chains = sum(count for record in records for name, count in record['fusion_counts'].items()
                 if name.startswith('F_CHAIN_'))
    if chains:
        manifest['chained_register_fusion'] = {
            'groups': chains, 'operations_per_group': 2,
            'semantics': 'sequential direct expressions with both intermediate register writes retained'}
    return ir, manifest


_FUNCTION = re.compile(r'(?ms)^define\s+[^\r\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\([^\r\n]*\)[^\r\n]*\{\r?\n.*?^\}')
_BLOB = re.compile(r'^@(kagura_vm_bc_(\d+)) = private constant \[(\d+) x i8\] c"([^"\r\n]*)"', re.M)
_IDENTIFIER = re.compile(r'[A-Za-z_][A-Za-z0-9_.$]*\Z')


def codec_fingerprint(params: dict) -> str:
    """Fingerprint the actual opcode/fetch/operand contract, not helper salts."""
    codec = {name: params[name] for name in
             ("tokens", "multiply", "add", "mix", "rotate", "header", "operand_multiply", "operand_add")}
    return sha256(json.dumps(codec, sort_keys=True, separators=(",", ":")).encode())


def _namespace_runtime(source: str, dispatcher: str, prefix: str) -> str:
    # Pinned runtime identifiers only. External CRT/intrinsics remain shared;
    # each VM's frame types, helpers, enum names and optional checks are private.
    pattern = r'\b(?:vm_\w+|bc_\w+|VM\w*|OP_\w+|F_\w+|antirea_\w+)\b'
    return re.sub(pattern, lambda match: match.group() if match.group() == dispatcher
                  else prefix + match.group(), source)


def runtime_for_manifest(source: str, manifest: dict) -> str:
    """Emit one TU, retaining a separate decoder and dispatcher for every engine."""
    if manifest.get("engine_mode") != "per_function_indirect":
        return specialize_runtime(source, manifest["parameters"], manifest["dispatcher_symbol"])
    return "\n\n".join(_namespace_runtime(
        specialize_runtime(source, engine["parameters"], engine["dispatcher_symbol"]),
        engine["dispatcher_symbol"], engine["namespace_prefix"])
        for engine in manifest["engines"])


def _transform_multi_ir(ir: str, table: dict[int, str], seed: int, chosen: tuple[str, ...]) -> tuple[str, dict]:
    blobs = list(_BLOB.finditer(ir))
    functions = list(_FUNCTION.finditer(ir))
    if len({match.group(1) for match in functions}) != len(functions):
        raise ValueError("Duplicate function definitions in VM input")
    declaration = re.findall(r'(?m)^declare i64 @kagura_vm_execute\([^\r\n]+$', ir)
    if len(declaration) != 1:
        raise ValueError("Multi-VM requires exactly one supported stock dispatcher declaration")
    replacements, slots, engines, records, shared = [], [], [], [], None
    used_functions = set()
    for blob, parameter_seed in zip(blobs, derive_multi_vm_seeds(seed, len(blobs))):
        name, suffix = blob.group(1), blob.group(2)
        owners = [function for function in functions if re.search(
            r'@kagura_vm_execute\(ptr @' + re.escape(name) + r',', function.group())]
        if len(owners) != 1 or owners[0].group(1) in used_functions:
            raise ValueError("Multi-VM requires one distinct wrapper function per blob")
        owner = owners[0]
        used_functions.add(owner.group(1))
        key = re.search(r'^@kagura_vm_key_' + suffix + r' = private constant i64 -?\d+$', ir, re.M)
        if key is None:
            raise ValueError("Unsupported key expression")
        fragment = '\n'.join((blob.group(), key.group(), owner.group(), declaration[0])) + '\n'
        converted, single = _transform_shared_ir(fragment, table, parameter_seed,
                                                  enabled_layers=chosen, require_fusion=False)
        symbol = single["dispatcher_symbol"]
        tag = f'{parameter_seed:016x}'
        slot, local, prefix = f'antirea_vm_slot_{tag}', f'antirea_vm_target_{tag}', f'antirea_e_{tag}_'
        if re.search(r'[@%](?:' + '|'.join(map(re.escape, (slot, local, symbol))) + r')\b', ir):
            raise ValueError("Generated VM identifier collides with source")
        wrapper = _FUNCTION.search(converted).group()
        call = re.search(r'(?m)^(\s*)(%[-\w.$]+ = (?:tail )?call i64 )@' + symbol + r'\(', wrapper)
        if call is None:
            raise ValueError("Unsupported wrapper call for indirect dispatch")
        replacement = (call.group(1) + f'%{local} = load volatile ptr, ptr @{slot}, align 8\n'
                       + call.group(1) + call.group(2) + f'%{local}(')
        wrapper = wrapper[:call.start()] + replacement + wrapper[call.end():]
        replacements.extend([(blob.start(), blob.end(), _BLOB.search(converted).group()),
                             (owner.start(), owner.end(), wrapper)])
        slots.append(f'@{slot} = internal global ptr @{symbol}, align 8')
        engines.append({"function": owner.group(1), "blob_global": name, "dispatcher_symbol": symbol,
                        "dispatch_slot": slot, "integrity_checker_symbol": prefix + "antirea_check_bytecode_integrity",
                        "namespace_prefix": prefix, "parameter_seed": parameter_seed,
                        "parameters": single["parameters"], "used_handlers": single["used_handlers"],
                        "codec_sha256": codec_fingerprint(single["parameters"])})
        records.append(single["blobs"][0])
        if shared is None:
            shared = single
    if not any(record["fused_groups"] for record in records):
        raise ValueError("No meaningful fusion applied; refusing diversification claim")
    for start, stop, replacement in sorted(replacements, reverse=True):
        ir = ir[:start] + replacement + ir[stop:]
    declarations = '\n'.join(declaration[0].replace('@kagura_vm_execute', '@' + e["dispatcher_symbol"]) for e in engines)
    ir = ir.replace(declaration[0], '\n'.join(slots) + '\n' + declarations)
    if '@kagura_vm_execute' in ir:
        raise ValueError("Unclaimed stock dispatcher reference in multi-VM input")
    if "anti_llm_honeypot" in chosen:
        ir = ir.rstrip() + '\n' + emit_llvm_ir_honeypot(seed)
    manifest = dict(shared)
    manifest.update(seed=seed, blobs=records, engine_mode="per_function_indirect", engines=engines,
                    dispatcher_symbols=[e["dispatcher_symbol"] for e in engines],
                    used_handlers=sorted({name for e in engines for name in e["used_handlers"]}),
                    legacy_alias_semantics="dispatcher_symbol and parameters refer only to the first engine; use engines for all functions")
    manifest.pop("chained_register_fusion", None)
    chains = sum(n for record in records for name, n in record["fusion_counts"].items() if name.startswith('F_CHAIN_'))
    if chains:
        manifest["chained_register_fusion"] = {"groups": chains, "operations_per_group": 2,
            "semantics": "sequential direct expressions with both intermediate register writes retained"}
    manifest["limitations"] = list(manifest["limitations"]) + [
        "Per-function engines are deterministic diversification, not cryptographic independence.",
        "Volatile function-pointer slots and all decoder parameters remain recoverable in the artifact."]
    inspect_vm_bindings(ir, manifest)
    manifest["hardening_capabilities"] = hardening_capabilities(
        manifest["parameters"].get("hardening"), core_ir=ir, dispatcher_symbol=manifest["dispatcher_symbol"],
        blob_count=len(records), vm_engines=engines)
    return ir, manifest


def transform_ir(ir: str, table: dict[int, str], seed: int, *, enable_hardening: bool = True,
                 enabled_layers: Iterable[str] | None = None) -> tuple[str, dict]:
    requested = selected_layers(HARDENING_LAYERS if enabled_layers is None else enabled_layers)
    if not enable_hardening and enabled_layers is not None and requested:
        raise ValueError("enable_hardening=False conflicts with nonempty enabled_layers")
    chosen = requested if enable_hardening else ()
    if "multi_vm_indirect_dispatch" in chosen and len(_BLOB.findall(ir)) > 1:
        return _transform_multi_ir(ir, table, seed, chosen)
    # Preserve the old manifest and direct-call shape for single-function and
    # explicitly disabled multi-VM builds.
    return _transform_shared_ir(ir, table, seed, enable_hardening=enable_hardening, enabled_layers=chosen)


def inspect_vm_bindings(core_ir: str, manifest: dict) -> dict[str, dict]:
    """Fail closed on missing/mismatched per-function VM bindings in supplied IR.

    This checks generated or retained IR, not executable linkage or resistance.
    Callers must also compare the result's function set to their selection plan.
    """
    if manifest.get("engine_mode") != "per_function_indirect":
        raise ValueError("VM binding inspection requires a per-function indirect manifest")
    engines, blobs = manifest.get("engines"), manifest.get("blobs")
    if not isinstance(engines, list) or len(engines) < 2 or not isinstance(blobs, list) or len(blobs) != len(engines):
        raise ValueError("Invalid multi-VM engine/blob manifest")
    if any(not isinstance(engine, dict) for engine in engines) or any(not isinstance(record, dict) for record in blobs):
        raise ValueError("Invalid multi-VM manifest entries")
    for field in ("function", "blob_global", "dispatcher_symbol", "dispatch_slot"):
        values = [engine.get(field) for engine in engines]
        if any(not isinstance(value, str) or not _IDENTIFIER.fullmatch(value) for value in values) or len(set(values)) != len(values):
            raise ValueError(f"Invalid or duplicate multi-VM {field}")
    try:
        fingerprints = [codec_fingerprint(e["parameters"]) for e in engines]
    except (KeyError, TypeError) as exc:
        raise ValueError("Invalid VM codec parameters") from exc
    if len(set(fingerprints)) != len(engines) or fingerprints != [e.get("codec_sha256") for e in engines]:
        raise ValueError("VM codec parameters are not independently distinct or correctly bound")
    if manifest.get("dispatcher_symbols") != [e["dispatcher_symbol"] for e in engines]:
        raise ValueError("Dispatcher list does not match engines")
    try:
        record_map = {record["global"]: record for record in blobs}
    except (KeyError, TypeError) as exc:
        raise ValueError("Invalid VM blob records") from exc
    blob_matches = list(_BLOB.finditer(core_ir))
    actual_blobs = {match.group(1): match for match in blob_matches}
    if len(record_map) != len(blobs) or len(actual_blobs) != len(blob_matches):
        raise ValueError("Duplicate VM blob records or definitions")
    if set(record_map) != {e["blob_global"] for e in engines} or set(actual_blobs) != set(record_map):
        raise ValueError("VM blob sets do not match")
    function_matches = list(_FUNCTION.finditer(core_ir))
    functions = {match.group(1): match.group() for match in function_matches}
    if len(functions) != len(function_matches):
        raise ValueError("Duplicate function definitions in VM artifact")
    result = {}
    for engine in engines:
        name, symbol, slot, blob = (engine[k] for k in ("function", "dispatcher_symbol", "dispatch_slot", "blob_global"))
        record, match = record_map[blob], actual_blobs[blob]
        data = llvm_bytes(match.group(4))
        if len(data) != int(match.group(3)) or len(data) != record["encoded_bytes"] or sha256(data) != record["encoded_sha256"]:
            raise ValueError("VM blob content/length/hash mismatch")
        slot_pattern = r'(?m)^@' + re.escape(slot) + r' = internal (?:local_unnamed_addr )?global ptr @' + re.escape(symbol) + r'(?:,|\s*$)'
        if len(re.findall(slot_pattern, core_ir)) != 1:
            raise ValueError("Missing or changed VM dispatcher slot initializer")
        body = functions.get(name, "")
        loads = list(re.finditer(r'(%[-\w.$]+) = load volatile ptr, ptr @' + re.escape(slot) + r'\b', body))
        if len(loads) != 1:
            raise ValueError("Missing unique volatile VM dispatcher load")
        call_pattern = (r'\bcall i64 ' + re.escape(loads[0].group(1)) + r'\(ptr (?:nonnull )?@'
                        + re.escape(blob) + r', i32 ' + str(len(data)) + r'\b')
        calls = list(re.finditer(call_pattern, body))
        if len(calls) != 1 or calls[0].start() < loads[0].end():
            raise ValueError("Missing unique indirect call with bound VM bytecode")
        if any(re.search(r'@' + re.escape(other["dispatch_slot"]) + r'\b', body)
               for other in engines if other is not engine):
            raise ValueError("Wrapper refers to another VM dispatcher slot")
        result[name] = {"virtualized": True, "dispatcher": symbol, "dispatch_slot": slot,
                        "dispatch_mode": "volatile_function_pointer", "bytecode_global": blob,
                        "bytecode_size": len(data), "encoded_sha256": sha256(data),
                        "codec_sha256": engine["codec_sha256"]}
    return result


def generate(input_ir: Path, runtime_source: Path, opcode_source: Path, output_dir: Path, seed: int, *,
             enabled_layers: Iterable[str] | None = None, enable_hardening: bool = True) -> dict:
    runtime_bytes, opcode_bytes = runtime_source.read_bytes(), opcode_source.read_bytes()
    if sha256(runtime_bytes) != RUNTIME_SHA256 or sha256(opcode_bytes) != OPCODES_SHA256:
        raise ValueError("Upstream runtime/opcode source does not match pinned build input")
    ir_bytes = input_ir.read_bytes()
    ir, manifest = transform_ir(ir_bytes.decode("utf-8-sig"), opcode_table(opcode_bytes.decode("utf-8")), seed,
                                enabled_layers=enabled_layers, enable_hardening=enable_hardening)
    runtime = runtime_for_manifest(runtime_bytes.decode("utf-8"), manifest)
    manifest["hardening_capabilities"] = hardening_capabilities(
        manifest["parameters"].get("hardening"), runtime_source=runtime, core_ir=ir,
        dispatcher_symbol=manifest["dispatcher_symbol"], blob_count=len(manifest["blobs"]),
        vm_engines=manifest.get("engines"))
    manifest["source_emitted_hardening_layers"] = [name for name, state in manifest["hardening_capabilities"]["layers"].items()
                                                   if state["source_emitted"]]
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = [output_dir / name for name in ("core.diversified.ll", "runtime.generated.c", "diversification.json")]
    if any(path.exists() for path in paths):
        raise ValueError("Refusing to overwrite generated artifacts")
    manifest.update(kagura_commit=PINNED_COMMIT, input_ir_sha256=sha256(ir_bytes),
                    upstream_runtime_sha256=sha256(runtime_bytes), upstream_opcodes_sha256=sha256(opcode_bytes),
                    output_ir_sha256=sha256(ir.encode()), generated_runtime_sha256=sha256(runtime.encode()))
    paths[0].write_text(ir, encoding="utf-8", newline="\n")
    paths[1].write_text(runtime, encoding="utf-8", newline="\n")
    paths[2].write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-ir", type=Path, required=True)
    parser.add_argument("--runtime-source", type=Path, required=True)
    parser.add_argument("--opcode-source", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--hardening-layer", action="append", choices=HARDENING_LAYERS,
                        help="Select specific optional components (repeatable); default requests all legacy names, including explicit gaps.")
    parser.add_argument("--no-hardening", action="store_true")
    args = parser.parse_args()
    result = generate(args.input_ir, args.runtime_source, args.opcode_source, args.output_dir, args.seed,
                      enabled_layers=args.hardening_layer, enable_hardening=not args.no_hardening)
    print(json.dumps({key: result[key] for key in ("dispatcher_symbol", "blobs", "external_attack_evaluation")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
