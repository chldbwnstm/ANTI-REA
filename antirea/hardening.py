"""Optional code-generation components and conservative artifact evidence.

HARDENING_LAYERS is a request vocabulary for C/LLVM-IR hardening helpers.
Source emission, retained IR, functional checks and external resistance are
separate facts. Internal symbol-table dispatch does not walk OS PEB/PE headers,
and ephemeral buffer scrubbing does not claim OS memory-dump blocking.
Decoys are inert program code/data, never instructions to an analysis agent.
"""

from __future__ import annotations

import hashlib
import copy
import re
from typing import Iterable


U32_MASK = 0xFFFF_FFFF
U64_MASK = 0xFFFF_FFFF_FFFF_FFFF

HARDENING_LAYERS = (
    "anti_debug",
    "anti_tamper",
    "mba_opaque",
    "string_constant_encryption",
    "iat_api_hiding",
    "multi_vm_indirect_dispatch",
    "anti_dump",
    "anti_llm_honeypot",
)

_TAMPER_PRIMES = (0x01000193, 0x85EBCA6B, 0xC2B2AE35, 0x27D4EB2F)


def _csprng_block(seed: int | str, domain: str, counter: int = 0) -> bytes:
    payload = f"antirea-hardening-csprng-v2:{domain}:{seed}:{counter}".encode("utf-8")
    return hashlib.sha256(payload).digest()


def _csprng_u32(seed: int | str, domain: str, counter: int = 0, *, non_zero_odd: bool = False) -> int:
    val = int.from_bytes(_csprng_block(seed, domain, counter)[:4], "little") & U32_MASK
    if non_zero_odd:
        return (val | 1) & U32_MASK
    return val or 1


def _seed_int(seed: int | str) -> int:
    digest = hashlib.sha256(f"antirea-hardening:{seed}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "little")


def selected_layers(enabled_layers: Iterable[str]) -> tuple[str, ...]:
    if isinstance(enabled_layers, (str, bytes)):
        raise ValueError("enabled_layers must be an iterable of layer names, not a string")
    values = tuple(enabled_layers)
    if any(not isinstance(item, str) for item in values):
        raise ValueError("hardening layer names must be strings")
    layers = tuple(dict.fromkeys(values))
    unknown = set(layers) - set(HARDENING_LAYERS)
    if unknown:
        raise ValueError(f"Unknown hardening layers: {sorted(unknown)}")
    return layers


def hardening_parameters(
    seed: int | str,
    *,
    enabled_layers: Iterable[str] = HARDENING_LAYERS,
) -> dict:
    """Derive deterministic parameters via one-way SHA-256 counter-mode streams."""
    layers = selected_layers(enabled_layers)
    poison_salt = _csprng_u32(seed, "poison_salt", 0, non_zero_odd=True)
    tamper_seed = _csprng_u32(seed, "tamper_seed", 0, non_zero_odd=True)
    prime_idx = _csprng_block(seed, "tamper_prime", 0)[0] & 3
    tamper_prime = _TAMPER_PRIMES[prime_idx]
    mba_variant = _csprng_block(seed, "mba_variant", 0)[0] & 3
    string_key = _csprng_u32(seed, "string_key", 0, non_zero_odd=True)
    api_hash_salt = _csprng_u32(seed, "api_hash_salt", 0, non_zero_odd=True)
    dispatch_guard_salt = _csprng_u32(seed, "dispatch_guard_salt", 0, non_zero_odd=True)
    honeypot_seed = _csprng_u32(seed, "honeypot_seed", 0, non_zero_odd=True)
    honeypot_constants = [_csprng_u32(seed, "honeypot_const", idx) for idx in range(8)]
    return {
        "schema_version": 1,
        "enabled_layers": list(layers),
        "poison_salt": poison_salt,
        "tamper_seed": tamper_seed,
        "tamper_prime": tamper_prime,
        "mba_variant": mba_variant,
        "string_key": string_key,
        "api_hash_salt": api_hash_salt,
        "dispatch_guard_salt": dispatch_guard_salt,
        "honeypot_seed": honeypot_seed,
        "honeypot_constants": honeypot_constants,
    }


# ---------------------------------------------------------------------------
# Layer 2: Anti-Tampering & Self-Checksumming (Hash-to-Key Binding)
# ---------------------------------------------------------------------------

def compute_header_integrity_tag(
    bytecode: bytes,
    tamper_seed: int,
    tamper_prime: int = 0x01000193,
) -> int:
    """Compute a 32-bit integrity tag over the 4-byte bytecode header."""
    if len(bytecode) < 4:
        raise ValueError("bytecode must contain at least 4 header bytes")
    h = tamper_seed & U32_MASK
    for b in bytecode[:4]:
        h = ((h ^ b) * (tamper_prime & U32_MASK)) & U32_MASK
        h = (((h << 13) | (h >> 19)) ^ 0x9E3779B9) & U32_MASK
    return h


def verify_header_integrity_poison(
    bytecode: bytes,
    expected_tag: int,
    tamper_seed: int,
    tamper_prime: int = 0x01000193,
) -> int:
    """Return 0 when bytecode header is intact, or non-zero poison mask if tampered."""
    actual = compute_header_integrity_tag(bytecode, tamper_seed, tamper_prime)
    return (actual ^ (expected_tag & U32_MASK)) & U32_MASK


def compute_bytecode_integrity_tag(bytecode: bytes, tamper_seed: int, tamper_prime: int = 0x01000193) -> int:
    """Non-cryptographic corruption checksum over length and every encoded byte."""
    if len(bytecode) < 4 or len(bytecode) > U32_MASK:
        raise ValueError("bytecode length must be 4..2**32-1")
    h = tamper_seed & U32_MASK
    for b in len(bytecode).to_bytes(4, "little") + bytecode:
        h = ((h ^ b) * (tamper_prime & U32_MASK)) & U32_MASK
        h = (((h << 13) | (h >> 19)) ^ 0x9E3779B9) & U32_MASK
    return h


def _emit_integrity_check(hparams: dict) -> str:
    entries = hparams.get("bytecode_integrity", [])
    if not entries:
        return ""
    checks = "\n".join(
        f"    {'if' if index == 0 else 'else if'} (key == 0x{entry['key']:016x}ULL && bc_len == {entry['bytes']}u) expected = 0x{entry['tag']:08x}u;"
        for index, entry in enumerate(entries))
    return f"""/* Non-cryptographic corruption check; expected values are present in the binary. */
static __attribute__((noinline)) uint32_t antirea_check_bytecode_integrity(
    const uint8_t *bc, uint32_t bc_len, uint64_t key
) {{
    if (!bc || bc_len < 4u) return 0u;
    uint32_t expected;
{checks}
    else return 0u;
    uint32_t h = 0x{hparams['tamper_seed'] & U32_MASK:08x}u;
    for (unsigned i = 0; i < 4u; ++i) {{
        h = (h ^ ((bc_len >> (8u * i)) & 255u)) * 0x{hparams['tamper_prime'] & U32_MASK:08x}u;
        h = ((h << 13) | (h >> 19)) ^ 0x9E3779B9u;
    }}
    for (uint32_t i = 0; i < bc_len; ++i) {{
        h = (h ^ bc[i]) * 0x{hparams['tamper_prime'] & U32_MASK:08x}u;
        h = ((h << 13) | (h >> 19)) ^ 0x9E3779B9u;
    }}
    return h == expected;
}}
"""


# ---------------------------------------------------------------------------
# Layer 3: MBA (Mixed Boolean-Arithmetic), Opaque Predicates, String/Constant
#          Encryption & Dynamic API Resolution (IAT Hiding)
# ---------------------------------------------------------------------------

def mba_expression(op: str, lhs: str = "a", rhs: str = "b", variant: int = 0) -> str:
    """Return a mathematically equivalent Mixed Boolean-Arithmetic C expression."""
    v = variant % 3
    if op == "add":
        if v == 0:
            return f"(({lhs} ^ {rhs}) + ((({lhs} & {rhs})) << 1))"
        if v == 1:
            return f"(({lhs} | {rhs}) + ({lhs} & {rhs}))"
        return f"(({lhs} ^ ~{rhs}) + ((({lhs} | {rhs})) << 1) + 1ULL)"
    if op == "sub":
        if v == 0:
            return f"(({lhs} ^ {rhs}) - (((~{lhs}) & {rhs}) << 1))"
        if v == 1:
            return f"(({lhs} & ~{rhs}) - ((~{lhs}) & {rhs}))"
        return f"(({lhs} + ~{rhs}) + 1ULL)"
    if op == "xor":
        if v == 0:
            return f"(({lhs} | {rhs}) - ({lhs} & {rhs}))"
        if v == 1:
            return f"(({lhs} | {rhs}) & ~({lhs} & {rhs}))"
        return f"(({lhs} + {rhs}) - ((({lhs} & {rhs})) << 1))"
    if op == "and":
        if v == 0:
            return f"(({lhs} + {rhs}) - ({lhs} | {rhs}))"
        return f"(~(~{lhs} | ~{rhs}))"
    if op == "or":
        if v == 0:
            return f"(({lhs} ^ {rhs}) + ({lhs} & {rhs}))"
        return f"(~(~{lhs} & ~{rhs}))"
    raise ValueError(f"Unsupported MBA operation: {op}")


def evaluate_mba_u64(op: str, a: int, b: int, variant: int = 0) -> int:
    """Evaluate the MBA identity in 64-bit unsigned integer arithmetic for verification."""
    a &= U64_MASK
    b &= U64_MASK
    v = variant % 3
    if op == "add":
        if v == 0:
            return ((a ^ b) + (((a & b) << 1) & U64_MASK)) & U64_MASK
        if v == 1:
            return ((a | b) + (a & b)) & U64_MASK
        return ((a ^ (~b & U64_MASK)) + (((a | b) << 1) & U64_MASK) + 1) & U64_MASK
    if op == "sub":
        if v == 0:
            return ((a ^ b) - ((((~a & U64_MASK) & b) << 1) & U64_MASK)) & U64_MASK
        if v == 1:
            return ((a & (~b & U64_MASK)) - ((~a & U64_MASK) & b)) & U64_MASK
        return (a + (~b & U64_MASK) + 1) & U64_MASK
    if op == "xor":
        if v == 0:
            return ((a | b) - (a & b)) & U64_MASK
        if v == 1:
            return ((a | b) & (~(a & b) & U64_MASK)) & U64_MASK
        return ((a + b) - (((a & b) << 1) & U64_MASK)) & U64_MASK
    if op == "and":
        if v == 0:
            return ((a + b) - (a | b)) & U64_MASK
        return (~((~a & U64_MASK) | (~b & U64_MASK))) & U64_MASK
    if op == "or":
        if v == 0:
            return ((a ^ b) + (a & b)) & U64_MASK
        return (~((~a & U64_MASK) & (~b & U64_MASK))) & U64_MASK
    raise ValueError(f"Unsupported MBA operation: {op}")


def opaque_zero_u64(x: int) -> int:
    """Number-theoretic opaque zero: for any odd integer (x | 1), its square mod 8 is 1."""
    x &= U64_MASK
    odd = (x | 1) & U64_MASK
    sq_mod8 = ((odd * odd) & U64_MASK) & 7
    consec_even = ((x * ((x + 1) & U64_MASK)) & U64_MASK) & 1
    return (sq_mod8 ^ 1) | consec_even


def encrypt_bytes(data: bytes, key: int) -> bytes:
    """Encrypt constant bytes or strings with a rolling XOR-rotate stream cipher."""
    state = (key & U32_MASK) or 0xA5A55A5A
    out = bytearray(len(data))
    for i, b in enumerate(data):
        state = ((state * 0x01000193) ^ ((i + 1) * 0x9E3779B9)) & U32_MASK
        state = (((state << 7) | (state >> 25)) & U32_MASK)
        mask = (state ^ (state >> 16)) & 0xFF
        out[i] = b ^ mask
    return bytes(out)


def decrypt_bytes(encoded: bytes, key: int) -> bytes:
    """Decrypt bytes encrypted by encrypt_bytes (symmetric stream cipher)."""
    return encrypt_bytes(encoded, key)


def api_symbol_hash(symbol: str, salt: int = 0x811C9DC5) -> int:
    """Compute a 32-bit FNV-1a + ROR13 hybrid hash for IAT-less dynamic API resolution."""
    h = salt & U32_MASK
    for ch in symbol.encode("ascii"):
        h ^= ch
        h = (((h >> 13) | (h << 19)) & U32_MASK)
        h = (h * 0x01000193) & U32_MASK
    return h


def emit_encrypted_constant_pool(name: str, plaintext: bytes, key: int) -> str:
    """Emit a C encrypted byte array and an inline stack decryptor function."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise ValueError("Invalid C identifier for encrypted pool")
    ciphertext = encrypt_bytes(plaintext, key)
    hex_bytes = ", ".join(f"0x{b:02x}u" for b in ciphertext) or "0x00u"
    return (
        f"static const uint8_t {name}_enc[{max(1, len(ciphertext))}] = {{ {hex_bytes} }};\n"
        f"static inline __attribute__((always_inline)) void {name}_decrypt(uint8_t *out, uint32_t len) {{\n"
        f"    uint32_t st = 0x{((key & U32_MASK) or 0xA5A55A5A):08x}u;\n"
        f"    for (uint32_t i = 0u; i < len && i < {len(ciphertext)}u; ++i) {{\n"
        f"        st = (st * 0x01000193u) ^ ((uint32_t)(i + 1u) * 0x9E3779B9u);\n"
        f"        st = (st << 7) | (st >> 25);\n"
        f"        out[i] = (uint8_t)({name}_enc[i] ^ ((st ^ (st >> 16)) & 0xFFu));\n"
        f"    }}\n"
        f"}}\n"
    )


def emit_peb_api_resolver(salt: int = 0x811C9DC5) -> str:
    """Emit salted symbol hash and registered internal dispatch-table resolver (no OS PEB/PE walk)."""
    return (
        f"typedef struct antirea_symbol_entry {{\n"
        f"    uint32_t sym_hash;\n"
        f"    const void *target;\n"
        f"}} antirea_symbol_entry_t;\n"
        f"static inline __attribute__((always_inline)) uint32_t antirea_api_hash(const char *sym) {{\n"
        f"    uint32_t h = 0x{salt & U32_MASK:08x}u;\n"
        f"    while (sym && *sym) {{\n"
        f"        h ^= (uint8_t)(*sym++);\n"
        f"        h = (h >> 13) | (h << 19);\n"
        f"        h *= 0x01000193u;\n"
        f"    }}\n"
        f"    return h;\n"
        f"}}\n"
        f"static __attribute__((noinline)) const void *antirea_resolve_symbol_by_hash(\n"
        f"    const antirea_symbol_entry_t *table, uint32_t count, uint32_t target_hash\n"
        f") {{\n"
        f"    if (!table || count == 0u) return (const void *)0;\n"
        f"    for (uint32_t i = 0u; i < count; ++i) {{\n"
        f"        if (table[i].sym_hash == target_hash && table[i].target) {{\n"
        f"            return table[i].target;\n"
        f"        }}\n"
        f"    }}\n"
        f"    return (const void *)0;\n"
        f"}}\n"
    )


def _emit_ephemeral_scrub_and_pool_guard(hparams: dict) -> str:
    anchor_plain = b"ANTIREA8"
    anchor_enc = encrypt_bytes(anchor_plain, hparams["string_key"])
    anchor_tag = compute_bytecode_integrity_tag(
        anchor_enc, hparams["tamper_seed"], hparams["tamper_prime"]
    )
    anchor_hex = ", ".join(f"0x{b:02x}u" for b in anchor_enc)
    return (
        f"/* Ephemeral working-buffer zeroizer and read-only guard anchor check; not an OS dump blocker. */\n"
        f"static const uint8_t antirea_guard_anchor[8] = {{ {anchor_hex} }};\n"
        f"static __attribute__((noinline)) void antirea_scrub_ephemeral_bytes(\n"
        f"    volatile uint8_t *buf, uint32_t len\n"
        f") {{\n"
        f"    if (!buf) return;\n"
        f"    for (uint32_t i = 0u; i < len; ++i) {{\n"
        f"        buf[i] = 0u;\n"
        f"    }}\n"
        f"#if defined(__clang__) || defined(__GNUC__)\n"
        f"    __asm__ __volatile__(\"\" : : \"r\"(buf) : \"memory\");\n"
        f"#endif\n"
        f"}}\n"
        f"static __attribute__((noinline)) uint32_t antirea_verify_guard_pool_integrity(\n"
        f"    const uint8_t *pool, uint32_t pool_len, uint32_t expected_tag\n"
        f") {{\n"
        f"    if (!pool || pool_len < 4u) return 0u;\n"
        f"    uint32_t h = 0x{hparams['tamper_seed'] & U32_MASK:08x}u;\n"
        f"    for (unsigned i = 0u; i < 4u; ++i) {{\n"
        f"        h = (h ^ ((pool_len >> (8u * i)) & 255u)) * 0x{hparams['tamper_prime'] & U32_MASK:08x}u;\n"
        f"        h = ((h << 13) | (h >> 19)) ^ 0x9E3779B9u;\n"
        f"    }}\n"
        f"    for (uint32_t i = 0u; i < pool_len; ++i) {{\n"
        f"        h = (h ^ pool[i]) * 0x{hparams['tamper_prime'] & U32_MASK:08x}u;\n"
        f"        h = ((h << 13) | (h >> 19)) ^ 0x9E3779B9u;\n"
        f"    }}\n"
        f"    return h == expected_tag ? 0u : 0x{anchor_tag:08x}u;\n"
        f"}}\n"
    ), anchor_tag


# ---------------------------------------------------------------------------
# Layer 4: Multi-VM & Decentralized Dispatch Guard
# ---------------------------------------------------------------------------

def derive_multi_vm_seeds(master_seed: int | str, count: int) -> list[int]:
    """Derive independent deterministic VM seeds via one-way SHA-256 counter blocks."""
    if type(count) is not int or count < 1 or count > 256:
        raise ValueError("Multi-VM count must be between 1 and 256")
    seeds: list[int] = []
    seen: set[int] = set()
    counter = 0
    while len(seeds) < count:
        digest = _csprng_block(master_seed, "multi_vm_seed", counter)
        counter += 1
        cand = (int.from_bytes(digest[:8], "little") | 1) & U64_MASK
        if cand not in seen:
            seen.add(cand)
            seeds.append(cand)
    return seeds


# ---------------------------------------------------------------------------
# Layer 1, 2, 3, 4, 5, 6 Combined C Runtime Hardening Prelude
# ---------------------------------------------------------------------------

def emit_runtime_hardening_helpers(hparams: dict) -> str:
    """Emit only selected components; unused helpers may be optimized away.

    Missing implementations are not synthesized from labels. The integrity
    function is intentionally noinline so its runtime use can be checked in IR.
    """
    layers = set(selected_layers(hparams.get("enabled_layers", ())))
    pieces = []
    anchor_tag = 0
    if "anti_tamper" in layers:
        pieces.append(_emit_integrity_check(hparams))
    if "string_constant_encryption" in layers:
        pieces.append(emit_encrypted_constant_pool("antirea_guard_sig", b"ANTIREA-VM-GUARD-V2", hparams["string_key"]))
    if "iat_api_hiding" in layers:
        pieces.append(emit_peb_api_resolver(hparams["api_hash_salt"]))
    if "anti_dump" in layers:
        scrub_src, anchor_tag = _emit_ephemeral_scrub_and_pool_guard(hparams)
        pieces.append(scrub_src)
    if "mba_opaque" in layers:
        for op in ("add", "sub", "xor"):
            expression = mba_expression(op, "a", "b", hparams["mba_variant"])
            pieces.append(f"static inline __attribute__((always_inline)) uint64_t antirea_mba_{op}(uint64_t a, uint64_t b) {{ return {expression}; }}\n")
    if layers & {"mba_opaque", "anti_llm_honeypot"}:
        pieces.append("""static inline __attribute__((always_inline)) uint32_t antirea_opaque_zero(uint64_t x) {
    uint64_t odd = x | 1ULL;
    uint64_t sq_mod8 = (odd * odd) & 7ULL;
    uint64_t even_prod = (x * (x + 1ULL)) & 1ULL;
    return (uint32_t)((sq_mod8 ^ 1ULL) | even_prod);
}
""")
    if "anti_llm_honeypot" in layers:
        constants = ", ".join(f"0x{c & U32_MASK:08x}u" for c in hparams["honeypot_constants"])
        pieces.append(f"""/* Inert decoy code/data, not instructions to an analysis tool. */
static const uint32_t antirea_decoy_sbox[8] = {{ {constants} }};
static inline __attribute__((always_inline)) uint32_t antirea_honeypot_feistel(uint32_t v, uint32_t k) {{
    uint32_t l = v ^ 0x{hparams['honeypot_seed'] & U32_MASK:08x}u;
    uint32_t r = k ^ antirea_decoy_sbox[v & 7u];
    for (unsigned i = 0; i < 4u; ++i) {{
        uint32_t f = ((r << 5) | (r >> 27)) + (r ^ antirea_decoy_sbox[(i + r) & 7u]);
        uint32_t next_l = r;
        r = l ^ f;
        l = next_l;
    }}
    return l ^ r;
}}
""")
    guard = []
    if "anti_debug" in layers:
        guard.append(f"""    /* Existing Windows BeingDebugged check only; no Frida/hook scanner. */
#if defined(_WIN32) && defined(__x86_64__)
    unsigned long long __readgsqword(unsigned long);
    const uint8_t *peb = (const uint8_t *)(uintptr_t)__readgsqword(0x60ul);
    if (peb && peb[2] != 0) {{
        poison ^= 0x{hparams['poison_salt'] & U32_MASK:08x}u;
    }}
#elif defined(_WIN32) && defined(__i386__)
    unsigned long __readfsdword(unsigned long);
    const uint8_t *peb = (const uint8_t *)(uintptr_t)__readfsdword(0x30ul);
    if (peb && peb[2] != 0) {{
        poison ^= 0x{hparams['poison_salt'] & U32_MASK:08x}u;
    }}
#endif
""")
    if "string_constant_encryption" in layers:
        guard.append(f"""    {{
        uint8_t sig_check_buf[20];
        antirea_guard_sig_decrypt(sig_check_buf, 19u);
        uint32_t sig_diff = ((uint32_t)sig_check_buf[0] ^ 0x41u) | ((uint32_t)sig_check_buf[18] ^ 0x32u);
        poison ^= sig_diff * 0x{hparams['poison_salt'] & U32_MASK:08x}u;
        for (unsigned i = 0u; i < 20u; ++i) ((volatile uint8_t *)sig_check_buf)[i] = 0u;
    }}
""")
    if "anti_dump" in layers:
        guard.append(f"""    {{
        uint8_t eph_tmp[8] = {{ (uint8_t)key, (uint8_t)(key >> 8), 0x5au, 0xa5u, 1u, 2u, 3u, 4u }};
        poison ^= antirea_verify_guard_pool_integrity(antirea_guard_anchor, 8u, 0x{anchor_tag & U32_MASK:08x}u);
        antirea_scrub_ephemeral_bytes(eph_tmp, 8u);
    }}
""")
    if "mba_opaque" in layers:
        guard.append(f"""    /* Algebraic-zero diagnostic checks, not replacement of target arithmetic. */
    if (bc && bc_len >= 4u) {{
        uint32_t hdr = (uint32_t)bc[0] | ((uint32_t)bc[1] << 8) | ((uint32_t)bc[2] << 16) | ((uint32_t)bc[3] << 24);
        uint64_t mba_check = antirea_mba_sub(antirea_mba_add((uint64_t)hdr, (uint64_t)key), (uint64_t)key) ^ (uint64_t)hdr;
        uint32_t op_zero = antirea_opaque_zero(antirea_mba_xor((uint64_t)hdr, (uint64_t)key) ^ 0x{hparams['tamper_prime'] & U32_MASK:08x}u);
        poison ^= (op_zero | (uint32_t)mba_check) * 0x{hparams['dispatch_guard_salt'] & U32_MASK:08x}u;
    }}
""")
    if "anti_llm_honeypot" in layers:
        decoy_input = "key"
        decoy_lines = ""
        if "string_constant_encryption" in layers:
            decoy_lines += "        uint8_t sig_buf[20];\n        antirea_guard_sig_decrypt(sig_buf, sizeof(sig_buf));\n"
            decoy_input += " ^ sig_buf[0]"
        if "iat_api_hiding" in layers:
            decoy_input += ' ^ antirea_api_hash("antirea_decoy_symbol")'
        guard.append(f"""    /* Mathematically unreachable decoy; optimization may remove it. */
    if (antirea_opaque_zero((uint64_t)bc_len ^ (uint64_t)key) != 0u) {{
{decoy_lines}        poison ^= antirea_honeypot_feistel({decoy_input}, bc_len);
    }}
""")
    if guard:
        pieces.append("static inline __attribute__((always_inline)) uint32_t antirea_env_and_tamper_guard(\n"
                      "    const uint8_t *bc, uint32_t bc_len, uint32_t key\n) {\n    uint32_t poison = 0u;\n"
                      + "".join(guard) + "    return poison;\n}\n")
    return "".join(pieces)


# ---------------------------------------------------------------------------
# Layer 6: LLVM IR Honeypot, String Constant Encryption & MBA SSA Rewriter
# ---------------------------------------------------------------------------

def _decode_llvm_ir_cstring(escaped: str) -> bytes:
    out = bytearray()
    i = 0
    n = len(escaped)
    while i < n:
        ch = escaped[i]
        if ch == "\\":
            if i + 1 < n and escaped[i + 1] == "\\":
                out.append(0x5C)
                i += 2
                continue
            if i + 2 >= n or not re.fullmatch(r"[0-9A-Fa-f]{2}", escaped[i + 1 : i + 3]):
                raise ValueError(f"Unsupported LLVM string escape near {escaped[i:i+4]!r}")
            out.append(int(escaped[i + 1 : i + 3], 16))
            i += 3
        else:
            code = ord(ch)
            if code > 127:
                raise ValueError("Non-ASCII unescaped byte in LLVM IR string")
            out.append(code)
            i += 1
    return bytes(out)


def _encode_llvm_ir_bytes(data: bytes) -> str:
    return "".join(f"\\{b:02X}" for b in data)


_IR_PRIVATE_CSTRING_RE = re.compile(
    r'^(?P<name>@[A-Za-z0-9_.$]+)\s*=\s*(?P<vis>private|internal)\s+'
    r'(?P<addr>(?:(?:unnamed_addr|local_unnamed_addr)\s+)*)'
    r'constant\s+\[(?P<len>\d+)\s+x\s+i8\]\s+c"(?P<body>[^"]*)"(?P<tail>.*)$'
)


def encrypt_llvm_ir_cstrings(ir_text: str, key: int) -> tuple[str, dict]:
    """Encrypt module-private [N x i8] c"..." constants and inject a lazy materializer."""
    if not isinstance(ir_text, str):
        raise ValueError("ir_text must be a string")
    eff_key = (key & U32_MASK) or 0xA5A55A5A
    encrypted_entries: list[tuple[str, str, int]] = []
    out_lines: list[str] = []

    for line in ir_text.splitlines():
        m = _IR_PRIVATE_CSTRING_RE.match(line.strip())
        if m is not None:
            gname = m.group("name")
            tail = m.group("tail") or ""
            if (
                not gname.startswith(("@llvm.", "@__antirea_", "@antirea_vm_", "@kagura_vm_"))
                and "section" not in tail
            ):
                arr_len = int(m.group("len"))
                try:
                    plain = _decode_llvm_ir_cstring(m.group("body"))
                except ValueError:
                    plain = b""
                if len(plain) == arr_len and arr_len >= 1:
                    cipher = encrypt_bytes(plain, eff_key)
                    enc_sym = f"{gname}.antirea_enc"
                    escaped = _encode_llvm_ir_bytes(cipher)
                    out_lines.append(
                        f'{enc_sym} = private unnamed_addr constant [{arr_len} x i8] c"{escaped}"{tail}'
                    )
                    out_lines.append(
                        f"{gname} = internal global [{arr_len} x i8] zeroinitializer, align 1"
                    )
                    encrypted_entries.append((gname, enc_sym, arr_len))
                    continue
        out_lines.append(line)

    if not encrypted_entries:
        return ir_text, {"encrypted_globals": 0, "globals": []}

    target_names = [g for g, _, _ in encrypted_entries]
    rewritten_lines: list[str] = []
    idx = 0
    total = len(out_lines)
    while idx < total:
        line = out_lines[idx]
        stripped = line.strip()
        if stripped.startswith("define ") and stripped.endswith("{") and "@__antirea_" not in stripped:
            fn_lines = [line]
            idx += 1
            while idx < total and out_lines[idx].strip() != "}":
                fn_lines.append(out_lines[idx])
                idx += 1
            if idx < total:
                fn_lines.append(out_lines[idx])
                idx += 1
            fn_body_text = "\n".join(fn_lines[1:-1])
            if any(re.search(re.escape(g) + r"(?![A-Za-z0-9_.$])", fn_body_text) for g in target_names):
                insert_pos = 1
                if insert_pos < len(fn_lines) - 1 and fn_lines[insert_pos].strip().endswith(":"):
                    insert_pos += 1
                while insert_pos < len(fn_lines) - 1:
                    stmt = fn_lines[insert_pos].strip()
                    if not stmt or stmt.startswith(";") or "= phi " in stmt or "= alloca " in stmt:
                        insert_pos += 1
                    else:
                        break
                fn_lines.insert(insert_pos, "  call void @__antirea_materialize_cstrings()")
            rewritten_lines.extend(fn_lines)
            continue
        rewritten_lines.append(line)
        idx += 1

    helper_lines = [
        "",
        "@__antirea_cstrings_ready = internal global i8 0, align 1",
        "define internal void @__antirea_materialize_cstrings() noinline nounwind {",
        "entry:",
        "  %ready = load volatile i8, ptr @__antirea_cstrings_ready, align 1",
        "  %done = icmp ne i8 %ready, 0",
        "  br i1 %done, label %exit, label %init_0",
    ]
    for e_idx, (gname, enc_sym, arr_len) in enumerate(encrypted_entries):
        next_lbl = f"init_{e_idx + 1}" if e_idx + 1 < len(encrypted_entries) else "mark_done"
        helper_lines.extend([
            f"init_{e_idx}:",
            f"  br label %loop_{e_idx}",
            f"loop_{e_idx}:",
            f"  %i.{e_idx} = phi i32 [ 0, %init_{e_idx} ], [ %inext.{e_idx}, %loop_{e_idx} ]",
            f"  %st.{e_idx} = phi i32 [ {eff_key}, %init_{e_idx} ], [ %st.rot.{e_idx}, %loop_{e_idx} ]",
            f"  %ip1.{e_idx} = add i32 %i.{e_idx}, 1",
            f"  % m1.{e_idx} = mul i32 %st.{e_idx}, 16777619".replace("% m1", "%m1"),
            f"  %m2.{e_idx} = mul i32 %ip1.{e_idx}, 2654435769",
            f"  %st.x.{e_idx} = xor i32 %m1.{e_idx}, %m2.{e_idx}",
            f"  %shl.{e_idx} = shl i32 %st.x.{e_idx}, 7",
            f"  %shr.{e_idx} = lshr i32 %st.x.{e_idx}, 25",
            f"  %st.rot.{e_idx} = or i32 %shl.{e_idx}, %shr.{e_idx}",
            f"  %hi.{e_idx} = lshr i32 %st.rot.{e_idx}, 16",
            f"  %mx.{e_idx} = xor i32 %st.rot.{e_idx}, %hi.{e_idx}",
            f"  %mask.{e_idx} = trunc i32 %mx.{e_idx} to i8",
            f"  %idx64.{e_idx} = zext i32 %i.{e_idx} to i64",
            f"  %sp.{e_idx} = getelementptr inbounds [{arr_len} x i8], ptr {enc_sym}, i64 0, i64 %idx64.{e_idx}",
            f"  %dp.{e_idx} = getelementptr inbounds [{arr_len} x i8], ptr {gname}, i64 0, i64 %idx64.{e_idx}",
            f"  %cb.{e_idx} = load i8, ptr %sp.{e_idx}, align 1",
            f"  %pb.{e_idx} = xor i8 %cb.{e_idx}, %mask.{e_idx}",
            f"  store i8 %pb.{e_idx}, ptr %dp.{e_idx}, align 1",
            f"  %inext.{e_idx} = add i32 %i.{e_idx}, 1",
            f"  %cont.{e_idx} = icmp ult i32 %inext.{e_idx}, {arr_len}",
            f"  br i1 %cont.{e_idx}, label %loop_{e_idx}, label %{next_lbl}",
        ])
    helper_lines.extend([
        "mark_done:",
        "  store volatile i8 1, ptr @__antirea_cstrings_ready, align 1",
        "  br label %exit",
        "exit:",
        "  ret void",
        "}",
    ])
    final_ir = "\n".join(rewritten_lines + helper_lines) + "\n"
    return final_ir, {"encrypted_globals": len(encrypted_entries), "globals": target_names}


_IR_MBA_BINOP_RE = re.compile(
    r"^(?P<indent>\s*)(?P<dst>%[A-Za-z0-9_.$]+)\s*=\s*"
    r"(?P<op>add|sub|xor)(?:\s+(?:nuw|nsw))*\s+"
    r"(?P<ty>i32|i64)\s+(?P<lhs>[^,\r\n;]+),\s*(?P<rhs>[^,\r\n;]+?)"
    r"(?P<comment>\s*(?:;.*)?)$"
)


def rewrite_llvm_ir_mba(ir_text: str, seed: int | str) -> tuple[str, dict]:
    """Rewrite i32/i64 add/sub/xor SSA instructions into polymorphic MBA + opaque-zero sequences."""
    if not isinstance(ir_text, str):
        raise ValueError("ir_text must be a string")
    out_lines: list[str] = []
    op_counts = {"add": 0, "sub": 0, "xor": 0}
    site = 0
    in_user_fn = False

    for line in ir_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("define ") and stripped.endswith("{"):
            in_user_fn = "@__antirea_" not in stripped
            out_lines.append(line)
            continue
        if in_user_fn and stripped == "}":
            in_user_fn = False
            out_lines.append(line)
            continue
        if in_user_fn:
            m = _IR_MBA_BINOP_RE.match(line)
            if m is not None:
                ind = m.group("indent")
                dst = m.group("dst")
                op = m.group("op")
                ty = m.group("ty")
                lhs = m.group("lhs").strip()
                rhs = m.group("rhs").strip()
                variant = _csprng_block(seed, "ir_mba_site", site)[0] % 3
                p = f"%__antirea_mba_{site}"
                site += 1
                op_counts[op] += 1

                # Opaque zero: (((lhs | 1) * (lhs | 1)) & 7) ^ 1 == 0 mod 2^w
                seq = [
                    f"{ind}{p}.odd = or {ty} {lhs}, 1",
                    f"{ind}{p}.sq = mul {ty} {p}.odd, {p}.odd",
                    f"{ind}{p}.m8 = and {ty} {p}.sq, 7",
                    f"{ind}{p}.oz = xor {ty} {p}.m8, 1",
                ]
                if op == "add":
                    if variant == 0:
                        seq.extend([
                            f"{ind}{p}.x = xor {ty} {lhs}, {rhs}",
                            f"{ind}{p}.a = and {ty} {lhs}, {rhs}",
                            f"{ind}{p}.s = shl {ty} {p}.a, 1",
                            f"{ind}{p}.core = add {ty} {p}.x, {p}.s",
                        ])
                    elif variant == 1:
                        seq.extend([
                            f"{ind}{p}.o = or {ty} {lhs}, {rhs}",
                            f"{ind}{p}.a = and {ty} {lhs}, {rhs}",
                            f"{ind}{p}.core = add {ty} {p}.o, {p}.a",
                        ])
                    else:
                        seq.extend([
                            f"{ind}{p}.o = or {ty} {lhs}, {rhs}",
                            f"{ind}{p}.s = shl {ty} {p}.o, 1",
                            f"{ind}{p}.x = xor {ty} {lhs}, {rhs}",
                            f"{ind}{p}.core = sub {ty} {p}.s, {p}.x",
                        ])
                elif op == "sub":
                    if variant == 0:
                        seq.extend([
                            f"{ind}{p}.x = xor {ty} {lhs}, {rhs}",
                            f"{ind}{p}.na = xor {ty} {lhs}, -1",
                            f"{ind}{p}.b = and {ty} {p}.na, {rhs}",
                            f"{ind}{p}.s = shl {ty} {p}.b, 1",
                            f"{ind}{p}.core = sub {ty} {p}.x, {p}.s",
                        ])
                    elif variant == 1:
                        seq.extend([
                            f"{ind}{p}.nb = xor {ty} {rhs}, -1",
                            f"{ind}{p}.na = xor {ty} {lhs}, -1",
                            f"{ind}{p}.l = and {ty} {lhs}, {p}.nb",
                            f"{ind}{p}.r = and {ty} {p}.na, {rhs}",
                            f"{ind}{p}.core = sub {ty} {p}.l, {p}.r",
                        ])
                    else:
                        seq.extend([
                            f"{ind}{p}.nb = xor {ty} {rhs}, -1",
                            f"{ind}{p}.t = add {ty} {lhs}, {p}.nb",
                            f"{ind}{p}.core = add {ty} {p}.t, 1",
                        ])
                else:  # xor
                    if variant == 0:
                        seq.extend([
                            f"{ind}{p}.o = or {ty} {lhs}, {rhs}",
                            f"{ind}{p}.a = and {ty} {lhs}, {rhs}",
                            f"{ind}{p}.core = sub {ty} {p}.o, {p}.a",
                        ])
                    elif variant == 1:
                        seq.extend([
                            f"{ind}{p}.o = or {ty} {lhs}, {rhs}",
                            f"{ind}{p}.a = and {ty} {lhs}, {rhs}",
                            f"{ind}{p}.na = xor {ty} {p}.a, -1",
                            f"{ind}{p}.core = and {ty} {p}.o, {p}.na",
                        ])
                    else:
                        seq.extend([
                            f"{ind}{p}.sum = add {ty} {lhs}, {rhs}",
                            f"{ind}{p}.a = and {ty} {lhs}, {rhs}",
                            f"{ind}{p}.s = shl {ty} {p}.a, 1",
                            f"{ind}{p}.core = sub {ty} {p}.sum, {p}.s",
                        ])
                seq.append(f"{ind}{dst} = xor {ty} {p}.core, {p}.oz")
                out_lines.extend(seq)
                continue
        out_lines.append(line)

    return "\n".join(out_lines) + ("\n" if ir_text.endswith("\n") else ""), {
        "rewritten_instructions": site,
        "ops": op_counts,
    }


def emit_llvm_ir_honeypot(seed: int | str) -> str:
    """Emit inert unreferenced decoys; retention and analysis impact are unproven."""
    hparams = hardening_parameters(seed)
    tag = f"{hparams['honeypot_seed']:08x}"
    enc_bytes = encrypt_bytes(b"CHACHA20-POLY1305-DECOY-KEY-EXPAND", hparams["string_key"])
    ir_escaped = "".join(f"\\{b:02X}" for b in enc_bytes)
    c0, c1, c2, c3 = hparams["honeypot_constants"][:4]
    return (
        f'\n@__antirea_decoy_pool_{tag} = private unnamed_addr constant [{len(enc_bytes)} x i8] c"{ir_escaped}", align 1\n'
        f"define internal i64 @__antirea_decoy_cipher_{tag}(i64 %x, i64 %y) noinline nounwind {{\n"
        f"entry:\n"
        f"  %k0 = xor i64 %x, {c0}\n"
        f"  %k1 = add i64 %y, {c1}\n"
        f"  %m0 = mul i64 %k0, {c2 | 1}\n"
        f"  %r0 = xor i64 %m0, %k1\n"
        f"  %s0 = lshr i64 %r0, 17\n"
        f"  %r1 = xor i64 %r0, %s0\n"
        f"  %m1 = mul i64 %r1, {c3 | 1}\n"
        f"  ret i64 %m1\n"
        f"}}\n"
    )


def hardening_capabilities(hparams: dict | None, *, runtime_source: str = "", core_ir: str = "",
                          dispatcher_symbol: str = "", blob_count: int = 0,
                          vm_engines: list[dict] | None = None) -> dict:
    """Describe generated components without turning source text into application proof."""
    requested = selected_layers((hparams or {}).get("enabled_layers", ()))
    descriptions = {
        "anti_debug": ("partial_implementation", ["Windows x86/x64 BeingDebugged read only.",
                        "No Frida detection, prologue scanner, hook scanner or debugger-resistance proof."]),
        "anti_tamper": ("scoped_corruption_check", ["Encoded bytecode and length only; no executable/self-text checksum.",
                         "32-bit non-cryptographic checksum and expected values are recoverable; not authentication."]),
        "mba_opaque": ("guard_and_ir_mba_rewriter", ["Emits C MBA/opaque-zero guards and provides rewrite_llvm_ir_mba for i32/i64 add/sub/xor SSA instructions.",
                       "Algebraic identities remain statically simplifiable without VM virtualization; external resistance not evaluated."]),
        "string_constant_encryption": ("guard_pool_and_ir_cstring_cipher", ["Encodes runtime guard signature pool with active guard check and provides encrypt_llvm_ir_cstrings for private [N x i8] IR literals.",
                                       "Lazy IR materializer decrypts into module-internal globals on first call; external resistance not evaluated."]),
        "iat_api_hiding": ("internal_dispatch_table_resolver", ["Provides salted symbol hashing and antirea_resolve_symbol_by_hash over caller-registered internal antirea_symbol_entry_t tables.",
                           "Intentionally does not walk OS PEB/PE export tables, hide OS imports, or rewrite IAT entries."]),
        "multi_vm_indirect_dispatch": ("per_function_diversification" if vm_engines and len(vm_engines) > 1
                                       else "not_applied_shared_dispatcher", [
                                       "Distinct per-function opcode/fetch/operand contracts and volatile function-pointer slots, when multi-engine mode is selected.",
                                       "Deterministic SHA-256 diversification; decoders and pointers remain in the delivered binary.",
                                       "Single-function and disabled profiles retain the shared/direct path."]),
        "anti_dump": ("ephemeral_scrub_and_pool_guard", ["Provides volatile working-buffer zeroizer (antirea_scrub_ephemeral_bytes) and read-only guard-anchor integrity check.",
                      "Does not block OS memory dumps, erase executable headers, alter page permissions, or pack binaries."]),
        "anti_llm_honeypot": ("inert_decoys_only", ["Unreferenced IR data/functions and a mathematically unreachable C branch.",
                              "No prompt-injection text; no measured LLM-specific effect; compiler/linker may remove decoys."]),
    }
    markers = {
        "anti_debug": "__readgsqword", "anti_tamper": "antirea_check_bytecode_integrity",
        "mba_opaque": "antirea_mba_add", "string_constant_encryption": "antirea_guard_sig_enc",
        "iat_api_hiding": "antirea_resolve_symbol_by_hash", "anti_dump": "antirea_scrub_ephemeral_bytes",
        "anti_llm_honeypot": "antirea_honeypot_feistel",
    }
    layers = {}
    for name in HARDENING_LAYERS:
        implementation, gaps = descriptions[name]
        emitted = name in requested and (markers.get(name, "\x00") in runtime_source
                    or (name == "anti_llm_honeypot" and "define internal i64 @__antirea_decoy_cipher_" in core_ir))
        if name == "multi_vm_indirect_dispatch":
            emitted = bool(name in requested and vm_engines and len(vm_engines) > 1
                           and all(f'uint64_t {engine["dispatcher_symbol"]}(' in runtime_source
                                   and f'load volatile ptr, ptr @{engine["dispatch_slot"]}' in core_ir
                                   for engine in vm_engines))
        layers[name] = {"requested": name in requested, "implementation": implementation,
                        "source_emitted": emitted,
                        "artifact_status": "retention_not_checked" if emitted else
                                           "not_emitted" if name in requested else "disabled",
                        "runtime_component_retained": None, "limitations": gaps}
    return {"schema_version": 1, "evidence_stage": "generated_source_only", "requested_layers": list(requested),
            "dispatcher_symbol": dispatcher_symbol, "blob_count": blob_count,
            "independent_vm_parameter_sets": len(vm_engines) if vm_engines else 1 if blob_count else 0,
            "parameter_set_count_semantics": "Generated parameter sets; retained dispatcher evidence is separate.", "layers": layers,
            "source_evidence": {"runtime_sha256": hashlib.sha256(runtime_source.encode()).hexdigest(),
                                "core_ir_sha256": hashlib.sha256(core_ir.encode()).hexdigest()},
            "verified_retained_components": [], "binary_linkage": "not_verified",
            "functional_preservation": "not_evaluated", "external_resistance": "not_evaluated"}


def _ir_function(ir: str, symbol: str) -> str:
    match = re.search(r"(?ms)^define\s+[^\r\n]*@" + re.escape(symbol) + r"\([^\r\n]*\)[^\r\n]*\{\r?\n(.*?)^\}", ir)
    return match.group(1) if match else ""


def inspect_hardening_artifact(manifest: dict, runtime_ir: str, core_ir: str | None = None) -> dict:
    """Read retained LLVM IR structure, not source markers or executable efficacy.

    The caller must bind these IR hashes to its own compilation/link commands.
    This function does not mutate the manifest or read/write files.
    """
    if not isinstance(runtime_ir, str) or (core_ir is not None and not isinstance(core_ir, str)):
        raise ValueError("artifact inspection requires IR text")
    symbol = manifest["dispatcher_symbol"]
    evidence = copy.deepcopy(manifest.get("hardening_capabilities") or hardening_capabilities(
        manifest.get("parameters", {}).get("hardening"), dispatcher_symbol=symbol,
        blob_count=len(manifest.get("blobs", [])), vm_engines=manifest.get("engines")))
    engines = manifest.get("engines") if manifest.get("engine_mode") == "per_function_indirect" else None
    runtime_engines = engines or [{"dispatcher_symbol": symbol,
                                   "integrity_checker_symbol": "antirea_check_bytecode_integrity"}]
    bodies = {engine["dispatcher_symbol"]: _ir_function(runtime_ir, engine["dispatcher_symbol"])
              for engine in runtime_engines}
    body = "\n".join(bodies.values())
    evidence.update(evidence_stage="retained_llvm_ir", dispatcher_found=all(bool(part) for part in bodies.values()),
                    dispatchers_found={name: bool(part) for name, part in bodies.items()},
                    ir_evidence={"runtime_sha256": hashlib.sha256(runtime_ir.encode()).hexdigest(),
                                 "core_sha256": hashlib.sha256(core_ir.encode()).hexdigest() if core_ir is not None else None})
    retained = []
    for name, layer in evidence["layers"].items():
        if not layer["requested"]:
            continue
        if name == "anti_tamper":
            checks = []
            for engine in runtime_engines:
                checker_name = engine["integrity_checker_symbol"]
                checker = _ir_function(runtime_ir, checker_name)
                dispatcher_body = bodies[engine["dispatcher_symbol"]]
                called = bool(re.search(r"\bcall\b[^\n]*@" + re.escape(checker_name) + r"\(", dispatcher_body))
                observed = bool(checker and called and re.search(r"\bload i8\b", checker)
                                and re.search(r"\bmul i32\b", checker)
                                and re.search(r"\bcall\b[^\n]*@abort\(", dispatcher_body))
                checks.append({"dispatcher": engine["dispatcher_symbol"], "checker": checker_name,
                               "checker_defined": bool(checker), "called_from_dispatcher": called,
                               "byte_loads": len(re.findall(r"\bload i8\b", checker)),
                               "checksum_multiplications": len(re.findall(r"\bmul i32\b", checker)),
                               "observed": observed})
            observed = all(check["observed"] for check in checks)
            layer["retained_ir_evidence"] = {"engines": checks, "all_engines_checked": observed} if engines else checks[0]
            layer["runtime_component_retained"] = observed
            layer["artifact_status"] = "scoped_check_retained" if observed else "retention_not_proven"
            if observed:
                retained.append("encoded_bytecode_length_checksum_check")
        elif name == "multi_vm_indirect_dispatch":
            bindings, error = {}, None
            if engines and core_ir is not None:
                # Local import avoids a module initialization cycle. The shared
                # parser is also used by the builder's VM coverage gate.
                from antirea.diversify import inspect_vm_bindings
                try:
                    bindings = inspect_vm_bindings(core_ir, manifest)
                except (ValueError, KeyError, TypeError) as exc:
                    error = str(exc)
            hashes = {name: hashlib.sha256(part.encode()).hexdigest() for name, part in bodies.items() if part}
            observed = bool(engines and len(engines) > 1 and len(bindings) == len(engines)
                            and len(hashes) == len(engines) and len(set(hashes.values())) == len(engines))
            layer["runtime_component_retained"] = observed
            layer["artifact_status"] = "independent_dispatchers_retained" if observed else "retention_not_proven" if engines else "not_applied_shared_dispatcher"
            layer["retained_ir_evidence"] = {"bindings": bindings, "dispatcher_body_sha256": hashes,
                                             "binding_error": error, "core_ir_supplied": core_ir is not None,
                                             "scope": "IR function/slot/blob bindings plus separate dispatcher definitions; not binary efficacy"}
            if observed:
                retained.append("per_function_independent_vm_indirect_dispatch")
        elif name == "anti_debug":
            # This is deliberately narrow and only observes the existing PEB
            # read in the dispatcher. It does not prove a general anti-debugger.
            observations = re.findall(r"(?:__readgsqword|__readfsdword|llvm\.[^\s(]*(?:readgs|readfs|read_register)[^\s(]*|asm[^\n]*(?:gs:|fs:))", body)
            layer["runtime_component_retained"] = bool(observations)
            layer["retained_ir_evidence"] = {"peb_read_markers": observations}
            layer["artifact_status"] = "partial_component_retained" if observations else "retention_not_proven"
            if observations:
                retained.append("windows_peb_read_only")
        elif name == "anti_dump":
            checks = []
            for engine in runtime_engines:
                prefix = engine.get("namespace_prefix", "")
                scrub_sym = f"{prefix}antirea_scrub_ephemeral_bytes"
                scrubber = _ir_function(runtime_ir, scrub_sym)
                dispatcher_body = bodies[engine["dispatcher_symbol"]]
                called = bool(re.search(r"\bcall\b[^\n]*@" + re.escape(scrub_sym) + r"\(", dispatcher_body))
                volatile_stores = len(re.findall(r"\bstore(?:\s+atomic)?\s+volatile\s+i8\s+0\b", scrubber))
                observed = bool(scrubber and called and volatile_stores > 0)
                checks.append({"dispatcher": engine["dispatcher_symbol"], "scrubber": scrub_sym,
                               "scrubber_defined": bool(scrubber), "called_from_dispatcher": called,
                               "volatile_zero_stores": volatile_stores, "observed": observed})
            observed = all(item["observed"] for item in checks)
            layer["retained_ir_evidence"] = {"engines": checks, "all_engines_checked": observed} if engines else checks[0]
            layer["runtime_component_retained"] = observed
            layer["artifact_status"] = "scoped_check_retained" if observed else "retention_not_proven"
            if observed:
                retained.append("volatile_ephemeral_buffer_scrub")
        elif name == "iat_api_hiding":
            checks = []
            for engine in runtime_engines:
                prefix = engine.get("namespace_prefix", "")
                res_sym = f"{prefix}antirea_resolve_symbol_by_hash"
                resolver = _ir_function(runtime_ir, res_sym)
                dispatcher_body = bodies[engine["dispatcher_symbol"]]
                called = bool(re.search(r"\bcall\b[^\n]*@" + re.escape(res_sym) + r"\(", dispatcher_body))
                hash_cmps = len(re.findall(r"\bicmp eq i32\b", resolver))
                observed = bool(resolver and called and hash_cmps > 0)
                checks.append({"dispatcher": engine["dispatcher_symbol"], "resolver": res_sym,
                               "resolver_defined": bool(resolver), "called_from_dispatcher": called,
                               "hash_comparisons": hash_cmps, "observed": observed})
            observed = all(item["observed"] for item in checks)
            layer["retained_ir_evidence"] = {"engines": checks, "all_engines_checked": observed} if engines else checks[0]
            layer["runtime_component_retained"] = observed
            layer["artifact_status"] = "scoped_check_retained" if observed else "retention_not_proven"
            if observed:
                retained.append("internal_hashed_symbol_table_dispatch")
        elif name == "anti_llm_honeypot":
            count = len(re.findall(r"(?m)^define\s+[^\n]*@__antirea_decoy_cipher_", core_ir or ""))
            layer["retained_ir_evidence"] = {"decoy_definitions_in_supplied_core_ir": count,
                                             "core_ir_supplied": core_ir is not None}
            layer["runtime_component_retained"] = False
            layer["artifact_status"] = "inert_core_ir_present" if count else "not_retained_in_supplied_ir" if core_ir is not None else "retention_not_checked"
        elif layer["implementation"] != "gap_not_implemented":
            layer["runtime_component_retained"] = None
            layer["artifact_status"] = "helper_only_no_application_claim"
    evidence["verified_retained_components"] = retained
    return evidence
