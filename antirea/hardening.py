"""Optional code-generation components and conservative artifact evidence.

HARDENING_LAYERS is a legacy request vocabulary, not a list of implemented or
applied protections. Source emission, retained IR, functional checks and external
resistance are separate facts. API resolution and anti-dump are not implemented;
per-function VM diversification is conditional on multiple selected functions.
Decoys are inert program code/data, never instructions to an analysis agent.
"""

from __future__ import annotations

import hashlib
import copy
import random
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
    """Derive deterministic parameters; selection does not assert application."""
    layers = selected_layers(enabled_layers)
    rng = random.Random(_seed_int(seed))
    poison_salt = rng.randrange(1, 1 << 32) | 1
    tamper_seed = rng.randrange(1, 1 << 32) | 1
    tamper_prime = rng.choice((0x01000193, 0x85EBCA6B, 0xC2B2AE35, 0x27D4EB2F))
    mba_variant = rng.randrange(0, 4)
    string_key = rng.randrange(1, 1 << 32) | 1
    api_hash_salt = rng.randrange(1, 1 << 32) | 1
    dispatch_guard_salt = rng.randrange(1, 1 << 32) | 1
    honeypot_seed = rng.randrange(1, 1 << 32) | 1
    honeypot_constants = [rng.randrange(1, 1 << 32) for _ in range(8)]
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
        f"static inline __attribute__((always_inline)) void {name}_decrypt(uint8_t *out, size_t len) {{\n"
        f"    uint32_t st = 0x{((key & U32_MASK) or 0xA5A55A5A):08x}u;\n"
        f"    for (size_t i = 0; i < len && i < {len(ciphertext)}u; ++i) {{\n"
        f"        st = (st * 0x01000193u) ^ ((uint32_t)(i + 1u) * 0x9E3779B9u);\n"
        f"        st = (st << 7) | (st >> 25);\n"
        f"        out[i] = (uint8_t)({name}_enc[i] ^ ((st ^ (st >> 16)) & 0xFFu));\n"
        f"    }}\n"
        f"}}\n"
    )


def emit_peb_api_resolver(salt: int = 0x811C9DC5) -> str:
    """Legacy name: emits ONLY a symbol hash, no PEB/export walk or API resolver."""
    return (
        f"static inline __attribute__((always_inline)) uint32_t antirea_api_hash(const char *sym) {{\n"
        f"    uint32_t h = 0x{salt & U32_MASK:08x}u;\n"
        f"    while (sym && *sym) {{\n"
        f"        h ^= (uint8_t)(*sym++);\n"
        f"        h = (h >> 13) | (h << 19);\n"
        f"        h *= 0x01000193u;\n"
        f"    }}\n"
        f"    return h;\n"
        f"}}\n"
    )


# ---------------------------------------------------------------------------
# Layer 4: Multi-VM & Decentralized Dispatch Guard
# ---------------------------------------------------------------------------

def derive_multi_vm_seeds(master_seed: int | str, count: int) -> list[int]:
    """Derive independent deterministic VM seeds for Multi-VM per-function isolation."""
    if type(count) is not int or count < 1 or count > 256:
        raise ValueError("Multi-VM count must be between 1 and 256")
    base = _seed_int(master_seed)
    return [((base + (idx + 1) * 0x9E3779B97F4A7C15) & U64_MASK) for idx in range(count)]


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
    if "anti_tamper" in layers:
        pieces.append(_emit_integrity_check(hparams))
    if "string_constant_encryption" in layers:
        pieces.append(emit_encrypted_constant_pool("antirea_guard_sig", b"ANTIREA-VM-GUARD-V2", hparams["string_key"]))
    if "iat_api_hiding" in layers:
        pieces.append(emit_peb_api_resolver(hparams["api_hash_salt"]))
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
# Layer 6: LLVM IR Honeypot & Encrypted Constant Pool Injection
# ---------------------------------------------------------------------------

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
        "mba_opaque": ("diagnostic_helpers_only", ["Algebraic-zero guard checks, not target arithmetic replacement.",
                       "Optimizer may remove these identities and opaque branches."]),
        "string_constant_encryption": ("decoy_pool_helper_only", ["Only a synthetic guard-signature pool is encoded.",
                                       "Application strings/constants are not scanned or rewritten."]),
        "iat_api_hiding": ("hash_helper_only", ["No PEB module walk, export lookup, import rewrite or API resolution."]),
        "multi_vm_indirect_dispatch": ("per_function_diversification" if vm_engines and len(vm_engines) > 1
                                       else "not_applied_shared_dispatcher", [
                                       "Distinct per-function opcode/fetch/operand contracts and volatile function-pointer slots, when multi-engine mode is selected.",
                                       "Deterministic diversification, not cryptographic independence; decoders and pointers remain recoverable.",
                                       "Single-function and disabled profiles retain the shared/direct path."]),
        "anti_dump": ("gap_not_implemented", ["No packing, page protection, header erase or memory-dump guard."]),
        "anti_llm_honeypot": ("inert_decoys_only", ["Unreferenced IR data/functions and a mathematically unreachable C branch.",
                              "No prompt-injection text; no measured LLM-specific effect; compiler/linker may remove decoys."]),
    }
    markers = {
        "anti_debug": "__readgsqword", "anti_tamper": "antirea_check_bytecode_integrity",
        "mba_opaque": "antirea_mba_add", "string_constant_encryption": "antirea_guard_sig_enc",
        "iat_api_hiding": "antirea_api_hash", "anti_llm_honeypot": "antirea_honeypot_feistel",
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
