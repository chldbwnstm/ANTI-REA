from __future__ import annotations

from pathlib import Path
import ctypes
import os
import subprocess
import random
import tempfile
import unittest

import antirea.diversify as d
import antirea.hardening as h
ROOT = Path(__file__).resolve().parents[1]
CLANG = ROOT / ".tools/clang+llvm-22.1.0-x86_64-pc-windows-msvc/bin/clang.exe"


class HardeningSuiteTests(unittest.TestCase):
    def test_registry_records_requested_names_not_applied_features(self):
        params = h.hardening_parameters(42)
        self.assertEqual(set(params["enabled_layers"]), set(h.HARDENING_LAYERS))
        self.assertEqual(len(params["honeypot_constants"]), 8)
        self.assertTrue(params["poison_salt"] & 1)
        self.assertTrue(params["tamper_seed"] & 1)

    def test_anti_tamper_header_integrity_tag_and_silent_poison(self):
        blob = bytes([0xFE, 0x12, 0x34, 0x56, 0xAA, 0xBB])
        tag = h.compute_header_integrity_tag(blob, 0x13579BDF, 0x01000193)
        self.assertEqual(h.verify_header_integrity_poison(blob, tag, 0x13579BDF, 0x01000193), 0)
        for idx in range(4):
            tampered = bytearray(blob)
            tampered[idx] ^= 0x01
            poison = h.verify_header_integrity_poison(bytes(tampered), tag, 0x13579BDF, 0x01000193)
            self.assertNotEqual(poison, 0)

    def test_mba_identities_match_exact_64bit_arithmetic_and_bitwise_ops(self):
        samples = [
            (0, 0),
            (1, 1),
            (0xFFFFFFFF, 1),
            (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF),
            (0x123456789ABCDEF0, 0xFEDCBA9876543210),
            (0x8000000000000000, 0x7FFFFFFFFFFFFFFF),
        ]
        for a, b in samples:
            for variant in range(3):
                self.assertEqual(h.evaluate_mba_u64("add", a, b, variant), (a + b) & h.U64_MASK)
                self.assertEqual(h.evaluate_mba_u64("sub", a, b, variant), (a - b) & h.U64_MASK)
                self.assertEqual(h.evaluate_mba_u64("xor", a, b, variant), (a ^ b) & h.U64_MASK)
                self.assertEqual(h.evaluate_mba_u64("and", a, b, variant), (a & b) & h.U64_MASK)
                self.assertEqual(h.evaluate_mba_u64("or", a, b, variant), (a | b) & h.U64_MASK)

    def test_opaque_zero_holds_for_all_boundary_and_sampled_u64_values(self):
        values = [
            0, 1, 2, 3, 7, 8, 255, 65535,
            0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
            0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0xFFFFFFFFFFFFFFFF,
            0x9E3779B97F4A7C15, 0xBF58476D1CE4E5B9,
        ]
        for x in values:
            self.assertEqual(h.opaque_zero_u64(x), 0)

    def test_string_and_constant_stream_encryption_roundtrips(self):
        secret = b"ANTIREA-SECRET-CONSTANT-TABLE-V2"
        cipher = h.encrypt_bytes(secret, 0xCAFEBABE)
        self.assertNotEqual(cipher, secret)
        self.assertEqual(h.decrypt_bytes(cipher, 0xCAFEBABE), secret)
        c_code = h.emit_encrypted_constant_pool("test_pool", secret, 0xCAFEBABE)
        self.assertIn("test_pool_enc", c_code)
        self.assertIn("test_pool_decrypt", c_code)

    def test_dynamic_api_symbol_hash_and_multi_vm_seeds(self):
        h1 = h.api_symbol_hash("IsDebuggerPresent")
        h2 = h.api_symbol_hash("NtQueryInformationProcess")
        self.assertNotEqual(h1, h2)
        seeds = h.derive_multi_vm_seeds(99, 4)
        self.assertEqual(len(set(seeds)), 4)

    def test_runtime_helpers_do_not_claim_vendor_features(self):
        params = d.parameters(7, {"F_RR_ADD", "OP_RET"})
        self.assertIn("hardening", params)
        prelude = h.emit_runtime_hardening_helpers(params["hardening"])
        self.assertIn("antirea_env_and_tamper_guard", prelude)
        self.assertIn("antirea_honeypot_feistel", prelude)
        self.assertIn("antirea_mba_add", prelude)
        self.assertIn("antirea_opaque_zero", prelude)
        self.assertIn("__readgsqword(0x60ul)", prelude)
        self.assertNotIn("AntiFrida", prelude)
        self.assertNotIn("Anti-Dump", prelude)

    def test_empty_layer_selection_emits_no_helpers(self):
        params = h.hardening_parameters(7, enabled_layers=[])
        self.assertEqual(h.emit_runtime_hardening_helpers(params), "")

    def test_individual_layers_do_not_enable_unrequested_checks(self):
        for layer in h.HARDENING_LAYERS:
            with self.subTest(layer=layer):
                source = h.emit_runtime_hardening_helpers(h.hardening_parameters(7, enabled_layers=[layer]))
                self.assertEqual("__readgsqword" in source, layer == "anti_debug")
                self.assertEqual("antirea_api_hash" in source, layer == "iat_api_hiding")
                self.assertEqual("antirea_guard_sig_enc" in source, layer == "string_constant_encryption")
                self.assertEqual("antirea_honeypot_feistel" in source, layer == "anti_llm_honeypot")

    def test_unknown_and_malformed_layer_selection_rejected(self):
        for value in (["made_up"], "anti_debug", [1], [["anti_debug"]]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                h.hardening_parameters(7, enabled_layers=value)

    def test_full_bytecode_checksum_covers_body_and_length_not_only_header(self):
        blob = bytes(range(80))
        tag = h.compute_bytecode_integrity_tag(blob, 7)
        for index in range(len(blob)):
            changed = bytearray(blob)
            changed[index] ^= 1
            self.assertNotEqual(h.compute_bytecode_integrity_tag(changed, 7), tag)
        self.assertNotEqual(h.compute_bytecode_integrity_tag(blob + b"\x00", 7), tag)
        with self.assertRaises(ValueError):
            h.compute_bytecode_integrity_tag(b"bad", 7)

    def test_zero_key_pool_emitter_matches_python_fallback_key(self):
        source = h.emit_encrypted_constant_pool("zero", b"constant", 0)
        self.assertIn("uint32_t st = 0xa5a55a5au", source)
        self.assertEqual(h.decrypt_bytes(h.encrypt_bytes(b"constant", 0), 0), b"constant")

    def test_capabilities_expose_gaps_helpers_and_source_only_evidence(self):
        params = h.hardening_parameters(7)
        report = h.hardening_capabilities(params, runtime_source=h.emit_runtime_hardening_helpers(params),
                                         core_ir=h.emit_llvm_ir_honeypot(7), blob_count=4)
        self.assertEqual(report["independent_vm_parameter_sets"], 1)
        self.assertEqual(report["layers"]["anti_dump"]["implementation"], "ephemeral_scrub_and_pool_guard")
        self.assertEqual(report["layers"]["multi_vm_indirect_dispatch"]["implementation"], "not_applied_shared_dispatcher")
        self.assertEqual(report["layers"]["iat_api_hiding"]["implementation"], "internal_dispatch_table_resolver")
        self.assertEqual(report["layers"]["string_constant_encryption"]["implementation"], "guard_pool_and_ir_cstring_cipher")
        self.assertEqual(report["layers"]["mba_opaque"]["implementation"], "guard_and_ir_mba_rewriter")
        self.assertEqual(report["verified_retained_components"], [])
        self.assertEqual(report["external_resistance"], "not_evaluated")

    def test_kerckhoffs_sha256_derivation_eliminates_linear_seed_stepping(self):
        p1 = h.hardening_parameters(101)
        p2 = h.hardening_parameters(101)
        p3 = h.hardening_parameters(102)
        self.assertEqual(p1, p2)
        self.assertNotEqual(p1["poison_salt"], p3["poison_salt"])
        seeds = h.derive_multi_vm_seeds(99, 6)
        self.assertEqual(len(set(seeds)), 6)
        # Verify non-affine spacing (no constant step s[i+1] - s[i] mod 2^64)
        deltas = {(seeds[i + 1] - seeds[i]) & h.U64_MASK for i in range(len(seeds) - 1)}
        self.assertGreaterEqual(len(deltas), 4)

    def test_llvm_ir_cstring_encryption_and_mba_rewriter_units(self):
        sample_ir = (
            '@.str.secret = private unnamed_addr constant [14 x i8] c"ANTIREA_TOKEN\\00", align 1\n'
            '@llvm.used = appending global [1 x ptr] [ptr @.str.secret], section "llvm.metadata"\n'
            'define i64 @compute_tag(i64 %a, i64 %b) {\n'
            'entry:\n'
            '  %0 = add nsw i64 %a, %b\n'
            '  %1 = xor i64 %0, 255\n'
            '  %2 = sub i64 %1, %a\n'
            '  %ch = load i8, ptr @.str.secret, align 1\n'
            '  %ch64 = zext i8 %ch to i64\n'
            '  %out = add i64 %2, %ch64\n'
            '  ret i64 %out\n'
            '}\n'
        )
        enc_ir, str_meta = h.encrypt_llvm_ir_cstrings(sample_ir, 0xCAFEBABE)
        self.assertEqual(str_meta["encrypted_globals"], 1)
        self.assertNotIn("ANTIREA_TOKEN", enc_ir)
        self.assertIn("@__antirea_materialize_cstrings", enc_ir)

        mba_ir, mba_meta = h.rewrite_llvm_ir_mba(enc_ir, 20261111)
        self.assertGreaterEqual(mba_meta["rewritten_instructions"], 4)
        self.assertNotIn("add nsw i64 %a, %b", mba_ir)

    def test_retained_evidence_does_not_accept_source_labels_or_unreferenced_helpers(self):
        params = h.hardening_parameters(7, enabled_layers=["anti_tamper"])
        manifest = {"dispatcher_symbol": "dispatch", "parameters": {"hardening": params}}
        ir = "define i64 @dispatch() {\n  ret i64 0\n}\n; antirea_check_bytecode_integrity load i8 mul i32\n"
        evidence = h.inspect_hardening_artifact(manifest, ir)
        self.assertFalse(evidence["layers"]["anti_tamper"]["runtime_component_retained"])
        self.assertEqual(evidence["verified_retained_components"], [])

    def test_mba_random_regression_preserves_u64_values(self):
        rng = random.Random(1729)
        for _ in range(128):
            a, b = rng.getrandbits(64), rng.getrandbits(64)
            for variant in range(3):
                self.assertEqual(h.evaluate_mba_u64("add", a, b, variant), (a + b) & h.U64_MASK)
                self.assertEqual(h.evaluate_mba_u64("sub", a, b, variant), (a - b) & h.U64_MASK)


@unittest.skipUnless(CLANG.exists(), "portable local Clang needed for retained IR evidence")
class CompiledHardeningTests(unittest.TestCase):
    def compile_ir(self, source, language="c"):
        completed = subprocess.run([str(CLANG), "-O2", "-S", "-emit-llvm", "-x", language, "-", "-o", "-"],
                                   input=source, text=True, capture_output=True, timeout=30, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return completed.stdout

    def test_actual_compiled_checksum_and_call_are_retained(self):
        params = h.hardening_parameters(7, enabled_layers=["anti_tamper"])
        blob = b"head-body"
        params["bytecode_integrity"] = [{"key": 7, "bytes": len(blob), "tag": h.compute_bytecode_integrity_tag(blob, params["tamper_seed"], params["tamper_prime"])}]
        prelude = "typedef unsigned char uint8_t; typedef unsigned int uint32_t; typedef unsigned long long uint64_t; extern void abort(void);\n"
        source = prelude + h.emit_runtime_hardening_helpers(params) + "\nuint64_t dispatch(const uint8_t *p, uint32_t n, uint64_t k) { if (!antirea_check_bytecode_integrity(p,n,k)) abort(); return k; }\n"
        ir = self.compile_ir(source)
        manifest = {"dispatcher_symbol": "dispatch", "parameters": {"hardening": params}}
        evidence = h.inspect_hardening_artifact(manifest, ir)
        self.assertTrue(evidence["layers"]["anti_tamper"]["runtime_component_retained"], ir)
        self.assertEqual(evidence["verified_retained_components"], ["encoded_bytecode_length_checksum_check"])
        self.assertEqual(evidence["binary_linkage"], "not_verified")

    def test_unused_decoys_are_removed_and_not_reported_as_effective(self):
        core_ir = self.compile_ir(h.emit_llvm_ir_honeypot(7), language="ir")
        params = h.hardening_parameters(7, enabled_layers=["anti_llm_honeypot"])
        manifest = {"dispatcher_symbol": "dispatch", "parameters": {"hardening": params}}
        evidence = h.inspect_hardening_artifact(manifest, "", core_ir)
        self.assertEqual(evidence["layers"]["anti_llm_honeypot"]["artifact_status"], "not_retained_in_supplied_ir")

    @unittest.skipUnless(os.name == "nt", "compiled helper execution uses a Windows DLL")
    def test_compiled_checksum_matches_python_and_rejects_changed_inputs(self):
        params = h.hardening_parameters(19, enabled_layers=["anti_tamper"])
        blob = bytes(range(80))
        key = 0x123456789ABCDEF0
        params["bytecode_integrity"] = [{
            "key": key, "bytes": len(blob),
            "tag": h.compute_bytecode_integrity_tag(blob, params["tamper_seed"], params["tamper_prime"]),
        }]
        source = "typedef unsigned char uint8_t; typedef unsigned int uint32_t; typedef unsigned long long uint64_t;\n"
        source += h.emit_runtime_hardening_helpers(params)
        source += "\n__declspec(dllexport) uint32_t check(const uint8_t *p, uint32_t n, uint64_t k) { return antirea_check_bytecode_integrity(p,n,k); }\n"
        with tempfile.TemporaryDirectory(prefix="antirea-checksum-test-") as temporary:
            dll_path = Path(temporary) / "checksum.dll"
            compiled = subprocess.run([
                str(CLANG), "-O2", "-x", "c", "-", "-shared", "-nostdlib", "-fuse-ld=lld",
                "-Wl,/NOENTRY", "-o", str(dll_path),
            ], input=source, text=True, capture_output=True, timeout=30, check=False)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            dll = ctypes.CDLL(str(dll_path))
            try:
                check = dll.check
                check.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32, ctypes.c_uint64]
                check.restype = ctypes.c_uint32
                data = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
                self.assertEqual(check(data, len(blob), key), 1)
                for index in range(len(blob)):
                    data[index] ^= 1
                    self.assertEqual(check(data, len(blob), key), 0)
                    data[index] ^= 1
                self.assertEqual(check(data, len(blob) - 1, key), 0)
                self.assertEqual(check(data, 0xFFFFFFFF, key), 0)
                self.assertEqual(check(data, len(blob), key ^ 1), 0)
                self.assertEqual(check(None, len(blob), key), 0)
            finally:
                # Explicitly unload this test-owned DLL before Windows temp cleanup.
                import _ctypes
                _ctypes.FreeLibrary(dll._handle)

    @unittest.skipUnless(os.name == "nt", "compiled helper execution uses a Windows DLL")
    def test_compiled_dispatch_resolver_ephemeral_scrub_and_ir_passes(self):
        params = h.hardening_parameters(31, enabled_layers=["iat_api_hiding", "anti_dump"])
        salt = params["api_hash_salt"]
        add_hash = h.api_symbol_hash("internal_secret_add", salt)
        miss_hash = h.api_symbol_hash("nonexistent_entry", salt)
        source = (
            "typedef unsigned char uint8_t; typedef unsigned int uint32_t; typedef unsigned long long uint64_t;\n"
            + h.emit_runtime_hardening_helpers(params)
            + f"""
static uint64_t internal_secret_add(uint64_t x, uint64_t y) {{ return (x + y) ^ 0x55aaULL; }}
static const antirea_symbol_entry_t DISPATCH_TABLE[1] = {{
    {{ 0x{add_hash:08x}u, (const void *)&internal_secret_add }}
}};
__declspec(dllexport) uint64_t invoke_by_hash(uint32_t hval, uint64_t x, uint64_t y) {{
    typedef uint64_t (*fn_t)(uint64_t, uint64_t);
    const void *p = antirea_resolve_symbol_by_hash(DISPATCH_TABLE, 1u, hval);
    if (!p) return 0xdeadbeefULL;
    return ((fn_t)p)(x, y);
}}
__declspec(dllexport) uint32_t scrub_probe(uint8_t seed_byte) {{
    uint8_t buf[16];
    for (unsigned i = 0; i < 16u; ++i) buf[i] = (uint8_t)(seed_byte + i + 1u);
    antirea_scrub_ephemeral_bytes(buf, 16u);
    uint32_t acc = 0u;
    for (unsigned i = 0; i < 16u; ++i) acc |= buf[i];
    return acc;
}}
"""
        )
        # Also test retained IR evidence for anti_dump and iat_api_hiding
        ir_check_src = (
            "typedef unsigned char uint8_t; typedef unsigned int uint32_t; typedef unsigned long long uint64_t;\n"
            + h.emit_runtime_hardening_helpers(params)
            + "\nuint64_t dispatch(uint8_t *b, const antirea_symbol_entry_t *t, uint32_t hval) {\n"
            "  antirea_scrub_ephemeral_bytes(b, 8u);\n"
            "  return (uint64_t)(uintptr_t)antirea_resolve_symbol_by_hash(t, 1u, hval);\n"
            "}\n"
        ).replace("uintptr_t", "unsigned long long")
        retained_ir = self.compile_ir(ir_check_src)
        manifest = {"dispatcher_symbol": "dispatch", "parameters": {"hardening": params}}
        ev = h.inspect_hardening_artifact(manifest, retained_ir)
        self.assertTrue(ev["layers"]["anti_dump"]["runtime_component_retained"], retained_ir)
        self.assertTrue(ev["layers"]["iat_api_hiding"]["runtime_component_retained"], retained_ir)

        # Also compile LLVM IR transformed by encrypt_llvm_ir_cstrings + rewrite_llvm_ir_mba into a live DLL
        raw_ir = (
            '@.str.banner = private unnamed_addr constant [8 x i8] c"V20-OK!\\00", align 1\n'
            'define dllexport i64 @ir_pipeline_eval(i64 %a, i64 %b) {\n'
            'entry:\n'
            '  %s0 = add i64 %a, %b\n'
            '  %s1 = sub i64 %s0, 17\n'
            '  %s2 = xor i64 %s1, %b\n'
            '  %p1 = getelementptr inbounds [8 x i8], ptr @.str.banner, i64 0, i64 1\n'
            '  %c0 = load i8, ptr @.str.banner, align 1\n'
            '  %c1 = load i8, ptr %p1, align 1\n'
            '  %z0 = zext i8 %c0 to i64\n'
            '  %z1 = zext i8 %c1 to i64\n'
            '  %tag = add i64 %z0, %z1\n'
            '  %res = xor i64 %s2, %tag\n'
            '  ret i64 %res\n'
            '}\n'
        )
        enc_ir, _ = h.encrypt_llvm_ir_cstrings(raw_ir, 0x13579BDF)
        mba_ir, _ = h.rewrite_llvm_ir_mba(enc_ir, 987654321)

        with tempfile.TemporaryDirectory(prefix="antirea-v20-hardening-") as temporary:
            dll_c = Path(temporary) / "helpers.dll"
            res_c = subprocess.run(
                [str(CLANG), "-O2", "-x", "c", "-", "-shared", "-nostdlib", "-fuse-ld=lld", "-Wl,/NOENTRY", "-o", str(dll_c)],
                input=source, text=True, capture_output=True, timeout=30, check=False,
            )
            self.assertEqual(res_c.returncode, 0, res_c.stderr)

            dll_ir = Path(temporary) / "irpass.dll"
            res_ir = subprocess.run(
                [str(CLANG), "-O2", "-x", "ir", "-", "-shared", "-nostdlib", "-fuse-ld=lld", "-Wl,/NOENTRY", "-o", str(dll_ir)],
                input=mba_ir, text=True, capture_output=True, timeout=30, check=False,
            )
            self.assertEqual(res_ir.returncode, 0, res_ir.stderr)

            lib_c = ctypes.CDLL(str(dll_c))
            lib_ir = ctypes.CDLL(str(dll_ir))
            try:
                invoke = lib_c.invoke_by_hash
                invoke.argtypes = [ctypes.c_uint32, ctypes.c_uint64, ctypes.c_uint64]
                invoke.restype = ctypes.c_uint64
                self.assertEqual(invoke(add_hash, 40, 2), (40 + 2) ^ 0x55AA)
                self.assertEqual(invoke(miss_hash, 40, 2), 0xDEADBEEF)

                scrub = lib_c.scrub_probe
                scrub.argtypes = [ctypes.c_ubyte]
                scrub.restype = ctypes.c_uint32
                self.assertEqual(scrub(0x77), 0)

                ir_eval = lib_ir.ir_pipeline_eval
                ir_eval.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
                ir_eval.restype = ctypes.c_uint64
                expected_tag = ord("V") + ord("2")
                for a, b in [(0, 0), (40, 2), (0xFFFFFFFFFFFFFFFF, 1), (0x123456789ABCDEF0, 0x0FEDCBA987654321)]:
                    s0 = (a + b) & h.U64_MASK
                    s1 = (s0 - 17) & h.U64_MASK
                    s2 = (s1 ^ b) & h.U64_MASK
                    expected = (s2 ^ expected_tag) & h.U64_MASK
                    self.assertEqual(ir_eval(a, b), expected)
            finally:
                import _ctypes
                _ctypes.FreeLibrary(lib_c._handle)
                _ctypes.FreeLibrary(lib_ir._handle)


if __name__ == "__main__":
    unittest.main()
