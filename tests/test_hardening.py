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
        self.assertEqual(report["layers"]["anti_dump"]["implementation"], "gap_not_implemented")
        self.assertEqual(report["layers"]["multi_vm_indirect_dispatch"]["implementation"], "not_applied_shared_dispatcher")
        self.assertEqual(report["layers"]["iat_api_hiding"]["implementation"], "hash_helper_only")
        self.assertEqual(report["verified_retained_components"], [])
        self.assertEqual(report["external_resistance"], "not_evaluated")

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


if __name__ == "__main__":
    unittest.main()
