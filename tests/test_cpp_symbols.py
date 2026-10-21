"""Owned C++ symbol mapping tests; actual LLVM parsing is opt-in."""
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from antirea import cpp_symbols as cs
from antirea import native_build as nb


IR = b'''target triple = "x86_64-pc-windows-msvc"
define i64 @"?mix@core@@YA_K_K0@Z"(i64 %a, i64 %b) {
entry:
  %x = xor i64 %a, 713
  %y = add i64 %x, %b
  ret i64 %y
}
define i32 @"?mix@core@@YAIII@Z"(i32 %a, i32 %b) {
entry:
  %x = xor i32 %a, 53
  %y = add i32 %x, %b
  ret i32 %y
}
define i64 @public_score(i64 %a, i64 %b) {
entry:
  %wide = call i64 @"?mix@core@@YA_K_K0@Z"(i64 %a, i64 %b)
  %small_a = trunc i64 %a to i32
  %small_b = trunc i64 %b to i32
  %small = call i32 @"?mix@core@@YAIII@Z"(i32 %small_a, i32 %small_b)
  %small64 = zext i32 %small to i64
  %result = xor i64 %wide, %small64
  ret i64 %result
}
'''
WIDE = "?mix@core@@YA_K_K0@Z"
NARROW = "?mix@core@@YAIII@Z"
SELECTED = [WIDE, NARROW, "public_score"]


def completed(argv, cwd):
    return {"argv": argv, "cwd": str(cwd), "returncode": 0, "timed_out": False, "cancelled": False, "pid": 123,
            "cleanup": {"method": "windows_job", "status": "assigned_job_empty", "parent_pid": 123,
                        "assignment_timing": "immediately_after_launch", "job_assigned": True, "active_after": 0,
                        "parent_exit_confirmed": True, "job_handle_closed": True}}


def write_toolchain(root, actual_config=None):
    """Owned config fixture; fake tools are inert bytes and never executed."""
    config_dir = root / ".tools"
    config_dir.mkdir()
    if actual_config is None:
        llvm_root = config_dir / "llvm"
        binaries = llvm_root / "bin"
        binaries.mkdir(parents=True)
        for name in ("clang++.exe", "llvm-link.exe", "opt.exe", "lld-link.exe", "LLVM-C.dll"):
            (binaries / name).write_bytes(b"INERT UNIT METADATA ONLY: " + name.encode())
        config = {"schema_version": 1, "target": cs.TARGET, "llvm_root": str(llvm_root),
                  "clangxx": str(binaries / "clang++.exe")}
    else:
        config = copy.deepcopy(actual_config)
        llvm_root = Path(config["llvm_root"])
    (config_dir / "kagura-toolchain.json").write_text(json.dumps(config), encoding="utf-8")
    return {"llvm_link": str(llvm_root / "bin/llvm-link.exe"),
            "scope_optimizer": str(llvm_root / "bin/opt.exe"), "clangxx": config["clangxx"]}


def make_boundary(root, build, tools, ir=IR, exports=None):
    exports = exports or ["public_score"]
    units, modules = [], []
    for index, name in enumerate(("mix.cpp", "narrow.cpp", "entry.cpp")):
        modules.append(build / f"source-{index:03d}.ll")
        modules[-1].write_bytes(b"; inert module inventory fixture\n")
        units.append({"source": str(root / name), "entry_sha256": str(index + 1) * 64})
    database = {"workspace_root": str(root), "translation_units": units}
    database["fingerprint"] = cs._json_digest(database)
    (build / "compile-database-plan.json").write_text(json.dumps(database))
    raw, canonical = build / "module.raw.ll", build / "module.before.ll"
    raw.write_bytes(ir)
    canonical.write_bytes(ir)
    return cs.make_link_boundary(workspace=root, build_dir=build, database=database,
        module_paths=modules, raw_ir=raw, input_ir=canonical, toolchain=tools, exports=exports,
        module_link_record=completed([tools["llvm_link"], "-S", *map(str, modules), "-o", str(raw)], build),
        canonicalize_record=completed([tools["scope_optimizer"], "-passes=mem2reg", "-S", str(raw), "-o", str(canonical)], build))


def fake_pe(names=("public_score",)):
    """Non-executable PE metadata fixture, never loaded as a DLL."""
    data = bytearray(4096)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", data, 0x84, 0x8664, 1)
    struct.pack_into("<H", data, 0x94, 240)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20b)
    struct.pack_into("<I", data, optional + 108, 16)
    struct.pack_into("<II", data, optional + 112, 0x1000, 0x180)
    section = optional + 240
    struct.pack_into("<IIII", data, section + 8, 0xe00, 0x1000, 0xe00, 0x200)
    struct.pack_into("<IIIII", data, 0x200 + 20, len(names), len(names), 0x1040, 0x1080, 0x10c0)
    cursor = 0x1100
    for index, name in enumerate(names):
        struct.pack_into("<I", data, 0x240 + 4 * index, 0x1800 + index * 16)
        struct.pack_into("<I", data, 0x280 + 4 * index, cursor)
        struct.pack_into("<H", data, 0x2c0 + 2 * index, index)
        encoded = name.encode() + b"\0"
        offset = cursor - 0x1000 + 0x200
        data[offset:offset + len(encoded)] = encoded
        cursor += len(encoded)
    return bytes(data)


class PureSymbolEvidenceTests(unittest.TestCase):
    def test_pe_metadata_inventory_and_extra_export(self):
        self.assertEqual(cs.pe_exports(fake_pe()), ["public_score"])
        self.assertEqual(cs.pe_exports(fake_pe(("extra", "public_score"))), ["extra", "public_score"])
        bad = bytearray(fake_pe())
        struct.pack_into("<I", bad, 0x240, 0x1110)
        with self.assertRaisesRegex(cs.SymbolMappingError, "forwarded"):
            cs.pe_exports(bytes(bad))

    def test_ordinal_only_duplicate_or_unbacked_exports_fail(self):
        for mutation in ("ordinal_only", "duplicate", "unbacked"):
            data = bytearray(fake_pe(("a", "a") if mutation == "duplicate" else ("a",)))
            if mutation == "ordinal_only":
                struct.pack_into("<I", data, 0x200 + 20, 2)
            if mutation == "unbacked":
                struct.pack_into("<I", data, 0x240, 0xFFFFFFF0)
            with self.subTest(mutation=mutation), self.assertRaises(cs.SymbolMappingError):
                cs.pe_exports(bytes(data))

    def test_coverage_is_exact_bijection_at_every_stage(self):
        manifest = {"source_selected_functions": [WIDE, "public_score"],
            "protected_selected_functions": ["mapped", "public_score"],
            "functions": {WIDE: {"protected_symbol": "mapped"}, "public_score": {"protected_symbol": "public_score"}}}
        stages = {stage: {name: {"virtualized": True} for name in manifest["protected_selected_functions"]}
                  for stage in ("post_vm", "diversified", "final_codegen")}
        self.assertEqual(set(cs.bind_coverage(manifest, **stages)), {WIDE, "public_score"})
        for stage in stages:
            bad = copy.deepcopy(stages)
            bad[stage].pop("mapped")
            with self.subTest(stage=stage), self.assertRaises(cs.SymbolMappingError):
                cs.bind_coverage(manifest, **bad)
        duplicate = copy.deepcopy(manifest)
        duplicate["functions"][WIDE]["protected_symbol"] = "public_score"
        with self.assertRaises(cs.SymbolMappingError):
            cs.bind_coverage(duplicate, **stages)

    def test_final_link_requires_exact_command_definition_and_exports(self):
        definition = b"EXPORTS\npublic_score\n"
        temporary = tempfile.TemporaryDirectory(prefix="cpp-final-link-unit-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        build = root / ".runs/build"
        build.mkdir(parents=True)
        boundary = make_boundary(root, build, write_toolchain(root))
        record = completed(boundary["protected_link_argv"], boundary["build_directory"])
        result = cs.verify_final_link(boundary, record, fake_pe(), definition, workspace_root=root)
        self.assertEqual(result["status"], "fixed_link_and_exports_verified")
        for mutation in ("argv", "definition", "exports", "cleanup"):
            action, encoded, names = copy.deepcopy(record), definition, ("public_score",)
            if mutation == "argv":
                action["argv"].append("unreviewed.obj")
            elif mutation == "definition":
                encoded += b"extra\n"
            elif mutation == "exports":
                names = ("public_score", "extra")
            else:
                action["cleanup"]["active_after"] = 1
            with self.subTest(mutation=mutation), self.assertRaises(cs.SymbolMappingError):
                cs.verify_final_link(boundary, action, fake_pe(names), encoded, workspace_root=root)

    def test_cleanup_status_method_pid_and_error_fields_fail_closed(self):
        argv, cwd = ["owned-tool"], "owned-build"
        cs._completed(completed(argv, cwd), argv, cwd)
        for key, value in (("status", "best_effort"), ("method", "taskkill_fallback"), ("status", None),
                           ("parent_pid", 456), ("parent_pid", True), ("active_after", False),
                           ("assignment_timing", None), ("error", "accounting failure"),
                           ("job_setup_error", "unassigned"), ("job_close_error", "close failed")):
            item = completed(argv, cwd)
            item["cleanup"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(cs.SymbolMappingError):
                cs._completed(item, argv, cwd)
        for key, value in (("pid", True), ("pid", 0), ("error", "launch failed"),
                           ("post_cleanup_wait_error", "wait failed"), ("cleanup", [])):
            item = completed(argv, cwd)
            item[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(cs.SymbolMappingError):
                cs._completed(item, argv, cwd)


class ProducerScopeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cpp-scope-unit-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.ir, self.policy = self.root / "module.before.ll", self.root / "policy.json"
        self.ir.write_bytes(IR)
        self.policy.write_text(json.dumps({"core_roots": [WIDE], "sensitive_functions": []}), encoding="utf-8")
        self.project = {"scope_policy": str(self.policy), "scope_policy_sha256": nb._hash(self.policy),
                        "functions": ["public_score"], "compilation_database": {"owned_test_recipe": True}}

    def test_decorated_scope_requires_mapping_but_preserves_source_graph(self):
        result = nb._select_scope(self.project, self.ir, self.ir)
        self.assertEqual(result["status"], "requires_symbol_mapping")
        self.assertEqual(set(result["selected_functions"]), set(SELECTED))
        self.assertEqual(result["scope_plan"]["status"], "ready")
        self.assertEqual(set(result["symbol_mapping_required"]), {WIDE, NARROW})
        self.assertEqual(result["scope_plan"]["graph"]["calls"]["public_score"], sorted([WIDE, NARROW]))
        self.assertEqual(self.ir.read_bytes(), IR)

    def test_mapping_cannot_enable_non_database_or_unreviewed_scope(self):
        ordinary = dict(self.project)
        ordinary.pop("compilation_database")
        self.assertEqual(nb._select_scope(ordinary, self.ir, self.ir)["status"], "needs_review")
        self.ir.write_bytes(IR.replace(b"%x = xor i64 %a, 713", b"%x = load i64, ptr @secret")
                            + b"\n@secret = global i64 713\n")
        result = nb._select_scope(self.project, self.ir, self.ir)
        self.assertEqual(result["status"], "needs_review")
        self.assertTrue(result["scope_plan"]["data_risks"])

    def test_generated_namespace_cannot_be_remapped_as_owned_source(self):
        self.ir.write_bytes(IR.replace(b'@"' + NARROW.encode() + b'"', b"@antirea_cpp_fn_owned"))
        result = nb._select_scope(self.project, self.ir, self.ir)
        self.assertEqual(result["status"], "needs_review")


class ClosedLinkToolTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cpp-trusted-tools-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.build = self.root / ".runs/build"
        self.build.mkdir(parents=True)
        self.tools = write_toolchain(self.root)
        self.boundary = make_boundary(self.root, self.build, self.tools)

    def verify(self, boundary=None):
        return cs._verify_boundary_files(boundary or self.boundary, cs.digest(IR), {"public_score"}, workspace_root=self.root)

    def test_record_cannot_choose_its_own_tool_or_relabel_its_pin(self):
        self.verify()
        for record_key, role in (("module_link_record", "llvm_link"), ("canonicalize_record", "scope_optimizer")):
            changed = copy.deepcopy(self.boundary)
            other = str(self.root / "unreviewed.exe")
            changed[record_key]["argv"][0] = other
            with self.subTest(role=role), self.assertRaises(cs.SymbolMappingError):
                self.verify(changed)
            changed["trusted_link_tools"]["tools"][role]["path"] = other
            with self.subTest(role=role, forged_pin=True), self.assertRaises(cs.SymbolMappingError):
                self.verify(changed)
        changed = copy.deepcopy(self.boundary)
        changed["protected_link_argv"][0] = str(self.root / "unreviewed.exe")
        with self.assertRaises(cs.SymbolMappingError):
            self.verify(changed)

    def test_tool_content_change_and_config_change_are_detected(self):
        path = Path(self.tools["llvm_link"])
        original = path.read_bytes()
        path.write_bytes(b"changed")
        with self.assertRaises(cs.SymbolMappingError):
            self.verify()
        path.write_bytes(original)
        config = self.root / ".tools/kagura-toolchain.json"
        config.write_text(config.read_text() + "\n", encoding="utf-8")
        with self.assertRaises(cs.SymbolMappingError):
            self.verify()

    def test_workspace_and_parser_are_not_report_selected(self):
        changed = copy.deepcopy(self.boundary)
        changed["workspace_root"] = str(self.root / "other-workspace")
        with self.assertRaises(cs.SymbolMappingError):
            self.verify(changed)
        with patch.object(cs, "_api", side_effect=AssertionError("must fail before loading any library")):
            with self.assertRaises(cs.SymbolMappingError):
                cs.remap_protection_symbols(IR, selected_symbols=SELECTED, exported_symbols=["public_score"],
                    llvm_library=self.root / "untrusted.dll", link_boundary=self.boundary, workspace_root=self.root)

    def test_final_link_rechecks_trusted_tool_path(self):
        changed = copy.deepcopy(self.boundary)
        changed["protected_link_argv"][0] = str(self.root / "unreviewed.exe")
        record = completed(changed["protected_link_argv"], self.build)
        with self.assertRaises(cs.SymbolMappingError):
            cs.verify_final_link(changed, record, fake_pe(), b"EXPORTS\npublic_score\n", workspace_root=self.root)

    def test_closed_link_paths_are_exact_not_only_build_contained(self):
        for key, replacement in (("raw_ir", self.build / "other/module.raw.ll"),
                                 ("input_ir", self.build / "other/module.before.ll")):
            changed = copy.deepcopy(self.boundary)
            changed[key]["path"] = str(replacement)
            with self.subTest(key=key), self.assertRaises(cs.SymbolMappingError):
                self.verify(changed)
        changed = copy.deepcopy(self.boundary)
        changed["build_directory"] = str(self.build / ".." / "build")
        with self.assertRaises(cs.SymbolMappingError):
            self.verify(changed)


@unittest.skipUnless(os.environ.get("ANTIREA_CPP_SYMBOL_LLVM") == "1", "explicit pinned LLVM-C parser opt-in")
class ActualLLVMRemapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cpp-symbol-unit-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.build = self.root / ".runs/build"
        self.build.mkdir(parents=True)
        config = json.loads((Path(__file__).resolve().parents[1] / ".tools/kagura-toolchain.json").read_text())
        self.library = Path(config["llvm_root"]) / "bin/LLVM-C.dll"
        self.tools = write_toolchain(self.root, actual_config=config)

    def boundary(self, ir=IR, exports=None):
        return make_boundary(self.root, self.build, self.tools, ir=ir, exports=exports)

    def remap(self, ir=IR, selected=None, exports=None):
        exports = exports or ["public_score"]
        return cs.remap_protection_symbols(ir, selected_symbols=selected or SELECTED,
            exported_symbols=exports, llvm_library=self.library, link_boundary=self.boundary(ir, exports), workspace_root=self.root)

    def test_external_namespace_overloads_and_calls_round_trip(self):
        mapped, manifest = self.remap()
        self.assertEqual(manifest["status"], "mapped_not_protected")
        self.assertEqual(manifest["functions"]["public_score"]["protected_symbol"], "public_score")
        self.assertNotEqual(manifest["functions"][WIDE]["protected_symbol"], manifest["functions"][NARROW]["protected_symbol"])
        for source in (WIDE, NARROW):
            name = manifest["functions"][source]["protected_symbol"]
            self.assertEqual(mapped.count(("@" + name + "(").encode()), 2)
            self.assertNotIn(("@\"" + source + "\"(").encode(), mapped)
        again, other = self.remap(selected=list(reversed(SELECTED)))
        self.assertEqual(mapped, again)
        self.assertEqual(manifest["functions"], other["functions"])

    def test_global_name_collision_fails_instead_of_llvm_suffixing(self):
        ir = IR + b"@antirea_cpp_fn_collision = internal global i64 1\n"
        with patch.object(cs, "_mapped_name", return_value="antirea_cpp_fn_collision"), self.assertRaisesRegex(cs.SymbolMappingError, "collides"):
            self.remap(ir)

    def test_linked_private_name_suffix_and_allowlist_metacharacters_stay_distinct(self):
        # These are legal quoted LLVM names, not claimed compiler spellings.
        # Suffixes left by llvm-link are exact source IDs; no demangling merge.
        names = ["?mix@core@@YA_K_K0@Z", "?mix@core@@YA_K_K0@Z.1,leaf*"]
        ir = IR.replace(NARROW.encode(), names[1].encode())
        ir = ir.replace(b"define i32 @", b"define internal i32 @", 1)
        mapped, manifest = self.remap(ir, selected=[*names, "public_score"])
        targets = [manifest["functions"][name]["protected_symbol"] for name in names]
        self.assertEqual(len(set(targets)), 2)
        for source, target in zip(names, targets):
            self.assertTrue(cs.PLAIN.fullmatch(target))
            self.assertEqual(manifest["functions"][source]["source_symbol_bytes_hex"], source.encode().hex())
            self.assertIn(("@" + target + "(").encode(), mapped)

    def test_address_taken_callback_global_and_alias_rejected(self):
        for suffix in (b'@callback = global ptr @"?mix@core@@YA_K_K0@Z"\n',
                       b'@other = alias i64 (i64, i64), ptr @"?mix@core@@YA_K_K0@Z"\n'):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                self.remap(IR + suffix)

    def test_non_c_convention_comdat_or_unreviewed_export_rejected(self):
        mutations = [IR.replace(b'define i64 @"?mix', b'define fastcc i64 @"?mix', 1).replace(
                         b'call i64 @"?mix', b'call fastcc i64 @"?mix', 1),
                     IR.replace(b'define i64 @"?mix', b'define dllexport i64 @"?mix', 1),
                     b'$group = comdat any\n' + IR.replace(b'i64 %a, i64 %b) {', b'i64 %a, i64 %b) comdat($group) {', 1)]
        for ir in mutations:
            with self.subTest(ir=ir[:120]), self.assertRaises(ValueError):
                self.remap(ir)

    def test_closed_link_cannot_omit_tu_or_add_extra_object(self):
        for mutation in ("omit", "extra", "changed"):
            boundary = self.boundary()
            if mutation == "omit":
                boundary["source_modules"].pop()
            elif mutation == "extra":
                boundary["protected_link_argv"].insert(-2, "unreviewed.obj")
            else:
                Path(boundary["source_modules"][0]["path"]).write_bytes(b"changed")
            with self.subTest(mutation=mutation), self.assertRaises(cs.SymbolMappingError):
                cs.remap_protection_symbols(IR, selected_symbols=SELECTED, exported_symbols=["public_score"],
                                             llvm_library=self.library, link_boundary=boundary, workspace_root=self.root)

if __name__ == "__main__":
    unittest.main()
