"""Stdlib-unittest tests for the PRODUCTION C# app-integration engine.

These tests import the ACTUAL production modules ``antirea.csharp_app_integration``
and ``antirea.csharp_transform`` (never a ``.runs`` candidate, never a
monkeypatched trusted-name import). They are launched by the owned OUTER bounded
wrapper ``.runs/orca-wave6-csharp-tests/driver/outer_run.py`` (clean allowlisted
env, private TEMP, fresh run dir, real workspace STOP as cancel_file, Windows Job
+ parent-exit receipt). Inner dotnet / cold children run through
``antirea.process.run_logged``.

Coverage policy (phase20 engine_tests):

* Behaviours already present in the adopted candidate baseline run and PASS
  against the real production bytes now (transform lexer/selector/byte
  preservation, trusted-module keyset + drift-before-import, workspace resolve,
  plan JSON round trip / tamper, case contract, cold-process saved-plan transform
  drift rejection).
* Phase20 seams the engine worker is still landing (the ``trusted_inputs``
  keyword on run_integration/validate/build_and_compare; the app-engine lexical
  5-name reserved guard) are CAPABILITY-GATED: when absent the test skips with a
  reason that names the pending adoption gate -- it is never a silent pass.
* The dotnet-executing differential and the ``trusted_inputs`` behavioural
  pre/post drift check are gated on dotnet + the pinned producer fixtures.

Results produced here are against INTERMEDIATE, unfrozen production bytes; the
authoritative run is root's post-source-freeze full suite. Defense strength and
performance remain not_evaluated.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import csharp_application_test_support as support  # noqa: E402

cai = support.cai
ct = support.ct
GATE = "production antirea.csharp_app_integration/csharp_transform not importable: %s" % support.IMPORT_ERROR

EXEC_CASES = [
    {"label": "v(0,0)", "kind": "value", "args": [0, 0], "expect": {"returncode": 0, "stdout_is_integer": True}},
    {"label": "v(7,3)", "kind": "value", "args": [7, 3], "expect": {"returncode": 0, "stdout_is_integer": True}},
    {"label": "v(min,4)", "kind": "value", "args": [-2147483648, 4], "expect": {"returncode": 0, "stdout_is_integer": True}},
    {"label": "v(max,4)", "kind": "value", "args": [2147483647, 4], "expect": {"returncode": 0, "stdout_is_integer": True}},
    {"label": "e(usage)", "kind": "exception", "args": [], "expect": {"returncode": 2}},
    {"label": "e(nonnumeric)", "kind": "exception", "args": ["abc", "3"], "expect": {"exception": "System.FormatException"}},
    {"label": "e(overflow)", "kind": "exception", "args": ["9999999999", "3"], "expect": {"exception": "System.OverflowException"}},
]


def _tmp():
    base = support.OUT_BASE / "pytmp"
    base.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(dir=str(base), ignore_cleanup_errors=True)


# =========================================================================== #
# (A) Production import, API version, exact trusted-module keyset.
# =========================================================================== #
@unittest.skipUnless(support.MODULES_AVAILABLE, GATE)
class ProductionImportAndKeysetTests(unittest.TestCase):
    def test_imported_from_production_package_not_candidate(self):
        # The module must resolve to antirea/ under the repo root, not .runs.
        p = Path(cai.__file__).resolve()
        self.assertEqual(p, (support.ROOT / "antirea" / "csharp_app_integration.py").resolve())
        self.assertNotIn(".runs", p.parts, "engine must not be a .runs candidate")
        pt = Path(ct.__file__).resolve()
        self.assertEqual(pt, (support.ROOT / "antirea" / "csharp_transform.py").resolve())

    def test_trusted_transform_name_and_complete_engine_keyset(self):
        self.assertEqual(cai.TRUSTED_TRANSFORM_MODULE, "antirea.csharp_transform")
        expected = {"antirea.csharp_app_integration", "antirea.csharp_transform",
                    "antirea.dotnet_frontend", "antirea.source_validate",
                    "antirea.bindings", "antirea.process"}
        self.assertEqual(set(cai.TRUSTED_ENGINE_MODULES), expected)
        # The keyset must INCLUDE the integration engine itself and the transform.
        self.assertIn("antirea.csharp_app_integration", cai.TRUSTED_ENGINE_MODULES)
        self.assertIn("antirea.csharp_transform", cai.TRUSTED_ENGINE_MODULES)

    def test_engine_binding_is_exactly_the_trusted_set(self):
        binding = cai._engine_binding()
        self.assertEqual(set(binding), set(cai.TRUSTED_ENGINE_MODULES))
        for name, entry in binding.items():
            self.assertEqual(entry["module"], name)
            self.assertRegex(entry["sha256"], r"^[0-9a-f]{64}$")
            # Bound path must be the real in-package source (never a .runs candidate).
            self.assertNotIn(".runs", Path(entry["path"]).parts)

    def test_contract_advertises_serializable_plan_and_trusted_modules(self):
        c = cai.project_service_contract()
        self.assertEqual(c["trusted_modules"]["transform"], "antirea.csharp_transform")
        self.assertEqual(set(c["trusted_modules"]["engine"]), set(cai.TRUSTED_ENGINE_MODULES))
        self.assertTrue(c["serializable_plan"]["json_serializable"])
        self.assertIn("load", c["serializable_plan"]["round_trip_revalidated_at"])


# =========================================================================== #
# (B) Transform lexer boundaries + byte/newline preservation (pure, no dotnet).
# =========================================================================== #
@unittest.skipUnless(support.MODULES_AVAILABLE, GATE)
class TransformLexerBoundaryTests(unittest.TestCase):
    def test_mask_noncode_preserves_length_and_newlines(self):
        src = 'int a=1; // c\nstring s="x\\ny"; /* b */\nchar q=\'z\';\r\nint k=2;\n'
        masked = ct.mask_noncode(src)
        self.assertEqual(len(masked), len(src), "mask must preserve byte offsets")
        self.assertEqual([i for i, c in enumerate(src) if c in "\r\n"],
                         [i for i, c in enumerate(masked) if c in "\r\n"],
                         "newline positions must be identical")
        # Code outside literals/comments is preserved verbatim.
        self.assertTrue(masked.startswith("int a=1; "))
        self.assertIn("int k=2;", masked)
        # The comment/string/char contents are blanked (not present in masked).
        self.assertNotIn("x", masked[:src.index("int k")])

    def test_mask_noncode_rejects_unsupported_lexical_constructs(self):
        for bad in ('var s=$"{x}";', 'var s="""raw""";', 'var s="unterminated\n',
                    "var c='\n", "/* never closed"):
            with self.assertRaises(ct.CsTransformError):
                ct.mask_noncode(bad)

    def test_mask_noncode_rejects_preprocessor_directives(self):
        for bad in ("#if DEBUG\nint x=1;\n#endif\n", "#define FOO\n", "  #else\n"):
            with self.assertRaises(ct.CsTransformError):
                ct.mask_noncode(bad)

    def test_supported_interop_constants_are_fixed(self):
        self.assertEqual(ct.SUPPORTED_INTEROP_TYPE, "global::NativeCore")
        self.assertEqual(ct.SUPPORTED_NATIVE_LIBRARY, "antirea_contract")
        self.assertEqual(tuple(ct.GENERATED_FILES), ("NativeCore.cs", "ProtectedBootstrap.cs"))
        self.assertEqual(ct.CS_ALIAS, {"int": "Int32", "uint": "UInt32", "long": "Int64", "ulong": "UInt64"})

    def test_limitations_do_not_broaden_language_claims(self):
        text = " ".join(ct.LIMITATIONS).lower()
        self.assertIsInstance(ct.LIMITATIONS, list)
        self.assertTrue(ct.LIMITATIONS)
        # The transform must keep its honest unsupported-scope disclosures.
        self.assertIn("generation is not compilation", text)
        self.assertIn("no", text)
        self.assertTrue("whole-.net" in text or "nativeaot" in text,
                        "must disclaim whole-language/AOT support")


# =========================================================================== #
# (C) Transform selector contract (supported boundaries only).
# =========================================================================== #
@unittest.skipUnless(support.MODULES_AVAILABLE, GATE)
class TransformSelectorContractTests(unittest.TestCase):
    def _sel(self, **over):
        s = {"type": "N.T", "name": "M", "parameters": ["int"], "export": "m"}
        s.update(over)
        return s

    def test_accepts_wellformed_keyword_scalar_selector(self):
        out = ct.validate_selectors([self._sel()])
        self.assertEqual(out[0]["export"], "m")
        self.assertEqual(out[0]["canonical_params"], ["Int32"])

    def test_rejects_bcl_alias_type_names(self):
        for bad_param in ("Int32", "System.Int32", "Int64"):
            with self.assertRaises(ct.CsTransformError):
                ct.validate_selectors([self._sel(parameters=[bad_param])])

    def test_rejects_bad_name_export_and_reserved_prefix(self):
        with self.assertRaises(ct.CsTransformError):
            ct.validate_selectors([self._sel(name="1bad")])
        with self.assertRaises(ct.CsTransformError):
            ct.validate_selectors([self._sel(export="has-dash")])
        for reserved in ("kagura_x", "antirea_x", "ar_x"):
            with self.assertRaises(ct.CsTransformError):
                ct.validate_selectors([self._sel(export=reserved)])

    def test_rejects_wrong_keyset_counts_and_duplicates(self):
        with self.assertRaises(ct.CsTransformError):
            ct.validate_selectors([{"type": "N.T", "name": "M", "parameters": ["int"]}])  # missing export
        with self.assertRaises(ct.CsTransformError):
            ct.validate_selectors([])                                       # empty
        with self.assertRaises(ct.CsTransformError):
            ct.validate_selectors([self._sel() for _ in range(17)])         # > 16
        with self.assertRaises(ct.CsTransformError):
            ct.validate_selectors([self._sel(parameters=["int"] * 9)])      # > 8 params
        with self.assertRaises(ct.CsTransformError):
            ct.validate_selectors([self._sel(), self._sel()])               # dup selector+export
        with self.assertRaises(ct.CsTransformError):
            ct.validate_selectors([self._sel(), self._sel(name="M2", export="m")])  # dup export


# =========================================================================== #
# (D) Transform byte preservation + fresh-output / collision / reserved guards.
# =========================================================================== #
@unittest.skipUnless(support.MODULES_AVAILABLE, GATE)
class TransformBytePreservationTests(unittest.TestCase):
    def test_unselected_source_is_byte_for_byte_preserved(self):
        with _tmp() as td:
            app = Path(td) / "app"
            fx = support.write_transform_app(app)
            out = Path(td) / "out"
            result = ct.write_integration(fx["app_dir"], fx["spec_path"], fx["contract_path"], out)
            self.assertEqual(result["report"]["status"], "integrated_unvalidated")
            # The UNSELECTED file is copied byte-for-byte into the deployable bundle.
            depl_unsel = out / "deployable" / support.UNSELECTED_FILE
            self.assertEqual(depl_unsel.read_bytes(), fx["unselected_raw"])
            self.assertNotIn(support.UNSELECTED_FILE, result["report"]["rewritten_files"])
            # The SELECTED file is rewritten (its body replaced) -> bytes differ.
            depl_sel = out / "deployable" / support.SELECTED_FILE
            self.assertIn(support.SELECTED_FILE, result["report"]["rewritten_files"])
            self.assertNotEqual(depl_sel.read_bytes(), fx["selected_raw"])
            # Generated interop files are present.
            for gen in ct.GENERATED_FILES:
                self.assertTrue((out / "deployable" / gen).is_file())

    def test_rejects_unsupported_interop_type_and_native_library(self):
        with _tmp() as td:
            sources = {"A.cs": support.SELECTED_SRC}
            sel = [{"type": "N.T", "name": "M", "parameters": ["int"], "export": "m"}]
            contract = {"schema_version": 1, "library_name": "antirea_contract",
                        "functions": [{"name": "m", "return_type": "i32",
                                       "parameters": [{"name": "a0", "type": "i32"}]}]}
            with self.assertRaises(ct.CsTransformError):
                ct.integrate(sources, sel, contract, interop_type="global::Other")
            with self.assertRaises(ct.CsTransformError):
                ct.integrate(sources, sel, contract, native_library="other_lib")
            with self.assertRaises(ct.CsTransformError):
                ct.integrate({"NativeCore.cs": "x"}, sel, contract)      # collides w/ generated file

    def test_write_integration_requires_fresh_out(self):
        with _tmp() as td:
            app = Path(td) / "app"
            fx = support.write_transform_app(app)
            out = Path(td) / "out"
            out.mkdir()
            with self.assertRaises(ct.CsTransformError):
                ct.write_integration(fx["app_dir"], fx["spec_path"], fx["contract_path"], out)


# =========================================================================== #
# (E) Lexical reserved/received-name guard, BEFORE any stat/read/hash.
# Synthetic NON-EXISTENT paths only: no real private data is ever opened.
# =========================================================================== #
@unittest.skipUnless(support.MODULES_AVAILABLE, GATE)
class ReservedNameLexicalGuardTests(unittest.TestCase):
    SYNTH_ROOT = r"C:\__synthetic_w6_root__"

    def test_transform_reserved_set_is_the_phase20_five(self):
        self.assertEqual(support.transform_reserved_components(), support.EXPECTED_RESERVED)

    def test_transform_guard_rejects_each_reserved_component_lexically(self):
        # The guard is pure string inspection: the path need not exist, so no
        # stat/read/hash/traversal happens before rejection.
        for name in support.EXPECTED_RESERVED:
            synthetic = os.path.join(self.SYNTH_ROOT, name, "nonexistent_child.cs")
            self.assertFalse(os.path.exists(synthetic))
            with self.assertRaises(ct.CsTransformError):
                ct._reserved_guard(synthetic)

    def test_transform_guard_allows_clean_paths(self):
        ct._reserved_guard(os.path.join(self.SYNTH_ROOT, "app", "A.cs"))  # must not raise

    def test_write_integration_rejects_reserved_input_path_before_read(self):
        # A reserved component anywhere in a consumed path is rejected lexically;
        # the (non-existent) file is never read.
        with _tmp() as td:
            app = Path(td) / "app"
            fx = support.write_transform_app(app)
            out = Path(td) / "env.setting" / "out"     # reserved component in the OUTPUT path
            with self.assertRaises(ct.CsTransformError):
                ct.write_integration(fx["app_dir"], fx["spec_path"], fx["contract_path"], out)

    def test_app_engine_reserved_guard_covers_phase20_five(self):
        # REQUIRED production guard: the app engine must expose a pure-lexical
        # 5-name reserved guard. Its absence is a failure, not a skip.
        self.assertEqual(frozenset(cai.RESERVED_PATH_COMPONENTS), support.EXPECTED_RESERVED)
        self.assertTrue(callable(getattr(cai, "_reserved_guard", None)))
        for name in support.EXPECTED_RESERVED:
            synthetic = os.path.join(self.SYNTH_ROOT, name, "nonexistent_child.json")
            self.assertFalse(os.path.exists(synthetic))
            with self.assertRaises(cai.ProducerIntegrateError):
                cai._reserved_guard(synthetic)
        cai._reserved_guard(os.path.join(self.SYNTH_ROOT, "clean", "x.json"))  # must not raise


# =========================================================================== #
# (F) Trusted-name-only transform load + drift-before-import (in-process).
# =========================================================================== #
@unittest.skipUnless(support.MODULES_AVAILABLE, GATE)
class TrustedLoadAndDriftTests(unittest.TestCase):
    def test_load_transform_accepts_only_the_trusted_name(self):
        mod = cai._load_transform(cai.TRUSTED_TRANSFORM_MODULE)
        self.assertTrue(hasattr(mod, "write_integration"))
        for bad in ("antirea.dotnet_frontend", "csharp_transform", "antirea.csharp_app_integration",
                    str(support.ROOT / ".runs/orca-wave5-csharp/candidate/antirea/csharp_transform.py"),
                    ".runs/orca-wave1-csharp-v2/candidate/antirea/csharp_integrate.py"):
            with self.assertRaises(cai.ProducerIntegrateError):
                cai._load_transform(bad)

    def test_load_transform_rejects_hash_drift_before_import(self):
        with self.assertRaises(cai.ProducerIntegrateError) as cm:
            cai._load_transform(cai.TRUSTED_TRANSFORM_MODULE, expected_sha256="0" * 64)
        self.assertIn("changed since it was bound", str(cm.exception))

    def test_module_source_identity_rejects_untrusted_and_is_nonexecuting(self):
        with self.assertRaises(cai.ProducerIntegrateError):
            cai._module_source_identity("antirea.not_a_trusted_module")
        ident = cai._module_source_identity("antirea.csharp_transform")
        self.assertEqual(ident["module"], "antirea.csharp_transform")
        self.assertEqual(ident["sha256"], support.sha_file(support.ROOT / "antirea" / "csharp_transform.py"))


# =========================================================================== #
# (G) WorkspacePlan.resolve: transform name, fresh out under .runs, workspace id.
# =========================================================================== #
@unittest.skipUnless(support.MODULES_AVAILABLE, GATE)
class WorkspacePlanResolveTests(unittest.TestCase):
    def test_rejects_arbitrary_transform_module(self):
        with _tmp() as td:
            with self.assertRaises(cai.ProducerIntegrateError) as cm:
                cai.WorkspacePlan.resolve(workspace_root=support.ROOT, out_dir=Path(td) / "o",
                                          transform_module=str(support.ROOT / "evil.py"))
            self.assertIn("trusted owned module", str(cm.exception))

    def test_requires_out_dir_under_runs_and_fresh(self):
        outside = support.ROOT / "zzz_w6_outside_runs_scratch"
        self.assertFalse(outside.is_relative_to(support.ROOT / ".runs"))
        with self.assertRaises(cai.ProducerIntegrateError):
            cai.WorkspacePlan.resolve(workspace_root=support.ROOT, out_dir=outside)
        self.assertFalse(outside.exists(), "resolve must not create a rejected dir")
        with _tmp() as td:
            existing = Path(td) / "already"
            existing.mkdir()
            with self.assertRaises(cai.ProducerIntegrateError):
                cai.WorkspacePlan.resolve(workspace_root=support.ROOT, out_dir=existing)

    def test_requires_antirea_package_in_workspace_root(self):
        with _tmp() as td:
            fake_ws = Path(td) / "ws"
            (fake_ws / ".runs").mkdir(parents=True)
            with self.assertRaises(cai.ProducerIntegrateError):
                cai.WorkspacePlan.resolve(workspace_root=fake_ws, out_dir=fake_ws / ".runs" / "o")

    def test_resolve_binds_real_stop_marker(self):
        with _tmp() as td:
            ws = cai.WorkspacePlan.resolve(workspace_root=support.ROOT, out_dir=Path(td) / "o")
            expected_stop = os.path.abspath(str(support.ROOT / ".runs" / "defense-loop" / "STOP"))
            self.assertEqual(os.path.normcase(os.path.abspath(str(ws.stop_file))),
                             os.path.normcase(expected_stop))
            self.assertEqual(ws.transform_module, cai.TRUSTED_TRANSFORM_MODULE)


# =========================================================================== #
# (H) Plan JSON round trip + every tamper / alias / keyset vector (no dotnet).
# =========================================================================== #
@unittest.skipUnless(support.MODULES_AVAILABLE, GATE)
class PlanSerializeTamperTests(unittest.TestCase):
    def setUp(self):
        self._td = _tmp()
        td = self._td.__enter__()
        self.plan = support.synthetic_plan(
            app_dir=os.path.join(td, "app"),
            spec_path=os.path.join(td, "app", "integration.json"),
            out_dir=os.path.join(str(support.OUT_BASE), "plan_out"))

    def tearDown(self):
        self._td.__exit__(None, None, None)

    def test_round_trip_preserves_fingerprint(self):
        reloaded = cai.load_plan(cai.serialize_plan(self.plan))
        self.assertEqual(reloaded["plan_fingerprint"], self.plan["plan_fingerprint"])
        self.assertEqual(reloaded["status"], "planned")
        # Serialized form is canonical JSON text (no live handles).
        txt = cai.serialize_plan(self.plan)
        self.assertIsInstance(txt, str)
        json.loads(txt)

    def test_self_binding_present_in_plan(self):
        self.assertEqual(set(self.plan["engine_binding"]), set(cai.TRUSTED_ENGINE_MODULES))
        self.assertIn("antirea.csharp_app_integration", self.plan["engine_binding"])
        self.assertIn("antirea.csharp_transform", self.plan["engine_binding"])

    def test_tampered_fingerprint_rejected(self):
        bad = support.clone(self.plan)
        bad["plan_fingerprint"] = "0" * 64
        with self.assertRaises(cai.StagingIntegrityError):
            cai.load_plan(bad)

    def test_tampered_body_rejected(self):
        bad = support.clone(self.plan)
        bad["selectors"][0]["name"] = "Other"      # bound content changed, fingerprint stale
        with self.assertRaises(cai.StagingIntegrityError):
            cai.load_plan(bad)

    def test_untrusted_transform_module_rejected(self):
        bad = support.clone(self.plan)
        bad["transform_module"] = "evil.module"
        with self.assertRaises(cai.ProducerIntegrateError):
            cai.load_plan(bad)

    def test_execution_alias_tamper_rejected(self):
        bad = support.clone(self.plan)
        bad["app_dir"] = bad["app_dir"] + "_swapped"    # unbound alias disagrees with snapshot
        with self.assertRaises(cai.StagingIntegrityError):
            cai.load_plan(bad)
        bad2 = support.clone(self.plan)
        bad2["integration_spec_path"] = bad2["integration_spec_path"] + "_swapped"
        with self.assertRaises(cai.StagingIntegrityError):
            cai.load_plan(bad2)

    def test_dropped_or_extra_engine_binding_key_rejected(self):
        dropped = support.clone(self.plan)
        dropped["engine_binding"].pop("antirea.process")
        with self.assertRaises(cai.ProducerIntegrateError):
            cai.load_plan(dropped)
        extra = support.clone(self.plan)
        extra["engine_binding"]["antirea.sneaky"] = {"module": "antirea.sneaky",
                                                      "path": "x", "sha256": "f" * 64}
        with self.assertRaises(cai.ProducerIntegrateError):
            cai.load_plan(extra)

    def test_schema_version_and_missing_key_rejected(self):
        badv = support.clone(self.plan)
        badv["schema_version"] = 999
        with self.assertRaises(cai.ProducerIntegrateError):
            cai.load_plan(badv)
        for key in ("pinned", "engine_binding", "workspace", "plan_fingerprint"):
            miss = support.clone(self.plan)
            miss.pop(key)
            with self.assertRaises(cai.ProducerIntegrateError):
                cai.load_plan(miss)

    def test_serialize_refuses_inconsistent_fingerprint(self):
        bad = support.clone(self.plan)
        bad["plan_fingerprint"] = "0" * 64
        with self.assertRaises(cai.ProducerIntegrateError):
            cai.serialize_plan(bad)

    def test_workspace_transform_module_must_be_trusted(self):
        bad = support.clone(self.plan)
        bad["workspace"]["transform_module"] = "evil"
        with self.assertRaises(cai.ProducerIntegrateError):
            cai.load_plan(bad)

    def test_self_binding_present_in_plan_has_workspace_identity(self):
        wi = self.plan["workspace_identity"]
        self.assertEqual(wi["transform_module"], cai.TRUSTED_TRANSFORM_MODULE)
        self.assertEqual(wi["stop_relative"], cai.STOP_RELATIVE)

    def test_stop_relative_tamper_rejected(self):
        bad = support.clone(self.plan)
        bad["workspace_identity"]["stop_relative"] = ".runs/elsewhere/STOP"
        with self.assertRaises(cai.StagingIntegrityError):
            cai.load_plan(bad)

    def test_stop_file_alias_tamper_rejected(self):
        # A tampered serialized STOP alias must not redirect the authoritative
        # cancel file; STOP is rederived from the bound root.
        bad = support.clone(self.plan)
        bad["workspace"]["stop_file"] = r"C:\evil\STOP"
        with self.assertRaises(cai.StagingIntegrityError):
            cai.load_plan(bad)
        bad2 = support.clone(self.plan)
        bad2["workspace_identity"]["stop_file"] = r"C:\evil\STOP"
        with self.assertRaises(cai.StagingIntegrityError):
            cai.load_plan(bad2)

    def test_workspace_root_alias_mismatch_rejected(self):
        bad = support.clone(self.plan)
        bad["workspace"]["workspace_root"] = r"C:\some\other\root"
        with self.assertRaises(cai.StagingIntegrityError):
            cai.load_plan(bad)

    def test_workspace_identity_root_tamper_changes_fingerprint(self):
        # Rebinding the workspace_root in the identity (without re-signing) must
        # fail the fingerprint recompute -- the identity is fingerprint-bound.
        bad = support.clone(self.plan)
        bad["workspace_identity"]["workspace_root"] = os.path.abspath(
            os.path.join(str(support.ROOT), "antirea"))
        bad["workspace_identity"]["stop_file"] = str(
            cai._stop_path(bad["workspace_identity"]["workspace_root"]))
        bad["workspace"]["workspace_root"] = bad["workspace_identity"]["workspace_root"]
        bad["workspace"]["stop_file"] = bad["workspace_identity"]["stop_file"]
        with self.assertRaises(cai.StagingIntegrityError):
            cai.load_plan(bad)


# =========================================================================== #
# (I) Explicit case contract (validated before any execution).
# =========================================================================== #
@unittest.skipUnless(support.MODULES_AVAILABLE, GATE)
class CaseContractTests(unittest.TestCase):
    def test_empty_or_non_list_rejected(self):
        for bad in ([], None, {}, "x"):
            with self.assertRaises(cai.ProducerIntegrateError):
                cai.validate_cases(bad)

    def test_missing_and_extra_keys_rejected(self):
        with self.assertRaises(cai.ProducerIntegrateError):
            cai.validate_cases([{"label": "a", "kind": "value"}])            # missing args
        with self.assertRaises(cai.ProducerIntegrateError):
            cai.validate_cases([{"label": "a", "kind": "value", "args": [], "extra": 1}])

    def test_bad_kind_args_and_bool_rejected(self):
        with self.assertRaises(cai.ProducerIntegrateError):
            cai.validate_cases([{"label": "a", "kind": "weird", "args": []}])
        with self.assertRaises(cai.ProducerIntegrateError):
            cai.validate_cases([{"label": "a", "kind": "value", "args": [True]}])  # bool rejected

    def test_duplicate_label_rejected(self):
        with self.assertRaises(cai.ProducerIntegrateError):
            cai.validate_cases([{"label": "d", "kind": "value", "args": [1]},
                                {"label": "d", "kind": "value", "args": [2]}])

    def test_bad_expect_rejected(self):
        with self.assertRaises(cai.ProducerIntegrateError):
            cai.validate_cases([{"label": "a", "kind": "value", "args": [1],
                                 "expect": {"exception": "System.FooException"}}])  # exc w/ value kind
        with self.assertRaises(cai.ProducerIntegrateError):
            cai.validate_cases([{"label": "a", "kind": "exception", "args": [],
                                 "expect": {"exception": "NotAToken"}}])

    def test_valid_cases_normalized_and_expectation_eval(self):
        out = cai.validate_cases([{"label": "ok", "kind": "value", "args": [7, "x"],
                                   "expect": {"returncode": 0, "stdout_is_integer": True}}])
        self.assertEqual(out[0]["args"], ["7", "x"])            # stringified
        ev = cai._evaluate_expectation(out[0]["expect"], {"rc": 0, "exc": None, "stdout": "42"})
        self.assertTrue(ev["satisfied"])
        ev2 = cai._evaluate_expectation(out[0]["expect"], {"rc": 1, "exc": None, "stdout": "x"})
        self.assertFalse(ev2["satisfied"])


# =========================================================================== #
# (J) Cold-process saved-plan transform DRIFT rejection BEFORE import.
# Faithful: a synthetic temp "installed" antirea package (verbatim production
# engine bytes + a DRIFTED poison transform) is loaded in a FRESH python -I
# process via run_logged; the engine must reject the drifted transform by hash
# before importing it. Never mutates production; the poison is never executed.
# =========================================================================== #
@unittest.skipUnless(support.MODULES_AVAILABLE, GATE)
class ColdProcessSavedPlanDriftTests(unittest.TestCase):
    def _build_pkg(self, pkgroot: Path):
        import antirea.process as process  # noqa: F401 (for run_logged)
        pkg = pkgroot / "antirea"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text("", encoding="utf-8")   # light namespace shadow
        src_antirea = support.ROOT / "antirea"
        # Verbatim production copies so their bound hashes match (engine is the real one).
        for name in ("csharp_app_integration.py", "dotnet_frontend.py",
                     "source_validate.py", "bindings.py", "process.py"):
            (pkg / name).write_bytes((src_antirea / name).read_bytes())
        # DRIFTED poison transform: real bytes + a side effect that would fire ONLY
        # if the module were executed. A hash-before-import reject must prevent that.
        sentinel = pkgroot / "POISON_EXECUTED.sentinel"
        poison = (src_antirea / "csharp_transform.py").read_text(encoding="utf-8")
        poison += ("\n# --- w6 drift marker ---\n"
                   "import os as _os\n"
                   "open(_os.environ['ANTIREA_W6_SENTINEL'], 'w').write('poison executed')\n")
        (pkg / "csharp_transform.py").write_text(poison, encoding="utf-8")
        return sentinel

    def test_cold_process_rejects_drifted_transform_before_import(self):
        import antirea.process as process
        with _tmp() as td:
            tdp = Path(td)
            pkgroot = tdp / "pkg"
            sentinel = self._build_pkg(pkgroot)
            # The saved plan binds the REAL (repo) transform hash.
            plan = support.synthetic_plan(app_dir=str(tdp / "app"),
                                          spec_path=str(tdp / "app" / "integration.json"),
                                          out_dir=str(support.OUT_BASE / "cold_out"))
            bound_sha = plan["engine_binding"]["antirea.csharp_transform"]["sha256"]
            self.assertNotEqual(bound_sha, support.sha_file(pkgroot / "antirea" / "csharp_transform.py"),
                                "poison transform must differ from the bound hash")
            plan_path = tdp / "saved_plan.json"
            plan_path.write_text(cai.serialize_plan(plan), encoding="utf-8")
            verdict_path = tdp / "verdict.json"

            driver = tdp / "cold_driver.py"
            driver.write_text(_COLD_DRIVER, encoding="utf-8")

            out_dir = support.OUT_BASE / "run" / ("cold-%d" % os.getpid())
            out_dir.mkdir(parents=True, exist_ok=True)
            priv_tmp = out_dir / "_tmp"; priv_tmp.mkdir(exist_ok=True)
            priv_home = out_dir / "_home"; priv_home.mkdir(exist_ok=True)
            env = support.allowlisted_env(priv_tmp, priv_home)
            env["ANTIREA_W6_SENTINEL"] = str(sentinel)
            stop = support.real_stop_path()                     # real workspace STOP (existence-only)

            proc = process.run_logged(
                [sys.executable, "-I", "-B", str(driver), str(pkgroot),
                 str(plan_path), str(verdict_path)],
                out_dir, out_dir / "logs" / "cold-drift",
                timeout=120, env=env, cancel_file=stop)

            # Bounded-child receipt assertions.
            self.assertFalse(proc.get("timed_out"), proc)
            self.assertFalse(proc.get("cancelled"), proc)
            self.assertIsInstance(proc.get("returncode"), int)
            cleanup = proc.get("cleanup", {})
            self.assertTrue(cleanup.get("parent_exit_confirmed"), cleanup)
            if os.name == "nt":
                self.assertEqual(cleanup.get("status"), "assigned_job_empty", cleanup)
                self.assertTrue(cleanup.get("job_handle_closed"), cleanup)

            self.assertTrue(verdict_path.is_file(), Path(proc["stderr"]).read_text(errors="replace"))
            verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
            self.assertTrue(verdict["rejected"], verdict)
            self.assertIn("changed since it was bound", verdict["message"])
            self.assertFalse(verdict["transform_imported"], "drifted transform must NOT be imported")
            self.assertFalse(os.path.exists(sentinel), "poison transform body must never execute")
            self.assertEqual(proc.get("returncode"), 0, "cold driver reports clean rejection via rc 0")


# Cold driver source: fresh interpreter, synthetic pkg first on sys.path, load the
# saved plan, then refuse the drifted transform BEFORE importing it.
_COLD_DRIVER = r'''
import json, os, sys
pkgroot, plan_path, verdict_path = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, pkgroot)   # synthetic antirea shadow wins
verdict = {"rejected": False, "message": "", "transform_imported": None}
try:
    import antirea.csharp_app_integration as cai
    plan = cai.load_plan(open(plan_path, "r", encoding="utf-8").read())
    bound = plan["engine_binding"]["antirea.csharp_transform"]["sha256"]
    try:
        cai._load_transform(cai.TRUSTED_TRANSFORM_MODULE, expected_sha256=bound)
        verdict["message"] = "NOT REJECTED (bug)"
    except cai.ProducerIntegrateError as exc:
        verdict["rejected"] = True
        verdict["message"] = str(exc)
    verdict["transform_imported"] = "antirea.csharp_transform" in sys.modules
except Exception as exc:  # pragma: no cover
    verdict["message"] = "driver error: %r" % (exc,)
    verdict["transform_imported"] = "antirea.csharp_transform" in sys.modules
open(verdict_path, "w", encoding="utf-8").write(json.dumps(verdict))
sys.exit(0 if verdict["rejected"] and not verdict["transform_imported"] else 5)
'''


# =========================================================================== #
# (K) trusted_inputs seam (PENDING engine gate). Keyword contract + behaviour.
# =========================================================================== #
@unittest.skipUnless(support.MODULES_AVAILABLE, GATE)
class TrustedInputsSeamContractTests(unittest.TestCase):
    def test_trusted_inputs_is_keyword_on_all_three_seams(self):
        # REQUIRED seam: keyword-only trusted_inputs on all three entry points.
        import inspect
        for fn in ("run_integration", "validate", "build_and_compare"):
            params = inspect.signature(getattr(cai, fn)).parameters
            self.assertIn("trusted_inputs", params, fn)
            self.assertEqual(params["trusted_inputs"].kind, inspect.Parameter.KEYWORD_ONLY, fn)

    def test_trusted_inputs_record_shape_is_fail_closed(self):
        # Malformed records rejected WITHOUT touching disk (shape + lexical guard).
        norm = cai._normalize_trusted_inputs(None)
        self.assertEqual(norm, [])
        for bad in ("notalist", [{"path": "x"}],                       # non-list / missing sha
                    [{"path": "rel/path.cs", "sha256": "a" * 64}],     # not absolute
                    [{"path": os.path.abspath("x"), "sha256": "nothex"}],   # bad digest
                    [{"path": os.path.abspath("x"), "sha256": "A" * 64}]):  # not lowercase
            with self.assertRaises(cai.ProducerIntegrateError):
                cai._normalize_trusted_inputs(bad)

    def test_trusted_inputs_reserved_path_rejected_lexically(self):
        rec = [{"path": os.path.join(r"C:\__synthetic_w6_root__", "env.setting", "svc.py"),
                "sha256": "a" * 64}]
        with self.assertRaises(cai.ProducerIntegrateError):
            cai._normalize_trusted_inputs(rec)


@unittest.skipUnless(support.MODULES_AVAILABLE, GATE)
class TrustedInputsBehaviourTests(unittest.TestCase):
    @unittest.skipUnless(support.executed_fixtures_available(),
                         "environmental: needs installed dotnet SDK + pinned producer fixtures")
    def test_trusted_input_drift_is_rejected(self):
        with _tmp() as td:
            bound = Path(td) / "bound_input.txt"
            bound.write_text("original-bytes", encoding="utf-8")
            ws = cai.WorkspacePlan.resolve(workspace_root=support.ROOT, out_dir=Path(td) / "out")
            producer = cai.ProducerManifest.at(support.PRODUCER_REPORT)
            receipt = cai.ProtectedBuildReceipt.reused_from_report(
                support.PRODUCER_REPORT, workspace_root=support.ROOT)
            toolchain = cai.ToolchainSnapshot.discover(workspace_root=support.ROOT)
            # Deliberately WRONG sha256 -> must be rejected before/around children.
            drifted = [{"path": str(bound), "sha256": "0" * 64}]
            with self.assertRaises(cai.ProducerIntegrateError):
                cai.run_integration(producer, receipt, toolchain, ws, support.SAMPLE_APP,
                                    support.SAMPLE_APP / "integration.json",
                                    timeout_seconds=60, cases=EXEC_CASES,
                                    trusted_inputs=drifted)


# =========================================================================== #
# (L) dotnet-gated executed differential (original vs protected arm equivalence).
# =========================================================================== #
@unittest.skipUnless(support.MODULES_AVAILABLE, GATE)
class ExecutedEquivalenceTests(unittest.TestCase):
    @unittest.skipUnless(support.executed_fixtures_available(),
                         "PENDING gate: needs dotnet + pinned producer report + sample app")
    def test_run_integration_round_trip_original_equals_protected(self):
        with _tmp() as td:
            ws = cai.WorkspacePlan.resolve(workspace_root=support.ROOT, out_dir=Path(td) / "out")
            producer = cai.ProducerManifest.at(support.PRODUCER_REPORT)
            receipt = cai.ProtectedBuildReceipt.reused_from_report(
                support.PRODUCER_REPORT, workspace_root=support.ROOT)
            toolchain = cai.ToolchainSnapshot.discover(workspace_root=support.ROOT)
            report = cai.run_integration(producer, receipt, toolchain, ws, support.SAMPLE_APP,
                                         support.SAMPLE_APP / "integration.json",
                                         timeout_seconds=60, cases=EXEC_CASES,
                                         round_trip_plan=True, write_report=True)
            comp = report["comparison"]
            self.assertEqual(report["status"], "producer_bound_integration_passed", comp.get("comparisons"))
            self.assertFalse(report["fresh_protected_native_build"])     # reused, honest provenance
            self.assertIn("reused", report["producer_provenance"])
            self.assertTrue(report["plan_round_trip_through_json"])
            self.assertEqual(comp["original_values_sha256"], comp["protected_values_sha256"])
            self.assertTrue(comp["integrity_verified_before_and_after"])
            for cmd in comp["commands"]:
                self.assertFalse(cmd["timed_out"], cmd)
                self.assertFalse(cmd["cancelled"], cmd)
                if os.name == "nt":
                    self.assertEqual(cmd["cleanup_status"], "assigned_job_empty", cmd)
                    self.assertTrue(cmd["job_handle_closed"], cmd)


# =========================================================================== #
# (M) Production availability is REQUIRED (absence is a failure, not a skip).
# =========================================================================== #
class ProductionAvailabilityTests(unittest.TestCase):
    def test_production_modules_import(self):
        self.assertTrue(support.MODULES_AVAILABLE,
                        "REQUIRED production modules not importable: %s" % support.IMPORT_ERROR)


# =========================================================================== #
# (N) Bounded consumed-file helpers: reserved-first, nonlinked, regular, bounded
# BEFORE any read. Synthetic/mock paths only (gap #1).
# =========================================================================== #
@unittest.skipUnless(support.MODULES_AVAILABLE, GATE)
class BoundedHelperNegativeTests(unittest.TestCase):
    def test_hash_file_reserved_component_rejected_before_stat(self):
        for name in support.EXPECTED_RESERVED:
            synthetic = os.path.join(r"C:\__synthetic_w6_root__", name, "nonexistent.bin")
            self.assertFalse(os.path.exists(synthetic))
            with self.assertRaises(cai.ProducerIntegrateError):
                cai._hash_file(synthetic)
            with self.assertRaises(cai.ProducerIntegrateError):
                cai._guarded_regular_file(synthetic)

    def test_no_links_reserved_component_rejected_lexically(self):
        with self.assertRaises(cai.ProducerIntegrateError):
            cai._no_links(Path(r"C:\__synthetic_w6_root__\attackerfolder\x"))

    def test_nonregular_path_rejected(self):
        with _tmp() as td:
            d = Path(td) / "a_directory"
            d.mkdir()
            with self.assertRaises(cai.ProducerIntegrateError):
                cai._hash_file(d)                       # a directory is not a regular file

    def test_overlimit_file_rejected_before_full_read(self):
        with _tmp() as td:
            f = Path(td) / "big.bin"
            f.write_bytes(b"0123456789")                # 10 bytes
            with self.assertRaises(cai.ProducerIntegrateError) as cm:
                cai._hash_file(f, limit=5)
            self.assertIn("bounded read limit", str(cm.exception))
            with self.assertRaises(cai.ProducerIntegrateError):
                cai._read_bytes_bounded(f, limit=5)
            self.assertEqual(cai._hash_file(f, limit=10), support.sha_file(f))   # exactly at limit ok

    def test_read_bytes_bounded_rejects_oversize_not_truncate(self):
        # An over-limit input is REJECTED, never silently truncated to `limit`
        # bytes (the streamed byte count, not just the pre-stat, is the real bound).
        with _tmp() as td:
            f = Path(td) / "grow.bin"
            f.write_bytes(b"0123456789")               # 10 bytes
            with self.assertRaises(cai.ProducerIntegrateError):
                cai._read_bytes_bounded(f, limit=4)
            with self.assertRaises(cai.ProducerIntegrateError):
                cai._hash_file(f, limit=4)
            self.assertEqual(cai._read_bytes_bounded(f, limit=10), b"0123456789")   # whole content, no over-read

    @unittest.skipUnless(support.can_symlink(),
                         "environmental: symlink creation needs OS privilege on this host")
    def test_symlink_reparse_rejected(self):
        with _tmp() as td:
            target = Path(td) / "real.bin"
            target.write_bytes(b"real")
            link = Path(td) / "link.bin"
            os.symlink(target, link)
            with self.assertRaises(cai.ProducerIntegrateError):
                cai._hash_file(link)
            with self.assertRaises(cai.ProducerIntegrateError):
                cai._no_links(link)


# =========================================================================== #
# (O) Guard ordering: lexical reserved / no-link BEFORE other probes (gap #2).
# =========================================================================== #
@unittest.skipUnless(support.MODULES_AVAILABLE, GATE)
class GuardOrderingTests(unittest.TestCase):
    def test_workspace_resolve_reserved_out_dir_before_fresh_probe(self):
        # out_dir with a reserved component is rejected lexically, before out.exists.
        reserved_out = support.ROOT / ".runs" / "defense-loop" / "w6_out"
        with self.assertRaises(cai.ProducerIntegrateError) as cm:
            cai.WorkspacePlan.resolve(workspace_root=support.ROOT, out_dir=reserved_out)
        self.assertIn("reserved", str(cm.exception).lower())

    def test_workspace_resolve_reserved_root_before_antirea_probe(self):
        # A workspace_root carrying a reserved component is rejected lexically,
        # before the wr/antirea existence probe (which would otherwise differ).
        reserved_ws = os.path.join(r"C:\__synthetic_w6_root__", "attackerfolder", "ws")
        with self.assertRaises(cai.ProducerIntegrateError) as cm:
            cai.WorkspacePlan.resolve(workspace_root=reserved_ws,
                                      out_dir=os.path.join(reserved_ws, ".runs", "o"))
        self.assertIn("reserved", str(cm.exception).lower())

    def test_reverify_producer_reserved_path_before_is_file(self):
        # _reverify_producer_from_disk must guard the report path lexically before
        # any is_file/hash. A reserved, non-existent path raises the reserved error
        # (not a 'missing on disk' problem).
        pinned = {"report_path": os.path.join(r"C:\__synthetic_w6_root__",
                                              "defense-loop", "report.json")}
        with self.assertRaises(cai.ProducerIntegrateError) as cm:
            cai._reverify_producer_from_disk(pinned, workspace_root=support.ROOT)
        self.assertIn("reserved", str(cm.exception).lower())


# =========================================================================== #
# (P) Tree inventory: reserved child rejected BEFORE descent; bounded (gap #3).
# =========================================================================== #
@unittest.skipUnless(support.MODULES_AVAILABLE, GATE)
class TreeInventoryGuardTests(unittest.TestCase):
    def test_clean_tree_inventoried(self):
        with _tmp() as td:
            root = Path(td) / "tree"
            (root / "sub").mkdir(parents=True)
            (root / "a.txt").write_bytes(b"aa")
            (root / "sub" / "b.txt").write_bytes(b"bbb")
            inv = cai._tree_inventory(root)
            self.assertEqual(set(inv), {"a.txt", "sub/b.txt"})
            self.assertEqual(inv["a.txt"]["bytes"], 2)

    def test_reserved_child_rejected_before_descent(self):
        with _tmp() as td:
            root = Path(td) / "tree"
            reserved_child = root / "env.setting"
            reserved_child.mkdir(parents=True)
            (reserved_child / "secret_marker.bin").write_bytes(b"x")   # must never be read
            with self.assertRaises(cai.ProducerIntegrateError) as cm:
                cai._tree_inventory(root)
            self.assertIn("reserved", str(cm.exception).lower())

    @unittest.skipUnless(support.can_symlink(),
                         "environmental: symlink creation needs OS privilege on this host")
    def test_symlink_entry_in_tree_rejected(self):
        with _tmp() as td:
            root = Path(td) / "tree"
            root.mkdir(parents=True)
            target = Path(td) / "outside.bin"
            target.write_bytes(b"t")
            os.symlink(target, root / "link.bin")
            with self.assertRaises(cai.ProducerIntegrateError):
                cai._tree_inventory(root)


# =========================================================================== #
# (Q) Producer source locations: owned samples OK; outside / mismatch / overlap
# fail. Synthetic producer report; sample sources read-only (gap #4).
# =========================================================================== #
@unittest.skipUnless(support.MODULES_AVAILABLE, GATE)
class ProducerSourceLocationTests(unittest.TestCase):
    def test_source_under_owned_samples_is_accepted(self):
        sample_src = support.SAMPLE_CSHARP_APP / "Ops.cs"
        self.assertTrue(sample_src.is_file(), "expected owned sample source present")
        with _tmp() as td:
            rp = support.fake_producer_report(Path(td) / "producer", sources=[(sample_src, None)])
            pinned = cai.load_producer_report(rp, workspace_root=support.ROOT)
            self.assertIn("Ops.cs", pinned["producer_sources"])
            self.assertTrue(Path(pinned["producer_source_paths"]["Ops.cs"]).is_relative_to(
                support.ROOT / "samples"))

    def test_source_outside_workspace_rejected(self):
        # Synthetic absolute path NOT under the workspace root (never created): the
        # loader rejects it on the is_relative_to(root) check, before any read/hash.
        outside = r"C:\__w6_outside_synthetic__\External.cs"
        self.assertFalse(Path(outside).is_relative_to(support.ROOT))
        self.assertFalse(os.path.exists(outside))
        with _tmp() as td:
            rp = support.fake_producer_report(Path(td) / "producer",
                                              sources=[(outside, "0" * 64)])   # explicit sha, no hashing
            with self.assertRaises(cai.ProducerIntegrateError) as cm:
                cai.load_producer_report(rp, workspace_root=support.ROOT)
            self.assertIn("escapes the owned workspace", str(cm.exception))

    def test_source_hash_mismatch_rejected(self):
        sample_src = support.SAMPLE_CSHARP_APP / "Ops.cs"
        with _tmp() as td:
            rp = support.fake_producer_report(Path(td) / "producer",
                                              sources=[(sample_src, "0" * 64)])   # wrong claim
            with self.assertRaises(cai.ProducerIntegrateError) as cm:
                cai.load_producer_report(rp, workspace_root=support.ROOT)
            self.assertIn("differ from the report claim", str(cm.exception))

    def test_output_overlapping_source_rejected(self):
        with _tmp() as td:
            app = Path(td) / "app"
            app.mkdir()
            cai._reject_overlap(Path(td) / "fresh_out", app)            # disjoint: ok
            with self.assertRaises(cai.ProducerIntegrateError):
                cai._reject_overlap(app / "nested_out", app)           # out inside source
            with self.assertRaises(cai.ProducerIntegrateError):
                cai._reject_overlap(app.parent, app)                   # out contains source


# =========================================================================== #
# (R) Per-command cleanup + persisted receipt mapping (gap #6, executed).
# =========================================================================== #
@unittest.skipUnless(support.MODULES_AVAILABLE, GATE)
class CommandReceiptCleanupTests(unittest.TestCase):
    @unittest.skipUnless(support.executed_fixtures_available(),
                         "environmental: needs installed dotnet SDK + pinned producer fixtures")
    def test_every_command_has_full_cleanup_and_persisted_receipt(self):
        with _tmp() as td:
            ws = cai.WorkspacePlan.resolve(workspace_root=support.ROOT, out_dir=Path(td) / "out")
            producer = cai.ProducerManifest.at(support.PRODUCER_REPORT)
            receipt = cai.ProtectedBuildReceipt.reused_from_report(
                support.PRODUCER_REPORT, workspace_root=support.ROOT)
            toolchain = cai.ToolchainSnapshot.discover(workspace_root=support.ROOT)
            report = cai.run_integration(producer, receipt, toolchain, ws, support.SAMPLE_APP,
                                         support.SAMPLE_APP / "integration.json",
                                         timeout_seconds=60, cases=EXEC_CASES, write_report=True)
            commands = report["comparison"]["commands"]
            self.assertTrue(commands)
            for cmd in commands:
                self.assertTrue(cmd["clean_completion"], cmd.get("label"))
                self.assertIsInstance(cmd["pid"], int)
                self.assertTrue(Path(cmd["receipt_path"]).is_file(), cmd["receipt_path"])
                c = cmd["cleanup"]
                self.assertTrue(c.get("parent_exit_confirmed"))
                if os.name == "nt":
                    self.assertEqual(c.get("method"), "windows_job")
                    self.assertTrue(c.get("job_assigned"))
                    self.assertEqual(c.get("active_after"), 0)
                    self.assertEqual(c.get("status"), "assigned_job_empty")
                    self.assertTrue(c.get("job_handle_closed"))
                    self.assertEqual(c.get("parent_pid"), cmd["pid"])


# =========================================================================== #
# (S) runtimeconfig pin exposed for packaging (gap #7, executed).
# comparison.deployable_app.runtimeconfig {path, sha256, bytes}
# =========================================================================== #
@unittest.skipUnless(support.MODULES_AVAILABLE, GATE)
class RuntimeconfigExposureTests(unittest.TestCase):
    @unittest.skipUnless(support.executed_fixtures_available(),
                         "environmental: needs installed dotnet SDK + pinned producer fixtures")
    def test_deployable_app_runtimeconfig_is_pinned_and_exposed(self):
        with _tmp() as td:
            ws = cai.WorkspacePlan.resolve(workspace_root=support.ROOT, out_dir=Path(td) / "out")
            producer = cai.ProducerManifest.at(support.PRODUCER_REPORT)
            receipt = cai.ProtectedBuildReceipt.reused_from_report(
                support.PRODUCER_REPORT, workspace_root=support.ROOT)
            toolchain = cai.ToolchainSnapshot.discover(workspace_root=support.ROOT)
            report = cai.run_integration(producer, receipt, toolchain, ws, support.SAMPLE_APP,
                                         support.SAMPLE_APP / "integration.json",
                                         timeout_seconds=60, cases=EXEC_CASES, write_report=True)
            comp = report["comparison"]
            dep = comp["deployable_app"]
            rc = dep["runtimeconfig"]
            self.assertEqual(set(rc) >= {"path", "sha256", "bytes"}, True, rc)
            self.assertTrue(Path(rc["path"]).is_file(), rc["path"])
            self.assertEqual(support.sha_file(rc["path"]), rc["sha256"])
            self.assertEqual(Path(rc["path"]).stat().st_size, rc["bytes"])
            # Output + runtimeconfig pins rechecked around every child, and the
            # original arm's runtimeconfig is pinned the same way (gap #7 + followup).
            self.assertTrue(comp["output_pins_rechecked_around_every_child"])
            self.assertTrue(comp["runtimeconfig_pins_rechecked"])
            self.assertIn("deployable_app.runtimeconfig.json", comp["output_pins"])
            self.assertIn("original_app.runtimeconfig.json", comp["output_pins"])
            orc = comp["original_app"]["runtimeconfig"]
            self.assertEqual(set(orc) >= {"path", "sha256", "bytes"}, True, orc)
            self.assertEqual(support.sha_file(orc["path"]), orc["sha256"])
            # Explicit compiler identity verified and rechecked around compiler children.
            self.assertTrue(comp["compiler_pin_verified"])
            self.assertTrue(comp["compiler_rechecked_around_compiler_children"])


# =========================================================================== #
# (T) Route-control argv derived from an explicit success case; no hardcoded
# 7,3 or integer-stdout rule; missing eligible case fails before children (gap #5).
# =========================================================================== #
@unittest.skipUnless(support.MODULES_AVAILABLE, GATE)
class RouteControlDerivationTests(unittest.TestCase):
    @unittest.skipUnless(support.executed_fixtures_available(),
                         "environmental: needs installed dotnet SDK + pinned producer fixtures")
    def test_control_argv_derived_from_explicit_success_case(self):
        with _tmp() as td:
            ws = cai.WorkspacePlan.resolve(workspace_root=support.ROOT, out_dir=Path(td) / "out")
            producer = cai.ProducerManifest.at(support.PRODUCER_REPORT)
            receipt = cai.ProtectedBuildReceipt.reused_from_report(
                support.PRODUCER_REPORT, workspace_root=support.ROOT)
            toolchain = cai.ToolchainSnapshot.discover(workspace_root=support.ROOT)
            report = cai.run_integration(producer, receipt, toolchain, ws, support.SAMPLE_APP,
                                         support.SAMPLE_APP / "integration.json",
                                         timeout_seconds=60, cases=support.ROUTE_CONTROL_CASES,
                                         write_report=True)
            comp = report["comparison"]
            self.assertEqual(report["status"], "producer_bound_integration_passed", comp.get("comparisons"))
            self.assertTrue(comp["route_proof_ok"])
            self.assertTrue(comp["route_proofs"])
            # The gating control argv is DERIVED from the eligible returncode==0 value
            # case ctl(4,2) and reused for both negative controls -- NOT a hardcoded
            # ['7','3'] and no integer-stdout restriction (ctl's expect omits it).
            for proof in comp["route_proofs"]:
                self.assertEqual(proof["control_args"], ["4", "2"], proof)
                self.assertEqual(proof["control_case"], "ctl(4,2)", proof)
                self.assertTrue(proof["control_succeeded"], proof)

    @unittest.skipUnless(support.executed_fixtures_available(),
                         "environmental: needs installed dotnet SDK + pinned producer fixtures")
    def test_missing_eligible_success_case_fails_before_children(self):
        only_negative = [{"label": "e(nonnumeric)", "kind": "exception", "args": ["abc", "3"],
                          "expect": {"exception": "System.FormatException"}}]
        with _tmp() as td:
            ws = cai.WorkspacePlan.resolve(workspace_root=support.ROOT, out_dir=Path(td) / "out")
            producer = cai.ProducerManifest.at(support.PRODUCER_REPORT)
            receipt = cai.ProtectedBuildReceipt.reused_from_report(
                support.PRODUCER_REPORT, workspace_root=support.ROOT)
            toolchain = cai.ToolchainSnapshot.discover(workspace_root=support.ROOT)
            with self.assertRaises(cai.ProducerIntegrateError):
                cai.run_integration(producer, receipt, toolchain, ws, support.SAMPLE_APP,
                                    support.SAMPLE_APP / "integration.json",
                                    timeout_seconds=60, cases=only_negative, write_report=False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
