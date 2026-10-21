"""Cross-seam adversarial regression tests for the Phase 21 JVM application
source-integrate route, authored by the Phase 21 *audit* lane.

WHAT CHANGED (root corrective, 2026-10-20)
===========================================
Root does NOT accept missing-fixture / capability-import skips as implemented
cross-seam coverage, and the samples will NEVER ship ``.class`` /
``producer_report.json`` / ``integration.json`` artifacts. This module therefore:

* HARD-imports the landed production engine (``antirea.jvm_app_integration``) and
  service (``antirea.jvm_application``) at module load. A missing production
  import FAILS (ImportError aborts the module) -- it is never skipped.
* Exercises the real landed validators/seams with SELF-CONTAINED synthetic JVM
  class bytes (``_synth_classfile``), TEMP pinned producer fixtures built on disk,
  and a CONCRETE MOCKED engine object for the service's engine-API seam. No source
  text is grepped; behaviour is driven through the real functions.
* Has exactly ONE optional gate, the explicit opt-in ``ANTIREA_RUN_JVM_APP_E2E``
  (a real compiler/target end-to-end run), which stays OFF here. Every other test
  runs unconditionally.
* Contains a single honest landing-gate test for the not-yet-landed facade lane
  (``antirea.jvm_facade``): it hard-imports and FAILS while the module is absent,
  converting to real coverage the moment the facade lane lands. The audit
  worker_done reports facade behavioural coverage as the remaining incomplete work.

EXECUTION
=========
PURE / NO COMPILER OR TARGET. These tests invoke no ``javac``/``java``/
``kotlinc``/native builder/child process. They are run by the audit lane through
the OUTER bounded ``antirea.process.run_logged`` wrapper
(``.runs/phase21-audit/run_focused.py``: clean allowlisted env, private TEMP,
fresh run dir, real ``.runs/defense-loop/STOP`` cancel-file, Windows Job
empty/closed/parent-exit receipt, source/tool pins before+after). Root's
post-freeze full suite remains the authoritative run. Sampled equivalence is NOT
REA resistance, performance, or whole-language support.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import tempfile
import types
import unittest
from pathlib import Path

# -- HARD production imports: a missing module FAILS the suite, never skips. --
from antirea import jvm_app_integration as E   # landed engine (loaders/validators/staging/exec)
from antirea import jvm_application as S        # landed public service binding
from antirea import jvm_facade as F             # landed facade (pure parse/generate/check)
from antirea import jvm_frontend                # producer seam (descriptor/ABI)
from antirea import bindings                    # generator seam

REPO_ROOT = Path(__file__).resolve().parents[1]
RUN_E2E = os.environ.get("ANTIREA_RUN_JVM_APP_E2E") == "1"


def _tmp():
    base = REPO_ROOT / ".runs" / "phase21-audit" / "pytmp"
    base.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(dir=str(base), ignore_cleanup_errors=True)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- #
# Self-contained synthetic JVM classfile bytes (no compiler). Builds a
# structurally valid class (magic, version 52.0, dynamic constant pool,
# ACC_PUBLIC|ACC_SUPER, Object superclass, zero fields) with an optional list of
# methods. Accepted by both jvm_frontend.parse_class (strict Object-only, no
# fields) and jvm_facade._read_class, so it drives the real producer core
# inventory AND the facade application/inspection seams with no toolchain.
# --------------------------------------------------------------------------- #
def _synth_classfile(internal_name: str = "sample/App",
                     super_name: str = "java/lang/Object", *, methods=()) -> bytes:
    cp = []                       # 1-based category-1 constant pool entries
    interned = {}

    def utf8(s: str) -> int:
        if ("u", s) in interned:
            return interned[("u", s)]
        b = s.encode("utf-8")
        cp.append(struct.pack(">BH", 1, len(b)) + b)
        interned[("u", s)] = len(cp)
        return len(cp)

    def klass(internal: str) -> int:
        if ("c", internal) in interned:
            return interned[("c", internal)]
        ni = utf8(internal)
        cp.append(struct.pack(">BH", 7, ni))
        interned[("c", internal)] = len(cp)
        return len(cp)

    this_i, super_i = klass(internal_name), klass(super_name)
    code_utf = utf8("Code") if any(m.get("code") is not None for m in methods) else None
    method_section = b""
    for m in methods:
        ni, di = utf8(m["name"]), utf8(m["descriptor"])
        attrs, acount = b"", 0
        if m.get("code") is not None:
            code = m["code"]
            payload = (struct.pack(">HHI", m.get("max_stack", 2), m.get("max_locals", 2), len(code))
                       + code + struct.pack(">HH", 0, 0))   # no exception table, no nested attrs
            attrs = struct.pack(">HI", code_utf, len(payload)) + payload
            acount = 1
        method_section += struct.pack(">HHHH", m.get("access", 0x0009), ni, di, acount) + attrs

    out = struct.pack(">IHH", 0xCAFEBABE, 0, 52)      # magic, minor=0, major=52 (Java 8)
    out += struct.pack(">H", len(cp) + 1) + b"".join(cp)
    out += struct.pack(">H", 0x0021)                  # ACC_PUBLIC|ACC_SUPER
    out += struct.pack(">HH", this_i, super_i)
    out += struct.pack(">H", 0)                       # interfaces
    out += struct.pack(">H", 0)                       # fields
    out += struct.pack(">H", len(methods)) + method_section
    out += struct.pack(">H", 0)                       # class attributes
    return out


def _synth_core_class() -> bytes:
    # sample/Core with `public static int fold(int)` whose body is iload_0; ireturn
    # (0x1a, 0xac) -- a real root method the facade core inventory requires.
    return _synth_classfile("sample/Core", methods=[
        {"name": "fold", "descriptor": "(I)I", "access": 0x0009,
         "code": b"\x1a\xac", "max_stack": 1, "max_locals": 1}])


class SyntheticClassfileSanityTests(unittest.TestCase):
    def test_synth_classfile_valid_and_parseable(self):
        data = _synth_classfile("sample/App")
        self.assertEqual(data[:4], b"\xca\xfe\xba\xbe")
        self.assertEqual(struct.unpack(">H", data[6:8])[0], 52)
        # The method-bearing core must survive jvm_frontend's strict parser and
        # expose exactly the fold(I)I root.
        parsed = jvm_frontend.parse_class(_synth_core_class())
        self.assertEqual(parsed["class"], "sample/Core")
        self.assertEqual([(m["name"], m["descriptor"]) for m in parsed["methods"]], [("fold", "(I)I")])


# =========================================================================== #
# (A) ENGINE validators (landed) -- application contract cases + argv + control.
# =========================================================================== #
class EngineCaseContractTests(unittest.TestCase):
    GOOD = [{"label": "ok", "args": ["7", "3"], "expect": {"returncode": 0, "stdout": "42\n"}}]

    def test_valid_cases_normalized(self):
        out = E.validate_cases(self.GOOD)
        self.assertEqual(out, self.GOOD)

    def test_rejects_non_list_and_empty_and_overlong(self):
        for bad in (None, {}, [], [self.GOOD[0]] * (E.MAX_CASES + 1)):
            with self.assertRaises(E.JvmIntegrateError):
                E.validate_cases(bad)

    def test_rejects_wrong_case_keyset_and_duplicate_label(self):
        with self.assertRaises(E.JvmIntegrateError):
            E.validate_cases([{"label": "a", "args": [], "expect": {"returncode": 0, "stdout": ""}, "x": 1}])
        dup = [dict(self.GOOD[0]), dict(self.GOOD[0])]
        with self.assertRaises(E.JvmIntegrateError):
            E.validate_cases(dup)

    def test_rejects_too_many_args_and_control_characters(self):
        with self.assertRaises(E.JvmIntegrateError):
            E.validate_cases([{"label": "a", "args": ["x"] * (E.MAX_CASE_ARGS + 1),
                               "expect": {"returncode": 0, "stdout": ""}}])
        with self.assertRaises(E.JvmIntegrateError):
            E.validate_cases([{"label": "a", "args": ["a\x00b"], "expect": {"returncode": 0, "stdout": ""}}])

    def test_expect_must_be_exactly_returncode_and_stdout_no_stderr_or_stack(self):
        # Coordinator case 7 / audit R9: stdout+exit only; NO stderr/stack key may
        # ride an equivalence claim.
        for expect in ({"returncode": 0}, {"stdout": "x\n"},
                       {"returncode": 0, "stdout": "x\n", "stderr": "trace"},
                       {"returncode": 0, "stdout": "x\n", "exception": "java.lang.Error"}):
            with self.assertRaises(E.JvmIntegrateError):
                E.validate_cases([{"label": "a", "args": [], "expect": expect}])

    def test_rejects_bad_returncode_range_and_stdout_control(self):
        with self.assertRaises(E.JvmIntegrateError):
            E.validate_cases([{"label": "a", "args": [], "expect": {"returncode": 256, "stdout": ""}}])
        with self.assertRaises(E.JvmIntegrateError):
            E.validate_cases([{"label": "a", "args": [], "expect": {"returncode": True, "stdout": ""}}])
        with self.assertRaises(E.JvmIntegrateError):
            E.validate_cases([{"label": "a", "args": [], "expect": {"returncode": 0, "stdout": "\x07"}}])

    def test_check_argv_string_bounds(self):
        self.assertEqual(E._check_argv_string("abc", "w"), "abc")
        self.assertEqual(E._check_argv_string(7, "w"), "7")           # int accepted->str
        with self.assertRaises(E.JvmIntegrateError):
            E._check_argv_string(True, "w")
        with self.assertRaises(E.JvmIntegrateError):
            E._check_argv_string("a" * (E.MAX_ARG_LEN + 1), "w")
        with self.assertRaises(E.JvmIntegrateError):
            E._check_argv_string("a\x00", "w")

    def test_select_control_case_requires_a_success_case(self):
        # Audit R3: the missing-core / missing-adapter negative controls need a
        # success (rc==0) control chosen BEFORE any child runs.
        good = E.validate_cases(self.GOOD)
        self.assertEqual(E._select_control_case(good)["label"], "ok")
        only_fail = E.validate_cases([{"label": "f", "args": [], "expect": {"returncode": 2, "stdout": ""}}])
        with self.assertRaises(E.JvmIntegrateError):
            E._select_control_case(only_fail)


class EngineSpecAndContractLoaderTests(unittest.TestCase):
    def _project(self, d: Path, language="java"):
        suffix = ".java" if language == "java" else ".kt"
        proj = d / "proj"
        proj.mkdir()
        (proj / ("Core" + suffix)).write_text("// core\n", encoding="utf-8")
        (proj / ("App" + suffix)).write_text("// app\n", encoding="utf-8")
        pinned = {"language": language, "project_root": str(proj),
                  "core_sources": [str(proj / ("Core" + suffix))]}
        return proj, pinned

    def _spec(self, proj: Path, body: dict) -> Path:
        p = proj / "spec.json"
        p.write_text(json.dumps(body), encoding="utf-8")
        return p

    def test_spec_accepts_wellformed_java(self):
        with _tmp() as d:
            root = Path(d)
            proj, pinned = self._project(root)
            spec = self._spec(proj, {"schema_version": 1, "kind": E.SPEC_KIND, "language": "java",
                                     "application_sources": ["App.java"], "main_class": "sample.App"})
            got = E.load_integration_spec(spec, workspace_root=root, pinned=pinned)
            self.assertEqual(got["main_class"], "sample.App")
            self.assertEqual(got["application_sources"][0]["relative"], "App.java")

    def test_spec_rejects_wrong_keyset_kind_and_language_mismatch(self):
        with _tmp() as d:
            root = Path(d)
            proj, pinned = self._project(root)
            for body in (
                {"schema_version": 1, "kind": E.SPEC_KIND, "language": "java",
                 "application_sources": ["App.java"], "main_class": "sample.App", "extra": 1},
                {"schema_version": 1, "kind": "wrong", "language": "java",
                 "application_sources": ["App.java"], "main_class": "sample.App"},
                {"schema_version": 1, "kind": E.SPEC_KIND, "language": "kotlin",
                 "application_sources": ["App.java"], "main_class": "sample.App"}):
                with self.assertRaises(E.JvmIntegrateError):
                    E.load_integration_spec(self._spec(proj, body), workspace_root=root, pinned=pinned)

    def test_spec_rejects_core_overlap_traversal_and_wrong_suffix(self):
        with _tmp() as d:
            root = Path(d)
            proj, pinned = self._project(root)
            # overlap with a protected core source
            with self.assertRaises(E.JvmIntegrateError):
                E.load_integration_spec(self._spec(proj, {"schema_version": 1, "kind": E.SPEC_KIND,
                    "language": "java", "application_sources": ["Core.java"], "main_class": "sample.App"}),
                    workspace_root=root, pinned=pinned)
            # parent traversal
            with self.assertRaises(E.JvmIntegrateError):
                E.load_integration_spec(self._spec(proj, {"schema_version": 1, "kind": E.SPEC_KIND,
                    "language": "java", "application_sources": ["../App.java"], "main_class": "sample.App"}),
                    workspace_root=root, pinned=pinned)
            # wrong suffix
            with self.assertRaises(E.JvmIntegrateError):
                E.load_integration_spec(self._spec(proj, {"schema_version": 1, "kind": E.SPEC_KIND,
                    "language": "java", "application_sources": ["App.kt"], "main_class": "sample.App"}),
                    workspace_root=root, pinned=pinned)

    def test_application_contract_loader_roundtrip_and_rejection(self):
        with _tmp() as d:
            root = Path(d)
            good = {"schema_version": 1, "kind": E.CONTRACT_KIND,
                    "cases": [{"label": "ok", "args": ["1"], "expect": {"returncode": 0, "stdout": "1\n"}}]}
            p = root / "contract.json"
            p.write_text(json.dumps(good), encoding="utf-8")
            loaded = E.load_application_contract(p, workspace_root=root)
            self.assertEqual(loaded["cases"][0]["label"], "ok")
            bad = root / "bad.json"
            bad.write_text(json.dumps({"schema_version": 1, "kind": "nope", "cases": good["cases"]}), encoding="utf-8")
            with self.assertRaises(E.JvmIntegrateError):
                E.load_application_contract(bad, workspace_root=root)


class EngineProducerBindingTests(unittest.TestCase):
    """Build a TEMP pinned producer fixture on disk and drive load_producer_report
    for real: the report's claimed hashes are CLAIMS; the on-disk bytes are the
    evidence (audit R5: no silent repin, fail closed on drift/escape)."""

    @staticmethod
    def _fixture(root: Path, *, protected_bytes=b"PROT", baseline_bytes=b"BASE",
                 protected_sha=None, backend=E.PRODUCER_BACKEND, status=E.PRODUCER_OK_STATUS):
        build = root / ".runs" / "prod"
        build.mkdir(parents=True)
        proj = root / "proj"
        proj.mkdir()
        (proj / "Core.java").write_text("// core\n", encoding="utf-8")
        (build / "protected.dll").write_bytes(protected_bytes)
        (build / "baseline.dll").write_bytes(baseline_bytes)
        core_cls = build / "sample" / "Core.class"
        core_cls.parent.mkdir(parents=True)
        core_bytes = _synth_core_class()
        core_cls.write_bytes(core_bytes)
        contract = {"schema_version": 1, "library_name": "core_lib",
                    "functions": [{"name": "fold", "return_type": "i32",
                                   "parameters": [{"name": "a0", "type": "i32"}]}]}
        contract_bytes = json.dumps(contract).encode("utf-8")
        (build / "contract.json").write_bytes(contract_bytes)
        base_sha = _sha256_bytes(baseline_bytes)
        prot_sha = protected_sha or _sha256_bytes(protected_bytes)
        # Native sub-report (origin + VM coverage) that the engine re-reads and
        # cross-checks: it lives beside the DLLs and names the same artifact shas,
        # selected_functions covering the lowered method exports, and VM evidence.
        native_coverage = {"selected_functions": ["fold"], "functions": ["fold"],
                           "original_vm": {"opcodes": 2}, "final_vm": {"opcodes": 2}}
        native_report = {"schema_version": 1, "status": E.PRODUCER_OK_STATUS,
                         "artifacts": {"baseline": {"sha256": base_sha}, "protected": {"sha256": prot_sha}},
                         "coverage": native_coverage}
        nr_bytes = json.dumps(native_report).encode("utf-8")
        (build / "native-report.json").write_bytes(nr_bytes)
        report = {
            "schema_version": 1, "backend": backend, "status": status, "language": "java",
            "artifacts": {
                "baseline": {"path": str(build / "baseline.dll"), "sha256": base_sha},
                "protected": {"path": str(build / "protected.dll"), "sha256": prot_sha}},
            "project": {"name": "core", "language": "java", "project_root": str(proj),
                        "sources": [str(proj / "Core.java")],
                        "methods": [{"class": "sample.Core", "name": "fold",
                                     "descriptor": "(I)I", "export": "fold"}],
                        "functions": ["fold"]},
            "methods": [{"class": "sample/Core", "name": "fold", "descriptor": "(I)I",
                         "export": "fold", "is_root": True}],
            "contract": contract, "contract_path": str(build / "contract.json"),
            "frontend_artifact_hashes": {"contract.json": _sha256_bytes(contract_bytes)},
            "native_report": str(build / "native-report.json"),
            "native_report_sha256": _sha256_bytes(nr_bytes),
            "original_classes": {str(core_cls): _sha256_bytes(core_bytes)},
            "coverage": {**native_coverage, "exported_functions": ["fold"]},
        }
        rp = build / "report.json"
        rp.write_text(json.dumps(report), encoding="utf-8")
        return rp

    def test_binds_valid_producer_report(self):
        with _tmp() as d:
            root = Path(d)
            rp = self._fixture(root)
            pinned = E.load_producer_report(rp, workspace_root=root)
            self.assertEqual(pinned["backend"], E.PRODUCER_BACKEND)
            self.assertEqual(pinned["language"], "java")
            self.assertEqual(pinned["native_library"], "core_lib")
            self.assertTrue(pinned["protected"]["sha256"])
            self.assertEqual(len(pinned["original_classes"]), 1)
            # _facade_producer now returns the FULL re-hashed producer report.
            fp = E._facade_producer(pinned)
            self.assertEqual(fp["schema_version"], 1)
            self.assertIn("original_classes", fp)
            self.assertEqual(fp["contract"]["library_name"], "core_lib")

    def test_rejects_wrong_backend_and_status(self):
        with _tmp() as d:
            root = Path(d)
            with self.assertRaises(E.JvmIntegrateError):
                E.load_producer_report(self._fixture(root, backend="dotnet_il_native"), workspace_root=root)
        with _tmp() as d2:
            root = Path(d2)
            with self.assertRaises(E.JvmIntegrateError):
                E.load_producer_report(self._fixture(root, status="passed"), workspace_root=root)

    def test_rejects_artifact_hash_mismatch_disk_is_evidence(self):
        with _tmp() as d:
            root = Path(d)
            rp = self._fixture(root, protected_sha="0" * 64)  # claimed != disk
            with self.assertRaises(E.JvmIntegrateError):
                E.load_producer_report(rp, workspace_root=root)

    def test_rejects_report_outside_runs(self):
        with _tmp() as d:
            root = Path(d)
            rp = self._fixture(root)
            # Point workspace_root elsewhere so the report is no longer under root/.runs.
            other = root / "proj"
            with self.assertRaises(E.JvmIntegrateError):
                E.load_producer_report(rp, workspace_root=other)


# =========================================================================== #
# (B) SERVICE validators (landed) -- spec/contract/path guards + engine seam.
# =========================================================================== #
class ServiceSpecValidatorTests(unittest.TestCase):
    def test_accepts_wellformed_and_rejects_keyset_and_nested_main(self):
        good = {"schema_version": 1, "kind": S.INTEGRATION_SPEC_KIND, "language": "java",
                "application_sources": ["App.java"], "main_class": "sample.App"}
        out = S._validate_integration_spec(good, plan_language="java")
        self.assertEqual(out["main_class"], "sample.App")
        with self.assertRaises(S.JvmApplicationError):   # language mismatch vs producer
            S._validate_integration_spec(good, plan_language="kotlin")
        nested = dict(good, main_class="sample.App$Inner")
        with self.assertRaises(S.JvmApplicationError):   # nested/$ identity rejected initially
            S._validate_integration_spec(nested, plan_language="java")
        extra = dict(good, extra=1)
        with self.assertRaises(S.JvmApplicationError):
            S._validate_integration_spec(extra, plan_language="java")

    def test_rejects_duplicate_and_wrong_suffix_sources(self):
        with self.assertRaises(S.JvmApplicationError):
            S._validate_integration_spec({"schema_version": 1, "kind": S.INTEGRATION_SPEC_KIND,
                "language": "java", "application_sources": ["App.java", "App.java"],
                "main_class": "sample.App"}, plan_language="java")
        with self.assertRaises(S.JvmApplicationError):
            S._validate_integration_spec({"schema_version": 1, "kind": S.INTEGRATION_SPEC_KIND,
                "language": "java", "application_sources": ["App.kt"], "main_class": "sample.App"},
                plan_language="java")


class ServiceContractValidatorTests(unittest.TestCase):
    def test_accepts_wellformed(self):
        cases = S._validate_app_contract({"schema_version": 1, "kind": S.APPLICATION_CONTRACT_KIND,
            "cases": [{"label": "ok", "args": ["1"], "expect": {"returncode": 0, "stdout": "1\n"}}]})
        self.assertEqual(cases[0]["label"], "ok")

    def test_expect_exactly_returncode_stdout_no_stderr_or_exception(self):
        # Audit R9: the service contract must not admit a stderr/stack-equivalence expectation.
        for expect in ({"returncode": 0, "stdout": "x", "stderr": "trace"},
                       {"returncode": 0, "stdout": "x", "exception": "E"},
                       {"returncode": 0}, {"stdout": "x"}):
            with self.assertRaises(S.JvmApplicationError):
                S._validate_app_contract({"schema_version": 1, "kind": S.APPLICATION_CONTRACT_KIND,
                    "cases": [{"label": "a", "args": [], "expect": expect}]})

    def test_rejects_control_args_nonstring_args_and_dup_labels(self):
        with self.assertRaises(S.JvmApplicationError):
            S._validate_app_contract({"schema_version": 1, "kind": S.APPLICATION_CONTRACT_KIND,
                "cases": [{"label": "a", "args": ["x\x00"], "expect": {"returncode": 0, "stdout": ""}}]})
        with self.assertRaises(S.JvmApplicationError):
            S._validate_app_contract({"schema_version": 1, "kind": S.APPLICATION_CONTRACT_KIND,
                "cases": [{"label": "a", "args": [5], "expect": {"returncode": 0, "stdout": ""}}]})
        with self.assertRaises(S.JvmApplicationError):
            S._validate_app_contract({"schema_version": 1, "kind": S.APPLICATION_CONTRACT_KIND,
                "cases": [{"label": "d", "args": [], "expect": {"returncode": 0, "stdout": ""}},
                          {"label": "d", "args": [], "expect": {"returncode": 1, "stdout": ""}}]})


class ServicePathGuardTests(unittest.TestCase):
    def test_reserved_and_relative_source_guards(self):
        for bad in ("/abs/App.java", "C:/App.java", "../App.java", "a/../App.java", "App.txt", "x\x00.java"):
            with self.assertRaises(S.JvmApplicationError):
                S._safe_relative_source(bad, "app source", ".java")
        self.assertEqual(S._safe_relative_source("pkg/App.java", "app source", ".java"), "pkg/App.java")
        for reserved in ("rea-analysis-reports/x.java", "attackerfolder/x.java", "defense-loop/x.java"):
            with self.assertRaises(S.JvmApplicationError):
                S._safe_relative_source(reserved, "app source", ".java")


class ServiceEngineApiSeamTests(unittest.TestCase):
    """Concrete MOCK of the engine object (no reliance on the real run_integration,
    which the engine lane has not landed yet). Audit R10: the service must require
    the full keyword seam incl. trusted_inputs."""

    def _engine_with(self, params_src: str):
        ns = {}
        exec("def run_integration(" + params_src + "): return {}", ns)  # noqa: S102 (test-local synthetic fn)
        return types.SimpleNamespace(run_integration=ns["run_integration"])

    def test_accepts_full_keyword_seam(self):
        eng = self._engine_with("*, producer_report_path=None, integration_spec_path=None, "
                                "application_contract_path=None, output_dir=None, workspace_root=None, "
                                "timeout_seconds=120, trusted_inputs=None")
        self.assertIsNone(S._require_engine_api(eng))

    def test_accepts_var_keyword(self):
        self.assertIsNone(S._require_engine_api(self._engine_with("**kw")))

    def test_rejects_missing_trusted_inputs_keyword(self):
        eng = self._engine_with("*, producer_report_path=None, integration_spec_path=None, "
                                "application_contract_path=None, output_dir=None, workspace_root=None, "
                                "timeout_seconds=120")
        with self.assertRaises(S.JvmApplicationError):
            S._require_engine_api(eng)


class ServiceDeploymentLeakTests(unittest.TestCase):
    """Audit R4/R6 + corrected same-name-facade logic: the facade legitimately
    KEEPS the original class identity/path, but the bundle must carry NO original
    BYTES (core/helper/baseline sha). Driven through the real service verifiers."""

    def test_forbidden_byte_shas_collects_core_helper_baseline(self):
        a, b, c = ("1" * 64, "2" * 64, "3" * 64)
        report = {"original_classes": {"x": a}, "reference_runner_hashes": {"y": b}}
        artifacts = {"baseline": {"sha256": c}, "protected": {"sha256": "4" * 64}}
        forbidden = S._forbidden_byte_shas(report, artifacts)
        self.assertEqual(forbidden, {a, b, c})
        self.assertNotIn("4" * 64, forbidden)   # protected core bytes are allowed

    def _deployment(self, **over):
        dep = {"path": "/x", "files": [{"relative_path": "sample/App.class",
                                        "sha256": "a" * 64, "bytes": 10}],
               "allowlist": ["sample/App.class"], "forbidden_absent": True,
               "main_class": "sample.App", "classpath_entries": ["."],
               "native_core": "core.dll", "jni_adapter": "adapter.dll"}
        dep.update(over)
        return {"deployment": dep}

    def test_inventory_structural_rejections_before_disk(self):
        base_args = dict(engine_out=Path("/x"), artifacts={}, expected_native_sha="a" * 64, report={})
        # no deployment block
        with self.assertRaises(S.JvmApplicationError):
            S._inventory_bundle({}, **base_args)
        # missing forbidden_absent assertion
        with self.assertRaises(S.JvmApplicationError):
            S._inventory_bundle(self._deployment(forbidden_absent=False), **base_args)
        # nested/$ main_class
        with self.assertRaises(S.JvmApplicationError):
            S._inventory_bundle(self._deployment(main_class="sample.App$X"), **base_args)
        # allowlist disagrees with file manifest
        with self.assertRaises(S.JvmApplicationError):
            S._inventory_bundle(self._deployment(allowlist=["other.class"]), **base_args)
        # non-allowlisted suffix
        with self.assertRaises(S.JvmApplicationError):
            S._inventory_bundle(self._deployment(
                files=[{"relative_path": "App.txt", "sha256": "a" * 64, "bytes": 1}],
                allowlist=["App.txt"]), **base_args)
        # malformed classpath_entries
        with self.assertRaises(S.JvmApplicationError):
            S._inventory_bundle(self._deployment(classpath_entries=[]), **base_args)


class ServiceEngineReportAuthenticationTests(unittest.TestCase):
    """Audit R5/R9: a pass must rest on a GENUINE persisted engine report whose
    bytes equal the returned dict, with honest observed original-vs-protected
    cases (not a bare flag), reuse flag False, and the pinned status token."""

    def _report(self, root: Path, *, tamper=None):
        prot_sha, base_sha, adapter_sha = ("a" * 64, "b" * 64, "c" * 64)
        report_path = root / "src_report.json"
        report_path.write_text("{}", encoding="utf-8")
        report_sha = _sha256_bytes(report_path.read_bytes())
        cases = [{"label": "ok", "args": ["1"], "expect": {"returncode": 0, "stdout": "1\n"}}]
        comparison = {"status": S.ENGINE_COMPARISON_PASSED, "total_cases": 1,
                      "cases": [{"label": "ok", "args": ["1"], "expect": {"returncode": 0, "stdout": "1\n"},
                                 "baseline": {"returncode": 0, "stdout": "1\n"},
                                 "protected": {"returncode": 0, "stdout": "1\n"}, "match": True}]}
        for flag in S._COMPARISON_PASS_FLAGS:
            comparison[flag] = True
        engine_report = {
            "status": S.ENGINE_STATUS_PASSED, "language": "java",
            "producer": {"backend": S.PRODUCER_BACKEND, "report_path": str(report_path),
                         "report_sha256": report_sha,
                         "artifacts": {"protected": {"sha256": prot_sha}, "baseline": {"sha256": base_sha}}},
            "staging": {"native_core_sha256": prot_sha, "jni_adapter": "adapter.dll",
                        "jni_adapter_sha256": adapter_sha},
            "comparison": comparison,
            "trusted_inputs_verification": {"verified": True, "declared_count": 3},
            "fresh_protected_native_build": False,
        }
        if tamper:
            tamper(engine_report)
        erp = root / "engine" / "integration.json"
        erp.parent.mkdir(parents=True)
        erp.write_text(json.dumps(engine_report), encoding="utf-8")
        artifacts = {"protected": {"sha256": prot_sha}, "baseline": {"sha256": base_sha}}
        return engine_report, erp, report_path, report_sha, artifacts, cases

    def _verify(self, engine_report, erp, report_path, report_sha, artifacts, cases):
        return S._verify_engine_report(engine_report, erp, report_path=report_path, report_sha=report_sha,
                                       artifacts=artifacts, cases=cases, language="java", declared_trusted_count=3)

    def test_authentic_on_honest_report(self):
        with _tmp() as d:
            res = self._verify(*self._report(Path(d)))
            self.assertTrue(res["authentic"], res.get("reason"))

    def test_rejects_fresh_build_flag_true(self):
        with _tmp() as d:
            er, erp, rp, rs, ar, cs = self._report(Path(d), tamper=lambda r: r.__setitem__("fresh_protected_native_build", True))
            res = self._verify(er, erp, rp, rs, ar, cs)
            self.assertFalse(res["authentic"])
            self.assertFalse(res["checks"]["fresh_protected_native_build_false"])

    def test_rejects_status_token_tamper(self):
        with _tmp() as d:
            er, erp, rp, rs, ar, cs = self._report(Path(d), tamper=lambda r: r.__setitem__("status", "ok"))
            res = self._verify(er, erp, rp, rs, ar, cs)
            self.assertFalse(res["authentic"])
            self.assertFalse(res["checks"]["engine_status_passed"])

    def test_rejects_when_persisted_differs_from_returned(self):
        with _tmp() as d:
            er, erp, rp, rs, ar, cs = self._report(Path(d))
            erp.write_text(json.dumps({"status": "different"}), encoding="utf-8")  # forged/stale on disk
            res = self._verify(er, erp, rp, rs, ar, cs)
            self.assertFalse(res["authentic"])
            self.assertFalse(res["checks"]["persisted_equals_returned"])

    def test_comparison_cases_detect_dishonest_observation(self):
        cases = [{"label": "ok", "args": ["1"], "expect": {"returncode": 0, "stdout": "1\n"}}]
        honest = {"cases": [{"label": "ok", "args": ["1"], "expect": {"returncode": 0, "stdout": "1\n"},
                             "baseline": {"returncode": 0, "stdout": "1\n"},
                             "protected": {"returncode": 0, "stdout": "1\n"}, "match": True}]}
        self.assertTrue(S._verify_comparison_cases(honest, cases))
        # protected observation disagrees with expected -> must be rejected
        bad = json.loads(json.dumps(honest))
        bad["cases"][0]["protected"]["stdout"] = "999\n"
        self.assertFalse(S._verify_comparison_cases(bad, cases))
        # a bare match flag with no per-arm observation -> rejected
        self.assertFalse(S._verify_comparison_cases({"cases": [{"label": "ok", "match": True}]}, cases))


class ServiceConstantsTests(unittest.TestCase):
    def test_public_status_token_and_suffix_allowlist(self):
        self.assertEqual(S.PUBLIC_STATUS_PASSED, "jvm_application_samples_passed")
        self.assertEqual(set(S.DEPLOY_SUFFIX_ALLOWLIST), {".class", ".dll", ".jar"})
        self.assertIn("jvm_application.py", S._SERVICE_MODULE_FILES)


# =========================================================================== #
# (C) PRODUCER + GENERATOR seams (landed) -- integer-only ABI the facade reuses.
# =========================================================================== #
class ProducerGeneratorSeamTests(unittest.TestCase):
    def test_descriptor_int_long_only(self):
        self.assertEqual(jvm_frontend.descriptor("(IJ)J"), (["I", "J"], "J"))
        for bad in ("(F)I", "([I)I", "()V", "(Ljava/lang/String;)I", "(IJIJIJIJI)I"):
            with self.assertRaises(jvm_frontend.JvmFrontendError):
                jvm_frontend.descriptor(bad)

    def test_bindings_java_nativecore_fail_closed_and_no_public_ctor(self):
        contract = bindings.validate_contract({"schema_version": 1, "library_name": "core_lib",
            "calling_convention": "cdecl",
            "functions": [{"name": "fold", "return_type": "i32",
                           "parameters": [{"name": "a0", "type": "i32"}]}]})
        java, jni, _kt = bindings._java(contract)
        self.assertIn("private NativeCore() {}", java)
        self.assertIn("isAbsolute()", java)            # absolute-path requirement
        self.assertIn("System.load(", java)
        self.assertIn("Java_NativeCore_nativeLoad", jni)


# =========================================================================== #
# (D) FACADE seams (landed) -- independent classfile reader, fail-closed
#     bootstrap, antirea.runtime repackage + JNI re-mangle, producer contract.
# =========================================================================== #
class FacadeApiAndReaderTests(unittest.TestCase):
    def test_api_surface(self):
        for name in ("generate_facades", "inspect_application_classes", "validate_facade_classes"):
            self.assertTrue(callable(getattr(F, name, None)), "facade must expose %s()" % name)

    def test_read_class_parses_synthetic_bytes(self):
        meta = F._read_class(_synth_classfile("sample/App"))
        self.assertEqual(meta["class_internal"], "sample/App")
        self.assertEqual(meta["super_internal"], "java/lang/Object")
        self.assertEqual(meta["methods"], [])
        self.assertEqual(meta["fields"], [])

    def test_read_class_rejects_bad_magic_and_version(self):
        with self.assertRaises(F.JvmFacadeError):
            F._read_class(b"\x00\x00\x00\x00rest")
        bad = bytearray(_synth_classfile("sample/App"))
        bad[6:8] = (0).to_bytes(2, "big")            # major 0 < 45
        with self.assertRaises(F.JvmFacadeError):
            F._read_class(bytes(bad))

    def test_bootstrap_source_is_fail_closed_no_fallback(self):
        # Audit R2 (addressed in landed facade): ensureReady loads once from the
        # absolute env paths and throws when either is unset/empty -- no fallback.
        src = F._bootstrap_source()
        self.assertIn("package antirea.runtime;", src)
        self.assertIn("ANTIREA_JNI_ADAPTER", src)
        self.assertIn("ANTIREA_NATIVE_CORE", src)
        self.assertIn("throw new IllegalStateException", src)
        self.assertIn("NativeCore.initialize(adapter, core)", src)
        self.assertIn("private ProtectedBootstrap() {}", src)

    def test_packaged_bindings_repackage_and_jni_remangle(self):
        # Audit R1 (addressed in landed facade): NativeCore is moved to
        # antirea.runtime and the JNI exports are re-mangled to the fqn, so the
        # loaded class and its native symbols stay in lockstep.
        contract = bindings.validate_contract({"schema_version": 1, "library_name": "core_lib",
            "calling_convention": "cdecl",
            "functions": [{"name": "fold", "return_type": "i32",
                           "parameters": [{"name": "a0", "type": "i32"}]}]})
        packaged_java, adapter, _header, _bridge, symbols = F._packaged_bindings(contract)
        self.assertTrue(packaged_java.startswith("package antirea.runtime;"))
        self.assertIn("Java_antirea_runtime_NativeCore_nativeLoad", adapter)
        self.assertIn("Java_antirea_runtime_NativeCore_nativeLoad", symbols)
        self.assertNotIn("Java_NativeCore_nativeLoad(", adapter)   # old default-package symbol gone


class FacadeProducerContractTests(unittest.TestCase):
    """Cross-seam producer contract. Audit finding X1 (engine<->facade producer
    shape) was OBSERVED earlier this session and has since been RECONCILED: the
    engine's ``_facade_producer`` now re-reads and re-hashes the FULL producer
    report from disk and hands it to the facade, which the facade's
    ``_validate_producer`` accepts. These tests LOCK that reconciled agreement and
    the fail-closed re-hash so a future drift between the lanes is caught."""

    def test_engine_facade_producer_agreement(self):
        # The exact object the engine hands the facade must pass the facade's own
        # producer validation (schema_version/status/backend/project/methods/
        # contract/original_classes). This is the reconciled shared schema.
        with _tmp() as d:
            root = Path(d)
            rp = EngineProducerBindingTests._fixture(root)
            pinned = E.load_producer_report(rp, workspace_root=root)
            producer = E._facade_producer(pinned)
            self.assertIsNone(F._validate_producer(producer))

    def test_facade_producer_fails_closed_on_report_drift(self):
        # _facade_producer re-hashes the pinned report; a post-pin mutation must
        # fail closed rather than hand the facade altered bytes.
        with _tmp() as d:
            root = Path(d)
            rp = EngineProducerBindingTests._fixture(root)
            pinned = E.load_producer_report(rp, workspace_root=root)
            rp.write_text(rp.read_text(encoding="utf-8") + " ", encoding="utf-8")
            with self.assertRaises(E.JvmIntegrateError):
                E._facade_producer(pinned)

    def test_facade_validate_producer_requires_full_report(self):
        # Facade-own contract (stable regardless of reconciliation): a dict missing
        # schema_version/status/backend/project is rejected.
        with self.assertRaises(F.JvmFacadeError):
            F._validate_producer({"language": "java", "methods": [],
                                  "original_classes": {"x.class": "a" * 64}})


_CLEAN_RECEIPT = {
    "pid": 4321, "returncode": 0, "timed_out": False, "cancelled": False,
    "error": None, "post_cleanup_wait_error": None,
    "cleanup": {"method": "windows_job", "job_assigned": True, "parent_pid": 4321,
                "parent_exit_confirmed": True, "active_after": 0,
                "status": "assigned_job_empty", "job_handle_closed": True},
}


# =========================================================================== #
# (E) Facade application-inspection + facade-validation (pure, synthetic bytes).
#     Exercises the landed facade's reserved-namespace / core-identity / clean /
#     exact-inventory checks against a real parsed producer core inventory --
#     NO compiler, per root's "these ARE pure-testable" note. Keys are the
#     canonical internal/name.class form the facade requires.
# =========================================================================== #
class FacadeInspectValidateTests(unittest.TestCase):
    def _producer(self, root: Path):
        rp = EngineProducerBindingTests._fixture(root)
        return E._facade_producer(E.load_producer_report(rp, workspace_root=root))

    def test_inspect_rejects_app_class_in_reserved_runtime_namespace(self):
        with _tmp() as d:
            root = Path(d)
            producer = self._producer(root)
            res = F.inspect_application_classes(
                {"antirea/runtime/Evil.class": _synth_classfile("antirea/runtime/Evil")}, producer)
            self.assertEqual(res["status"], "rejected")
            self.assertTrue(any(v.get("kind") == "reserved_namespace" for v in res["violations"]))

    def test_inspect_rejects_core_identity_reuse(self):
        with _tmp() as d:
            root = Path(d)
            producer = self._producer(root)
            res = F.inspect_application_classes(
                {"sample/Core.class": _synth_classfile("sample/Core")}, producer)
            self.assertEqual(res["status"], "rejected")
            self.assertTrue(any(v.get("kind") == "identity" for v in res["violations"]))

    def test_inspect_accepts_clean_ordinary_app_class(self):
        with _tmp() as d:
            root = Path(d)
            producer = self._producer(root)
            res = F.inspect_application_classes(
                {"sample/App.class": _synth_classfile("sample/App")}, producer)
            self.assertEqual(res["status"], "accepted", res.get("violations"))

    def test_validate_rejects_missing_expected_facade_and_runtime(self):
        # The expected facade class (same identity as the core) and both runtime
        # classes are absent here, so validation must reject -- exact inventory,
        # not a permissive pass.
        with _tmp() as d:
            root = Path(d)
            producer = self._producer(root)
            res = F.validate_facade_classes(
                {"sample/App.class": _synth_classfile("sample/App")}, producer)
            self.assertEqual(res["status"], "rejected")
            self.assertTrue(res["violations"])


# =========================================================================== #
# (F) Repaired-defect regressions (root early-review.md). The three draft
#     defects root flagged are now MANDATORY regressions (no expectedFailure):
#     a red here is a real, reported regression, never completion. E1/S1 target
#     the owners' landed strict receipt predicates; E2 asserts the non-string
#     core-hash rejection.
# =========================================================================== #
class RepairedDefectRegressionTests(unittest.TestCase):
    # ---- Engine E1: _strict_receipt_clean requires a full Windows Job receipt.
    def test_strict_receipt_clean_accepts_full_receipt(self):
        self.assertTrue(E._strict_receipt_clean(_CLEAN_RECEIPT))

    def test_strict_receipt_clean_rejects_unassigned_job_and_empty(self):
        self.assertFalse(E._strict_receipt_clean({}))
        self.assertFalse(E._strict_receipt_clean({"pid": 1}))
        bad = json.loads(json.dumps(_CLEAN_RECEIPT))
        bad["cleanup"]["job_assigned"] = False
        self.assertFalse(E._strict_receipt_clean(bad))

    # ---- Service S1: _receipt_clean rejects empty/partial/unclean receipts.
    def test_receipt_clean_accepts_full_receipt(self):
        self.assertTrue(S._receipt_clean(_CLEAN_RECEIPT))

    def test_receipt_clean_rejects_empty_nondict_and_unassigned_job(self):
        self.assertFalse(S._receipt_clean({}))
        self.assertFalse(S._receipt_clean(None))
        bad = json.loads(json.dumps(_CLEAN_RECEIPT))
        bad["cleanup"]["job_assigned"] = False
        self.assertFalse(S._receipt_clean(bad))

    # ---- Engine E2: load_producer_report must reject a non-string core hash.
    def test_load_producer_report_rejects_nonstring_core_hash(self):
        with _tmp() as d:
            root = Path(d)
            rp = EngineProducerBindingTests._fixture(root)
            report = json.loads(rp.read_text(encoding="utf-8"))
            only = next(iter(report["original_classes"]))
            report["original_classes"][only] = 123           # non-string claimed SHA
            rp.write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaises(E.JvmIntegrateError):
                E.load_producer_report(rp, workspace_root=root)


@unittest.skipUnless(RUN_E2E, "opt-in real compiler/target e2e (ANTIREA_RUN_JVM_APP_E2E=1); OFF by default")
class OptInEndToEndTests(unittest.TestCase):
    def test_placeholder_requires_root_frozen_toolchain(self):
        # The only legitimate skip gate. Real producer build + source-integrate +
        # relocation is owned by root post-freeze; this never runs in the audit lane.
        self.fail("ANTIREA_RUN_JVM_APP_E2E is set but real compiler/target e2e is root-owned, not audit-lane")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
