"""Focused tests for the production JVM app-integration ENGINE lane.

These import the ACTUAL production module ``antirea.jvm_app_integration`` and
exercise its logic with FOCUSED MOCKS -- a stub ``antirea.jvm_facade`` (the facade
lane is landed separately) and a fake ``antirea.process.run_logged`` that simulates
the javac / java / cl / bootstrap children WITHOUT running any real compiler or
target. Per the phase21 engine brief: NO real compiler/target execution happens
here; the authoritative fresh Java AND Kotlin native/app run is root's, after the
source freeze. The whole unittest process is launched by the owned OUTER bounded
driver ``.runs/phase21-engine/outer_run.py`` (clean allowlisted env, private TEMP,
real workspace STOP as the cancel file, Windows Job empty/closed/parent-exit proof).

The fake ``run_logged`` faithfully reproduces the FAIL-CLOSED bootstrap semantics
the engine relies on: a protected-arm child whose ANTIREA_JNI_ADAPTER /
ANTIREA_NATIVE_CORE path is missing/unset exits non-zero with no original output,
so the missing-core / missing-adapter route proofs are genuinely exercised.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for _p in (str(ROOT),):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import antirea.jvm_app_integration as m  # noqa: E402

OUT_BASE = ROOT / ".runs" / "phase21-engine" / "pytmp"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- #
# Stub facade (on-disk source so the engine can hash it by trusted name).
# --------------------------------------------------------------------------- #
_STUB_FACADE_SRC = '''
"""Stub antirea.jvm_facade mirroring the landed facade CONTRACT (pure, no execution).

Return shapes match antirea/jvm_facade.py: generate_facades -> status
'generated_not_validated', files {relpath: sha256}, jni.adapter_sources, dotted
expected_deploy_classes, forbidden_original_core_classes.internal_names; the two
checks return status 'accepted'/'rejected' with a violations list.
"""
import hashlib
from pathlib import Path


def _w(output_dir, rel, data):
    p = output_dir / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def generate_facades(producer, output_dir):
    output_dir = Path(output_dir)
    if output_dir.exists():
        raise ValueError("output_dir must be new; facades never overwrite existing files")
    output_dir.mkdir(parents=True)
    files = {}
    files["java/sample/Core.java"] = _w(output_dir, "java/sample/Core.java", b"// facade core\\n")
    files["java/antirea/runtime/ProtectedBootstrap.java"] = _w(
        output_dir, "java/antirea/runtime/ProtectedBootstrap.java", b"// bootstrap\\n")
    files["java/antirea/runtime/NativeCore.java"] = _w(
        output_dir, "java/antirea/runtime/NativeCore.java", b"// nativecore\\n")
    files["jni/antirea_bridge.h"] = _w(output_dir, "jni/antirea_bridge.h", b"/* header */\\n")
    files["jni/antirea_bridge.c"] = _w(output_dir, "jni/antirea_bridge.c", b"/* bridge */\\n")
    files["jni/adapter.c"] = _w(output_dir, "jni/adapter.c", b"/* adapter */\\n")
    exports = [f["name"] for f in producer["contract"]["functions"]]
    originals = producer["original_classes"]           # {abs_path: sha256}
    opath, osha = sorted(originals.items())[0]          # fixture has exactly one core class
    class_inventory = [{
        "internal_name": "sample/Core", "class": "sample.Core",
        "original_sha256": osha, "original_classfile": opath,
        "facade_source_file": "java/sample/Core.java",
        "facade_source_sha256": files["java/sample/Core.java"],
        "same_relative_class_path": True, "original_bytes_must_be_absent": True, "methods": []}]
    return {
        "schema_version": 1, "kind": "jvm_facade_generation",
        "status": "generated_not_validated", "language": producer["language"],
        "package": "antirea.runtime", "executed": False, "files": files,
        "contract": producer["contract"],
        "facade_classes": [{"internal_name": "sample/Core", "class": "sample.Core",
                            "source_file": "java/sample/Core.java", "methods": []}],
        "runtime_classes": [
            {"class": "antirea.runtime.ProtectedBootstrap",
             "source_file": "java/antirea/runtime/ProtectedBootstrap.java",
             "entry": "ensureReady", "environment": ["ANTIREA_JNI_ADAPTER", "ANTIREA_NATIVE_CORE"],
             "fail_closed": True},
            {"class": "antirea.runtime.NativeCore", "source_file": "java/antirea/runtime/NativeCore.java"}],
        "jni": {"header": "jni/antirea_bridge.h",
                "adapter_sources": ["jni/adapter.c", "jni/antirea_bridge.c"],
                "exported_symbols": exports},
        "native_exports": exports,
        "expected_deploy_classes": sorted(["sample.Core", "antirea.runtime.ProtectedBootstrap",
                                           "antirea.runtime.NativeCore"]),
        "replaced_core_classes": ["sample/Core"],
        "class_inventory": class_inventory,
        "closure": {"roots": [], "helpers": []},
        "limitations": ["stub facade: generation is not compilation"],
    }


def inspect_application_classes(class_files, producer):
    return {"schema_version": 1, "kind": "jvm_application_inspection",
            "status": "accepted", "violations": [], "classes": sorted(class_files)}


def validate_facade_classes(class_files, producer):
    return {"schema_version": 1, "kind": "jvm_facade_validation",
            "status": "accepted", "violations": [], "classes": sorted(class_files)}
'''


def install_stub_facade(dirpath: Path, tc: unittest.TestCase) -> Path:
    stub = dirpath / "stub_jvm_facade.py"
    stub.write_text(_STUB_FACADE_SRC, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("antirea.jvm_facade", str(stub))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    replacement = mock.patch.dict(sys.modules, {"antirea.jvm_facade": module})
    replacement.start()
    tc.addCleanup(replacement.stop)
    return stub


# --------------------------------------------------------------------------- #
# Synthetic workspace + producer report + spec + contract.
# --------------------------------------------------------------------------- #
ORIGINAL_CORE_BYTES = b"ORIGINAL_CORE_CLASS_BYTES"
CASES = [
    {"label": "ok(2,3)", "args": ["2", "3"], "expect": {"returncode": 0, "stdout": "5\n"}},
    {"label": "ok(10,20)", "args": ["10", "20"], "expect": {"returncode": 0, "stdout": "30\n"}},
    {"label": "usage", "args": [], "expect": {"returncode": 2, "stdout": "usage\n"}},
]


def build_workspace(ws: Path, language: str = "java", cases=CASES) -> dict:
    (ws / "antirea").mkdir(parents=True)                     # WorkspacePlan marker
    ext = ".java" if language == "java" else ".kt"
    main_class = "sample.App" if language == "java" else "sample.AppKt"
    project = ws / "project"
    project.mkdir()
    (project / ("Core" + ext)).write_text("// core source\n", encoding="utf-8")
    (project / ("App" + ext)).write_text("// app source\n", encoding="utf-8")
    build = ws / ".runs" / "producer"
    (build / "frontend" / "classes" / "sample").mkdir(parents=True)
    core_class = build / "frontend" / "classes" / "sample" / "Core.class"
    core_class.write_bytes(ORIGINAL_CORE_BYTES)
    native = build / "native"
    native.mkdir(parents=True)
    baseline = native / "baseline.dll"
    protected = native / "protected.dll"
    baseline.write_bytes(b"BASELINE-NATIVE")
    protected.write_bytes(b"PROTECTED-NATIVE-CORE")
    native_artifacts = {"baseline": {"path": str(baseline), "sha256": _sha(b"BASELINE-NATIVE"), "bytes": 15},
                        "protected": {"path": str(protected), "sha256": _sha(b"PROTECTED-NATIVE-CORE"), "bytes": 21}}
    # Realistic native coverage (native_build schema-2 fields): selected_functions +
    # VM evidence cover the lowered method exports; exported_functions are the exports.
    native_coverage = {"schema_version": 2, "protection": "native-diversified-layered",
                       "functions": ["m"], "original_vm": {"m": {"ops": 12}},
                       "selected_functions": ["m"], "exported_functions": ["m"],
                       "final_vm": {"m": {"ops": 7}}, "artifacts": native_artifacts}
    native_report = native / "report.json"
    native_report.write_text(json.dumps({"status": "artifact_created_unvalidated",
                                         "artifacts": native_artifacts, "coverage": native_coverage}),
                             encoding="utf-8")
    contract = {"schema_version": 1, "library_name": "sample", "calling_convention": "cdecl",
                "functions": [{"name": "m", "return_type": "i32",
                               "parameters": [{"name": "a0", "type": "i32"}, {"name": "a1", "type": "i32"}]}]}
    contract_file = build / "contract.json"
    contract_file.write_text(json.dumps(contract), encoding="utf-8")
    methods = [{"class": "sample/Core", "name": "m", "descriptor": "(II)I", "export": "m", "is_root": True}]
    original_classes = {str(core_class): _sha(ORIGINAL_CORE_BYTES)}
    frontend_hashes = {"contract.json": _sha(contract_file.read_bytes()),
                       "classes/sample/Core.class": _sha(ORIGINAL_CORE_BYTES)}
    if language == "kotlin":
        meta = build / "frontend" / "classes" / "META-INF"
        meta.mkdir(parents=True)
        module = meta / "main.kotlin_module"
        module.write_bytes(b"KOTLIN-MODULE-METADATA")
        frontend_hashes["classes/META-INF/main.kotlin_module"] = _sha(b"KOTLIN-MODULE-METADATA")
    report = {
        "schema_version": 1, "status": "artifact_created_unvalidated", "backend": "jvm_bytecode_native",
        "language": language,
        "project": {"name": "sample", "language": language, "project_root": str(project),
                    "project_path": str(project / "project.json"),
                    "sources": [str(project / ("Core" + ext))], "methods": methods,
                    "functions": ["m"]},
        "methods": methods,
        "contract": contract, "contract_path": str(contract_file),
        "native_report": str(native_report), "native_report_sha256": _sha(native_report.read_bytes()),
        "artifacts": native_artifacts,
        "original_classes": original_classes,
        "frontend_artifact_hashes": frontend_hashes,
        "coverage": {**native_coverage, "exported_functions": ["m"]},
        "compiler_inputs": {},
    }
    report_path = build / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    spec = {"schema_version": 1, "kind": "jvm_application_integration", "language": language,
            "application_sources": ["App" + ext], "main_class": main_class}
    spec_path = project / "app-integration.json"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    contract_doc = {"schema_version": 1, "kind": "jvm_application_samples", "cases": cases}
    contract_path = ws / "app-contract.json"
    contract_path.write_text(json.dumps(contract_doc), encoding="utf-8")
    return {"workspace": ws, "report_path": report_path, "spec_path": spec_path,
            "contract_path": contract_path, "out_dir": ws / ".runs" / "engine-out",
            "language": language, "main_class": main_class}


def fake_toolchains(ws: Path, language: str = "java"):
    """Create a fake JDK layout (jni headers) and return patched discovery values."""
    jdk = ws / "fakejdk"
    (jdk / "include" / "win32").mkdir(parents=True)
    (jdk / "include" / "jni.h").write_text("/* jni */\n", encoding="utf-8")
    (jdk / "include" / "win32" / "jni_md.h").write_text("/* jni_md */\n", encoding="utf-8")
    (jdk / "bin").mkdir()
    javac = jdk / "bin" / "javac.exe"
    java = jdk / "bin" / "java.exe"
    javac.write_text("x", encoding="utf-8")
    java.write_text("x", encoding="utf-8")
    jvm_compiler = {"javac": str(javac), "java": str(java), "jdk_root": str(jdk),
                    "helper": str(jdk / "bin" / "javac.exe"), "blockers": [],
                    "input_hashes": {str(javac): "a" * 64, str(java): "b" * 64}}
    if language == "kotlin":
        khome = ws / "fakekotlin"
        (khome / "lib").mkdir(parents=True)
        stdlib = khome / "lib" / "kotlin-stdlib.jar"
        stdlib.write_bytes(b"KOTLIN-STDLIB-JAR")
        (khome / "lib" / "kotlin-compiler.jar").write_bytes(b"KC")
        (khome / "lib" / "annotations-13.0.jar").write_bytes(b"ANN")
        jvm_compiler.update(kotlin_home=str(khome), kotlin_compiler=str(khome / "lib" / "kotlin-compiler.jar"),
                            kotlin_stdlib=str(stdlib), kotlin_annotations=str(khome / "lib" / "annotations-13.0.jar"))
        jvm_compiler["input_hashes"][str(stdlib)] = "d" * 64
    devshell = ws / "fakedev" / "Launch-VsDevShell.ps1"
    devshell.parent.mkdir(parents=True)
    devshell.write_text("param()\n", encoding="utf-8")
    native_toolchain = {"developer_shell": str(devshell),
                        "tool_hashes": {str(devshell): "c" * 64}}
    # Fake selected MSVC tools + powershell (real files so _pin_tool can hash them).
    sdkbin = ws / "fakesdk" / "bin"
    sdkbin.mkdir(parents=True)
    (sdkbin / "cl.exe").write_bytes(b"FAKE-CL")
    (sdkbin / "link.exe").write_bytes(b"FAKE-LINK")
    ps = ws / "fakeps" / "powershell.exe"
    ps.parent.mkdir(parents=True)
    ps.write_bytes(b"FAKE-PS")
    tools = {"cl.exe": str(sdkbin / "cl.exe"), "link.exe": str(sdkbin / "link.exe"),
             "powershell.exe": str(ps)}
    return jvm_compiler, native_toolchain, tools


def fake_which(tools):
    def which(name, path=None):
        base = os.path.basename(str(name)).lower()
        if base in tools:
            return tools[base]
        if name in tools:
            return tools[name]
        return None
    return which


def _strict_cleanup(pid):
    # Full strict Windows-Job receipt the service/engine require (parent_pid==pid).
    return {"method": "windows_job", "job_assigned": True, "parent_pid": pid,
            "status": "assigned_job_empty", "job_handle_closed": True,
            "parent_exit_confirmed": True, "active_after": 0, "active_before": 0,
            "assignment_timing": "immediately_after_launch"}


def make_fake_run_logged(facade_dir_marker: str, cases):
    expected = {tuple(c["args"]): (c["expect"]["stdout"], c["expect"]["returncode"]) for c in cases}

    def fake(argv, directory, log_prefix, timeout=600, env=None, stdin=None, cancel_file=None):
        argv = [str(a) for a in argv]
        log_prefix = Path(log_prefix)
        label = log_prefix.name
        log_prefix.parent.mkdir(parents=True, exist_ok=True)
        stdout_text, rc = "", 0

        def _dir_after_flag(flag):
            return Path(argv[argv.index(flag) + 1])

        if label == "sdk-capture":
            stdout_text = json.dumps({"INCLUDE": "i", "LIB": "l", "PATH": "p"})
        elif label == "cl-adapter":
            fe = [a for a in argv if a.startswith("/Fe:")]
            Path(fe[0][len("/Fe:"):]).write_bytes(b"ADAPTER-DLL")
        elif label == "compile-app":
            d = _dir_after_flag("-d")
            (d / "sample").mkdir(parents=True, exist_ok=True)
            (d / "sample" / "App.class").write_bytes(b"APP-CLASS")
            if "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler" in argv:
                # Kotlin app output includes module metadata: pinned, never deployed.
                (d / "META-INF").mkdir(parents=True, exist_ok=True)
                (d / "META-INF" / "main.kotlin_module").write_bytes(b"APP-KOTLIN-MODULE")
        elif label == "compile-facade":
            d = _dir_after_flag("-d")
            (d / "sample").mkdir(parents=True, exist_ok=True)
            (d / "sample" / "Core.class").write_bytes(b"FACADE-CORE-CLASS")
            (d / "antirea" / "runtime").mkdir(parents=True, exist_ok=True)
            (d / "antirea" / "runtime" / "ProtectedBootstrap.class").write_bytes(b"BOOT-CLASS")
            (d / "antirea" / "runtime" / "NativeCore.class").write_bytes(b"NC-CLASS")
        elif label.startswith(("case-", "route-")):
            cp = argv[2]
            args = tuple(argv[4:])
            is_protected = facade_dir_marker in cp
            if is_protected:
                adapter = (env or {}).get("ANTIREA_JNI_ADAPTER")
                core = (env or {}).get("ANTIREA_NATIVE_CORE")
                ready = bool(adapter and os.path.exists(adapter) and core and os.path.exists(core))
                if not ready:
                    stdout_text, rc = "", 1           # fail closed, no original fallback
                else:
                    stdout_text, rc = expected.get(args, ("", 0))
            else:
                stdout_text, rc = expected.get(args, ("", 0))
        pid = 4321
        # Write the EXACT stdout bytes (a real child writes to the fd directly; no
        # Python-side newline translation), so raw-byte observation is faithful.
        log_prefix.with_suffix(".stdout.log").write_bytes(stdout_text.encode("utf-8"))
        log_prefix.with_suffix(".stderr.log").write_bytes(b"")
        result = {"argv": argv, "returncode": rc, "pid": pid, "timed_out": False,
                  "cancelled": False, "seconds": 0.01, "cleanup": _strict_cleanup(pid),
                  "stdout": str(log_prefix.with_suffix(".stdout.log")),
                  "stderr": str(log_prefix.with_suffix(".stderr.log"))}
        log_prefix.with_suffix(".process.json").write_text(json.dumps(result), encoding="utf-8")
        return result

    return fake


def _tmp():
    OUT_BASE.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(dir=str(OUT_BASE), ignore_cleanup_errors=True)


# =========================================================================== #
# (A) Public API shape, trusted keyset, service contract, honest labels.
# =========================================================================== #
class PublicSurfaceTests(unittest.TestCase):
    def test_run_integration_signature_is_keyword_only_and_exact(self):
        import inspect
        sig = inspect.signature(m.run_integration)
        self.assertEqual(list(sig.parameters), ["producer_report_path", "integration_spec_path",
                                                 "application_contract_path", "output_dir", "workspace_root",
                                                 "timeout_seconds", "trusted_inputs"])
        for name in ("producer_report_path", "integration_spec_path", "application_contract_path",
                     "output_dir", "workspace_root", "timeout_seconds", "trusted_inputs"):
            self.assertEqual(sig.parameters[name].kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertEqual(sig.parameters["timeout_seconds"].default, 120)
        self.assertIsNone(sig.parameters["trusted_inputs"].default)

    def test_trusted_module_keyset_includes_engine_and_facade(self):
        self.assertEqual(m.TRUSTED_FACADE_MODULE, "antirea.jvm_facade")
        self.assertEqual(m.RUNTIME_PACKAGE, "antirea.runtime")
        self.assertIn("antirea.jvm_app_integration", m.TRUSTED_ENGINE_MODULES)
        self.assertIn("antirea.jvm_facade", m.TRUSTED_ENGINE_MODULES)
        for dep in ("antirea.jvm_frontend", "antirea.bindings", "antirea.native_build",
                    "antirea.process", "antirea.source_validate"):
            self.assertIn(dep, m.TRUSTED_ENGINE_MODULES)

    def test_contract_is_honest_experimental_and_names_schema(self):
        c = m.project_service_contract()
        self.assertFalse(c["whole_language_support"])
        self.assertFalse(c["whole_language_claim"])
        self.assertEqual(c["run_integration_signature"]["passing_status"], "jvm_application_samples_passed")
        self.assertFalse(c["provenance_model"]["fresh_protected_native_build"])
        self.assertTrue(c["native_jni_environment"]["no_env_setting"])
        self.assertTrue(c["native_jni_environment"]["no_historical_linkrepro"])
        self.assertEqual(set(c["deployment_schema"]) >= {"path", "files", "allowlist", "main_class",
                         "classpath_entries", "jni_adapter", "native_core", "forbidden_absent"}, True)
        self.assertEqual(c["report_schema"]["comparison_status"], "producer_bound_integration_passed")
        self.assertEqual(set(c["report_schema"]["comparison_pass_flags"]),
                         {"all_match", "env_ok", "route_proof_ok", "integrity_verified_before_and_after",
                          "expectations_ok", "missing_core_control_ok", "missing_adapter_control_ok"})
        self.assertEqual(c["gates_pending"]["performance_evaluation"], "not_evaluated")

    def test_qualification_status_requires_pass_and_integrity(self):
        self.assertFalse(m.qualification_status(
            {"passed": False, "comparison": {"status": "failed"},
             "integrity_verified_before_and_after": True})["functional_sample_passed"])
        self.assertFalse(m.qualification_status(
            {"passed": True, "comparison": {"status": "producer_bound_integration_passed"},
             "integrity_verified_before_and_after": False})["functional_sample_passed"])
        self.assertTrue(m.qualification_status(
            {"passed": True, "comparison": {"status": "producer_bound_integration_passed"},
             "integrity_verified_before_and_after": True})["functional_sample_passed"])


# =========================================================================== #
# (B) Reserved/received guards, bounded reads (pure, synthetic paths).
# =========================================================================== #
class GuardTests(unittest.TestCase):
    def test_reserved_components_rejected_lexically(self):
        for bad in ("env.setting", "linkrepro", "rea-analysis-reports", "attackerfolder", "defense-loop"):
            with self.assertRaises(m.JvmIntegrateError):
                m._reserved_guard(os.path.join("C:\\ws", bad, "x.bin"))

    def test_reserved_set_is_exactly_the_five_names(self):
        self.assertEqual(m.RESERVED_PATH_COMPONENTS,
                         frozenset({"rea-analysis-reports", "attackerfolder", "defense-loop",
                                    "env.setting", "linkrepro"}))

    def test_trusted_inputs_normalize_fails_closed(self):
        with self.assertRaises(m.JvmIntegrateError):
            m._normalize_trusted_inputs([{"path": "rel/not/abs", "sha256": "0" * 64}])
        with self.assertRaises(m.JvmIntegrateError):
            m._normalize_trusted_inputs([{"path": "C:\\ws\\a", "sha256": "nothex"}])
        with self.assertRaises(m.JvmIntegrateError):
            m._normalize_trusted_inputs([{"path": "C:\\ws\\env.setting", "sha256": "0" * 64}])
        self.assertEqual(m._normalize_trusted_inputs(None), [])
        ok = m._normalize_trusted_inputs([{"path": "C:\\ws\\a", "sha256": "0" * 64, "role": "plan"}])
        self.assertEqual(ok[0]["role"], "plan")


# =========================================================================== #
# (C) Integration-spec + application-contract strict schema.
# =========================================================================== #
class SchemaTests(unittest.TestCase):
    def test_cases_require_exact_stdout_and_exit(self):
        good = [{"label": "a", "args": ["1"], "expect": {"returncode": 0, "stdout": "x\n"}}]
        self.assertEqual(m.validate_cases(good)[0]["expect"], {"returncode": 0, "stdout": "x\n"})
        # missing stdout
        with self.assertRaises(m.JvmIntegrateError):
            m.validate_cases([{"label": "a", "args": [], "expect": {"returncode": 0}}])
        # missing returncode
        with self.assertRaises(m.JvmIntegrateError):
            m.validate_cases([{"label": "a", "args": [], "expect": {"stdout": "x"}}])
        # out-of-range returncode
        with self.assertRaises(m.JvmIntegrateError):
            m.validate_cases([{"label": "a", "args": [], "expect": {"returncode": 999, "stdout": "x"}}])
        # too many argv
        with self.assertRaises(m.JvmIntegrateError):
            m.validate_cases([{"label": "a", "args": ["x"] * 17, "expect": {"returncode": 0, "stdout": "x"}}])
        # NUL in argv
        with self.assertRaises(m.JvmIntegrateError):
            m.validate_cases([{"label": "a", "args": ["x\x00y"], "expect": {"returncode": 0, "stdout": "x"}}])

    def test_control_case_requires_a_success_case(self):
        with self.assertRaises(m.JvmIntegrateError):
            m._select_control_case([{"label": "f", "args": [], "expect": {"returncode": 2, "stdout": "n"}}])
        ctl = m._select_control_case(m.validate_cases(CASES))
        self.assertEqual(ctl["expect"]["returncode"], 0)

    def test_spec_rejects_core_overlap_and_absolute_and_dotdot(self):
        with _tmp() as d:
            ws = Path(d) / "ws"
            fx = build_workspace(ws)
            pinned = m.load_producer_report(fx["report_path"], workspace_root=ws)
            # Overlapping the core source is rejected.
            bad = ws / "project" / "bad-spec.json"
            bad.write_text(json.dumps({"schema_version": 1, "kind": "jvm_application_integration",
                                       "language": "java", "application_sources": ["Core.java"],
                                       "main_class": "sample.App"}), encoding="utf-8")
            with self.assertRaises(m.JvmIntegrateError):
                m.load_integration_spec(bad, workspace_root=ws, pinned=pinned)
            # Absolute path rejected.
            bad2 = ws / "project" / "bad2.json"
            bad2.write_text(json.dumps({"schema_version": 1, "kind": "jvm_application_integration",
                                        "language": "java", "application_sources": [str(ws / "project" / "App.java")],
                                        "main_class": "sample.App"}), encoding="utf-8")
            with self.assertRaises(m.JvmIntegrateError):
                m.load_integration_spec(bad2, workspace_root=ws, pinned=pinned)

    def test_spec_language_must_match_producer(self):
        with _tmp() as d:
            ws = Path(d) / "ws"
            fx = build_workspace(ws)
            pinned = m.load_producer_report(fx["report_path"], workspace_root=ws)
            bad = ws / "project" / "kt-spec.json"
            bad.write_text(json.dumps({"schema_version": 1, "kind": "jvm_application_integration",
                                       "language": "kotlin", "application_sources": ["App.java"],
                                       "main_class": "sample.App"}), encoding="utf-8")
            with self.assertRaises(m.JvmIntegrateError):
                m.load_integration_spec(bad, workspace_root=ws, pinned=pinned)


# =========================================================================== #
# (D) Producer report consume + pin (fail closed on drift).
# =========================================================================== #
class ProducerReportTests(unittest.TestCase):
    def _mutate(self, fx, fn):
        report = json.loads(fx["report_path"].read_text())
        fn(report)
        fx["report_path"].write_text(json.dumps(report))

    def test_backend_and_status_enforced(self):
        with _tmp() as d:
            ws = Path(d) / "ws"
            fx = build_workspace(ws)
            report = json.loads(fx["report_path"].read_text())
            report["backend"] = "dotnet_il_native"
            fx["report_path"].write_text(json.dumps(report))
            with self.assertRaises(m.JvmIntegrateError):
                m.load_producer_report(fx["report_path"], workspace_root=ws)

    def test_required_origin_not_optional(self):
        # Each required producer-origin omission/contradiction must FAIL (never be
        # treated as optional or silently repinned) -- engine-final-acceptance item 2.
        def _expect_fail(mutator):
            with _tmp() as d:
                ws = Path(d) / "ws"
                fx = build_workspace(ws)
                self._mutate(fx, mutator)
                with self.assertRaises(m.JvmIntegrateError):
                    m.load_producer_report(fx["report_path"], workspace_root=ws)
        _expect_fail(lambda r: r.pop("native_report"))
        _expect_fail(lambda r: r.pop("native_report_sha256"))
        _expect_fail(lambda r: r.__setitem__("native_report_sha256", "zz" + "0" * 62))
        _expect_fail(lambda r: r["frontend_artifact_hashes"].pop("contract.json"))
        _expect_fail(lambda r: r["frontend_artifact_hashes"].__setitem__("contract.json", "0" * 64))
        # Contradictory coverage (not the native coverage + export override).
        _expect_fail(lambda r: r["coverage"].__setitem__("original_vm", {"m": {"ops": 999}}))
        # Non-hex original class hash is still rejected strictly.
        _expect_fail(lambda r: r.__setitem__(
            "original_classes", {list(r["original_classes"])[0]: "NOT-HEX"}))

    def test_native_report_contradictions_fail(self):
        # Mutating the SEPARATE native report file (selected_functions / artifacts /
        # status) must be detected via the pinned native-report bytes.
        def _expect_fail(nr_mutator):
            with _tmp() as d:
                ws = Path(d) / "ws"
                fx = build_workspace(ws)
                nrp = Path(json.loads(fx["report_path"].read_text())["native_report"])
                nr = json.loads(nrp.read_text())
                nr_mutator(nr)
                nrp.write_text(json.dumps(nr))
                # Re-pin the (now changed) native report sha into the report so the
                # hash check passes and the CONTENT contradiction is what fails.
                self._mutate(fx, lambda r: r.__setitem__("native_report_sha256", _sha(nrp.read_bytes())))
                with self.assertRaises(m.JvmIntegrateError):
                    m.load_producer_report(fx["report_path"], workspace_root=ws)
        _expect_fail(lambda nr: nr["coverage"].__setitem__("selected_functions", ["other"]))
        _expect_fail(lambda nr: nr["coverage"].pop("original_vm"))
        _expect_fail(lambda nr: nr.__setitem__("status", "failed"))
        _expect_fail(lambda nr: nr["artifacts"]["protected"].__setitem__("sha256", "0" * 64))

    def test_artifact_hash_mismatch_fails_closed(self):
        with _tmp() as d:
            ws = Path(d) / "ws"
            fx = build_workspace(ws)
            report = json.loads(fx["report_path"].read_text())
            report["artifacts"]["protected"]["sha256"] = "0" * 64
            fx["report_path"].write_text(json.dumps(report))
            with self.assertRaises(m.JvmIntegrateError):
                m.load_producer_report(fx["report_path"], workspace_root=ws)

    def test_report_must_live_under_runs(self):
        with _tmp() as d:
            ws = Path(d) / "ws"
            fx = build_workspace(ws)
            outside = ws / "report.json"
            outside.write_text(fx["report_path"].read_text())
            with self.assertRaises(m.JvmIntegrateError):
                m.load_producer_report(outside, workspace_root=ws)


# =========================================================================== #
# (E) Full mocked pipeline: run_integration end to end.
# =========================================================================== #
def mocked_pipeline(tc, ws, fx, cases=CASES, trusted_inputs=None):
    """Run run_integration end-to-end with the stub facade + fake run_logged + fake
    toolchains, registering patch cleanups on the given TestCase ``tc``."""
    stub_dir = ws / "_stub"
    stub_dir.mkdir()
    install_stub_facade(stub_dir, tc)
    jvm_compiler, native_toolchain, tools = fake_toolchains(ws, fx["language"])
    facade_marker = str(fx["out_dir"] / "facade_classes")
    fake = make_fake_run_logged(facade_marker, m.validate_cases(cases))
    patches = [
        mock.patch.object(m, "_discover_jvm_toolchain", lambda language: dict(jvm_compiler)),
        mock.patch.object(m, "_discover_native_toolchain", lambda workspace_root: dict(native_toolchain)),
        mock.patch("antirea.jvm_app_integration.shutil.which", fake_which(tools)),
        mock.patch("antirea.jvm_frontend.parse_class", lambda data: {"class": "sample/Core"}),
        mock.patch("antirea.process.run_logged", fake),
    ]
    for p in patches:
        p.start()
        tc.addCleanup(p.stop)
    return m.run_integration(producer_report_path=fx["report_path"],
                             integration_spec_path=fx["spec_path"],
                             application_contract_path=fx["contract_path"],
                             output_dir=fx["out_dir"], workspace_root=ws,
                             timeout_seconds=30, trusted_inputs=trusted_inputs)


class PipelineTests(unittest.TestCase):
    def _run(self, ws, fx, cases=CASES, trusted_inputs=None):
        return mocked_pipeline(self, ws, fx, cases=cases, trusted_inputs=trusted_inputs)

    def test_happy_path_passes_and_emits_bundle(self):
        with _tmp() as d:
            ws = Path(d) / "ws"
            fx = build_workspace(ws)
            report = self._run(ws, fx)
            self.assertEqual(report["status"], "jvm_application_samples_passed")
            self.assertFalse(report["fresh_protected_native_build"])
            self.assertTrue(report["plan_round_trip_through_json"])
            self.assertEqual(report["language"], "java")
            self.assertEqual(report["main_class"], "sample.App")
            # Persisted report exists.
            self.assertTrue((fx["out_dir"] / "integration.json").is_file())
            # Comparison: every case matched + route proofs + integrity + facade checks.
            comp = report["comparison"]
            self.assertTrue(comp["all_match"])
            self.assertTrue(comp["route_proof_ok"])
            self.assertTrue(comp["integrity_verified_before_and_after"])
            self.assertTrue(comp["facade_forwarding_only"])
            self.assertTrue(comp["application_references_allowed_roots_only"])
            self.assertEqual(comp["total_cases"], 3)

    def test_exact_stdout_preserves_crlf(self):
        cases = json.loads(json.dumps(CASES))
        for case in cases:
            case["expect"]["stdout"] = case["expect"]["stdout"].replace("\n", "\r\n")
        with _tmp() as d:
            ws = Path(d) / "ws"
            fx = build_workspace(ws, cases=cases)
            report = self._run(ws, fx, cases=cases)
            self.assertEqual(report["status"], "jvm_application_samples_passed")
            self.assertEqual(report["comparison"]["cases"][0]["baseline"]["stdout"], "5\r\n")

    def test_invalid_utf8_cannot_match_replacement_character_contract(self):
        cases = json.loads(json.dumps(CASES))
        cases[0]["expect"]["stdout"] = "\ufffd\n"
        factory = make_fake_run_logged

        def corrupting_factory(*args):
            child = factory(*args)

            def run(*argv, **kwargs):
                receipt = child(*argv, **kwargs)
                output = Path(receipt["stdout"])
                if output.read_bytes() == b"\xef\xbf\xbd\n":
                    output.write_bytes(b"\xff\n")
                return receipt

            return run

        with _tmp() as d, mock.patch(__name__ + ".make_fake_run_logged", corrupting_factory):
            ws = Path(d) / "ws"
            fx = build_workspace(ws, cases=cases)
            report = self._run(ws, fx, cases=cases)
            self.assertNotEqual(report["status"], "jvm_application_samples_passed")
            self.assertFalse(report["comparison"]["all_match"])

    def test_application_stdout_uses_bounded_reader(self):
        with _tmp() as d, mock.patch.object(m, "_read_bytes_bounded", wraps=m._read_bytes_bounded) as reader:
            ws = Path(d) / "ws"
            fx = build_workspace(ws)
            report = self._run(ws, fx)
            read_paths = {str(Path(call.args[0])) for call in reader.call_args_list}
            for command in report["comparison"]["commands"]:
                self.assertIn(command["stdout_log"], read_paths)

    def test_every_executed_child_has_one_report_reference(self):
        with _tmp() as d:
            ws = Path(d) / "ws"
            fx = build_workspace(ws)
            report = self._run(ws, fx)
            commands = report["preparation_commands"] + report["comparison"]["commands"]
            referenced = {str(Path(command["receipt_path"])) for command in commands}
            persisted = {str(path) for path in fx["out_dir"].rglob("*.process.json")}
            self.assertEqual(referenced, persisted)
            self.assertEqual(len(commands), len(referenced))

    def test_kotlin_happy_path_includes_runtime_jar(self):
        with _tmp() as d:
            ws = Path(d) / "ws"
            fx = build_workspace(ws, language="kotlin")
            report = self._run(ws, fx)
            self.assertEqual(report["status"], "jvm_application_samples_passed")
            self.assertEqual(report["language"], "kotlin")
            self.assertEqual(report["main_class"], "sample.AppKt")
            db = report["deployment"]
            # The Kotlin runtime jar is packaged and declared on the classpath.
            jar_entries = [e for e in db["classpath_entries"] if e.endswith(".jar")]
            self.assertTrue(jar_entries, "kotlin runtime jar must be on the classpath")
            rels = {f["relative_path"] for f in db["files"]}
            for e in jar_entries:
                self.assertIn(e, rels)
            # The Kotlin app module metadata is NOT deployed (pinned only).
            self.assertFalse(any(r.endswith(".kotlin_module") for r in rels))

    def test_deployment_schema_and_substitution(self):
        with _tmp() as d:
            ws = Path(d) / "ws"
            fx = build_workspace(ws)
            report = self._run(ws, fx)
            db = report["deployment"]
            self.assertEqual(set(db) >= {"path", "files", "allowlist", "main_class", "classpath_entries",
                                         "jni_adapter", "native_core", "forbidden_absent"}, True)
            self.assertEqual(db["main_class"], "sample.App")
            self.assertEqual(db["classpath_entries"], ["."])      # bundle root is the class root
            self.assertIs(db["forbidden_absent"], True)
            self.assertTrue(db["jni_adapter"].startswith("native/"))
            self.assertTrue(db["native_core"].startswith("native/"))
            rels = {f["relative_path"] for f in db["files"]}
            self.assertEqual(set(db["allowlist"]), rels)          # allowlist == file manifest
            self.assertIn(db["jni_adapter"], rels)
            self.assertIn(db["native_core"], rels)
            # The shipped core class is the FACADE at the bundle root, never the original.
            self.assertIn("sample/Core.class", rels)
            shipped = Path(db["path"]) / "sample" / "Core.class"
            self.assertNotEqual(shipped.read_bytes(), ORIGINAL_CORE_BYTES)
            # Every deployed file has an allowlisted suffix.
            for f in db["files"]:
                self.assertTrue(f["relative_path"].lower().endswith((".class", ".dll", ".jar")))

    def test_route_proofs_fail_closed_on_missing_core_and_adapter(self):
        with _tmp() as d:
            ws = Path(d) / "ws"
            fx = build_workspace(ws)
            report = self._run(ws, fx)
            variants = report["comparison"]["route_proofs"]
            for v in ("missing_core", "unset_core", "missing_adapter", "unset_adapter"):
                self.assertIn(v, variants)
                self.assertTrue(variants[v]["proves_native_required"], v)
                self.assertTrue(variants[v]["failed_cleanly"], v)
                self.assertFalse(variants[v]["silent_fallback_detected"], v)
            self.assertTrue(report["comparison"]["missing_core_control_ok"])
            self.assertTrue(report["comparison"]["missing_adapter_control_ok"])

    def test_trusted_inputs_round_tripped_and_verified(self):
        with _tmp() as d:
            ws = Path(d) / "ws"
            fx = build_workspace(ws)
            # Bind the integration spec itself as a trusted input (owned workspace file).
            spec_sha = _sha(fx["spec_path"].read_bytes())
            ti = [{"path": str(fx["spec_path"]), "sha256": spec_sha, "role": "integration_spec"}]
            report = self._run(ws, fx, trusted_inputs=ti)
            tiv = report["trusted_inputs_verification"]
            self.assertEqual(tiv["declared_count"], 1)
            self.assertTrue(tiv["verified"])
            self.assertTrue(tiv["no_code_executed_from_records"])

    def test_stop_marker_fails_closed_at_preflight(self):
        with _tmp() as d:
            ws = Path(d) / "ws"
            fx = build_workspace(ws)
            stop = ws / ".runs" / "defense-loop" / "STOP"
            stop.parent.mkdir(parents=True, exist_ok=True)
            stop.write_text("stop", encoding="utf-8")
            with self.assertRaises(m.JvmIntegrateError):
                self._run(ws, fx)

    def test_tampered_app_source_between_plan_and_run_fails_closed(self):
        # The engine re-verifies the spec/app sources from disk; a changed app source
        # after the fingerprint is bound must fail closed. We simulate by patching
        # prepare's disk re-check target.
        with _tmp() as d:
            ws = Path(d) / "ws"
            fx = build_workspace(ws)
            stub_dir = ws / "_stub"
            stub_dir.mkdir()
            install_stub_facade(stub_dir, self)
            jvm_compiler, native_toolchain, _tools = fake_toolchains(ws)
            patches = [
                mock.patch.object(m, "_discover_jvm_toolchain", lambda language: dict(jvm_compiler)),
                mock.patch.object(m, "_discover_native_toolchain", lambda workspace_root: dict(native_toolchain)),
            ]
            for p in patches:
                p.start()
                self.addCleanup(p.stop)
            workspace = m.WorkspacePlan.resolve(workspace_root=ws, out_dir=fx["out_dir"])
            prepared = m.plan(fx["report_path"], fx["spec_path"], fx["contract_path"], workspace=workspace)
            prepared = m.load_plan(m.serialize_plan(prepared))
            # Mutate the app source AFTER the plan fingerprint is bound.
            (ws / "project" / "App.java").write_text("// tampered\n", encoding="utf-8")
            with self.assertRaises(m.JvmIntegrateError):
                m.prepare(prepared, workspace)


# =========================================================================== #
# (F) Serializable plan tamper / facade drift rejection.
# =========================================================================== #
class PlanTamperTests(unittest.TestCase):
    def _planned(self, ws, fx):
        jvm_compiler, native_toolchain, _tools = fake_toolchains(ws)
        p1 = mock.patch.object(m, "_discover_jvm_toolchain", lambda language: dict(jvm_compiler))
        p2 = mock.patch.object(m, "_discover_native_toolchain", lambda workspace_root: dict(native_toolchain))
        p1.start(); p2.start()
        self.addCleanup(p1.stop); self.addCleanup(p2.stop)
        workspace = m.WorkspacePlan.resolve(workspace_root=ws, out_dir=fx["out_dir"])
        return m.plan(fx["report_path"], fx["spec_path"], fx["contract_path"], workspace=workspace)

    def test_fingerprint_tamper_rejected_on_load(self):
        with _tmp() as d:
            ws = Path(d) / "ws"
            fx = build_workspace(ws)
            (ws / "_stub").mkdir(exist_ok=True)
            install_stub_facade(ws / "_stub", self)
            prepared = self._planned(ws, fx)
            serialized = m.serialize_plan(prepared)
            doc = json.loads(serialized)
            doc["input_snapshot"]["main_class"] = "sample.Evil"
            with self.assertRaises(m.JvmIntegrateError):
                m.load_plan(json.dumps(doc))

    def test_facade_drift_rejected_on_load(self):
        with _tmp() as d:
            ws = Path(d) / "ws"
            fx = build_workspace(ws)
            (ws / "_stub").mkdir(exist_ok=True)
            stub = install_stub_facade(ws / "_stub", self)
            prepared = self._planned(ws, fx)
            serialized = m.serialize_plan(prepared)
            # Drift the facade source on disk after the plan bound its hash.
            stub.write_text(_STUB_FACADE_SRC + "\n# drift\n", encoding="utf-8")
            spec = importlib.util.spec_from_file_location("antirea.jvm_facade", str(stub))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            sys.modules["antirea.jvm_facade"] = module
            with self.assertRaises(m.JvmIntegrateError):
                m.load_plan(serialized)


# =========================================================================== #
# (G) Fresh native SDK capture parse logic (mocked run_logged + which).
# =========================================================================== #
class SdkCaptureTests(unittest.TestCase):
    def test_capture_parses_allowlisted_env_and_rejects_extra_keys(self):
        with _tmp() as d:
            out = Path(d) / "out"
            out.mkdir()
            devshell = Path(d) / "dev.ps1"
            devshell.write_text("param()\n", encoding="utf-8")
            nt = {"developer_shell": str(devshell), "tool_hashes": {}}

            def _capture(env_obj):
                def fake(argv, directory, log_prefix, timeout=600, env=None, stdin=None, cancel_file=None):
                    self.assertEqual(env["PATHEXT"], ".COM;.EXE;.BAT;.CMD")
                    self.assertEqual(Path(env["COMSPEC"]), Path(env["SystemRoot"]) / "System32" / "cmd.exe")
                    self.assertIn("-VsInstallationPath $env:ANTIREA_NATIVE_DEVSHELL", argv[-1])
                    self.assertIn("-NonInteractive", argv)
                    lp = Path(log_prefix)
                    lp.parent.mkdir(parents=True, exist_ok=True)
                    lp.with_suffix(".stdout.log").write_text(json.dumps(env_obj), encoding="utf-8")
                    lp.with_suffix(".stderr.log").write_text("", encoding="utf-8")
                    result = {"argv": [str(a) for a in argv], "returncode": 0, "timed_out": False,
                              "cancelled": False, "seconds": 0.0, "cleanup": _strict_cleanup(7), "pid": 7,
                              "stdout": str(lp.with_suffix(".stdout.log")),
                              "stderr": str(lp.with_suffix(".stderr.log"))}
                    lp.with_suffix(".process.json").write_text(json.dumps(result), encoding="utf-8")
                    return result
                return fake

            with mock.patch("antirea.jvm_app_integration.shutil.which",
                            lambda name, path=None: "C:\\Windows\\System32\\powershell.exe"), \
                    mock.patch("antirea.process.run_logged", _capture({"INCLUDE": "i", "LIB": "l", "PATH": "p"})):
                res = m._capture_native_sdk_env(nt, out, real_stop=out / "NO_STOP")
            self.assertEqual(res["sdk_env"], {"INCLUDE": "i", "LIB": "l", "PATH": "p"})
            self.assertEqual(res["prep_entry"]["label"], "sdk-capture")
            self.assertEqual(len(res["prep_entry"]["receipt_sha256"]), 64)

            with mock.patch("antirea.jvm_app_integration.shutil.which",
                            lambda name, path=None: "C:\\Windows\\System32\\powershell.exe"), \
                    mock.patch("antirea.process.run_logged", _capture({"INCLUDE": "i", "LIB": "l", "EVIL": "x"})):
                with self.assertRaises(m.JvmIntegrateError):
                    m._capture_native_sdk_env(nt, Path(d) / "out2", real_stop=out / "NO_STOP")


# =========================================================================== #
# (H) Cross-check: the REAL service independently accepts the engine report,
# receipts/logs and deployment bundle (proves schema compatibility end to end).
# =========================================================================== #
try:
    import antirea.jvm_application as svc
    _SERVICE_IMPORT_ERROR = None
except Exception as _exc:                       # pragma: no cover - gate path
    svc = None
    _SERVICE_IMPORT_ERROR = repr(_exc)


@unittest.skipUnless(svc is not None, "service antirea.jvm_application not importable: %s" % _SERVICE_IMPORT_ERROR)
class ServiceCrossCheckTests(unittest.TestCase):
    def _producer_bits(self, fx):
        prod = json.loads(fx["report_path"].read_text())
        return prod, prod["artifacts"], prod["artifacts"]["protected"]["sha256"]

    def test_service_accepts_child_evidence_and_deployment(self):
        with _tmp() as d:
            ws = Path(d) / "ws"
            fx = build_workspace(ws)
            report = mocked_pipeline(self, ws, fx)
            out = fx["out_dir"]
            validated = m.validate_cases(CASES)
            prod, artifacts, prot_sha = self._producer_bits(fx)

            # 1. The service independently re-reads every receipt + stdout/stderr log.
            ev = svc._verify_child_evidence(report, engine_out=out, cases=validated)
            self.assertTrue(ev["authentic"], ev.get("reason"))
            self.assertTrue(ev["coverage_ok"] and ev["observations_ok"] and ev["controls_ok"] and ev["prep_ok"])
            self.assertFalse(ev["infra_failures"])

            # 2. The service independently inventories the deployment bundle.
            bundle = svc._inventory_bundle(report, engine_out=out, artifacts=artifacts,
                                           expected_native_sha=prot_sha, report=prod)
            self.assertEqual(bundle["main_class"], "sample.App")
            self.assertEqual(bundle["classpath_entries"], ["."])

    def test_service_verify_engine_report_authentic(self):
        with _tmp() as d:
            ws = Path(d) / "ws"
            fx = build_workspace(ws)
            report = mocked_pipeline(self, ws, fx)
            out = fx["out_dir"]
            validated = m.validate_cases(CASES)
            prod, artifacts, _ = self._producer_bits(fx)
            report_sha = _sha(fx["report_path"].read_bytes())
            verdict = svc._verify_engine_report(
                report, out / "integration.json", report_path=fx["report_path"],
                report_sha=report_sha, artifacts=artifacts, cases=validated,
                language="java", declared_trusted_count=0)
            self.assertTrue(verdict["authentic"], verdict.get("reason"))

    def test_service_rejects_a_non_strict_receipt(self):
        # Flip one persisted receipt to job_assigned False and confirm the service's
        # strict predicate rejects it (proves the strict contract is enforced on the
        # ACTUAL persisted bytes, not a returned boolean).
        with _tmp() as d:
            ws = Path(d) / "ws"
            fx = build_workspace(ws)
            report = mocked_pipeline(self, ws, fx)
            out = fx["out_dir"]
            validated = m.validate_cases(CASES)
            victim = report["comparison"]["commands"][0]
            rp = Path(victim["receipt_path"])
            data = json.loads(rp.read_text())
            data["cleanup"]["job_assigned"] = False
            rp.write_text(json.dumps(data), encoding="utf-8")
            ev = svc._verify_child_evidence(report, engine_out=out, cases=validated)
            self.assertFalse(ev["authentic"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
