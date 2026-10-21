"""Production-shaped shared support for the owned-fixture TypeScript mixed-module
VALIDATION tests (tests/test_typescript_mixed_validate*.py).

Run each test file with:  C:/Python313/python.exe -I -S -B <test_file>.py

This module imports the PRODUCTION engine directly as
``antirea.javascript_mixed_validate`` (the same engine validates JavaScript and
TypeScript mixed builds) and uses the PRODUCTION per-arm runner
``tools/javascript_frontend/mixed_run_arm.cjs`` resolved from that module's own
``_RUNNER``. It never loads a candidate file, and it never injects any module
into ``sys.modules`` as the implementation under test. The owned TypeScript
sample package is embedded here as source literals, so these tests have NO
dependency on any ``.runs/`` wave directory.

No production file is modified by these tests. Every test runs in its own fresh
temp workspace, so the real defense-loop controller/STOP under the project is
never written; the real repository ``.runs/defense-loop/STOP`` is only ever read,
as the cancel marker for every bounded child process.

TypeScript actual-execution validation additionally requires the independent
reference-compiler helper (``antirea.typescript_reference`` +
``tools/typescript_frontend/mixed_reference.cjs``). Until that helper is staged
by its owning worker, the execution tests gate themselves off with
``ts_reference_ready()`` and skip; the contract/boundary refusals below are
reached before the helper is imported and run regardless.
"""
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve()
REPO = HERE.parents[1]                                   # repository root (parent of tests/)

# Import the real production package + engine. No candidate is loaded and nothing
# is installed into sys.modules; ``from .process import run_logged`` /
# ``from . import javascript_frontend`` inside the engine reuse the real package.
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
import antirea  # noqa: E402,F401
from antirea.process import run_logged  # noqa: E402
import antirea.javascript_mixed_validate as V  # noqa: E402

RUNNER = V._RUNNER                                       # production per-arm runner (never a copy)
STOP = REPO / ".runs" / "defense-loop" / "STOP"          # real repo cancel marker (read-only)

TS_CONTRACT_KIND = "typescript_mixed_module_application_samples"
JS_CONTRACT_KIND = "javascript_mixed_module_application_samples"


def load_validate():
    """Return the production engine module (symmetry with the JS harness; it
    performs no sys.modules injection and always returns production)."""
    return V


def load_builder():
    from antirea import javascript_mixed_module as builder
    return builder


# ---------------------------------------------------------------------------
# Embedded owned TypeScript sample package (byte source, not read from .runs)
# ---------------------------------------------------------------------------
# One owned TypeScript module with: a runtime enum and a runtime namespace
# (emitted as ordinary JavaScript, preserved unselected), a JavaScript sibling it
# imports, one selected pure scalar root (``core``) and its reachable owned helper
# (``sq``), a preserved scalar caller (``combo``) that invokes the virtualized
# ``core``, a preserved scalar caller (``small``) that invokes the JS sibling,
# ordinary UI exports and a benign top-level module-load call. ``core``/``sq``
# load no module-global values, so they fit the virtualized scalar subset; the
# enum/namespace/import stay as preserved runtime code.
SAMPLE_INDEX_TS = (
    'import { isSmall } from "./lib/util.js";\n'
    "\n"
    "export enum Colour {\n"
    "  Red,\n"
    "  Green,\n"
    "  Blue,\n"
    "}\n"
    "\n"
    "export namespace Geometry {\n"
    "  export const TAU = 6;\n"
    "  export function ring(n: number): number {\n"
    "    return n * TAU;\n"
    "  }\n"
    "}\n"
    "\n"
    "function sq(x: number): number {\n"
    "  return x * x;\n"
    "}\n"
    "\n"
    "export function core(x: number): number {\n"
    "  return sq(x) + 1;\n"
    "}\n"
    "\n"
    "export function combo(x: number): number {\n"
    "  return core(x) + core(x);\n"
    "}\n"
    "\n"
    "export function small(n: number): boolean {\n"
    "  return isSmall(n);\n"
    "}\n"
    "\n"
    'export const label: string = "ui-" + Colour[Colour.Red];\n'
    "\n"
    "const boot: number = Geometry.ring(1);\n"
    "export { boot };\n"
)

SAMPLE_UTIL_JS = (
    "'use strict';\n"
    "\n"
    "function isSmall(n) {\n"
    "  return n < 100;\n"
    "}\n"
    "\n"
    "module.exports = { isSmall };\n"
)

SAMPLE_PACKAGE_JSON = (
    '{\n'
    '  "name": "antirea-wave5-ts-sample-app",\n'
    '  "version": "0.0.0",\n'
    '  "private": true,\n'
    '  "type": "commonjs"\n'
    '}\n'
)

SAMPLE_PROJECT_JSON = json.dumps(
    {"schema_version": 1, "name": "wave5-ts-app", "language": "typescript",
     "sources": ["index.ts"], "functions": ["core"],
     "protection_mode": "mixed_module"},
    indent=2) + "\n"


def write_sample_ts(dest):
    """Materialise the embedded owned TypeScript sample package into a fresh dir."""
    dest = Path(dest)
    (dest / "lib").mkdir(parents=True, exist_ok=False)
    (dest / "index.ts").write_text(SAMPLE_INDEX_TS, encoding="utf-8")
    (dest / "lib" / "util.js").write_text(SAMPLE_UTIL_JS, encoding="utf-8")
    (dest / "package.json").write_text(SAMPLE_PACKAGE_JSON, encoding="utf-8")
    (dest / "project.json").write_text(SAMPLE_PROJECT_JSON, encoding="utf-8")
    return dest


# ---------------------------------------------------------------------------
# Hash + wire helpers
# ---------------------------------------------------------------------------

def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def bom_normalized_sha(text):
    """SHA-256 after the exact UTF-8 BOM normalisation the engine applies to the
    bound original source (``decode('utf-8-sig').encode('utf-8')``)."""
    normalized = text.encode("utf-8").decode("utf-8-sig").encode("utf-8")
    return hashlib.sha256(normalized).hexdigest()


def num_bits(value):
    return struct.pack(">d", float(value)).hex()


def node_path():
    return load_builder().discover_toolchain()["files"]["node"]["path"]


def node_pin():
    node = Path(node_path())
    return {"path": str(node), "sha256": hashlib.sha256(node.read_bytes()).hexdigest()}


def clean_env(private_temp):
    """The engine's strict allow-listed child environment (NOT an os.environ copy),
    with a private TEMP -- used for the bounded focused-test runner."""
    Path(private_temp).mkdir(parents=True, exist_ok=True)
    allow = ("SystemRoot", "SystemDrive", "windir", "NUMBER_OF_PROCESSORS",
             "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "COMSPEC", "PATHEXT",
             "LANG", "LC_ALL", "LC_CTYPE", "TZ")
    env = {k: os.environ[k] for k in allow if k in os.environ}
    if os.name == "nt":
        system_root = env.get("SystemRoot") or env.get("windir") or "C:\\Windows"
        env["PATH"] = os.pathsep.join([str(Path(system_root) / "System32"), str(Path(system_root))])
    else:
        env["PATH"] = "/usr/bin:/bin"
    env["TEMP"] = env["TMP"] = env["TMPDIR"] = str(private_temp)
    return env


# ---------------------------------------------------------------------------
# TypeScript reference-helper readiness probe (gates the execution tests)
# ---------------------------------------------------------------------------

def ts_reference_ready():
    """True only when the independent TypeScript reference helper is staged AND
    its declared tool pins point at existing files. The execution tests skip
    until this holds; they run for real once the helper's owner stages it."""
    try:
        from antirea import typescript_reference
    except Exception:
        return False
    helper_tool_pins = getattr(typescript_reference, "helper_tool_pins", None)
    build_reference = getattr(typescript_reference, "build_reference", None)
    if not callable(helper_tool_pins) or not callable(build_reference):
        return False
    try:
        pins = helper_tool_pins()
    except Exception:
        return False
    if not isinstance(pins, list) or not pins:
        return False
    for pin in pins:
        if not isinstance(pin, dict) or "path" not in pin:
            return False
        try:
            if not Path(pin["path"]).is_file():
                return False
        except (OSError, ValueError):
            return False
    return True


# ---------------------------------------------------------------------------
# Real end-to-end build of the owned TS sample (production builder; never runs it)
# ---------------------------------------------------------------------------

def build_sample_ts(workspace, *, seed=20261020):
    """Copy the owned TS sample into a temp workspace and build it with the
    production mixed-module builder (owned source; the builder transpiles the
    whole module to CommonJS and never executes it)."""
    workspace = Path(workspace)
    app = workspace / "app"
    write_sample_ts(app)
    builder = load_builder()
    out = workspace / ".runs" / "build"
    report = builder.build_project(str(app / "project.json"), str(out),
                                   workspace_root=str(workspace), seed=seed)
    report_path = out / "report.json"
    return {"report": report, "report_path": report_path, "app": app, "output": out}


# ---------------------------------------------------------------------------
# Synthetic (hand-built) owned TypeScript build for the pre-execution refusals
# (contract-kind, contract-source, coverage-flag, original-hash, runtime .cjs
#  collision, extra-TS sibling). These reach their refusal BEFORE the engine
# imports the reference helper, so they do not need it and start no process.
# ---------------------------------------------------------------------------

def synth_ts_coverage(selected, closure, preserved, *, original_sha, working_sha,
                      transpiled=True):
    return {"schema_version": 1, "backend": "javascript_mixed_module_vm",
            "protection_mode": "mixed_module",
            "original_module_source_sha256": original_sha, "working_source_sha256": working_sha,
            "transpiled_typescript": transpiled,
            "selected_functions": list(selected), "exported_functions": list(closure),
            "helper_closure": list(closure), "preserved_unprotected_functions": list(preserved),
            "functions": {name: {"virtualized": True, "parameters": []} for name in closure}}


def make_synthetic_ts(workspace, *, module_relative="index.ts",
                      ts_text=None, baseline_cjs_text="'use strict';\nmodule.exports={};\n",
                      protected_cjs_text="'use strict';\nmodule.exports={};\n",
                      selected=("core",), closure=("core", "sq"), preserved=("combo",),
                      extra_files=None, transpiled=True,
                      original_sha=None, working_sha=None):
    """Write an owned TS package + two ``.cjs`` arm artifacts + a passing-shaped
    build report whose project language is ``typescript``.

    The owned ``.ts`` original and the coverage ``original_module_source_sha256``
    are bound honestly (BOM-normalised SHA-256 of the written source) unless the
    caller overrides ``original_sha`` to exercise the original-identity refusal.
    The arm ``.cjs`` artifacts are owned fixtures controlled by this test author;
    they are never produced by any attack path and are only read, never executed,
    on the refusal paths these fixtures drive.
    """
    workspace = Path(workspace)
    app = workspace / "app"
    (app / Path(module_relative).parent).mkdir(parents=True, exist_ok=True)
    if ts_text is None:
        ts_text = ("export function core(x: number): number { return x + 1; }\n"
                   "export function combo(x: number): number { return core(x); }\n")
    # Write in BINARY so there is no newline translation and the on-disk bytes equal
    # ``ts_text.encode('utf-8')``; the bound original hash then truly matches.
    (app / module_relative).write_bytes(ts_text.encode("utf-8"))
    (app / "package.json").write_bytes(b'{"type":"commonjs"}')
    for rel, text in (extra_files or {}).items():
        (app / Path(rel).parent).mkdir(parents=True, exist_ok=True)
        (app / rel).write_bytes(text.encode("utf-8"))
    artifacts_dir = workspace / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    baseline_cjs = artifacts_dir / "baseline.cjs"
    protected_cjs = artifacts_dir / "protected.cjs"
    baseline_cjs.write_bytes(baseline_cjs_text.encode("utf-8"))
    protected_cjs.write_bytes(protected_cjs_text.encode("utf-8"))
    coverage = synth_ts_coverage(
        selected, closure, preserved, transpiled=transpiled,
        original_sha=original_sha if original_sha is not None else bom_normalized_sha(ts_text),
        working_sha=working_sha if working_sha is not None else sha256_text("working-placeholder"))
    report = {"schema_version": 1, "status": "artifact_created_unvalidated",
              "backend": "javascript_mixed_module_vm", "protection_mode": "mixed_module",
              "project": {"project_root": str(app), "sources": [str(app / module_relative)],
                          "language": "typescript"},
              "artifacts": {"baseline": {"path": str(baseline_cjs), "sha256": sha256_bytes(baseline_cjs.read_bytes()),
                                         "bytes": baseline_cjs.stat().st_size},
                            "protected": {"path": str(protected_cjs), "sha256": sha256_bytes(protected_cjs.read_bytes()),
                                          "bytes": protected_cjs.stat().st_size}},
              "coverage": coverage, "toolchain": {"files": {"node": node_pin()}}}
    build_dir = workspace / "build"
    build_dir.mkdir(parents=True, exist_ok=True)
    report_path = build_dir / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    return {"report_path": report_path, "report": report, "app": app, "module_relative": module_relative}


def make_synthetic_js_min(workspace, *, module_relative="index.js",
                          selected=("f",), closure=("f",), preserved=()):
    """A minimal owned JavaScript synthetic build (language=javascript) used only
    to prove a TypeScript contract cannot authorize a JavaScript build. The engine
    rejects the cross-language kind right after deriving the module, before the
    JS baseline-equality or toolchain checks, so this stays deliberately minimal."""
    workspace = Path(workspace)
    app = workspace / "jsapp"
    (app / Path(module_relative).parent).mkdir(parents=True, exist_ok=True)
    js_text = "'use strict';\nfunction f(x){return x;}\nmodule.exports={f};\n"
    (app / module_relative).write_bytes(js_text.encode("utf-8"))
    (app / "package.json").write_bytes(b'{"type":"commonjs"}')
    artifacts_dir = workspace / "jsartifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    baseline_cjs = artifacts_dir / "baseline.cjs"
    protected_cjs = artifacts_dir / "protected.cjs"
    baseline_cjs.write_bytes(js_text.encode("utf-8"))
    protected_cjs.write_bytes(js_text.encode("utf-8"))
    coverage = {"schema_version": 1, "backend": "javascript_mixed_module_vm",
                "protection_mode": "mixed_module",
                "original_module_source_sha256": bom_normalized_sha(js_text),
                "working_source_sha256": sha256_text(js_text),
                "transpiled_typescript": False,
                "selected_functions": list(closure), "exported_functions": list(closure),
                "helper_closure": list(closure), "preserved_unprotected_functions": list(preserved),
                "functions": {name: {"virtualized": True} for name in closure}}
    report = {"schema_version": 1, "status": "artifact_created_unvalidated",
              "backend": "javascript_mixed_module_vm", "protection_mode": "mixed_module",
              "project": {"project_root": str(app), "sources": [str(app / module_relative)],
                          "language": "javascript"},
              "artifacts": {"baseline": {"path": str(baseline_cjs), "sha256": sha256_bytes(baseline_cjs.read_bytes()),
                                         "bytes": baseline_cjs.stat().st_size},
                            "protected": {"path": str(protected_cjs), "sha256": sha256_bytes(protected_cjs.read_bytes()),
                                          "bytes": protected_cjs.stat().st_size}},
              "coverage": coverage, "toolchain": {"files": {"node": node_pin()}}}
    build_dir = workspace / "jsbuild"
    build_dir.mkdir(parents=True, exist_ok=True)
    report_path = build_dir / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    return {"report_path": report_path, "report": report, "app": app, "module_relative": module_relative}


# ---------------------------------------------------------------------------
# Contract writer (new first-class TypeScript contract kind)
# ---------------------------------------------------------------------------

def write_ts_contract(path, *, source="index.ts", entrypoints, preserved=None):
    contract = {"schema_version": 1, "kind": TS_CONTRACT_KIND,
                "source": source, "entrypoints": entrypoints,
                "preserved_entrypoints": preserved or []}
    Path(path).write_text(json.dumps(contract), encoding="utf-8")
    return contract


def num_param(name, lo, hi):
    return {"name": name, "type": "number", "minimum": lo, "maximum": hi}


# Canonical sampling contract for the embedded sample: select ``core`` (a
# virtualized root), preserve ``combo`` (an unselected caller that invokes the
# virtualized ``core`` through its wrapper).
SAMPLE_ENTRYPOINTS = [{"name": "core", "parameters": [num_param("x", -50, 50)]}]
SAMPLE_PRESERVED = [{"name": "combo", "parameters": [num_param("x", -50, 50)]}]
