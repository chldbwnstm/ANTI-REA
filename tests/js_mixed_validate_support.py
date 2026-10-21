"""Production-shaped shared support for the owned-fixture JavaScript mixed-module
VALIDATION tests (tests/test_javascript_mixed_validate*.py).

Run each test file with:  C:/Python313/python.exe -I -S -B <test_file>.py

This module imports the PRODUCTION engine directly as
``antirea.javascript_mixed_validate`` and uses the PRODUCTION per-arm runner
``tools/javascript_frontend/mixed_run_arm.cjs`` resolved from that module's own
``_RUNNER``. It never loads a candidate file, and it never injects any module
into ``sys.modules``. The owned sample package is embedded here as source
literals, so these tests have NO dependency on any ``.runs/`` wave directory.

No production file is modified by these tests. Every test runs in its own fresh
temp workspace, so the real defense-loop controller/STOP under the project is
never written; the real repository ``.runs/defense-loop/STOP`` is only ever read,
as the cancel marker for every bounded child process.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
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

# The production per-arm runner, resolved from the engine itself (never a copy).
RUNNER = V._RUNNER
STOP = REPO / ".runs" / "defense-loop" / "STOP"          # real repo cancel marker (read-only)


def load_validate():
    """Return the production engine module. Present for symmetry with the old
    harness; it performs no sys.modules injection and always returns production."""
    return V


def load_builder():
    from antirea import javascript_mixed_module as builder
    return builder


# ---------------------------------------------------------------------------
# Embedded owned sample package (byte source, not read from any .runs tree)
# ---------------------------------------------------------------------------
# Owned CommonJS sample: every entry in FUNCTIONS below is a pure
# Number/BigInt/boolean function over its parameters, inline literals and owned
# helpers -- the subset the mixed-module builder virtualizes. ``describe`` is
# deliberately NOT virtualized; it stays plaintext and is sampled as a preserved
# entrypoint. ``sq`` is a reachable helper, discovered into the closure.
SAMPLE_INDEX_JS = (
    "'use strict';\n"
    "\n"
    "const util = require('./lib/util.js');\n"
    "\n"
    "function sq(x) {\n"
    "  return x * x;\n"
    "}\n"
    "\n"
    "function fadd(a, b) {\n"
    "  return a + b;\n"
    "}\n"
    "\n"
    "function fmul(a, b) {\n"
    "  return a * b;\n"
    "}\n"
    "\n"
    "function frecip(x) {\n"
    "  return 1 / x;\n"
    "}\n"
    "\n"
    "function quad(x) {\n"
    "  return sq(x) + sq(x);\n"
    "}\n"
    "\n"
    "function bigadd(a, b) {\n"
    "  return a + b;\n"
    "}\n"
    "\n"
    "function bigmul(a, b) {\n"
    "  return a * b;\n"
    "}\n"
    "\n"
    "function isposz(x) {\n"
    "  return x === 0 && 1 / x > 0;\n"
    "}\n"
    "\n"
    "function mix(a, b) {\n"
    "  return a + b;\n"
    "}\n"
    "\n"
    "function describe(n) {\n"
    "  return util.isSmall(n);\n"
    "}\n"
    "\n"
    "module.exports = { fadd, fmul, frecip, quad, bigadd, bigmul, isposz, mix, describe };\n"
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
    '  "name": "antirea-wave4-sample-app",\n'
    '  "version": "0.0.0",\n'
    '  "private": true,\n'
    '  "type": "commonjs"\n'
    '}\n'
)

SAMPLE_FUNCTIONS = ["fadd", "fmul", "frecip", "quad", "bigadd", "bigmul", "isposz", "mix"]

SAMPLE_PROJECT_JSON = json.dumps(
    {"schema_version": 1, "name": "wave4-sample-app", "language": "javascript",
     "sources": ["index.js"], "functions": list(SAMPLE_FUNCTIONS),
     "protection_mode": "mixed_module"},
    indent=2) + "\n"


def write_sample_app(dest):
    """Materialise the embedded owned sample package into a fresh directory."""
    dest = Path(dest)
    (dest / "lib").mkdir(parents=True, exist_ok=False)
    (dest / "index.js").write_text(SAMPLE_INDEX_JS, encoding="utf-8")
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
    """SHA-256 of ``text`` after the exact UTF-8 BOM normalisation the engine's
    baseline-equality check performs (``decode('utf-8-sig').encode('utf-8')``),
    so synthetic coverage binds the true owned original source, not a placeholder."""
    normalized = text.encode("utf-8").decode("utf-8-sig").encode("utf-8")
    return hashlib.sha256(normalized).hexdigest()


def working_source_sha(text):
    """Hash the pre-VM source, excluding BOM and leading shebang like the builder."""
    source = text.encode("utf-8").decode("utf-8-sig").encode("utf-8")
    if source.startswith(b"#!"):
        newline = source.find(b"\n")
        source = b"" if newline < 0 else source[newline + 1:]
    return hashlib.sha256(source).hexdigest()


def num_bits(value):
    return struct.pack(">d", float(value)).hex()


def arg_num(value):
    return {"t": "number", "bits": num_bits(value)}


def arg_num_bits(bits):
    return {"t": "number", "bits": bits}


def arg_big(value):
    return {"t": "bigint", "v": str(value)}


def arg_bool(value):
    return {"t": "boolean", "v": bool(value)}


def node_path():
    return load_builder().discover_toolchain()["files"]["node"]["path"]


def node_pin():
    node = Path(node_path())
    return {"path": str(node), "sha256": hashlib.sha256(node.read_bytes()).hexdigest()}


def clean_env(private_temp):
    """Mirror the engine's strict allow-listed child environment for direct runner
    tests, so they too run in a clean, bounded environment with a private TEMP."""
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


def stage(src_dir, module_relative, artifact_bytes, dest_stage):
    """Copy an owned package tree into a fresh stage and swap the module file."""
    dest_stage = Path(dest_stage)
    shutil.copytree(src_dir, dest_stage)
    target = dest_stage / module_relative
    target.write_bytes(artifact_bytes)
    return target


def run_runner(stage_root, target, functions, cases, workdir, *, timeout=60, env=None,
               target_sha256=None):
    """Run the PRODUCTION per-arm runner in a separate clean, bounded process via
    run_logged, with the real workspace STOP as the cancel marker and verified
    Windows Job process-tree cleanup -- the same lifecycle actual validation uses.

    ``target_sha256`` overrides the pinned target hash (for the pin-mismatch test);
    otherwise it is computed from the staged target bytes."""
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    pinned = target_sha256 if target_sha256 is not None else hashlib.sha256(Path(target).read_bytes()).hexdigest()
    request = {"stage_root": str(stage_root), "target": str(target),
               "target_sha256": pinned,
               "module_relative": str(Path(target).relative_to(stage_root)).replace("\\", "/"),
               "functions": functions, "cases": cases}
    request_path = workdir / "arm.request.json"
    request_path.write_text(json.dumps(request), encoding="utf-8")
    if env is None:
        env = clean_env(workdir / "tmp")
    command = [node_path(), "--no-addons", "--max-old-space-size=256", str(RUNNER), str(request_path)]
    proc = run_logged(command, workdir, workdir / "runner", timeout, env=env, cancel_file=STOP)
    cleanup = proc.get("cleanup", {})
    if os.name == "nt" and not (cleanup.get("job_assigned")
                                and cleanup.get("parent_exit_confirmed")
                                and cleanup.get("job_handle_closed")
                                and cleanup.get("active_after") == 0
                                and cleanup.get("status") == "assigned_job_empty"):
        raise RuntimeError("direct runner test process cleanup was not verified: " + json.dumps(cleanup))
    if proc.get("cancelled") or proc.get("timed_out"):
        raise RuntimeError("direct runner test was cancelled or timed out")
    reply_path = workdir / "arm.reply.json"
    reply = json.loads(reply_path.read_text(encoding="utf-8")) if reply_path.exists() else None
    return {"returncode": proc["returncode"],
            "stdout": Path(proc["stdout"]).read_text(encoding="utf-8"),
            "stderr": Path(proc["stderr"]).read_text(encoding="utf-8"),
            "reply": reply, "process": proc}


# ---------------------------------------------------------------------------
# Real end-to-end build of the owned sample (production builder; never executes it)
# ---------------------------------------------------------------------------

def build_sample(workspace, *, seed=20261020):
    """Copy the owned sample into a temp workspace and build it with the production
    mixed-module builder (owned source; the builder never executes it)."""
    workspace = Path(workspace)
    app = workspace / "app"
    write_sample_app(app)
    builder = load_builder()
    out = workspace / ".runs" / "build"
    report = builder.build_project(str(app / "project.json"), str(out), workspace_root=str(workspace), seed=seed)
    report_path = out / "report.json"
    return {"report": report, "report_path": report_path, "app": app, "output": out}


# ---------------------------------------------------------------------------
# Synthetic (hand-built) owned build for mismatch / timeout / STOP / drift
# ---------------------------------------------------------------------------

def synth_coverage(selected, closure, preserved, *, transpiled=False,
                   original_sha="0" * 64, working_sha="0" * 64):
    """Builder-shaped mixed coverage.

    ``original_sha`` / ``working_sha`` default to a structurally-valid hex64
    placeholder for the pure ``_verify_mixed_coverage`` unit tests, which never
    invoke the engine's baseline-equality check. ``make_synthetic`` always passes
    the TRUE BOM-normalised hash of the owned original source it writes, so the
    full validate_build path binds real source and never bypasses that check."""
    return {"schema_version": 1, "backend": "javascript_mixed_module_vm", "protection_mode": "mixed_module",
            "original_module_source_sha256": original_sha, "working_source_sha256": working_sha,
            "transpiled_typescript": transpiled,
            "selected_functions": list(selected), "exported_functions": list(closure),
            "helper_closure": list(closure), "preserved_unprotected_functions": list(preserved),
            "functions": {name: {"virtualized": True, "parameters": []} for name in closure}}


def make_synthetic(workspace, *, module_relative, baseline_text, protected_text,
                   selected, closure, preserved, extra_files=None):
    """Write an owned package + two artifact modules + a passing build report.

    The baseline arm artifact IS the owned original module source, and the coverage
    binds the TRUE BOM-normalised SHA-256 of that source, so the engine's stricter
    original-source baseline-equality check is satisfied honestly (never bypassed).

    baseline_text/protected_text are owned .cjs sources this test author controls;
    they are NOT produced by any attack path and are only ever run as owned fixtures.
    """
    workspace = Path(workspace)
    app = workspace / "app"
    (app / Path(module_relative).parent).mkdir(parents=True, exist_ok=True)
    # Write in BINARY so there is no newline translation: the bytes on disk equal
    # ``*_text.encode('utf-8')``, so the coverage hash bound below truly matches the
    # owned original the engine re-reads (text-mode writes would become CRLF on
    # Windows and silently diverge from the bound hash).
    (app / module_relative).write_bytes(baseline_text.encode("utf-8"))
    (app / "package.json").write_bytes(b'{"type":"commonjs"}')
    for rel, text in (extra_files or {}).items():
        (app / Path(rel).parent).mkdir(parents=True, exist_ok=True)
        (app / rel).write_bytes(text.encode("utf-8"))
    artifacts_dir = workspace / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    baseline_cjs = artifacts_dir / "baseline.cjs"
    protected_cjs = artifacts_dir / "protected.cjs"
    # The baseline artifact equals the owned original module byte-for-byte.
    baseline_cjs.write_bytes(baseline_text.encode("utf-8"))
    protected_cjs.write_bytes(protected_text.encode("utf-8"))
    coverage = synth_coverage(selected, closure, preserved,
                              original_sha=bom_normalized_sha(baseline_text),
                              working_sha=working_source_sha(baseline_text))
    report = {"schema_version": 1, "status": "artifact_created_unvalidated",
              "backend": "javascript_mixed_module_vm", "protection_mode": "mixed_module",
              "project": {"project_root": str(app), "sources": [str(app / module_relative)],
                          "language": "javascript"},
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


def write_contract(path, *, source, entrypoints, preserved=None):
    contract = {"schema_version": 1, "kind": "javascript_mixed_module_application_samples",
                "source": source, "entrypoints": entrypoints, "preserved_entrypoints": preserved or []}
    Path(path).write_text(json.dumps(contract), encoding="utf-8")
    return contract
