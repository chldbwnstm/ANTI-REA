"""Owned test support for the production C# app-integration engine tests.

Synthetic-first fixtures and HONEST availability / capability gates for
``tests/test_csharp_app_integration.py``.

Scope rules enforced here (phase20 engine_tests ownership):

* This module imports the ACTUAL production engine
  (``antirea.csharp_app_integration`` + ``antirea.csharp_transform``). It never
  loads a ``.runs`` candidate module and never monkeypatches the trusted-name
  import to resolve to candidate bytes. If the production modules are not yet
  importable (the engine worker has not landed them), ``MODULES_AVAILABLE`` is
  False and the suite skips with a named gate -- it does not fake a pass.
* Fixtures are synthetic (built in a private temp dir) or read from known pinned
  owned paths only. No reserved/received path (``rea-analysis-reports``,
  ``attackerfolder``, ``defense-loop``, ``env.setting``, ``linkrepro``) is ever
  opened: reserved-name guard tests use SYNTHETIC non-existent paths so the
  lexical check is exercised without touching real private data.
* ``build_and_compare`` / ``validate`` / ``run_integration`` children run through
  the engine's own ``antirea.process.run_logged``; the whole unittest process is
  launched by the owned OUTER bounded wrapper
  ``.runs/orca-wave6-csharp-tests/driver/outer_run.py``.
"""
from __future__ import annotations

import copy
import hashlib
import inspect
import json
import os
import shutil
import sys
from pathlib import Path

# ``antirea`` must resolve to the PRODUCTION package in the repo root (never a
# .runs candidate). The tests dir is added so this support module imports.
ROOT = Path(__file__).resolve().parents[1]          # repo root (contains antirea/)
TESTS_DIR = Path(__file__).resolve().parent
for _p in (str(ROOT), str(TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# --------------------------------------------------------------------------- #
# ACTUAL production modules (availability gate, not a candidate fallback).
# --------------------------------------------------------------------------- #
IMPORT_ERROR: str | None = None
try:
    import antirea  # noqa: F401
    import antirea.csharp_app_integration as cai   # production engine
    import antirea.csharp_transform as ct          # production transform
except Exception as exc:                           # pragma: no cover - gate path
    cai = None                                     # type: ignore[assignment]
    ct = None                                      # type: ignore[assignment]
    IMPORT_ERROR = repr(exc)

MODULES_AVAILABLE = cai is not None and ct is not None

# Owned, fresh, append-only run area for this task (the outer wrapper writes
# receipts under here; tests use private temp dirs under here too).
OUT_BASE = ROOT / ".runs" / "orca-wave6-csharp-tests"

# Known pinned owned fixtures for the dotnet-gated executed-equivalence test.
SAMPLE_APP = ROOT / ".runs" / "orca-wave3-csharp" / "sample" / "app"
PRODUCER_REPORT = ROOT / ".runs" / "orca-wave2-csharp" / "build" / "producer-001" / "report.json"
# Owned public sample sources (gap #4: producer sources may live under samples,
# not only under .runs). Read-only in these tests.
SAMPLE_CSHARP_APP = ROOT / "samples" / "multilang" / "csharp_application"

# The phase20 engine.md reserved/received component contract (lexical guard).
EXPECTED_RESERVED = frozenset(
    {"rea-analysis-reports", "attackerfolder", "defense-loop", "env.setting", "linkrepro"})


# --------------------------------------------------------------------------- #
# Hashing / path helpers.
# --------------------------------------------------------------------------- #
def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_file(path) -> str:
    return sha_bytes(Path(path).read_bytes())


def production_pins() -> dict:
    """Exact on-disk SHA-256 pins of the production modules under test."""
    pins = {}
    for name in ("csharp_app_integration.py", "csharp_transform.py",
                 "dotnet_frontend.py", "source_validate.py", "bindings.py", "process.py"):
        p = ROOT / "antirea" / name
        if p.is_file():
            pins["antirea/" + name] = sha_file(p)
    return pins


# --------------------------------------------------------------------------- #
# Capability probes: distinguish the FINAL phase20 contract from the current
# (possibly intermediate / unfrozen) production bytes. A probe returning False
# means the seam is a PENDING engine-adoption gate, not a test failure.
# --------------------------------------------------------------------------- #
def seam_has_trusted_inputs(func_name: str) -> bool:
    if not MODULES_AVAILABLE:
        return False
    fn = getattr(cai, func_name, None)
    if fn is None:
        return False
    try:
        return "trusted_inputs" in inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False


def transform_reserved_components() -> frozenset:
    if not MODULES_AVAILABLE:
        return frozenset()
    return frozenset(getattr(ct, "RESERVED_PATH_COMPONENTS", ()) or ())


def app_reserved_components() -> frozenset | None:
    """The app engine's own lexical reserved set, if it exposes one yet."""
    if not MODULES_AVAILABLE:
        return None
    val = getattr(cai, "RESERVED_PATH_COMPONENTS", None)
    return frozenset(val) if val else None


def app_has_lexical_reserved_guard() -> bool:
    """True once the app engine exposes a pure-lexical reserved-name guard.

    The phase19 baseline used ``_received_guard`` with ``Path.resolve()`` (a
    filesystem traversal) and only three names; the phase20 gate requires a
    lexical guard over all five names run before any stat/read/hash.
    """
    if not MODULES_AVAILABLE:
        return False
    names = app_reserved_components()
    guard = getattr(cai, "_reserved_guard", None)
    return callable(guard) and names is not None and EXPECTED_RESERVED <= names


def dotnet_available() -> bool:
    return shutil.which("dotnet") is not None


def executed_fixtures_available() -> bool:
    return (MODULES_AVAILABLE and dotnet_available()
            and SAMPLE_APP.is_dir() and PRODUCER_REPORT.is_file())


# --------------------------------------------------------------------------- #
# Clean ALLOWLISTED environment (NOT an os.environ copy) -- mirrors the outer
# wrapper so any in-test child process is launched clean.
# --------------------------------------------------------------------------- #
def allowlisted_env(priv_tmp: Path, priv_home: Path) -> dict:
    sysroot = r"C:\Windows"
    dotnet_dir = r"C:\Program Files\dotnet"
    return {
        "SystemRoot": sysroot, "windir": sysroot, "SystemDrive": "C:",
        "PATH": os.pathsep.join([dotnet_dir, sysroot + r"\System32", sysroot]),
        "TEMP": str(priv_tmp), "TMP": str(priv_tmp),
        "USERPROFILE": str(priv_home),
        "APPDATA": str(priv_home / "AppData" / "Roaming"),
        "LOCALAPPDATA": str(priv_home / "AppData" / "Local"),
        "DOTNET_ROOT": dotnet_dir, "DOTNET_CLI_HOME": str(priv_home),
        "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
        "DOTNET_NOLOGO": "1", "DOTNET_MULTILEVEL_LOOKUP": "0",
        "NUGET_PACKAGES": str(priv_home / "nuget"),
        "PROCESSOR_ARCHITECTURE": "AMD64",
        "PYTHONPATH": str(ROOT),
    }


def real_stop_path() -> Path:
    """The real workspace defense STOP marker (existence-only; never created)."""
    return ROOT / ".runs" / "defense-loop" / "STOP"


def nonexistent_stop(tmp) -> Path:
    return Path(tmp) / "NO_STOP_sentinel"          # deliberately absent


# --------------------------------------------------------------------------- #
# Synthetic, dotnet-free, self-consistent PLAN dict. Built against the REAL
# production engine (``cai._engine_binding`` / ``cai._plan_fingerprint``), so the
# serialize/load/tamper tests exercise production logic with no child process.
# --------------------------------------------------------------------------- #
def synthetic_plan(*, app_dir: str, spec_path: str, out_dir: str) -> dict:
    """A self-consistent ``planned`` dict accepted by ``cai.load_plan``.

    Paths are absolute strings; they need not exist on disk because load_plan /
    serialize_plan validate structure + alias equality + fingerprint only.
    """
    if not MODULES_AVAILABLE:
        raise RuntimeError("production modules unavailable")
    app_dir = os.path.abspath(app_dir)
    spec_path = os.path.abspath(spec_path)
    engine_binding = cai._engine_binding()          # real trusted-name source hashes
    # Workspace identity exactly as the production engine derives it (STOP rederived
    # from the bound root; out_dir is per-run fresh and intentionally unbound).
    wr = os.path.abspath(str(ROOT))
    workspace_identity = {"workspace_root": wr,
                          "transform_module": cai.TRUSTED_TRANSFORM_MODULE,
                          "stop_relative": cai.STOP_RELATIVE,
                          "stop_file": str(cai._stop_path(wr))}
    snap = {
        "app_dir": app_dir,
        "app_sources": {"A.cs": "a" * 64, "B.cs": "b" * 64},
        "integration_spec": {"path": spec_path, "sha256": "c" * 64},
    }
    pinned = {
        "report_path": os.path.join(app_dir, "report.json"),
        "report_sha256": "1" * 64,
        "contract_path": os.path.join(app_dir, "contract.json"),
        "contract_sha256": "2" * 64,
        "protected": {"path": os.path.join(app_dir, "protected.dll"), "sha256": "3" * 64, "bytes": 10},
        "baseline": {"path": os.path.join(app_dir, "baseline.dll"), "sha256": "4" * 64, "bytes": 8},
    }
    compiler = {"input_hashes": {r"C:\dotnet\dotnet.exe": "d" * 64, r"C:\dotnet\csc.dll": "e" * 64},
                "dotnet": r"C:\dotnet\dotnet.exe", "csc": r"C:\dotnet\csc.dll"}
    selectors = [{"export": "m", "type": "N.T", "name": "M", "parameters": ["int"]}]
    fingerprint = cai._plan_fingerprint(
        snap, pinned, cai._compiler_digest(compiler["input_hashes"]), selectors,
        engine_binding, workspace_identity)
    return {
        "status": "planned",
        "schema_version": cai.PLAN_SCHEMA_VERSION,
        "pinned": pinned,
        "identity": {"status": "identity_confirmed", "evidence": "synthetic_plan_fixture", "methods": []},
        "compiler": compiler,
        "receipt_binding": {"protected": pinned["protected"], "baseline": pinned["baseline"],
                            "provenance": "synthetic_reused_fixture", "fresh_protected_native_build": False},
        "selectors": selectors,
        "input_snapshot": snap,
        "engine_binding": engine_binding,
        "transform_module": cai.TRUSTED_TRANSFORM_MODULE,
        "workspace_identity": workspace_identity,
        "plan_fingerprint": fingerprint,
        "app_dir": app_dir,
        "integration_spec_path": spec_path,
        "workspace": {"workspace_root": workspace_identity["workspace_root"],
                      "out_dir": os.path.abspath(out_dir),
                      "transform_module": cai.TRUSTED_TRANSFORM_MODULE,
                      "stop_file": workspace_identity["stop_file"]},
    }


def clone(obj):
    return copy.deepcopy(obj)


# --------------------------------------------------------------------------- #
# Minimal valid C# app + integration spec + contract for the TRANSFORM byte-
# preservation test (one selected call-free integer leaf, one UNSELECTED file).
# --------------------------------------------------------------------------- #
SELECTED_FILE = "A.cs"
UNSELECTED_FILE = "B.cs"

SELECTED_SRC = (
    "namespace N;\n"
    "public class T {\n"
    "    // selected call-free integer leaf\n"
    "    public static int M(int a) { return a; }\n"
    "}\n"
)
UNSELECTED_SRC = (
    "namespace N;\n"
    "public class Helper {\n"
    "    public static int Keep(int b) { return b + 1; }\n"
    "    /* untouched comment */\n"
    "    public static string Note() { return \"kept\"; }\n"
    "}\n"
)


def write_transform_app(app_dir: Path) -> dict:
    """Write the minimal app + spec + contract. Returns {paths, raw bytes}."""
    app_dir.mkdir(parents=True, exist_ok=True)
    a = app_dir / SELECTED_FILE
    b = app_dir / UNSELECTED_FILE
    a.write_text(SELECTED_SRC, encoding="utf-8", newline="")
    b.write_text(UNSELECTED_SRC, encoding="utf-8", newline="")
    spec = {"schema_version": 1, "sources": [SELECTED_FILE, UNSELECTED_FILE],
            "methods": [{"type": "N.T", "name": "M", "parameters": ["int"], "export": "m"}]}
    contract = {"schema_version": 1, "library_name": "antirea_contract",
                "functions": [{"name": "m", "return_type": "i32",
                               "parameters": [{"name": "a0", "type": "i32"}]}]}
    spec_path = app_dir / "integration.json"
    contract_path = app_dir / "contract.json"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    contract_path.write_text(json.dumps(contract), encoding="utf-8")
    return {"app_dir": app_dir, "selected": a, "unselected": b,
            "spec_path": spec_path, "contract_path": contract_path,
            "selected_raw": a.read_bytes(), "unselected_raw": b.read_bytes()}


# --------------------------------------------------------------------------- #
# Environmental capability probes (NOT feature gates): symlink creation needs OS
# privilege on Windows, so a guard test that must *create* a symlink to exercise
# the (required) rejection is qualified on this capability for fresh clones. The
# guard itself is also covered by reserved / non-regular / over-limit cases that
# always run.
# --------------------------------------------------------------------------- #
def can_symlink() -> bool:
    import tempfile
    try:
        with tempfile.TemporaryDirectory() as d:
            tgt = os.path.join(d, "t"); open(tgt, "w").close()
            lnk = os.path.join(d, "l")
            os.symlink(tgt, lnk)
            return os.path.islink(lnk)
    except (OSError, NotImplementedError, AttributeError):
        return False


def outside_workspace_dir():
    """A temp dir OUTSIDE the owned workspace root (for 'escapes workspace' tests).

    Uses the OS temp area (system scratch, not under the repo). Returned as a
    TemporaryDirectory context manager. Only synthetic files are placed here.
    """
    import tempfile
    return tempfile.TemporaryDirectory(prefix="w6_outside_")


# --------------------------------------------------------------------------- #
# Synthetic producer report builder (for load_producer_report gap #4 regressions).
# Writes report.json + baseline/protected DLL bytes + contract.json under
# ``build_dir`` (which must be under workspace/.runs). ``sources`` is a list of
# (abs_source_path, claimed_sha_or_None); None uses the real on-disk sha. No real
# producer bytes are consumed; nothing is executed.
# --------------------------------------------------------------------------- #
def fake_producer_report(build_dir: Path, *, sources, status="artifact_created_unvalidated",
                         backend="dotnet_il_native"):
    build_dir = Path(build_dir)
    build_dir.mkdir(parents=True, exist_ok=True)
    baseline = b"BASELINE-DLL-BYTES"
    protected = b"PROTECTED-DLL-BYTES-longer-payload"
    (build_dir / "baseline.dll").write_bytes(baseline)
    (build_dir / "protected.dll").write_bytes(protected)
    contract = {"schema_version": 1, "library_name": "antirea_contract",
                "functions": [{"name": "m", "return_type": "i32",
                               "parameters": [{"name": "a0", "type": "i32"}]}]}
    (build_dir / "contract.json").write_text(json.dumps(contract), encoding="utf-8")
    source_hashes = {}
    for abs_source, claimed in sources:
        abs_source = str(abs_source)
        source_hashes[abs_source] = claimed if claimed is not None else sha_file(abs_source)
    report = {
        "schema_version": 1, "status": status, "backend": backend,
        "artifacts": {"baseline": {"path": str(build_dir / "baseline.dll"), "sha256": sha_bytes(baseline)},
                      "protected": {"path": str(build_dir / "protected.dll"), "sha256": sha_bytes(protected)}},
        "contract_path": str(build_dir / "contract.json"),
        "source_hashes": source_hashes,
        "frontend": {
            "source_hashes": source_hashes,
            "compiler_inputs": {str(build_dir / "fake-dotnet.exe"): "d" * 64},
            "project": {"sources": [str(s) for s, _ in sources]},
            "methods": [],
        },
    }
    report_path = build_dir / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    return report_path


# A route-control value case whose own expectation does NOT constrain stdout to an
# integer (gap #5): the engine must derive the control argv from an explicit
# returncode==0 value case, not a hardcoded ['7','3'] / integer-stdout rule.
ROUTE_CONTROL_CASES = [
    {"label": "ctl(4,2)", "kind": "value", "args": [4, 2], "expect": {"returncode": 0}},
    {"label": "e(usage)", "kind": "exception", "args": [], "expect": {"returncode": 2}},
    {"label": "e(nonnumeric)", "kind": "exception", "args": ["abc", "3"],
     "expect": {"exception": "System.FormatException"}},
]
