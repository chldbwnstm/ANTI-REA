"""Self-contained producer-bound ordinary JVM application integration (phase 21).

This is the reusable EXECUTION ENGINE lane of the explicit JVM source-integrate
seam. A separated pure scalar CORE project is first produced by
``antirea.jvm_frontend`` (int/long static roots lowered to a protected native
shared library). An ORDINARY application (Java or Kotlin) that lives in the same
fingerprinted project tree is compiled against the ORIGINAL core classes; its
bytecode is preserved unchanged. The PROTECTED bundle substitutes generated,
same-name facade classes that forward each original public static root descriptor
through packaged JNI bindings (``antirea.runtime.NativeCore`` + a JNI adapter DLL)
to the pinned protected native core, and the engine proves -- by re-deriving every
pin from on-disk bytes -- that an original/protected sample comparison ran against
exactly the staged source, generated runtime and native artifacts.

Lane boundary (defender-only, engine lane):
  * The pure parsing/generation/checking of facades is owned by the in-package
    module ``antirea.jvm_facade`` (the facade lane), loaded ONLY by that trusted
    name (``importlib.import_module``) -- never from a caller-supplied path and
    never with ``sys.path`` injection. It is bound by on-disk source hash and is
    NOT executed at plan time.
  * The protected/baseline native core is a REUSED pinned ``jvm_frontend`` producer
    artifact, re-hashed from disk; this engine NEVER re-runs the IL->native
    protection, so ``fresh_protected_native_build`` is always False.
  * Only the freshly staged ordinary caller, the generated facade/runtime classes
    and the JNI adapter DLL are compiled here, through the OUTER bounded
    ``antirea.process.run_logged`` child harness.

Native JNI compile environment (root-reviewed reuse, phase21):
  * The trusted native toolchain is discovered via ``antirea.native_build._toolchain``
    (the fixed trusted Visual Studio developer shell pinned in
    ``.tools/kagura-toolchain.json``), and the SDK search-path environment is
    captured FRESH through that developer shell, exporting ONLY the allowlisted
    SDK variables (INCLUDE/LIB/LIBPATH/PATH/VC*/WindowsSdk*/UCRT*). No historical
    ``env.setting`` and no historical ``LINKREPRO`` are read, inventoried or
    consumed. The consumed JDK ``include/jni.h`` + ``include/win32/jni_md.h`` and
    the ``cl.exe``/``link.exe`` identity are pinned, honestly scoped.

Scope / non-claims (fail closed, never overclaim):
  * Installed JDK/Kotlin/Kagura/MSVC toolchains + owned source only. No install,
    download, restore, publish or push. Received code is never executed.
  * Child processes are bounded, run under a minimal private allowlisted env and
    are cleaned up. Windows Job cleanup is cleanup evidence, NOT an atomic security
    sandbox; process ownership is not a security boundary.
  * Reflection / dynamic name construction cannot be proven absent and is OUTSIDE
    this contract; no general JVM API / metadata / reflection equivalence is
    claimed, no whole-JAR / whole-language / Gradle / Maven claim, no downstream
    Kotlin recompilation claim. Coverage is sampled functional equivalence only.
  * This module implements the gate LOGIC. Gate CLOSURE and final qualification are
    owned by root's frozen-source full suite and fresh public JVM native/app run.
    Performance, defense strength and external-attack resistance stay
    ``not_evaluated`` here.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat


SCHEMA_VERSION = 1
PLAN_SCHEMA_VERSION = 1
PUBLIC_API_VERSION = "1.0"
API_VERSION = "phase21.1-experimental"
SUPPORT_LEVEL = "experimental"
WHOLE_LANGUAGE_SUPPORT = False

# The facade generator is the OWNED in-package module, loaded ONLY by trusted name.
TRUSTED_FACADE_MODULE = "antirea.jvm_facade"
# Fixed trusted runtime package the generated bootstrap/NativeCore classes live in.
RUNTIME_PACKAGE = "antirea.runtime"
# Trusted modules bound (by name + on-disk source hash) into every plan so a change
# to the facade or any engine dependency is detected before/at prepare and run. This
# INCLUDES the integration engine itself: a saved plan binds the actual engine bytes.
TRUSTED_ENGINE_MODULES = (
    "antirea.jvm_app_integration", "antirea.jvm_facade", "antirea.jvm_frontend",
    "antirea.bindings", "antirea.native_build", "antirea.process", "antirea.source_validate")

# The producer report this engine consumes must be a real successful jvm_frontend
# native build (honest status string, not a validated/qualified claim).
PRODUCER_BACKEND = "jvm_bytecode_native"
PRODUCER_OK_STATUS = "artifact_created_unvalidated"

# Staged roots that must stay byte-frozen across the whole run. Build outputs
# (compiled classes, generated sources, the JNI adapter DLL, logs) are written as
# siblings of these roots, never inside them.
FROZEN_ROOT_NAMES = ("app_sources", "original_core", "native")

# The live workspace defense STOP marker (controller cancel file), relative to the
# workspace root. It is only ever checked for existence -- never created/read/deleted.
STOP_RELATIVE = ".runs/defense-loop/STOP"

# The exact allowlisted Visual Studio SDK search-path variables captured fresh from
# the trusted developer shell (mirrors antirea.native_build; no other env is kept).
SDK_ENV_NAMES = ("INCLUDE", "LIB", "LIBPATH", "PATH", "VCINSTALLDIR", "VCToolsInstallDir",
                 "WindowsSdkDir", "WindowsSDKVersion", "UniversalCRTSdkDir", "UCRTVersion")

# Integration-spec + application-contract strict schema bounds.
SPEC_KIND = "jvm_application_integration"
CONTRACT_KIND = "jvm_application_samples"
MAX_APPLICATION_SOURCES = 32
MAX_CASES = 64
MAX_CASE_ARGS = 16
MAX_ARG_LEN = 4096
MAX_STDOUT_LEN = 1 << 20
_MAIN_CLASS_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*\Z")
_LABEL_RE = re.compile(r"[ -~]{1,120}\Z")


class JvmIntegrateError(ValueError):
    """Raised for any producer/report/identity/spec/contract inconsistency (fail closed)."""


class StagingIntegrityError(JvmIntegrateError):
    """A bound staged input changed / went missing / was injected (fail closed)."""


# --------------------------------------------------------------------------- #
# Byte-level helpers (pure disk hashing; symlink/reparse and received guards).
# --------------------------------------------------------------------------- #
# Reserved path components that must never be read/hashed/traversed as a consumed
# input (rejected LEXICALLY -- pure string inspection of the absolutized path parts,
# before any stat/lstat/resolve/read). The ONLY exception is the real workspace STOP
# existence probe, which is never routed through here (``_check_stop`` only tests
# ``Path.exists()``).
RESERVED_PATH_COMPONENTS = frozenset(
    {"rea-analysis-reports", "attackerfolder", "defense-loop", "env.setting", "linkrepro"})

_MAX_FILE_BYTES = 64 << 20            # 64 MiB per consumed/hashed regular file
_MAX_TREE_ENTRIES = 20000            # max entries in a single frozen staged root
_MAX_TREE_BYTES = 512 << 20          # max total bytes in a single frozen staged root


def _reserved_guard(path) -> None:
    """Reject a path that lexically contains a reserved/received component.

    Pure string inspection of the absolutized path parts -- no stat/lstat/resolve,
    no read -- so it runs before any stat/read/hash/traversal of a consumed path.
    """
    for part in Path(os.path.abspath(str(path))).parts:
        if part.casefold() in RESERVED_PATH_COMPONENTS:
            raise JvmIntegrateError(
                "path lexically traverses a reserved/received component %r: %s" % (part, path))


def _no_links(path) -> Path:
    _reserved_guard(path)                      # lexical guard BEFORE any lstat
    p = Path(path)
    for item in (p, *p.parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue                           # absent item cannot be a link
        except OSError as exc:                 # fail CLOSED on any other OS error
            raise JvmIntegrateError("link check failed (fail closed) for %s: %s" % (item, exc))
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise JvmIntegrateError("path traverses a symlink/reparse point: " + str(item))
    return p


def _guarded_regular_file(path, *, limit: int = _MAX_FILE_BYTES) -> int:
    """Shared pre-read gate for EVERY consumed file: lexical reserved guard FIRST,
    then symlink/reparse rejection, then a regular-file check, then a size bound."""
    _reserved_guard(path)                      # lexical guard BEFORE any stat/read
    p = _no_links(path)                        # reject symlink/reparse (fail closed)
    try:
        info = p.lstat()
    except OSError as exc:
        raise JvmIntegrateError("cannot stat consumed file (fail closed): %s (%s)" % (p, exc))
    if not stat.S_ISREG(info.st_mode):
        raise JvmIntegrateError("consumed path is not a regular file: " + str(p))
    if info.st_size > limit:
        raise JvmIntegrateError("file exceeds bounded read limit (%d > %d bytes): %s" % (info.st_size, limit, p))
    return info.st_size


def _hash_file(path, *, limit: int = _MAX_FILE_BYTES) -> str:
    _guarded_regular_file(path, limit=limit)   # reserved-first, nonlinked, regular, bounded
    h = hashlib.sha256()
    streamed = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            streamed += len(chunk)
            if streamed > limit:
                raise JvmIntegrateError(
                    "file exceeded bounded read limit while hashing (past %d bytes): %s" % (limit, path))
            h.update(chunk)
    return h.hexdigest()


def _read_bytes_bounded(path, *, limit: int = _MAX_FILE_BYTES) -> bytes:
    _guarded_regular_file(path, limit=limit)
    with open(path, "rb") as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise JvmIntegrateError("file exceeded bounded read limit during read (> %d bytes): %s" % (limit, path))
    return data


def _read_text_bounded(path, *, limit: int = _MAX_FILE_BYTES, encoding: str = "utf-8") -> str:
    return _read_bytes_bounded(path, limit=limit).decode(encoding)


def _received_guard(root: Path, path: Path) -> None:
    """Refuse received/shared/reserved artifacts as consumable inputs.

    The LEXICAL ``_reserved_guard`` (no filesystem access) runs first; the
    resolve-based pass is defense-in-depth once ``_no_links`` has established there
    is no symlink/reparse redirection into a reserved location under ``root``.
    """
    _reserved_guard(path)
    try:
        parts = Path(path).resolve().relative_to(root).parts
    except (ValueError, OSError):
        parts = Path(os.path.abspath(str(path))).parts
    for part in parts:
        if part.casefold() in RESERVED_PATH_COMPONENTS:
            raise JvmIntegrateError(
                "received/shared/reserved artifacts cannot be consumed here: " + str(path))


def _tree_inventory(root: Path) -> dict:
    """Full exact recursive inventory of ``root`` -> {posix_relpath: {sha256,bytes}}.

    Bounded manual walk via ``os.scandir`` (NOT ``rglob``): the lexical reserved
    guard and symlink/reparse rejection run on EVERY entry BEFORE it is stat'd or a
    directory is descended, symlinks are never followed, and entry/byte counts are
    both bounded (fail closed)."""
    root = Path(os.path.abspath(root))
    _reserved_guard(root)
    _no_links(root)
    if not root.is_dir():
        raise JvmIntegrateError("frozen staged root is not a directory: " + str(root))
    inventory = {}
    total_bytes = 0
    entry_count = 0
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            scan = os.scandir(current)
        except OSError as exc:
            raise JvmIntegrateError("frozen staged root unreadable (fail closed): %s (%s)" % (current, exc))
        with scan:
            for entry in scan:
                p = Path(entry.path)
                _reserved_guard(p)
                entry_count += 1
                if entry_count > _MAX_TREE_ENTRIES:
                    raise JvmIntegrateError(
                        "frozen staged root exceeds the bounded entry count (%d): %s" % (_MAX_TREE_ENTRIES, root))
                try:
                    is_link = entry.is_symlink()
                    info = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise JvmIntegrateError("frozen entry unreadable (fail closed): %s (%s)" % (p, exc))
                if is_link or (getattr(info, "st_file_attributes", 0) & 0x400):
                    raise JvmIntegrateError("frozen staged root holds a symlink/reparse entry: " + str(p))
                if stat.S_ISDIR(info.st_mode):
                    stack.append(p)
                    continue
                if not stat.S_ISREG(info.st_mode):
                    raise JvmIntegrateError("frozen staged root holds a non-regular entry: " + str(p))
                total_bytes += info.st_size
                if total_bytes > _MAX_TREE_BYTES:
                    raise JvmIntegrateError("frozen staged root exceeds the bounded total bytes: " + str(root))
                inventory[p.relative_to(root).as_posix()] = {"sha256": _hash_file(p), "bytes": info.st_size}
    return inventory


def _inventory_diff(bound: dict, disk: dict):
    bk, dk = set(bound), set(disk)
    missing = sorted(bk - dk)
    extra = sorted(dk - bk)
    changed = sorted(k for k in (bk & dk) if bound[k]["sha256"] != disk[k]["sha256"])
    return missing, extra, changed


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Trusted module identity: locate+hash WITHOUT executing the leaf module.
# --------------------------------------------------------------------------- #
def _locate_module_source(module_name: str) -> Path:
    """Locate a module's on-disk source WITHOUT importing/executing the leaf.

    Uses ``importlib.util.find_spec`` (imports only parent packages, never the named
    leaf), so a drifted leaf is never run before its bytes are hashed.
    """
    try:
        spec = importlib.util.find_spec(module_name)
    except (ImportError, AttributeError, ValueError) as exc:
        raise JvmIntegrateError("cannot locate module %s without importing it: %s" % (module_name, exc))
    origin = getattr(spec, "origin", None) if spec is not None else None
    if not origin or origin in ("built-in", "frozen", "namespace") or not origin.endswith(".py"):
        raise JvmIntegrateError("module has no importable .py source file: " + str(module_name))
    p = _no_links(Path(os.path.abspath(origin)))
    if not p.is_file():
        raise JvmIntegrateError("module source missing on disk: " + str(p))
    return p


def _module_source_identity(module_name: str) -> dict:
    if module_name not in TRUSTED_ENGINE_MODULES:
        raise JvmIntegrateError("refusing to bind an untrusted module: " + str(module_name))
    p = _locate_module_source(module_name)
    return {"module": module_name, "path": str(p), "sha256": _hash_file(p)}


def _engine_binding() -> dict:
    """Bind the owned facade + every trusted engine module by name + source hash."""
    return {name: _module_source_identity(name) for name in TRUSTED_ENGINE_MODULES}


def _engine_binding_digest(engine_binding: dict) -> str:
    return _digest({name: entry["sha256"] for name, entry in engine_binding.items()})


def _load_facade(module_name: str = TRUSTED_FACADE_MODULE, *, expected_sha256: str | None = None):
    """Load the OWNED facade module by its trusted name ONLY (no path injection).

    When ``expected_sha256`` is given, the facade source is located and hashed FIRST
    (non-executing find_spec) and the import is refused on mismatch, so a drifted
    facade is never executed before its bytes are verified.
    """
    if module_name != TRUSTED_FACADE_MODULE:
        raise JvmIntegrateError(
            "only the trusted owned facade module %r may be loaded; an arbitrary facade "
            "module name/path supplied by the project is rejected: %r" % (TRUSTED_FACADE_MODULE, module_name))
    source = _locate_module_source(module_name)
    actual = _hash_file(source)
    if expected_sha256 is not None and actual != expected_sha256:
        raise JvmIntegrateError(
            "trusted facade source changed since it was bound; refusing to import a drifted facade "
            "(expected %s, on disk %s)" % (expected_sha256, actual))
    module = importlib.import_module(module_name)
    for entry in ("generate_facades", "inspect_application_classes", "validate_facade_classes"):
        if not hasattr(module, entry):
            raise JvmIntegrateError("trusted facade module has no %s entry point" % entry)
    return module


def _engine():
    """Return the trusted engine dependency modules, imported BY NAME only."""
    return (importlib.import_module("antirea.jvm_frontend"),
            importlib.import_module("antirea.bindings"),
            importlib.import_module("antirea.native_build"),
            importlib.import_module("antirea.process"),
            importlib.import_module("antirea.source_validate"))


# --------------------------------------------------------------------------- #
# STOP + path helpers.
# --------------------------------------------------------------------------- #
def _stop_path(workspace_root) -> Path:
    return Path(os.path.abspath(workspace_root)) / STOP_RELATIVE


def _same_path(a, b) -> bool:
    return os.path.normcase(os.path.abspath(str(a))) == os.path.normcase(os.path.abspath(str(b)))


def _check_stop(real_stop: Path, fixture_stop, phase: str) -> None:
    """Fail closed if EITHER the real workspace STOP marker OR an optional fixture
    cancellation marker exists. Existence-only; neither file is created/read/deleted.
    The optional fixture can only ADD a reason to stop; never suppress the real STOP."""
    if Path(real_stop).exists():
        raise JvmIntegrateError("workspace defense STOP present at %s; refusing to proceed" % phase)
    if fixture_stop is not None and Path(fixture_stop).exists():
        raise JvmIntegrateError("fixture cancellation present at %s; refusing to proceed" % phase)


# --------------------------------------------------------------------------- #
# Toolchain discovery (patchable seams; reuse jvm_frontend + native_build).
# --------------------------------------------------------------------------- #
def _discover_jvm_toolchain(language: str) -> dict:
    """Trusted installed JDK (+ portable Kotlin) identity via jvm_frontend._compiler.

    Pure disk hashing of javac/java/JDK release + modules + helper (+ Kotlin jars);
    no cached env.setting. Returns the frontend compiler dict (with input_hashes)."""
    jvm_frontend, _, _, _, _ = _engine()
    compiler = jvm_frontend._compiler(language)
    if compiler.get("blockers"):
        raise JvmIntegrateError("JVM toolchain incomplete: " + "; ".join(compiler["blockers"]))
    return compiler


def _discover_native_toolchain(workspace_root) -> dict:
    """Trusted native toolchain (fixed developer shell) via native_build._toolchain.

    No env.setting, no historical LINKREPRO: only the pinned
    ``.tools/kagura-toolchain.json`` developer shell + tool identity."""
    _, _, native_build, _, _ = _engine()
    config, hashes = native_build._toolchain(Path(os.path.abspath(workspace_root)))
    developer_shell = config.get("developer_shell")
    if not developer_shell or not Path(developer_shell).is_file():
        raise JvmIntegrateError("trusted native developer shell is missing from the pinned toolchain")
    return {"developer_shell": str(_no_links(Path(developer_shell))),
            "tool_hashes": {k: v for k, v in hashes.items()}}


def _jni_headers(jvm_compiler: dict) -> dict:
    """Pin the consumed JDK JNI headers (jni.h + win32/jni_md.h), honestly scoped."""
    jdk = Path(jvm_compiler["jdk_root"])
    headers = {"jni.h": jdk / "include" / "jni.h",
               "jni_md.h": jdk / "include" / "win32" / "jni_md.h"}
    pinned = {}
    for label, path in headers.items():
        p = _no_links(path)
        if not p.is_file():
            raise JvmIntegrateError("required JDK JNI header missing: " + str(p))
        pinned[label] = {"path": str(p), "sha256": _hash_file(p)}
    return {"include_dir": str(jdk / "include"), "win32_dir": str(jdk / "include" / "win32"), "headers": pinned}


# --------------------------------------------------------------------------- #
# 1. Consume + pin the jvm_frontend producer report (every hash from disk bytes).
# --------------------------------------------------------------------------- #
def load_producer_report(report_path, *, workspace_root) -> dict:
    report_path = _no_links(Path(os.path.abspath(report_path)))
    root = Path(os.path.abspath(workspace_root))
    if not report_path.is_relative_to(root / ".runs"):
        raise JvmIntegrateError("producer report must live under workspace/.runs")
    _received_guard(root, report_path)
    report = json.loads(_read_text_bounded(report_path))
    if not isinstance(report, dict):
        raise JvmIntegrateError("producer report must be a JSON object")
    if report.get("backend") != PRODUCER_BACKEND:
        raise JvmIntegrateError("producer backend must be %s, got %r" % (PRODUCER_BACKEND, report.get("backend")))
    if report.get("status") != PRODUCER_OK_STATUS:
        raise JvmIntegrateError(
            "producer status must be %s (a real successful build), got %r" % (PRODUCER_OK_STATUS, report.get("status")))
    language = report.get("language")
    if language not in ("java", "kotlin"):
        raise JvmIntegrateError("producer language must be java or kotlin, got %r" % (language,))
    artifacts = report.get("artifacts")
    if not isinstance(artifacts, dict) or "protected" not in artifacts or "baseline" not in artifacts:
        raise JvmIntegrateError("producer report missing baseline/protected native artifacts")

    directory = report_path.parent
    pinned_artifacts = {}
    for arm in ("baseline", "protected"):
        entry = artifacts[arm]
        if (not isinstance(entry, dict) or not isinstance(entry.get("path"), str)
                or not isinstance(entry.get("sha256"), str)):
            raise JvmIntegrateError("artifact entry malformed: " + arm)
        path = _no_links(Path(os.path.abspath(entry["path"])))
        if not path.is_relative_to(directory):
            raise JvmIntegrateError("producer artifact escapes its build directory: " + str(path))
        if not path.is_file():
            raise JvmIntegrateError("producer artifact missing on disk: " + str(path))
        actual = _hash_file(path)
        if actual != entry["sha256"]:        # report hash is a CLAIM; disk bytes are the evidence
            raise JvmIntegrateError(
                "producer artifact hash mismatch for %s: report %s vs disk %s" % (arm, entry["sha256"], actual))
        pinned_artifacts[arm] = {"path": str(path), "sha256": actual, "bytes": path.stat().st_size}

    project = report.get("project")
    if not isinstance(project, dict) or not isinstance(project.get("methods"), list):
        raise JvmIntegrateError("producer report has no project/method metadata")
    if project.get("language") != language:
        raise JvmIntegrateError("producer project language disagrees with the report")
    methods = report.get("methods")
    if not isinstance(methods, list) or not methods:
        raise JvmIntegrateError("producer report has no lowered method metadata")
    contract = report.get("contract")
    if not isinstance(contract, dict) or not isinstance(contract.get("functions"), list):
        raise JvmIntegrateError("producer report has no native ABI contract")

    contract_path = _no_links(Path(os.path.abspath(report["contract_path"])))
    if not contract_path.is_relative_to(directory):
        raise JvmIntegrateError("producer contract escapes its build directory")
    contract_sha = _hash_file(contract_path)
    # The native ABI contract is validated AND its on-disk bytes are bound to the
    # inline contract (early-review Engine item 2).
    _, _bindings, _, _, _ = _engine()
    try:
        _bindings.validate_contract(contract)
    except Exception as exc:
        raise JvmIntegrateError("producer native ABI contract is invalid: %s" % exc)
    on_disk_contract = json.loads(_read_text_bounded(contract_path))
    if on_disk_contract != contract:
        raise JvmIntegrateError("producer contract file bytes disagree with the inline contract")

    # REQUIRED producer origin (engine-final-acceptance item 2): a successful
    # jvm_frontend.build_project ALWAYS emits the frontend contract hash + native
    # report + its sha. Missing / non-string / non-hex / contradictory origin FAILS
    # CLOSED -- it is never silently treated as optional or freshly repinned.
    frontend_hashes = report.get("frontend_artifact_hashes")
    if (not isinstance(frontend_hashes, dict)
            or not isinstance(frontend_hashes.get("contract.json"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", frontend_hashes["contract.json"])):
        raise JvmIntegrateError("producer report is missing a valid frontend contract.json hash")
    if contract_sha != frontend_hashes["contract.json"]:
        raise JvmIntegrateError("producer contract bytes disagree with the frontend artifact hash")

    native_report_rel = report.get("native_report")
    native_report_sha_claim = report.get("native_report_sha256")
    if (not isinstance(native_report_rel, str)
            or not isinstance(native_report_sha_claim, str)
            or not re.fullmatch(r"[0-9a-f]{64}", native_report_sha_claim)):
        raise JvmIntegrateError("producer report is missing a valid native_report + native_report_sha256")
    nrp = _no_links(Path(os.path.abspath(native_report_rel)))
    if not nrp.is_relative_to(directory) or not nrp.is_file():
        raise JvmIntegrateError("producer native report missing or escaping the build dir")
    nr_sha = _hash_file(nrp)
    if nr_sha != native_report_sha_claim:
        raise JvmIntegrateError("producer native report hash mismatch")
    for arm in ("baseline", "protected"):
        if not Path(pinned_artifacts[arm]["path"]).is_relative_to(nrp.parent):
            raise JvmIntegrateError("producer %s native artifact is not under the native report origin" % arm)
    # Parse the SAME pinned native-report bytes and verify recorded origin+coverage.
    native_report = json.loads(_read_text_bounded(nrp))
    if not isinstance(native_report, dict) or native_report.get("status") != PRODUCER_OK_STATUS:
        raise JvmIntegrateError("producer native report is not a successful native build")
    na = native_report.get("artifacts")
    if not isinstance(na, dict):
        raise JvmIntegrateError("producer native report has no artifacts record")
    for arm in ("baseline", "protected"):
        entry = na.get(arm)
        if not isinstance(entry, dict) or entry.get("sha256") != pinned_artifacts[arm]["sha256"]:
            raise JvmIntegrateError("producer native report %s artifact disagrees with the producer report" % arm)
    native_coverage = native_report.get("coverage")
    if not isinstance(native_coverage, dict):
        raise JvmIntegrateError("producer native report has no coverage record")
    exports = list(project.get("functions") or [])
    contract_exports = sorted(f["name"] for f in contract["functions"])
    if sorted(exports) != contract_exports:
        raise JvmIntegrateError("producer project exports disagree with the contract exports")
    # JVM coverage == native coverage with ONLY the frontend exported_functions
    # override, exactly as jvm_frontend builds it.
    coverage = report.get("coverage")
    if coverage != {**native_coverage, "exported_functions": exports}:
        raise JvmIntegrateError("producer JVM coverage is not the native coverage with the frontend export override")
    # Native selected_functions + VM evidence must COVER the lowered method exports
    # (roots AND owned helpers), not merely the ABI export names.
    selected = native_coverage.get("selected_functions")
    method_exports = {m["export"] for m in methods if isinstance(m, dict) and isinstance(m.get("export"), str)}
    if not isinstance(selected, list) or not method_exports or not method_exports <= set(selected):
        raise JvmIntegrateError("native selected_functions do not cover the lowered method exports (incl helpers)")
    for vm_field in ("functions", "original_vm", "final_vm"):
        if not native_coverage.get(vm_field):
            raise JvmIntegrateError("producer native report lacks VM evidence field: " + vm_field)
    native_report_pin = {"path": str(nrp), "sha256": nr_sha}

    # Original core classfiles the ordinary caller is compiled against. Each hash
    # MUST be a lowercase sha256 string equal to the disk bytes -- a non-string /
    # non-hex / mismatching hash fails closed; it is never silently repinned.
    original_classes = report.get("original_classes")
    if not isinstance(original_classes, dict) or not original_classes:
        raise JvmIntegrateError("producer report has no original core classfiles")
    pinned_core = {}
    for raw_path, claimed in original_classes.items():
        p = _no_links(Path(os.path.abspath(raw_path)))
        if not p.is_relative_to(directory):
            raise JvmIntegrateError("producer original core classfile escapes its build directory: " + str(p))
        if not p.is_file():
            raise JvmIntegrateError("producer original core classfile missing on disk: " + str(p))
        if not isinstance(claimed, str) or not re.fullmatch(r"[0-9a-f]{64}", claimed):
            raise JvmIntegrateError("producer original core classfile hash must be a lowercase sha256: " + str(p))
        actual = _hash_file(p)
        if claimed != actual:
            raise JvmIntegrateError("original core classfile hash mismatch: " + str(p))
        pinned_core[str(p)] = actual

    project_root = project.get("project_root")
    if not isinstance(project_root, str):
        raise JvmIntegrateError("producer report has no project_root")

    return {
        "report_path": str(report_path), "report_sha256": _hash_file(report_path),
        "backend": PRODUCER_BACKEND, "status": PRODUCER_OK_STATUS, "language": language,
        "name": project.get("name"), "project_root": str(_no_links(Path(os.path.abspath(project_root)))),
        "core_sources": [str(s) for s in project.get("sources", [])],
        "baseline": pinned_artifacts["baseline"], "protected": pinned_artifacts["protected"],
        "contract_path": str(contract_path), "contract_sha256": contract_sha, "contract": contract,
        "native_library": contract.get("library_name"),
        "native_report": native_report_pin,
        "methods": methods, "selectors": project["methods"],
        "exported_functions": project.get("functions", []),
        "original_classes": pinned_core,
        "frontend_artifact_hashes": frontend_hashes if isinstance(frontend_hashes, dict) else {},
        "compiler_inputs": report.get("compiler_inputs") or project.get("compiler_inputs") or {},
        "coverage": coverage,
    }


def _facade_producer(pinned: dict) -> dict:
    """Return the AUTHENTIC full jvm_frontend producer report dict for the facade.

    The landed ``antirea.jvm_facade`` consumes the COMPLETE build report (it
    re-reads and re-hashes ``original_classes`` itself and cross-checks
    project.methods / methods / contract). Re-read the report from the pinned path
    and re-verify its hash so the facade is handed exactly the pinned bytes."""
    raw = _read_bytes_bounded(pinned["report_path"])
    if hashlib.sha256(raw).hexdigest() != pinned["report_sha256"]:
        raise JvmIntegrateError("producer report changed on disk before facade generation")
    report = json.loads(raw.decode("utf-8"))
    if not isinstance(report, dict):
        raise JvmIntegrateError("producer report is not a JSON object")
    return report


# --------------------------------------------------------------------------- #
# 2. Integration spec (java|kotlin ordinary application) strict schema.
# --------------------------------------------------------------------------- #
def load_integration_spec(spec_path, *, workspace_root, pinned: dict) -> dict:
    spec_path = _no_links(Path(os.path.abspath(spec_path)))
    root = Path(os.path.abspath(workspace_root))
    if not spec_path.is_relative_to(root):
        raise JvmIntegrateError("integration spec must stay inside the workspace")
    _received_guard(root, spec_path)
    spec = json.loads(_read_text_bounded(spec_path))
    expected = {"schema_version", "kind", "language", "application_sources", "main_class"}
    if not isinstance(spec, dict) or set(spec) != expected:
        raise JvmIntegrateError("integration spec must contain exactly " + ", ".join(sorted(expected)))
    if spec["schema_version"] != 1 or spec["kind"] != SPEC_KIND:
        raise JvmIntegrateError("integration spec schema_version must be 1 and kind %r" % SPEC_KIND)
    if spec["language"] not in ("java", "kotlin"):
        raise JvmIntegrateError("integration spec language must be java or kotlin")
    if spec["language"] != pinned["language"]:
        raise JvmIntegrateError("integration spec language must match the producer language")
    sources = spec["application_sources"]
    if not isinstance(sources, list) or not 1 <= len(sources) <= MAX_APPLICATION_SOURCES:
        raise JvmIntegrateError("application_sources must contain 1..%d files" % MAX_APPLICATION_SOURCES)
    extension = ".java" if spec["language"] == "java" else ".kt"
    main_class = spec["main_class"]
    if not isinstance(main_class, str) or not _MAIN_CLASS_RE.fullmatch(main_class) or len(main_class) > 256:
        raise JvmIntegrateError("main_class must be a bounded dotted JVM class name")

    project_root = Path(pinned["project_root"])
    core_sources = {os.path.normcase(os.path.abspath(s)) for s in pinned["core_sources"]}
    resolved, seen = [], set()
    for raw in sources:
        if not isinstance(raw, str) or not raw or os.path.isabs(raw) or raw != raw.strip():
            raise JvmIntegrateError("application_sources entries must be clean relative paths: %r" % (raw,))
        rel = Path(raw)
        if rel.suffix != extension or any(part == ".." for part in rel.parts):
            raise JvmIntegrateError("only in-tree %s source files are accepted (no .. / wrong suffix)" % extension)
        abs_path = _no_links((spec_path.parent / rel))
        if not abs_path.is_relative_to(project_root):
            raise JvmIntegrateError("application source must live in the same project tree as the core: " + str(abs_path))
        if not abs_path.is_file():
            raise JvmIntegrateError("application source missing on disk: " + str(abs_path))
        key = os.path.normcase(os.path.abspath(abs_path))
        if key in seen:
            raise JvmIntegrateError("duplicate application source: " + raw)
        if key in core_sources:
            raise JvmIntegrateError("application source must not overlap a protected core source: " + raw)
        seen.add(key)
        resolved.append({"relative": rel.as_posix(), "path": str(abs_path), "sha256": _hash_file(abs_path)})

    return {"path": str(spec_path), "sha256": _hash_file(spec_path), "language": spec["language"],
            "main_class": main_class, "application_sources": resolved,
            "spec_dir": str(spec_path.parent)}


# --------------------------------------------------------------------------- #
# 3. Application-samples contract (explicit exact expected stdout + exit status).
# --------------------------------------------------------------------------- #
def _check_argv_string(value, where: str) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise JvmIntegrateError("%s must be a string or integer" % where)
    text = str(value)
    if len(text) > MAX_ARG_LEN:
        raise JvmIntegrateError("%s exceeds the bounded length" % where)
    if any(ord(ch) < 0x20 and ch not in "\t" or ch == "\x00" for ch in text):
        raise JvmIntegrateError("%s contains a NUL/control character" % where)
    return text


def validate_cases(cases) -> list:
    """Validate the EXPLICIT application-samples cases (no implicit/default fixture).

    EVERY case requires an explicit exact expected stdout AND exit status. argv is
    bounded (<=%d entries) with NUL/control safeguards. Max %d cases.""" % (MAX_CASE_ARGS, MAX_CASES)
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise JvmIntegrateError("cases must be an explicit list of 1..%d entries" % MAX_CASES)
    out, labels = [], set()
    for idx, case in enumerate(cases):
        if not isinstance(case, dict) or set(case) != {"label", "args", "expect"}:
            raise JvmIntegrateError("case[%d] must contain exactly label, args, expect" % idx)
        label = case["label"]
        if not isinstance(label, str) or not _LABEL_RE.fullmatch(label):
            raise JvmIntegrateError("case[%d].label must be a bounded printable string" % idx)
        if label in labels:
            raise JvmIntegrateError("duplicate case label: " + label)
        labels.add(label)
        args = case["args"]
        if not isinstance(args, list) or len(args) > MAX_CASE_ARGS:
            raise JvmIntegrateError("case[%d].args must be a list of <=%d entries" % (idx, MAX_CASE_ARGS))
        norm_args = [_check_argv_string(a, "case[%d].args[%d]" % (idx, j)) for j, a in enumerate(args)]
        expect = case["expect"]
        if not isinstance(expect, dict) or set(expect) != {"returncode", "stdout"}:
            raise JvmIntegrateError("case[%d].expect must contain exactly returncode and stdout" % idx)
        rc = expect["returncode"]
        if isinstance(rc, bool) or not isinstance(rc, int) or not 0 <= rc <= 255:
            raise JvmIntegrateError("case[%d].expect.returncode must be an int in 0..255" % idx)
        stdout = expect["stdout"]
        if not isinstance(stdout, str) or len(stdout) > MAX_STDOUT_LEN:
            raise JvmIntegrateError("case[%d].expect.stdout must be a bounded string" % idx)
        if any(ord(ch) < 0x20 and ch not in "\t\r\n" for ch in stdout):
            raise JvmIntegrateError("case[%d].expect.stdout contains a disallowed control character" % idx)
        out.append({"label": label, "args": norm_args, "expect": {"returncode": rc, "stdout": stdout}})
    return out


def load_application_contract(contract_path, *, workspace_root) -> dict:
    contract_path = _no_links(Path(os.path.abspath(contract_path)))
    root = Path(os.path.abspath(workspace_root))
    if not contract_path.is_relative_to(root):
        raise JvmIntegrateError("application contract must stay inside the workspace")
    _received_guard(root, contract_path)
    data = json.loads(_read_text_bounded(contract_path))
    if not isinstance(data, dict) or set(data) != {"schema_version", "kind", "cases"}:
        raise JvmIntegrateError("application contract must contain exactly schema_version, kind, cases")
    if data["schema_version"] != 1 or data["kind"] != CONTRACT_KIND:
        raise JvmIntegrateError("application contract schema_version must be 1 and kind %r" % CONTRACT_KIND)
    cases = validate_cases(data["cases"])
    return {"path": str(contract_path), "sha256": _hash_file(contract_path), "cases": cases}


def _select_control_case(cases: list) -> dict:
    """A success control case (expect.returncode==0) used for the missing-core /
    missing-adapter negative proofs. Chosen before any child runs."""
    for case in cases:
        if case["expect"]["returncode"] == 0:
            return case
    raise JvmIntegrateError("at least one case must declare expect.returncode==0 (success control)")


# --------------------------------------------------------------------------- #
# Optional public-compatible trusted_inputs seam (path+sha256 records).
# --------------------------------------------------------------------------- #
_MAX_TRUSTED_INPUTS = 128
_MAX_TRUSTED_INPUT_BYTES = 16 << 20
_MAX_TRUSTED_INPUTS_TOTAL_BYTES = 128 << 20
_TRUSTED_ROLE_MAXLEN = 64
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _normalize_trusted_inputs(trusted_inputs) -> list:
    """Validate the OPTIONAL trusted_inputs list shape WITHOUT touching disk.

    Returns a normalized ``[{path, sha256, role}]`` list. NONE is silently dropped:
    any malformed/non-absolute/out-of-bound record fails closed. The lexical
    reserved-name guard runs here, before any stat/read."""
    if trusted_inputs is None:
        return []
    if not isinstance(trusted_inputs, list):
        raise JvmIntegrateError("trusted_inputs must be a list of {path, sha256} records")
    if len(trusted_inputs) > _MAX_TRUSTED_INPUTS:
        raise JvmIntegrateError("too many trusted_inputs records (max %d)" % _MAX_TRUSTED_INPUTS)
    out, seen = [], set()
    for idx, rec in enumerate(trusted_inputs):
        if not isinstance(rec, dict):
            raise JvmIntegrateError("trusted_inputs[%d] must be an object" % idx)
        extra = set(rec) - {"path", "sha256", "role"}
        if extra:
            raise JvmIntegrateError("trusted_inputs[%d] has unsupported key(s): %s" % (idx, ", ".join(sorted(extra))))
        if "path" not in rec or "sha256" not in rec:
            raise JvmIntegrateError("trusted_inputs[%d] requires both path and sha256" % idx)
        path, sha, role = rec["path"], rec["sha256"], rec.get("role")
        if not isinstance(path, str) or not path or not os.path.isabs(path):
            raise JvmIntegrateError("trusted_inputs[%d].path must be a non-empty absolute string" % idx)
        _reserved_guard(path)
        if not isinstance(sha, str) or not _SHA256_RE.fullmatch(sha):
            raise JvmIntegrateError("trusted_inputs[%d].sha256 must be a lowercase 64-hex digest" % idx)
        if role is not None and (not isinstance(role, str) or len(role) > _TRUSTED_ROLE_MAXLEN or not role.isprintable()):
            raise JvmIntegrateError("trusted_inputs[%d].role must be a short printable string" % idx)
        key = os.path.normcase(os.path.abspath(path))
        if key in seen:
            raise JvmIntegrateError("duplicate trusted_inputs record: " + path)
        seen.add(key)
        out.append({"path": os.path.abspath(path), "sha256": sha, "role": role})
    return out


def _verify_trusted_inputs(normalized: list, *, workspace_root: Path, phase: str) -> dict:
    """Re-verify each trusted-input record from on-disk bytes (fail closed). No code
    is imported/executed from the records; the role is a diagnostic string only."""
    root = Path(os.path.abspath(workspace_root))
    total = 0
    checked = []
    for rec in normalized:
        p = _no_links(Path(rec["path"]))
        if not p.is_relative_to(root):
            raise JvmIntegrateError("trusted input escapes the workspace root (%s): %s" % (phase, p))
        size = _guarded_regular_file(p, limit=_MAX_TRUSTED_INPUT_BYTES)
        total += size
        if total > _MAX_TRUSTED_INPUTS_TOTAL_BYTES:
            raise JvmIntegrateError("trusted inputs exceed the bounded total bytes (%s)" % phase)
        actual = _hash_file(p, limit=_MAX_TRUSTED_INPUT_BYTES)
        if actual != rec["sha256"]:
            raise JvmIntegrateError("trusted input changed on disk (%s): %s" % (phase, p))
        checked.append({"path": str(p), "sha256": actual, "role": rec["role"]})
    return {"phase": phase, "count": len(checked), "records": checked, "total_bytes": total}


# --------------------------------------------------------------------------- #
# Clean allowlisted environments for child processes (never an os.environ copy).
# --------------------------------------------------------------------------- #
def _private_dirs(out_dir: Path) -> tuple:
    priv_tmp = out_dir / "_tmp"
    priv_home = out_dir / "_home"
    priv_tmp.mkdir(parents=True, exist_ok=True)
    priv_home.mkdir(parents=True, exist_ok=True)
    return priv_tmp, priv_home


def _clean_jvm_env(out_dir: Path, jvm_compiler: dict, *, adapter=None, native_core=None) -> dict:
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    java_dir = str(Path(jvm_compiler["java"]).parent)
    priv_tmp, priv_home = _private_dirs(out_dir)
    env = {
        "SystemRoot": sysroot, "windir": sysroot, "SystemDrive": "C:",
        "PATH": os.pathsep.join([java_dir, sysroot + r"\System32", sysroot]),
        "TEMP": str(priv_tmp), "TMP": str(priv_tmp),
        "USERPROFILE": str(priv_home), "APPDATA": str(priv_home / "AppData" / "Roaming"),
        "LOCALAPPDATA": str(priv_home / "AppData" / "Local"),
        "JAVA_HOME": jvm_compiler["jdk_root"],
        "PROCESSOR_ARCHITECTURE": os.environ.get("PROCESSOR_ARCHITECTURE", "AMD64"),
    }
    # The protected bootstrap loads these explicit absolute paths ONCE. Missing/unset
    # fails closed (no original algorithm fallback); the negative controls rely on it.
    if adapter is not None:
        env["ANTIREA_JNI_ADAPTER"] = str(adapter)
    if native_core is not None:
        env["ANTIREA_NATIVE_CORE"] = str(native_core)
    return env


def _clean_native_env(out_dir: Path, sdk_env: dict) -> dict:
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    priv_tmp, priv_home = _private_dirs(out_dir)
    env = {
        "SystemRoot": sysroot, "windir": sysroot, "SystemDrive": "C:",
        "TEMP": str(priv_tmp), "TMP": str(priv_tmp),
        "USERPROFILE": str(priv_home),
        "PROCESSOR_ARCHITECTURE": os.environ.get("PROCESSOR_ARCHITECTURE", "AMD64"),
    }
    # Overlay ONLY the allowlisted SDK search-path variables captured fresh from the
    # trusted developer shell; case-insensitive de-dup of PATH.
    for key, value in sdk_env.items():
        for existing in list(env):
            if existing.upper() == key.upper():
                del env[existing]
        env[key] = value
    if "PATH" not in {k.upper() for k in env}:
        env["PATH"] = os.pathsep.join([sysroot + r"\System32", sysroot])
    return env


def _read_log(path) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


def _strict_receipt_clean(receipt: dict) -> bool:
    """STRICT full Windows-Job receipt predicate over a FULL persisted raw process
    receipt (coordinated byte-for-byte with the service ``_receipt_clean``). An
    empty/partial receipt is NOT clean. Requires a positive int pid and an int
    returncode (bool rejected for both), ``timed_out``/``cancelled`` exactly False,
    NO ``error``/``post_cleanup_wait_error``, and a complete Windows-Job cleanup
    record: method==windows_job, job_assigned True, parent_pid==pid,
    parent_exit_confirmed True, active_after exactly int 0, status==assigned_job_empty,
    job_handle_closed True. A NON-ZERO returncode is still infra-clean (the
    fail-closed controls run cleanly yet exit non-zero); returncode semantics are
    checked separately by the caller. This never accepts job_assigned=False or any
    missing cleanup field (early-review Engine item 1)."""
    if not isinstance(receipt, dict):
        return False
    pid = receipt.get("pid")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return False
    rc = receipt.get("returncode")
    if isinstance(rc, bool) or not isinstance(rc, int):
        return False
    if receipt.get("timed_out") is not False or receipt.get("cancelled") is not False:
        return False
    if receipt.get("error") not in (None, "") or receipt.get("post_cleanup_wait_error") not in (None, ""):
        return False
    cleanup = receipt.get("cleanup")
    if not isinstance(cleanup, dict):
        return False
    if cleanup.get("method") != "windows_job":
        return False
    if cleanup.get("job_assigned") is not True:
        return False
    if cleanup.get("parent_pid") != pid:
        return False
    if cleanup.get("parent_exit_confirmed") is not True:
        return False
    active_after = cleanup.get("active_after")
    if isinstance(active_after, bool) or not isinstance(active_after, int) or active_after != 0:
        return False
    if cleanup.get("status") != "assigned_job_empty":
        return False
    if cleanup.get("job_handle_closed") is not True:
        return False
    return True


def _persisted_receipt(proc: dict, log_prefix: Path) -> dict:
    """Read the FULL raw persisted ``*.process.json`` the child wrote, bind it by its
    own SHA-256 and parse it. The clean-ness predicate is applied to THESE persisted
    bytes (never a flattened/reconstructed copy), matching the service, so the raw
    receipt identity is preserved and independently re-checkable."""
    receipt_path = Path(log_prefix).with_suffix(".process.json")
    data = _read_bytes_bounded(receipt_path)
    parsed = json.loads(data.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise JvmIntegrateError("persisted process receipt is not a JSON object: " + str(receipt_path))
    return {"receipt_path": str(receipt_path), "receipt_sha256": hashlib.sha256(data).hexdigest(),
            "stdout_log": proc["stdout"], "stderr_log": proc["stderr"], "parsed": parsed}


def _pin_tool(path) -> dict:
    """Pin an actual selected native tool by on-disk byte hash (cl.exe/link.exe)."""
    p = _no_links(Path(path))
    size = _guarded_regular_file(p)
    return {"path": str(p), "sha256": _hash_file(p), "bytes": size}


def _which_in(name: str, path_value: str) -> str:
    found = shutil.which(name, path=path_value)
    if not found:
        raise JvmIntegrateError("required native tool not found on the captured SDK PATH: " + name)
    return str(_no_links(Path(found)))


# --------------------------------------------------------------------------- #
# Fresh native SDK capture through the trusted developer shell (reused from
# antirea.native_build; no env.setting / LINKREPRO). Only the allowlisted SDK
# search-path variables are exported from the shell.
# --------------------------------------------------------------------------- #
def _capture_native_sdk_env(native_toolchain: dict, out_dir: Path, *, real_stop: Path,
                            timeout: int = 60) -> dict:
    _, _, _, process, _ = _engine()
    powershell = shutil.which("powershell.exe")
    if powershell is None:
        raise JvmIntegrateError("Windows PowerShell is required for installed Visual Studio SDK initialization")
    developer_shell = native_toolchain["developer_shell"]
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    priv_tmp, priv_home = _private_dirs(out_dir)
    base_env = {
        "SystemRoot": sysroot, "windir": sysroot, "SystemDrive": "C:",
        "COMSPEC": str(Path(sysroot) / "System32" / "cmd.exe"),
        "PATHEXT": ".COM;.EXE;.BAT;.CMD",
        "PATH": os.pathsep.join([sysroot + r"\System32", sysroot]),
        "TEMP": str(priv_tmp), "TMP": str(priv_tmp), "USERPROFILE": str(priv_home),
        "PROCESSOR_ARCHITECTURE": os.environ.get("PROCESSOR_ARCHITECTURE", "AMD64"),
        # Explicit ALLOWED install-location selectors so Launch-VsDevShell can locate
        # the installed Visual Studio without inheriting the ambient environment
        # (early-review Engine item 10; honestly a concern to validate at root's real
        # run, not a reproduced failure here).
        "ProgramFiles": os.environ.get("ProgramFiles", r"C:\Program Files"),
        "ProgramFiles(x86)": os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        "ProgramData": os.environ.get("ProgramData", r"C:\ProgramData"),
        "ANTIREA_NATIVE_DEVSHELL": developer_shell,
    }
    # Fixed SDK environment initialization via the trusted developer shell -- NOT a
    # user/project shell hook, NOT env.setting. Only compiler search-path variables
    # are read back. Explicit installation selection avoids Default -> Latest ->
    # interactive List fallback; SkipAutomaticLocation only controls working dir.
    names = "','".join(SDK_ENV_NAMES)
    script = ("$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); "
              "& $env:ANTIREA_NATIVE_DEVSHELL -VsInstallationPath $env:ANTIREA_NATIVE_DEVSHELL "
              "-Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null; "
              "$nativeSdk=@{}; foreach($nativeKey in @('" + names + "')) { "
              "$nativeValue=[Environment]::GetEnvironmentVariable($nativeKey); "
              "if($nativeValue) { $nativeSdk[$nativeKey]=$nativeValue } }; "
              "$nativeSdk | ConvertTo-Json -Compress")
    log_prefix = out_dir / "logs" / "sdk-capture"
    proc = process.run_logged([powershell, "-NoProfile", "-NonInteractive", "-Command", script],
                              out_dir, log_prefix, timeout=timeout, env=base_env, cancel_file=real_stop)
    rec = _persisted_receipt(proc, log_prefix)
    if proc.get("returncode") != 0 or not _strict_receipt_clean(rec["parsed"]):
        raise JvmIntegrateError("fresh native SDK capture child failed its strict Windows receipt")
    try:
        sdk_env = json.loads(_read_log(proc["stdout"]))
    except json.JSONDecodeError as exc:
        raise JvmIntegrateError("developer-shell SDK capture did not emit a JSON environment: %s" % exc)
    if not isinstance(sdk_env, dict) or set(sdk_env) - set(SDK_ENV_NAMES):
        raise JvmIntegrateError("captured SDK environment has unexpected keys")
    if not sdk_env.get("INCLUDE") or not sdk_env.get("LIB"):
        raise JvmIntegrateError("captured SDK environment is incomplete (INCLUDE/LIB missing)")
    prep_entry = {"label": "sdk-capture", "kind": "sdk_capture", "tool": str(_no_links(Path(powershell))),
                  "cwd": str(out_dir), "receipt_path": rec["receipt_path"],
                  "receipt_sha256": rec["receipt_sha256"], "stdout_log": rec["stdout_log"],
                  "stderr_log": rec["stderr_log"]}
    return {"sdk_env": sdk_env, "prep_entry": prep_entry, "allowed_install_selectors":
            ["ProgramFiles", "ProgramFiles(x86)", "ProgramData"]}


# --------------------------------------------------------------------------- #
# Staging: copy + pin the frozen roots (app sources, original core classfiles,
# native core). Generated facade sources and compiled outputs are siblings.
# --------------------------------------------------------------------------- #
def _class_relpath(jvm_frontend, classfile: Path) -> str:
    parsed = jvm_frontend.parse_class(_read_bytes_bounded(classfile))
    name = parsed.get("class")
    if not isinstance(name, str) or not name or ".." in name.split("/"):
        raise JvmIntegrateError("original core classfile has no usable binary name: " + str(classfile))
    return name + ".class"


def stage(pinned: dict, spec: dict, out_dir, *, workspace_root) -> dict:
    jvm_frontend, _, _, _, _ = _engine()
    root = Path(os.path.abspath(workspace_root))
    out = Path(os.path.abspath(out_dir))
    staging = out / "staging"
    app_root = staging / "app_sources"
    core_root = staging / "original_core"
    native_root = staging / "native"
    for directory in (app_root, core_root, native_root):
        directory.mkdir(parents=True)

    # (a) App sources (same relative layout the spec declares).
    app_files = []
    for entry in spec["application_sources"]:
        dest = app_root / entry["relative"]
        if not dest.resolve().is_relative_to(app_root.resolve()):
            raise JvmIntegrateError("application source relative path escapes the staged tree")
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(entry["path"], dest)
        if _hash_file(dest) != entry["sha256"]:
            raise StagingIntegrityError("application source changed while staging: " + entry["relative"])
        app_files.append({"relative": entry["relative"], "sha256": entry["sha256"]})

    # (b) Original core classfiles reconstructed into their package layout.
    core_files = []
    for abs_path, sha in pinned["original_classes"].items():
        src = _no_links(Path(abs_path))
        if _hash_file(src) != sha:
            raise StagingIntegrityError("original core classfile changed before staging: " + str(src))
        rel = _class_relpath(jvm_frontend, src)
        dest = core_root / rel
        if not dest.resolve().is_relative_to(core_root.resolve()):
            raise JvmIntegrateError("original core class relative path escapes the staged tree: " + rel)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
        core_files.append({"relative": Path(rel).as_posix(), "sha256": sha})

    # (b2) Kotlin core module metadata (META-INF/*.kotlin_module) is hash-bound by the
    # producer frontend but is NOT a classfile in original_classes. Stage it PRIVATELY
    # so the ordinary Kotlin caller compiles against the real core module (early-review
    # Engine item 11). It is pinned in the frozen original_core root but is NEVER
    # deployed, and is NOT treated as an original-core class needing a facade substitute.
    core_module_meta = []
    if pinned["language"] == "kotlin":
        classes_roots = set()
        for abs_path in pinned["original_classes"]:
            src = _no_links(Path(abs_path))
            name = _class_relpath(jvm_frontend, src)[:-len(".class")]
            croot = src
            for _ in range(len(name.split("/"))):
                croot = croot.parent
            classes_roots.add(str(_no_links(croot)))
        if len(classes_roots) != 1:
            raise JvmIntegrateError("kotlin core classfiles span multiple class roots; cannot bind module metadata")
        classes_root = Path(next(iter(classes_roots)))
        meta_dir = classes_root / "META-INF"
        modules = sorted(meta_dir.glob("*.kotlin_module")) if meta_dir.is_dir() else []
        if not modules:
            raise JvmIntegrateError("kotlin producer core has no META-INF/*.kotlin_module to bind")
        fah = pinned.get("frontend_artifact_hashes") or {}
        for mod in modules:
            mod = _no_links(mod)
            rel_from_classes = mod.relative_to(classes_root).as_posix()      # META-INF/<name>.kotlin_module
            mod_sha = _hash_file(mod)
            fah_key = "classes/" + rel_from_classes
            if isinstance(fah.get(fah_key), str) and fah[fah_key] != mod_sha:
                raise StagingIntegrityError("kotlin core module metadata disagrees with the frontend artifact hash")
            dest = core_root / rel_from_classes
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(mod, dest)
            core_module_meta.append({"relative": rel_from_classes, "sha256": mod_sha})

    # (c) Native core (REUSED protected producer artifact) + baseline (provenance).
    protected = Path(pinned["protected"]["path"])
    native_core_dest = native_root / protected.name
    shutil.copyfile(protected, native_core_dest)
    if _hash_file(native_core_dest) != pinned["protected"]["sha256"]:
        raise StagingIntegrityError("protected native core changed while staging")
    baseline = Path(pinned["baseline"]["path"])
    baseline_dest = native_root / ("baseline_" + baseline.name)
    shutil.copyfile(baseline, baseline_dest)

    frozen_roots = {"app_sources": _tree_inventory(app_root),
                    "original_core": _tree_inventory(core_root),
                    "native": _tree_inventory(native_root)}
    manifest = {
        "out_dir": str(out), "staging_dir": str(staging),
        "frozen_root_names": list(FROZEN_ROOT_NAMES),
        "frozen_roots": frozen_roots,
        "app_source_root": str(app_root), "original_core_root": str(core_root),
        "native_root": str(native_root),
        "native_core": {"path": str(native_core_dest), "sha256": pinned["protected"]["sha256"],
                        "name": protected.name},
        "baseline_core": {"path": str(baseline_dest), "sha256": pinned["baseline"]["sha256"]},
        "app_files": app_files, "core_files": core_files,
        "core_module_metadata": core_module_meta,
        "spec": {"path": spec["path"], "sha256": spec["sha256"]},
        "producer": {"report_path": pinned["report_path"], "report_sha256": pinned["report_sha256"],
                     "protected": pinned["protected"], "baseline": pinned["baseline"],
                     "contract_path": pinned["contract_path"], "contract_sha256": pinned["contract_sha256"]},
    }
    return {"manifest": manifest, "app_source_root": str(app_root),
            "original_core_root": str(core_root), "native_core": str(native_core_dest),
            "native_core_sha256": pinned["protected"]["sha256"]}


def verify_staged_integrity(manifest: dict, pinned: dict, *, workspace_root, phase: str,
                            stop_file=None, jvm_compiler=None, native_toolchain=None) -> dict:
    root = Path(os.path.abspath(workspace_root))
    _check_stop(_stop_path(root), stop_file, phase)
    diffs = {}
    roots = {"app_sources": Path(manifest["app_source_root"]),
             "original_core": Path(manifest["original_core_root"]),
             "native": Path(manifest["native_root"])}
    for name, directory in roots.items():
        missing, extra, changed = _inventory_diff(manifest["frozen_roots"][name], _tree_inventory(directory))
        if missing or extra or changed:
            raise StagingIntegrityError(
                "frozen root %r drifted (%s): missing=%s extra=%s changed=%s"
                % (name, phase, missing, extra, changed))
        diffs[name] = {"missing": missing, "extra": extra, "changed": changed}
    # Native core re-pinned, producer artifacts re-verified from their own disk bytes.
    if _hash_file(manifest["native_core"]["path"]) != manifest["native_core"]["sha256"]:
        raise StagingIntegrityError("staged native core changed (%s)" % phase)
    for arm in ("protected", "baseline"):
        if _hash_file(pinned[arm]["path"]) != pinned[arm]["sha256"]:
            raise StagingIntegrityError("producer %s native artifact changed on disk (%s)" % (arm, phase))
    if _hash_file(manifest["spec"]["path"]) != manifest["spec"]["sha256"]:
        raise StagingIntegrityError("integration spec changed on disk (%s)" % phase)
    if _hash_file(manifest["producer"]["report_path"]) != manifest["producer"]["report_sha256"]:
        raise StagingIntegrityError("producer report changed on disk (%s)" % phase)
    # Installed toolchain identity re-checked (fresh disk hashing), if supplied.
    tool_checks = {}
    if jvm_compiler is not None:
        fresh = _discover_jvm_toolchain(pinned["language"])
        if _digest(fresh["input_hashes"]) != _digest(jvm_compiler["input_hashes"]):
            raise StagingIntegrityError("installed JVM toolchain changed during the run (%s)" % phase)
        tool_checks["jvm"] = "verified"
    if native_toolchain is not None:
        fresh = _discover_native_toolchain(root)
        if _digest(fresh["tool_hashes"]) != _digest(native_toolchain["tool_hashes"]):
            raise StagingIntegrityError("installed native toolchain changed during the run (%s)" % phase)
        tool_checks["native"] = "verified"
    return {"status": "staged_integrity_verified", "phase": phase, "roots": diffs, "tool_checks": tool_checks}


# --------------------------------------------------------------------------- #
# Facade generation + generated-source pinning (facade lane owns the generator).
# --------------------------------------------------------------------------- #
def _facade_rel_abs(generated_dir: Path, relpath: str) -> Path:
    if not isinstance(relpath, str) or not relpath or os.path.isabs(relpath):
        raise JvmIntegrateError("facade file path must be a clean relative string: %r" % (relpath,))
    rel = Path(relpath)
    if any(part == ".." for part in rel.parts):
        raise JvmIntegrateError("facade file path escapes the generated tree: " + relpath)
    abs_path = _no_links(generated_dir / rel)
    if not abs_path.resolve().is_relative_to(generated_dir.resolve()):
        raise JvmIntegrateError("facade file path escapes the generated tree: " + relpath)
    return abs_path


def generate_and_pin_facades(facade, producer: dict, generated_dir: Path) -> dict:
    """Call the trusted facade generator and pin every emitted source from disk.

    Aligned to the landed ``antirea.jvm_facade`` contract: the facade is PURE
    (writes sources + ``facades.json``, compiles/executes nothing), REQUIRES a fresh
    ``output_dir``, and returns ``status == 'generated_not_validated'`` with
    ``files`` as ``{relpath: sha256}``. The engine re-hashes each reported file and
    derives the exact Java source set, the JNI adapter source set (``jni.adapter_sources``),
    the expected deploy classes and the forbidden original-core classes it must honour."""
    generated_dir = Path(generated_dir)
    if generated_dir.exists():
        raise JvmIntegrateError("generated facade dir must be fresh (facade never overwrites): " + str(generated_dir))
    report = facade.generate_facades(producer, generated_dir)
    if not isinstance(report, dict) or report.get("status") != "generated_not_validated":
        raise JvmIntegrateError("facade generation did not report generated_not_validated")
    if report.get("package") != RUNTIME_PACKAGE:
        raise JvmIntegrateError("facade runtime package must be %r" % RUNTIME_PACKAGE)
    files = report.get("files")
    if not isinstance(files, dict) or not files:
        raise JvmIntegrateError("facade report has no generated files map")
    java_sources, pinned_files = [], {}
    for relpath, sha in sorted(files.items()):
        if not isinstance(sha, str) or not _SHA256_RE.fullmatch(sha):
            raise JvmIntegrateError("facade file entry malformed (expected sha256 string): " + str(relpath))
        abs_path = _facade_rel_abs(generated_dir, relpath)
        if not abs_path.is_file():
            raise JvmIntegrateError("facade reported a file it did not write: " + relpath)
        actual = _hash_file(abs_path)
        if actual != sha:
            raise JvmIntegrateError("facade file hash mismatch (report vs disk): " + relpath)
        pinned_files[relpath] = {"path": str(abs_path), "sha256": actual}
        if relpath.startswith("java/") and relpath.endswith(".java"):
            java_sources.append(str(abs_path))
    if not java_sources:
        raise JvmIntegrateError("facade report produced no Java facade/runtime sources under java/")
    jni = report.get("jni")
    if not isinstance(jni, dict) or not isinstance(jni.get("adapter_sources"), list) or not jni["adapter_sources"]:
        raise JvmIntegrateError("facade report has no jni.adapter_sources")
    adapter_sources = []
    for rel in jni["adapter_sources"]:
        if rel not in files:
            raise JvmIntegrateError("facade adapter source is not in the pinned files map: " + str(rel))
        adapter_sources.append(str(_facade_rel_abs(generated_dir, rel)))
    deploy_classes = report.get("expected_deploy_classes")
    if not isinstance(deploy_classes, list) or not deploy_classes:
        raise JvmIntegrateError("facade report has no expected_deploy_classes")
    expected_classfiles = [str(c).replace(".", "/") + ".class" for c in deploy_classes]

    # FINAL facade inventory (engine-final-acceptance item 1): consume exactly
    # replaced_core_classes (internal names) + class_inventory, validate their
    # agreement with the producer originals AND the generated files, and preserve the
    # original-BYTES ban at the intentionally shared class identities. No fallback.
    replaced = report.get("replaced_core_classes")
    inventory = report.get("class_inventory")
    if not isinstance(replaced, list) or not replaced:
        raise JvmIntegrateError("facade report has no replaced_core_classes")
    if not isinstance(inventory, list) or not inventory:
        raise JvmIntegrateError("facade report has no class_inventory")
    producer_originals = producer.get("original_classes")
    if not isinstance(producer_originals, dict) or not producer_originals:
        raise JvmIntegrateError("producer passed to facade has no original_classes")
    replaced_set = set()
    forbidden_original_shas = set()
    replaced_core_relpaths = []
    inv_original_paths = set()
    for entry in inventory:
        if not isinstance(entry, dict):
            raise JvmIntegrateError("facade class_inventory entry must be an object")
        internal = entry.get("internal_name")
        osha = entry.get("original_sha256")
        opath = entry.get("original_classfile")
        fsf = entry.get("facade_source_file")
        fsha = entry.get("facade_source_sha256")
        if not isinstance(internal, str) or internal not in replaced:
            raise JvmIntegrateError("facade class_inventory internal_name not in replaced_core_classes: %r" % (internal,))
        if not isinstance(osha, str) or not _SHA256_RE.fullmatch(osha) or not isinstance(opath, str):
            raise JvmIntegrateError("facade class_inventory has an invalid original sha/path: " + str(internal))
        if producer_originals.get(opath) != osha:
            raise JvmIntegrateError("facade original class sha/path disagrees with the producer originals: " + str(internal))
        if not isinstance(fsf, str) or fsf not in files or files[fsf] != fsha:
            raise JvmIntegrateError("facade source sha disagrees with the generated file: " + str(internal))
        if entry.get("same_relative_class_path") is not True or entry.get("original_bytes_must_be_absent") is not True:
            raise JvmIntegrateError("facade class_inventory must assert shared-path + original-bytes-absent: " + str(internal))
        replaced_set.add(internal)
        forbidden_original_shas.add(osha)
        replaced_core_relpaths.append(internal + ".class")
        inv_original_paths.add(opath)
    if replaced_set != set(replaced):
        raise JvmIntegrateError("facade class_inventory internal set disagrees with replaced_core_classes")
    # Agreement with the producer originals: the inventory must cover EXACTLY the
    # producer's original core classfiles (no missing, no extra).
    if inv_original_paths != set(producer_originals):
        raise JvmIntegrateError("facade class_inventory does not cover exactly the producer original core classes")
    return {"report": report, "pinned_files": pinned_files,
            "java_sources": sorted(java_sources),
            "adapter_sources": sorted(adapter_sources),
            "jni_include_dir": str(generated_dir / "jni"),
            "expected_classfiles": expected_classfiles,
            "replaced_core_classes": sorted(replaced_set),
            "replaced_core_relpaths": sorted(replaced_core_relpaths),
            "forbidden_original_shas": sorted(forbidden_original_shas),
            "class_inventory": inventory,
            "native_exports": list(report.get("native_exports", []))}


# --------------------------------------------------------------------------- #
# Deployment bundle (minimal exact allowlist). Schema coordinated with root's
# relocation harness: {path, files[{relative_path,sha256,bytes}], main_class,
# classpath_entries[], jni_adapter, native_core}. Every entry resolves in-bundle.
# --------------------------------------------------------------------------- #
_DEPLOY_ALLOWED_SUFFIXES = (".class", ".dll", ".jar")


def _copy_class_tree_to_root(src_root: Path, bundle_root: Path) -> None:
    """Copy .class files into the bundle ROOT at their package-relative paths so the
    class root IS the bundle root (service classpath rule: an entry is '.' or a member
    jar, never a directory). Kotlin ``*.kotlin_module`` metadata is PINNED elsewhere
    but NEVER deployed (early-review Engine item 11); any other non-class artifact is
    an unexpected compiler output and fails closed."""
    for item in sorted(src_root.rglob("*")):
        if item.is_dir():
            continue
        if item.suffix == ".class":
            dest = bundle_root / item.relative_to(src_root)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(item, dest)
        elif item.name.endswith(".kotlin_module"):
            continue                       # pinned in the compiled inventory, not deployed
        else:
            raise JvmIntegrateError("unexpected non-class artifact in a compiled class tree: " + str(item))


def _assemble_deploy_bundle(*, out: Path, app_classes_dir: Path, facade_classes_dir: Path,
                            adapter_dll: Path, native_core: Path, language: str,
                            jvm_compiler: dict, spec: dict, manifest: dict, facade: dict) -> dict:
    bundle = out / "deployment_bundle"
    if bundle.exists():
        raise JvmIntegrateError("deployment bundle dir must be fresh: " + str(bundle))
    native_dir = bundle / "native"
    bundle.mkdir(parents=True)
    native_dir.mkdir(parents=True)
    # Class files at the bundle ROOT (unchanged app + generated facade/runtime).
    _copy_class_tree_to_root(app_classes_dir, bundle)
    _copy_class_tree_to_root(facade_classes_dir, bundle)

    # Prove the facade SUBSTITUTED every original core CLASS: at each original-core
    # class relpath the bundle carries the facade bytes, never the original core
    # bytes. Kotlin META-INF/*.kotlin_module entries are NOT core classes and are
    # skipped (early-review Engine item 11).
    original_core_inv = manifest["frozen_roots"]["original_core"]
    facade_inv = _tree_inventory(facade_classes_dir)
    for rel, meta in original_core_inv.items():
        if not rel.endswith(".class"):
            continue
        if rel not in facade_inv:
            raise JvmIntegrateError("facade produced no substitute for original core class: " + rel)
        if facade_inv[rel]["sha256"] == meta["sha256"]:
            raise JvmIntegrateError("deployment bundle would ship the ORIGINAL core class bytes: " + rel)
        shipped = bundle / rel
        if not shipped.is_file() or _hash_file(shipped) != facade_inv[rel]["sha256"]:
            raise JvmIntegrateError("bundle core class is not the generated facade: " + rel)

    adapter_dest = native_dir / adapter_dll.name
    core_dest = native_dir / native_core.name
    shutil.copyfile(adapter_dll, adapter_dest)
    shutil.copyfile(native_core, core_dest)

    classpath_entries = ["."]              # the bundle root IS the class root
    if language == "kotlin":
        lib = bundle / "lib"
        lib.mkdir()
        stdlib = Path(jvm_compiler["kotlin_stdlib"])
        shutil.copyfile(stdlib, lib / stdlib.name)
        classpath_entries.append("lib/" + stdlib.name)

    # Forbidden original BYTES that must never be deployed: original core class bytes
    # (engine-staged + facade-declared), and the unprotected baseline native bytes.
    forbidden_shas = {m["sha256"] for m in original_core_inv.values() if "sha256" in m}
    forbidden_shas |= set(facade.get("forbidden_original_shas", []))
    forbidden_shas.add(manifest["baseline_core"]["sha256"])

    files, forbidden_hit = [], []
    for item in sorted(bundle.rglob("*")):
        if item.is_dir():
            continue
        rel = item.relative_to(bundle).as_posix()
        if not rel.lower().endswith(_DEPLOY_ALLOWED_SUFFIXES):
            raise JvmIntegrateError("non-allowlisted artifact in deployment bundle: " + rel)
        sha = _hash_file(item)
        if sha in forbidden_shas:
            forbidden_hit.append(rel)
        files.append({"relative_path": rel, "sha256": sha, "bytes": item.stat().st_size})
    if forbidden_hit:
        raise JvmIntegrateError("deployment bundle carries forbidden original bytes: " + ", ".join(forbidden_hit))

    present = {f["relative_path"] for f in files}
    native_core_rel = ("native/" + native_core.name)
    jni_adapter_rel = ("native/" + adapter_dll.name)
    deployment = {
        "path": str(bundle), "files": files, "allowlist": sorted(present),
        "main_class": spec["main_class"], "classpath_entries": classpath_entries,
        "jni_adapter": jni_adapter_rel, "native_core": native_core_rel,
        "forbidden_absent": True,
    }
    # Every declared launch member must resolve inside the bundle.
    for entry in classpath_entries:
        if entry != "." and entry not in present:
            raise JvmIntegrateError("deployment classpath entry is not a bundle member: " + entry)
    for key in ("jni_adapter", "native_core"):
        if deployment[key] not in present:
            raise JvmIntegrateError("deployment %s is not a bundle member: %s" % (key, deployment[key]))
    return deployment


# --------------------------------------------------------------------------- #
# Core: compile the JNI adapter + ordinary caller + facade classes, then run and
# compare the ORIGINAL vs PROTECTED arms over the explicit application cases.
# --------------------------------------------------------------------------- #
def build_and_compare(prepared: dict, staging: dict, cases: list, *, workspace_root,
                      timeout_seconds: int = 120, stop_file=None, trusted_inputs=None) -> dict:
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
        raise JvmIntegrateError("timeout_seconds must be 1..600")
    trusted_norm = _normalize_trusted_inputs(trusted_inputs)
    cases = validate_cases(cases)
    control_case = _select_control_case(cases)

    jvm_frontend, bindings, native_build, process, source_validate = _engine()
    facade = _load_facade(expected_sha256=prepared["engine_binding"][TRUSTED_FACADE_MODULE]["sha256"])
    root = Path(os.path.abspath(workspace_root))
    real_stop = _stop_path(root)
    manifest = staging["manifest"]
    out = Path(manifest["out_dir"])
    logs = out / "logs"
    pinned = prepared["pinned"]
    spec = prepared["spec"]
    jvm_compiler = prepared["jvm_compiler"]
    native_toolchain = prepared["native_toolchain"]
    jni_headers = prepared["jni_headers"]
    language = pinned["language"]
    producer = _facade_producer(pinned)      # FULL authentic producer report (hash-verified)
    native_core = Path(staging["native_core"])
    core_root = Path(staging["original_core_root"])
    app_root = Path(staging["app_source_root"])

    trusted_checks = []
    preparation_commands = []
    comparison_commands = []
    stop_events = []
    pinned_singletons = {}                   # label -> (abs path, sha256): generated sources, adapter
    frozen_dir_inventories = {}              # dir -> full _tree_inventory captured post-compile

    # Preflight: STOP + staged integrity + trusted inputs + toolchain identity.
    _check_stop(real_stop, stop_file, "preflight")
    integrity_pre = verify_staged_integrity(manifest, pinned, workspace_root=root, phase="preflight",
                                             stop_file=stop_file, jvm_compiler=jvm_compiler,
                                             native_toolchain=native_toolchain)
    trusted_pre = _verify_trusted_inputs(trusted_norm, workspace_root=root, phase="preflight")
    trusted_checks.append({"phase": "preflight", "count": trusted_pre["count"]})

    def between_check(where):
        """Full tamper recheck BETWEEN children (early-review Engine item 8): frozen
        app/core/source + native roots, spec/producer report, installed JVM + native
        toolchain inputs, native core, pinned generated sources/adapter, and the fixed
        compiled caller/facade inventories (extras detected, not only known hashes)."""
        verify_staged_integrity(manifest, pinned, workspace_root=root, phase=where, stop_file=stop_file,
                                jvm_compiler=jvm_compiler, native_toolchain=native_toolchain)
        if _hash_file(str(native_core)) != manifest["native_core"]["sha256"]:
            raise StagingIntegrityError("native core changed during execution (%s)" % where)
        for name, (path, sha) in pinned_singletons.items():
            if _hash_file(path) != sha:
                raise StagingIntegrityError("pinned %s changed during execution (%s)" % (name, where))
        for directory, inv in frozen_dir_inventories.items():
            miss, extra, chg = _inventory_diff(inv, _tree_inventory(Path(directory)))
            if miss or extra or chg:
                raise StagingIntegrityError(
                    "compiled inventory %s drifted (%s): missing=%s extra=%s changed=%s"
                    % (directory, where, miss, extra, chg))

    def recheck_native_tools(where):
        fresh = _discover_native_toolchain(root)
        if _digest(fresh["tool_hashes"]) != _digest(native_toolchain["tool_hashes"]):
            raise StagingIntegrityError("installed native toolchain changed during execution (%s)" % where)

    def run(argv, log_label, *, env, cwd=None):
        """Run ONE bounded child honouring an explicit cwd (early-review Engine item
        5); retain the FULL persisted raw receipt and bind it by its own SHA (item 6).
        STOP + trusted + between-children tamper checks run before AND after."""
        if env is None:
            raise JvmIntegrateError("every child must run under an explicit clean env")
        _check_stop(real_stop, stop_file, "during:" + log_label)
        tb = _verify_trusted_inputs(trusted_norm, workspace_root=root, phase="before:" + log_label)
        trusted_checks.append({"phase": "before:" + log_label, "count": tb["count"]})
        between_check("before:" + log_label)
        directory = Path(os.path.abspath(cwd)) if cwd is not None else out
        proc = process.run_logged([str(a) for a in argv], directory, logs / log_label,
                                  timeout=timeout_seconds, env=env, cancel_file=real_stop)
        rec = _persisted_receipt(proc, logs / log_label)      # read+hash the FULL persisted receipt
        rec["returncode"] = rec["parsed"].get("returncode")
        rec["strict_clean"] = _strict_receipt_clean(rec["parsed"])
        rec["cwd"] = str(directory)
        if rec["parsed"].get("cancelled") is True:
            stop_events.append(log_label)
        ta = _verify_trusted_inputs(trusted_norm, workspace_root=root, phase="after:" + log_label)
        trusted_checks.append({"phase": "after:" + log_label, "count": ta["count"]})
        between_check("after:" + log_label)
        return rec

    def prep_entry(label, kind, tool, rec):
        if not rec["strict_clean"] or not isinstance(rec["returncode"], int) or rec["returncode"] != 0:
            raise JvmIntegrateError("preparation child %s failed its strict clean+zero receipt" % label)
        preparation_commands.append({"label": label, "kind": kind, "tool": str(tool), "cwd": rec["cwd"],
                                     "receipt_path": rec["receipt_path"], "receipt_sha256": rec["receipt_sha256"],
                                     "stdout_log": rec["stdout_log"], "stderr_log": rec["stderr_log"]})

    def case_cmd(case_label, arm, rec):
        if not rec["strict_clean"]:
            raise JvmIntegrateError("case arm %s:%s failed its strict Windows receipt" % (case_label, arm))
        comparison_commands.append({"label": "case:%s:%s" % (case_label, arm), "kind": "case_arm",
                                    "arm": arm, "case_label": case_label, "control": None,
                                    "receipt_path": rec["receipt_path"], "receipt_sha256": rec["receipt_sha256"],
                                    "stdout_log": rec["stdout_log"], "stderr_log": rec["stderr_log"]})

    def control_cmd(short, rec):
        if not rec["strict_clean"]:
            raise JvmIntegrateError("control %s failed its strict Windows receipt" % short)
        comparison_commands.append({"label": "control:%s" % short, "kind": "control",
                                    "arm": None, "case_label": None, "control": short,
                                    "receipt_path": rec["receipt_path"], "receipt_sha256": rec["receipt_sha256"],
                                    "stdout_log": rec["stdout_log"], "stderr_log": rec["stderr_log"]})

    # (A) Fresh native SDK capture through the trusted developer shell (own full
    # strict pinned receipt); integrity/trusted are verified immediately before
    # (preflight) and after (between_check).
    capture = _capture_native_sdk_env(native_toolchain, out, real_stop=real_stop, timeout=timeout_seconds)
    sdk_env = capture["sdk_env"]
    native_env = _clean_native_env(out, sdk_env)
    preparation_commands.append(capture["prep_entry"])
    _verify_trusted_inputs(trusted_norm, workspace_root=root, phase="after:sdk-capture")
    between_check("after:sdk-capture")

    # (B) Generate + pin facades (pin every generated source so it is re-checked
    # around every subsequent compiler, early-review Engine item 7).
    generated_dir = out / "generated"
    facade_bundle = generate_and_pin_facades(facade, producer, generated_dir)
    for rel, meta in facade_bundle["pinned_files"].items():
        pinned_singletons["generated:" + rel] = (meta["path"], meta["sha256"])

    # Pin the ACTUAL selected MSVC cl.exe + link.exe by on-disk byte hash (honestly
    # bounded native-tool pinning; this is NOT a full SDK/OS pin -- see limitations).
    recheck_native_tools("adapter:pre")
    cl = _which_in("cl.exe", sdk_env.get("PATH", ""))
    link = _which_in("link.exe", sdk_env.get("PATH", ""))
    tool_pins = {"cl.exe": _pin_tool(cl), "link.exe": _pin_tool(link)}
    native_build_dir = out / "native_build"
    native_build_dir.mkdir(parents=True)
    adapter_dll = native_build_dir / "antirea_adapter.dll"
    adapter_argv = [cl, "/nologo", "/O2", "/MT", "/LD",
                    "/I", jni_headers["include_dir"], "/I", jni_headers["win32_dir"],
                    "/I", facade_bundle["jni_include_dir"], *facade_bundle["adapter_sources"],
                    "/Fe:" + str(adapter_dll)]
    rec = run(adapter_argv, "cl-adapter", env=native_env, cwd=native_build_dir)
    recheck_native_tools("adapter:post")
    if rec["returncode"] != 0 or not rec["strict_clean"] or not adapter_dll.is_file():
        raise JvmIntegrateError("JNI adapter compile failed its strict receipt or produced no DLL")
    if _pin_tool(cl)["sha256"] != tool_pins["cl.exe"]["sha256"] or _pin_tool(link)["sha256"] != tool_pins["link.exe"]["sha256"]:
        raise StagingIntegrityError("selected MSVC cl/link tool bytes changed around the adapter compile")
    prep_entry("cl-adapter", "native_compile", cl, rec)
    pinned_singletons["adapter.dll"] = (str(adapter_dll), _hash_file(adapter_dll))

    # (C) Compile the ordinary caller against the ORIGINAL core (bytecode preserved).
    app_classes_dir = out / "app_classes"
    app_classes_dir.mkdir(parents=True)
    app_src = [str(app_root / e["relative"]) for e in spec["application_sources"]]
    if language == "java":
        app_argv = [jvm_compiler["javac"], "-proc:none", "-implicit:none", "-encoding", "UTF-8",
                    "-g:none", "--release", "21", "-classpath", str(core_root),
                    "-d", str(app_classes_dir), *app_src]
    else:
        app_cp = os.pathsep.join([str(core_root), jvm_compiler["kotlin_stdlib"], jvm_compiler["kotlin_annotations"]])
        app_argv = [jvm_compiler["java"], "-cp", jvm_compiler["kotlin_compiler"],
                    "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-kotlin-home", jvm_compiler["kotlin_home"],
                    "-jdk-home", jvm_compiler["jdk_root"], "-jvm-target", "21", "-no-stdlib", "-no-reflect",
                    "-classpath", app_cp, "-d", str(app_classes_dir), *app_src]
    rec = run(app_argv, "compile-app", env=_clean_jvm_env(out, jvm_compiler))
    if rec["returncode"] != 0 or not rec["strict_clean"]:
        raise JvmIntegrateError("ordinary caller compile failed its strict receipt")
    app_classfiles = sorted(p.relative_to(app_classes_dir).as_posix() for p in app_classes_dir.rglob("*.class"))
    if not app_classfiles:
        raise JvmIntegrateError("ordinary caller compile produced no classfiles")
    # Fix the FULL compiled caller inventory (classes + any kotlin module metadata).
    frozen_dir_inventories[str(app_classes_dir)] = _tree_inventory(app_classes_dir)
    prep_entry("compile-app", "app_compile", jvm_compiler.get("javac") or jvm_compiler.get("kotlin_compiler"), rec)

    # (D) Compile the generated facade/runtime classes (separate from core & caller).
    facade_classes_dir = out / "facade_classes"
    facade_classes_dir.mkdir(parents=True)
    facade_argv = [jvm_compiler["javac"], "-proc:none", "-implicit:none", "-encoding", "UTF-8",
                   "-g:none", "--release", "21", "-d", str(facade_classes_dir), *facade_bundle["java_sources"]]
    rec = run(facade_argv, "compile-facade", env=_clean_jvm_env(out, jvm_compiler))
    if rec["returncode"] != 0 or not rec["strict_clean"]:
        raise JvmIntegrateError("facade compile failed its strict receipt")
    produced_rel = set(p.relative_to(facade_classes_dir).as_posix() for p in facade_classes_dir.rglob("*.class"))
    # EXACT inventory: produced facade classfiles must EQUAL the expected deploy set
    # (no missing AND no unexpected extras) -- early-review Engine item 7.
    expected_set = set(facade_bundle["expected_classfiles"])
    if produced_rel != expected_set:
        raise JvmIntegrateError("facade classfile inventory is not exact: missing=%s extra=%s"
                                % (sorted(expected_set - produced_rel), sorted(produced_rel - expected_set)))
    frozen_dir_inventories[str(facade_classes_dir)] = _tree_inventory(facade_classes_dir)
    facade_classfiles = sorted(produced_rel)
    prep_entry("compile-facade", "facade_compile", jvm_compiler["javac"], rec)

    # (E) Pure facade/app structural checks (no execution; parse compiled bytecode).
    facade_class_bytes = {p.relative_to(facade_classes_dir).as_posix(): _read_bytes_bounded(p)
                          for p in sorted(facade_classes_dir.rglob("*.class"))}
    app_class_bytes = {p.relative_to(app_classes_dir).as_posix(): _read_bytes_bounded(p)
                       for p in sorted(app_classes_dir.rglob("*.class"))}
    facade_validation = facade.validate_facade_classes(facade_class_bytes, producer)
    if not isinstance(facade_validation, dict) or facade_validation.get("status") not in ("accepted", "rejected"):
        raise JvmIntegrateError("facade validation returned an unexpected shape")
    facade_forwarding_only = facade_validation.get("status") == "accepted"
    if not facade_forwarding_only:
        raise JvmIntegrateError("facade classes failed structural validation: %s" % (facade_validation.get("violations"),))
    app_inspection = facade.inspect_application_classes(app_class_bytes, producer)
    if not isinstance(app_inspection, dict) or app_inspection.get("status") not in ("accepted", "rejected"):
        raise JvmIntegrateError("application inspection returned an unexpected shape")
    app_refs_ok = app_inspection.get("status") == "accepted"
    if not app_refs_ok:
        raise JvmIntegrateError("application classes reference protected non-root members: %s" % (app_inspection.get("violations"),))

    # (F) Run helpers.
    kotlin_runtime = [jvm_compiler["kotlin_stdlib"]] if language == "kotlin" else []
    original_cp = os.pathsep.join([str(app_classes_dir), str(core_root), *kotlin_runtime])
    protected_cp = os.pathsep.join([str(app_classes_dir), str(facade_classes_dir), *kotlin_runtime])
    base_env = _clean_jvm_env(out, jvm_compiler)
    protected_env = _clean_jvm_env(out, jvm_compiler, adapter=adapter_dll, native_core=native_core)

    def run_java(classpath, args, env, log_label):
        rec = run([jvm_compiler["java"], "-cp", classpath, spec["main_class"], *args], log_label, env=env)
        # Observe the RAW stdout bytes the child actually wrote (the service compares
        # raw bytes to the contract's expected stdout); no newline normalization.
        rec["stdout_bytes"] = _read_bytes_bounded(rec["stdout_log"])
        rec["stdout_text"] = rec["stdout_bytes"].decode("utf-8", "replace")
        return rec

    # (G) Sampled original(baseline)/protected equivalence against the EXPLICIT exact
    # contract, compared on RAW stdout bytes + persisted exit codes. The case record
    # names the original arm "baseline" (the service reads baseline+protected).
    case_records = []
    original_receipts = {}
    all_match = True
    expectations_ok = True
    for i, case in enumerate(cases):
        L = case["label"]
        expect = case["expect"]
        expect_bytes = expect["stdout"].encode("utf-8")
        o = run_java(original_cp, case["args"], base_env, "case-%03d-original" % i)
        d = run_java(protected_cp, case["args"], protected_env, "case-%03d-protected" % i)
        case_cmd(L, "original", o)
        case_cmd(L, "protected", d)
        original_receipts[L] = o
        original_ok = (o["returncode"] == expect["returncode"] and o["stdout_bytes"] == expect_bytes)
        expectations_ok = expectations_ok and original_ok
        case_match = (o["stdout_bytes"] == d["stdout_bytes"] and o["returncode"] == d["returncode"] and original_ok)
        all_match = all_match and case_match
        case_records.append({
            "label": L, "args": case["args"], "expect": expect,
            "baseline": {"returncode": o["returncode"], "stdout": o["stdout_text"]},
            "protected": {"returncode": d["returncode"], "stdout": d["stdout_text"]},
            "original_meets_expected": original_ok, "match": case_match,
            "baseline_stderr_log": o["stderr_log"], "protected_stderr_log": d["stderr_log"]})

    # (H) Fail-closed native-required proofs (no silent original fallback). The control
    # ORIGINAL success baseline reuses the already-executed and referenced case.
    # Every executed child thus has exactly one public receipt reference.
    control = original_receipts[control_case["label"]]
    control_expect_bytes = control_case["expect"]["stdout"].encode("utf-8")
    control_ok = (control["returncode"] == control_case["expect"]["returncode"]
                  and control["stdout_bytes"] == control_expect_bytes and control["strict_clean"])
    control_stdout_bytes = control["stdout_bytes"]
    absent_core = out / "_absent_core.dll"
    absent_adapter = out / "_absent_adapter.dll"
    control_variants = {
        "missing_core": _clean_jvm_env(out, jvm_compiler, adapter=adapter_dll, native_core=absent_core),
        "unset_core": _clean_jvm_env(out, jvm_compiler, adapter=adapter_dll),
        "missing_adapter": _clean_jvm_env(out, jvm_compiler, adapter=absent_adapter, native_core=native_core),
        "unset_adapter": _clean_jvm_env(out, jvm_compiler, native_core=native_core),
    }
    route_proofs = {}
    for short, env in control_variants.items():
        dep = run_java(protected_cp, control_case["args"], env, "route-" + short)
        control_cmd(short, dep)
        rc = dep["returncode"]
        failed_cleanly = dep["strict_clean"] and isinstance(rc, int) and rc != 0
        silent_fallback = isinstance(rc, int) and rc == 0 and dep["stdout_bytes"] == control_stdout_bytes
        route_proofs[short] = {"variant": short, "deployable_rc": rc, "failed_cleanly": failed_cleanly,
                               "silent_fallback_detected": silent_fallback,
                               "proves_native_required": failed_cleanly and not silent_fallback,
                               "stderr_log": dep["stderr_log"]}
    missing_core_control_ok = route_proofs["missing_core"]["proves_native_required"] and route_proofs["unset_core"]["proves_native_required"]
    missing_adapter_control_ok = route_proofs["missing_adapter"]["proves_native_required"] and route_proofs["unset_adapter"]["proves_native_required"]
    route_ok = control_ok and all(p["proves_native_required"] for p in route_proofs.values())

    # (I) Assemble the minimal deployment bundle (exact allowlist, classes at root).
    deployment = _assemble_deploy_bundle(
        out=out, app_classes_dir=app_classes_dir, facade_classes_dir=facade_classes_dir,
        adapter_dll=adapter_dll, native_core=native_core, language=language,
        jvm_compiler=jvm_compiler, spec=spec, manifest=manifest, facade=facade_bundle)

    # (J) Postflight: STOP + integrity + trusted inputs + pin stability.
    _check_stop(real_stop, stop_file, "postflight")
    integrity_post = verify_staged_integrity(manifest, pinned, workspace_root=root, phase="postflight",
                                             stop_file=stop_file, jvm_compiler=jvm_compiler,
                                             native_toolchain=native_toolchain)
    trusted_post = _verify_trusted_inputs(trusted_norm, workspace_root=root, phase="postflight")
    trusted_checks.append({"phase": "postflight", "count": trusted_post["count"]})
    between_check("postflight")

    integrity_ok = (integrity_pre["status"] == "staged_integrity_verified"
                    and integrity_post["status"] == "staged_integrity_verified")
    env_ok = True            # every child ran under an engine-built allowlisted env (no os.environ inheritance)
    facade_ok = facade_forwarding_only and app_refs_ok
    passed = (all_match and route_ok and facade_ok and integrity_ok and expectations_ok
              and env_ok and missing_core_control_ok and missing_adapter_control_ok)

    comparison = {
        "status": "producer_bound_integration_passed" if passed else "failed",
        "total_cases": len(cases),
        "all_match": all_match, "env_ok": env_ok, "route_proof_ok": route_ok,
        "integrity_verified_before_and_after": integrity_ok, "expectations_ok": expectations_ok,
        "missing_core_control_ok": missing_core_control_ok, "missing_adapter_control_ok": missing_adapter_control_ok,
        "route_control_ok": control_ok, "route_proofs": route_proofs,
        "stop_cancellations": stop_events,
        "cases": case_records, "commands": comparison_commands,
        "integrity_preflight": integrity_pre, "integrity_postflight": integrity_post,
        "facade_validation": facade_validation, "facade_forwarding_only": facade_forwarding_only,
        "application_inspection": app_inspection, "application_references_allowed_roots_only": app_refs_ok,
    }
    staging_block = {
        "native_core_sha256": staging["native_core_sha256"],
        "jni_adapter": str(adapter_dll), "jni_adapter_sha256": pinned_singletons["adapter.dll"][1],
        "generated_sources_pinned": len(facade_bundle["pinned_files"]),
    }
    evidence = {
        "jvm_toolchain_input_digest": _digest(jvm_compiler["input_hashes"]),
        "native_toolchain_digest": _digest(native_toolchain["tool_hashes"]),
        "native_tool_pins": tool_pins,
        "sdk_env_keys": sorted(sdk_env), "native_env_keys": sorted(native_env), "jvm_env_keys": sorted(base_env),
        "allowed_install_selectors": capture.get("allowed_install_selectors", []),
        "jni_headers": jni_headers["headers"],
        "facade_report": facade_bundle["report"],
        "app_classfiles": app_classfiles, "facade_classfiles": facade_classfiles,
        "adapter_dll": {"path": str(adapter_dll), "sha256": pinned_singletons["adapter.dll"][1]},
        "between_children_checks": True,
        "trusted_inputs_verification": {
            "declared_count": len(trusted_norm), "verified": True,
            "verified_phases": ["preflight", "before_each_child", "after_each_child", "postflight"],
            "check_events": len(trusted_checks), "preflight": trusted_pre, "postflight": trusted_post,
            "no_code_executed_from_records": True},
        "limitations": [
            "Sampled exact-stdout/exit equivalence of one owned application; not an exhaustive proof.",
            "Bounded owned child processes under a minimal private allowlisted env with a full Windows Job "
            "receipt (strict: job empty, handle closed, parent exit confirmed); cleanup is NOT an atomic "
            "security sandbox and process ownership is not a security boundary.",
            "The protected native core is a REUSED pinned producer artifact re-verified from disk, NOT a "
            "fresh protected-native build; only the caller, generated facade/runtime classes and the JNI "
            "adapter DLL are freshly compiled here.",
            "Native-tool pinning covers the SELECTED cl.exe and link.exe bytes and the consumed JDK JNI "
            "headers plus the allowlisted SDK env; it is NOT a full MSVC/Windows-SDK/OS byte pin.",
            "Kotlin core + app module metadata (META-INF/*.kotlin_module) is pinned for faithful compilation "
            "but is never deployed; the bundle is classfiles + DLLs + runtime JAR(s) only.",
            "The fail-closed controls reuse the first success (returncode==0) case; if that case does NOT "
            "exercise the native route, the missing/unset core+adapter variants cannot fail closed and the "
            "integration FAILS -- it is never reported as a faked success.",
            "stderr is recorded raw and NOT used for any exception-equivalence claim; stack-trace paths are "
            "unstable and are not compared.",
            "Integrity + compiled caller/facade inventories + pinned generated sources are rechecked BEFORE "
            "and AFTER every child and at postflight; this detects a NET change across the run, not a "
            "transient swap-and-restore. SHA-256 content hashes, not a cryptographically signed report.",
            "No performance, defense-strength, whole-JAR/whole-language, Gradle/Maven or external-attack claim.",
        ],
    }
    return {"passed": passed, "comparison": comparison, "preparation_commands": preparation_commands,
            "deployment": deployment, "staging": staging_block, "evidence": evidence,
            "integrity_verified_before_and_after": integrity_ok}


# --------------------------------------------------------------------------- #
# Workspace snapshot + JSON-serializable, fingerprinted plan.
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class WorkspacePlan:
    workspace_root: Path
    out_dir: Path
    stop_file: Path
    facade_module: str = TRUSTED_FACADE_MODULE
    frozen_root_names: tuple = FROZEN_ROOT_NAMES

    @classmethod
    def resolve(cls, *, workspace_root, out_dir, stop_file=None, require_fresh_out: bool = True) -> "WorkspacePlan":
        wr = Path(os.path.abspath(workspace_root))
        out = Path(os.path.abspath(out_dir))
        _reserved_guard(wr)
        _reserved_guard(out)
        _no_links(wr)
        _no_links(out)
        if not out.is_relative_to(wr / ".runs"):
            raise JvmIntegrateError("out_dir must live under workspace/.runs")
        if not (wr / "antirea").is_dir():
            raise JvmIntegrateError("workspace_root does not contain an antirea/ package: " + str(wr))
        if require_fresh_out and out.exists():
            raise JvmIntegrateError("out_dir must be fresh (append-only runs): " + str(out))
        stop = Path(os.path.abspath(stop_file)) if stop_file is not None else _stop_path(wr)
        return cls(workspace_root=wr, out_dir=out, stop_file=stop,
                   facade_module=TRUSTED_FACADE_MODULE, frozen_root_names=tuple(FROZEN_ROOT_NAMES))


def _workspace_identity(workspace: "WorkspacePlan") -> dict:
    wr = str(workspace.workspace_root)
    return {"workspace_root": wr, "facade_module": TRUSTED_FACADE_MODULE,
            "stop_relative": STOP_RELATIVE, "stop_file": str(_stop_path(wr))}


def _plan_fingerprint(input_snapshot, pinned, jvm_digest, native_digest, jni_digest,
                      engine_binding, workspace_identity) -> str:
    return _digest({
        "schema": PLAN_SCHEMA_VERSION, "input_snapshot": input_snapshot,
        "pinned": {k: pinned[k] for k in ("report_sha256", "protected", "baseline",
                                          "contract_sha256", "language", "native_library",
                                          "original_classes")},
        "jvm_digest": jvm_digest, "native_digest": native_digest, "jni_digest": jni_digest,
        "engine_binding": {n: e["sha256"] for n, e in engine_binding.items()},
        "workspace_identity": workspace_identity,
    })


def plan(producer_report_path, integration_spec_path, application_contract_path, *, workspace: "WorkspacePlan") -> dict:
    root = workspace.workspace_root
    pinned = load_producer_report(producer_report_path, workspace_root=root)
    spec = load_integration_spec(integration_spec_path, workspace_root=root, pinned=pinned)
    contract = load_application_contract(application_contract_path, workspace_root=root)
    jvm_compiler = _discover_jvm_toolchain(pinned["language"])
    native_toolchain = _discover_native_toolchain(root)
    jni_headers = _jni_headers(jvm_compiler)
    engine_binding = _engine_binding()
    workspace_identity = _workspace_identity(workspace)
    _no_links(workspace.out_dir)
    if workspace.out_dir.exists():
        raise JvmIntegrateError("out_dir must be fresh at plan time")
    input_snapshot = {
        "app_sources": {e["relative"]: e["sha256"] for e in spec["application_sources"]},
        "main_class": spec["main_class"], "language": spec["language"],
        "integration_spec": {"path": spec["path"], "sha256": spec["sha256"]},
        "application_contract": {"path": contract["path"], "sha256": contract["sha256"],
                                 "cases_digest": _digest(contract["cases"])},
    }
    jvm_digest = _digest(jvm_compiler["input_hashes"])
    native_digest = _digest(native_toolchain["tool_hashes"])
    jni_digest = _digest({k: v["sha256"] for k, v in jni_headers["headers"].items()})
    fingerprint = _plan_fingerprint(input_snapshot, pinned, jvm_digest, native_digest, jni_digest,
                                    engine_binding, workspace_identity)
    return {
        "status": "planned", "schema_version": PLAN_SCHEMA_VERSION,
        "pinned": pinned, "spec": spec, "cases": contract["cases"],
        "application_contract": {"path": contract["path"], "sha256": contract["sha256"]},
        "jvm_compiler": jvm_compiler, "native_toolchain": native_toolchain, "jni_headers": jni_headers,
        "engine_binding": engine_binding, "facade_module": TRUSTED_FACADE_MODULE,
        "input_snapshot": input_snapshot, "workspace_identity": workspace_identity,
        "jvm_digest": jvm_digest, "native_digest": native_digest, "jni_digest": jni_digest,
        "plan_fingerprint": fingerprint,
        "workspace": {"workspace_root": str(workspace.workspace_root), "out_dir": str(workspace.out_dir),
                      "stop_file": str(workspace.stop_file)},
    }


def serialize_plan(prepared: dict) -> str:
    # Recompute the fingerprint to reject a self-inconsistent plan before it is emitted.
    expected = _plan_fingerprint(prepared["input_snapshot"], prepared["pinned"], prepared["jvm_digest"],
                                 prepared["native_digest"], prepared["jni_digest"],
                                 prepared["engine_binding"], prepared["workspace_identity"])
    if expected != prepared["plan_fingerprint"]:
        raise JvmIntegrateError("refusing to serialize a self-inconsistent plan (fingerprint mismatch)")
    return json.dumps(prepared, sort_keys=True)


def load_plan(serialized) -> dict:
    prepared = json.loads(serialized) if isinstance(serialized, str) else serialized
    if not isinstance(prepared, dict) or prepared.get("status") != "planned":
        raise JvmIntegrateError("serialized plan is malformed")
    if prepared.get("schema_version") != PLAN_SCHEMA_VERSION:
        raise JvmIntegrateError("serialized plan schema_version mismatch")
    if prepared.get("facade_module") != TRUSTED_FACADE_MODULE:
        raise JvmIntegrateError("serialized plan references an untrusted facade module")
    # Re-derive the trusted engine/facade binding from disk by NAME (never from the
    # serialized path) and reject drift since the plan was written.
    fresh_binding = _engine_binding()
    stored = prepared["engine_binding"]
    if set(fresh_binding) != set(stored) or any(fresh_binding[n]["sha256"] != stored[n]["sha256"] for n in fresh_binding):
        raise JvmIntegrateError("trusted engine/facade module changed since the plan was written (drift rejected)")
    expected = _plan_fingerprint(prepared["input_snapshot"], prepared["pinned"], prepared["jvm_digest"],
                                 prepared["native_digest"], prepared["jni_digest"],
                                 fresh_binding, prepared["workspace_identity"])
    if expected != prepared["plan_fingerprint"]:
        raise JvmIntegrateError("serialized plan fingerprint does not re-validate (tamper rejected)")
    return prepared


def prepare(prepared: dict, workspace: "WorkspacePlan") -> dict:
    root = workspace.workspace_root
    if _workspace_identity(workspace) != prepared["workspace_identity"]:
        raise JvmIntegrateError("workspace identity disagrees with the bound plan")
    # Re-verify the planned sources + producer report from disk BEFORE staging.
    spec = prepared["spec"]
    if _hash_file(spec["path"]) != spec["sha256"]:
        raise JvmIntegrateError("integration spec changed between plan and prepare")
    for e in spec["application_sources"]:
        if _hash_file(e["path"]) != e["sha256"]:
            raise JvmIntegrateError("application source changed between plan and prepare: " + e["relative"])
    pinned = prepared["pinned"]
    if _hash_file(pinned["report_path"]) != pinned["report_sha256"]:
        raise JvmIntegrateError("producer report changed between plan and prepare")
    for arm in ("protected", "baseline"):
        if _hash_file(pinned[arm]["path"]) != pinned[arm]["sha256"]:
            raise JvmIntegrateError("producer %s native artifact changed between plan and prepare" % arm)
    # Re-verify the trusted facade/engine binding by NAME before any facade execution.
    fresh_binding = _engine_binding()
    if any(fresh_binding[n]["sha256"] != prepared["engine_binding"][n]["sha256"] for n in fresh_binding):
        raise JvmIntegrateError("trusted engine/facade module changed between plan and prepare")
    return stage(pinned, spec, workspace.out_dir, workspace_root=root)


def validate(prepared: dict, staging: dict, workspace: "WorkspacePlan", *, timeout_seconds: int = 120,
             trusted_inputs=None) -> dict:
    if _workspace_identity(workspace) != prepared["workspace_identity"]:
        raise JvmIntegrateError("workspace identity disagrees with the bound plan")
    return build_and_compare(prepared, staging, prepared["cases"], workspace_root=workspace.workspace_root,
                             timeout_seconds=timeout_seconds, stop_file=workspace.stop_file,
                             trusted_inputs=trusted_inputs)


# --------------------------------------------------------------------------- #
# Public service-facing contract + qualification (consumed by jvm_application).
# --------------------------------------------------------------------------- #
def project_service_contract() -> dict:
    return {
        "api_version": PUBLIC_API_VERSION, "production_api_version": API_VERSION,
        "support_level": SUPPORT_LEVEL, "whole_language_support": WHOLE_LANGUAGE_SUPPORT,
        "whole_language_claim": False, "scope": "jvm_producer_bound_ordinary_app_integration",
        "integration_mode": "explicit_source_integrate",
        "run_integration_signature": {
            "keyword_only": True,
            "required": ["producer_report_path", "integration_spec_path",
                         "application_contract_path", "output_dir", "workspace_root"],
            "optional": {"timeout_seconds": 120, "trusted_inputs": None},
            "persisted_report": "output_dir/integration.json",
            "passing_status": "jvm_application_samples_passed",
        },
        "trusted_modules": {
            "facade": TRUSTED_FACADE_MODULE, "engine": list(TRUSTED_ENGINE_MODULES),
            "loaded_by": "importlib.import_module(trusted_name) only; no spec_from_file_location on a "
                         "caller path and no sys.path injection; facade bound by source hash, not executed at plan",
        },
        "integration_spec_schema": {
            "schema_version": 1, "kind": SPEC_KIND, "language": ["java", "kotlin"],
            "application_sources": "1..%d in-tree relative source files (no overlap with core)" % MAX_APPLICATION_SOURCES,
            "main_class": "bounded dotted JVM class name",
            "sources_relative_to": "spec.parent, same producer project snapshot",
            "rejects": ["absolute path", "..", "wrong suffix", "core-source overlap",
                        "arbitrary runtime jars/native libs/flags/commands"],
        },
        "application_contract_schema": {
            "schema_version": 1, "kind": CONTRACT_KIND,
            "cases": "1..%d cases; EVERY case needs exact expected stdout AND exit status" % MAX_CASES,
            "argv": "<=%d bounded strings; NUL/control safeguarded" % MAX_CASE_ARGS,
            "comparison": "original vs protected stdout + returncode (exact); stderr recorded raw, "
                          "NOT used for exception-equivalence; unstable stack-trace paths not compared",
        },
        "report_schema": {
            "status": "jvm_application_samples_passed (top-level) only when the comparison passed",
            "producer": "{backend, report_path, report_sha256, artifacts:{protected:{sha256}, baseline:{sha256}}, "
                        "contract_path, contract_sha256, native_report, native_library}",
            "staging": "{native_core_sha256, jni_adapter, jni_adapter_sha256}",
            "comparison_status": "producer_bound_integration_passed",
            "comparison_pass_flags": ["all_match", "env_ok", "route_proof_ok",
                                      "integrity_verified_before_and_after", "expectations_ok",
                                      "missing_core_control_ok", "missing_adapter_control_ok"],
            "comparison_cases": "[{label, args, expect:{returncode,stdout}, original:{returncode,stdout}, "
                                "protected:{returncode,stdout}, match}]",
            "comparison_commands": "EXACTLY case:<L>:original|case:<L>:protected per case + control:"
                                   "{missing_core,unset_core,missing_adapter,unset_adapter}; entry keys subset of "
                                   "{label,kind,arm,case_label,control,receipt_path,receipt_sha256,stdout_log,stderr_log}",
            "preparation_commands": "top-level [{label,kind,tool,cwd,receipt_path,receipt_sha256,stdout_log,stderr_log}] "
                                    "for sdk-capture + cl-adapter + compile-app + compile-facade (full clean pinned receipts)",
        },
        "deployment_schema": {
            "path": "absolute bundle directory",
            "files": "[{relative_path, sha256, bytes}] exact set == allowlist, all resolve inside the bundle",
            "allowlist": "sorted list of file relpaths, equal to the files manifest keyset",
            "main_class": "spec.main_class",
            "classpath_entries": "'.' (the bundle root IS the class root) plus optional 'lib/<kotlin-stdlib>.jar'",
            "jni_adapter": "relative DLL member path inside the bundle (native/<adapter>.dll)",
            "native_core": "relative DLL member path inside the bundle (native/<core>.dll)",
            "forbidden_absent": "True: no deployed file carries original core/baseline bytes",
            "excludes": ["original core classes (facade-substituted)", "original algorithms/private helpers",
                         "source", "IR", "reports", "baseline", "native link intermediates",
                         "kotlin module metadata (pinned, not deployed)"],
            "relocation": "root copies the exact allowlist, sets ANTIREA_JNI_ADAPTER/ANTIREA_NATIVE_CORE, "
                          "runs java -cp <joined relocated entries> main_class args (no arbitrary launch commands)",
        },
        "strict_child_receipt": {
            "required_for": ["sdk-capture", "cl-adapter", "compile-app", "compile-facade",
                             "every case original/protected arm", "every control"],
            "predicate": "positive int pid, int returncode (no bool), timed_out/cancelled exactly False, "
                         "no error/post_cleanup_wait_error, cleanup.method windows_job, job_assigned True, "
                         "parent_pid==pid, parent_exit_confirmed True, active_after int 0, "
                         "status assigned_job_empty, job_handle_closed True",
            "receipt_binding": "receipt_sha256 == sha256 of the persisted *.process.json (service re-reads it)",
        },
        "native_jni_environment": {
            "toolchain_discovery": "antirea.native_build._toolchain (pinned .tools/kagura-toolchain.json developer shell)",
            "sdk_capture": "fresh capture through the trusted developer shell; only allowlisted SDK vars "
                           + ", ".join(SDK_ENV_NAMES) + "; explicit ProgramFiles/ProgramData selectors",
            "no_env_setting": True, "no_historical_linkrepro": True,
            "pinned": ["JDK include/jni.h", "JDK include/win32/jni_md.h", "selected cl.exe bytes",
                       "selected link.exe bytes", "native toolchain tool identity"],
            "not_pinned": "full MSVC/Windows-SDK/OS byte set (honestly out of scope here)",
        },
        "serializable_plan": {
            "plan_schema_version": PLAN_SCHEMA_VERSION, "json_serializable": True,
            "serialize": "serialize_plan(prepared) -> canonical JSON",
            "load": "load_plan(json) -> prepared; re-derives engine binding by name and re-validates fingerprint",
            "round_trip_revalidated_at": ["load", "prepare"],
        },
        "integrity_model": {
            "bound_from": "on_disk_bytes_not_report_claims", "trusts_stored_manifest": False,
            "recompute_phases": ["preflight", "postflight", "before_and_after_every_child"],
            "rejects": ["changed/missing/injected staged file", "native core change", "app source change",
                        "integration spec change", "producer report change", "facade/engine module drift",
                        "installed JVM/native toolchain change", "plan fingerprint tamper",
                        "reserved/received path", "trusted_input mismatch", "original-core bytes in bundle"],
            "stop_phases": ["preflight", "during_execution", "before_each_case", "postflight", "per_child_cancel"],
            "stop_sources": ["real_workspace_stop_always", "optional_fixture_cancellation_additive_only"],
            "caveats": ["net-change detection across the run, not transient swap-and-restore",
                        "SHA-256 content hashes, not a cryptographically signed report",
                        "Windows Job cleanup is cleanup evidence, not an atomic security sandbox"],
        },
        "provenance_model": {
            "native_producer": "caller-declared reuse of a hash-pinned jvm_frontend artifact, re-verified from disk",
            "caller": "freshly_staged_compiled_executed",
            "generated_runtime": "freshly_generated_compiled (facade/bootstrap/NativeCore + JNI adapter DLL)",
            "fresh_protected_native_build": False,
        },
        "qualification_owner": "root_final_report",
        "gates_pending": {
            "frozen_full_suite": "root_owned_pending_all_editor_agreement",
            "fresh_public_native_app_run": "root_owned_after_source_freeze",
            "performance_evaluation": "not_evaluated",
            "defense_strength_evaluation": "not_evaluated",
            "external_attack_evaluation": "not_evaluated",
        },
    }


def qualification_status(result: dict) -> dict:
    comparison = result.get("comparison") if isinstance(result.get("comparison"), dict) else {}
    functional_sample_passed = bool(result.get("passed")
                                    and comparison.get("status") == "producer_bound_integration_passed"
                                    and result.get("integrity_verified_before_and_after"))
    return {
        "integration_mode": "explicit_source_integrate", "support_level": SUPPORT_LEVEL,
        "functional_sample_passed": functional_sample_passed,
        "functional_sample_basis": "sampled_exact_stdout_exit_equivalence_plus_tamper_evident_staging",
        "qualification_owner": "root_final_report",
        "frozen_full_suite": "root_owned_pending_all_editor_agreement",
        "whole_language_support": WHOLE_LANGUAGE_SUPPORT,
        "performance_acceptance": "not_evaluated", "defense_effectiveness": "not_evaluated",
        "external_attack_evaluation": "not_evaluated",
    }


# --------------------------------------------------------------------------- #
# Public entry point (the reusable execution engine surface).
# --------------------------------------------------------------------------- #
def run_integration(*, producer_report_path, integration_spec_path, application_contract_path,
                    output_dir, workspace_root, timeout_seconds: int = 120, trusted_inputs=None) -> dict:
    """End-to-end producer-bound ordinary JVM application integration.

    Consumes a pinned ``jvm_frontend`` producer report (REUSED protected native core,
    re-verified from disk -> ``fresh_protected_native_build`` False), freshly stages and
    compiles the ordinary caller against the original core, generates + compiles the
    facade/runtime classes and the JNI adapter DLL, and compares the ORIGINAL vs
    PROTECTED arms over the EXPLICIT application-samples contract (exact stdout + exit
    status on every case). Persists ``output_dir/integration.json`` and returns the
    disclosed report. ``status`` is ``jvm_application_samples_passed`` only after
    authentic source/core/toolchain/staged pins, original/protected observations,
    missing-core/missing-adapter fail-closed controls, the exact deployment allowlist,
    and final STOP/pin checks. The optional ``trusted_inputs`` is a bounded list of
    ``{path, sha256}`` records re-verified from disk around every child (no code run).
    """
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
        raise JvmIntegrateError("timeout_seconds must be 1..600")
    trusted_norm = _normalize_trusted_inputs(trusted_inputs)   # fail closed on malformed records up front
    workspace = WorkspacePlan.resolve(workspace_root=workspace_root, out_dir=output_dir)
    prepared = plan(producer_report_path, integration_spec_path, application_contract_path, workspace=workspace)
    prepared = load_plan(serialize_plan(prepared))             # save+reload, re-validate fingerprint by trusted name
    staging = prepare(prepared, workspace)
    result = validate(prepared, staging, workspace, timeout_seconds=timeout_seconds, trusted_inputs=trusted_norm)

    pinned = prepared["pinned"]
    comparison = result["comparison"]
    evidence = result["evidence"]
    # Top-level status is the PUBLIC passing status only when the comparison passed.
    status = "jvm_application_samples_passed" if result["passed"] else "failed"
    report = {
        "schema_version": SCHEMA_VERSION, "status": status,
        "scope": "jvm_producer_bound_ordinary_app_integration",
        "integration_mode": "explicit_source_integrate",
        "language": pinned["language"], "main_class": prepared["spec"]["main_class"],
        "plan_fingerprint": prepared["plan_fingerprint"], "plan_round_trip_through_json": True,
        "facade_module": TRUSTED_FACADE_MODULE, "engine_binding": prepared["engine_binding"],
        "plan_input_snapshot": prepared["input_snapshot"],
        # Producer block the service re-checks (backend + both native artifact pins).
        "producer": {"backend": pinned["backend"],
                     "report_path": pinned["report_path"], "report_sha256": pinned["report_sha256"],
                     "artifacts": {"protected": pinned["protected"], "baseline": pinned["baseline"]},
                     "contract_path": pinned["contract_path"], "contract_sha256": pinned["contract_sha256"],
                     "native_report": pinned.get("native_report"), "native_library": pinned["native_library"]},
        "caller_provenance": "freshly_staged_compiled_executed",
        "generated_runtime_provenance": "freshly_generated_compiled",
        "fresh_protected_native_build": False,
        # Staging block the service re-checks (reused native core sha + JNI adapter pin).
        "staging": result["staging"],
        "staging_manifest": staging["manifest"],
        "comparison": comparison,
        "preparation_commands": result["preparation_commands"],
        "deployment": result["deployment"],
        "integrity_preflight": comparison["integrity_preflight"],
        "integrity_postflight": comparison["integrity_postflight"],
        "trusted_inputs_verification": evidence["trusted_inputs_verification"],
        "native_tool_pins": evidence["native_tool_pins"],
        "jni_headers": evidence["jni_headers"],
        "evidence": evidence,
        "project_service_contract": project_service_contract(),
        "qualification": qualification_status(result),
        "api_version": API_VERSION, "support_level": SUPPORT_LEVEL,
        "whole_language_support": WHOLE_LANGUAGE_SUPPORT,
        "external_attack_evaluation": "not_evaluated", "performance_evaluation": "not_evaluated",
        "defense_strength_evaluation": "not_evaluated",
        "full_suite_freeze": "root_owned_pending_all_editor_agreement",
    }
    out = Path(workspace.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "integration.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report
