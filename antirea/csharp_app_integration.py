"""Self-contained producer-bound C# managed-application integration (wave 5).

This is the public-adoption pass over the wave-4 generic candidate
(``.runs/orca-wave4-csharp/candidate/antirea/csharp_app_integration.py``,
phase-18 SHA-256 34e27bde13e4bf84d50f2e87b2e7fb1b320f24f76fddda6d7e3dca69844526a2).
The wave-4 candidate still loaded its source-transform module from an ARBITRARY
caller-supplied filesystem path via ``importlib.util.spec_from_file_location`` and
injected a workspace root onto ``sys.path``. Both are removed here so the module
can live under the real ``antirea`` package with NO executable ``.runs`` path, NO
fixed repo-root depth, and NO arbitrary import-path injection:

  * The transform is the OWNED, in-package module ``antirea.csharp_transform``,
    loaded ONLY by that trusted module name (``importlib.import_module``); any
    other transform module name/path supplied by the project is rejected.
  * Engine dependencies (``antirea.dotnet_frontend`` / ``source_validate`` /
    ``bindings`` / ``process``) are imported by name, never by injecting a path.
  * The PLAN is a plain JSON-serializable dict (no live dataclass/module handles):
    it can be written to disk and reloaded, and its ``plan_fingerprint`` is
    re-validated at load, at prepare and at validate. Reconstruction never takes a
    project-supplied importlib path; it only re-imports trusted known modules.

Run-specific inputs still arrive through four explicit, immutable snapshot inputs
so a public project service can drive it against ANY producer build, toolchain and
workspace without editing this file:

  * ``ProducerManifest``       -- the trusted producer build report to consume.
  * ``ProtectedBuildReceipt``  -- the immutable protected/baseline artifact pins
                                  the caller declares it is reusing (honestly
                                  labelled; never called a fresh protected-native
                                  build when a pinned artifact is reused).
  * ``ToolchainSnapshot``      -- the discovered compiler identity (pure disk
                                  hashing via ``dotnet_frontend._compiler``; no
                                  cached ``env.setting`` / link responses).
  * ``WorkspacePlan``          -- workspace root, fresh out dir, the trusted
                                  transform module NAME, and the real workspace
                                  STOP marker used as the child cancel file.

It does NOT re-implement the IL->native lowering or the native protection: it
*consumes* real artifacts produced by ``antirea.dotnet_frontend`` /
``antirea.native_build`` and binds an ordinary managed application to them, then
proves, by re-deriving every pin from on-disk bytes, that the binary comparison
ran against exactly the staged source and native artifacts.

Preserved from wave 3 without weakening (each re-tested):
  * method selection is confirmed from the compiler's OWN emitted IL metadata,
    never from the caller-echoed selector;
  * the native core is the producer's protected artifact, re-hashed from disk and
    captured in the full frozen native inventory (native-origin evidence);
  * the full exact staged-tree inventory of every frozen root detects changed /
    missing / extra (injected) files; integrity is recomputed at preflight and
    postflight and the native core + compiled assemblies are re-pinned before each
    executed case;
  * STOP is checked at preflight, between children, before each case and at
    postflight, and every child is individually cancellable via the STOP marker.

Caller wrappers (``NativeCore.cs`` / ``ProtectedBootstrap.cs`` / the rewritten
leaves) are GENERATED from the application source and the compiler-derived
contract by the owned trusted transform module -- never from a project path.

Scope / non-claims (fail closed, never overclaim):
  * Installed C# toolchain + owned source only. No install/restore/download/
    publish/push. Received code is never executed.
  * Child processes are bounded, run under a minimal private env and are cleaned
    up. Windows Job cleanup is cleanup evidence, not an atomic security sandbox;
    process ownership is not a security boundary.
  * This is an EXPERIMENTAL producer-bound ``explicit_source_integrate`` seam. It
    makes NO performance, defense-strength, whole-application, whole-language or
    external-attack claim; those stay ``not_evaluated``. The module implements the
    gate logic, but gate CLOSURE and final qualification are owned by root's
    frozen-source full suite and fresh public native/app run, not by this module.
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
MANIFEST_SCHEMA_VERSION = 3          # wave-5: owned transform + engine binding.
PLAN_SCHEMA_VERSION = 1              # wave-5: JSON-serializable plan.
PUBLIC_API_VERSION = "3.0"
# Production adoption (phase20): this module is adopted into the antirea package as
# an EXPERIMENTAL, producer-bound managed-application integration seam that a public
# ``ProjectService`` drives. ``API_VERSION`` identifies that public-facing surface.
# This is explicitly NOT a whole-language C# claim: only owned, installed-toolchain
# managed applications bound to a pre-produced native core are in scope, and defense
# strength, performance and external-attack resistance remain ``not_evaluated``.
API_VERSION = "phase20.1-experimental"
SUPPORT_LEVEL = "experimental"
WHOLE_LANGUAGE_SUPPORT = False

# The transform is the OWNED in-package module, loaded ONLY by this trusted name.
# There is no caller-supplied transform path and no importlib path injection.
TRUSTED_TRANSFORM_MODULE = "antirea.csharp_transform"
# Trusted engine modules bound (by name + on-disk source hash) into every plan so
# a change to the transform or the engine is detected before/at prepare and run.
# This INCLUDES the integration engine itself (``antirea.csharp_app_integration``):
# a saved plan binds the actual engine bytes, not just the transform/dependencies.
TRUSTED_ENGINE_MODULES = (
    "antirea.csharp_app_integration", "antirea.csharp_transform",
    "antirea.dotnet_frontend", "antirea.source_validate",
    "antirea.bindings", "antirea.process")

# Staged directories that must stay byte-frozen across the whole run. Build
# outputs (compiled DLLs, runtimeconfig, probe/inspect assemblies, logs) are
# written as siblings of these roots, never inside them.
FROZEN_ROOT_NAMES = ("original", "deployable_bundle", "native")

_ABI = {"Int32": "i32", "UInt32": "u32", "Int64": "i64", "UInt64": "u64"}
_CS_ALIAS = {"int": "Int32", "uint": "UInt32", "long": "Int64", "ulong": "UInt64"}
_CSC_FLAGS = ("-nologo", "-noconfig", "-nostdlib+", "-optimize+", "-deterministic+",
              "-checked-", "-unsafe-", "-langversion:12")

# The live workspace defense STOP marker, relative to the workspace root. This is
# the controller cancel file (not a historical run directory); it is only ever
# checked for existence here, never created, read or deleted.
STOP_RELATIVE = ".runs/defense-loop/STOP"


class ProducerIntegrateError(ValueError):
    """Raised for any producer/report/identity/build inconsistency (fail closed)."""


class StagingIntegrityError(ProducerIntegrateError):
    """A bound staged input changed / went missing / was injected (fail closed)."""


# --------------------------------------------------------------------------- #
# Byte-level helpers (pure disk hashing; symlink/reparse and received guards).
# --------------------------------------------------------------------------- #
# Reserved path components that must never be read/hashed/traversed as a consumed
# input. Rejected LEXICALLY (pure string inspection of the absolutized path parts,
# no stat/lstat/resolve and no read) so the check runs BEFORE any stat/read/hash/
# traversal. The ONLY exception is the real workspace STOP existence probe, which
# is never routed through here (``_check_stop`` only tests ``Path.exists()``).
RESERVED_PATH_COMPONENTS = frozenset(
    {"rea-analysis-reports", "attackerfolder", "defense-loop", "env.setting", "linkrepro"})

# Bounded reads: a single consumed/hashed regular file and a frozen staged tree are
# size/entry bounded so a hostile or accidental giant input cannot drive an
# unbounded read. The native core / compiled assemblies are well under these.
_MAX_FILE_BYTES = 64 << 20            # 64 MiB per consumed/hashed regular file
_MAX_TREE_ENTRIES = 20000            # max files in a single frozen staged root
_MAX_TREE_BYTES = 512 << 20          # max total bytes in a single frozen staged root


def _reserved_guard(path) -> None:
    """Reject a path that lexically contains a reserved/received component.

    Pure string inspection of the absolutized path parts -- no stat/lstat/resolve,
    no read -- so it runs before any stat/read/hash/traversal of a consumed path.
    """
    for part in Path(os.path.abspath(str(path))).parts:
        if part.casefold() in RESERVED_PATH_COMPONENTS:
            raise ProducerIntegrateError(
                "path lexically traverses a reserved/received component %r: %s" % (part, path))


def _guarded_regular_file(path, *, limit: int = _MAX_FILE_BYTES) -> int:
    """Shared pre-read gate for EVERY consumed file: lexical reserved guard FIRST,
    then symlink/reparse rejection, then a regular-file check, then a size bound.
    Returns the (bounded) file size. Fail closed on anything unexpected."""
    _reserved_guard(path)                      # lexical guard BEFORE any stat/read
    p = Path(path)
    _no_links(p)                               # reject symlink/reparse (fail closed on OS error)
    try:
        info = p.lstat()
    except OSError as exc:
        raise ProducerIntegrateError("cannot stat consumed file (fail closed): %s (%s)" % (p, exc))
    if not stat.S_ISREG(info.st_mode):
        raise ProducerIntegrateError("consumed path is not a regular file: " + str(p))
    size = info.st_size
    if size > limit:
        raise ProducerIntegrateError("file exceeds bounded read limit (%d > %d bytes): %s" % (size, limit, p))
    return size


def _hash_file(path, *, limit: int = _MAX_FILE_BYTES) -> str:
    _guarded_regular_file(path, limit=limit)   # reserved-first, nonlinked, regular, stat pre-check
    h = hashlib.sha256()
    streamed = 0                               # the stat is a pre-check; the stream count is the real bound
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            streamed += len(chunk)
            if streamed > limit:
                raise ProducerIntegrateError(
                    "file exceeded bounded read limit while hashing (grew past %d bytes): %s" % (limit, path))
            h.update(chunk)
    return h.hexdigest()


def _read_bytes_bounded(path, *, limit: int = _MAX_FILE_BYTES) -> bytes:
    _guarded_regular_file(path, limit=limit)   # reserved-first, nonlinked, regular, stat pre-check
    with open(path, "rb") as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:                      # reject growth past the bound; never silently truncate
        raise ProducerIntegrateError("file exceeded bounded read limit during read (> %d bytes): %s" % (limit, path))
    return data


def _read_text_bounded(path, *, limit: int = _MAX_FILE_BYTES, encoding: str = "utf-8") -> str:
    return _read_bytes_bounded(path, limit=limit).decode(encoding)


def _no_links(path: Path):
    _reserved_guard(path)                      # lexical guard BEFORE any lstat
    for item in (Path(path), *Path(path).parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue                           # absent item cannot be a link
        except OSError as exc:                 # fail CLOSED on any other OS error
            raise ProducerIntegrateError("link check failed (fail closed) for %s: %s" % (item, exc))
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ProducerIntegrateError("path traverses a symlink/reparse point: " + str(item))


def _received_guard(root: Path, path: Path):
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
            raise ProducerIntegrateError(
                "received/shared/reserved artifacts cannot be consumed here: " + str(path))


def _tree_inventory(root: Path) -> dict:
    """Full exact recursive inventory of ``root`` -> {posix_relpath: {sha256,bytes}}.

    Bounded manual walk via ``os.scandir`` (NOT ``rglob``): the lexical reserved
    guard and symlink/reparse rejection run on EVERY entry BEFORE it is stat'd or a
    directory is descended into, symlinks are never followed, and both the directory
    and file counts are bounded along with the total byte size (fail closed)."""
    root = Path(os.path.abspath(root))
    _reserved_guard(root)
    _no_links(root)
    if not root.is_dir():
        raise ProducerIntegrateError("frozen staged root is not a directory: " + str(root))
    inventory = {}
    total_bytes = 0
    entry_count = 0                              # directories AND files both counted
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            scan = os.scandir(current)
        except OSError as exc:
            raise ProducerIntegrateError("frozen staged root unreadable (fail closed): %s (%s)" % (current, exc))
        with scan:
            for entry in scan:
                p = Path(entry.path)
                _reserved_guard(p)               # lexical guard BEFORE any stat/descent
                entry_count += 1
                if entry_count > _MAX_TREE_ENTRIES:
                    raise ProducerIntegrateError(
                        "frozen staged root exceeds the bounded entry count (%d): %s" % (_MAX_TREE_ENTRIES, root))
                try:
                    is_link = entry.is_symlink()
                    info = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise ProducerIntegrateError("frozen entry unreadable (fail closed): %s (%s)" % (p, exc))
                if is_link or (getattr(info, "st_file_attributes", 0) & 0x400):
                    raise ProducerIntegrateError("frozen staged root holds a symlink/reparse entry: " + str(p))
                if stat.S_ISDIR(info.st_mode):
                    stack.append(p)              # descend only into real directories
                    continue
                if not stat.S_ISREG(info.st_mode):
                    raise ProducerIntegrateError("frozen staged root holds a non-regular entry: " + str(p))
                total_bytes += info.st_size
                if total_bytes > _MAX_TREE_BYTES:
                    raise ProducerIntegrateError("frozen staged root exceeds the bounded total bytes: " + str(root))
                rel = p.relative_to(root).as_posix()
                inventory[rel] = {"sha256": _hash_file(p), "bytes": info.st_size}
    return inventory


def _inventory_diff(bound: dict, disk: dict):
    bk, dk = set(bound), set(disk)
    missing = sorted(bk - dk)
    extra = sorted(dk - bk)
    changed = sorted(k for k in (bk & dk) if bound[k]["sha256"] != disk[k]["sha256"])
    return missing, extra, changed


def _compiler_digest(input_hashes: dict) -> str:
    return hashlib.sha256(json.dumps(input_hashes, sort_keys=True).encode("utf-8")).hexdigest()


def _load_transform(module_name: str = TRUSTED_TRANSFORM_MODULE, *, expected_sha256: str | None = None):
    """Load the OWNED source-transform module by its trusted name ONLY.

    No arbitrary module path/name supplied by the project is accepted: the engine
    loads exactly ``antirea.csharp_transform``, the owned in-package transform.
    There is no ``spec_from_file_location`` on a caller path and no ``sys.path``
    injection. When ``expected_sha256`` is given, the transform's on-disk source is
    LOCATED and HASHED first (via ``_locate_module_source``, which never executes
    the leaf module) and the import is refused on a hash mismatch, so a drifted
    transform is never executed before its bytes are verified -- including in a
    fresh process that loads a saved plan with the transform not yet imported.
    """
    if module_name != TRUSTED_TRANSFORM_MODULE:
        raise ProducerIntegrateError(
            "only the trusted owned transform module %r may be loaded; an arbitrary "
            "transform module name/path supplied by the project is rejected: %r"
            % (TRUSTED_TRANSFORM_MODULE, module_name))
    source = _locate_module_source(module_name)          # locate WITHOUT executing the leaf
    actual = _hash_file(source)
    if expected_sha256 is not None and actual != expected_sha256:
        raise ProducerIntegrateError(
            "trusted transform source changed since it was bound; refusing to import a drifted "
            "transform (expected %s, on disk %s)" % (expected_sha256, actual))
    module = importlib.import_module(module_name)         # verified -> now safe to execute
    if not hasattr(module, "write_integration"):
        raise ProducerIntegrateError("trusted transform module has no write_integration entry point")
    return module


def _engine():
    """Return the trusted engine modules, imported BY NAME (no path injection)."""
    dotnet_frontend = importlib.import_module("antirea.dotnet_frontend")
    source_validate = importlib.import_module("antirea.source_validate")
    bindings = importlib.import_module("antirea.bindings")
    process = importlib.import_module("antirea.process")
    return dotnet_frontend, source_validate, bindings, process


def _locate_module_source(module_name: str) -> Path:
    """Locate a module's on-disk source file WITHOUT importing/executing the leaf.

    Uses ``importlib.util.find_spec``, which imports only parent packages and never
    executes the named leaf module, so a drifted leaf is never run before its bytes
    are hashed. Returns the resolved source ``Path`` (reparse/symlink rejected).
    """
    try:
        spec = importlib.util.find_spec(module_name)
    except (ImportError, AttributeError, ValueError) as exc:
        raise ProducerIntegrateError("cannot locate module %s without importing it: %s" % (module_name, exc))
    origin = getattr(spec, "origin", None) if spec is not None else None
    if not origin or origin in ("built-in", "frozen", "namespace") or not origin.endswith(".py"):
        raise ProducerIntegrateError("module has no importable .py source file: " + str(module_name))
    p = Path(os.path.abspath(origin))
    _no_links(p)
    if not p.is_file():
        raise ProducerIntegrateError("module source missing on disk: " + str(p))
    return p


def _module_source_identity(module_name: str) -> dict:
    """Bind a TRUSTED module by name + on-disk source hash, WITHOUT executing it.

    The path is resolved via :func:`_locate_module_source` (non-executing
    find_spec), never from a project-supplied path and never by importing the leaf.
    This binds the transform/engine source bytes into the plan so later drift is
    detected -- and, critically, detected before the module is ever executed.
    """
    if module_name not in TRUSTED_ENGINE_MODULES:
        raise ProducerIntegrateError("refusing to bind an untrusted module: " + str(module_name))
    p = _locate_module_source(module_name)
    return {"module": module_name, "path": str(p), "sha256": _hash_file(p)}


def _engine_binding() -> dict:
    """Bind the owned transform + every trusted engine module by name + source hash."""
    return {name: _module_source_identity(name) for name in TRUSTED_ENGINE_MODULES}


def _engine_binding_digest(engine_binding: dict) -> str:
    reduced = {name: entry["sha256"] for name, entry in engine_binding.items()}
    return hashlib.sha256(json.dumps(reduced, sort_keys=True).encode("utf-8")).hexdigest()


def _canonical(cs_type: str) -> str:
    key = cs_type.strip()
    if key not in _CS_ALIAS:
        raise ProducerIntegrateError("unsupported managed keyword type: %r" % (cs_type,))
    return _CS_ALIAS[key]


def _stop_path(workspace_root) -> Path:
    return Path(os.path.abspath(workspace_root)) / STOP_RELATIVE


def _same_path(a, b) -> bool:
    return os.path.normcase(os.path.abspath(str(a))) == os.path.normcase(os.path.abspath(str(b)))


def _check_stop(real_stop: Path, fixture_stop, phase: str):
    """Fail closed if EITHER the real workspace STOP marker OR an optional fixture
    cancellation marker exists. Existence-only; neither file is created/read/deleted.
    The optional fixture can only ADD a reason to stop; it can never suppress the
    real workspace STOP."""
    if Path(real_stop).exists():
        raise ProducerIntegrateError("workspace defense STOP present at %s; refusing to proceed" % phase)
    if fixture_stop is not None and Path(fixture_stop).exists():
        raise ProducerIntegrateError("fixture cancellation present at %s; refusing to proceed" % phase)


# --------------------------------------------------------------------------- #
# Explicit immutable snapshot inputs (the reusable public API surface).
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class WorkspacePlan:
    """Workspace + trusted-transform NAME + STOP marker snapshot.

    ``transform_module`` is the trusted owned module NAME (``antirea.csharp_transform``),
    never a filesystem path: there is no arbitrary transform path to inject.
    """
    workspace_root: Path
    out_dir: Path
    stop_file: Path | None = None
    transform_module: str = TRUSTED_TRANSFORM_MODULE
    frozen_root_names: tuple = FROZEN_ROOT_NAMES

    @classmethod
    def resolve(cls, *, workspace_root, out_dir, stop_file=None,
                transform_module: str = TRUSTED_TRANSFORM_MODULE,
                require_fresh_out: bool = True) -> "WorkspacePlan":
        wr = Path(os.path.abspath(workspace_root))
        out = Path(os.path.abspath(out_dir))
        # LEXICAL reserved-name guard + symlink/reparse rejection FIRST, before any
        # probing stat (``is_dir``/``exists``) of the workspace root or out dir.
        _reserved_guard(wr)
        _reserved_guard(out)
        _no_links(wr)
        _no_links(out)
        if transform_module != TRUSTED_TRANSFORM_MODULE:
            raise ProducerIntegrateError(
                "workspace transform_module must be the trusted owned module %r; an arbitrary "
                "transform module name/path is not accepted: %r" % (TRUSTED_TRANSFORM_MODULE, transform_module))
        if not out.is_relative_to(wr / ".runs"):
            raise ProducerIntegrateError("out_dir must live under workspace/.runs")
        if not (wr / "antirea").is_dir():
            raise ProducerIntegrateError("workspace_root does not contain an antirea/ package: " + str(wr))
        if require_fresh_out and out.exists():
            raise ProducerIntegrateError("out_dir must be fresh (append-only runs): " + str(out))
        stop = Path(os.path.abspath(stop_file)) if stop_file is not None else _stop_path(wr)
        return cls(workspace_root=wr, out_dir=out, stop_file=stop, transform_module=transform_module,
                   frozen_root_names=tuple(FROZEN_ROOT_NAMES))


@dataclass(frozen=True)
class ProducerManifest:
    """The trusted producer build report to consume (re-hashed from disk)."""
    report_path: Path

    @classmethod
    def at(cls, report_path) -> "ProducerManifest":
        return cls(report_path=Path(os.path.abspath(report_path)))


@dataclass(frozen=True)
class ProtectedBuildReceipt:
    """Immutable protected/baseline artifact pins the caller declares it reuses.

    ``fresh_protected_native_build`` MUST be False for a reused pinned artifact;
    the honest provenance label is recorded verbatim in every output report. The
    pins are cross-checked against the producer report's own artifacts (both the
    report claim and the on-disk bytes) in :func:`plan`.
    """
    protected_path: Path
    protected_sha256: str
    baseline_path: Path
    baseline_sha256: str
    provenance: str
    fresh_protected_native_build: bool = False

    @classmethod
    def reused_from_report(cls, report_path, *, workspace_root,
                           provenance: str = "reused_pinned_native_artifact_reverified_from_disk"
                           ) -> "ProtectedBuildReceipt":
        """Build a REUSE receipt from a producer report's declared artifacts.

        This is a convenience for the common "reuse an existing pinned native
        artifact" path; it explicitly marks ``fresh_protected_native_build=False``.
        The pins are still independently re-hashed and cross-checked in plan().
        """
        rp = Path(os.path.abspath(report_path))
        root = Path(os.path.abspath(workspace_root))
        _no_links(rp)
        if not rp.is_relative_to(root / ".runs"):
            raise ProducerIntegrateError("producer report must live under workspace/.runs")
        _received_guard(root, rp)
        report = json.loads(_read_text_bounded(rp))
        arts = report.get("artifacts") if isinstance(report, dict) else None
        if not isinstance(arts, dict) or "protected" not in arts or "baseline" not in arts:
            raise ProducerIntegrateError("producer report missing baseline/protected artifacts")
        prot, base = arts["protected"], arts["baseline"]
        return cls(protected_path=Path(os.path.abspath(prot["path"])), protected_sha256=prot["sha256"],
                   baseline_path=Path(os.path.abspath(base["path"])), baseline_sha256=base["sha256"],
                   provenance=provenance, fresh_protected_native_build=False)


@dataclass(frozen=True)
class ToolchainSnapshot:
    """Discovered compiler identity (pure disk hashing; no cached env.setting)."""
    compiler: dict

    @classmethod
    def discover(cls, *, workspace_root) -> "ToolchainSnapshot":
        dotnet_frontend, _, _, _ = _engine()
        return cls(compiler=dotnet_frontend._compiler())


# --------------------------------------------------------------------------- #
# 1. Consume + pin the producer report (every hash re-derived from disk bytes).
# --------------------------------------------------------------------------- #
def load_producer_report(report_path, *, workspace_root) -> dict:
    report_path = Path(os.path.abspath(report_path))
    root = Path(os.path.abspath(workspace_root))
    _no_links(report_path)
    if not report_path.is_relative_to(root / ".runs"):
        raise ProducerIntegrateError("producer report must live under workspace/.runs")
    _received_guard(root, report_path)
    report = json.loads(_read_text_bounded(report_path))
    if not isinstance(report, dict):
        raise ProducerIntegrateError("producer report must be a JSON object")
    if report.get("backend") != "dotnet_il_native":
        raise ProducerIntegrateError("producer backend must be dotnet_il_native, got %r" % (report.get("backend"),))
    if report.get("status") != "artifact_created_unvalidated":
        raise ProducerIntegrateError(
            "producer status must be artifact_created_unvalidated (a real successful build), got %r"
            % (report.get("status"),))
    artifacts = report.get("artifacts")
    if not isinstance(artifacts, dict) or "protected" not in artifacts or "baseline" not in artifacts:
        raise ProducerIntegrateError("producer report missing baseline/protected artifacts")

    directory = report_path.parent
    pinned_artifacts = {}
    for arm in ("baseline", "protected"):
        entry = artifacts[arm]
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str) or not isinstance(entry.get("sha256"), str):
            raise ProducerIntegrateError("artifact entry malformed: " + arm)
        path = Path(os.path.abspath(entry["path"]))
        _no_links(path)
        if not path.is_relative_to(directory):
            raise ProducerIntegrateError("producer artifact escapes its build directory: " + str(path))
        if not path.is_file():
            raise ProducerIntegrateError("producer artifact missing on disk: " + str(path))
        actual = _hash_file(path)
        if actual != entry["sha256"]:     # report hash is a CLAIM; disk bytes are the evidence
            raise ProducerIntegrateError(
                "producer artifact hash mismatch for %s: report %s vs disk %s" % (arm, entry["sha256"], actual))
        pinned_artifacts[arm] = {"path": str(path), "sha256": actual, "bytes": path.stat().st_size}

    frontend = report.get("frontend")
    if not isinstance(frontend, dict) or not isinstance(frontend.get("methods"), list):
        raise ProducerIntegrateError("producer report has no frontend method metadata")

    contract_path = Path(os.path.abspath(report["contract_path"]))
    _no_links(contract_path)
    if not contract_path.is_relative_to(directory):
        raise ProducerIntegrateError("producer contract escapes its build directory")
    contract = json.loads(_read_text_bounded(contract_path))
    contract_sha256 = _hash_file(contract_path)

    project = frontend.get("project")
    source_hashes = frontend.get("source_hashes")
    if not isinstance(project, dict) or not isinstance(source_hashes, dict) or not isinstance(project.get("sources"), list):
        raise ProducerIntegrateError("producer report is missing project source pins")
    producer_sources = {}
    producer_source_paths = {}
    for abs_source in project["sources"]:
        src = Path(os.path.abspath(abs_source))
        _reserved_guard(src)                   # lexical guard BEFORE no_links/stat/hash
        _no_links(src)
        # A FRESH public source-build compiles owned application sources under the
        # workspace (e.g. samples/multilang/csharp_application), not only under
        # .runs; allow bounded, nonlinked, exact-pinned sources anywhere inside the
        # OWNED workspace, while the report/contract/artifacts stay in the owned
        # .runs producer directory (checked above). Exact pin stays mandatory.
        if not src.is_relative_to(root):
            raise ProducerIntegrateError("producer source escapes the owned workspace: " + str(src))
        _received_guard(root, src)
        name = src.name
        if abs_source not in source_hashes:
            raise ProducerIntegrateError("producer source not pinned in source_hashes: " + abs_source)
        if name in producer_sources:
            raise ProducerIntegrateError("ambiguous producer source basename: " + name)
        if not src.is_file():
            raise ProducerIntegrateError("producer-compiled source missing on disk: " + str(src))
        disk_hash = _hash_file(src)
        if disk_hash != source_hashes[abs_source]:
            raise ProducerIntegrateError(
                "producer-compiled source bytes differ from the report claim for %s: disk %s vs report %s"
                % (name, disk_hash, source_hashes[abs_source]))
        producer_sources[name] = disk_hash
        producer_source_paths[name] = str(src)

    compiler_inputs = frontend.get("compiler_inputs")
    if not isinstance(compiler_inputs, dict) or not compiler_inputs:
        raise ProducerIntegrateError("producer report is missing compiler input pins")

    return {"report": report, "report_path": str(report_path), "report_sha256": _hash_file(report_path),
            "build_dir": str(directory), "baseline": pinned_artifacts["baseline"],
            "protected": pinned_artifacts["protected"], "contract_path": str(contract_path),
            "contract": contract, "contract_sha256": contract_sha256,
            "frontend_methods": frontend["methods"],
            "producer_sources": producer_sources, "producer_source_paths": producer_source_paths,
            "compiler_inputs": compiler_inputs}


def _cross_check_receipt(pinned: dict, receipt) -> dict:
    """Require the caller's protected-build receipt to match the producer report's
    own baseline/protected artifacts (both the report claim re-hashed from disk and
    the receipt's declared pins). Fail closed on any disagreement."""
    out = {}
    for arm, decl_path, decl_sha in (("protected", receipt.protected_path, receipt.protected_sha256),
                                     ("baseline", receipt.baseline_path, receipt.baseline_sha256)):
        pin = pinned[arm]
        if not _same_path(decl_path, pin["path"]):
            raise ProducerIntegrateError(
                "protected-build receipt %s path disagrees with the producer report: %s vs %s"
                % (arm, decl_path, pin["path"]))
        if decl_sha != pin["sha256"]:
            raise ProducerIntegrateError(
                "protected-build receipt %s sha256 disagrees with the on-disk producer artifact" % arm)
        out[arm] = {"path": pin["path"], "sha256": pin["sha256"], "bytes": pin["bytes"]}
    out["provenance"] = receipt.provenance
    out["fresh_protected_native_build"] = bool(receipt.fresh_protected_native_build)
    return out


# --------------------------------------------------------------------------- #
# 2. Identity + signature from the compiler's OWN emitted metadata.
# --------------------------------------------------------------------------- #
def verify_compiler_identity(pinned: dict, selectors: list, *, workspace_root) -> dict:
    _, source_validate, _, _ = _engine()
    report, contract = pinned["report"], pinned["contract"]

    signature = source_validate.verify_source_contract(report, contract)
    if signature.get("status") != "matched":
        raise ProducerIntegrateError("compiler-derived signature binding did not match")

    by_export = {}
    for method in report["frontend"]["methods"]:
        md = method.get("metadata")
        sel = method.get("selector")
        if not isinstance(md, dict) or not isinstance(sel, dict) or not isinstance(sel.get("export"), str):
            raise ProducerIntegrateError("producer method metadata malformed")
        md_type, md_name = md.get("type"), md.get("name")
        if not isinstance(md_type, str) or not isinstance(md_name, str):
            raise ProducerIntegrateError("emitted metadata lacks its own declaring type/name")
        if "`" in md_type or "`" in md_name:
            raise ProducerIntegrateError("generic enclosing type/method is unsupported: " + md_type + "." + md_name)
        ret = _ABI.get(md.get("return_type"))
        params = [_ABI.get(t) for t in md.get("parameters", [])]
        if ret is None or any(p is None for p in params):
            raise ProducerIntegrateError("producer method uses an unsupported scalar type")
        if not (md.get("is_static") and md.get("is_public")) or md.get("generic_count"):
            raise ProducerIntegrateError("producer method is not a public static non-generic leaf: " + md_name)
        by_export[sel["export"]] = {"type": md_type, "name": md_name,
                                    "return_type": ret, "parameter_types": params}

    confirmed = []
    for sel in selectors:
        export = sel["export"]
        meta = by_export.get(export)
        if meta is None:
            raise ProducerIntegrateError("selector export not produced by the compiler: " + export)
        if meta["type"] != sel["type"] or meta["name"] != sel["name"]:
            raise ProducerIntegrateError(
                "requested identity disagrees with emitted compiler metadata for %s: requested %s.%s vs emitted %s.%s"
                % (export, sel["type"], sel["name"], meta["type"], meta["name"]))
        want_params = [_ABI[_canonical(t)] for t in sel["parameters"]]
        if meta["parameter_types"] != want_params:
            raise ProducerIntegrateError(
                "requested parameters disagree with emitted metadata for %s: %s vs %s"
                % (export, want_params, meta["parameter_types"]))
        confirmed.append({"export": export, "type": meta["type"], "name": meta["name"],
                          "return_type": meta["return_type"], "parameter_types": meta["parameter_types"]})

    if {c["export"] for c in confirmed} != set(by_export):
        raise ProducerIntegrateError("selector export set differs from the producer contract export set")
    return {"status": "identity_confirmed", "evidence": "compiler_emitted_il_metadata",
            "signature_binding": signature, "methods": confirmed}


# --------------------------------------------------------------------------- #
# 3. Stage: bind source bytes, byte-accurate transform, pin protected DLL, and
#    BIND the authoritative tamper-evident manifest from on-disk bytes.
# --------------------------------------------------------------------------- #
def _verify_compiler_against_producer(workspace_root, producer_compiler_inputs: dict, *, compiler=None) -> dict:
    dotnet_frontend, _, _, _ = _engine()
    compiler = compiler if compiler is not None else dotnet_frontend._compiler()
    fresh = compiler["input_hashes"]
    # The installed compiler/runtime lives OUTSIDE the workspace (kept in this
    # explicit snapshot, not the trusted_inputs seam) but still gets the same
    # LEXICAL reserved-name guard over every pinned input path (fail closed).
    for input_path in list(producer_compiler_inputs) + [compiler.get("dotnet"), compiler.get("csc")]:
        if input_path:
            _reserved_guard(input_path)
    mismatches = [k for k, v in producer_compiler_inputs.items() if fresh.get(k) != v]
    missing = [k for k in producer_compiler_inputs if k not in fresh]
    if mismatches or missing:
        raise ProducerIntegrateError(
            "freshly discovered compiler does not match the producer's pinned compiler inputs "
            "(mismatch=%d, missing=%d): %s" % (len(mismatches), len(missing), (mismatches + missing)[:5]))
    for key in ("dotnet", "csc"):
        tool = compiler[key]
        if producer_compiler_inputs.get(tool) is None or fresh.get(tool) != producer_compiler_inputs.get(tool):
            raise ProducerIntegrateError("producer/fresh compiler disagree on " + key)
    return compiler


def _bind_compiler_identity(workspace_root, producer_compiler_inputs: dict, *, compiler=None) -> dict:
    compiler = _verify_compiler_against_producer(workspace_root, producer_compiler_inputs, compiler=compiler)
    return {"sdk_version": compiler["sdk_version"], "framework": compiler["framework"],
            "runtime_version": compiler["runtime_version"], "dotnet": compiler["dotnet"],
            "csc": compiler["csc"], "dotnet_sha256": compiler["input_hashes"][compiler["dotnet"]],
            "csc_sha256": compiler["input_hashes"][compiler["csc"]],
            "input_count": len(compiler["input_hashes"]),
            "input_digest": _compiler_digest(compiler["input_hashes"]),
            "producer_match": True}


def stage(app_dir, integration_spec_path, pinned: dict, out_dir, *, workspace_root,
          transform_module: str = TRUSTED_TRANSFORM_MODULE, engine_binding: dict | None = None,
          compiler=None) -> dict:
    app_dir = Path(os.path.abspath(app_dir))
    out = Path(os.path.abspath(out_dir))
    root = Path(os.path.abspath(workspace_root))
    integration_spec_path = Path(os.path.abspath(integration_spec_path))
    _no_links(app_dir)
    _no_links(integration_spec_path)
    if out.exists():
        raise ProducerIntegrateError("staging out_dir must be fresh")
    if not out.is_relative_to(root / ".runs"):
        raise ProducerIntegrateError("staging must be under workspace/.runs")
    # Reject a staging output that overlaps the consumed app sources or the producer
    # build directory (lexical containment; defense-in-depth with _verify_plan_inputs).
    _reject_overlap(out, app_dir, Path(pinned["build_dir"]))
    _received_guard(root, app_dir)
    # Verify the owned transform + engine binding (non-executing find_spec hashes)
    # and the exact trusted key set BEFORE the transform is imported/executed, so a
    # drifted module is rejected before any of its code runs.
    staged_engine_binding = _engine_binding()
    if set(staged_engine_binding) != set(TRUSTED_ENGINE_MODULES):
        raise ProducerIntegrateError("engine binding key set is not exactly the trusted module set")
    if engine_binding is not None:
        if set(engine_binding) != set(TRUSTED_ENGINE_MODULES):
            raise ProducerIntegrateError("supplied engine binding key set is not the trusted module set")
        for name, entry in engine_binding.items():
            cur = staged_engine_binding.get(name)
            if cur is None or cur["sha256"] != entry["sha256"]:
                raise ProducerIntegrateError(
                    "trusted transform/engine module changed between plan and staging: " + str(name))
    # Load the OWNED transform by trusted name only, hash-verified before import.
    transform = _load_transform(transform_module,
                                expected_sha256=staged_engine_binding[TRUSTED_TRANSFORM_MODULE]["sha256"])
    engine_binding = staged_engine_binding

    spec = json.loads(_read_text_bounded(integration_spec_path))
    if spec.get("schema_version") != 1 or not isinstance(spec.get("sources"), list):
        raise ProducerIntegrateError("integration spec must be schema_version 1 with a sources list")
    native_library = spec.get("native_library")
    if not isinstance(native_library, str) or not native_library or "/" in native_library or "\\" in native_library:
        raise ProducerIntegrateError("integration spec must name a simple native_library")
    native_lib_file = native_library + ".dll"

    source_binding = []
    for name in spec["sources"]:
        src = app_dir / name
        _no_links(src)
        if not src.is_file():
            raise ProducerIntegrateError("application source missing: " + name)
        actual = _hash_file(src)
        pinned_hash = pinned["producer_sources"].get(name)
        if pinned_hash is None:
            raise ProducerIntegrateError("application source not among producer-compiled sources: " + name)
        if actual != pinned_hash:
            raise ProducerIntegrateError(
                "application source bytes differ from the producer-compiled pin for %s "
                "(the protected DLL was built from different source): disk %s vs producer %s"
                % (name, actual, pinned_hash))
        source_binding.append({"name": name, "sha256": actual})

    original = out / "original"
    native = out / "native"
    bundle = out / "deployable_bundle"
    for d in (original, native):
        d.mkdir(parents=True)

    # DEPLOYABLE: reuse the supplied byte-accurate transform writer, driven by the
    # PRODUCER (compiler-derived) contract. It preserves BOM/CRLF/final-newline.
    wi = transform.write_integration(app_dir, integration_spec_path, pinned["contract_path"], bundle)
    deployable_dir = bundle / "deployable"

    for name in spec["sources"]:           # ORIGINAL = exact source bytes, no normalization
        shutil.copyfile(app_dir / name, original / name)

    rewritten = set(wi["report"]["rewritten_files"])
    byte_preservation = []
    for name in spec["sources"]:
        src_bytes = _read_bytes_bounded(app_dir / name)
        dep_bytes = _read_bytes_bounded(deployable_dir / name)
        byte_preservation.append({
            "name": name, "role": "rewritten" if name in rewritten else "unchanged",
            "app_bytes": len(src_bytes), "deployable_bytes": len(dep_bytes),
            "identical": (src_bytes == dep_bytes)})
        if name not in rewritten and src_bytes != dep_bytes:
            raise ProducerIntegrateError("unselected file not byte-preserved through staging: " + name)

    interop_evidence = []
    for method in wi["mapping"]["methods"]:
        export = method["export"]
        marker = "call_%s(" % export
        present = any(marker in _read_text_bounded(deployable_dir / n) for n in rewritten)
        if not present:
            raise ProducerIntegrateError("deployable source does not forward into interop for " + export)
        interop_evidence.append({"export": export, "interop_call": method["interop_call"],
                                 "forwarding_call_present": True})

    # Pin: copy the protected DLL (named from the spec's native_library) and
    # re-hash the copy against the producer pin.
    staged_dll = native / native_lib_file
    shutil.copyfile(pinned["protected"]["path"], staged_dll)
    staged_sha = _hash_file(staged_dll)
    if staged_sha != pinned["protected"]["sha256"]:
        raise ProducerIntegrateError("staged protected DLL hash does not match the producer artifact")

    deployable_hashes = {p.name: _hash_file(p) for p in sorted(deployable_dir.glob("*.cs"))}
    original_hashes = {p.name: _hash_file(p) for p in sorted(original.glob("*.cs"))}

    compiler_identity = _bind_compiler_identity(workspace_root, pinned["compiler_inputs"], compiler=compiler)
    frozen_roots = {}
    for name in FROZEN_ROOT_NAMES:
        frozen_roots[name] = _tree_inventory(out / name)
    if staged_dll.relative_to(out / "native").as_posix() not in frozen_roots["native"]:
        raise ProducerIntegrateError("native core not captured in the frozen native inventory")

    # ``engine_binding`` was verified against the current (non-executing) hashes at
    # the top of stage, before the transform was imported; it is recorded verbatim.
    original_app_identity = {name: _hash_file(app_dir / name) for name in spec["sources"]}
    bound_inputs = {
        "app_dir": str(app_dir),
        "original_app_source": original_app_identity,
        "integration_spec": {"path": str(integration_spec_path), "sha256": _hash_file(integration_spec_path)},
        "transform_module": TRUSTED_TRANSFORM_MODULE,
        "engine_binding": dict(staged_engine_binding),
    }

    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "api_version": PUBLIC_API_VERSION,
        "scope": "csharp_producer_bound_managed_app_integration",
        "bound_from": "on_disk_bytes",
        "trusts_report_hashes": False,
        "trusts_stored_manifest": False,
        "out_dir": str(out),
        "native_library": native_library,
        "native_core_file": native_lib_file,
        "transform_module": TRUSTED_TRANSFORM_MODULE,
        "frozen_root_names": list(FROZEN_ROOT_NAMES),
        "producer": {
            "report_path": pinned["report_path"], "report_sha256": pinned["report_sha256"],
            "baseline": dict(pinned["baseline"]), "protected": dict(pinned["protected"]),
            "contract_path": pinned["contract_path"], "contract_sha256": pinned["contract_sha256"],
            "source_paths": dict(pinned["producer_source_paths"]),
        },
        "source_identity": dict(pinned["producer_sources"]),
        "inputs": bound_inputs,
        "frozen_roots": frozen_roots,
        "native_core": {"path": str(staged_dll), "sha256": staged_sha, "bytes": staged_dll.stat().st_size},
        "compiler_identity": compiler_identity,
    }

    return {"out_dir": str(out), "original_dir": str(original), "deployable_dir": str(deployable_dir),
            "native_core": str(staged_dll), "native_core_sha256": staged_sha,
            "native_library": native_library,
            "source_binding": source_binding, "byte_preservation": byte_preservation,
            "interop_evidence": interop_evidence,
            "deployable_source_hashes": deployable_hashes, "original_source_hashes": original_hashes,
            "rewritten_files": wi["report"]["rewritten_files"], "unchanged_files": wi["report"]["unchanged_files"],
            "deployable_sources": sorted(deployable_hashes), "interop_files": sorted(wi["interop"]),
            "report": wi["report"], "mapping": wi["mapping"], "mapping_path": str(bundle / "mapping.json"),
            "producer_compiler_inputs": pinned["compiler_inputs"],
            "engine_binding": dict(staged_engine_binding),
            "transform_module": TRUSTED_TRANSFORM_MODULE,
            "manifest": manifest}


# --------------------------------------------------------------------------- #
# 3b. Re-derive the manifest from disk and reject any drift (fail closed).
# --------------------------------------------------------------------------- #
def verify_staged_integrity(manifest: dict, pinned: dict, *, workspace_root, phase: str,
                            stop_file: Path | None = None, compiler=None) -> dict:
    if not isinstance(manifest, dict) or manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise StagingIntegrityError("unsupported or missing staging manifest")
    root = Path(os.path.abspath(workspace_root))
    real_stop = _stop_path(root)
    _check_stop(real_stop, stop_file, phase)
    out = Path(manifest["out_dir"])
    problems = []

    root_results = {}
    for name in manifest["frozen_root_names"]:
        bound = manifest["frozen_roots"][name]
        try:
            disk = _tree_inventory(out / name)
        except ProducerIntegrateError as exc:
            problems.append("frozen root %s unreadable: %s" % (name, exc))
            continue
        missing, extra, changed = _inventory_diff(bound, disk)
        if missing:
            problems.append("frozen root %s missing %d file(s): %s" % (name, len(missing), missing[:8]))
        if extra:
            problems.append("frozen root %s has %d EXTRA/injected file(s): %s" % (name, len(extra), extra[:8]))
        if changed:
            problems.append("frozen root %s changed %d file(s): %s" % (name, len(changed), changed[:8]))
        root_results[name] = {"files": len(bound), "missing": missing, "extra": extra, "changed": changed}

    nc = manifest["native_core"]
    nc_path = Path(nc["path"])
    if not nc_path.is_file():
        problems.append("native core missing on disk: " + str(nc_path))
    else:
        nc_disk = _hash_file(nc_path)
        if nc_disk != nc["sha256"]:
            problems.append("native core bytes changed: disk %s vs bound %s" % (nc_disk, nc["sha256"]))

    for name, pin in manifest["source_identity"].items():
        sp = manifest["producer"]["source_paths"].get(name)
        if sp is None or not Path(sp).is_file():
            problems.append("producer source path missing for %s" % name)
            continue
        if _hash_file(Path(sp)) != pin:
            problems.append("producer source %s changed: disk vs bound" % name)

    bound_inputs = manifest.get("inputs")
    if not isinstance(bound_inputs, dict):
        problems.append("manifest has no bound inputs section")
    else:
        app_dir = Path(bound_inputs.get("app_dir", ""))
        for name, pin in bound_inputs.get("original_app_source", {}).items():
            p = app_dir / name
            if not p.is_file():
                problems.append("original app source missing on disk: %s" % name)
            elif _hash_file(p) != pin:
                problems.append("original app source %s changed on disk" % name)
        spec_entry = bound_inputs.get("integration_spec")
        if not isinstance(spec_entry, dict):
            problems.append("manifest missing bound input: integration_spec")
        else:
            p = Path(spec_entry["path"])
            if not p.is_file():
                problems.append("bound input integration_spec missing on disk: %s" % p)
            elif _hash_file(p) != spec_entry["sha256"]:
                problems.append("bound input integration_spec bytes changed on disk")
        # Owned transform + engine re-verified BY TRUSTED NAME + source hash, never
        # from a project-supplied path (rejects transform/engine mismatch).
        if bound_inputs.get("transform_module") != TRUSTED_TRANSFORM_MODULE:
            problems.append("manifest transform_module is not the trusted owned module")
        eb = bound_inputs.get("engine_binding")
        if not isinstance(eb, dict) or set(eb) != set(TRUSTED_ENGINE_MODULES):
            problems.append("manifest engine_binding key set is not exactly the trusted module set")
            eb = {}
        else:
            for name, entry in eb.items():
                try:
                    cur = _module_source_identity(name)
                except ProducerIntegrateError as exc:
                    problems.append("engine_binding %s unverifiable: %s" % (name, exc))
                    continue
                if not isinstance(entry, dict) or cur["sha256"] != entry.get("sha256"):
                    label = "transform_module" if name == TRUSTED_TRANSFORM_MODULE else "engine module"
                    problems.append("%s changed on disk since staging: %s" % (label, name))

    prod = manifest["producer"]
    for label, path_key, sha_key in (("report", "report_path", "report_sha256"),
                                     ("contract", "contract_path", "contract_sha256")):
        p = Path(prod[path_key])
        if not p.is_file():
            problems.append("producer %s missing on disk: %s" % (label, p))
        elif _hash_file(p) != prod[sha_key]:
            problems.append("producer %s bytes changed on disk" % label)
    for arm in ("baseline", "protected"):
        entry = prod[arm]
        p = Path(entry["path"])
        if not p.is_file():
            problems.append("producer %s artifact missing on disk: %s" % (arm, p))
        elif _hash_file(p) != entry["sha256"]:
            problems.append("producer %s artifact bytes changed on disk" % arm)

    compiler_match = False
    comp_digest = None
    try:
        comp = _verify_compiler_against_producer(root, pinned["compiler_inputs"], compiler=compiler)
        comp_digest = _compiler_digest(comp["input_hashes"])
        if comp_digest != manifest["compiler_identity"]["input_digest"]:
            problems.append("installed compiler changed since staging (input digest drift)")
        else:
            compiler_match = True
    except ProducerIntegrateError as exc:
        problems.append("compiler/producer pin re-verification failed: %s" % exc)

    _check_stop(real_stop, stop_file, phase + ":post")
    if problems:
        raise StagingIntegrityError("staged integrity (%s) rejected: %s" % (phase, "; ".join(problems)))
    return {"phase": phase, "status": "staged_integrity_verified",
            "frozen_roots": {k: v["files"] for k, v in root_results.items()},
            "native_core_sha256": nc["sha256"],
            "producer_report_sha256": prod["report_sha256"],
            "compiler_input_digest": comp_digest, "compiler_producer_match": compiler_match,
            "source_identity_count": len(manifest["source_identity"])}


# --------------------------------------------------------------------------- #
# 4. Build + bounded original-vs-protected comparison (clean env, STOP-aware).
# --------------------------------------------------------------------------- #
def _clean_env(out_dir: Path, compiler: dict, *, native_core=None) -> dict:
    dotnet_dir = str(Path(compiler["dotnet"]).parent)
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    priv_tmp = out_dir / "_tmp"
    priv_home = out_dir / "_home"
    priv_tmp.mkdir(exist_ok=True)
    priv_home.mkdir(exist_ok=True)
    env = {
        "SystemRoot": sysroot, "windir": sysroot,
        "PATH": os.pathsep.join([dotnet_dir, sysroot + r"\System32", sysroot]),
        "TEMP": str(priv_tmp), "TMP": str(priv_tmp),
        "USERPROFILE": str(priv_home), "APPDATA": str(priv_home / "AppData/Roaming"),
        "LOCALAPPDATA": str(priv_home / "AppData/Local"),
        "DOTNET_ROOT": dotnet_dir, "DOTNET_CLI_HOME": str(priv_home),
        "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
        "DOTNET_NOLOGO": "1", "DOTNET_MULTILEVEL_LOOKUP": "0",
        "NUGET_PACKAGES": str(priv_home / "nuget"),
        "PROCESSOR_ARCHITECTURE": os.environ.get("PROCESSOR_ARCHITECTURE", "AMD64"),
    }
    if native_core is not None:
        env["ANTIREA_NATIVE_CORE"] = str(native_core)
    return env


def _exc_class(stderr: str):
    m = re.search(r"System\.[A-Za-z0-9_.]*Exception", stderr)
    return m.group(0) if m else None


def _read_log(path) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


def _write_runtimeconfig(out_dll, framework, runtime_version):
    cfg = {"runtimeOptions": {"tfm": framework,
                              "framework": {"name": "Microsoft.NETCore.App", "version": runtime_version}}}
    Path(out_dll).with_suffix(".runtimeconfig.json").write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")


_ARITH_OPS = {"mul", "xor", "shr", "shr.un", "and", "or", "add", "sub", "shl", "neg", "not"}
_ENV_SENTINEL = "ANTIREA_W4_AMBIENT_PROBE"

_ENV_PROBE_SRC = """using System;
public static class EnvProbe {
    public static int Main() {
        Console.WriteLine(Environment.GetEnvironmentVariable(\"%s\") ?? \"<unset>\");
        Console.WriteLine(Environment.GetEnvironmentVariable(\"DOTNET_CLI_TELEMETRY_OPTOUT\") ?? \"<unset>\");
        return 0;
    }
}
""" % _ENV_SENTINEL


def _il_counts(dotnet_frontend, metadata, declaring_type, name):
    match = [m for m in metadata["methods"] if m.get("type") == declaring_type and m.get("name") == name]
    if len(match) != 1 or not match[0].get("il"):
        raise ProducerIntegrateError("expected exactly one bodied %s.%s in compiled metadata" % (declaring_type, name))
    instructions = dotnet_frontend.decode_il(match[0]["il"], metadata["opcodes"])
    names = [i["name"] for i in instructions]
    bases = {n[:-2] if n.endswith(".s") else n for n in names}
    return {"instruction_count": len(instructions),
            "call_opcodes": sum(1 for n in names if n == "call" or n.startswith("call")),
            "arith_opcodes": sorted(bases & _ARITH_OPS),
            "opcodes": sorted(set(names))}


def _derive_execution(manifest: dict, staging: dict) -> dict:
    out = Path(manifest["out_dir"])
    derived = {"out_dir": str(out), "original_dir": str(out / "original"),
               "deployable_dir": str(out / "deployable_bundle" / "deployable"),
               "native_core": manifest["native_core"]["path"],
               "native_core_sha256": manifest["native_core"]["sha256"]}
    for key in ("out_dir", "original_dir", "deployable_dir", "native_core"):
        val = staging.get(key)
        if val is not None and not _same_path(val, derived[key]):
            raise StagingIntegrityError(
                "staging path %r disagrees with the frozen manifest: %s vs %s" % (key, val, derived[key]))
    if staging.get("native_core_sha256") not in (None, derived["native_core_sha256"]):
        raise StagingIntegrityError("staging native_core_sha256 disagrees with the frozen manifest")
    nrel = Path(derived["native_core"]).name
    native_inv = manifest["frozen_roots"]["native"]
    if nrel not in native_inv or native_inv[nrel]["sha256"] != derived["native_core_sha256"]:
        raise StagingIntegrityError("native core is not bound in the frozen native inventory")
    return derived


# --------------------------------------------------------------------------- #
# Optional public-compatible trusted_inputs seam (path+sha256 records).
#
# A public ProjectService constructs these records from its saved source inputs and
# the owned service/engine module bytes -- never from arbitrary user argv -- and the
# engine re-verifies them from on-disk bytes at preflight, BEFORE every child, AFTER
# every child, and at postflight. Records are data only: NO code is imported or
# executed from them. The ``role`` field is an optional bounded diagnostic string
# echoed into the report; it carries no authority and never affects control flow.
# The installed compiler/runtime (outside the workspace) is NOT bound here; it stays
# in the explicit compiler snapshot, verified separately with the same lexical guard.
# --------------------------------------------------------------------------- #
_MAX_TRUSTED_INPUTS = 128                       # bounded record count (fail closed over)
_MAX_TRUSTED_INPUT_BYTES = 16 << 20            # 16 MiB per trusted-input record
_MAX_TRUSTED_INPUTS_TOTAL_BYTES = 128 << 20    # 128 MiB across all records
_TRUSTED_ROLE_MAXLEN = 64
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _normalize_trusted_inputs(trusted_inputs) -> list:
    """Validate the OPTIONAL trusted_inputs list shape WITHOUT touching disk.

    Returns a normalized ``[{path, sha256, role}]`` list. Every record is validated
    and NONE is silently dropped: any malformed / non-absolute / out-of-bound record
    fails closed. The lexical reserved-name guard runs here, before any stat/read.
    """
    if trusted_inputs is None:
        return []
    if not isinstance(trusted_inputs, list):
        raise ProducerIntegrateError("trusted_inputs must be a list of {path, sha256} records")
    if len(trusted_inputs) > _MAX_TRUSTED_INPUTS:
        raise ProducerIntegrateError("too many trusted_inputs records (max %d)" % _MAX_TRUSTED_INPUTS)
    out, seen = [], set()
    for idx, rec in enumerate(trusted_inputs):
        if not isinstance(rec, dict):
            raise ProducerIntegrateError("trusted_inputs[%d] must be an object" % idx)
        extra = set(rec) - {"path", "sha256", "role"}
        if extra:
            raise ProducerIntegrateError("trusted_inputs[%d] has unsupported key(s): %s" % (idx, ", ".join(sorted(extra))))
        if "path" not in rec or "sha256" not in rec:
            raise ProducerIntegrateError("trusted_inputs[%d] requires both path and sha256" % idx)
        path, sha, role = rec["path"], rec["sha256"], rec.get("role")
        if not isinstance(path, str) or not path:
            raise ProducerIntegrateError("trusted_inputs[%d].path must be a non-empty string" % idx)
        if not os.path.isabs(path):
            raise ProducerIntegrateError("trusted_inputs[%d].path must be absolute: %r" % (idx, path))
        if not isinstance(sha, str) or not _SHA256_RE.fullmatch(sha):
            raise ProducerIntegrateError("trusted_inputs[%d].sha256 must be a lowercase 64-hex digest" % idx)
        if role is not None and (not isinstance(role, str) or len(role) > _TRUSTED_ROLE_MAXLEN or not role.isprintable()):
            raise ProducerIntegrateError("trusted_inputs[%d].role must be a short printable diagnostic string" % idx)
        _reserved_guard(path)                   # lexical reserved-name guard before any stat/read/hash
        key = os.path.normcase(os.path.abspath(path))
        if key in seen:
            raise ProducerIntegrateError("trusted_inputs[%d] duplicate path: %r" % (idx, path))
        seen.add(key)
        out.append({"path": os.path.abspath(path), "sha256": sha, "role": role})
    return out


def _verify_trusted_inputs(normalized: list, *, workspace_root, phase: str) -> dict:
    """Re-verify each trusted-input record against on-disk bytes (fail closed).

    Each path must be absolute, under ``workspace_root`` (owned workspace files:
    contracts under samples, service/engine modules under antirea -- NOT limited to
    .runs), lexically free of reserved components, a non-symlink regular file within
    the bounded size, and hash-match its declared sha256. No code is imported or
    executed. Returns a per-record verification block for the report.
    """
    root = Path(os.path.abspath(workspace_root))
    records, total = [], 0
    for rec in normalized:
        _reserved_guard(rec["path"])            # lexical, before any stat/read/hash
        p = Path(rec["path"])
        if not p.is_absolute():
            raise ProducerIntegrateError("trusted input path must be absolute: %s" % p)
        if not p.is_relative_to(root):
            raise ProducerIntegrateError("trusted input escapes the workspace root: %s" % p)
        _no_links(p)                            # reject symlink/reparse redirection
        if not p.is_file():
            raise ProducerIntegrateError("trusted input is not a regular file: %s" % p)
        size = p.stat().st_size
        if size > _MAX_TRUSTED_INPUT_BYTES:
            raise ProducerIntegrateError(
                "trusted input exceeds bounded size (%d > %d): %s" % (size, _MAX_TRUSTED_INPUT_BYTES, p))
        total += size
        if total > _MAX_TRUSTED_INPUTS_TOTAL_BYTES:
            raise ProducerIntegrateError("trusted inputs exceed the bounded total bytes")
        actual = _hash_file(p)
        if actual != rec["sha256"]:
            raise ProducerIntegrateError(
                "trusted input bytes do not match the declared sha256 for %s (phase %s)" % (p, phase))
        records.append({"path": str(p), "sha256": actual, "bytes": size, "role": rec["role"]})
    return {"phase": phase, "count": len(records), "records": records}


def _clean_completion(proc: dict) -> bool:
    """Full process-control receipt assertion for one owned child. On Windows a
    child is only 'clean' when it ran under an assigned Windows Job that is
    empty (active_after==0) and closed, with method ``windows_job`` and a
    confirmed owned-parent exit whose ``parent_pid`` matches the launched ``pid``.
    Fails closed if timed out, cancelled, or the return code is not an int."""
    if proc.get("timed_out") or proc.get("cancelled") or not isinstance(proc.get("returncode"), int):
        return False
    c = proc.get("cleanup", {}) or {}
    if not bool(c.get("parent_exit_confirmed")):
        return False
    if os.name != "nt":
        return True
    return (c.get("method") == "windows_job"
            and bool(c.get("job_assigned"))
            and c.get("active_after") == 0
            and c.get("status") == "assigned_job_empty"
            and bool(c.get("job_handle_closed"))
            and isinstance(proc.get("pid"), int)
            and c.get("parent_pid") == proc.get("pid"))


def _select_control_case(cases: list) -> dict:
    """Pick the gating route control case: the first EXPLICIT value case whose own
    expectation declares ``returncode == 0``. The route proof runs the ORIGINAL arm
    on its args and requires an actual success, then drives both negative controls
    with the SAME args. Fail closed BEFORE any child if none is eligible, so the
    control argv is derived from a declared success rather than hardcoded."""
    for case in cases:
        exp = case.get("expect")
        if case.get("kind") == "value" and isinstance(exp, dict) and exp.get("returncode") == 0:
            return case
    raise ProducerIntegrateError(
        "route proof requires at least one explicit value case with expect.returncode==0 "
        "(the gating control argv is derived from it, never hardcoded)")


def build_and_compare(staging: dict, pinned: dict, cases: list, *, workspace_root,
                      timeout_seconds: int = 60, stop_file: Path | None = None, compiler=None,
                      trusted_inputs=None) -> dict:
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
        raise ProducerIntegrateError("timeout_seconds must be 1..600")
    # Normalize the optional trusted_inputs records up front (shape + lexical guard,
    # no disk access); they are then re-verified from disk at preflight, before AND
    # after every child, and at postflight.
    trusted_norm = _normalize_trusted_inputs(trusted_inputs)
    # Explicit case contract validated BEFORE any child is launched: no implicit
    # execution, no default fixture. Malformed cases fail closed here.
    cases = validate_cases(cases)
    # The gating route control argv is DERIVED from an explicit value case whose own
    # expectation declares returncode==0 (chosen before any child); require one.
    control_case = _select_control_case(cases)
    dotnet_frontend, _, _, process = _engine()
    root = Path(os.path.abspath(workspace_root))
    real_stop = _stop_path(root)
    manifest = staging["manifest"]

    exec_paths = _derive_execution(manifest, staging)

    _check_stop(real_stop, stop_file, "preflight")
    integrity_pre = verify_staged_integrity(manifest, pinned, workspace_root=root,
                                            phase="preflight", stop_file=stop_file, compiler=compiler)
    # Trusted inputs are re-verified from disk BEFORE any child runs (preflight).
    trusted_checks = []
    trusted_pre = _verify_trusted_inputs(trusted_norm, workspace_root=root, phase="preflight")
    trusted_checks.append({"phase": "preflight", "count": trusted_pre["count"]})

    compiler = _verify_compiler_against_producer(root, staging["producer_compiler_inputs"], compiler=compiler)
    out = Path(exec_paths["out_dir"])
    native_core = exec_paths["native_core"]
    logs = out / "logs"
    framework, runtime_version = compiler["framework"], compiler["runtime_version"]
    base_env = _clean_env(out, compiler)
    deploy_env = _clean_env(out, compiler, native_core=native_core)
    commands = []
    stop_events = []
    # Output pins (compiled DLLs + their runtimeconfig.json) are registered as soon
    # as they are produced; the native core is pinned from staging. verify_pins()
    # re-checks the native core ALWAYS and every registered output pin, and is run
    # BEFORE and AFTER every child (incl. the original->protected gap and the route
    # controls), not only at case boundaries.
    registered_pins = {}

    def verify_pins(where):
        if _hash_file(native_core) != manifest["native_core"]["sha256"]:
            raise StagingIntegrityError("native core changed during execution (%s)" % where)
        for name, (path, sha) in registered_pins.items():
            if _hash_file(path) != sha:
                raise StagingIntegrityError("output pin %s changed during execution (%s)" % (name, where))

    def recheck_compiler(where):
        # Re-discover + re-hash the installed compiler FROM DISK and re-verify it
        # against the producer pins (same lexical guard) before/after every compiler
        # child; reject any drift from the staging-time compiler identity.
        fresh = _verify_compiler_against_producer(root, staging["producer_compiler_inputs"], compiler=None)
        if _compiler_digest(fresh["input_hashes"]) != _compiler_digest(compiler["input_hashes"]):
            raise StagingIntegrityError("installed compiler changed during execution (%s)" % where)

    def run(argv, label, *, env):
        if env is None:
            raise ProducerIntegrateError("every child must run under an explicit clean env")
        _check_stop(real_stop, stop_file, "during:" + label)
        # Trusted inputs + output/native pins re-verified from disk BEFORE every child.
        before = _verify_trusted_inputs(trusted_norm, workspace_root=root, phase="before:" + label)
        trusted_checks.append({"phase": "before:" + label, "count": before["count"]})
        verify_pins("before:" + label)
        proc = process.run_logged([str(a) for a in argv], out, logs / label,
                                  timeout=timeout_seconds, env=env, cancel_file=real_stop)
        c = proc.get("cleanup", {})
        # Retain the FULL process receipt (incl. pid + complete cleanup dict) and the
        # on-disk receipt path for audit, not only summary fields.
        commands.append({"label": label, "argv": proc["argv"], "returncode": proc["returncode"],
                         "pid": proc.get("pid"), "timed_out": proc["timed_out"],
                         "cancelled": proc["cancelled"], "seconds": proc["seconds"],
                         "cleanup": c,
                         "cleanup_status": c.get("status"),
                         "job_handle_closed": c.get("job_handle_closed"),
                         "parent_exit_confirmed": c.get("parent_exit_confirmed"),
                         "clean_completion": clean_completion(proc),
                         "receipt_path": str((logs / label).with_suffix(".process.json")),
                         "stdout": proc["stdout"], "stderr": proc["stderr"]})
        if proc["cancelled"]:
            stop_events.append(label)
        # Trusted inputs + output/native pins re-verified from disk AFTER every child.
        after = _verify_trusted_inputs(trusted_norm, workspace_root=root, phase="after:" + label)
        trusted_checks.append({"phase": "after:" + label, "count": after["count"]})
        verify_pins("after:" + label)
        return proc

    def clean_completion(proc):
        return _clean_completion(proc)

    def compile_exe(sources, out_dll, env):
        refs = ["-r:" + str(p) for p in sorted(Path(compiler["reference_dir"]).glob("*.dll"))]
        argv = [compiler["dotnet"], "exec", compiler["csc"], *_CSC_FLAGS, *refs,
                "-target:exe", "-out:" + str(out_dll), *[str(s) for s in sources]]
        label = Path(out_dll).stem
        recheck_compiler("compile:" + label + ":pre")     # compiler identity BEFORE the compiler child
        proc = run(argv, "csc-" + label, env=env)
        recheck_compiler("compile:" + label + ":post")    # compiler identity AFTER the compiler child
        if proc["returncode"] != 0 or not clean_completion(proc):
            raise ProducerIntegrateError("compile failed for %s: %s"
                                         % (Path(out_dll).name, _read_log(proc["stderr"])[:4000]))
        _write_runtimeconfig(out_dll, framework, runtime_version)
        return proc

    def run_exe(dll, args, env, label):
        proc = run([compiler["dotnet"], "exec", dll, *args], label, env=env)
        return {"returncode": proc["returncode"], "stdout": _read_log(proc["stdout"]),
                "stderr": _read_log(proc["stderr"]), "clean": clean_completion(proc)}

    # (A) Captured-env evidence.
    probe_dir = out / "probe"
    probe_dir.mkdir(exist_ok=True)
    (probe_dir / "EnvProbe.cs").write_text(_ENV_PROBE_SRC, encoding="utf-8")
    probe_dll = out / "EnvProbe.dll"
    prior = os.environ.get(_ENV_SENTINEL)
    os.environ[_ENV_SENTINEL] = "LEAKED_IF_AMBIENT"
    try:
        compile_exe([probe_dir / "EnvProbe.cs"], probe_dll, base_env)
        probe = run_exe(probe_dll, [], base_env, "env-probe")
    finally:
        if prior is None:
            os.environ.pop(_ENV_SENTINEL, None)
        else:
            os.environ[_ENV_SENTINEL] = prior
    probe_lines = probe["stdout"].splitlines()
    env_sentinel_leaked = not (probe["clean"] and probe_lines[:1] == ["<unset>"])
    env_evidence = {"clean_completion": probe["clean"], "sentinel": _ENV_SENTINEL,
                    "sentinel_value_in_child": probe_lines[0] if probe_lines else None,
                    "dotnet_opt_out_in_child": probe_lines[1] if len(probe_lines) > 1 else None,
                    "ambient_leak_detected": env_sentinel_leaked,
                    "env_keys": sorted(base_env)}
    env_ok = not env_sentinel_leaked and env_evidence["dotnet_opt_out_in_child"] == "1"

    # (B) Compile ORIGINAL + DEPLOYABLE with the producer-pinned compiler.
    original_dll = out / "original_app.dll"
    deployable_dll = out / "deployable_app.dll"
    compile_exe(sorted(Path(exec_paths["original_dir"]).glob("*.cs")), original_dll, base_env)
    compile_exe(sorted(Path(exec_paths["deployable_dir"]).glob("*.cs")), deployable_dll, base_env)
    # The generated runtimeconfig.json files are part of the executable surface, so
    # they are pinned and re-checked across execution/postflight alongside the DLLs.
    original_rc = original_dll.with_suffix(".runtimeconfig.json")
    deployable_rc = deployable_dll.with_suffix(".runtimeconfig.json")
    output_pins = {"original_app.dll": _hash_file(original_dll),
                   "deployable_app.dll": _hash_file(deployable_dll),
                   "original_app.runtimeconfig.json": _hash_file(original_rc),
                   "deployable_app.runtimeconfig.json": _hash_file(deployable_rc)}
    # Register the output pins so verify_pins() re-checks them BEFORE and AFTER every
    # subsequent child (inspect, each case's original->protected pair, route controls).
    registered_pins["original_app.dll"] = (original_dll, output_pins["original_app.dll"])
    registered_pins["deployable_app.dll"] = (deployable_dll, output_pins["deployable_app.dll"])
    registered_pins["original_app.runtimeconfig.json"] = (original_rc, output_pins["original_app.runtimeconfig.json"])
    registered_pins["deployable_app.runtimeconfig.json"] = (deployable_rc, output_pins["deployable_app.runtimeconfig.json"])

    def _output_pins_match():
        return all(_hash_file(path) == sha for path, sha in registered_pins.values())

    def quick_pin_check(where):
        verify_pins(where)       # native core + all registered output/runtimeconfig pins

    # (C) Actual compiled-IL evidence.
    inspect_dll = out / "Inspect.dll"
    compile_exe([Path(compiler["helpers"]) / "Inspect.cs"], inspect_dll, base_env)

    def inspect(assembly, label):
        proc = run([compiler["dotnet"], "exec", inspect_dll, assembly], label, env=base_env)
        if proc["returncode"] != 0 or not clean_completion(proc):
            raise ProducerIntegrateError("IL inspection failed for " + Path(assembly).name)
        return json.loads(_read_log(proc["stdout"]))

    meta_orig = inspect(original_dll, "il-original")
    meta_dep = inspect(deployable_dll, "il-deployable")
    il_evidence, il_ok = [], True
    for m in staging["mapping"]["methods"]:
        decl_type = m["managed"]["type"]
        method = m["managed"]["method"]
        orig_il = _il_counts(dotnet_frontend, meta_orig, decl_type, method)
        dep_il = _il_counts(dotnet_frontend, meta_dep, decl_type, method)
        proof = (dep_il["call_opcodes"] >= 1 and not dep_il["arith_opcodes"]
                 and dep_il["instruction_count"] <= 8
                 and orig_il["call_opcodes"] == 0 and bool(orig_il["arith_opcodes"])
                 and orig_il["instruction_count"] > dep_il["instruction_count"])
        il_ok = il_ok and proof
        il_evidence.append({"export": m["export"], "type": decl_type, "method": method,
                            "original_il": orig_il, "deployable_il": dep_il,
                            "body_replaced_by_call": proof})

    # (D) Value/type/exception equivalence over clean bounded child processes.
    comparisons, original_values, protected_values = [], [], []
    all_match = True
    expectations_ok = True
    for i, case in enumerate(cases):
        quick_pin_check("case-%03d" % i)
        args = [str(a) for a in case["args"]]
        o = run_exe(original_dll, args, base_env, "orig-%03d" % i)
        d = run_exe(deployable_dll, args, deploy_env, "depl-%03d" % i)
        o_exc, d_exc = _exc_class(o["stderr"]), _exc_class(d["stderr"])
        value_match = o["stdout"] == d["stdout"]
        rc_match = o["returncode"] == d["returncode"]
        exc_match = o_exc == d_exc
        ok = value_match and rc_match and exc_match and o["clean"] and d["clean"]
        all_match = all_match and ok
        o_obs = {"rc": o["returncode"], "stdout": o["stdout"].strip(), "exc": o_exc}
        d_obs = {"rc": d["returncode"], "stdout": d["stdout"].strip(), "exc": d_exc}
        # Explicit expected-observation contract (optional per case): the ORIGINAL
        # arm must satisfy the declared observation (and the protected arm equals it).
        expectation = _evaluate_expectation(case.get("expect"), o_obs)
        if expectation is not None and not expectation["satisfied"]:
            expectations_ok = False
        original_values.append({"args": args, **o_obs})
        protected_values.append({"args": args, **d_obs})
        comparisons.append({"case": case["label"], "args": args, "kind": case["kind"],
                            "value_match": value_match, "returncode_match": rc_match,
                            "exception_match": exc_match, "match": ok,
                            "expectation": expectation,
                            "original": o_obs, "protected": d_obs})

    # (E) Gating route proof: run the ORIGINAL arm on the DERIVED control argv (from
    # an explicit value case with expect.returncode==0) and require an ACTUAL success
    # (clean, rc==0, no exception, its own expectation satisfied); then drive BOTH
    # negative controls (native core absent / unset) with the SAME argv and require a
    # clean failure. stdout is NOT constrained to an integer unless that case's own
    # expectation (expect.stdout_is_integer) asks for it.
    quick_pin_check("route-proof")
    control_args = [str(a) for a in control_case["args"]]
    control = run_exe(original_dll, control_args, base_env, "route-control")
    control_exc = _exc_class(control["stderr"])
    control_obs = {"rc": control["returncode"], "stdout": control["stdout"].strip(), "exc": control_exc}
    control_expectation = _evaluate_expectation(control_case.get("expect"), control_obs)
    control_ok = (control["clean"] and control["returncode"] == 0 and control_exc is None
                  and control_expectation is not None and control_expectation["satisfied"])
    route_proofs = []
    expected = {"missing-core": ("System.DllNotFoundException", _clean_env(out, compiler, native_core=out / "_absent_core.dll")),
                "unset-core": ("System.InvalidOperationException", base_env)}
    for label, (want_exc, env) in expected.items():
        dep = run_exe(deployable_dll, control_args, env, "route-" + label)
        dep_exc = _exc_class(dep["stderr"])
        rc = dep["returncode"]
        failed_cleanly = dep["clean"] and isinstance(rc, int) and rc != 0
        silent_fallback = (isinstance(rc, int) and rc == 0 and dep["stdout"].strip() == control["stdout"].strip())
        proves = failed_cleanly and dep_exc == want_exc and not silent_fallback
        route_proofs.append({"variant": label, "control_case": control_case["label"],
                             "control_args": control_args, "control_rc": control["returncode"],
                             "control_succeeded": control_ok,
                             "deployable_rc": rc, "deployable_exc": dep_exc, "expected_exc": want_exc,
                             "failed_cleanly": failed_cleanly, "silent_fallback_detected": silent_fallback,
                             "proves_native_required": proves})
    route_ok = control_ok and bool(route_proofs) and all(p["proves_native_required"] for p in route_proofs)

    _check_stop(real_stop, stop_file, "postflight")
    integrity_post = verify_staged_integrity(manifest, pinned, workspace_root=root,
                                             phase="postflight", stop_file=stop_file, compiler=compiler)
    # Trusted inputs re-verified from disk AFTER all children (postflight).
    trusted_post = _verify_trusted_inputs(trusted_norm, workspace_root=root, phase="postflight")
    trusted_checks.append({"phase": "postflight", "count": trusted_post["count"]})
    trusted_inputs_verification = {
        "declared_count": len(trusted_norm),
        "verified": True,
        "verified_phases": ["preflight", "before_each_child", "after_each_child", "postflight"],
        "check_events": len(trusted_checks),
        "preflight": trusted_pre, "postflight": trusted_post,
        "no_code_executed_from_records": True,
    }
    output_pins_stable = _output_pins_match()
    if not output_pins_stable:
        raise StagingIntegrityError("compiled comparison assemblies or runtimeconfig changed during the run")
    deployable_runtimeconfig = {"path": str(deployable_rc),
                                "sha256": output_pins["deployable_app.runtimeconfig.json"],
                                "bytes": deployable_rc.stat().st_size}
    original_runtimeconfig = {"path": str(original_rc),
                              "sha256": output_pins["original_app.runtimeconfig.json"],
                              "bytes": original_rc.stat().st_size}

    raw = {"original": original_values, "protected": protected_values}
    integrity_ok = (integrity_pre["status"] == "staged_integrity_verified"
                    and integrity_post["status"] == "staged_integrity_verified"
                    and output_pins_stable)
    passed = all_match and route_ok and env_ok and il_ok and integrity_ok and expectations_ok
    return {
        "status": "producer_bound_integration_passed" if passed else "failed",
        "expectations_ok": expectations_ok,
        "target_executed": True, "compiler_pin_verified": True,
        "integrity_verified_before_and_after": integrity_ok,
        "native_pinned_between_cases": True,
        "output_pins_rechecked_around_every_child": True,
        "compiler_rechecked_around_compiler_children": True,
        "integrity_preflight": integrity_pre, "integrity_postflight": integrity_post,
        "execution_paths_bound_to_manifest": True,
        "trusted_inputs_verification": trusted_inputs_verification,
        "output_pins": output_pins, "output_pins_stable": output_pins_stable,
        "stop_checked_phases": ["preflight", "during_each_child", "before_each_case", "postflight"],
        "stop_sources_checked": ["real_workspace_stop", "optional_fixture_cancellation"],
        "stop_cancellations": stop_events,
        "sdk_version": compiler["sdk_version"], "framework": framework, "runtime_version": runtime_version,
        "original_app": {"dll": str(original_dll), "sha256": output_pins["original_app.dll"],
                         "runtimeconfig": original_runtimeconfig},
        "deployable_app": {"dll": str(deployable_dll), "sha256": output_pins["deployable_app.dll"],
                           "runtimeconfig": deployable_runtimeconfig},
        "deployable_runtimeconfig": deployable_runtimeconfig,
        "runtimeconfig_pins_rechecked": True,
        "native_core": {"path": staging["native_core"], "sha256": staging["native_core_sha256"]},
        "total_cases": len(cases),
        "value_cases": sum(1 for c in cases if c.get("kind", "value") == "value"),
        "exception_cases": sum(1 for c in cases if c.get("kind") == "exception"),
        "all_match": all_match, "env_ok": env_ok, "env_evidence": env_evidence,
        "il_evidence_ok": il_ok, "il_evidence": il_evidence,
        "route_proof_ok": route_ok, "route_control_ok": control_ok, "route_proofs": route_proofs,
        "original_values_sha256": hashlib.sha256(json.dumps(raw["original"], sort_keys=True).encode()).hexdigest(),
        "protected_values_sha256": hashlib.sha256(json.dumps(raw["protected"], sort_keys=True).encode()).hexdigest(),
        "comparisons": comparisons, "raw_arrays": raw, "commands": commands,
        "limitations": [
            "Sampled value/boundary/exception equivalence of one owned app; not an exhaustive proof.",
            "Bounded owned child processes under a minimal private env with Windows Job cleanup; "
            "cleanup is not an atomic security sandbox and process ownership is not a security boundary.",
            "IL evidence shows each selected leaf compiled to a single managed call + ret vs the "
            "original arithmetic; the call-target-to-NativeCore binding is evidenced by the preserved "
            "deployable source and the gating missing-core runtime proof, not by MemberRef name resolution.",
            "Integrity is fully recomputed from on-disk bytes at preflight and postflight, and the native "
            "core plus compiled comparison assemblies are re-pinned before each executed case. This detects a "
            "NET change of a bound input across the run; it does NOT prove the absence of a transient "
            "swap-and-restore between checks. The SHA-256 value arrays/manifest are plain content hashes, "
            "not a cryptographically signed report.",
            "The native core is a REUSED pinned producer artifact re-verified from disk, NOT a fresh "
            "protected-native build; only the managed original/deployable assemblies are freshly compiled here.",
            "No performance, defense-strength, parity or external-attack claim is made here.",
        ],
    }


# --------------------------------------------------------------------------- #
# Explicit case + expected-observation contract (NO implicit default fixture).
# --------------------------------------------------------------------------- #
CASE_KINDS = ("value", "exception")
_CASE_REQUIRED_KEYS = frozenset({"label", "kind", "args"})
_CASE_OPTIONAL_KEYS = frozenset({"expect"})
# The observation a case may assert about the ORIGINAL arm (the protected arm must
# then equal it). This is the explicit "expected observation" contract; it never
# triggers execution by itself and is validated before any child runs.
_EXPECT_KEYS = frozenset({"returncode", "exception", "stdout", "stdout_is_integer"})
MAX_CASES = 512
MAX_CASE_ARGS = 16


def validate_cases(cases) -> list:
    """Validate an EXPLICIT list of cases + their CLI args / expected observation.

    Each case is ``{"label": str, "kind": "value"|"exception", "args": [int|str...]}``
    with an optional ``"expect"`` observation. Args are the exact CLI arguments the
    target is invoked with (stringified). Malformed input fails closed; there is no
    implicit default fixture and nothing is executed here.
    """
    if not isinstance(cases, list) or not cases:
        raise ProducerIntegrateError("cases must be a non-empty explicit list (no implicit default fixture)")
    if len(cases) > MAX_CASES:
        raise ProducerIntegrateError("too many cases (max %d)" % MAX_CASES)
    out, seen_labels = [], set()
    for idx, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ProducerIntegrateError("case %d must be an object" % idx)
        keys = set(case)
        missing = _CASE_REQUIRED_KEYS - keys
        extra = keys - (_CASE_REQUIRED_KEYS | _CASE_OPTIONAL_KEYS)
        if missing:
            raise ProducerIntegrateError("case %d missing key(s): %s" % (idx, ", ".join(sorted(missing))))
        if extra:
            raise ProducerIntegrateError("case %d has unsupported key(s): %s" % (idx, ", ".join(sorted(extra))))
        label = case["label"]
        if not isinstance(label, str) or not label or label in seen_labels:
            raise ProducerIntegrateError("case %d needs a unique non-empty string label" % idx)
        seen_labels.add(label)
        kind = case["kind"]
        if kind not in CASE_KINDS:
            raise ProducerIntegrateError("case %r kind must be one of %s" % (label, list(CASE_KINDS)))
        args = case["args"]
        if not isinstance(args, list) or len(args) > MAX_CASE_ARGS:
            raise ProducerIntegrateError("case %r args must be a list of 0..%d values" % (label, MAX_CASE_ARGS))
        norm_args = []
        for a in args:
            if isinstance(a, bool) or not isinstance(a, (int, str)):
                raise ProducerIntegrateError("case %r args must be int or str (bool rejected): %r" % (label, a))
            norm_args.append(str(a))
        expect = _validate_expect(case.get("expect"), kind, label)
        out.append({"label": label, "kind": kind, "args": norm_args, "expect": expect})
    return out


def _validate_expect(expect, kind: str, label: str):
    if expect is None:
        return None
    if not isinstance(expect, dict) or not expect:
        raise ProducerIntegrateError("case %r expect must be a non-empty object or omitted" % label)
    extra = set(expect) - _EXPECT_KEYS
    if extra:
        raise ProducerIntegrateError("case %r expect has unsupported key(s): %s" % (label, ", ".join(sorted(extra))))
    if "returncode" in expect and (isinstance(expect["returncode"], bool) or not isinstance(expect["returncode"], int)):
        raise ProducerIntegrateError("case %r expect.returncode must be an int" % label)
    if "exception" in expect:
        exc = expect["exception"]
        if not isinstance(exc, str) or not re.fullmatch(r"System\.[A-Za-z0-9_.]+Exception", exc):
            raise ProducerIntegrateError("case %r expect.exception must be a System.*Exception token" % label)
        if kind != "exception":
            raise ProducerIntegrateError("case %r declares expect.exception but kind is not 'exception'" % label)
    if "stdout" in expect and not isinstance(expect["stdout"], str):
        raise ProducerIntegrateError("case %r expect.stdout must be a string" % label)
    if "stdout_is_integer" in expect and not isinstance(expect["stdout_is_integer"], bool):
        raise ProducerIntegrateError("case %r expect.stdout_is_integer must be a bool" % label)
    return dict(expect)


def _evaluate_expectation(expect, observation: dict):
    """Check the ORIGINAL-arm observation against the case's expected observation."""
    if expect is None:
        return None
    checks = {}
    if "returncode" in expect:
        checks["returncode"] = (observation["rc"] == expect["returncode"])
    if "exception" in expect:
        checks["exception"] = (observation["exc"] == expect["exception"])
    if "stdout" in expect:
        checks["stdout"] = (observation["stdout"] == expect["stdout"])
    if "stdout_is_integer" in expect:
        is_int = bool(re.fullmatch(r"-?\d+", observation["stdout"]))
        checks["stdout_is_integer"] = (is_int == expect["stdout_is_integer"])
    return {"expected": dict(expect), "checks": checks, "satisfied": all(checks.values())}


# --------------------------------------------------------------------------- #
# Reusable plan / prepare / validate seams (for ProjectService adoption).
# --------------------------------------------------------------------------- #
def _workspace_identity(workspace: "WorkspacePlan") -> dict:
    """Stable, execution-bearing workspace identity bound into the plan fingerprint.

    ``out_dir`` is a per-run FRESH directory and is deliberately NOT bound here; it
    is re-validated (rederived) against this bound root at prepare/validate. The STOP
    marker is ALWAYS rederived from the bound ``workspace_root`` (``_stop_path``),
    never trusted from a stored alias, so a tampered serialized STOP alias cannot
    redirect the authoritative cancel file.
    """
    wr = Path(os.path.abspath(workspace.workspace_root))
    return {"workspace_root": str(wr),
            "transform_module": TRUSTED_TRANSFORM_MODULE,
            "stop_relative": STOP_RELATIVE,
            "stop_file": str(_stop_path(wr))}


def _reject_overlap(out: Path, *inputs) -> None:
    """Reject an output directory that overlaps (contains or is contained by) a
    consumed source/input path. Pure lexical path containment (no filesystem I/O)."""
    out = Path(os.path.abspath(out))
    for other in inputs:
        if other is None:
            continue
        o = Path(os.path.abspath(other))
        if _same_path(out, o) or out.is_relative_to(o) or o.is_relative_to(out):
            raise ProducerIntegrateError(
                "output directory overlaps a consumed source/input path: %s vs %s" % (out, o))


def _plan_fingerprint(input_snapshot: dict, pinned: dict, compiler_digest: str,
                      selectors: list, engine_binding: dict, workspace_identity: dict) -> str:
    """Single content fingerprint binding the app tree, integration spec, owned
    transform + engine modules, producer report/native, compiler AND the stable
    workspace identity (root + transform module + rederived STOP relative path) to
    the plan. Any drift in any of these changes it. Serializable scalar content only.
    ``out_dir`` is per-run fresh and intentionally excluded (rederived instead)."""
    payload = {"input_snapshot": input_snapshot,
               "producer_report_sha256": pinned["report_sha256"],
               "producer_contract_sha256": pinned["contract_sha256"],
               "protected_sha256": pinned["protected"]["sha256"],
               "baseline_sha256": pinned["baseline"]["sha256"],
               "compiler_input_digest": compiler_digest,
               "transform_module": TRUSTED_TRANSFORM_MODULE,
               "engine_binding": {name: engine_binding[name]["sha256"] for name in sorted(engine_binding)},
               "workspace_identity": {"workspace_root": workspace_identity["workspace_root"],
                                      "transform_module": workspace_identity["transform_module"],
                                      "stop_relative": workspace_identity["stop_relative"]},
               "selectors": [{"export": s["export"], "type": s["type"], "name": s["name"],
                              "parameters": list(s["parameters"])} for s in selectors]}
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def _reverify_producer_from_disk(pinned: dict, *, workspace_root) -> None:
    """Re-hash the producer report/contract/native/sources FROM DISK and reject any
    drift versus the plan-time pins. Used to re-validate the complete native/producer
    inputs BEFORE the transform is imported (prepare) and before any child."""
    root = Path(os.path.abspath(workspace_root))
    problems = []
    for label, path_key, sha_key in (("report", "report_path", "report_sha256"),
                                      ("contract", "contract_path", "contract_sha256")):
        p = Path(pinned[path_key])
        _reserved_guard(p)
        if not p.is_file():
            problems.append("producer %s missing on disk: %s" % (label, p))
        elif _hash_file(p) != pinned[sha_key]:
            problems.append("producer %s bytes changed on disk" % label)
    for arm in ("baseline", "protected"):
        entry = pinned[arm]
        p = Path(entry["path"])
        _reserved_guard(p)
        if not p.is_file():
            problems.append("producer %s artifact missing on disk: %s" % (arm, p))
        elif _hash_file(p) != entry["sha256"]:
            problems.append("producer %s artifact bytes changed on disk" % arm)
    for name, pin in pinned["producer_sources"].items():
        sp = pinned["producer_source_paths"].get(name)
        if sp is None:
            problems.append("producer source path missing for %s" % name)
            continue
        _reserved_guard(sp)                    # lexical guard BEFORE is_file/stat
        if not Path(sp).is_file():
            problems.append("producer source path missing for %s" % name)
        elif _hash_file(Path(sp)) != pin:
            problems.append("producer source %s changed on disk" % name)
    if problems:
        raise StagingIntegrityError("producer/native input drift rejected: " + "; ".join(problems))


def _snapshot_plan_inputs(app_dir: Path, spec: dict, spec_path: Path, spec_sha: str,
                          *, workspace_root: Path) -> dict:
    """Hash the app source tree + integration spec FROM DISK (no execution).

    The transform + engine are NOT hashed here from any project path; they are
    bound separately via the trusted-name engine binding.
    """
    root = Path(os.path.abspath(workspace_root))
    app_dir = Path(os.path.abspath(app_dir))
    _no_links(app_dir)
    _received_guard(root, app_dir)
    app_sources = {}
    for name in spec["sources"]:
        src = app_dir / name
        _no_links(src)
        if not src.is_file():
            raise ProducerIntegrateError("application source missing at plan time: " + name)
        app_sources[name] = _hash_file(src)
    return {"app_dir": str(app_dir),
            "app_sources": app_sources,
            "integration_spec": {"path": str(Path(os.path.abspath(spec_path))), "sha256": spec_sha}}


def plan(producer: ProducerManifest, receipt: ProtectedBuildReceipt,
         toolchain: ToolchainSnapshot, workspace: WorkspacePlan,
         app_dir, integration_spec_path) -> dict:
    """PLAN seam (pure disk hashing, NO child processes, transform NOT executed).

    Consume+pin the producer report + native artifact, cross-check the immutable
    protected-build receipt, require the toolchain snapshot to equal the producer's
    pinned compiler, confirm the selected-method identity from emitted IL metadata,
    BIND the owned transform + every trusted engine module (INCLUDING the
    integration engine itself) by trusted name + source hash, and BIND the app
    source tree + integration spec into an immutable ``plan_fingerprint``. The
    transform/engine sources are LOCATED and HASHED by trusted name via a
    non-executing ``find_spec`` lookup here -- the transform leaf is never imported
    or executed at plan time -- so a later drift is caught (by hash, before import)
    at prepare, including in a fresh process that loads a saved plan. The returned
    plan is a plain JSON-serializable dict (see :func:`serialize_plan` /
    :func:`load_plan`).
    """
    wr = workspace.workspace_root
    spec_path = Path(os.path.abspath(integration_spec_path))
    # LEXICAL reserved-name guard for the consumed spec + app dir BEFORE any
    # stat/read/hash/traversal (closes the review gate where plan() hashed the spec
    # path before a reserved/received-name check).
    _reserved_guard(spec_path)
    _reserved_guard(app_dir)
    # Reject an out_dir that overlaps the consumed app sources (lexical containment).
    _reject_overlap(workspace.out_dir, app_dir, wr / "antirea")
    _no_links(spec_path)
    spec_sha = _hash_file(spec_path)
    spec = json.loads(_read_text_bounded(spec_path))
    if spec.get("schema_version") != 1 or not isinstance(spec.get("sources"), list) or not isinstance(spec.get("methods"), list):
        raise ProducerIntegrateError("integration spec must be schema_version 1 with sources + methods lists")
    selectors = spec["methods"]

    pinned = load_producer_report(producer.report_path, workspace_root=wr)
    receipt_binding = _cross_check_receipt(pinned, receipt)
    compiler = _verify_compiler_against_producer(wr, pinned["compiler_inputs"], compiler=toolchain.compiler)
    identity = verify_compiler_identity(pinned, selectors, workspace_root=wr)
    engine_binding = _engine_binding()      # owned transform + engine, by trusted name + hash
    workspace_identity = _workspace_identity(workspace)

    input_snapshot = _snapshot_plan_inputs(app_dir, spec, spec_path, spec_sha, workspace_root=wr)
    fingerprint = _plan_fingerprint(input_snapshot, pinned, _compiler_digest(compiler["input_hashes"]),
                                    selectors, engine_binding, workspace_identity)
    return {"status": "planned", "schema_version": PLAN_SCHEMA_VERSION,
            "pinned": pinned, "identity": identity, "compiler": compiler,
            "receipt_binding": receipt_binding, "selectors": list(selectors),
            "input_snapshot": input_snapshot, "engine_binding": engine_binding,
            "transform_module": TRUSTED_TRANSFORM_MODULE,
            "workspace_identity": workspace_identity,
            "plan_fingerprint": fingerprint,
            "app_dir": input_snapshot["app_dir"], "integration_spec_path": str(spec_path),
            "workspace": {"workspace_root": workspace_identity["workspace_root"],
                          "out_dir": str(Path(os.path.abspath(workspace.out_dir))),
                          "transform_module": TRUSTED_TRANSFORM_MODULE,
                          "stop_file": workspace_identity["stop_file"]}}


_PLAN_REQUIRED_KEYS = ("pinned", "identity", "compiler", "receipt_binding", "selectors",
                       "input_snapshot", "engine_binding", "transform_module",
                       "workspace_identity", "plan_fingerprint", "app_dir",
                       "integration_spec_path", "workspace")


def serialize_plan(prepared: dict) -> str:
    """Serialize a plan to canonical JSON (round-trips through :func:`load_plan`).

    Refuses to emit a plan whose stored fingerprint is not self-consistent, and
    refuses anything that is not JSON-serializable (no live handles)."""
    if not isinstance(prepared, dict) or prepared.get("status") != "planned":
        raise ProducerIntegrateError("serialize_plan requires a planned dict")
    expected = _plan_fingerprint(prepared["input_snapshot"], prepared["pinned"],
                                 _compiler_digest(prepared["compiler"]["input_hashes"]),
                                 prepared["selectors"], prepared["engine_binding"],
                                 prepared["workspace_identity"])
    if expected != prepared.get("plan_fingerprint"):
        raise ProducerIntegrateError("refusing to serialize a plan whose fingerprint is inconsistent")
    return json.dumps(prepared, sort_keys=True, indent=2)


def load_plan(serialized) -> dict:
    """Reconstruct a plan from JSON and re-validate its fingerprint (tamper-evidence).

    The transform/engine are reconstructed ONLY by trusted module name; no importlib
    path from the serialized plan is honoured. The recomputed fingerprint must equal
    the stored one, so a tampered body or a tampered fingerprint is rejected. This is
    plan-internal tamper-evidence; the authoritative control is the from-disk
    re-verification at prepare()/validate()."""
    data = json.loads(serialized) if isinstance(serialized, (str, bytes)) else serialized
    if not isinstance(data, dict) or data.get("status") != "planned":
        raise ProducerIntegrateError("not a serialized plan")
    if data.get("schema_version") != PLAN_SCHEMA_VERSION:
        raise ProducerIntegrateError("unsupported plan schema_version: %r" % (data.get("schema_version"),))
    for key in _PLAN_REQUIRED_KEYS:
        if key not in data:
            raise ProducerIntegrateError("serialized plan missing key: " + key)
    if data.get("transform_module") != TRUSTED_TRANSFORM_MODULE:
        raise ProducerIntegrateError("serialized plan transform_module is not the trusted owned module")
    if not isinstance(data.get("workspace"), dict) or data["workspace"].get("transform_module") != TRUSTED_TRANSFORM_MODULE:
        raise ProducerIntegrateError("serialized plan workspace transform_module is not the trusted owned module")
    # The engine binding must be EXACTLY the trusted module set (no dropped/extra keys).
    if not isinstance(data.get("engine_binding"), dict) or set(data["engine_binding"]) != set(TRUSTED_ENGINE_MODULES):
        raise ProducerIntegrateError("serialized plan engine_binding key set is not exactly the trusted module set")
    # Workspace identity is fingerprint-bound; STOP is rederived from the bound root
    # (never trusted from a stored alias), and the informational workspace block must
    # agree with it, so a tampered workspace/root/out/STOP alias cannot redirect
    # execution or the authoritative cancel file.
    wi = data.get("workspace_identity")
    if not isinstance(wi, dict) or set(wi) < {"workspace_root", "transform_module", "stop_relative", "stop_file"}:
        raise ProducerIntegrateError("serialized plan has no complete workspace_identity")
    if wi.get("transform_module") != TRUSTED_TRANSFORM_MODULE:
        raise ProducerIntegrateError("serialized plan workspace_identity transform_module is not the trusted owned module")
    if wi.get("stop_relative") != STOP_RELATIVE:
        raise StagingIntegrityError("serialized plan workspace_identity stop_relative disagrees with the engine STOP")
    rederived_stop = str(_stop_path(wi["workspace_root"]))      # rederive STOP, never trust the stored alias
    if not _same_path(rederived_stop, wi.get("stop_file", "")):
        raise StagingIntegrityError("serialized plan STOP alias disagrees with the rederived workspace STOP")
    if not _same_path(data["workspace"].get("workspace_root", ""), wi["workspace_root"]):
        raise StagingIntegrityError("serialized plan workspace.workspace_root disagrees with the bound identity")
    if not _same_path(data["workspace"].get("stop_file", ""), rederived_stop):
        raise StagingIntegrityError("serialized plan workspace.stop_file disagrees with the rederived STOP")
    # The duplicate top-level execution aliases MUST equal the fingerprint-bound
    # snapshot, so changing only an unbound alias cannot stage a different app/spec.
    snap = data.get("input_snapshot")
    if not isinstance(snap, dict) or not isinstance(snap.get("integration_spec"), dict):
        raise ProducerIntegrateError("serialized plan has no bound input snapshot")
    if not _same_path(data.get("app_dir", ""), snap.get("app_dir", "")):
        raise StagingIntegrityError("serialized plan app_dir alias disagrees with the bound snapshot")
    if not _same_path(data.get("integration_spec_path", ""), snap["integration_spec"].get("path", "")):
        raise StagingIntegrityError("serialized plan integration_spec_path alias disagrees with the bound snapshot")
    recomputed = _plan_fingerprint(snap, data["pinned"],
                                   _compiler_digest(data["compiler"]["input_hashes"]),
                                   data["selectors"], data["engine_binding"], wi)
    if recomputed != data["plan_fingerprint"]:
        raise StagingIntegrityError("serialized plan fingerprint mismatch (tampered or drifted plan)")
    return data


def _verify_plan_inputs(prepared: dict, workspace: WorkspacePlan) -> dict:
    """Re-hash app/spec FROM DISK and re-verify the owned transform + engine BY
    TRUSTED NAME, rejecting any drift since plan() BEFORE the transform is imported/
    executed or sources are staged. Also recompute the plan fingerprint and require
    it to equal the bound one."""
    snap = prepared["input_snapshot"]
    app_dir = Path(snap["app_dir"])
    wi = prepared.get("workspace_identity")
    problems = []
    # Workspace identity consistency: the runtime WorkspacePlan must match the
    # fingerprint-bound workspace_root; the STOP marker is rederived from that bound
    # root (never trusted from a stored alias); out_dir is rederived/re-validated
    # against the bound root/.runs and must not overlap the consumed app sources.
    if not isinstance(wi, dict):
        problems.append("plan has no workspace_identity")
    else:
        if not _same_path(workspace.workspace_root, wi.get("workspace_root", "")):
            problems.append("runtime workspace_root disagrees with the fingerprint-bound workspace identity")
        if wi.get("transform_module") != TRUSTED_TRANSFORM_MODULE or wi.get("stop_relative") != STOP_RELATIVE:
            problems.append("workspace_identity transform/STOP binding is not the trusted engine binding")
        rederived_stop = str(_stop_path(workspace.workspace_root))
        if not _same_path(rederived_stop, wi.get("stop_file", "")):
            problems.append("rederived workspace STOP disagrees with the bound workspace identity")
    out_dir = Path(os.path.abspath(workspace.out_dir))
    if not out_dir.is_relative_to(Path(os.path.abspath(workspace.workspace_root)) / ".runs"):
        problems.append("workspace out_dir is not under the bound workspace/.runs")
    try:
        _reject_overlap(out_dir, app_dir)
    except ProducerIntegrateError as exc:
        problems.append(str(exc))
    # Execution paths are taken from the fingerprint-bound snapshot; require the
    # duplicate top-level aliases to agree so an unbound alias cannot be swapped.
    if not _same_path(prepared.get("app_dir", ""), snap.get("app_dir", "")):
        problems.append("plan app_dir alias disagrees with the bound snapshot")
    if not _same_path(prepared.get("integration_spec_path", ""), snap["integration_spec"].get("path", "")):
        problems.append("plan integration_spec_path alias disagrees with the bound snapshot")
    for name, pin in snap["app_sources"].items():
        p = app_dir / name
        if not p.is_file():
            problems.append("app source missing since plan: %s" % name)
        elif _hash_file(p) != pin:
            problems.append("app source changed since plan: %s" % name)
    sp = Path(snap["integration_spec"]["path"])
    if not sp.is_file() or _hash_file(sp) != snap["integration_spec"]["sha256"]:
        problems.append("integration spec changed since plan")
    # Owned transform + engine re-verified by trusted name (NOT by a project path),
    # located+hashed WITHOUT executing the leaf, BEFORE the transform is imported.
    if prepared.get("transform_module") != TRUSTED_TRANSFORM_MODULE:
        problems.append("plan transform module is not the trusted owned module")
    if workspace.transform_module != TRUSTED_TRANSFORM_MODULE:
        problems.append("workspace transform module differs from the trusted owned module")
    if set(prepared.get("engine_binding", {})) != set(TRUSTED_ENGINE_MODULES):
        problems.append("plan engine_binding key set is not exactly the trusted module set")
    for name, entry in prepared["engine_binding"].items():
        try:
            cur = _module_source_identity(name)
        except ProducerIntegrateError as exc:
            problems.append("engine/transform module unverifiable since plan: %s (%s)" % (name, exc))
            continue
        if cur["sha256"] != entry["sha256"]:
            label = "transform module" if name == TRUSTED_TRANSFORM_MODULE else "engine module"
            problems.append("%s changed since plan (NOT executed): %s" % (label, name))
    if problems:
        raise StagingIntegrityError("plan input drift rejected before prepare: " + "; ".join(problems))
    # Re-validate the COMPLETE producer/native inputs from disk and the installed
    # compiler against the producer pins BEFORE the transform is imported or any
    # child runs (raises StagingIntegrityError/ProducerIntegrateError on drift).
    _reverify_producer_from_disk(prepared["pinned"], workspace_root=workspace.workspace_root)
    _verify_compiler_against_producer(workspace.workspace_root, prepared["pinned"]["compiler_inputs"],
                                      compiler=prepared["compiler"])
    current = _plan_fingerprint(prepared["input_snapshot"], prepared["pinned"],
                                _compiler_digest(prepared["compiler"]["input_hashes"]),
                                prepared["selectors"], prepared["engine_binding"],
                                prepared["workspace_identity"])
    if current != prepared["plan_fingerprint"]:
        raise StagingIntegrityError("plan fingerprint mismatch at prepare")
    return {"status": "plan_inputs_verified", "plan_fingerprint": current}


def prepare(prepared: dict, workspace: WorkspacePlan, staging_subdir: str = "staging") -> dict:
    """PREPARE seam: re-verify the planned app/spec/transform inputs from disk
    (BEFORE importing/executing the transform), then stage source + inventory +
    native DLL + compiler into a tamper-evident manifest. The app_dir and spec are
    taken SOLELY from the fingerprint-bound ``input_snapshot`` (not the duplicate
    top-level aliases, which _verify_plan_inputs separately requires to agree), so
    they cannot be swapped between plan and prepare."""
    _verify_plan_inputs(prepared, workspace)
    snap = prepared["input_snapshot"]
    staging = stage(snap["app_dir"], snap["integration_spec"]["path"], prepared["pinned"],
                    Path(workspace.out_dir) / staging_subdir,
                    workspace_root=workspace.workspace_root,
                    transform_module=TRUSTED_TRANSFORM_MODULE,
                    engine_binding=prepared["engine_binding"],
                    compiler=prepared["compiler"])
    staging["plan_fingerprint"] = prepared["plan_fingerprint"]
    staging["manifest"]["plan_fingerprint"] = prepared["plan_fingerprint"]
    return staging


def validate(prepared: dict, staging: dict, workspace: WorkspacePlan, cases: list,
             timeout_seconds: int = 60, *, trusted_inputs=None) -> dict:
    """VALIDATE seam: compile+run original vs protected with integrity recomputed
    before and after child execution; children cancel on the real workspace STOP.

    Re-validates the SAVED PLAN (fingerprint + aliases + workspace identity), the
    disk app/spec sources and the complete engine/compiler/native/producer inputs
    BEFORE any child is launched -- not only at prepare -- so a drift introduced
    between prepare and validate is rejected. ``cases`` is REQUIRED and explicit
    (validated by :func:`validate_cases`); there is no implicit default fixture.
    The optional ``trusted_inputs`` ({path, sha256}[]) are re-verified from disk at
    preflight, before/after every child, and postflight."""
    if cases is None:
        raise ProducerIntegrateError("validate requires an explicit cases list (no implicit default fixture)")
    if not isinstance(prepared, dict) or prepared.get("status") != "planned":
        raise ProducerIntegrateError("validate requires a planned dict (saved plan)")
    if not isinstance(staging, dict) or not isinstance(staging.get("manifest"), dict):
        raise ProducerIntegrateError("validate requires a staging produced by prepare()")
    _verify_plan_inputs(prepared, workspace)       # re-validate saved plan + disk + engine/compiler/native/prod
    # Bind the staging to THIS re-validated plan so a staging produced from a
    # different plan cannot be validated against it (close the lower-level bypass).
    if staging.get("plan_fingerprint") != prepared["plan_fingerprint"]:
        raise StagingIntegrityError("staging plan_fingerprint does not match the re-validated plan")
    if staging["manifest"].get("plan_fingerprint") != prepared["plan_fingerprint"]:
        raise StagingIntegrityError("staging manifest plan_fingerprint does not match the re-validated plan")
    return build_and_compare(staging, prepared["pinned"], cases,
                             workspace_root=workspace.workspace_root, timeout_seconds=timeout_seconds,
                             stop_file=workspace.stop_file, compiler=prepared["compiler"],
                             trusted_inputs=trusted_inputs)


# --------------------------------------------------------------------------- #
# Public-ready API surface for eventual ProjectService adoption.
# --------------------------------------------------------------------------- #
def project_service_contract() -> dict:
    return {
        "api_version": PUBLIC_API_VERSION,
        "production_api_version": API_VERSION,
        "support_level": SUPPORT_LEVEL,
        "whole_language_support": WHOLE_LANGUAGE_SUPPORT,
        "whole_language_claim": False,
        "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
        "scope": "csharp_producer_bound_managed_app_integration",
        "snapshot_inputs": {
            "ProducerManifest": "the trusted producer build report to consume (disk-rehashed)",
            "ProtectedBuildReceipt": "immutable protected/baseline artifact pins; fresh_protected_native_build flag honest",
            "ToolchainSnapshot": "compiler identity discovered by pure disk hashing (no cached env.setting)",
            "WorkspacePlan": "workspace root, fresh out_dir, trusted transform module NAME, real STOP marker",
        },
        "trusted_inputs_seam": {
            "optional": True,
            "record": {"required": ["path", "sha256"], "optional": ["role"]},
            "path_boundary": "absolute path under the workspace root (owned workspace files: contracts "
                             "under samples, service/engine modules under antirea; NOT limited to .runs)",
            "role": "optional bounded diagnostic string only; never authority, never affects control flow",
            "guards": ["lexical_reserved_name_before_stat_read_hash", "absolute_path_only",
                       "under_workspace_root", "non_symlink_regular_file", "bounded_size_and_total_bytes",
                       "sha256_match_from_disk", "no_code_imported_or_executed", "no_record_silently_dropped"],
            "verified_phases": ["preflight", "before_each_child", "after_each_child", "postflight"],
            "bounds": {"max_records": _MAX_TRUSTED_INPUTS, "max_bytes_per_record": _MAX_TRUSTED_INPUT_BYTES,
                       "max_total_bytes": _MAX_TRUSTED_INPUTS_TOTAL_BYTES},
            "accepted_by": ["run_integration", "validate", "build_and_compare"],
            "compiler_runtime_identity": "installed compiler/runtime (outside the workspace) stays in the "
                                         "explicit compiler snapshot, verified before/after compiler children "
                                         "with the same lexical guard; it is NOT a trusted_inputs record",
        },
        "runtimeconfig_api": {
            "stable": True,
            "original_app_field": "comparison.original_app.runtimeconfig {path, sha256, bytes}",
            "deployable_app_field": "comparison.deployable_app.runtimeconfig {path, sha256, bytes}",
            "also_exposed": ["comparison.deployable_runtimeconfig", "report.deployable_runtimeconfig"],
            "pinned_and_rechecked": "generated original/deployable runtimeconfig.json are hashed, pinned, and "
                                    "re-checked across every child and at postflight alongside both DLLs + the "
                                    "native core",
            "packaging_guidance": "service packaging should CONSUME this exact deployable runtimeconfig pin, not "
                                  "silently repin or regenerate it",
        },
        "trusted_modules": {
            "transform": TRUSTED_TRANSFORM_MODULE,
            "engine": list(TRUSTED_ENGINE_MODULES),
            "loaded_by": "importlib.import_module(trusted_name) only; no spec_from_file_location on a "
                         "caller path and no sys.path injection",
        },
        "serializable_plan": {
            "plan_schema_version": PLAN_SCHEMA_VERSION,
            "json_serializable": True,
            "no_live_handles": "plan carries only scalar/dict content (no dataclass/module handles)",
            "serialize": "serialize_plan(prepared) -> canonical JSON",
            "load": "load_plan(json) -> prepared; recomputes and re-validates plan_fingerprint",
            "round_trip_revalidated_at": ["load", "prepare", "validate"],
            "reconstruction": "transform/engine reconstructed ONLY by trusted module name; no importlib "
                              "path from the serialized plan is honoured",
        },
        "cases_contract": {
            "explicit_required": True,
            "no_default_fixture": True,
            "case_keys": {"required": sorted(_CASE_REQUIRED_KEYS), "optional": sorted(_CASE_OPTIONAL_KEYS)},
            "kinds": list(CASE_KINDS),
            "args": "explicit CLI arguments the target is invoked with (int|str, stringified)",
            "expected_observation_keys": sorted(_EXPECT_KEYS),
            "validated_before_execution": True,
        },
        "seams": {
            "plan": "pure-disk consume+pin producer+native, cross-check receipt, verify toolchain+identity, "
                    "bind owned-transform+engine by trusted name, and bind app-tree+spec into an immutable "
                    "plan_fingerprint (transform hashed by name, never executed here)",
            "prepare": "re-verify planned app/spec from disk and owned-transform+engine by trusted name "
                       "BEFORE importing/executing the transform, then stage source+inventory+native+compiler "
                       "into a tamper-evident manifest",
            "validate": "re-validate the SAVED PLAN (fingerprint + aliases + workspace identity), disk "
                        "sources and complete engine/compiler/native/producer inputs BEFORE any child, then "
                        "compile+run original vs protected over EXPLICIT cases with integrity recomputed "
                        "before and after (optional trusted_inputs re-verified around every child)",
            "serialize_plan": "emit a JSON-serializable plan (fingerprint self-consistency enforced)",
            "load_plan": "reconstruct+re-validate a serialized plan by trusted name (tamper-evident); "
                         "workspace identity fingerprint-bound and STOP rederived, never trusted from an alias",
            "run_integration": "end-to-end plan->prepare->validate producing a disclosed report",
        },
        "plan_binding": {
            "bound_at_plan": ["app_source_tree", "integration_spec", "owned_transform_module_by_name",
                              "engine_modules_by_name", "producer_report", "producer_contract",
                              "protected_artifact", "baseline_artifact", "compiler", "selectors",
                              "workspace_root", "stop_relative"],
            "transform_executed_at_plan": False,
            "workspace_out_dir_binding": "per_run_fresh_rederived_and_revalidated_not_fingerprinted",
            "stop_binding": "rederived_from_bound_workspace_root_never_trusted_from_alias",
            "reverify_points": ["serialized_plan_load", "before_prepare_and_transform_execution",
                                "before_validate_children", "preflight_before_children",
                                "native_and_assembly_repin_before_each_case", "postflight_after_all_children"],
            "drift_rejected": ["app_source_change_between_plan_and_prepare",
                               "integration_spec_change_between_plan_and_prepare",
                               "transform_module_change_between_plan_and_prepare_without_executing_it",
                               "engine_module_change_between_plan_and_prepare",
                               "producer_or_native_change_between_plan_and_prepare",
                               "workspace_root_or_stop_alias_tamper", "source_output_overlap",
                               "trusted_input_mismatch",
                               "plan_fingerprint_mismatch", "serialized_plan_tamper"],
        },
        "self_containedness_over_wave4": {
            "transform_module": "owned in-package antirea.csharp_transform, loaded by trusted NAME; "
                                "no caller-supplied .runs path and no spec_from_file_location",
            "import_path_injection": "removed; engine imported by name, no sys.path.insert",
            "repo_root": "workspace_root is explicit, not a fixed __file__ parent depth",
            "plan": "JSON-serializable with save/load round trip and fingerprint re-validation",
            "cases": "explicit cases + expected-observation contract; default_cases fixture removed",
            "provenance": "declared by the caller's ProtectedBuildReceipt, not a hard-coded phase label",
            "native_core_filename": "derived from the integration spec's native_library",
        },
        "integrity_model": {
            "bound_from": "on_disk_bytes_not_report_claims",
            "trusts_stored_manifest": False,
            "execution_paths_bound_to_manifest": True,
            "recompute_phases": ["preflight_before_child_execution", "postflight_after_all_children",
                                 "native_and_assembly_repin_before_each_case"],
            "rejects": ["changed_staged_file", "missing_staged_file", "extra_injected_file",
                        "native_dll_change", "original_app_source_change", "integration_spec_change",
                        "transform_module_change", "engine_module_change", "producer_report_change",
                        "producer_or_compiler_tool_change", "redirected_staging_path",
                        "protected_receipt_disagreement", "untrusted_transform_module",
                        "workspace_identity_tamper", "source_output_overlap",
                        "reserved_or_received_path", "trusted_input_mismatch",
                        "serialized_plan_tamper"],
            "stop_phases": ["preflight", "during_execution", "before_each_case", "postflight", "per_child_cancel"],
            "stop_sources": ["real_workspace_stop_always", "optional_fixture_cancellation_additive_only"],
            "caveats": [
                "net-change detection across the run, not transient swap-and-restore detection",
                "SHA-256 content hashes, not a cryptographically signed report",
                "Windows Job cleanup is cleanup evidence, not an atomic security sandbox",
            ],
        },
        "provenance_model": {
            "native_producer": "caller-declared reuse of a hash-pinned producer artifact, re-verified from disk",
            "caller": "freshly_staged_compiled_executed",
            "fresh_protected_native_build": "must be False for a reused pinned artifact",
        },
        "integration_mode": "explicit_source_integrate",
        "integration_note": "An EXPERIMENTAL explicit_source_integrate seam in the antirea package: it binds "
                            "an owned managed application to an existing pinned producer native core and "
                            "re-verifies every input from on-disk bytes. It makes NO whole-application, "
                            "whole-language, defense-strength or performance claim. The module's gate logic "
                            "is implemented here, but gate CLOSURE is only established by root's frozen-source "
                            "full suite and fresh public native/app qualification -- this metadata does NOT "
                            "assert all gates are closed, and root's final report owns qualification.",
        "qualification_owner": "root_final_report",
        "gates_pending": {
            "frozen_full_suite": "root_owned_pending_all_editor_agreement",
            "source_bound_fresh_native_build": "root_owned_after_source_freeze",
            "performance_evaluation": "not_evaluated",
            "defense_strength_evaluation": "not_evaluated",
            "external_attack_evaluation": "not_evaluated",
        },
    }


def qualification_status(comparison: dict) -> dict:
    functional_sample_passed = bool(comparison.get("status") == "producer_bound_integration_passed"
                                    and comparison.get("integrity_verified_before_and_after"))
    return {
        "integration_mode": "explicit_source_integrate",
        "support_level": SUPPORT_LEVEL,
        "functional_sample_passed": functional_sample_passed,
        "functional_sample_basis": "sampled_functional_equivalence_plus_tamper_evident_staging",
        "qualification_owner": "root_final_report",
        "frozen_full_suite": "root_owned_pending_all_editor_agreement",
        "whole_language_support": WHOLE_LANGUAGE_SUPPORT,
        "performance_acceptance": "not_evaluated",
        "defense_effectiveness": "not_evaluated",
        "external_attack_evaluation": "not_evaluated",
    }


def run_integration(producer: ProducerManifest, receipt: ProtectedBuildReceipt,
                    toolchain: ToolchainSnapshot, workspace: WorkspacePlan,
                    app_dir, integration_spec_path, *, timeout_seconds: int = 60,
                    cases: list, round_trip_plan: bool = True, write_report: bool = True,
                    trusted_inputs=None) -> dict:
    """End-to-end integration: plan -> (optional serialize/load round trip) -> prepare -> validate.

    ``cases`` is REQUIRED and explicit. When ``round_trip_plan`` is set (default),
    the plan is serialized to JSON and reloaded (re-validating the fingerprint by
    trusted name) before prepare, exercising the serializable facade end to end.

    The optional, public-compatible ``trusted_inputs`` is a list of ``{path, sha256}``
    records (an optional bounded diagnostic ``role`` is allowed) binding owned
    workspace files -- e.g. a source-service plan/result, the integration execution
    contract, and service module bytes -- verified from disk at preflight, before AND
    after every child, and at postflight. No code is imported/executed from them.

    REUSE DISCLOSURE: the native producer report/DLL are REUSED from the pinned
    producer build named by ``producer``/``receipt`` and re-verified from disk; the
    managed caller is freshly staged, compiled and executed. run_integration consumes
    existing producer artifacts, so ``fresh_protected_native_build`` stays False even
    when the producer was itself freshly made by the public source-build just before.
    """
    if cases is None:
        raise ProducerIntegrateError("run_integration requires an explicit cases list (no default fixture)")
    trusted_inputs = _normalize_trusted_inputs(trusted_inputs)   # fail closed on malformed records up front
    prepared = plan(producer, receipt, toolchain, workspace, app_dir, integration_spec_path)
    plan_round_trip = False
    if round_trip_plan:
        prepared = load_plan(serialize_plan(prepared))      # save+reload, re-validate fingerprint
        plan_round_trip = True
    staging = prepare(prepared, workspace)
    comparison = validate(prepared, staging, workspace, cases=cases, timeout_seconds=timeout_seconds,
                          trusted_inputs=trusted_inputs)
    pinned = prepared["pinned"]
    rb = prepared["receipt_binding"]
    report = {
        "schema_version": SCHEMA_VERSION, "status": comparison["status"],
        "scope": "csharp_producer_bound_managed_app_integration",
        "plan_fingerprint": prepared["plan_fingerprint"],
        "plan_round_trip_through_json": plan_round_trip,
        "transform_module": TRUSTED_TRANSFORM_MODULE,
        "engine_binding": prepared["engine_binding"],
        "plan_input_snapshot": prepared["input_snapshot"],
        "producer_provenance": rb["provenance"],
        "fresh_protected_native_build": rb["fresh_protected_native_build"],
        "caller_provenance": "freshly_staged_compiled_executed",
        "producer": {"report_path": pinned["report_path"], "report_sha256": pinned["report_sha256"],
                     "protected": pinned["protected"], "baseline": pinned["baseline"],
                     "contract_path": pinned["contract_path"], "contract_sha256": pinned["contract_sha256"]},
        "receipt_binding": rb,
        "identity": prepared["identity"],
        "staging_manifest": staging["manifest"],
        "staging": {k: staging[k] for k in ("out_dir", "native_core", "native_core_sha256", "native_library",
                                            "source_binding", "byte_preservation", "interop_evidence",
                                            "deployable_source_hashes", "original_source_hashes",
                                            "rewritten_files", "unchanged_files", "deployable_sources",
                                            "interop_files")},
        "source_transform_report": staging["report"],
        "comparison": comparison,
        "integrity_preflight": comparison["integrity_preflight"],
        "integrity_postflight": comparison["integrity_postflight"],
        "deployable_runtimeconfig": comparison["deployable_runtimeconfig"],
        "original_app": comparison["original_app"],
        "deployable_app": comparison["deployable_app"],
        "trusted_inputs_verification": comparison["trusted_inputs_verification"],
        "project_service_contract": project_service_contract(),
        "qualification": qualification_status(comparison),
        "api_version": API_VERSION,
        "support_level": SUPPORT_LEVEL,
        "whole_language_support": WHOLE_LANGUAGE_SUPPORT,
        "external_attack_evaluation": "not_evaluated",
        "performance_evaluation": "not_evaluated",
        "defense_strength_evaluation": "not_evaluated",
        "full_suite_freeze": "root_owned_pending_all_editor_agreement",
    }
    if write_report:
        out = Path(workspace.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "integration.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report
