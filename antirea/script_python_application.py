"""Stage an ordinary owned Python application around one protected module.

Defender-only staging adapter for the phase24 script application integration
route. :func:`prepare_application` copies the frozen planned source tree twice
into a fresh adapter-owned output directory:

* ``original`` -- the untouched planned tree (every application file byte-exact);
* ``protected`` -- the same tree with ONLY the single selected module replaced by
  the producer's protected artifact, every other file byte-identical.

It then derives runpy module execution from the relative ``.py`` entry and the
package ``__init__.py`` layout, writes a fixed (non-interpolated) runpy bootstrap
runner, and returns an exact deploy inventory plus original-source binding
evidence.

This module STAGES ONLY. It never executes the application, the interpreter, or
any child process; the shared engine runs and compares the original, protected
and independently copied deployment arms (plus the missing-module control) after
root freeze. A successful staging is not functional preservation, performance
acceptance, or attack-resistance evidence; those remain separate, later gates.

The security-critical path helpers (lexical reserved-component rejection,
symlink/reparse/hardlink rejection, bounded hashing and bounded tree inventory)
are reused from :mod:`antirea.jvm_app_integration` so every language route shares
one audited implementation.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re

from . import jvm_app_integration as safe

LANGUAGE = "python"
# Pure-source VM and mixed-module VM producers are both accepted; each protects a
# single owned source module. IMPORTANT: the two backends hash the original
# differently. The pure ``python_vm`` producer reads source as UTF-8-sig with
# universal newlines, so its ``baseline`` and ``source_sha256`` are over the
# NORMALIZED text (BOM stripped, CRLF->LF). The mixed ``python_mixed_module_vm``
# producer decodes raw UTF-8 and preserves BOM/CRLF, so its baseline IS the raw
# bytes. The raw original (what the staged original tree preserves and what
# ``original_core_sha256`` reports) is therefore bound to the producer through
# ``project.input_hashes`` (always the raw on-disk file hash), while the
# normalized ``baseline``/``source_sha256`` are checked for internal consistency.
PRODUCER_BACKENDS = ("python_vm", "python_mixed_module_vm")
MIXED_BACKEND = "python_mixed_module_vm"
PURE_BACKEND = "python_vm"
PRODUCER_OK_STATUS = "artifact_created_unvalidated"
# Ordinary Python application files: runnable source plus plain data. Anything
# else (``.pyc``, ``.pyd``/``.so`` native extensions, ``.d.ts`` etc.) is refused
# so caches or opaque binaries can never travel in place of preserved source.
ALLOWED_SUFFIXES = (".py", ".json", ".txt")
MAX_APPLICATION_FILES = 128
MAX_FILE_BYTES = 16 << 20            # 16 MiB per staged / replaced file
MAX_TOTAL_BYTES = 64 << 20           # 64 MiB total across the staged file set
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
# Windows reserved DOS device names: a path component whose stem (before the
# first dot) case-folds to one of these resolves to a device, never a file.
_DOS_DEVICES = frozenset(
    {"con", "prn", "aux", "nul",
     *("com%d" % i for i in range(1, 10)), *("lpt%d" % i for i in range(1, 10))})
# Build/cache directories that must never enter a staged application tree.
_FORBIDDEN_COMPONENTS = frozenset({"__pycache__", "node_modules"})

# Fixed, trusted runner. Module name and application arguments are supplied ONLY
# as argv (never interpolated into this source), so the staged bytes are
# identical for every prepared application and carry no program text. The engine
# invokes it as:  <python> bootstrap.py <root_dir> <dotted_module> [app-arg ...]
RUNPY_BOOTSTRAP = '''"""Fixed ANTI-REA Python application runner (trusted; no interpolated source).

Usage: python bootstrap.py <root_dir> <dotted_module> [app-arg ...]

Runs the owned application module under runpy as ``__main__`` with ``root_dir`` as
the sole prepended import root. The module name and application arguments arrive
only through argv; this file is byte-identical across every prepared application
and the engine re-hashes it before every run.
"""
import runpy
import sys


def _main():
    if len(sys.argv) < 3:
        raise SystemExit("usage: bootstrap.py <root_dir> <module> [app-arg ...]")
    root_dir = sys.argv[1]
    module = sys.argv[2]
    app_args = sys.argv[3:]
    # Never write .pyc caches into the staged/bundle tree; keep its inventory exact.
    sys.dont_write_bytecode = True
    sys.path.insert(0, root_dir)
    sys.argv = [module, *app_args]
    runpy.run_module(module, run_name="__main__", alter_sys=True)


if __name__ == "__main__":
    _main()
'''


class ScriptPythonApplicationError(ValueError):
    """Any spec/producer/identity/staging inconsistency (fail closed)."""


def _wrap(function, *args, **kwargs):
    """Call a shared ``safe`` helper, re-raising its error under this module's type."""
    try:
        return function(*args, **kwargs)
    except safe.JvmIntegrateError as exc:
        raise ScriptPythonApplicationError(str(exc)) from exc


def _sha(value) -> str:
    if not isinstance(value, str) or not _SHA256_RE.match(value):
        raise ScriptPythonApplicationError("Missing or malformed SHA256 (64 lowercase hex): %r" % (value,))
    return value


def _relative(value: str) -> PurePosixPath:
    """Validate a clean forward-slash relative path and return its posix form.

    Rejects absolute, drive-qualified, backslash, NUL, whitespace-padded, empty,
    ``.`` / ``..`` and reserved-component paths LEXICALLY, before any filesystem
    access.
    """
    if (not isinstance(value, str) or not value or value != value.strip()
            or "\\" in value or ":" in value or "\x00" in value or value.startswith("/")):
        raise ScriptPythonApplicationError("Expected a clean relative forward-slash path: %r" % (value,))
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ScriptPythonApplicationError("Relative path is empty or traverses: %r" % (value,))
    rel = PurePosixPath(value)
    if rel.is_absolute():
        raise ScriptPythonApplicationError("Relative path must not be absolute: %r" % (value,))
    for part in parts:
        if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in part):
            raise ScriptPythonApplicationError("Relative path component holds a control character: %r" % (value,))
        if part != part.strip() or part.endswith(".") or part.endswith(" "):
            # Windows silently strips trailing spaces/dots, which would alias two
            # distinct declared paths onto one on-disk name.
            raise ScriptPythonApplicationError("Relative path component has a trailing dot/space: %r" % (value,))
        folded = part.casefold()
        if part.split(".")[0].casefold() in _DOS_DEVICES:
            raise ScriptPythonApplicationError("Relative path uses a reserved Windows device name: %r" % (value,))
        if folded in safe.RESERVED_PATH_COMPONENTS or folded in _FORBIDDEN_COMPONENTS:
            raise ScriptPythonApplicationError("Relative path traverses a reserved/forbidden component %r: %s" % (part, value))
    return rel


def _fs(root: Path, rel: PurePosixPath) -> Path:
    """Resolve a validated relative path under ``root`` without escaping it."""
    target = _wrap(safe._no_links, Path(os.path.abspath(root / Path(*rel.parts))))
    if not target.is_relative_to(root):
        raise ScriptPythonApplicationError("Relative path escapes its root: %s" % (rel,))
    return target


def _dir(path: Path) -> Path:
    path = _wrap(safe._no_links, Path(os.path.abspath(path)))
    if path.exists():
        if not path.is_dir() or any(path.iterdir()):
            raise ScriptPythonApplicationError("Adapter output must be a fresh empty directory: %s" % (path,))
    else:
        path.mkdir(parents=True)
    return path


def _derive_module(entrypoint: PurePosixPath, rel_set: set[str]) -> dict:
    """Derive the dotted module and package chain from the ``.py`` entry layout.

    Each directory on the way to the entry must be an importable package (hold an
    ``__init__.py`` that is itself an explicit application file). The module is run
    from the tree root placed on ``sys.path``; no dynamic import graph is proven.
    """
    parts = entrypoint.parts
    if entrypoint.suffix != ".py":
        raise ScriptPythonApplicationError("Python entrypoint must be a .py source: %s" % (entrypoint,))
    dir_parts, stem = list(parts[:-1]), parts[-1][: -len(".py")]
    names = [*dir_parts, stem]
    if any(not _IDENTIFIER_RE.match(name) for name in names):
        raise ScriptPythonApplicationError("Entry path does not form valid module identifiers: %s" % (entrypoint,))
    package_chain, prefix = [], []
    for name in dir_parts:
        prefix.append(name)
        init_rel = "/".join([*prefix, "__init__.py"])
        if init_rel not in rel_set:
            raise ScriptPythonApplicationError("Package %r is missing its explicit __init__.py" % ("/".join(prefix),))
        package_chain.append("/".join(prefix))
    return {"runtime_entrypoint": entrypoint.as_posix(), "module": ".".join(names),
            "package_chain": package_chain, "is_package": bool(dir_parts),
            "root_is_sys_path_entry": True}


def _verify_artifact(entry, arm: str) -> dict:
    """Read a producer artifact's ACTUAL bytes and verify its SHA256 and byte count."""
    if (not isinstance(entry, dict) or not isinstance(entry.get("path"), str) or not entry["path"]
            or type(entry.get("bytes")) is not int):
        raise ScriptPythonApplicationError("producer %s artifact entry is malformed" % arm)
    claimed = _sha(entry.get("sha256"))
    path = _wrap(safe._no_links, Path(os.path.abspath(entry["path"])))
    if not path.is_file():
        raise ScriptPythonApplicationError("producer %s artifact is missing on disk: %s" % (arm, path))
    data = _wrap(safe._read_bytes_bounded, path, limit=MAX_FILE_BYTES)
    actual = hashlib.sha256(data).hexdigest()
    if actual != claimed:
        raise ScriptPythonApplicationError("producer %s artifact SHA256 does not match its actual bytes" % arm)
    if len(data) != entry["bytes"]:
        raise ScriptPythonApplicationError("producer %s artifact byte count does not match its 'bytes' field" % arm)
    return {"path": str(path), "sha256": actual, "bytes": len(data)}


def _bind_producer(producer, *, protected_source: str, original_core_sha: str) -> dict:
    """Authenticate the producer report and bind the integrated module to the original.

    The RAW original -- what the staged original tree preserves and what
    ``original_core_sha256`` reports -- is bound to the producer through
    ``project.input_hashes`` (always the raw on-disk file hash) for BOTH backends.
    Each artifact's ACTUAL bytes are read and its ``sha256``/``bytes`` fields
    verified. The normalized ``baseline``/``source_sha256`` are checked for internal
    consistency; only the mixed backend (which preserves raw BOM/CRLF) additionally
    requires ``baseline`` to equal the raw original, since the pure backend's
    baseline is deliberately UTF-8-sig/universal-newline normalized.
    """
    if not isinstance(producer, dict):
        raise ScriptPythonApplicationError("producer report must be a JSON object")
    if type(producer.get("schema_version")) is not int or producer["schema_version"] != 1:
        raise ScriptPythonApplicationError("producer schema_version must be the integer 1")
    if producer.get("status") != PRODUCER_OK_STATUS:
        raise ScriptPythonApplicationError("producer must be a successful unvalidated source build")
    backend = producer.get("backend")
    if backend not in PRODUCER_BACKENDS:
        raise ScriptPythonApplicationError("producer backend is not a supported Python VM backend")
    artifacts = producer.get("artifacts")
    if not isinstance(artifacts, dict) or not {"baseline", "protected"} <= set(artifacts):
        raise ScriptPythonApplicationError("producer must record baseline and protected artifacts")
    baseline = _verify_artifact(artifacts["baseline"], "baseline")
    protected = _verify_artifact(artifacts["protected"], "protected")

    # Authoritative RAW binding via project.input_hashes (required, both backends).
    project = producer.get("project")
    if not isinstance(project, dict) or project.get("language") != LANGUAGE:
        raise ScriptPythonApplicationError("producer project identity is missing or not python")
    sources = project.get("sources")
    input_hashes = project.get("input_hashes")
    if (not isinstance(sources, list) or len(sources) != 1 or not isinstance(sources[0], str)
            or not isinstance(input_hashes, dict)):
        raise ScriptPythonApplicationError("producer project must list exactly one source and input_hashes")
    if input_hashes.get(sources[0]) != original_core_sha:
        raise ScriptPythonApplicationError(
            "original-source binding failed: producer project raw source hash does not match the frozen module")
    basename_equal = PurePosixPath(protected_source).name == Path(sources[0]).name

    # Normalized self-consistency: the baseline is the producer's record of the
    # protected-source text (normalized for pure, raw for mixed).
    source_sha = project.get("source_sha256")
    inspection = producer.get("inspection")
    if isinstance(inspection, dict) and "source_sha256" in inspection:
        if source_sha is not None and inspection["source_sha256"] != source_sha:
            raise ScriptPythonApplicationError("producer project and inspection source_sha256 disagree")
        source_sha = source_sha if source_sha is not None else inspection["source_sha256"]
    if not isinstance(source_sha, str) or not _SHA256_RE.match(source_sha):
        raise ScriptPythonApplicationError("producer must record a source_sha256")
    if baseline["sha256"] != source_sha:
        raise ScriptPythonApplicationError("producer baseline does not match its recorded source_sha256")

    baseline_equals_raw = baseline["sha256"] == original_core_sha
    if backend == MIXED_BACKEND and not baseline_equals_raw:
        raise ScriptPythonApplicationError(
            "mixed-module producer must preserve raw bytes: baseline SHA256 must equal the raw original")

    coverage = producer.get("coverage")
    summary = None
    if isinstance(coverage, dict):
        summary = {key: coverage[key] for key in ("selected_functions", "helper_closure", "format_version")
                   if key in coverage}
    normalization = "raw_preserved" if backend == MIXED_BACKEND else "utf8sig_universal_newline_normalized"
    return {"backend": backend, "status": producer["status"], "protected_artifact": protected,
            "baseline": baseline, "source_sha256": source_sha, "normalization": normalization,
            "binding": {"raw_bound_via_project_input_hashes": True, "baseline_equals_source_sha256": True,
                        "baseline_equals_raw_original": baseline_equals_raw, "basename_equal": basename_equal},
            "coverage": summary}


def _copy(source: Path, destination: Path, *, expected: str) -> str:
    """Byte-exact bounded copy with origin + destination hash verification."""
    actual = _wrap(safe._hash_file, source, limit=MAX_FILE_BYTES)
    if actual != expected:
        raise ScriptPythonApplicationError("input content changed before staging: %s" % (source,))
    data = _wrap(safe._read_bytes_bounded, source, limit=MAX_FILE_BYTES)
    _wrap(safe._no_links, destination)
    if destination.exists():
        raise ScriptPythonApplicationError("staged filename collision: %s" % (destination,))
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as stream:
        stream.write(data)
    written = _wrap(safe._hash_file, destination, limit=MAX_FILE_BYTES)
    if written != expected:
        raise ScriptPythonApplicationError("staged copy hash mismatch: %s" % (destination,))
    return written


def _inventory(root: Path, expected: dict) -> dict:
    """Return the exact posix->sha256 map of ``root`` and assert it equals ``expected``."""
    disk = {rel: entry["sha256"] for rel, entry in _wrap(safe._tree_inventory, root).items()}
    if disk != expected:
        missing, extra, changed = safe._inventory_diff(expected, disk)
        raise ScriptPythonApplicationError(
            "staged tree inventory is not exactly the reviewed file set "
            "(missing=%s extra=%s changed=%s): %s" % (missing, extra, changed, root))
    return disk


def _stop(stop_file) -> None:
    # Existence probe only; never read/created/deleted and never routed through the
    # reserved-component guard (the real STOP lives under .runs/defense-loop).
    if stop_file is not None and Path(os.path.abspath(stop_file)).exists():
        raise ScriptPythonApplicationError("defense STOP marker present; refusing to stage")


def prepare_application(*, source_root, input_files, protected_source, entrypoint, producer,
                        output_dir, tools, trusted_inputs, timeout_seconds, stop_file) -> dict:
    """Stage the original and protected Python application trees (no execution).

    See the module docstring for the contract. Returns exactly the 11 adapter keys
    documented in the phase24 brief; the derived module and fixed runpy bootstrap
    live under ``reference_evidence`` for the engine to run the arms.
    """
    if type(timeout_seconds) is not int or isinstance(timeout_seconds, bool) or not 1 <= timeout_seconds <= 600:
        raise ScriptPythonApplicationError("timeout_seconds must be an int in 1..600")
    _stop(stop_file)
    source_root = _wrap(safe._no_links, Path(os.path.abspath(source_root)))
    if not source_root.is_dir():
        raise ScriptPythonApplicationError("source_root must be an existing directory")
    if not isinstance(input_files, dict) or not 1 <= len(input_files) <= MAX_APPLICATION_FILES:
        raise ScriptPythonApplicationError("input_files must map 1..%d relative paths to SHA256" % MAX_APPLICATION_FILES)
    if not isinstance(tools, dict):
        raise ScriptPythonApplicationError("tools must be a mapping")
    interpreter = tools.get("python_executable")
    if (not isinstance(interpreter, dict) or not isinstance(interpreter.get("path"), str)
            or not interpreter["path"] or not _SHA256_RE.match(str(interpreter.get("sha256", "")))):
        raise ScriptPythonApplicationError("tools must include python_executable as {path, sha256}")
    if not isinstance(trusted_inputs, dict):
        raise ScriptPythonApplicationError("trusted_inputs must map absolute paths to SHA256")
    for value in trusted_inputs.values():
        _sha(value)

    # Validate the explicit relative file set (lexical, before any copy/traversal).
    rels, casefold = {}, {}
    total = 0
    for value, digest in input_files.items():
        rel = _relative(value)
        key = rel.as_posix()
        digest = _sha(digest)
        if rel.suffix.lower() not in ALLOWED_SUFFIXES:
            raise ScriptPythonApplicationError("Unsupported Python application file suffix: %s" % key)
        folded = key.casefold()
        if folded in casefold:
            raise ScriptPythonApplicationError("Duplicate or case-folding file collision: %s vs %s"
                                               % (key, casefold[folded]))
        casefold[folded] = key
        rels[key] = digest
    rel_set = set(rels)
    prot_rel = _relative(protected_source).as_posix()
    entry_rel = _relative(entrypoint).as_posix()
    if prot_rel not in rel_set or entry_rel not in rel_set:
        raise ScriptPythonApplicationError("protected_source and entrypoint must be listed application files")
    if prot_rel == entry_rel:
        raise ScriptPythonApplicationError("entrypoint must differ from protected_source so an ordinary caller runs it")
    if PurePosixPath(prot_rel).suffix != ".py":
        raise ScriptPythonApplicationError("protected_source must be a .py module")
    module = _derive_module(PurePosixPath(entry_rel), rel_set)

    original_core_sha = rels[prot_rel]
    bound = _bind_producer(producer, protected_source=prot_rel, original_core_sha=original_core_sha)
    protected_sha = bound["protected_artifact"]["sha256"]

    output = _dir(output_dir)
    original_root = _dir(output / "original")
    protected_root = _dir(output / "protected")

    # Verify every on-disk input against its frozen snapshot hash and the total bound.
    for key, digest in rels.items():
        source_path = _fs(source_root, PurePosixPath(key))
        if not source_path.is_file():
            raise ScriptPythonApplicationError("declared application file is missing: %s" % key)
        actual = _wrap(safe._hash_file, source_path, limit=MAX_FILE_BYTES)
        if actual != digest:
            raise ScriptPythonApplicationError("application file content changed since the snapshot: %s" % key)
        if key == prot_rel:
            raw_core = _wrap(safe._read_bytes_bounded, source_path, limit=MAX_FILE_BYTES)
            if hashlib.sha256(raw_core).hexdigest() != digest:
                raise ScriptPythonApplicationError("original core changed during source binding")
            if bound["backend"] == PURE_BACKEND:
                try:
                    text = raw_core.decode("utf-8-sig").replace("\r\n", "\n").replace("\r", "\n")
                except UnicodeError as exc:
                    raise ScriptPythonApplicationError("pure Python source must be UTF-8") from exc
                expected_baseline = hashlib.sha256(text.encode("utf-8")).hexdigest()
            else:
                expected_baseline = digest
            if expected_baseline != bound["baseline"]["sha256"]:
                raise ScriptPythonApplicationError("producer baseline is not the decoded original source")
            bound["binding"]["baseline_matches_original_decoding"] = True
        total += source_path.stat().st_size
        if total > MAX_TOTAL_BYTES:
            raise ScriptPythonApplicationError("staged application exceeds the total byte bound")

    # Stage the original (untouched) tree.
    original_map = {}
    for key, digest in rels.items():
        source_path = _fs(source_root, PurePosixPath(key))
        original_map[key] = _copy(source_path, _fs(original_root, PurePosixPath(key)), expected=digest)

    # Verify + read the producer's protected artifact, then stage the protected
    # twin: every file byte-identical EXCEPT the one selected module.
    artifact_path = _wrap(safe._no_links, Path(os.path.abspath(bound["protected_artifact"]["path"])))
    if not artifact_path.is_file():
        raise ScriptPythonApplicationError("producer protected artifact is missing on disk")
    if _wrap(safe._hash_file, artifact_path, limit=MAX_FILE_BYTES) != protected_sha:
        raise ScriptPythonApplicationError("producer protected artifact hash mismatch")
    protected_map = {}
    for key, digest in rels.items():
        dest = _fs(protected_root, PurePosixPath(key))
        if key == prot_rel:
            protected_map[key] = _copy(artifact_path, dest, expected=protected_sha)
        else:
            source_path = _fs(source_root, PurePosixPath(key))
            protected_map[key] = _copy(source_path, dest, expected=digest)

    expected_protected = {**rels, prot_rel: protected_sha}
    _stop(stop_file)
    original_map = _inventory(original_root, rels)
    protected_map = _inventory(protected_root, expected_protected)
    if set(original_map) != set(protected_map):
        raise ScriptPythonApplicationError("original and protected trees disagree on membership")
    for key in original_map:
        preserved = original_map[key] == protected_map[key]
        if key == prot_rel:
            if preserved or protected_map[key] != protected_sha:
                raise ScriptPythonApplicationError("protected module was not substituted in the protected tree")
        elif not preserved:
            raise ScriptPythonApplicationError("an unselected application file was not preserved byte-for-byte: %s" % key)

    bootstrap = output / "bootstrap.py"
    with bootstrap.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(RUNPY_BOOTSTRAP)
    bootstrap_sha = _wrap(safe._hash_file, bootstrap, limit=MAX_FILE_BYTES)

    reference_evidence = {
        "producer": {"backend": bound["backend"], "status": bound["status"],
                     "protected_artifact": bound["protected_artifact"],
                     "baseline": bound["baseline"], "source_sha256": bound["source_sha256"],
                     "normalization": bound["normalization"], "binding": bound["binding"],
                     "coverage": bound["coverage"]},
        "original_source_binding": {"relative": prot_rel, "raw_sha256": original_core_sha,
                                    "bound_via_project_input_hashes": True,
                                    "baseline_equals_raw_original": bound["binding"]["baseline_equals_raw_original"]},
        "module_execution": module,
        "runpy_bootstrap": {"path": str(bootstrap), "relative_to_output": "bootstrap.py",
                            "sha256": bootstrap_sha, "run_mode": "runpy.run_module",
                            "run_name": "__main__",
                            "argv_contract": "<python> -I -S -B bootstrap.py <stage_root> <module> [app-arg ...]",
                            "interpreter_flags": ["-I", "-S", "-B"],
                            "interpolates_program_source": False, "writes_bytecode": False},
        "interpreter": {"path": interpreter["path"], "sha256": interpreter["sha256"],
                        "pin_verified_by_engine_around_execution": True},
        "staging": {"application_file_count": len(rels), "total_source_bytes": total,
                    "replaced_relative": prot_rel, "source_root": str(source_root)},
        "trusted_inputs_declared": len(trusted_inputs),
    }
    limitations = [
        "Adapter stages only; it does not execute the application, the interpreter or any child process.",
        "The protected module is a drop-in single-file source replacement; all unselected files are copied byte-for-byte.",
        "The original core source and the producer baseline are defender-private and must be excluded from any deployment bundle by the engine.",
        "original_core_sha256 and the staged original tree are the RAW source bytes; the pure python_vm producer baseline is UTF-8-sig/universal-newline normalized, so the raw binding is through project.input_hashes, not the baseline.",
        "Module execution is derived from the relative .py entry and the __init__.py package layout; no dynamic import graph or whole-application reachability is proven.",
        "No dependency installation, resolution, source overwrite or package/build hook is performed.",
        "Per-function VM hardening is referenced from the producer coverage, not re-verified here.",
        "whole_application_verified=false; functional preservation, performance and external resistance are not evaluated by this adapter.",
    ]
    result = {
        "language": LANGUAGE,
        "original_root": str(original_root),
        "protected_root": str(protected_root),
        "runtime_entrypoint": entry_rel,
        "protected_relative": prot_rel,
        "preparation_commands": [],
        "file_maps": {"original": original_map, "protected": protected_map},
        "protected_sha256": protected_sha,
        "original_core_sha256": original_core_sha,
        "reference_evidence": reference_evidence,
        "limitations": limitations,
    }
    # Persist a parse-identical copy so the engine can verify returned-vs-persisted.
    with (output / "preparation.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, indent=2, ensure_ascii=True, allow_nan=False, sort_keys=True)
        stream.write("\n")
    return result
