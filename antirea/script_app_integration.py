"""Shared, producer-bound Python/JavaScript/TypeScript application integration engine.

This is the common ENGINE lane of the explicit script source-integrate seam
(phase24). A separated producer (``antirea.script_python_application`` /
``antirea.script_javascript_application`` upstream build+report) first protects
exactly one selected source module into a reused ``protected`` artifact. An ORDINARY
surrounding application that lives in the same fingerprinted source plan is staged by
a trusted language ADAPTER into two runtime trees: an ``original`` tree whose core
module is the RAW original selected source (Python and mixed JavaScript) or an
independently compiled reference (pure JavaScript export syntax and all TypeScript)
-- NEVER the producer baseline -- and a ``protected`` tree whose core module is the
reused protected artifact. The engine then proves -- by re-deriving every pin from on-disk bytes and
recording complete bounded Windows-Job process receipts -- that the explicit sample
cases produce identical stdout/returncode across THREE arms (original, protected
and an independently copied relocatable deployment bundle), that a missing-module
control in a private copy fails the corresponding successful case, and that the
deployment bundle contains only the protected runtime file plus the explicit
unselected runtime/data files.

Lane boundary (defender-only, engine lane):
  * The language adapters are owned by the PYTHON / JAVASCRIPT worker lanes and are
    loaded ONLY by their trusted in-package names (``importlib.import_module``) --
    never from a caller-supplied path, never with ``sys.path`` injection -- and are
    bound by on-disk source hash. TypeScript routes through the JavaScript adapter.
  * The ``protected``/``baseline`` script artifacts are REUSED pinned producer
    outputs, re-hashed from disk; this engine NEVER re-runs the source protection,
    so ``fresh_protected_build`` is always False.
  * Adapters STAGE only (a TS adapter may run the pinned compiler as a bounded
    preparation child with receipts). The engine runs the SAMPLE cases + controls.

Scope / non-claims (fail closed, never overclaim):
  * Installed interpreters/compilers + owned source only. No install, download,
    restore, publish or push. Received code is never executed. The reserved/received
    path components (``env.setting``/``linkrepro``/``attackerfolder``/
    ``rea-analysis-reports``/``defense-loop``) are rejected lexically before any
    filesystem access, except the real workspace STOP existence probe.
  * Child processes are bounded, run under a minimal private allowlisted env with a
    private TEMP/HOME and are cleaned up under a Windows Job. Job cleanup is cleanup
    evidence, NOT an atomic security sandbox; process ownership is not a boundary.
  * A passing sample comparison proves dependency PRESENCE, not that every selected
    function is reached, not call-tracing, not whole-application/whole-language
    correctness. ``external_resistance`` and ``performance_acceptance`` stay
    ``not_evaluated`` here; final qualification is owned by the root service's
    independent raw-receipt verifier over this engine's persisted report.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import time

from . import jvm_app_integration as safe, process


SCHEMA_VERSION = 1
SPEC_KIND = "script_application_integration"
CONTRACT_KIND = "script_application_samples"
STATUS_PASSED = "script_application_samples_passed"
PRODUCER_OK_STATUS = "artifact_created_unvalidated"

# Trusted adapter module names (loaded by name only). TypeScript reuses the
# JavaScript adapter (JS + multi-file TS reference/preparation lane).
_ADAPTER_MODULES = {
    "python": "antirea.script_python_application",
    "javascript": "antirea.script_javascript_application",
    "typescript": "antirea.script_javascript_application",
}
# Support modules whose on-disk source bytes are pinned for the whole run.
_SUPPORT_MODULES = ("antirea.script_app_integration", "antirea.jvm_app_integration",
                    "antirea.process")
# Accepted producer backends per language (mirrors the root service).
_BACKENDS = {
    "python": {"python_vm", "python_mixed_module_vm"},
    "javascript": {"javascript_vm", "javascript_mixed_module_vm"},
    "typescript": {"javascript_vm", "javascript_mixed_module_vm"},
}
_PRODUCER_EXT = {"python": ".py", "javascript": ".cjs", "typescript": ".cjs"}

# Suffix allowlists. Spec-source allows the language's authoring sources + data;
# runtime trees (file_maps/bundle) are post-transpile (no original .ts). The
# selected protected source carries the authoring suffix.
_SPEC_SOURCE_SUFFIXES = {
    "python": {".py", ".json", ".txt"},
    "javascript": {".js", ".cjs", ".json", ".txt"},
    "typescript": {".ts", ".js", ".cjs", ".json", ".txt"},
}
_RUNTIME_SUFFIXES = {
    "python": {".py", ".json", ".txt"},
    "javascript": {".js", ".cjs", ".json", ".txt"},
    "typescript": {".js", ".cjs", ".json", ".txt"},
}
_ENTRYPOINT_SUFFIXES = {
    "python": {".py"},
    "javascript": {".js", ".cjs"},
    "typescript": {".ts", ".js", ".cjs"},
}
_PROTECTED_SOURCE_SUFFIXES = {
    "python": {".py"},
    "javascript": {".js", ".cjs"},
    "typescript": {".ts"},
}
# Always-rejected names (TS declaration/JSX/ESM + any source map), checked on the
# full lowercased filename (``.d.ts`` is two suffixes).
_REJECT_NAME_SUFFIXES = (".d.ts", ".tsx", ".mjs", ".map")
_BAD_DIR_COMPONENTS = frozenset({"__pycache__", "node_modules"})
# Windows reserved device base names (rejected case-insensitively, with or without
# an extension) so a relative path can never resolve to a DOS device.
_DOS_DEVICES = frozenset({"con", "prn", "aux", "nul",
                          *("com%d" % i for i in range(1, 10)),
                          *("lpt%d" % i for i in range(1, 10))})

MAX_APPLICATION_FILES = 128           # explicit spec application_files entries
MAX_TREE_ENTRIES = 4096               # entries in a single staged runtime tree
MAX_TREE_BYTES = 64 * 1024 * 1024     # total bytes in a single staged runtime tree
MAX_FILE_BYTES = 16 * 1024 * 1024     # a single staged runtime file
MAX_TOOL_BYTES = 512 * 1024 * 1024    # a pinned interpreter/compiler/artifact
MAX_STDOUT_LOG_BYTES = 1024 * 1024    # bounded read of a captured stdout/stderr log
MAX_PREP_RECEIPTS = 64                # adapter preparation_commands entries

# Application-samples bounds (identical to native_application).
MAX_CASES = 64
MAX_CASE_ARGS = 16
MAX_ARG_LEN = 256
MAX_LABEL_LEN = 128
MAX_STDOUT_LEN = 4096

_HEX = re.compile(r"[0-9a-f]{64}\Z")

_SPEC_KEYS = frozenset({"schema_version", "kind", "language", "protected_source",
                        "entrypoint", "application_files"})
_CONTRACT_KEYS = frozenset({"schema_version", "kind", "cases"})
_CASE_KEYS = frozenset({"label", "args", "expect"})
_EXPECT_KEYS = frozenset({"returncode", "stdout"})
_ADAPTER_RETURN_KEYS = frozenset({
    "language", "original_root", "protected_root", "runtime_entrypoint",
    "protected_relative", "preparation_commands", "file_maps", "protected_sha256",
    "original_core_sha256", "reference_evidence", "limitations"})


class ScriptIntegrateError(ValueError):
    """Any producer/spec/contract/identity/staging/execution inconsistency (fail closed)."""


# --------------------------------------------------------------------------- #
# Small shared helpers (reuse the audited jvm_app_integration byte primitives).
# --------------------------------------------------------------------------- #
def _sc(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except safe.JvmIntegrateError as exc:
        raise ScriptIntegrateError(str(exc)) from exc


def _relative(value) -> str:
    """Normalize+validate a clean in-tree relative slash path (pure, no disk).

    Rejects empty/whitespace, backslash/drive, NUL, absolute, ``.``/``..`` and any
    reserved/received path component, case-insensitively, before any filesystem use.
    """
    if (not isinstance(value, str) or not value or value != value.strip()
            or "\\" in value or ":" in value):
        raise ScriptIntegrateError("expected a clean relative slash path: %r" % (value,))
    if any(ord(ch) < 32 for ch in value):
        raise ScriptIntegrateError("relative path contains a control character: %r" % (value,))
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ScriptIntegrateError("relative path is absolute or not canonical: %r" % (value,))
    for part in parts:
        folded = part.casefold()
        if folded in safe.RESERVED_PATH_COMPONENTS:
            raise ScriptIntegrateError("relative path traverses a reserved component %r" % (part,))
        if folded in _BAD_DIR_COMPONENTS:
            raise ScriptIntegrateError("relative path traverses a forbidden directory %r" % (part,))
        if part != part.rstrip(" .") or part.startswith(" "):
            raise ScriptIntegrateError("relative path component has a trailing/leading space or dot: %r" % (part,))
        if folded.split(".", 1)[0] in _DOS_DEVICES:
            raise ScriptIntegrateError("relative path component is a reserved DOS device: %r" % (part,))
    return "/".join(parts)


def _suffix(relative: str) -> str:
    name = relative.rsplit("/", 1)[-1].lower()
    return ("." + name.rsplit(".", 1)[-1]) if "." in name else ""


def _reject_bad_name(relative: str) -> None:
    name = relative.rsplit("/", 1)[-1].lower()
    for bad in _REJECT_NAME_SUFFIXES:
        if name.endswith(bad):
            raise ScriptIntegrateError("rejected declaration/JSX/ESM/source-map file: " + relative)


def _rehash(path) -> str:
    return _sc(safe._hash_file, path, limit=MAX_TOOL_BYTES)


def _pin_or_check(pins: dict, path: str, sha: str) -> None:
    """Record a pin, or -- if the path is already pinned -- require the hashes agree.

    Never silently overwrites an existing (e.g. planning-time) pin: a disagreement is
    drift and fails closed before the module/bootstrap is imported or executed.
    """
    existing = pins.get(path)
    if existing is not None and existing != sha:
        raise ScriptIntegrateError("pinned input disagrees with an earlier pin: " + path)
    pins[path] = sha


def _normalize_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _write_report(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=True, allow_nan=False, sort_keys=True)
        stream.write("\n")


# --------------------------------------------------------------------------- #
# Public structural validators (pure; the root service calls these directly).
# --------------------------------------------------------------------------- #
def validate_spec(spec) -> dict:
    """Validate the strict script integration spec and return a normalized copy.

    Exact keys ``schema_version``=1, ``kind``=script_application_integration,
    ``language`` in python|javascript|typescript, ``protected_source`` (relative
    original selected source), ``entrypoint`` (relative ordinary owned app source)
    and ``application_files`` (1..128 explicit relative files). ``application_files``
    MUST include both ``protected_source`` and ``entrypoint``; ``entrypoint`` MUST
    differ from ``protected_source`` so an ordinary caller is actually integrated.
    Duplicates (case-folded), transpile-output collisions, absolute/traversal/
    reserved paths and wrong/declaration/JSX/ESM/source-map suffixes are rejected.
    Pure structural validation; nothing is read from disk here.
    """
    if not isinstance(spec, dict):
        raise ScriptIntegrateError("integration spec must be a JSON object")
    extra, missing = set(spec) - _SPEC_KEYS, _SPEC_KEYS - set(spec)
    if extra:
        raise ScriptIntegrateError("integration spec has unsupported key(s): " + ", ".join(sorted(extra)))
    if missing:
        raise ScriptIntegrateError("integration spec missing key(s): " + ", ".join(sorted(missing)))
    if type(spec["schema_version"]) is not int or spec["schema_version"] != 1:
        raise ScriptIntegrateError("integration spec schema_version must be 1")
    if spec["kind"] != SPEC_KIND:
        raise ScriptIntegrateError("integration spec kind must be %r" % SPEC_KIND)
    language = spec["language"]
    if not isinstance(language, str) or language not in _ADAPTER_MODULES:
        raise ScriptIntegrateError("integration spec language must be python|javascript|typescript")

    protected_source = _relative(spec["protected_source"])
    if _suffix(protected_source) not in _PROTECTED_SOURCE_SUFFIXES[language]:
        raise ScriptIntegrateError("protected_source suffix is not valid for " + language)
    _reject_bad_name(protected_source)
    entrypoint = _relative(spec["entrypoint"])
    if _suffix(entrypoint) not in _ENTRYPOINT_SUFFIXES[language]:
        raise ScriptIntegrateError("entrypoint suffix is not a runnable source for " + language)
    _reject_bad_name(entrypoint)
    if entrypoint == protected_source:
        raise ScriptIntegrateError("entrypoint must differ from protected_source")

    files = spec["application_files"]
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_APPLICATION_FILES:
        raise ScriptIntegrateError("application_files must list 1..%d files" % MAX_APPLICATION_FILES)
    normalized, seen, outputs = [], set(), set()
    for raw in files:
        rel = _relative(raw)
        _reject_bad_name(rel)
        if _suffix(rel) not in _SPEC_SOURCE_SUFFIXES[language]:
            raise ScriptIntegrateError("application file has an unsupported suffix: " + rel)
        key = rel.casefold()
        if key in seen:
            raise ScriptIntegrateError("duplicate application file (case-insensitive): " + rel)
        seen.add(key)
        # TypeScript ``.ts`` sources are transpiled to ``.js``; detect output
        # collisions with an explicitly listed ``.js`` of the same stem.
        output = rel[:-3] + ".js" if (language == "typescript" and _suffix(rel) == ".ts") else rel
        okey = output.casefold()
        if okey in outputs:
            raise ScriptIntegrateError("transpile/runtime output collision for: " + rel)
        outputs.add(okey)
        normalized.append(rel)
    normset = set(normalized)
    if protected_source not in normset:
        raise ScriptIntegrateError("application_files must include the protected_source")
    if entrypoint not in normset:
        raise ScriptIntegrateError("application_files must include the entrypoint")
    return {"schema_version": 1, "kind": SPEC_KIND, "language": language,
            "protected_source": protected_source, "entrypoint": entrypoint,
            "application_files": normalized}


def validate_contract(contract) -> list:
    """Validate the explicit application-samples contract and return its cases.

    Exact keys ``schema_version``=1, ``kind``=script_application_samples,
    ``cases`` (1..64). Every case has exact keys label/args/expect, a non-empty
    printable label <=128 chars (unique), <=16 argv strings of <=256 chars with no
    NUL/control bytes, and ``expect`` with an explicit integer returncode and a
    <=4096 char stdout (newline/tab allowed, no other control bytes). At least one
    case must declare a successful (returncode==0) run. Nothing is executed.
    """
    if not isinstance(contract, dict):
        raise ScriptIntegrateError("application contract must be a JSON object")
    extra, missing = set(contract) - _CONTRACT_KEYS, _CONTRACT_KEYS - set(contract)
    if extra:
        raise ScriptIntegrateError("application contract has unsupported key(s): " + ", ".join(sorted(extra)))
    if missing:
        raise ScriptIntegrateError("application contract missing key(s): " + ", ".join(sorted(missing)))
    if type(contract["schema_version"]) is not int or contract["schema_version"] != 1:
        raise ScriptIntegrateError("application contract schema_version must be 1")
    if contract["kind"] != CONTRACT_KIND:
        raise ScriptIntegrateError("application contract kind must be %r" % CONTRACT_KIND)
    cases = contract["cases"]
    if not isinstance(cases, list) or not cases:
        raise ScriptIntegrateError("application contract cases must be a non-empty list")
    if len(cases) > MAX_CASES:
        raise ScriptIntegrateError("too many cases (max %d)" % MAX_CASES)
    out, labels, has_success = [], set(), False
    for idx, case in enumerate(cases):
        if not isinstance(case, dict) or set(case) != _CASE_KEYS:
            raise ScriptIntegrateError("case %d must contain exactly label, args, expect" % idx)
        label = case["label"]
        if not isinstance(label, str) or not label or len(label) > MAX_LABEL_LEN:
            raise ScriptIntegrateError("case %d label must be a non-empty string <= %d chars" % (idx, MAX_LABEL_LEN))
        if any(ord(ch) < 32 for ch in label):
            raise ScriptIntegrateError("case %d label contains a control character" % idx)
        if label in labels:
            raise ScriptIntegrateError("duplicate case label: " + label)
        labels.add(label)
        args = case["args"]
        if not isinstance(args, list) or len(args) > MAX_CASE_ARGS:
            raise ScriptIntegrateError("case %r args must be a list of 0..%d strings" % (label, MAX_CASE_ARGS))
        norm_args = []
        for a in args:
            if isinstance(a, bool) or not isinstance(a, str):
                raise ScriptIntegrateError("case %r args must be strings (process argv)" % label)
            if len(a) > MAX_ARG_LEN:
                raise ScriptIntegrateError("case %r argument exceeds %d chars" % (label, MAX_ARG_LEN))
            if any(ord(ch) < 32 for ch in a):
                raise ScriptIntegrateError("case %r argument contains a NUL/control character" % label)
            norm_args.append(a)
        expect = case["expect"]
        if not isinstance(expect, dict) or set(expect) != _EXPECT_KEYS:
            raise ScriptIntegrateError("case %r expect must contain exactly returncode, stdout" % label)
        rc = expect["returncode"]
        if isinstance(rc, bool) or not isinstance(rc, int):
            raise ScriptIntegrateError("case %r expect.returncode must be an int" % label)
        stdout = expect["stdout"]
        if not isinstance(stdout, str) or len(stdout) > MAX_STDOUT_LEN:
            raise ScriptIntegrateError("case %r expect.stdout must be a string <= %d chars" % (label, MAX_STDOUT_LEN))
        if any(ord(ch) < 32 and ch not in "\t\n\r" for ch in stdout):
            raise ScriptIntegrateError("case %r expect.stdout contains a disallowed control character" % label)
        if rc == 0:
            has_success = True
        out.append({"label": label, "args": norm_args, "expect": {"returncode": rc, "stdout": stdout}})
    if not has_success:
        raise ScriptIntegrateError("at least one case must declare a successful (returncode==0) run")
    return out


def _select_control_case(cases: list) -> dict:
    for case in cases:
        if case["expect"]["returncode"] == 0:
            return case
    raise ScriptIntegrateError("no successful control case available")


# --------------------------------------------------------------------------- #
# Producer binding + tool/adapter pinning.
# --------------------------------------------------------------------------- #
def _bind_producer(producer, language: str, pins: dict) -> dict:
    """Re-hash the reused baseline/protected artifacts from disk; never repin."""
    if not isinstance(producer, dict):
        raise ScriptIntegrateError("producer must be the saved build/report object")
    if producer.get("backend") not in _BACKENDS[language]:
        raise ScriptIntegrateError("producer backend is not a %s script producer" % language)
    if producer.get("status") != PRODUCER_OK_STATUS:
        raise ScriptIntegrateError("producer status must be %r" % PRODUCER_OK_STATUS)
    project = producer.get("project")
    if not isinstance(project, dict) or project.get("language") != language:
        raise ScriptIntegrateError("producer project identity disagrees with the language")
    source_sha = project.get("source_sha256")
    if not isinstance(source_sha, str) or not _HEX.fullmatch(source_sha):
        raise ScriptIntegrateError("producer project is missing a valid original source hash")
    artifacts = producer.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != {"baseline", "protected"}:
        raise ScriptIntegrateError("producer must identify exactly baseline and protected artifacts")
    ext = _PRODUCER_EXT[language]
    pinned = {}
    for arm in ("baseline", "protected"):
        item = artifacts[arm]
        if not isinstance(item, dict):
            raise ScriptIntegrateError("malformed producer artifact: " + arm)
        sha = item.get("sha256")
        if not isinstance(sha, str) or not _HEX.fullmatch(sha):
            raise ScriptIntegrateError("producer %s artifact hash must be a lowercase sha256" % arm)
        path = _sc(safe._no_links, Path(os.path.abspath(item.get("path") or "")))
        if path.suffix.lower() != ext or not path.is_file():
            raise ScriptIntegrateError("producer %s artifact missing or wrong type" % arm)
        actual = _rehash(path)
        if actual != sha:
            raise ScriptIntegrateError("producer %s artifact bytes do not match the saved hash" % arm)
        if type(item.get("bytes")) is not int or item["bytes"] != path.stat().st_size:
            raise ScriptIntegrateError("producer %s artifact byte count disagrees with disk" % arm)
        pins[str(path)] = actual
        pinned[arm] = {"path": str(path), "sha256": actual, "bytes": item["bytes"]}
    if pinned["baseline"]["sha256"] == pinned["protected"]["sha256"]:
        raise ScriptIntegrateError("baseline and protected artifacts are byte-identical (no protection applied)")
    coverage = producer.get("coverage")
    if not isinstance(coverage, dict):
        raise ScriptIntegrateError("producer coverage evidence is missing")
    hardening = coverage.get("runtime_hardening")
    if not isinstance(hardening, dict) or hardening.get("external_resistance") != "not_evaluated":
        raise ScriptIntegrateError("producer runtime hardening evidence is missing or overclaims resistance")
    return {"backend": producer["backend"], "baseline": pinned["baseline"],
            "protected": pinned["protected"], "original_source_sha256": source_sha,
            "coverage_path": producer.get("coverage_path")}


def _pin_tools(tools, language: str, pins: dict) -> dict:
    """Re-hash every supplied interpreter/compiler pin; require the applicable ones."""
    if not isinstance(tools, dict) or not tools:
        raise ScriptIntegrateError("tools must be a non-empty mapping of pinned executables")
    resolved = {}
    for role, item in tools.items():
        if role not in ("python_executable", "node", "typescript"):
            raise ScriptIntegrateError("unsupported tool role: " + str(role))
        if not isinstance(item, dict) or set(item) - {"path", "sha256"} or "path" not in item or "sha256" not in item:
            raise ScriptIntegrateError("tool %r must be {path, sha256}" % role)
        sha = item["sha256"]
        if not isinstance(sha, str) or not _HEX.fullmatch(sha):
            raise ScriptIntegrateError("tool %r sha256 must be a lowercase 64-hex digest" % role)
        path = _sc(safe._no_links, Path(os.path.abspath(item["path"])))
        if not path.is_file():
            raise ScriptIntegrateError("tool %r is missing on disk" % role)
        actual = _rehash(path)
        if actual != sha:
            raise ScriptIntegrateError("tool %r changed on disk since it was pinned" % role)
        pins[str(path)] = actual
        resolved[role] = {"path": str(path), "sha256": actual}
    required = {"python": ("python_executable",), "javascript": ("node",),
                "typescript": ("node", "typescript")}[language]
    for role in required:
        if role not in resolved:
            raise ScriptIntegrateError("missing required %s tool pin: %s" % (language, role))
    return resolved


def _pin_support_modules(adapter_name: str, pins: dict) -> dict:
    """Locate+hash each trusted module source WITHOUT importing the leaf, binding it
    against any earlier (planning-time) pin rather than overwriting possible drift."""
    binding = {}
    for name in (*_SUPPORT_MODULES, adapter_name):
        source = _sc(safe._locate_module_source, name)
        sha = _rehash(source)
        _pin_or_check(pins, str(source), sha)
        binding[name] = {"path": str(source), "sha256": sha}
    return binding


def _load_adapter(language: str, pins: dict):
    """Load the trusted language adapter BY NAME only and confirm its API.

    The source is located+hashed through ``find_spec`` (the leaf is not imported to
    hash it) and bound against any earlier (planning-time) pin BEFORE the leaf is
    imported, so a drifted adapter is never executed. A caller-supplied module path
    is never honored. This is a seam so authored tests can inject a staging double
    without executing anything.
    """
    name = _ADAPTER_MODULES[language]
    source = _sc(safe._locate_module_source, name)
    sha = _rehash(source)
    _pin_or_check(pins, str(source), sha)
    module = importlib.import_module(name)
    if not hasattr(module, "prepare_application"):
        raise ScriptIntegrateError("trusted adapter %s lacks prepare_application" % name)
    return {"name": name, "path": str(source), "sha256": sha, "module": module}


# --------------------------------------------------------------------------- #
# Staging verification + runtime-tree helpers.
# --------------------------------------------------------------------------- #
def _check_file_map(file_map, language: str, label: str) -> None:
    if not isinstance(file_map, dict) or not 1 <= len(file_map) <= MAX_TREE_ENTRIES:
        raise ScriptIntegrateError("%s file_map must be a 1..%d entry mapping" % (label, MAX_TREE_ENTRIES))
    for rel, sha in file_map.items():
        if _relative(rel) != rel:
            raise ScriptIntegrateError("%s file_map key is not a normalized relative path: %r" % (label, rel))
        if not isinstance(sha, str) or not _HEX.fullmatch(sha):
            raise ScriptIntegrateError("%s file_map value is not a lowercase sha256: %r" % (label, rel))
        _reject_bad_name(rel)
        if _suffix(rel) not in _RUNTIME_SUFFIXES[language]:
            raise ScriptIntegrateError("%s file_map holds a non-runtime file: %s" % (label, rel))


def _verify_root(root, file_map, staging_dir: Path, language: str, label: str) -> Path:
    _check_file_map(file_map, language, label)
    resolved = _sc(safe._no_links, Path(os.path.abspath(root)))
    if not resolved.is_relative_to(staging_dir) or resolved == staging_dir or not resolved.is_dir():
        raise ScriptIntegrateError("%s root is not a dedicated directory under the adapter output" % label)
    inventory = _sc(safe._tree_inventory, resolved)
    if len(inventory) > MAX_TREE_ENTRIES:
        raise ScriptIntegrateError("%s root exceeds the bounded entry count" % label)
    total = 0
    for entry in inventory.values():
        if entry["bytes"] > MAX_FILE_BYTES:
            raise ScriptIntegrateError("%s root holds a file over the bounded size" % label)
        total += entry["bytes"]
    if total > MAX_TREE_BYTES:
        raise ScriptIntegrateError("%s root exceeds the bounded total bytes" % label)
    if {rel: entry["sha256"] for rel, entry in inventory.items()} != file_map:
        raise ScriptIntegrateError("%s root inventory disagrees with the returned file_map" % label)
    return resolved


def _copy_runtime_tree(src_root: Path, dst_root: Path, file_map: dict) -> None:
    """Explicit per-file copy (never an implicit tree copy) with hash re-check."""
    dst_root.mkdir()
    for rel, sha in sorted(file_map.items()):
        src = _sc(safe._no_links, src_root / rel)
        data = _sc(safe._read_bytes_bounded, src, limit=MAX_FILE_BYTES)
        if hashlib.sha256(data).hexdigest() != sha:
            raise ScriptIntegrateError("source changed before copy: " + rel)
        dst = _sc(safe._no_links, dst_root / rel)
        dst.parent.mkdir(parents=True, exist_ok=True)
        with dst.open("xb") as stream:
            stream.write(data)
        if _rehash(dst) != sha:
            raise ScriptIntegrateError("copied file hash mismatch: " + rel)


def _verify_prep_receipt(entry, staging_dir: Path, seen: set) -> dict:
    if not isinstance(entry, dict):
        raise ScriptIntegrateError("preparation command receipt must be an object")
    for key in ("receipt_path", "receipt_sha256", "stdout_log", "stderr_log", "label", "kind"):
        if not isinstance(entry.get(key), str) or not entry[key]:
            raise ScriptIntegrateError("preparation receipt missing key: " + key)
    receipt = _sc(safe._no_links, Path(os.path.abspath(entry["receipt_path"])))
    if not receipt.is_relative_to(staging_dir):
        raise ScriptIntegrateError("preparation receipt escaped the adapter output")
    data = _sc(safe._read_bytes_bounded, receipt, limit=MAX_STDOUT_LOG_BYTES)
    if hashlib.sha256(data).hexdigest() != entry["receipt_sha256"]:
        raise ScriptIntegrateError("preparation receipt bytes disagree with the recorded hash")
    parsed = json.loads(data.decode("utf-8"))
    if not safe._strict_receipt_clean(parsed) or parsed.get("returncode") != 0:
        raise ScriptIntegrateError("preparation child did not exit cleanly with returncode 0")
    for logkey, rawkey in (("stdout_log", "stdout"), ("stderr_log", "stderr")):
        logp = _sc(safe._no_links, Path(os.path.abspath(entry[logkey])))
        if str(logp) != str(_sc(safe._no_links, Path(os.path.abspath(parsed.get(rawkey) or "")))):
            raise ScriptIntegrateError("preparation log path disagrees with the receipt")
        if not logp.is_relative_to(staging_dir) or not logp.is_file():
            raise ScriptIntegrateError("preparation log is missing or escaped the adapter output")
    for key in ("receipt_path", "stdout_log", "stderr_log"):
        norm = os.path.normcase(str(_sc(safe._no_links, Path(os.path.abspath(entry[key])))))
        if norm in seen:
            raise ScriptIntegrateError("duplicated preparation evidence reference")
        seen.add(norm)
    return {"receipt_path": entry["receipt_path"], "receipt_sha256": entry["receipt_sha256"],
            "stdout_log": entry["stdout_log"], "stderr_log": entry["stderr_log"],
            "label": entry.get("label"), "kind": entry.get("kind"), "returncode": 0}


# --------------------------------------------------------------------------- #
# Child-process env + argv.
# --------------------------------------------------------------------------- #
def _clean_env(exec_dir: Path, exe: str, language: str) -> dict:
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    exe_dir = str(Path(exe).parent)
    priv_tmp, priv_home = safe._private_dirs(exec_dir)
    env = {
        "SystemRoot": sysroot, "windir": sysroot, "SystemDrive": "C:",
        "COMSPEC": str(Path(sysroot) / "System32" / "cmd.exe"),
        "PATHEXT": ".COM;.EXE;.BAT;.CMD",
        "PATH": os.pathsep.join([exe_dir, sysroot + r"\System32", sysroot]),
        "TEMP": str(priv_tmp), "TMP": str(priv_tmp), "USERPROFILE": str(priv_home),
        "APPDATA": str(priv_home / "AppData" / "Roaming"),
        "LOCALAPPDATA": str(priv_home / "AppData" / "Local"),
        "PROCESSOR_ARCHITECTURE": os.environ.get("PROCESSOR_ARCHITECTURE", "AMD64"),
    }
    if language == "python":
        # Isolated interpreter (-I/-S in argv) plus no bytecode so a run never mutates
        # the staged tree with __pycache__ (which the deploy bundle forbids).
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONNOUSERSITE"] = "1"
        env["PYTHONUTF8"] = "1"
    return env


_DOTTED_MODULE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z")
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def _derive_python_module(runtime_entrypoint: str, file_map: dict) -> str:
    """Derive the dotted module from the .py entry and the explicit __init__.py chain.

    Mirrors the adapter's derivation and NEVER trusts an adapter-supplied module name:
    every directory on the way to the entry must hold an explicit ``__init__.py`` in
    the staged file map, and the module is run from the tree root on ``sys.path``.
    """
    parts = runtime_entrypoint.split("/")
    stem = parts[-1]
    if not stem.endswith(".py"):
        raise ScriptIntegrateError("python runtime entrypoint must be a .py source")
    names = [*parts[:-1], stem[:-len(".py")]]
    if any(not _IDENTIFIER.match(name) for name in names):
        raise ScriptIntegrateError("python entry path does not form valid module identifiers")
    prefix = []
    for name in parts[:-1]:
        prefix.append(name)
        if "/".join([*prefix, "__init__.py"]) not in file_map:
            raise ScriptIntegrateError("package %r is missing its explicit __init__.py" % "/".join(prefix))
    return ".".join(names)


# --------------------------------------------------------------------------- #
# Pin re-verification (STOP + every bound input) around every child process.
# --------------------------------------------------------------------------- #
def _verify_pins(pins: dict, stop) -> None:
    """Re-check STOP and re-hash EVERY bound input from disk (fail closed).

    No input (including the pinned interpreters/compilers) is exempted: the agreed
    source/tool/hash checks run in full around every child process. The overall
    monotonic deadline -- not any skipped hashing -- bounds total runtime.
    """
    safe._check_stop(stop, None, "integration")
    for path, sha in pins.items():
        if _rehash(path) != sha:
            raise ScriptIntegrateError("pinned input changed on disk: " + str(path))


# --------------------------------------------------------------------------- #
# Common orchestration.
# --------------------------------------------------------------------------- #
def run_integration(*, language, source_root, input_files, producer, spec, contract,
                    output_dir, tools, trusted_inputs, timeout_seconds=120, stop_file) -> dict:
    """Stage via the trusted adapter, run the sample cases across original/protected/
    copied-deployment arms plus a missing-module control, and persist a parse-identical
    report. Workers author this logic only; the root service executes it after freeze
    and independently re-derives every result from the retained raw receipts.
    """
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
        raise ScriptIntegrateError("timeout_seconds must be an integer in 1..600")
    deadline = time.monotonic() + timeout_seconds
    if not isinstance(language, str) or language not in _ADAPTER_MODULES:
        raise ScriptIntegrateError("unsupported language: " + str(language))
    if os.name != "nt":
        raise ScriptIntegrateError("script application integration requires Windows Job receipts")
    source_root = _sc(safe._no_links, Path(os.path.abspath(source_root)))
    output = _sc(safe._no_links, Path(os.path.abspath(output_dir)))
    stop = Path(os.path.abspath(stop_file))
    if output.exists() or not output.parent.is_dir():
        raise ScriptIntegrateError("output_dir must be a fresh directory with an existing parent")
    if not isinstance(trusted_inputs, dict) or not isinstance(input_files, dict) or not input_files:
        raise ScriptIntegrateError("trusted_inputs and input_files must be mappings")
    safe._check_stop(stop, None, "preflight")

    spec = validate_spec(spec)
    if spec["language"] != language:
        raise ScriptIntegrateError("spec language disagrees with the requested language")
    cases = validate_contract(contract)
    control_case = _select_control_case(cases)

    pins = {}
    for raw, sha in trusted_inputs.items():
        if not isinstance(raw, str) or not isinstance(sha, str) or not _HEX.fullmatch(sha):
            raise ScriptIntegrateError("trusted_inputs must map absolute paths to lowercase sha256")
        path = _sc(safe._no_links, Path(os.path.abspath(raw)))
        if _rehash(path) != sha:
            raise ScriptIntegrateError("trusted input changed on disk: " + str(path))
        pins[str(path)] = sha

    # Bind each explicit application file from the fingerprinted plan snapshot.
    if set(input_files) != set(spec["application_files"]):
        raise ScriptIntegrateError("input_files do not match the spec application_files")
    for rel, sha in input_files.items():
        if _relative(rel) != rel or not isinstance(sha, str) or not _HEX.fullmatch(sha):
            raise ScriptIntegrateError("input_files entry is malformed: " + str(rel))
        path = _sc(safe._no_links, source_root / rel)
        if not path.is_relative_to(source_root) or not path.is_file():
            raise ScriptIntegrateError("application file is missing from the source tree: " + rel)
        if _rehash(path) != sha:
            raise ScriptIntegrateError("application file changed from the saved snapshot: " + rel)
        pins.setdefault(str(path), sha)

    bound_producer = _bind_producer(producer, language, pins)
    resolved_tools = _pin_tools(tools, language, pins)
    adapter = _load_adapter(language, pins)
    support = _pin_support_modules(adapter["name"], pins)
    _verify_pins(pins, stop)

    output.mkdir()
    staging_dir = output / "staging"
    exec_dir = output / "execution"
    exec_dir.mkdir()
    logs_dir = exec_dir / "logs"
    run_exe = resolved_tools["python_executable"]["path"] if language == "python" else resolved_tools["node"]["path"]

    result = {
        "schema_version": SCHEMA_VERSION, "kind": SPEC_KIND, "status": "failed",
        "language": language, "fresh_protected_build": False, "reused_protected_artifact": True,
        "timeout_seconds": timeout_seconds,
        "producer": {"backend": bound_producer["backend"], "baseline": bound_producer["baseline"],
                     "protected": bound_producer["protected"],
                     "coverage_path": bound_producer["coverage_path"],
                     "original_source_sha256": bound_producer["original_source_sha256"]},
        "support_modules": support, "adapter": {k: adapter[k] for k in ("name", "path", "sha256")},
        "staging": {}, "deployment": {},
        "comparison": {"status": "failed", "arms": ["original", "protected", "deployment"],
                       "commands": [], "cases": [], "controls": []},
        "trusted_inputs_verification": {"declared_count": len(trusted_inputs), "preflight_verified": True,
                                        "postflight_verified": False},
        "external_resistance": "not_evaluated", "performance_acceptance": "not_evaluated",
        "whole_application_verified": False, "published": False,
    }
    seen = set()
    ordinal = 0
    run_ctx = {}

    def remaining():
        left = deadline - time.monotonic()
        if left < 1:
            raise ScriptIntegrateError("overall integration execution deadline exceeded")
        return min(int(left), timeout_seconds)

    def child(argv, cwd, env, meta):
        nonlocal ordinal
        _verify_pins(pins, stop)
        ordinal += 1
        prefix = logs_dir / ("%03d" % ordinal)
        proc = process.run_logged([str(x) for x in argv], cwd, prefix, remaining(),
                                  env=env, cancel_file=stop)
        record = _sc(safe._persisted_receipt, proc, prefix)
        if proc != record["parsed"]:
            raise ScriptIntegrateError("returned and persisted child receipts differ")
        if not safe._strict_receipt_clean(record["parsed"]):
            raise ScriptIntegrateError("child receipt is unclean/timed-out/cancelled")
        for key in ("receipt_path", "stdout_log", "stderr_log"):
            path = _sc(safe._no_links, Path(os.path.abspath(record[key])))
            if not path.is_relative_to(logs_dir):
                raise ScriptIntegrateError("child evidence escaped its log directory")
            norm = os.path.normcase(str(path))
            if norm in seen:
                raise ScriptIntegrateError("duplicated child evidence reference")
            seen.add(norm)
            pins[record[key]] = _rehash(record[key])
        _verify_pins(pins, stop)
        raw = _sc(safe._read_bytes_bounded, record["stdout_log"], limit=MAX_STDOUT_LOG_BYTES)
        _sc(safe._read_bytes_bounded, record["stderr_log"], limit=MAX_STDOUT_LOG_BYTES)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = None
        normalized = _normalize_newlines(text) if text is not None else None
        command = {"label": meta["label"], "kind": meta["kind"], "arm": meta.get("arm"),
                   "case_label": meta.get("case_label"), "control": meta.get("control"),
                   "argv": [str(x) for x in argv], "returncode": proc["returncode"],
                   "receipt_path": record["receipt_path"], "receipt_sha256": record["receipt_sha256"],
                   "stdout_log": record["stdout_log"], "stderr_log": record["stderr_log"],
                   "stdout_sha256": hashlib.sha256(raw).hexdigest(), "stdout_bytes": len(raw)}
        result["comparison"]["commands"].append(command)
        preview = normalized if (normalized is not None and len(normalized) <= MAX_STDOUT_LEN) else None
        return {"returncode": proc["returncode"], "stdout": normalized, "stdout_preview": preview,
                "stdout_sha256": command["stdout_sha256"], "stdout_bytes": len(raw)}

    def run_arm(root, case, meta):
        where = meta.get("arm") or "copy"
        if language == "python":
            # Fixed trusted runpy bootstrap: stage_root + dotted module + case args are
            # passed as SEPARATE argv, never interpolated into program source. -S keeps
            # site/packages isolation; -B avoids writing __pycache__ into the tree.
            argv = [run_exe, "-I", "-S", "-B", run_ctx["bootstrap"], str(root),
                    run_ctx["module"], *case["args"]]
        else:
            entry = _sc(safe._no_links, root / runtime_entrypoint)
            if not entry.is_relative_to(root) or not entry.is_file():
                raise ScriptIntegrateError("runtime entrypoint missing in " + where)
            argv = [run_exe, "--no-addons", str(entry), *case["args"]]
        return child(argv, root, _clean_env(exec_dir, run_exe, language), meta)

    try:
        staging = adapter["module"].prepare_application(
            source_root=source_root, input_files=dict(input_files),
            protected_source=spec["protected_source"], entrypoint=spec["entrypoint"],
            producer=producer, output_dir=staging_dir, tools=resolved_tools,
            trusted_inputs=dict(trusted_inputs), timeout_seconds=remaining(), stop_file=stop)
        if not isinstance(staging, dict) or set(staging) != _ADAPTER_RETURN_KEYS:
            raise ScriptIntegrateError("adapter return keys are not exactly the agreed contract")
        if staging["language"] != language:
            raise ScriptIntegrateError("adapter staged a different language")
        staging_resolved = _sc(safe._no_links, staging_dir)
        if not staging_resolved.is_dir():
            raise ScriptIntegrateError("adapter did not create its owned output directory")
        # The adapter persists a parse-identical preparation.json; bind the returned
        # dict to those on-disk bytes so a return that differs from what was persisted
        # (which root re-verifies independently) fails closed here too.
        prep_report = _sc(safe._no_links, staging_resolved / "preparation.json")
        prep_bytes = _sc(safe._read_bytes_bounded, prep_report, limit=MAX_FILE_BYTES)
        if json.loads(prep_bytes.decode("utf-8")) != staging:
            raise ScriptIntegrateError("adapter return differs from its persisted preparation.json")
        _pin_or_check(pins, str(prep_report), hashlib.sha256(prep_bytes).hexdigest())
        file_maps = staging["file_maps"]
        if not isinstance(file_maps, dict) or set(file_maps) != {"original", "protected"}:
            raise ScriptIntegrateError("adapter file_maps must be {original, protected}")
        runtime_entrypoint = _relative(staging["runtime_entrypoint"])
        protected_relative = _relative(staging["protected_relative"])
        protected_sha = staging["protected_sha256"]
        original_core_sha = staging["original_core_sha256"]
        for sha in (protected_sha, original_core_sha):
            if not isinstance(sha, str) or not _HEX.fullmatch(sha):
                raise ScriptIntegrateError("adapter core hashes must be lowercase sha256")
        if protected_sha == original_core_sha:
            raise ScriptIntegrateError("protected and original core are byte-identical")
        # The protected runtime core is the REUSED pinned producer protected artifact.
        if protected_sha != bound_producer["protected"]["sha256"]:
            raise ScriptIntegrateError("staged protected core is not the pinned producer protected artifact")

        original_root = _verify_root(staging["original_root"], file_maps["original"],
                                     staging_resolved, language, "original")
        protected_root = _verify_root(staging["protected_root"], file_maps["protected"],
                                      staging_resolved, language, "protected")
        if os.path.normcase(str(original_root)) == os.path.normcase(str(protected_root)):
            raise ScriptIntegrateError("adapter original and protected roots collide")

        # Both arms stage exactly the same file set and differ ONLY at the core module.
        if set(file_maps["original"]) != set(file_maps["protected"]):
            raise ScriptIntegrateError("original and protected arms stage different file sets")
        for rel in file_maps["original"]:
            if rel == protected_relative:
                continue
            if file_maps["original"][rel] != file_maps["protected"][rel]:
                raise ScriptIntegrateError("unselected runtime file differs between arms: " + rel)
        if runtime_entrypoint not in file_maps["original"]:
            raise ScriptIntegrateError("runtime entrypoint is not a staged runtime file")
        if runtime_entrypoint == protected_relative:
            raise ScriptIntegrateError("runtime entrypoint must differ from the protected module")
        code_suffixes = {".py"} if language == "python" else {".js", ".cjs"}
        if _suffix(runtime_entrypoint) not in code_suffixes:
            raise ScriptIntegrateError("runtime entrypoint is not a runnable module")
        if _suffix(protected_relative) not in code_suffixes:
            raise ScriptIntegrateError("protected module is not a runnable module")
        if file_maps["protected"][protected_relative] != protected_sha:
            raise ScriptIntegrateError("protected module is not at protected_relative in the protected arm")
        if file_maps["original"][protected_relative] != original_core_sha:
            raise ScriptIntegrateError("original core is not at protected_relative in the original arm")

        reference = staging["reference_evidence"]
        limitations = staging["limitations"]
        if not isinstance(reference, dict) or not isinstance(limitations, list):
            raise ScriptIntegrateError("adapter reference_evidence/limitations are malformed")

        # Verify the adapter's preparation (e.g. TS/pure-JS transpile) receipts first:
        # independent-reference backends are gated on at least one clean prep child.
        prep_seen, prep = set(), []
        prep_commands = staging["preparation_commands"]
        if not isinstance(prep_commands, list) or len(prep_commands) > MAX_PREP_RECEIPTS:
            raise ScriptIntegrateError("adapter preparation_commands is not a bounded list")
        for entry in prep_commands:
            record = _verify_prep_receipt(entry, staging_resolved, prep_seen)
            prep.append(record)
            _pin_or_check(pins, record["receipt_path"], record["receipt_sha256"])
            for logkey in ("stdout_log", "stderr_log"):
                _pin_or_check(pins, record[logkey], _rehash(record[logkey]))
        # Bind the independent-reference helper request/response payloads (exact stdin
        # etc.) when the adapter records them, so they cannot drift before app children.
        requests = reference.get("requests")
        if requests is not None:
            if not isinstance(requests, list) or len(requests) > MAX_PREP_RECEIPTS:
                raise ScriptIntegrateError("reference_evidence.requests must be a bounded list")
            for item in requests:
                if (not isinstance(item, dict) or not isinstance(item.get("path"), str)
                        or not isinstance(item.get("sha256"), str) or not _HEX.fullmatch(item["sha256"])):
                    raise ScriptIntegrateError("reference_evidence.requests entry needs a valid path+sha256")
                rpath = _sc(safe._no_links, Path(os.path.abspath(item["path"])))
                if not rpath.is_relative_to(staging_resolved) or not rpath.is_file():
                    raise ScriptIntegrateError("reference request payload escaped the adapter output")
                if _rehash(rpath) != item["sha256"]:
                    raise ScriptIntegrateError("reference request payload bytes disagree with the recorded hash")
                _pin_or_check(pins, str(rpath), item["sha256"])

        # original_core_sha256 is the STAGED ORIGINAL RUNTIME core -- NEVER the producer
        # baseline. Python (pure+mixed) and MIXED JavaScript preserve the raw original
        # selected source bytes. Pure JavaScript (export syntax the vm grammar cannot
        # require) and ALL TypeScript stage an INDEPENDENTLY compiled reference, bound by
        # its own prep receipts, not the raw input. The raw selected source never leaks
        # into the protected runtime for any backend.
        raw_source_sha = input_files[spec["protected_source"]]
        backend = bound_producer["backend"]
        raw_preserving = (language == "python"
                          or (language == "javascript" and backend == "javascript_mixed_module_vm"))
        if raw_source_sha in file_maps["protected"].values():
            raise ScriptIntegrateError("raw original selected source leaked into the protected runtime")
        if raw_preserving:
            if protected_relative != spec["protected_source"]:
                raise ScriptIntegrateError("protected module relative path must equal the protected_source")
            if original_core_sha != raw_source_sha:
                raise ScriptIntegrateError("original runtime core is not the raw original selected source")
            for rel, sha in input_files.items():
                if rel == spec["protected_source"]:
                    continue
                if file_maps["original"].get(rel) != sha:
                    raise ScriptIntegrateError("unselected application file was not byte-preserved: " + rel)
        else:
            if not reference:
                raise ScriptIntegrateError("independent-reference staging must record reference_evidence")
            if not prep:
                raise ScriptIntegrateError("independent-reference staging must record its compiler receipts")
            if raw_source_sha in file_maps["original"].values():
                raise ScriptIntegrateError("raw original selected source leaked into the original runtime")
            if language == "typescript" and (spec["protected_source"] in file_maps["protected"]
                                             or spec["protected_source"] in file_maps["original"]):
                raise ScriptIntegrateError("original TypeScript source leaked into a runtime tree")

        # Python executes a FIXED private runpy bootstrap (never packaged into the
        # staged tree) against the stage root + a dotted module, both bound here. The
        # adapter's ``RUNPY_BOOTSTRAP`` constant is the trusted bootstrap SOURCE: the
        # private bootstrap file's bytes must equal that source exactly, so the engine
        # runs the adapter's fixed code and not a caller-substituted script.
        if language == "python":
            module_exec = reference.get("module_execution")
            if not isinstance(module_exec, dict) or not isinstance(module_exec.get("module"), str):
                raise ScriptIntegrateError("python staging is missing module_execution.module")
            # DERIVE the dotted module from the entry + __init__.py chain; never trust
            # the adapter-supplied name. Cross-check it against the recorded one.
            module = _derive_python_module(runtime_entrypoint, file_maps["original"])
            if len(module) > 256 or not _DOTTED_MODULE.fullmatch(module):
                raise ScriptIntegrateError("derived python module is not a valid dotted module")
            if module != module_exec["module"]:
                raise ScriptIntegrateError("adapter module_execution.module disagrees with the derived module")
            bootstrap = reference.get("runpy_bootstrap")
            # runpy_bootstrap carries reviewed metadata extras (run_name/argv_contract/
            # flags...); require only a valid path + sha256 and accept the rest.
            if (not isinstance(bootstrap, dict) or not isinstance(bootstrap.get("path"), str)
                    or not isinstance(bootstrap.get("sha256"), str) or not _HEX.fullmatch(bootstrap["sha256"])):
                raise ScriptIntegrateError("python staging is missing a valid runpy_bootstrap path+sha256")
            declared = getattr(adapter["module"], "RUNPY_BOOTSTRAP", None)
            if not isinstance(declared, (str, bytes)) or not declared:
                raise ScriptIntegrateError("adapter does not expose a RUNPY_BOOTSTRAP source constant")
            declared_bytes = declared.encode("utf-8") if isinstance(declared, str) else declared
            declared_sha = hashlib.sha256(declared_bytes).hexdigest()
            # The bootstrap is the private adapter-owned staging/bootstrap.py (NOT inside
            # a runtime tree); its bytes must equal the trusted RUNPY_BOOTSTRAP source.
            bootstrap_path = _sc(safe._no_links, Path(os.path.abspath(bootstrap["path"])))
            if os.path.normcase(str(bootstrap_path)) != os.path.normcase(str(staging_resolved / "bootstrap.py")):
                raise ScriptIntegrateError("runpy bootstrap must be the private staging/bootstrap.py")
            if not bootstrap_path.is_file():
                raise ScriptIntegrateError("runpy bootstrap is missing on disk")
            file_bytes = _sc(safe._read_bytes_bounded, bootstrap_path, limit=MAX_FILE_BYTES)
            bootstrap_sha = hashlib.sha256(file_bytes).hexdigest()
            if bootstrap_sha != bootstrap["sha256"]:
                raise ScriptIntegrateError("runpy bootstrap changed from its recorded hash")
            if bootstrap_sha != declared_sha:
                raise ScriptIntegrateError("runpy bootstrap file is not the adapter's fixed trusted source")
            if bootstrap_sha in file_maps["protected"].values() or bootstrap_sha in file_maps["original"].values():
                raise ScriptIntegrateError("runpy bootstrap must not be packaged into a runtime tree")
            _pin_or_check(pins, str(bootstrap_path), bootstrap_sha)
            run_ctx.update(module=module, bootstrap=str(bootstrap_path))

        # Pin the staged runtime trees so any mid-run tamper is caught around EVERY child.
        for root_path, fm in ((original_root, file_maps["original"]), (protected_root, file_maps["protected"])):
            for rel, sha in fm.items():
                _pin_or_check(pins, str(_sc(safe._no_links, root_path / rel)), sha)

        result["staging"] = {
            "adapter": adapter["name"], "adapter_sha256": adapter["sha256"],
            "original_root": str(original_root), "protected_root": str(protected_root),
            "runtime_entrypoint": runtime_entrypoint, "protected_relative": protected_relative,
            "protected_sha256": protected_sha, "original_core_sha256": original_core_sha,
            "module": run_ctx.get("module"),
            "bootstrap": ({"path": run_ctx["bootstrap"], "sha256": pins[run_ctx["bootstrap"]]}
                          if run_ctx.get("bootstrap") else None),
            "file_maps": {"original": dict(file_maps["original"]), "protected": dict(file_maps["protected"])},
            "preparation_commands": prep, "reference_evidence": reference, "limitations": limitations,
        }

        # Independently copied relocatable deployment bundle (protected runtime only).
        bundle_root = output / "deployment"
        _copy_runtime_tree(protected_root, bundle_root, file_maps["protected"])
        bundle_inventory = _sc(safe._tree_inventory, bundle_root)
        if {rel: e["sha256"] for rel, e in bundle_inventory.items()} != file_maps["protected"]:
            raise ScriptIntegrateError("deployment bundle inventory disagrees with the protected arm")
        files = [{"relative_path": rel, "sha256": e["sha256"], "bytes": e["bytes"]}
                 for rel, e in sorted(bundle_inventory.items())]
        result["deployment"] = {"path": str(bundle_root), "files": files,
                                "allowlist": sorted(file_maps["protected"]),
                                "protected_module": protected_relative,
                                "runtime_entrypoint": runtime_entrypoint, "forbidden_absent": True}
        for rel, sha in file_maps["protected"].items():
            _pin_or_check(pins, str(_sc(safe._no_links, bundle_root / rel)), sha)

        _verify_pins(pins, stop)
        for case in cases:
            arms = {}
            for arm, root in (("original", original_root), ("protected", protected_root),
                              ("deployment", bundle_root)):
                arms[arm] = run_arm(root, case, {"label": "case:" + case["label"] + ":" + arm,
                                                 "kind": "case_arm", "arm": arm,
                                                 "case_label": case["label"], "control": None})
            expect_rc = case["expect"]["returncode"]
            expect_out = _normalize_newlines(case["expect"]["stdout"])
            match = all(a["returncode"] == expect_rc and a["stdout"] == expect_out for a in arms.values())
            result["comparison"]["cases"].append({
                "label": case["label"], "args": list(case["args"]), "expect": dict(case["expect"]),
                "results": {arm: {"returncode": a["returncode"], "stdout_sha256": a["stdout_sha256"],
                                  "stdout_bytes": a["stdout_bytes"], "stdout_preview": a["stdout_preview"]}
                            for arm, a in arms.items()},
                "match": match})
            if not match:
                raise ScriptIntegrateError("sample case did not match across all arms: " + case["label"])

        # Missing-protected-module control in a separate private copy: an exact copy of
        # the protected runtime with ONLY the protected module removed. The copy's files
        # are pinned (so drift during the control child is rejected) and its exact
        # inventory is verified before and after the run.
        control_root = output / "control"
        _copy_runtime_tree(protected_root, control_root, file_maps["protected"])
        removed = _sc(safe._no_links, control_root / protected_relative)
        removed.unlink()
        if removed.exists():
            raise ScriptIntegrateError("could not remove the protected module for the control")
        control_expected = {rel: sha for rel, sha in file_maps["protected"].items() if rel != protected_relative}
        control_inv = _sc(safe._tree_inventory, control_root)
        if {rel: e["sha256"] for rel, e in control_inv.items()} != control_expected:
            raise ScriptIntegrateError("control copy is not the protected runtime minus the protected module")
        control_pins = {}
        for rel, sha in control_expected.items():
            path = str(_sc(safe._no_links, control_root / rel))
            _pin_or_check(pins, path, sha)
            control_pins[path] = sha
        control_result = run_arm(control_root, control_case,
                                 {"label": "control:missing_protected_module", "kind": "control",
                                  "arm": None, "case_label": control_case["label"],
                                  "control": "missing_module"})
        control_after = _sc(safe._tree_inventory, control_root)
        if {rel: e["sha256"] for rel, e in control_after.items()} != control_expected:
            raise ScriptIntegrateError("control copy mutated during the control run")
        reproduced = (control_result["returncode"] == control_case["expect"]["returncode"]
                      and control_result["stdout"] == _normalize_newlines(control_case["expect"]["stdout"]))
        if reproduced or control_result["returncode"] == 0:
            raise ScriptIntegrateError("missing-module control did not fail the successful case")
        result["comparison"]["controls"].append({
            "label": "missing_protected_module", "control": "missing_module",
            "case_label": control_case["label"], "returncode": control_result["returncode"],
            "stdout_sha256": control_result["stdout_sha256"], "reproduced_success": False,
            "failed_as_required": True, "control_root": str(control_root),
            "removed_module": protected_relative,
            "inventory": [{"relative_path": r, "sha256": s} for r, s in sorted(control_expected.items())]})

        # Post-run integrity: the three staged trees are unchanged (no bytecode/side
        # files), every pin still holds, and STOP is not set.
        for root, fm, label in ((original_root, file_maps["original"], "original"),
                                (protected_root, file_maps["protected"], "protected"),
                                (bundle_root, file_maps["protected"], "deployment")):
            inv = _sc(safe._tree_inventory, root)
            if {rel: e["sha256"] for rel, e in inv.items()} != fm:
                raise ScriptIntegrateError("%s tree mutated during execution" % label)
        _verify_pins(pins, stop)
        remaining()
        result["trusted_inputs_verification"]["postflight_verified"] = True
        result["comparison"].update(status="producer_bound_integration_passed", all_match=True,
                                    total_cases=len(cases), missing_module_control_ok=True)
        result["status"] = STATUS_PASSED
    except Exception as exc:
        result.update(status="cancelled" if Path(stop).exists() else "failed",
                      error=type(exc).__name__ + ": " + str(exc)[:4096])
    _write_report(output / "integration.json", result)
    return result
