"""Public native (Go / Swift) application-integration seam for
:class:`antirea.projects.ProjectService`.

This binds an already-reviewed native source build (the "producer": a successful
``go_typed_native`` or ``swift_llvm_native`` source-plan/source-build that lowered
selected scalar integer static roots of a separated pure-scalar CORE SOURCE project
into a protected native core DLL) to an ordinary Go or Swift application that lives
in the SAME fingerprinted project tree, then EXPLICITLY compiles and runs that
managed application -- original vs protected -- over an explicit application-sample
contract, and packages a minimal deployable bundle (the protected executable built
from the unchanged application sources + generated same-name core facade/binding
sources + the reused pinned protected native core DLL + any pinned Swift runtime
DLLs actually needed -- NEVER the original core sources/objects/baseline artifact).

It is a distinct, explicit execution step -- never an implicit part of plan/build.
Only ``go_typed_native`` (go) or ``swift_llvm_native`` (swift) is supported here;
any other backend is rejected cleanly without touching its routes.

The heavy lifting (facade parsing/generation/checking, byte-preserving application
compilation, tamper-evident staging, bounded owned child processes with Windows Job
cleanup, and the exact deployment packaging) is performed by the owned trusted
engine module :mod:`antirea.native_app_integration`, loaded lazily BY TRUSTED NAME
only. This module owns the public service contract: it rebinds the existing source
plan/result/report under the source job lock, recomputes the source toolchain and
project snapshot before and after execution, validates the explicit integration
spec and application-sample contract, independently re-derives the producer scalar
ABI contract from the pinned ``contract_path`` file, pins every input into the
engine ``trusted_inputs`` seam, independently verifies the persisted engine report
(bytes parse-equal to the returned report), independently re-derives per-case /
control / preparation raw child evidence from pinned receipts and captured logs,
and independently inventories the engine-owned deployment bundle against an exact
allowlist after a full postflight.

Scope / non-claims (fail closed, never overclaim):
  * The native core is REUSED from the pinned producer artifact and re-verified from
    disk; it is NOT freshly built here (``fresh_protected_native_build`` is always
    False), even when the producer was built moments earlier.
  * Generated facade sources legitimately keep the ORIGINAL core identities (same
    names/exports); what is prohibited is shipping the original core SOURCE bytes,
    objects, libraries, the baseline (unprotected) native artifact or the original
    reference executable. The inventory proves no deployed file's bytes equal any
    such forbidden original.
  * Neither runtime uses an external adapter DLL, so there are NO adapter controls;
    the only fail-closed controls are a missing native-core DLL and an unset
    ``ANTIREA_NATIVE_CORE`` environment variable.
  * Bounded owned child processes with Windows Job cleanup are cleanup evidence, not
    an atomic security sandbox, and process ownership is not a security boundary.
  * Sampled functional equivalence over explicit cases only. Performance, defense
    strength and external-attack resistance remain ``not_evaluated``.

This module never imports :mod:`antirea.projects` (it operates on the passed
``service`` instance) and performs no install/download/publish/push.
"""
from __future__ import annotations

import hashlib
import importlib
import inspect as _inspect_mod
import json
import os
from pathlib import Path
import re
import stat
import uuid

from .protectors import ProtectorError, _job_lock, _json, _no_links, _read


# The trusted owned engine module, loaded ONLY by this name (no caller path).
ENGINE_MODULE = "antirea.native_app_integration"

PUBLIC_STATUS_PASSED = "native_application_samples_passed"
ENGINE_STATUS_PASSED = "native_application_samples_passed"
ENGINE_COMPARISON_PASSED = "producer_bound_integration_passed"
APPLICATION_CONTRACT_KIND = "native_application_samples"
INTEGRATION_SPEC_KIND = "native_application_integration"
PLAN_KIND = "native_source_build"
PUBLIC_ROUTE = "explicit_source_integrate_execution"

NATIVE_CORE_ENV = "ANTIREA_NATIVE_CORE"

MAX_PROJECT_BYTES = 64 * 1024 * 1024
MAX_JSON_BYTES = 256 * 1024
MAX_SOURCE_BYTES = 16 * 1024 * 1024      # bounded read for an application source file
MAX_PREFLIGHT_ENTRIES = 4096             # bounded guarded project-tree walk

# Service-level contract bounds (brief-mandated ceilings).
MAX_CASES = 64
MAX_CASE_ARGS = 16
MAX_ARG_LEN = 256
MAX_LABEL_LEN = 128
MAX_STDOUT_LEN = 4096
MAX_APPLICATION_SOURCES = 32

# Deployment inventory bounds.
MAX_BUNDLE_FILES = 512
MAX_BUNDLE_FILE_BYTES = 512 * 1024 * 1024
DEPLOY_SUFFIX_ALLOWLIST = (".exe", ".dll")

_CONTRACT_KEYS = frozenset({"schema_version", "kind", "cases"})
_CASE_KEYS = frozenset({"label", "args", "expect"})
_EXPECT_KEYS = frozenset({"returncode", "stdout"})
# The native integration spec is deliberately minimal: there is NO caller-supplied
# entry symbol / main class / flags / imports / runtime path -- only the language
# (which must match the bound producer) and the ordinary application sources.
_SPEC_KEYS = frozenset({"schema_version", "kind", "language", "application_sources"})

_LANGUAGES = ("go", "swift")
_SOURCE_SUFFIX = {"go": ".go", "swift": ".swift"}
# The successful source-build backend expected for each supported language.
_BACKEND_BY_LANGUAGE = {"go": "go_typed_native", "swift": "swift_llvm_native"}
_NATIVE_BACKENDS = frozenset(_BACKEND_BY_LANGUAGE.values())

_HEX64 = re.compile(r"[a-f0-9]{64}\Z")

# Path segments refused LEXICALLY, before any stat/read/hash of a consumed path.
_RESERVED_PARTS = frozenset({"rea-analysis-reports", "attackerfolder", "defense-loop",
                             "env.setting", "linkrepro"})

# Owned service/source module bytes pinned into the engine trusted_inputs seam, in
# addition to the source plan/result/report, integration spec, application contract,
# application sources and the producer scalar-ABI contract.
_SERVICE_MODULE_FILES = ("native_application.py", "projects.py", "protectors.py")

# Engine comparison pass flags that must ALL be explicitly True for a pass. Native
# apps use NO external adapter, so there is deliberately no adapter-control flag.
_COMPARISON_PASS_FLAGS = ("all_match", "env_ok", "route_proof_ok",
                          "integrity_verified_before_and_after", "expectations_ok",
                          "missing_core_control_ok")

# Strict child-receipt contract.
# comparison.commands must hold EXACTLY: per contract case L, "case:<L>:original"
# and "case:<L>:protected"; plus the TWO fail-closed controls below (NO adapter
# controls). Each inline command entry carries ONLY metadata (clean-ness is read
# from the persisted raw receipt it pins). Compile/SDK children live in
# preparation_commands.
_CONTROL_SHORT = ("missing_core", "unset_core")
_CONTROL_LABELS = tuple("control:" + short for short in _CONTROL_SHORT)
_COMMAND_ARMS = ("original", "protected")
_COMMAND_META_KEYS = frozenset({"label", "kind", "arm", "case_label", "control",
                                "receipt_path", "receipt_sha256", "stdout_log", "stderr_log"})
_PREP_META_KEYS = frozenset({"label", "kind", "tool", "cwd",
                             "receipt_path", "receipt_sha256", "stdout_log", "stderr_log"})
# preparation_commands must hold EXACTLY these labels per language, each clean +
# exit 0. Go compiles the original and the protected application; Swift additionally
# captures the SDK environment and compiles the shared C bridge first.
_REQUIRED_PREP_LABELS = {
    "go": ("compile-original", "compile-protected"),
    "swift": ("sdk-capture", "compile-bridge", "compile-original", "compile-protected"),
}
MAX_COMMAND_RECEIPTS = 2 * MAX_CASES + len(_CONTROL_LABELS)
MAX_PREP_RECEIPTS = 128
MAX_RECEIPT_BYTES = 256 * 1024             # bounded read of a persisted process.json
MAX_STDOUT_LOG_BYTES = 1024 * 1024         # bounded read of a captured stdout log


def _expected_command_labels(cases) -> set:
    labels = set(_CONTROL_LABELS)
    for case in cases:
        labels.add("case:%s:original" % case["label"])
        labels.add("case:%s:protected" % case["label"])
    return labels


class NativeApplicationError(ValueError):
    """Fail-closed error for a malformed or ineligible integration request."""


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _encoded(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("utf-8")


def _create_json(path: Path, value) -> bytes:
    """Write a fresh append-only JSON file (never overwrite); return its bytes."""
    _no_links(path)
    data = _encoded(value) + b"\n"
    with path.open("xb") as stream:
        stream.write(data)
    return data


def _reserved_guard(raw) -> None:
    """Refuse lexically reserved/excluded path segments BEFORE any filesystem access."""
    if not isinstance(raw, str) or not raw or any(ord(c) < 32 for c in raw):
        raise NativeApplicationError("path must be a non-empty, control-character-free string")
    for part in raw.replace("\\", "/").split("/"):
        if part.casefold() in _RESERVED_PARTS:
            raise NativeApplicationError("reserved/excluded path segment is not allowed: " + part)


def _safe_relative_source(name, label: str, suffix: str) -> str:
    """Require a safe RELATIVE project source name (package subdirectories allowed)
    before any stat/read/hash.

    Rejects non-strings, control chars, absolute/drive-qualified paths, any ``..`` or
    empty component, lexically reserved segments and a wrong extension. Returns the
    POSIX-normalised relative string; the caller still resolves it under the planned
    project directory and requires fingerprinted-snapshot membership.
    """
    if not isinstance(name, str) or not name or any(ord(c) < 32 for c in name):
        raise NativeApplicationError(label + " must be a non-empty, control-character-free name")
    if ":" in name:
        raise NativeApplicationError(label + " must not be drive-qualified: " + name)
    normalized = name.replace("\\", "/")
    if normalized.startswith("/"):
        raise NativeApplicationError(label + " must be a relative project path: " + name)
    parts = normalized.split("/")
    for part in parts:
        if not part or part in (".", ".."):
            raise NativeApplicationError(label + " must not contain empty or parent components: " + name)
    _reserved_guard(normalized)
    if not normalized.lower().endswith(suffix):
        raise NativeApplicationError(label + " must be a %s source file: %s" % (suffix, name))
    candidate = Path(normalized)
    if candidate.is_absolute():
        raise NativeApplicationError(label + " must be a relative project path: " + name)
    return normalized


def _guarded_tree_preflight(app_dir: Path) -> None:
    """Bounded, STREAMING, non-link walk of the planned project tree that refuses
    reserved descendants BEFORE descending/reading. Protects the generic
    ``_snapshot``/``_toolchain`` (which lack env.setting/LINKREPRO guards) from ever
    stat/reading an excluded file, even for a malformed saved plan.
    """
    app_dir = Path(app_dir)
    _no_links(app_dir)
    if not app_dir.is_dir():
        raise NativeApplicationError("planned project directory is missing")
    entries = 0
    pending = [app_dir]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as iterator:
            for entry in iterator:
                entries += 1
                if entries > MAX_PREFLIGHT_ENTRIES:
                    raise NativeApplicationError("planned project tree exceeds the bounded preflight entry limit")
                if entry.name.casefold() in _RESERVED_PARTS:
                    raise NativeApplicationError(
                        "reserved/excluded descendant is not allowed under the project: " + entry.name)
                if entry.is_symlink():
                    raise NativeApplicationError("symlink is not allowed under the project: " + entry.path)
                info = entry.stat(follow_symlinks=False)
                if getattr(info, "st_file_attributes", 0) & 0x400:
                    raise NativeApplicationError("reparse point is not allowed under the project: " + entry.path)
                if stat.S_ISDIR(info.st_mode):
                    pending.append(Path(entry.path))
                elif not stat.S_ISREG(info.st_mode):
                    raise NativeApplicationError("non-regular entry is not allowed under the project: " + entry.path)


def _guard_saved_plan_paths(plan: dict) -> None:
    """Lexically guard every path recorded in the saved plan BEFORE the service
    recomputation touches the disk, so a malformed saved plan cannot steer
    ``_owned``/``_snapshot``/``_toolchain`` at an excluded file."""
    for rec in plan.get("inputs") or []:
        if isinstance(rec, dict) and isinstance(rec.get("path"), str):
            _reserved_guard(rec["path"])
    inspection = plan.get("inspection") or {}
    for mapping_key in ("compiler_inputs", "input_hashes"):
        mapping = inspection.get(mapping_key) or {}
        if isinstance(mapping, dict):
            for key in mapping:
                if isinstance(key, str):
                    _reserved_guard(key)
    tools = (plan.get("toolchain") or {}).get("tools") or {}
    if isinstance(tools, dict):
        for tool in tools.values():
            if isinstance(tool, dict) and isinstance(tool.get("path"), str):
                _reserved_guard(tool["path"])


# Path-bearing fields of the fixed native toolchain config that _toolchain turns
# into filesystem paths it follows/hashes during generic discovery.
_TOOLCHAIN_PATH_FIELDS = ("clang", "clangxx", "optimizer", "runtime", "developer_shell",
                          "llvm_root", "kagura_source")


def _preflight_toolchain_config(service, plan_toolchain: dict, inspection: dict) -> None:
    """Verify the FIXED native toolchain config bytes against the saved plan sha and
    lexically guard its path-bearing fields BEFORE the generic ``service._toolchain``
    discovery can follow (and hash) any newly changed configured path. The native
    source route always requires the native toolchain (language go/swift).
    """
    if not isinstance(plan_toolchain, dict):
        raise NativeApplicationError("saved plan toolchain is malformed")
    native_required = (inspection or {}).get("language") not in {"python", "javascript", "typescript"}
    config_path = service.root / ".tools" / "kagura-toolchain.json"
    _reserved_guard(str(config_path))
    saved_sha = plan_toolchain.get("sha256")
    if not native_required or plan_toolchain.get("status") != "present" or not isinstance(saved_sha, str):
        if native_required and isinstance(saved_sha, str) and not config_path.is_file():
            raise NativeApplicationError("planned native toolchain config is missing")
        return
    if not config_path.is_file():
        raise NativeApplicationError("planned native toolchain config is missing")
    raw = _read(config_path, MAX_JSON_BYTES)
    if _digest(raw) != saved_sha:
        raise NativeApplicationError("native toolchain config changed since planning; refusing to follow its paths")
    config = _json(raw)
    if not isinstance(config, dict):
        raise NativeApplicationError("native toolchain config must be an object")
    for field in _TOOLCHAIN_PATH_FIELDS:
        value = config.get(field)
        if isinstance(value, str) and value:
            _reserved_guard(value)
    for key in (inspection or {}).get("compiler_inputs", {}) or {}:
        if isinstance(key, str):
            _reserved_guard(key)


def _guarded_preflight(service, app_dir: Path, plan_toolchain: dict, inspection: dict) -> None:
    """Run BOTH guards (project-tree + fixed-toolchain-config) that must precede any
    generic ``_snapshot``/``_toolchain`` recomputation -- at plan time AND after
    execution AND after packaging."""
    _guarded_tree_preflight(app_dir)
    _preflight_toolchain_config(service, plan_toolchain, inspection)


def _owned_app_file(service, raw, app_dir: Path, label: str, snapshot_paths: set) -> Path:
    """Reserved guard, then owned/no-link validation, then require a regular file
    anywhere WITHIN ``app_dir`` (the planned project tree, nested subdirectories
    allowed) that is already pinned in the fingerprinted plan snapshot. This keeps
    the spec/contract inside the same planned project snapshot and rejects any
    arbitrary caller-supplied path. The engine lets the spec live in a project
    subdirectory and resolves application sources relative to the spec's own parent,
    so the service must not force the spec/contract directly into ``app_dir``."""
    _reserved_guard(raw)
    path = service._owned(raw)           # abs, no links, inside workspace, not received/service-output
    _no_links(path)
    if not path.is_relative_to(app_dir):
        raise NativeApplicationError(label + " must live within the planned project directory")
    if not path.is_file():
        raise NativeApplicationError(label + " must be an existing regular file")
    if str(path) not in snapshot_paths:
        raise NativeApplicationError(label + " is not part of the fingerprinted plan snapshot")
    return path


def _validate_integration_spec(spec, *, plan_language: str) -> dict:
    """Validate the strict native integration spec and return a normalised copy.

    Schema: ``{"schema_version": 1, "kind": "native_application_integration",
    "language": "go"|"swift", "application_sources": [relpath, ...]}``. No
    caller-supplied flags/commands/DLLs/import directories/runtime path fields are
    accepted; the language MUST match the bound producer. Nothing is executed here.
    """
    if not isinstance(spec, dict):
        raise NativeApplicationError("integration spec must be a JSON object")
    extra = set(spec) - _SPEC_KEYS
    missing = _SPEC_KEYS - set(spec)
    if extra:
        raise NativeApplicationError("integration spec has unsupported key(s): " + ", ".join(sorted(extra)))
    if missing:
        raise NativeApplicationError("integration spec missing key(s): " + ", ".join(sorted(missing)))
    if type(spec["schema_version"]) is not int or spec["schema_version"] != 1:
        raise NativeApplicationError("integration spec schema_version must be 1")
    if spec["kind"] != INTEGRATION_SPEC_KIND:
        raise NativeApplicationError("integration spec kind must be %r" % INTEGRATION_SPEC_KIND)
    language = spec["language"]
    if language not in _LANGUAGES:
        raise NativeApplicationError("integration spec language must be one of %s" % list(_LANGUAGES))
    if language != plan_language:
        raise NativeApplicationError(
            "integration spec language %r does not match the bound producer language %r" % (language, plan_language))
    sources = spec["application_sources"]
    if not isinstance(sources, list) or not 1 <= len(sources) <= MAX_APPLICATION_SOURCES:
        raise NativeApplicationError("integration spec application_sources must be a list of 1..%d files"
                                     % MAX_APPLICATION_SOURCES)
    suffix = _SOURCE_SUFFIX[language]
    normalized, seen = [], set()
    for name in sources:
        rel = _safe_relative_source(name, "integration spec application source", suffix)
        if rel in seen:
            raise NativeApplicationError("integration spec application_sources has a duplicate: " + rel)
        seen.add(rel)
        normalized.append(rel)
    return {"schema_version": 1, "kind": INTEGRATION_SPEC_KIND, "language": language,
            "application_sources": normalized}


def _validate_app_contract(contract) -> list:
    """Validate the explicit native application-sample contract and return its cases.

    Schema: ``{"schema_version": 1, "kind": "native_application_samples",
    "cases": [{"label", "args": [str...], "expect": {"returncode": int,
    "stdout": str}} ...]}``. EVERY case must carry an exact expected integer
    returncode AND exact expected stdout. Arguments are bounded strings with
    NUL/control safeguards. Nothing is executed here; malformed input fails closed
    BEFORE any child process is launched.
    """
    if not isinstance(contract, dict):
        raise NativeApplicationError("application contract must be a JSON object")
    extra = set(contract) - _CONTRACT_KEYS
    missing = _CONTRACT_KEYS - set(contract)
    if extra:
        raise NativeApplicationError("application contract has unsupported key(s): " + ", ".join(sorted(extra)))
    if missing:
        raise NativeApplicationError("application contract missing key(s): " + ", ".join(sorted(missing)))
    if type(contract["schema_version"]) is not int or contract["schema_version"] != 1:
        raise NativeApplicationError("application contract schema_version must be 1")
    if contract["kind"] != APPLICATION_CONTRACT_KIND:
        raise NativeApplicationError("application contract kind must be %r" % APPLICATION_CONTRACT_KIND)
    cases = contract["cases"]
    if not isinstance(cases, list) or not cases:
        raise NativeApplicationError("application contract cases must be a non-empty list")
    if len(cases) > MAX_CASES:
        raise NativeApplicationError("too many cases (max %d)" % MAX_CASES)
    out, labels = [], set()
    for idx, case in enumerate(cases):
        if not isinstance(case, dict):
            raise NativeApplicationError("case %d must be an object" % idx)
        keys = set(case)
        if _CASE_KEYS - keys:
            raise NativeApplicationError("case %d missing key(s): %s" % (idx, ", ".join(sorted(_CASE_KEYS - keys))))
        if keys - _CASE_KEYS:
            raise NativeApplicationError("case %d has unsupported key(s): %s" % (idx, ", ".join(sorted(keys - _CASE_KEYS))))
        label = case["label"]
        if not isinstance(label, str) or not label or len(label) > MAX_LABEL_LEN:
            raise NativeApplicationError("case %d label must be a non-empty string <= %d chars" % (idx, MAX_LABEL_LEN))
        if label in labels:
            raise NativeApplicationError("case %d has a duplicate label: %r" % (idx, label))
        labels.add(label)
        args = case["args"]
        if not isinstance(args, list) or len(args) > MAX_CASE_ARGS:
            raise NativeApplicationError("case %r args must be a list of 0..%d strings" % (label, MAX_CASE_ARGS))
        norm_args = []
        for a in args:
            if isinstance(a, bool) or not isinstance(a, str):
                raise NativeApplicationError("case %r args must be strings (process argv)" % label)
            if any(ord(c) < 32 for c in a):
                # Reject embedded NUL/control chars HERE, in pure preflight, never
                # later at the child boundary after compilers already ran.
                raise NativeApplicationError("case %r argument contains a NUL/control character" % label)
            if len(a) > MAX_ARG_LEN:
                raise NativeApplicationError("case %r argument exceeds %d chars" % (label, MAX_ARG_LEN))
            norm_args.append(a)
        expect = case["expect"]
        if not isinstance(expect, dict):
            raise NativeApplicationError("case %r expect must be an object" % label)
        ekeys = set(expect)
        if _EXPECT_KEYS - ekeys:
            raise NativeApplicationError("case %r expect missing key(s): %s" % (label, ", ".join(sorted(_EXPECT_KEYS - ekeys))))
        if ekeys - _EXPECT_KEYS:
            raise NativeApplicationError("case %r expect has unsupported key(s): %s"
                                         % (label, ", ".join(sorted(ekeys - _EXPECT_KEYS))))
        rc = expect["returncode"]
        if isinstance(rc, bool) or not isinstance(rc, int):
            raise NativeApplicationError("case %r expect.returncode must be an int" % label)
        stdout = expect["stdout"]
        if not isinstance(stdout, str) or len(stdout) > MAX_STDOUT_LEN:
            raise NativeApplicationError("case %r expect.stdout must be a string <= %d chars" % (label, MAX_STDOUT_LEN))
        if any(ord(c) < 32 and c not in "\t\n\r" for c in stdout):
            raise NativeApplicationError("case %r expect.stdout contains a NUL/control character" % label)
        out.append({"label": label, "args": norm_args, "expect": {"returncode": rc, "stdout": stdout}})
    return out


def _load_engine():
    """Import the trusted engine lazily, by trusted name only."""
    try:
        engine = importlib.import_module(ENGINE_MODULE)
    except ImportError as exc:
        raise NativeApplicationError(
            "trusted integration engine %r is not available in this build; native application "
            "integration cannot execute until it is present: %s" % (ENGINE_MODULE, exc)) from exc
    if not hasattr(engine, "run_integration"):
        raise NativeApplicationError("trusted integration engine is missing required API 'run_integration'")
    return engine


# The keyword seam the engine must accept (path-based, pure-keyword API).
_ENGINE_REQUIRED_KW = ("producer_report_path", "integration_spec_path", "application_contract_path",
                       "output_dir", "workspace_root", "timeout_seconds", "trusted_inputs")


def _require_engine_api(engine) -> None:
    """Require the engine's run_integration to accept the service keyword seam,
    including the ``trusted_inputs`` pin list."""
    try:
        params = _inspect_mod.signature(engine.run_integration).parameters
    except (TypeError, ValueError) as exc:
        raise NativeApplicationError("cannot introspect engine run_integration: %s" % exc) from exc
    has_var_kw = any(p.kind is _inspect_mod.Parameter.VAR_KEYWORD for p in params.values())
    if has_var_kw:
        return
    missing = [name for name in _ENGINE_REQUIRED_KW if name not in params]
    if missing:
        raise NativeApplicationError(
            "trusted integration engine run_integration does not accept required keyword seam(s): "
            + ", ".join(missing) + "; engine adoption is incomplete")


def _forbidden_byte_shas(source_report: dict, artifacts: dict) -> set:
    """The set of sha256 that MUST NOT appear in the deployment bundle: the baseline
    (unprotected) native artifact, the original reference executable (original app
    built with the original core) and every original core/app SOURCE byte. Generated
    facade/binding sources legitimately keep the original core IDENTITIES but must
    not carry these original BYTES."""
    forbidden = set()
    base = artifacts.get("baseline") if isinstance(artifacts, dict) else None
    if isinstance(base, dict) and isinstance(base.get("sha256"), str) and _HEX64.fullmatch(base["sha256"]):
        forbidden.add(base["sha256"])
    ref = source_report.get("reference_executable") if isinstance(source_report, dict) else None
    if isinstance(ref, dict) and isinstance(ref.get("sha256"), str) and _HEX64.fullmatch(ref["sha256"]):
        forbidden.add(ref["sha256"])
    source_hashes = source_report.get("source_hashes") if isinstance(source_report, dict) else None
    if isinstance(source_hashes, dict):
        for value in source_hashes.values():
            if isinstance(value, str) and _HEX64.fullmatch(value):
                forbidden.add(value)
    return forbidden


def _confined_under(raw, base: Path, label: str) -> Path:
    """Reserved-guard a producer path, require it confined under ``base`` (the source
    build job directory) and link-free, and require it is an existing regular file.
    Returns the absolute path. Used for producer artifacts the service reads itself
    (the scalar-ABI contract and the native build report)."""
    if not isinstance(raw, str) or not raw:
        raise NativeApplicationError(label + " path is missing")
    _reserved_guard(raw)
    p = Path(os.path.abspath(raw))
    _no_links(p)
    if not p.is_relative_to(Path(os.path.abspath(base))):
        raise NativeApplicationError(label + " is not confined under the source build directory")
    if not p.is_file():
        raise NativeApplicationError(label + " file is missing")
    return p


# Mandatory producer scalar-ABI contract fields the service authenticates
# independently (a superset check that must not reject a valid producer contract --
# the authoritative documented shape is bindings.validate_contract's schema-1 cdecl
# integer ABI; the full type table / identifier rules stay the generator's concern).
def _validate_producer_contract_schema(contract, exports) -> None:
    if not isinstance(contract, dict):
        raise NativeApplicationError("producer contract must be a JSON object")
    if set(contract) - {"schema_version", "library_name", "functions", "calling_convention"}:
        raise NativeApplicationError("producer contract has undocumented fields")
    if type(contract.get("schema_version")) is not int or contract["schema_version"] != 1:
        raise NativeApplicationError("producer contract schema_version must be 1")
    if contract.get("calling_convention", "cdecl") != "cdecl":
        raise NativeApplicationError("producer contract calling_convention must be cdecl")
    if not isinstance(contract.get("library_name"), str) or not contract["library_name"]:
        raise NativeApplicationError("producer contract library_name is missing")
    functions = contract.get("functions")
    if not isinstance(functions, list) or not 1 <= len(functions) <= 128:
        raise NativeApplicationError("producer contract functions must be a list of 1..128")
    names = []
    for fn in functions:
        if not isinstance(fn, dict) or set(fn) != {"name", "return_type", "parameters"}:
            raise NativeApplicationError("producer contract function shape is invalid")
        if not isinstance(fn["name"], str) or not fn["name"] or not isinstance(fn["return_type"], str) or not fn["return_type"]:
            raise NativeApplicationError("producer contract function name/return_type is invalid")
        params = fn["parameters"]
        if not isinstance(params, list) or len(params) > 16:
            raise NativeApplicationError("producer contract parameters must be a list of 0..16")
        for p in params:
            if (not isinstance(p, dict) or set(p) != {"name", "type"}
                    or not isinstance(p.get("name"), str) or not p["name"]
                    or not isinstance(p.get("type"), str) or not p["type"]):
                raise NativeApplicationError("producer contract parameter shape is invalid")
        names.append(fn["name"])
    if len(set(names)) != len(names):
        raise NativeApplicationError("producer contract has duplicate function names")
    if not isinstance(exports, list) or sorted(exports) != sorted(names):
        raise NativeApplicationError("producer contract functions disagree with project exports")


def _authenticate_producer_origin(source_report: dict, *, directory: Path, language: str,
                                  inspection: dict) -> dict:
    """Independently re-derive and authenticate the producer scalar-ABI contract and
    the native build origin from disk, BEFORE the engine runs. A syntax-only native
    pin is insufficient: the contract file's ACTUAL bytes must match the producer's
    claimed frontend hash (Go ``frontend_artifact_hashes[contract.json]`` + inline
    ``contract`` equality; Swift ``artifact_hashes[frontend/contract.json]``), the
    contract schema must be well-formed and agree with the project exports, and the
    native build report must be confined, byte-hash-equal to its pin, a successful
    build whose artifacts equal the producer's, whose VM coverage agrees, and whose
    selected native closure covers the lowered roots/helpers and the exports.

    Returns the authenticated pins ``{contract_path, contract_sha256,
    native_report_path, native_report_sha256}``; raises on any contradiction. Never
    repins an invalid claim.
    """
    dir_abs = Path(os.path.abspath(directory))
    exports = inspection.get("functions")

    # ---- scalar-ABI contract: actual file hash == claimed frontend hash ----
    contract_abs = _confined_under(source_report.get("contract_path"), dir_abs, "producer contract_path")
    contract_bytes = _read(contract_abs, MAX_JSON_BYTES)
    contract_sha = _digest(contract_bytes)
    hashes_key = "frontend_artifact_hashes" if language == "go" else "artifact_hashes"
    entry_key = "contract.json" if language == "go" else "frontend/contract.json"
    hashes = source_report.get(hashes_key)
    if not isinstance(hashes, dict):
        raise NativeApplicationError("producer %s is missing" % hashes_key)
    claimed = hashes.get(entry_key)
    if not isinstance(claimed, str) or not _HEX64.fullmatch(claimed) or claimed != contract_sha:
        raise NativeApplicationError("producer contract claimed frontend hash does not match the file bytes")
    contract = _json(contract_bytes)
    _validate_producer_contract_schema(contract, exports)
    if language == "go" and source_report.get("contract") != contract:
        raise NativeApplicationError("inline Go contract differs from the pinned contract file")

    # ---- native build report: confined, byte-hash-equal, origin-consistent ----
    nr_sha = source_report.get("native_report_sha256")
    if not isinstance(nr_sha, str) or not _HEX64.fullmatch(nr_sha):
        raise NativeApplicationError("producer native_report_sha256 is missing or malformed")
    nr_abs = _confined_under(source_report.get("native_report"), dir_abs, "producer native_report")
    native_bytes = _read(nr_abs, MAX_PROJECT_BYTES)
    if _digest(native_bytes) != nr_sha:
        raise NativeApplicationError("producer native build report bytes disagree with the pinned hash")
    native = _json(native_bytes)
    if not isinstance(native, dict) or native.get("status") != "artifact_created_unvalidated":
        raise NativeApplicationError("native origin is not a successful build")
    report_artifacts = source_report.get("artifacts")
    native_artifacts = native.get("artifacts")
    if not isinstance(report_artifacts, dict) or not isinstance(native_artifacts, dict):
        raise NativeApplicationError("native/report artifacts are missing")
    for arm in ("baseline", "protected"):
        if not isinstance(report_artifacts.get(arm), dict) or native_artifacts.get(arm) != report_artifacts.get(arm):
            raise NativeApplicationError("native artifact origin mismatch for " + arm)
    native_coverage = native.get("coverage")
    if not isinstance(native_coverage, dict):
        raise NativeApplicationError("native VM coverage is missing")
    if not isinstance(exports, list) or not exports or len(set(exports)) != len(exports):
        raise NativeApplicationError("producer exports missing or non-unique")
    expected_coverage = {**native_coverage, "exported_functions": exports} if language == "go" else native_coverage
    if source_report.get("coverage") != expected_coverage:
        raise NativeApplicationError("producer and native VM coverage disagree")
    if language == "go":
        methods = source_report.get("methods")
        if not isinstance(methods, list) or not methods or any(not isinstance(m, dict) for m in methods):
            raise NativeApplicationError("lowered Go methods are missing")
        selected = [m.get("export") for m in methods]
    else:
        normalization = source_report.get("normalization")
        if not isinstance(normalization, dict):
            raise NativeApplicationError("Swift normalization evidence is missing")
        selected = normalization.get("selected_functions")
    if (not isinstance(selected, list) or not selected or any(not isinstance(s, str) for s in selected)
            or not isinstance(native_coverage.get("selected_functions"), list)
            or set(selected) != set(native_coverage["selected_functions"])
            or not set(exports) <= set(selected)):
        raise NativeApplicationError("selected native closure does not match lowered roots and helpers")
    if any(not native_coverage.get(key) for key in ("functions", "original_vm", "final_vm")):
        raise NativeApplicationError("native VM structure evidence is missing")
    return {"contract_path": str(contract_abs), "contract_sha256": contract_sha,
            "native_report_path": str(nr_abs), "native_report_sha256": nr_sha}


def _bounded_bundle_dir(deploy_dir: Path, engine_out: Path) -> list:
    """Bounded, non-link walk of the engine-owned deployment directory. Confirms the
    directory is confined under the engine output, link-free and holds only regular
    files; returns the sorted list of POSIX relative paths actually present."""
    deploy_dir = Path(os.path.abspath(deploy_dir))
    engine_out = Path(os.path.abspath(engine_out))
    _reserved_guard(str(deploy_dir))
    if not deploy_dir.is_relative_to(engine_out):
        raise NativeApplicationError("deployment directory is not confined under the engine output directory")
    _no_links(deploy_dir)
    if not deploy_dir.is_dir():
        raise NativeApplicationError("deployment directory is missing")
    present = []
    entries = 0
    pending = [deploy_dir]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as iterator:
            for entry in iterator:
                entries += 1
                if entries > MAX_BUNDLE_FILES:
                    raise NativeApplicationError("deployment bundle exceeds the bounded file limit")
                if entry.name.casefold() in _RESERVED_PARTS:
                    raise NativeApplicationError("reserved descendant in the deployment bundle: " + entry.name)
                if entry.is_symlink():
                    raise NativeApplicationError("symlink in the deployment bundle: " + entry.path)
                info = entry.stat(follow_symlinks=False)
                if getattr(info, "st_file_attributes", 0) & 0x400:
                    raise NativeApplicationError("reparse point in the deployment bundle: " + entry.path)
                if stat.S_ISDIR(info.st_mode):
                    pending.append(Path(entry.path))
                elif stat.S_ISREG(info.st_mode):
                    rel = Path(entry.path).relative_to(deploy_dir).as_posix()
                    present.append(rel)
                else:
                    raise NativeApplicationError("non-regular entry in the deployment bundle: " + entry.path)
    return sorted(present)


def _inventory_bundle(engine_report: dict, *, engine_out: Path, artifacts: dict,
                      expected_native_sha: str, source_report: dict, language: str) -> dict:
    """Independently inventory the engine-owned deployment bundle against an exact
    allowlist, NEVER trusting the engine report alone.

    Verifies: a well-formed ``deployment`` block; the on-disk bundle directory is
    confined/link-free and its file set EXACTLY equals both the engine ``allowlist``
    and the engine ``files`` manifest; every file has an allowlisted suffix
    (.exe/.dll), is a bounded regular file and re-hashes to the engine-reported pin;
    no deployed file's bytes equal a forbidden original (baseline native artifact,
    original reference executable or any original source byte); the reused protected
    native core is present with the producer's protected sha; the executable is an
    .exe member distinct from the core; and every runtime DLL is a distinct .dll
    member (empty for Go). Returns the compact public ``deployment_bundle`` on
    success; raises :class:`NativeApplicationError` on any mismatch.
    """
    deployment = engine_report.get("deployment")
    if not isinstance(deployment, dict):
        raise NativeApplicationError("engine report has no deployment block")
    deploy_path = deployment.get("path")
    files = deployment.get("files")
    allowlist = deployment.get("allowlist")
    executable_rel = deployment.get("executable")
    native_core_rel = deployment.get("native_core")
    runtime_files = deployment.get("runtime_files")
    if not isinstance(deploy_path, str) or not isinstance(files, list) or not files:
        raise NativeApplicationError("engine deployment block is missing path/files")
    if not isinstance(allowlist, list) or not allowlist:
        raise NativeApplicationError("engine deployment block is missing the allowlist")
    if deployment.get("forbidden_absent") is not True:
        raise NativeApplicationError("engine deployment does not assert forbidden_absent")
    if not isinstance(executable_rel, str) or not executable_rel.lower().endswith(".exe"):
        raise NativeApplicationError("engine deployment executable is malformed")
    if not isinstance(native_core_rel, str) or not native_core_rel.lower().endswith(".dll"):
        raise NativeApplicationError("engine deployment native_core is malformed")
    if not isinstance(runtime_files, list) or not all(isinstance(r, str) for r in runtime_files):
        raise NativeApplicationError("engine deployment runtime_files is malformed")
    if language == "go" and runtime_files:
        raise NativeApplicationError("Go deployment must not declare runtime DLLs")

    # Parse + validate the engine file manifest into an exact relpath->pin map.
    manifest = {}
    for rec in files:
        if not isinstance(rec, dict):
            raise NativeApplicationError("engine deployment file entry must be an object")
        rel, sha, size = rec.get("relative_path"), rec.get("sha256"), rec.get("bytes")
        if not isinstance(rel, str) or not rel:
            raise NativeApplicationError("engine deployment file has no relative_path")
        norm = rel.replace("\\", "/")
        if norm.startswith("/") or ":" in norm or any(p in ("", ".", "..") for p in norm.split("/")):
            raise NativeApplicationError("engine deployment relative_path is unsafe: " + rel)
        _reserved_guard(norm)
        if not norm.lower().endswith(DEPLOY_SUFFIX_ALLOWLIST):
            raise NativeApplicationError("engine deployment file has a non-allowlisted suffix: " + rel)
        if not isinstance(sha, str) or not _HEX64.fullmatch(sha):
            raise NativeApplicationError("engine deployment file pin is not a sha256: " + rel)
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise NativeApplicationError("engine deployment file size is invalid: " + rel)
        if norm in manifest:
            raise NativeApplicationError("engine deployment lists a duplicate file: " + norm)
        manifest[norm] = (sha, size)
    allow_set = set()
    for rel in allowlist:
        if not isinstance(rel, str) or not rel:
            raise NativeApplicationError("engine allowlist entry is malformed")
        allow_set.add(rel.replace("\\", "/"))
    if allow_set != set(manifest):
        raise NativeApplicationError("engine allowlist and file manifest disagree")

    exe_norm = executable_rel.replace("\\", "/")
    core_norm = native_core_rel.replace("\\", "/")
    runtime_norm = [r.replace("\\", "/") for r in runtime_files]
    if exe_norm == core_norm:
        raise NativeApplicationError("engine deployment executable and native_core must be distinct")
    if len(set(runtime_norm)) != len(runtime_norm):
        raise NativeApplicationError("engine deployment runtime_files has duplicates")
    for rt in runtime_norm:
        if not rt.lower().endswith(".dll"):
            raise NativeApplicationError("engine deployment runtime file is not a .dll: " + rt)
        if rt in (exe_norm, core_norm):
            raise NativeApplicationError("engine deployment runtime file overlaps executable/native_core: " + rt)
    for rel in (exe_norm, core_norm, *runtime_norm):
        if rel not in manifest:
            raise NativeApplicationError("engine launch metadata names a non-member file: " + rel)

    deploy_dir = Path(os.path.abspath(deploy_path))
    present = _bounded_bundle_dir(deploy_dir, Path(os.path.abspath(engine_out)))
    if set(present) != set(manifest):
        extra = sorted(set(present) - set(manifest))
        absent = sorted(set(manifest) - set(present))
        raise NativeApplicationError(
            "deployment bundle contents disagree with the allowlist (unexpected=%s missing=%s)" % (extra, absent))

    forbidden = _forbidden_byte_shas(source_report, artifacts)
    native_core_seen = False
    out_files = []
    for rel in sorted(manifest):
        expected_sha, expected_size = manifest[rel]
        src = deploy_dir / rel
        _no_links(src)
        try:
            data = _read(src, MAX_BUNDLE_FILE_BYTES)
        except ProtectorError as exc:
            raise NativeApplicationError("deployment file is not a bounded regular file: " + rel + ": " + str(exc)) from exc
        actual = _digest(data)
        if actual != expected_sha:
            raise NativeApplicationError("deployment file bytes disagree with the engine pin: " + rel)
        if len(data) != expected_size:
            raise NativeApplicationError("deployment file size disagrees with the engine pin: " + rel)
        if actual in forbidden:
            # Facade identities are allowed; original BYTES (core/baseline/reference) are not.
            raise NativeApplicationError(
                "deployment file carries forbidden original bytes (baseline/reference/source): " + rel)
        if rel == core_norm:
            native_core_seen = True
            if actual != expected_native_sha:
                raise NativeApplicationError("deployment native core is not the reused protected producer artifact")
        out_files.append({"relative_path": rel, "sha256": actual, "bytes": len(data)})

    if not native_core_seen:
        raise NativeApplicationError("deployment bundle does not contain the declared protected native core")
    if not isinstance(expected_native_sha, str) or not _HEX64.fullmatch(expected_native_sha):
        raise NativeApplicationError("producer protected native sha is unavailable for the inventory")
    if expected_native_sha not in {f["sha256"] for f in out_files}:
        raise NativeApplicationError("the reused protected native sha does not appear in the bundle")
    return {"path": str(deploy_dir), "files": out_files, "executable": exe_norm,
            "native_core": core_norm, "runtime_files": runtime_norm}


def _comparison_summary(engine_report) -> dict | None:
    if not isinstance(engine_report, dict):
        return None
    c = engine_report.get("comparison")
    if not isinstance(c, dict):
        return None
    summary = {k: c.get(k) for k in ("status", "total_cases", "stop_cancellations", *_COMPARISON_PASS_FLAGS)}
    return summary


def _verify_engine_report(engine_report, engine_report_path: Path, *, report_path: Path,
                          report_sha: str, artifacts: dict, cases: list, language: str,
                          declared_trusted_count: int, source_report: dict, contract_path: str,
                          contract_sha: str, app_source_hash_map: dict) -> dict:
    """A success must rest on a GENUINE persisted engine report.

    Requires: the returned report is a dict; the persisted file exists, is bounded
    and parses EQUAL to the returned report (defeats a return-only/stale/forged
    on-disk report); the report's producer/native pins match the exact source build
    this service bound (backend-for-language, source report path+sha, baseline +
    protected artifact shas, the independently re-derived scalar-ABI contract
    path+sha, and the native build report path+sha); the reused native core equals
    the producer protected sha and the staging excludes the original core from the
    protected compile and covers the service's own application-source hashes; the
    comparison pass flags, coverage and per-case original-vs-protected observations
    (with the service's own expected returncode/stdout) are all present and honest;
    the engine's trusted-input verification matches the declared count; and the
    reuse flag is honestly False. Returns ``{"authentic", "checks", "reason"}``.
    """
    checks = {}

    def record(name, ok):
        checks[name] = bool(ok)
        return bool(ok)

    if not record("returned_report_is_dict", isinstance(engine_report, dict)):
        return {"authentic": False, "checks": checks, "reason": "returned report is not a dict"}
    reason = None
    try:
        persisted_ok = engine_report_path.is_file()
        if persisted_ok:
            info = engine_report_path.lstat()
            persisted_ok = stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_PROJECT_BYTES
        record("persisted_report_present_bounded_regular", persisted_ok)
        parsed_equal = False
        if persisted_ok:
            parsed = _json(_read(engine_report_path, MAX_PROJECT_BYTES))
            parsed_equal = (parsed == engine_report)
        record("persisted_equals_returned", parsed_equal)
    except Exception as exc:  # noqa: BLE001
        record("persisted_equals_returned", False)
        reason = "persisted report check error: " + type(exc).__name__

    record("engine_status_passed", engine_report.get("status") == ENGINE_STATUS_PASSED)
    record("language_match", engine_report.get("language") == language)

    producer = engine_report.get("producer") if isinstance(engine_report.get("producer"), dict) else {}
    record("producer_backend_match", producer.get("backend") == _BACKEND_BY_LANGUAGE.get(language))
    record("producer_report_path_match", producer.get("report_path") == str(report_path))
    record("producer_report_sha_match", producer.get("report_sha256") == report_sha)
    prot = artifacts.get("protected") if isinstance(artifacts, dict) else {}
    prot = prot if isinstance(prot, dict) else {}
    prot_sha = prot.get("sha256")
    p_artifacts = producer.get("artifacts") if isinstance(producer.get("artifacts"), dict) else {}

    def _artifact_bound(arm):
        """Bind producer artifact path AND size AND sha256 (not sha alone) to the
        exact source-build artifact record the service already pinned."""
        want = artifacts.get(arm) if isinstance(artifacts, dict) else None
        got = p_artifacts.get(arm)
        if not isinstance(want, dict) or not isinstance(got, dict):
            return False
        for field in ("path", "sha256", "bytes"):
            if field not in want or got.get(field) != want.get(field):
                return False
        if isinstance(got.get("bytes"), bool) or not isinstance(got.get("bytes"), int) or got["bytes"] < 0:
            return False
        if not isinstance(got.get("sha256"), str) or not _HEX64.fullmatch(got["sha256"]):
            return False
        return True

    record("producer_protected_artifact_bound", bool(prot_sha) and _artifact_bound("protected"))
    record("producer_baseline_artifact_bound", _artifact_bound("baseline"))

    # Independently re-derived scalar-ABI contract (from the pinned contract_path file)
    # and the native build report, both bound to what the source report itself declares.
    record("producer_contract_path_match",
           producer.get("contract_path") == contract_path and source_report.get("contract_path") == contract_path)
    record("producer_contract_sha_match",
           isinstance(contract_sha, str) and bool(_HEX64.fullmatch(contract_sha))
           and producer.get("contract_sha256") == contract_sha)
    p_native = producer.get("native_report") if isinstance(producer.get("native_report"), dict) else {}
    record("producer_native_report_match",
           p_native.get("path") == source_report.get("native_report")
           and p_native.get("sha256") == source_report.get("native_report_sha256")
           and isinstance(source_report.get("native_report_sha256"), str)
           and bool(_HEX64.fullmatch(str(source_report.get("native_report_sha256")))))

    staging = engine_report.get("staging") if isinstance(engine_report.get("staging"), dict) else {}
    record("native_core_is_reused_protected", bool(prot_sha) and staging.get("native_core_sha256") == prot_sha)
    record("original_core_excluded_from_protected_compile",
           staging.get("original_core_excluded_from_protected_compile") is True)
    # Bind the EXACT application_source_hashes path->sha map (not a sha-value subset):
    # the engine must stage precisely the application sources the service pinned, by
    # absolute path, with the service's own snapshot hashes.
    staging_app = staging.get("application_source_hashes")
    record("staging_application_source_hashes_exact",
           isinstance(staging_app, dict) and staging_app == app_source_hash_map
           and all(isinstance(v, str) and _HEX64.fullmatch(v) for v in staging_app.values()))

    comparison = engine_report.get("comparison") if isinstance(engine_report.get("comparison"), dict) else {}
    record("comparison_status_passed", comparison.get("status") == ENGINE_COMPARISON_PASSED)
    record("comparison_flags_present_true", all(comparison.get(flag) is True for flag in _COMPARISON_PASS_FLAGS))
    record("comparison_covers_all_cases", comparison.get("total_cases") == len(cases))
    record("comparison_cases_match", _verify_comparison_cases(comparison, cases))

    tiv = engine_report.get("trusted_inputs_verification")
    tiv = tiv if isinstance(tiv, dict) else {}
    record("trusted_inputs_verified", tiv.get("verified") is True and tiv.get("declared_count") == declared_trusted_count)
    record("fresh_protected_native_build_false", engine_report.get("fresh_protected_native_build") is False)

    authentic = all(checks.values())
    if reason is None and not authentic:
        reason = "failed checks: " + ", ".join(sorted(k for k, v in checks.items() if not v))
    return {"authentic": authentic, "checks": checks, "reason": reason or ""}


def _verify_comparison_cases(comparison: dict, cases: list) -> bool:
    """The engine must report, for EACH service case, the exact expected
    returncode/stdout and matching original (baseline) AND protected observations.
    This proves the pass is an observed original-vs-protected equivalence, not a bare
    flag. stderr is recorded by the engine but never used for an equivalence claim
    here."""
    reported = comparison.get("cases")
    if not isinstance(reported, list) or len(reported) != len(cases):
        return False
    by_label = {}
    for rec in reported:
        if not isinstance(rec, dict) or not isinstance(rec.get("label"), str):
            return False
        if rec["label"] in by_label:
            return False
        by_label[rec["label"]] = rec
    for case in cases:
        rec = by_label.get(case["label"])
        if rec is None:
            return False
        if rec.get("args") != case["args"]:
            return False
        expect = rec.get("expect")
        if not isinstance(expect, dict) or expect.get("returncode") != case["expect"]["returncode"] \
                or expect.get("stdout") != case["expect"]["stdout"]:
            return False
        for arm in ("baseline", "protected"):
            obs = rec.get(arm)
            if not isinstance(obs, dict):
                return False
            if obs.get("returncode") != case["expect"]["returncode"] or obs.get("stdout") != case["expect"]["stdout"]:
                return False
        if rec.get("match") is not True:
            return False
    return True


def _receipt_clean(receipt) -> bool:
    """STRICT Windows-Job infrastructure-clean predicate over a FULL persisted raw
    process receipt (never flattened fallbacks). An empty/partial receipt is NOT
    clean. Requires: a real positive integer pid and an integer returncode (bool
    rejected for both); ``timed_out``/``cancelled`` exactly False; no ``error`` or
    ``post_cleanup_wait_error``; and a complete Windows-Job cleanup record
    (method=windows_job, job_assigned True, parent_pid==pid, parent_exit_confirmed
    True, active_after exactly int 0, status=assigned_job_empty, job_handle_closed
    True). A non-zero returncode is still clean -- fail-closed controls run cleanly
    yet exit non-zero; the caller checks returncode semantics separately."""
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


def _canon(path) -> str:
    """Canonical path key for equality/uniqueness (case-insensitive on Windows)."""
    return os.path.normcase(os.path.abspath(str(path)))


def _confined(path, engine_out: Path, label: str) -> Path:
    """Reserved-guard, require confinement under the engine output, and reject
    symlink/reparse/hardlink BEFORE any read. Returns the absolute path."""
    if not isinstance(path, str) or not path:
        raise NativeApplicationError(label + " path is missing")
    p = Path(os.path.abspath(path))
    _reserved_guard(str(p))
    if not p.is_relative_to(engine_out):
        raise NativeApplicationError(label + " is not confined under the engine output directory: " + str(p))
    _no_links(p)
    return p


def _read_pinned_receipt(receipt_path, receipt_sha, engine_out: Path, label: str) -> dict:
    """Read the FULL raw process receipt the inline entry pins, bound it to its
    persisted bytes (confined, non-link, bounded regular, re-hash == receipt_sha256)
    and parse it. The clean-ness predicate is then applied to THESE bytes, never to
    the inline command entry's own (unpinned) copy."""
    if not isinstance(receipt_sha, str) or not _HEX64.fullmatch(receipt_sha):
        raise NativeApplicationError(label + " has no valid receipt_sha256")
    p = _confined(receipt_path, engine_out, label + " receipt_path")
    data = _read(p, MAX_RECEIPT_BYTES)
    if _digest(data) != receipt_sha:
        raise NativeApplicationError(label + " persisted receipt bytes disagree with receipt_sha256")
    parsed = _json(data)
    if not isinstance(parsed, dict):
        raise NativeApplicationError(label + " persisted receipt is not a JSON object")
    return parsed


def _read_stdout_log(path, engine_out: Path, label: str) -> bytes:
    """Bounded confined read of a captured stdout log (0 bytes allowed, unlike the
    nonempty ``_read``), so an observation is derived from the ACTUAL child output
    rather than a returned boolean."""
    p = _confined(path, engine_out, label + " stdout_log")
    info = p.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise NativeApplicationError(label + " stdout_log is not a regular file")
    if info.st_size > MAX_STDOUT_LOG_BYTES:
        raise NativeApplicationError(label + " stdout_log exceeds the bounded size")
    with p.open("rb") as fh:
        data = fh.read(MAX_STDOUT_LOG_BYTES + 1)
    _no_links(p)
    if len(data) > MAX_STDOUT_LOG_BYTES:
        raise NativeApplicationError(label + " stdout_log grew while reading")
    return data


def _verify_child_evidence(engine_report, *, engine_out: Path, cases: list, required_prep: tuple) -> dict:
    """Authoritative, log/receipt-based verification of the child evidence.

    Independently proves -- never from returned booleans alone -- that:
      * ``comparison.commands`` holds EXACTLY the expected identities (per-case
        original+protected and the two fail-closed controls missing_core/unset_core);
        missing, duplicate or unknown identities fail;
      * every command AND preparation entry carries only allowed metadata, pins a
        FULL persisted raw receipt (confined + re-hashed) that is infrastructure-
        clean, and BINDS its ``stdout_log``/``stderr_log`` to that receipt's OWN
        ``stdout``/``stderr`` paths (canonical, confined) -- a genuine receipt paired
        with a different passing log fails;
      * every receipt and bound log path is UNIQUE across all comparison and
        preparation entries -- one executed child cannot back two identities;
      * each case's ORIGINAL and PROTECTED observed stdout (read from the bound logs)
        are byte-equal to each other AND to the contract's expected stdout, and the
        persisted returncodes equal the expected exit status;
      * each of the two controls ran infrastructure-clean yet exited NON-ZERO (the
        protected app fails closed with a missing/unset native core);
      * ``preparation_commands`` holds EXACTLY the language's required labels, each a
        clean pinned receipt with returncode EXACTLY int 0 (missing/unknown/duplicate
        or any nonzero exit fails).
    Never raises; returns ``{authentic, infra_failures, cancellations, coverage_ok,
    observations_ok, controls_ok, prep_ok, checks, reason}``.
    """
    engine_out = Path(os.path.abspath(engine_out))
    infra, cancellations, reasons = [], [], []
    checks = {}
    seen_paths = set()          # canonical receipt + bound-log paths; GLOBAL uniqueness

    def note(name, ok, msg=None):
        checks[name] = bool(ok)
        if not ok and msg:
            reasons.append(msg)
        return bool(ok)

    def miss(label, reason):
        infra.append({"label": label, "reason": reason})

    def register(label, role, value):
        """Register a canonical path and flag any reuse across ALL entries."""
        key = _canon(value)
        if key in seen_paths:
            miss(label, role + " path is reused across entries: " + str(value))
            return False
        seen_paths.add(key)
        return True

    def bind_and_register(entry, lbl):
        """Pin the receipt; bind stdout_log/stderr_log to the receipt's OWN
        stdout/stderr (confined, canonical-equal); register receipt + both log paths
        for global uniqueness. Returns (parsed_or_None, stdout_log_or_None, ok)."""
        try:
            parsed = _read_pinned_receipt(entry.get("receipt_path"), entry.get("receipt_sha256"), engine_out, lbl)
        except Exception as exc:  # noqa: BLE001
            miss(lbl, "receipt pin/read failed: " + type(exc).__name__ + ": " + str(exc)[:200])
            return None, None, False
        ok = register(lbl, "receipt_path", entry.get("receipt_path"))
        stdout_log = None
        for key, rkey in (("stdout_log", "stdout"), ("stderr_log", "stderr")):
            val, rval = entry.get(key), parsed.get(rkey)
            if not isinstance(val, str) or not val:
                miss(lbl, "missing " + key); ok = False; continue
            try:
                _confined(val, engine_out, lbl + " " + key)
            except Exception as exc:  # noqa: BLE001
                miss(lbl, key + " not confined: " + type(exc).__name__); ok = False; continue
            if not isinstance(rval, str) or _canon(val) != _canon(rval):
                miss(lbl, key + " is not bound to the receipt's own " + rkey + " path"); ok = False; continue
            if not register(lbl, key, val):
                ok = False
            elif key == "stdout_log":
                stdout_log = val
        return parsed, stdout_log, ok

    if not isinstance(engine_report, dict) or not isinstance(engine_report.get("comparison"), dict):
        miss(None, "comparison block missing")
        return {"authentic": False, "infra_failures": infra, "cancellations": cancellations,
                "coverage_ok": False, "observations_ok": False, "controls_ok": False, "prep_ok": False,
                "checks": {"comparison_present": False}, "reason": "comparison block missing"}
    comparison = engine_report["comparison"]
    commands = comparison.get("commands")
    expected = _expected_command_labels(cases)

    coverage_ok = True
    if not isinstance(commands, list) or not commands:
        note("commands_present", False, "comparison.commands is empty or not a list")
        miss(None, "comparison.commands is empty or not a list")
        coverage_ok = False
        commands = []
    else:
        note("commands_present", True)
    if len(commands) > MAX_COMMAND_RECEIPTS:
        note("commands_bounded", False, "too many command receipts")
        coverage_ok = False
        commands = commands[:MAX_COMMAND_RECEIPTS]
    else:
        note("commands_bounded", True)

    cmd_map, dups = {}, set()
    receipts = {}       # label -> parsed persisted receipt
    stdout_bytes = {}   # label -> captured stdout bytes (from the bound log)
    for entry in commands:
        if not isinstance(entry, dict) or not isinstance(entry.get("label"), str) or not entry["label"]:
            coverage_ok = False
            miss(None, "malformed command entry")
            continue
        lbl = entry["label"]
        if lbl in cmd_map:
            dups.add(lbl)
            continue
        cmd_map[lbl] = entry
    present = set(cmd_map)
    note("no_duplicate_commands", not dups, "duplicate command identities: " + ", ".join(sorted(dups)))
    unknown = sorted(present - expected)
    missing = sorted(expected - present)
    note("no_unknown_commands", not unknown, "unknown command identities: " + ", ".join(unknown))
    note("complete_command_coverage", not missing, "missing command identities: " + ", ".join(missing))
    for u in unknown:
        miss(u, "unknown command identity")
    for m in missing:
        miss(m, "missing required command identity")
    if dups or unknown or missing:
        coverage_ok = False

    # Per-entry: EXACTLY the 9 metadata keys (every identity field present, unused
    # ones explicitly None), consistent identity tokens, pinned clean receipt,
    # stdout/stderr bound to the receipt's own logs, unique paths.
    clean_ok = True
    for lbl, entry in cmd_map.items():
        if set(entry) != _COMMAND_META_KEYS:
            clean_ok = False
            miss(lbl, "command entry metadata must be EXACTLY the 9 keys "
                      + ", ".join(sorted(_COMMAND_META_KEYS)))
        kind = entry.get("kind")
        if lbl in _CONTROL_LABELS:
            # A control carries its control token; arm and case_label are unused -> None.
            if kind != "control" or entry.get("control") not in _CONTROL_SHORT \
                    or lbl != "control:" + str(entry.get("control")) \
                    or entry.get("arm") is not None or entry.get("case_label") is not None:
                clean_ok = False
                miss(lbl, "control entry identity is inconsistent (arm/case_label must be None)")
        elif lbl in expected:
            # A case arm carries arm + case_label; control is unused -> None.
            if kind != "case_arm" or entry.get("arm") not in _COMMAND_ARMS \
                    or not isinstance(entry.get("case_label"), str) \
                    or lbl != "case:%s:%s" % (entry.get("case_label"), entry.get("arm")) \
                    or entry.get("control") is not None:
                clean_ok = False
                miss(lbl, "case arm entry identity is inconsistent (control must be None)")
        parsed, stdout_log, bound_ok = bind_and_register(entry, lbl)
        if parsed is None:
            clean_ok = False
            continue
        if not bound_ok:
            clean_ok = False
        if parsed.get("cancelled") is True:
            cancellations.append(lbl)
        if not _receipt_clean(parsed):
            clean_ok = False
            miss(lbl, "persisted receipt is not infrastructure-clean")
        receipts[lbl] = parsed
        if entry.get("arm") in _COMMAND_ARMS and stdout_log is not None:
            try:
                stdout_bytes[lbl] = _read_stdout_log(stdout_log, engine_out, lbl)
            except Exception as exc:  # noqa: BLE001
                clean_ok = False
                miss(lbl, "stdout_log read failed: " + type(exc).__name__ + ": " + str(exc)[:200])
    note("all_command_receipts_clean", clean_ok)

    # Observations derived from the receipt-bound logs + persisted exit codes.
    observations_ok = True
    for case in cases:
        lo = "case:%s:original" % case["label"]
        lp = "case:%s:protected" % case["label"]
        if lo not in receipts or lp not in receipts or lo not in stdout_bytes or lp not in stdout_bytes:
            observations_ok = False
            continue
        exp_out = case["expect"]["stdout"].encode("utf-8")
        exp_rc = case["expect"]["returncode"]
        orc = receipts[lo].get("returncode")
        prc = receipts[lp].get("returncode")
        if not (stdout_bytes[lo] == exp_out and stdout_bytes[lp] == exp_out
                and stdout_bytes[lo] == stdout_bytes[lp] and orc == exp_rc and prc == exp_rc):
            observations_ok = False
            miss(None, "observed original/protected stdout/exit disagree with the contract for case " + case["label"])
    note("observations_match_logs", observations_ok)

    # Controls: infrastructure-clean yet exit NON-ZERO (fail closed).
    controls_ok = True
    for lbl in _CONTROL_LABELS:
        parsed = receipts.get(lbl)
        if parsed is None:
            controls_ok = False
            continue
        rc = parsed.get("returncode")
        if isinstance(rc, bool) or not isinstance(rc, int) or rc == 0:
            controls_ok = False
            miss(lbl, "fail-closed control did not exit non-zero")
    note("controls_fail_closed", controls_ok)

    # preparation_commands: EXACTLY the language's required labels, each clean pinned
    # receipt with returncode exactly int 0, logs bound to the receipt, unique.
    prep_ok = True
    prep = engine_report.get("preparation_commands")
    if not isinstance(prep, list):
        prep_ok = False
        note("preparation_present", False, "preparation_commands missing or not a list")
        miss(None, "preparation_commands missing or not a list")
        prep = []
    else:
        note("preparation_present", True)
    if len(prep) > MAX_PREP_RECEIPTS:
        prep_ok = False
        note("preparation_bounded", False, "too many preparation receipts")
        prep = prep[:MAX_PREP_RECEIPTS]
    prep_map, prep_dups = {}, set()
    for entry in prep:
        if not isinstance(entry, dict) or not isinstance(entry.get("label"), str) or not entry["label"]:
            prep_ok = False
            miss(None, "malformed preparation entry")
            continue
        lbl = entry["label"]
        if lbl in prep_map:
            prep_dups.add(lbl)
            continue
        prep_map[lbl] = entry
    required_prep_set = set(required_prep)
    prep_present = set(prep_map)
    prep_unknown = sorted(prep_present - required_prep_set)
    prep_missing = sorted(required_prep_set - prep_present)
    note("preparation_exact_labels", not (prep_dups or prep_unknown or prep_missing),
         "preparation labels must be exactly %s (dups=%s unknown=%s missing=%s)"
         % (sorted(required_prep_set), sorted(prep_dups), prep_unknown, prep_missing))
    for d in sorted(prep_dups):
        miss(d, "duplicate preparation identity")
    for u in prep_unknown:
        miss(u, "unknown preparation identity")
    for m in prep_missing:
        miss(m, "missing required preparation identity")
    if prep_dups or prep_unknown or prep_missing:
        prep_ok = False
    for lbl in sorted(required_prep_set & prep_present):
        entry = prep_map[lbl]
        extra = set(entry) - _PREP_META_KEYS
        if extra:
            prep_ok = False
            miss(lbl, "preparation entry has non-metadata keys: " + ", ".join(sorted(extra)))
        parsed, _unused, bound_ok = bind_and_register(entry, lbl)
        if parsed is None:
            prep_ok = False
            continue
        if not bound_ok:
            prep_ok = False
        if parsed.get("cancelled") is True:
            cancellations.append(lbl)
        if not _receipt_clean(parsed):
            prep_ok = False
            miss(lbl, "preparation receipt is not infrastructure-clean")
        rc = parsed.get("returncode")
        if isinstance(rc, bool) or not isinstance(rc, int) or rc != 0:
            prep_ok = False
            miss(lbl, "preparation child did not exit 0")
    note("preparation_clean", prep_ok)

    authentic = bool(coverage_ok and clean_ok and observations_ok and controls_ok and prep_ok and not infra)
    reason = "" if authentic else "; ".join(reasons) or "child evidence verification failed"
    return {"authentic": authentic, "infra_failures": infra, "cancellations": sorted(set(cancellations)),
            "coverage_ok": coverage_ok, "observations_ok": observations_ok, "controls_ok": controls_ok,
            "prep_ok": prep_ok, "checks": checks, "reason": reason}


def _classify_child_issues(child_evidence: dict) -> dict:
    """Shape the child-evidence verdict into the stable public result keys. Any
    infrastructure failure, cancellation or observation/coverage/control/prep defect
    is surfaced so the pass gate can exclude ALL child issues."""
    infra = child_evidence.get("infra_failures") or []
    cancellations = child_evidence.get("cancellations") or []
    mismatch = not (child_evidence.get("coverage_ok") and child_evidence.get("observations_ok")
                    and child_evidence.get("controls_ok") and child_evidence.get("prep_ok"))
    return {"child_infrastructure_failures": infra, "child_cancellations": cancellations,
            "comparison_mismatch": bool(mismatch)}


def _base_pins_unchanged(base_trusted_inputs) -> bool:
    """Re-verify every original base trusted pin (source plan/result/report, spec,
    contract, application sources, producer scalar-ABI contract and service modules)
    against on-disk bytes with a bounded read. Returns False on any missing/changed
    pin; never refreshes a hash."""
    for rec in base_trusted_inputs:
        try:
            if _digest(_read(Path(rec["path"]), MAX_PROJECT_BYTES)) != rec["sha256"]:
                return False
        except Exception:
            return False
    return True


def _example_args(cases) -> list:
    return [str(a) for a in cases[0].get("args", [])] if cases else []


def _launch_instructions(bundle: dict, cases) -> list:
    """Generic launch guidance; example arguments come from an explicit contract
    case, never a hardcoded seed/rounds pair. All paths are bundle-relative so the
    relocation harness can run the bundle from any directory."""
    example = _example_args(cases)
    example_str = " ".join('"%s"' % a for a in example) if example else "<app-defined arguments>"
    exe = bundle["executable"].replace("/", "\\")
    core = bundle["native_core"]
    lines = [
        "Run the protected application from the deployment bundle directory: " + bundle["path"],
        "Bind the native core to the bundled protected DLL (absolute path); there is no "
        "default/search-path fallback:",
        "  (cmd)        set %s=%%CD%%\\%s" % (NATIVE_CORE_ENV, core.replace("/", "\\")),
        "  (PowerShell) $env:%s = (Resolve-Path '%s')" % (NATIVE_CORE_ENV, core),
    ]
    if bundle["runtime_files"]:
        lines.append("Keep the packaged runtime DLLs beside the executable (Windows DLL search): "
                     + ", ".join(bundle["runtime_files"]))
    lines += [
        "Launch the executable with its application-defined arguments "
        "(see application-contract.json cases):",
        "  .\\%s %s" % (exe, example_str),
        "The arguments above are an example taken from the contract's first case; argument "
        "meaning is application-defined, not a fixed seed/rounds pair.",
        "The application fails closed if %s is unset or the target DLL is absent; there is no "
        "original-algorithm fallback." % (NATIVE_CORE_ENV,),
    ]
    return lines


def integrate_source_application(service, plan_id, integration_spec_path, contract_path,
                                 *, timeout_seconds=120):
    """Explicitly compile/run an owned Go/Swift application around its reviewed native
    core and package a deployable protected bundle.

    ``service`` is an existing ``ProjectService``; ``plan_id`` names a successful
    ``go_typed_native`` or ``swift_llvm_native`` source build. The integration spec
    and application contract must be owned regular files already inside the planned
    project's directory (fingerprinted snapshot members). Returns a compact public
    report (full evidence is retained on disk). This action executes the application;
    it is NOT a build-only step.
    """
    # Timeout is validated with NO filesystem access first (preserved contract).
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
        raise NativeApplicationError("timeout_seconds must be an integer in 1..600")

    root = service.root
    directory = service._directory(plan_id)      # validates plan id format and existence

    with _job_lock(directory):
        # -- 1. Rebind the existing successful source plan / result / build report --
        result_bytes = _read(directory / "result.json", MAX_PROJECT_BYTES)
        result = _json(result_bytes)
        if not isinstance(result, dict) or result.get("status") != "artifact_created_unvalidated":
            raise NativeApplicationError("source plan has no successful artifact to integrate")
        backend = result.get("backend")
        if backend not in _NATIVE_BACKENDS:
            raise NativeApplicationError(
                "source-integrate supports only go/go_typed_native or swift/swift_llvm_native; "
                "refusing backend %r" % (backend,))

        plan_bytes = _read(directory / "plan.json", MAX_PROJECT_BYTES)
        plan = _json(plan_bytes)
        fingerprint = result.get("fingerprint")
        if (not isinstance(plan, dict) or not isinstance(fingerprint, str)
                or _digest(_encoded(plan)) != fingerprint
                or plan.get("plan_id") != plan_id or result.get("plan_id") != plan_id
                or plan.get("workspace_root") != str(root)
                or plan.get("kind") != PLAN_KIND
                or not isinstance(plan.get("inputs"), list)
                or not isinstance(plan.get("inspection"), dict)
                or not isinstance(plan.get("toolchain"), dict)):
            raise NativeApplicationError("source plan does not bind this native build result")

        report_path = directory / "build" / "report.json"
        report_bytes = _read(report_path, MAX_PROJECT_BYTES)
        report = _json(report_bytes)
        if (not isinstance(report, dict) or report.get("backend") != backend
                or report.get("status") != "artifact_created_unvalidated"):
            raise NativeApplicationError("build report is not a successful native artifact")
        if (not isinstance(result.get("build_report_sha256"), str)
                or _digest(report_bytes) != result["build_report_sha256"]
                or report.get("artifacts") != result.get("artifacts")
                or report.get("coverage") != result.get("coverage")):
            raise NativeApplicationError("build report no longer matches the source plan result (refusing silent repinning)")
        if plan.get("inspection") != report.get("project"):
            raise NativeApplicationError("source plan inspection does not match the build report project metadata")
        artifacts = result.get("artifacts")
        if not isinstance(artifacts, dict) or not {"baseline", "protected"} <= set(artifacts):
            raise NativeApplicationError("native build result is missing baseline/protected artifacts")
        prot = artifacts.get("protected") if isinstance(artifacts.get("protected"), dict) else {}
        protected_sha = prot.get("sha256")
        if not isinstance(protected_sha, str) or not _HEX64.fullmatch(protected_sha):
            raise NativeApplicationError("native build result has no valid protected native pin")

        # -- 2. app_dir = planned project parent; recompute snapshot + toolchain BEFORE --
        project_path = plan.get("project_path")
        if not isinstance(project_path, str):
            raise NativeApplicationError("source plan has no project path")
        _reserved_guard(project_path)
        _guard_saved_plan_paths(plan)
        source = service._owned(project_path)
        if report.get("project", {}).get("project_path") != str(source):
            raise NativeApplicationError("build report project path does not match the plan project")
        app_dir = source.parent
        inspection = plan["inspection"]
        language = inspection.get("language")
        if language not in _LANGUAGES:
            raise NativeApplicationError("bound producer language is not go/swift")
        if backend != _BACKEND_BY_LANGUAGE.get(language):
            raise NativeApplicationError(
                "bound producer backend %r does not match language %r" % (backend, language))
        _guarded_preflight(service, app_dir, plan["toolchain"], inspection)
        snapshot_before = service._snapshot(source, inspection)
        if snapshot_before != plan["inputs"]:
            raise NativeApplicationError("planned project source tree changed before integration")
        toolchain_before = service._toolchain(inspection)
        if toolchain_before != plan["toolchain"]:
            raise NativeApplicationError("source toolchain changed before integration")
        snapshot_paths = {rec["path"] for rec in snapshot_before if isinstance(rec, dict) and "path" in rec}
        snapshot_sha = {rec["path"]: rec["sha256"] for rec in snapshot_before
                        if isinstance(rec, dict) and "path" in rec and "sha256" in rec}
        # The core source identities (must not overlap the application sources).
        core_sources = set()
        for s in inspection.get("sources") or []:
            if isinstance(s, str):
                core_sources.add(str(service._owned(s)))

        # -- 2b. Independently AUTHENTICATE the producer scalar-ABI contract and the
        #        native build origin from disk BEFORE the engine (a syntax-only pin is
        #        insufficient): the contract file's ACTUAL bytes must match the claimed
        #        frontend hash (Go frontend_artifact_hashes[contract.json] + inline
        #        contract equality; Swift artifact_hashes[frontend/contract.json]), the
        #        contract schema must agree with the project exports, and native_report
        #        must be confined, byte-hash-equal to its pin, a successful build whose
        #        artifacts equal the producer's, whose VM coverage agrees, and whose
        #        selected closure covers the lowered roots/helpers and exports. --
        producer_origin = _authenticate_producer_origin(report, directory=directory,
                                                        language=language, inspection=inspection)
        contract_abspath = Path(producer_origin["contract_path"])
        producer_contract_sha = producer_origin["contract_sha256"]
        report_native_report = producer_origin["native_report_path"]
        report_native_report_sha = producer_origin["native_report_sha256"]

        # -- 3. Validate integration spec (reserved guard BEFORE stat; snapshot pin equality) --
        spec_path = _owned_app_file(service, integration_spec_path, app_dir, "integration spec", snapshot_paths)
        contract_file = _owned_app_file(service, contract_path, app_dir, "application contract", snapshot_paths)
        if spec_path == contract_file:
            raise NativeApplicationError("integration spec and application contract must be distinct files")
        spec_bytes = _read(spec_path, MAX_JSON_BYTES)
        if _digest(spec_bytes) != snapshot_sha.get(str(spec_path)):
            raise NativeApplicationError("integration spec bytes differ from the original plan snapshot pin")
        spec = _validate_integration_spec(_json(spec_bytes), plan_language=language)

        # -- 4. Validate the explicit application-sample contract + cases (BEFORE any child) --
        contract_bytes = _read(contract_file, MAX_JSON_BYTES)
        if _digest(contract_bytes) != snapshot_sha.get(str(contract_file)):
            raise NativeApplicationError("application contract bytes differ from the original plan snapshot pin")
        cases = _validate_app_contract(_json(contract_bytes))

        # -- 5. Real defense STOP (no implicit execution) --
        stop = root / ".runs" / "defense-loop" / "STOP"
        if stop.exists():
            return {"status": "cancelled", "reason": "defense STOP exists",
                    "plan_id": plan_id, "integration_id": None}

        # -- 6. Unique integration id inside the locked source job --
        integration_id = "integration-" + uuid.uuid4().hex[:12]
        integ_dir = directory / integration_id
        _no_links(integ_dir)
        if integ_dir.exists():
            raise NativeApplicationError("integration directory already exists; retry")
        integ_dir.mkdir()
        engine_out = integ_dir / "engine"
        engine_report_path = engine_out / "integration.json"

        # -- 7. BASE trusted-input pins (path + sha256 + role), all under workspace. --
        base_trusted_inputs = [
            {"path": str(directory / "plan.json"), "sha256": _digest(plan_bytes), "role": "source_plan"},
            {"path": str(directory / "result.json"), "sha256": _digest(result_bytes), "role": "source_result"},
            {"path": str(report_path), "sha256": _digest(report_bytes), "role": "source_build_report"},
            {"path": str(contract_abspath), "sha256": producer_contract_sha, "role": "producer_contract"},
            {"path": report_native_report, "sha256": report_native_report_sha, "role": "producer_native_report"},
            {"path": str(spec_path), "sha256": _digest(spec_bytes), "role": "integration_spec"},
            {"path": str(contract_file), "sha256": _digest(contract_bytes), "role": "application_contract"},
        ]
        # Application sources: resolved RELATIVE TO THE SPEC'S OWN PARENT directory
        # (exactly as the engine does), NOT app_dir -- the spec may live in a project
        # subdirectory. Each resolved file must still be owned, link-free, contained
        # WITHIN the planned project tree, a fingerprinted-snapshot member with pin
        # equality, of the correct extension, and NOT overlapping a protected core
        # source (the app calls the core; it is not the core).
        spec_dir = spec_path.parent
        app_source_pins = []
        app_source_hash_map = {}
        for rel in spec["application_sources"]:
            src = service._owned(str(spec_dir / rel))
            key = str(src)
            if not src.is_relative_to(app_dir):
                raise NativeApplicationError("application source escapes the planned project directory: " + rel)
            if key in core_sources:
                raise NativeApplicationError("application source overlaps a protected core source: " + rel)
            if key not in snapshot_sha:
                raise NativeApplicationError("application source is not part of the fingerprinted plan snapshot: " + rel)
            _no_links(src)
            if not src.is_file():
                raise NativeApplicationError("application source must be a regular project file: " + rel)
            sha = _digest(_read(src, MAX_SOURCE_BYTES))
            if sha != snapshot_sha[key]:
                raise NativeApplicationError("application source changed from the planned snapshot pin: " + rel)
            if key in app_source_hash_map:
                raise NativeApplicationError("application source resolves to a duplicate file: " + rel)
            base_trusted_inputs.append({"path": key, "sha256": sha, "role": "application_source"})
            app_source_pins.append({"path": key, "relative_path": rel, "sha256": sha})
            app_source_hash_map[key] = sha
        for mod in _SERVICE_MODULE_FILES:
            module_path = Path(__file__).with_name(mod)
            _no_links(module_path)
            if not module_path.is_file():
                raise NativeApplicationError("owned service module missing: " + mod)
            base_trusted_inputs.append({"path": str(module_path), "sha256": _digest(_read(module_path, MAX_SOURCE_BYTES)),
                                        "role": "service_module"})

        # -- 8. Append-only integration plan (source/contract/spec + all execution fields). --
        plan_record = {
            "schema_version": 1, "kind": "native_application_integration_plan",
            "plan_id": plan_id, "integration_id": integration_id, "language": language, "backend": backend,
            "workspace_root": str(root), "project_path": str(source), "app_dir": str(app_dir),
            "source_plan": {"path": str(directory / "plan.json"), "sha256": _digest(plan_bytes),
                            "fingerprint": fingerprint},
            "source_result": {"path": str(directory / "result.json"), "sha256": _digest(result_bytes)},
            "source_build_report": {"path": str(report_path), "sha256": result["build_report_sha256"]},
            "producer_contract": {"path": str(contract_abspath), "sha256": producer_contract_sha},
            "native_report": {"path": report_native_report, "sha256": report_native_report_sha},
            "integration_spec": {"path": str(spec_path), "sha256": _digest(spec_bytes),
                                 "application_sources": list(spec["application_sources"])},
            "application_contract": {"path": str(contract_file), "sha256": _digest(contract_bytes),
                                     "kind": APPLICATION_CONTRACT_KIND, "total_cases": len(cases)},
            "application_source_pins": app_source_pins,
            "cases": cases,
            "artifacts": artifacts, "coverage": result.get("coverage"),
            "protected_native_sha256": protected_sha,
            "snapshot_before_sha256": _digest(_encoded(snapshot_before)),
            "toolchain_before_sha256": _digest(_encoded(toolchain_before)),
            "trusted_input_pins": base_trusted_inputs,
            "engine_module": ENGINE_MODULE,
            "engine_out_dir": str(engine_out),
            "timeout_seconds": timeout_seconds,
            "reused_native_core": True, "fresh_protected_native_build": False,
            "executes_application": True, "publishes": False, "stop_marker": str(stop),
            "limitations": [
                "Explicit application execution step; not an implicit part of source plan/build.",
                "Native core is the reused pinned producer artifact re-verified from disk, not a fresh build.",
                "Generated facade/binding sources keep original core identities; original core "
                "source/object/library/baseline/reference BYTES are not shipped.",
                "Neither runtime uses an external adapter DLL; controls are missing-core and unset-core only.",
                "Bounded owned child processes with Windows Job cleanup; cleanup is not an atomic sandbox.",
                "Sampled functional equivalence over explicit cases; performance/defense/attack not_evaluated.",
            ],
        }
        plan_record["integration_plan_fingerprint"] = _digest(_encoded(plan_record))
        plan_file = integ_dir / "integration-plan.json"
        plan_file_bytes = _create_json(plan_file, plan_record)
        plan_file_sha = _digest(plan_file_bytes)

        # Engine trusted-input list = base pins + the just-saved integration plan hash.
        engine_trusted_inputs = base_trusted_inputs + [
            {"path": str(plan_file), "sha256": plan_file_sha, "role": "integration_plan"}]

        # -- 9. Drive the trusted engine (path-based keyword seam) --
        execution_error = None
        engine_report = None
        try:
            engine = _load_engine()
            _require_engine_api(engine)
            engine_report = engine.run_integration(
                producer_report_path=str(report_path),
                integration_spec_path=str(spec_path),
                application_contract_path=str(contract_file),
                output_dir=str(engine_out),
                workspace_root=str(root),
                timeout_seconds=timeout_seconds,
                trusted_inputs=engine_trusted_inputs)
            if not isinstance(engine_report, dict):
                raise NativeApplicationError("engine run_integration returned a non-dict report")
        except Exception as exc:    # capture execution-phase failures (incl. child failures)
            execution_error = type(exc).__name__ + ": " + str(exc)[:2048]

        # -- 10. Recompute snapshot + toolchain + pins AFTER execution (reject silent drift) --
        snapshot_after = toolchain_after = None
        try:
            _guarded_preflight(service, app_dir, plan["toolchain"], inspection)
            snapshot_after = service._snapshot(source, inspection)
            toolchain_after = service._toolchain(inspection)
        except Exception as exc:
            execution_error = execution_error or ("post-recompute failed: " + type(exc).__name__ + ": " + str(exc)[:512])
        try:
            pins_unchanged = (_digest(_read(report_path, MAX_PROJECT_BYTES)) == result["build_report_sha256"]
                              and _digest(_read(directory / "result.json", MAX_PROJECT_BYTES)) == _digest(result_bytes)
                              and _digest(_read(directory / "plan.json", MAX_PROJECT_BYTES)) == _digest(plan_bytes))
        except Exception:
            pins_unchanged = False
        original_unchanged = bool(snapshot_after == plan["inputs"] and toolchain_after == toolchain_before
                                  and pins_unchanged)

        # -- 11. Authenticate the engine report + recheck the saved plan --
        engine_status = engine_report.get("status") if isinstance(engine_report, dict) else None
        engine_report_sha256 = None
        if engine_report_path.is_file():
            try:
                engine_report_sha256 = _digest(_read(engine_report_path, MAX_PROJECT_BYTES))
            except Exception:
                engine_report_sha256 = None
        fresh_flag = engine_report.get("fresh_protected_native_build") if isinstance(engine_report, dict) else False

        report_verification = {"authentic": False, "checks": {}, "reason": "engine execution did not complete"}
        child_evidence = {"authentic": False, "infra_failures": [{"label": None, "reason": "engine execution did not complete"}],
                          "cancellations": [], "coverage_ok": False, "observations_ok": False,
                          "controls_ok": False, "prep_ok": False, "checks": {},
                          "reason": "engine execution did not complete"}
        required_prep = _REQUIRED_PREP_LABELS[language]
        if execution_error is None:
            report_verification = _verify_engine_report(
                engine_report, engine_report_path, report_path=report_path, report_sha=_digest(report_bytes),
                artifacts=artifacts, cases=cases, language=language,
                declared_trusted_count=len(engine_trusted_inputs), source_report=report,
                contract_path=str(contract_abspath), contract_sha=producer_contract_sha,
                app_source_hash_map=app_source_hash_map)
            # Independent, log/receipt-based child evidence (never returned booleans
            # alone): exact command coverage, full clean pinned receipts, original-
            # vs-protected observations read from the captured logs, two fail-closed
            # controls, and clean pinned preparation receipts.
            child_evidence = _verify_child_evidence(engine_report, engine_out=engine_out, cases=cases,
                                                    required_prep=required_prep)
        try:
            plan_unchanged = _digest(_read(plan_file, MAX_PROJECT_BYTES)) == plan_file_sha
        except Exception:
            plan_unchanged = False

        stop_now = stop.exists()
        child_issues = _classify_child_issues(child_evidence)
        # A pass must rest on the authenticated report, the independently verified
        # child evidence, AND the exclusion of ALL child issues (infrastructure
        # failures, cancellations, coverage/observation/control/prep mismatches) --
        # never on the engine's flattened comparison flags alone.
        passed = bool(execution_error is None and report_verification["authentic"]
                      and child_evidence["authentic"]
                      and engine_status == ENGINE_STATUS_PASSED
                      and fresh_flag is False and original_unchanged and plan_unchanged and not stop_now
                      and not child_issues["child_infrastructure_failures"]
                      and not child_issues["comparison_mismatch"])

        # -- 12. Inventory the engine-owned deployable bundle (only on a clean, authenticated pass) --
        deployment_bundle = launch_instructions = None
        package_error = None
        post_package_recheck = None
        if passed:
            try:
                bundle = _inventory_bundle(
                    engine_report, engine_out=engine_out, artifacts=artifacts,
                    expected_native_sha=protected_sha, source_report=report, language=language)
                # Post-inventory rechecks must not leave a success standing on drift/STOP.
                _guarded_preflight(service, app_dir, plan["toolchain"], inspection)
                post_package_recheck = {
                    "stop_absent": not stop.exists(),
                    "plan_unchanged": _digest(_read(plan_file, MAX_PROJECT_BYTES)) == plan_file_sha,
                    "build_report_unchanged": _digest(_read(report_path, MAX_PROJECT_BYTES)) == result["build_report_sha256"],
                    "base_pins_unchanged": _base_pins_unchanged(base_trusted_inputs),
                    "snapshot_unchanged": service._snapshot(source, inspection) == plan["inputs"],
                    "toolchain_unchanged": service._toolchain(inspection) == plan["toolchain"],
                    "engine_report_unchanged": engine_report_path.is_file()
                        and _digest(_read(engine_report_path, MAX_PROJECT_BYTES)) == engine_report_sha256,
                }
                if not all(post_package_recheck.values()):
                    raise NativeApplicationError(
                        "post-package recheck detected drift/STOP: "
                        + ", ".join(sorted(k for k, v in post_package_recheck.items() if not v)))
                launch_instructions = _launch_instructions(bundle, cases)
                deployment_bundle = bundle
            except Exception as exc:
                package_error = type(exc).__name__ + ": " + str(exc)[:2048]
                passed = False
                deployment_bundle = launch_instructions = None

        # -- 13. Status string + append-only service result + compact public return --
        stop_now = stop_now or stop.exists()
        status = "cancelled" if stop_now else (PUBLIC_STATUS_PASSED if passed else "failed")
        if status != PUBLIC_STATUS_PASSED:
            deployment_bundle = launch_instructions = None

        result_record = {
            "schema_version": 1, "kind": "native_application_integration_result",
            "status": status, "plan_id": plan_id, "integration_id": integration_id,
            "language": language, "backend": backend,
            "engine_module": ENGINE_MODULE, "engine_status": engine_status,
            "engine_report_path": str(engine_report_path) if engine_report_path.is_file() else None,
            "engine_report_sha256": engine_report_sha256,
            "engine_report_verification": report_verification,
            "child_evidence_verification": {k: child_evidence[k] for k in
                ("authentic", "coverage_ok", "observations_ok", "controls_ok", "prep_ok", "checks", "reason")},
            "integration_plan_path": str(plan_file), "integration_plan_sha256": plan_file_sha,
            "integration_plan_fingerprint": plan_record["integration_plan_fingerprint"],
            "integration_plan_unchanged_after_run": plan_unchanged,
            "producer_contract": plan_record["producer_contract"],
            "native_report": plan_record["native_report"],
            "integration_spec": plan_record["integration_spec"],
            "application_contract": plan_record["application_contract"],
            "total_cases": len(cases),
            "reused_native_core": True, "fresh_protected_native_build": fresh_flag,
            "original_inputs_unchanged": original_unchanged,
            "snapshot_after_sha256": (_digest(_encoded(snapshot_after)) if snapshot_after is not None else None),
            "toolchain_after_sha256": (_digest(_encoded(toolchain_after)) if toolchain_after is not None else None),
            "post_package_recheck": post_package_recheck,
            "deployment_bundle": deployment_bundle, "launch_instructions": launch_instructions,
            "comparison_summary": _comparison_summary(engine_report),
            "child_infrastructure_failures": child_issues["child_infrastructure_failures"],
            "child_cancellations": child_issues["child_cancellations"],
            "comparison_mismatch": child_issues["comparison_mismatch"],
            "execution_error": execution_error, "package_error": package_error, "stop_observed": stop_now,
            "external_attack_evaluation": "not_evaluated", "performance_evaluation": "not_evaluated",
            "defense_strength_evaluation": "not_evaluated", "public_route": PUBLIC_ROUTE,
        }
        result_file = integ_dir / "integration-result.json"
        result_file_bytes = _create_json(result_file, result_record)

        return {
            "status": status, "plan_id": plan_id, "integration_id": integration_id,
            "language": language, "backend": backend,
            "integration_report_path": str(result_file),
            "integration_report_sha256": _digest(result_file_bytes),
            "integration_plan_path": str(plan_file), "integration_plan_sha256": plan_file_sha,
            "engine_report_path": result_record["engine_report_path"],
            "engine_report_sha256": engine_report_sha256, "engine_status": engine_status,
            "engine_report_authentic": report_verification["authentic"],
            "child_evidence_authentic": child_evidence["authentic"],
            "deployment_bundle": deployment_bundle, "launch_instructions": launch_instructions,
            "total_cases": len(cases),
            "reused_native_core": True, "fresh_protected_native_build": fresh_flag,
            "original_inputs_unchanged": original_unchanged,
            "comparison_mismatch": child_issues["comparison_mismatch"],
            "external_attack_evaluation": "not_evaluated", "performance_evaluation": "not_evaluated",
            "defense_strength_evaluation": "not_evaluated", "public_route": PUBLIC_ROUTE,
        }
