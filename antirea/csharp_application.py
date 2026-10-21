"""Public C# application-integration seam for :class:`antirea.projects.ProjectService`.

This binds an already-reviewed C# source build (the "producer": a successful
``dotnet_il_native`` source-plan/source-build that lowered selected scalar integer
leaves into a protected native core) to its ordinary managed caller/UI, then
EXPLICITLY compiles and runs that managed application -- original vs protected --
over an explicit application-sample contract, and packages a minimal deployable
bundle (the compiled protected managed DLL + its runtimeconfig + the reused pinned
native core DLL).

It is a distinct, explicit execution step -- never an implicit part of plan/build.
Only ``csharp``/``dotnet_il_native`` is supported here; any other backend is
rejected cleanly without touching its routes.

The heavy lifting (plan -> serialize -> load -> prepare -> validate, the
byte-preserving source transform, tamper-evident staging, and bounded owned child
processes with Windows Job cleanup) is performed by the owned trusted engine module
:mod:`antirea.csharp_app_integration`, loaded lazily BY TRUSTED NAME only. This
module owns the public service contract: it binds the existing source
plan/result/report, recomputes the source toolchain and project snapshot before
and after execution, validates the explicit application-sample contract, threads a
service ``trusted_inputs`` seam into the engine, and assembles the deployable
bundle with an exact file allowlist and pins.

Scope / non-claims (fail closed, never overclaim):
  * The native core is REUSED from the pinned producer artifact and re-verified
    from disk; it is NOT freshly built here (``fresh_protected_native_build`` is
    always False), even when the producer was built moments earlier.
  * Bounded owned child processes with Windows Job cleanup are cleanup evidence,
    not an atomic security sandbox, and process ownership is not a security
    boundary.
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
import shutil
import stat
import uuid

from .protectors import ProtectorError, _job_lock, _json, _no_links, _read


# The trusted owned engine module, loaded ONLY by this name (no caller path).
ENGINE_MODULE = "antirea.csharp_app_integration"

PUBLIC_STATUS_PASSED = "csharp_application_samples_passed"
APPLICATION_CONTRACT_KIND = "csharp_application_samples"
PUBLIC_ROUTE = "explicit_source_integrate_execution"

MAX_PROJECT_BYTES = 64 * 1024 * 1024
MAX_JSON_BYTES = 256 * 1024
MAX_SOURCE_BYTES = 16 * 1024 * 1024      # bounded read for an application source file
MAX_PREFLIGHT_ENTRIES = 4096             # bounded guarded project-tree walk

# Service-level case bounds (deliberately tighter than the engine's own limits).
MAX_CASES = 256
MAX_CASE_ARGS = 16
MAX_ARG_LEN = 256
MAX_LABEL_LEN = 128
MAX_STDOUT_LEN = 4096

CASE_KINDS = ("value", "exception")
_CASE_REQUIRED = frozenset({"label", "kind", "args"})
_CASE_OPTIONAL = frozenset({"expect"})
_EXPECT_KEYS = frozenset({"returncode", "exception", "stdout", "stdout_is_integer"})
_CONTRACT_KEYS = frozenset({"schema_version", "kind", "cases"})
_EXC_TOKEN = re.compile(r"System\.[A-Za-z0-9_.]+Exception\Z")

# Path segments refused LEXICALLY, before any stat/read/hash of a consumed path.
_RESERVED_PARTS = frozenset({"rea-analysis-reports", "attackerfolder", "defense-loop",
                             "env.setting", "linkrepro"})

# Owned service/source module bytes pinned into the engine trusted_inputs seam, in
# addition to the source plan/result/report, the integration spec and the explicit
# application contract.
_SERVICE_MODULE_FILES = ("csharp_application.py", "projects.py", "protectors.py")


class CSharpApplicationError(ValueError):
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
        raise CSharpApplicationError("path must be a non-empty, control-character-free string")
    for part in raw.replace("\\", "/").split("/"):
        if part.casefold() in _RESERVED_PARTS:
            raise CSharpApplicationError("reserved/excluded path segment is not allowed: " + part)


def _safe_direct_name(name, label: str) -> str:
    """Require a safe DIRECT child file name before any stat/read/hash.

    Rejects empty/control-char names, absolute paths, drive-qualified paths, any
    path separator or ``..`` component, and lexically reserved/excluded segments.
    """
    if not isinstance(name, str) or not name or any(ord(c) < 32 for c in name):
        raise CSharpApplicationError(label + " must be a non-empty, control-character-free name")
    if "/" in name or "\\" in name or ":" in name:
        raise CSharpApplicationError(label + " must be a direct file name without path separators or drive: " + name)
    candidate = Path(name)
    if candidate.is_absolute() or len(candidate.parts) != 1 or candidate.name != name:
        raise CSharpApplicationError(label + " must be a single direct file name: " + name)
    if name in (".", "..") or ".." in candidate.parts:
        raise CSharpApplicationError(label + " must not traverse parent directories: " + name)
    _reserved_guard(name)
    return name


def _guarded_tree_preflight(app_dir: Path) -> None:
    """Bounded, STREAMING, non-link walk of the planned project tree that refuses
    reserved descendants BEFORE descending/reading. This protects the generic
    ``_snapshot``/``_toolchain`` (which lack env.setting/LINKREPRO guards) from ever
    stat/reading an excluded file, even for a malformed saved plan.

    Uses ``os.scandir`` and enforces the entry budget incrementally (per streamed
    entry), so a huge directory is never fully materialized before the bound bites.
    The reserved-name check is purely lexical and happens before any symlink/reparse
    classification or descent; no file contents are read.
    """
    app_dir = Path(app_dir)
    _no_links(app_dir)
    if not app_dir.is_dir():
        raise CSharpApplicationError("planned project directory is missing")
    entries = 0
    pending = [app_dir]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as iterator:
            for entry in iterator:
                entries += 1
                if entries > MAX_PREFLIGHT_ENTRIES:
                    raise CSharpApplicationError("planned project tree exceeds the bounded preflight entry limit")
                # Lexical reserved-name check BEFORE any stat/descent/read.
                if entry.name.casefold() in _RESERVED_PARTS:
                    raise CSharpApplicationError(
                        "reserved/excluded descendant is not allowed under the project: " + entry.name)
                # Classify without following links; reject symlink/reparse redirects.
                if entry.is_symlink():
                    raise CSharpApplicationError("symlink is not allowed under the project: " + entry.path)
                info = entry.stat(follow_symlinks=False)
                if getattr(info, "st_file_attributes", 0) & 0x400:
                    raise CSharpApplicationError("reparse point is not allowed under the project: " + entry.path)
                if stat.S_ISDIR(info.st_mode):
                    pending.append(Path(entry.path))
                elif not stat.S_ISREG(info.st_mode):
                    raise CSharpApplicationError("non-regular entry is not allowed under the project: " + entry.path)


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
    """Verify the FIXED toolchain config bytes against the saved plan sha and
    lexically guard its path-bearing fields BEFORE the generic ``service._toolchain``
    discovery can follow (and hash) any newly changed configured path.

    A config that changed since planning, or whose path fields hit a reserved
    segment, is rejected here -- before discovery -- using only bounded reads and
    lexical string checks (never following a path into an excluded location).
    """
    if not isinstance(plan_toolchain, dict):
        raise CSharpApplicationError("saved plan toolchain is malformed")
    native_required = (inspection or {}).get("language") not in {"python", "javascript", "typescript"}
    config_path = service.root / ".tools" / "kagura-toolchain.json"
    _reserved_guard(str(config_path))
    saved_sha = plan_toolchain.get("sha256")
    if not native_required or plan_toolchain.get("status") != "present" or not isinstance(saved_sha, str):
        # Non-native route or a plan with no present native toolchain: a config that
        # appears now would be drift the post-discovery comparison still rejects, but
        # there is no planned config path for us to follow here.
        if native_required and isinstance(saved_sha, str) and not config_path.is_file():
            raise CSharpApplicationError("planned native toolchain config is missing")
        return
    if not config_path.is_file():
        raise CSharpApplicationError("planned native toolchain config is missing")
    raw = _read(config_path, MAX_JSON_BYTES)
    if _digest(raw) != saved_sha:
        # Reject a changed config BEFORE following its (possibly redirected) paths.
        raise CSharpApplicationError("native toolchain config changed since planning; refusing to follow its paths")
    config = _json(raw)
    if not isinstance(config, dict):
        raise CSharpApplicationError("native toolchain config must be an object")
    for field in _TOOLCHAIN_PATH_FIELDS:
        value = config.get(field)
        if isinstance(value, str) and value:
            _reserved_guard(value)
    # The inspection's compiler inputs are followed by _toolchain too; guard them.
    for key in (inspection or {}).get("compiler_inputs", {}) or {}:
        if isinstance(key, str):
            _reserved_guard(key)


def _guarded_preflight(service, app_dir: Path, plan_toolchain: dict, inspection: dict) -> None:
    """Run BOTH guards (project-tree + fixed-toolchain-config) that must precede any
    generic ``_snapshot``/``_toolchain`` recomputation -- at plan time AND after
    execution AND after packaging. A child that planted a reserved descendant or
    redirected the fixed toolchain config is rejected here, before generic traversal
    or discovery reads any excluded data."""
    _guarded_tree_preflight(app_dir)
    _preflight_toolchain_config(service, plan_toolchain, inspection)


def _owned_app_file(service, raw, app_dir: Path, label: str, snapshot_paths: set) -> Path:
    """Reserved guard, then owned/no-link validation, then require a regular file
    DIRECTLY in ``app_dir`` that is already pinned in the fingerprinted plan
    snapshot. This keeps the spec/contract inside the same planned project
    snapshot and rejects any arbitrary producer-supplied path."""
    _reserved_guard(raw)
    path = service._owned(raw)           # abs, no links, inside workspace, not received/service-output
    _no_links(path)
    if path.parent != app_dir:
        raise CSharpApplicationError(label + " must live directly in the planned project directory")
    if not path.is_file():
        raise CSharpApplicationError(label + " must be an existing regular file")
    if str(path) not in snapshot_paths:
        raise CSharpApplicationError(label + " is not part of the fingerprinted plan snapshot")
    return path


def _validate_expect(expect, kind: str, label: str):
    if expect is None:
        return None
    if not isinstance(expect, dict) or not expect:
        raise CSharpApplicationError("case %r expect must be a non-empty object or omitted" % label)
    extra = set(expect) - _EXPECT_KEYS
    if extra:
        raise CSharpApplicationError("case %r expect has unsupported key(s): %s" % (label, ", ".join(sorted(extra))))
    if "returncode" in expect and (isinstance(expect["returncode"], bool) or not isinstance(expect["returncode"], int)):
        raise CSharpApplicationError("case %r expect.returncode must be an int" % label)
    if "exception" in expect:
        exc = expect["exception"]
        if not isinstance(exc, str) or not _EXC_TOKEN.fullmatch(exc):
            raise CSharpApplicationError("case %r expect.exception must be a System.*Exception token" % label)
        if kind != "exception":
            raise CSharpApplicationError("case %r declares expect.exception but kind is not 'exception'" % label)
    if "stdout" in expect and (not isinstance(expect["stdout"], str) or len(expect["stdout"]) > MAX_STDOUT_LEN):
        raise CSharpApplicationError("case %r expect.stdout must be a string <= %d chars" % (label, MAX_STDOUT_LEN))
    if "stdout_is_integer" in expect and not isinstance(expect["stdout_is_integer"], bool):
        raise CSharpApplicationError("case %r expect.stdout_is_integer must be a bool" % label)
    return dict(expect)


def _validate_app_contract(contract) -> list:
    """Validate the explicit application-sample contract and return its cases.

    Schema: ``{"schema_version": 1, "kind": "csharp_application_samples",
    "cases": [{"label", "kind": "value"|"exception", "args": [int|str...],
    "expect"?: {...}} ...]}``. Nothing is executed here; malformed input fails
    closed BEFORE any child process is launched.
    """
    if not isinstance(contract, dict):
        raise CSharpApplicationError("application contract must be a JSON object")
    extra = set(contract) - _CONTRACT_KEYS
    missing = _CONTRACT_KEYS - set(contract)
    if extra:
        raise CSharpApplicationError("application contract has unsupported key(s): " + ", ".join(sorted(extra)))
    if missing:
        raise CSharpApplicationError("application contract missing key(s): " + ", ".join(sorted(missing)))
    if type(contract["schema_version"]) is not int or contract["schema_version"] != 1:
        raise CSharpApplicationError("application contract schema_version must be 1")
    if contract["kind"] != APPLICATION_CONTRACT_KIND:
        raise CSharpApplicationError("application contract kind must be %r" % APPLICATION_CONTRACT_KIND)
    cases = contract["cases"]
    if not isinstance(cases, list) or not cases:
        raise CSharpApplicationError("application contract cases must be a non-empty list")
    if len(cases) > MAX_CASES:
        raise CSharpApplicationError("too many cases (max %d)" % MAX_CASES)
    out, labels = [], set()
    for idx, case in enumerate(cases):
        if not isinstance(case, dict):
            raise CSharpApplicationError("case %d must be an object" % idx)
        keys = set(case)
        if _CASE_REQUIRED - keys:
            raise CSharpApplicationError("case %d missing key(s): %s" % (idx, ", ".join(sorted(_CASE_REQUIRED - keys))))
        if keys - (_CASE_REQUIRED | _CASE_OPTIONAL):
            raise CSharpApplicationError(
                "case %d has unsupported key(s): %s" % (idx, ", ".join(sorted(keys - (_CASE_REQUIRED | _CASE_OPTIONAL)))))
        label = case["label"]
        if not isinstance(label, str) or not label or len(label) > MAX_LABEL_LEN:
            raise CSharpApplicationError("case %d label must be a non-empty string <= %d chars" % (idx, MAX_LABEL_LEN))
        if label in labels:
            raise CSharpApplicationError("case %d has a duplicate label: %r" % (idx, label))
        labels.add(label)
        kind = case["kind"]
        if kind not in CASE_KINDS:
            raise CSharpApplicationError("case %r kind must be one of %s" % (label, list(CASE_KINDS)))
        args = case["args"]
        if not isinstance(args, list) or len(args) > MAX_CASE_ARGS:
            raise CSharpApplicationError("case %r args must be a list of 0..%d values" % (label, MAX_CASE_ARGS))
        norm_args = []
        for a in args:
            if isinstance(a, bool) or not isinstance(a, (int, str)):
                raise CSharpApplicationError("case %r args must be int or str (bool rejected)" % label)
            if isinstance(a, str) and "\x00" in a:
                # Reject an embedded NUL in a string argument HERE, in pure preflight,
                # never later at Popen after compilers already ran.
                raise CSharpApplicationError("case %r argument contains an embedded NUL" % label)
            if len(str(a)) > MAX_ARG_LEN:
                raise CSharpApplicationError("case %r argument exceeds %d chars" % (label, MAX_ARG_LEN))
            norm_args.append(a)
        expect = _validate_expect(case.get("expect"), kind, label)
        entry = {"label": label, "kind": kind, "args": norm_args}
        if expect is not None:
            entry["expect"] = expect
        out.append(entry)
    return out


def _load_engine():
    """Import the trusted engine lazily, by trusted name only."""
    try:
        engine = importlib.import_module(ENGINE_MODULE)
    except ImportError as exc:
        raise CSharpApplicationError(
            "trusted integration engine %r is not available in this build; C# application "
            "integration cannot execute until it is present: %s" % (ENGINE_MODULE, exc)) from exc
    for attr in ("WorkspacePlan", "ProducerManifest", "ProtectedBuildReceipt",
                 "ToolchainSnapshot", "run_integration", "TRUSTED_TRANSFORM_MODULE"):
        if not hasattr(engine, attr):
            raise CSharpApplicationError("trusted integration engine is missing required API %r" % attr)
    return engine


def _require_trusted_inputs(engine) -> None:
    """Require the engine's run_integration to accept the service trusted_inputs seam."""
    try:
        params = _inspect_mod.signature(engine.run_integration).parameters
    except (TypeError, ValueError) as exc:
        raise CSharpApplicationError("cannot introspect engine run_integration: %s" % exc) from exc
    if "trusted_inputs" not in params and not any(
            p.kind is _inspect_mod.Parameter.VAR_KEYWORD for p in params.values()):
        raise CSharpApplicationError(
            "trusted integration engine run_integration does not accept the required 'trusted_inputs' "
            "keyword seam; engine adoption is incomplete")


_SAFE_IDENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\Z")
MAX_BUNDLE_FILE_BYTES = 512 * 1024 * 1024    # bounded source-artifact read before copy


def _bounded_source(path: Path, engine_out: Path, label: str) -> bytes:
    """Guard a source artifact BEFORE reading: reserved-free, confined under the
    engine output directory, non-link; then read it with a genuinely BOUNDED read
    (``_read`` does a limit+1 read and rejects oversize, with open/close identity
    stability), so a file that grows after the stat cannot be silently truncated."""
    path = Path(os.path.abspath(path))
    _reserved_guard(str(path))
    if not path.is_relative_to(engine_out):
        raise CSharpApplicationError(label + " is not confined under the engine output directory: " + str(path))
    try:
        return _read(path, MAX_BUNDLE_FILE_BYTES)
    except ProtectorError as exc:
        raise CSharpApplicationError(label + " is not a bounded regular file: " + str(exc)) from exc


def _package_bundle(deploy_dir: Path, *, engine_out: Path, project_name: str, native_library: str,
                    protected_dll: Path, runtimeconfig: Path, native_core: Path,
                    expected_protected_sha: str, expected_runtimeconfig_sha: str,
                    expected_native_sha: str) -> dict:
    """Copy ONLY the three engine-confined deployable files into a fresh bundle.

    No original source, IR, reference assemblies or build logs are included. Each
    source is guarded (reserved-free, confined under the engine output, non-link,
    regular, bounded) BEFORE any read; the managed DLL, its runtimeconfig and the
    reused native core must each match the ENGINE-REPORTED original pin (no silent
    repin); and the DESTINATION copy is re-hashed and asserted equal to that SAME
    original pin. The bundle is finally asserted to hold exactly the allowlist.
    """
    engine_out = Path(os.path.abspath(engine_out))
    if not _SAFE_IDENT.fullmatch(project_name):
        raise CSharpApplicationError("project name must be a safe identifier for deployable file names")
    if not re.fullmatch(r"[A-Za-z0-9_]+", native_library):
        raise CSharpApplicationError("native_library must be a simple identifier")
    managed_name = project_name + ".dll"
    config_name = project_name + ".runtimeconfig.json"
    native_name = native_library + ".dll"
    allow = {managed_name, config_name, native_name}
    if len(allow) != 3:
        raise CSharpApplicationError("deployment file names collide; refusing ambiguous bundle")
    # Guard + bounded-read each source, then verify its bytes against the original pin.
    items = (
        (protected_dll, managed_name, expected_protected_sha, "protected managed DLL"),
        (runtimeconfig, config_name, expected_runtimeconfig_sha, "managed runtimeconfig"),
        (native_core, native_name, expected_native_sha, "reused native core"),
    )
    staged = []
    for src, name, expected, label in items:
        if not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected):
            raise CSharpApplicationError(label + " has no valid engine pin; refusing to repin")
        data = _bounded_source(Path(src), engine_out, label)
        if _digest(data) != expected:
            raise CSharpApplicationError(label + " hash disagrees with the engine report pin")
        staged.append((name, data, expected, label))
    _no_links(deploy_dir)
    deploy_dir.mkdir()
    files = []
    for name, data, expected, label in staged:
        dst = deploy_dir / name
        with dst.open("xb") as fh:
            fh.write(data)
        # Re-hash the DESTINATION and require it to equal the ORIGINAL pin.
        dst_sha = _digest(_read(dst, MAX_BUNDLE_FILE_BYTES))
        if dst_sha != expected:
            raise CSharpApplicationError(label + " destination copy hash does not equal the original pin")
        files.append({"relative_path": name, "sha256": dst_sha, "bytes": len(data)})
    present = sorted(p.name for p in deploy_dir.iterdir())
    if present != sorted(allow):
        raise CSharpApplicationError("deployment bundle contains unexpected files: " + ", ".join(present))
    return {"path": str(deploy_dir), "managed_dll": managed_name, "runtimeconfig": config_name,
            "native_core": native_name, "files": sorted(files, key=lambda f: f["relative_path"])}


def _comparison_summary(engine_report) -> dict | None:
    if not isinstance(engine_report, dict):
        return None
    c = engine_report.get("comparison")
    if not isinstance(c, dict):
        return None
    return {k: c.get(k) for k in ("status", "all_match", "env_ok", "il_evidence_ok", "route_proof_ok",
                                  "integrity_verified_before_and_after", "expectations_ok",
                                  "total_cases", "value_cases", "exception_cases", "stop_cancellations")}


_COMPARISON_PASS_FLAGS = ("all_match", "env_ok", "il_evidence_ok", "route_proof_ok",
                          "integrity_verified_before_and_after", "expectations_ok")


def _verify_engine_report(engine_report, engine_report_path: Path, *, report_path: Path,
                          report_sha: str, artifacts: dict, case_count: int,
                          declared_trusted_count: int) -> dict:
    """Finding 4: a success must rest on a GENUINE persisted engine report.

    Requires: the returned report is a dict; the persisted file exists and is a
    bounded regular file whose parsed bytes EQUAL the returned report (defeats a
    return-only or stale/forged on-disk report); the report's producer/native match
    the original source build this service bound; the comparison pass flags and
    coverage are genuinely present and True; the engine's own trusted-input
    verification is present and verified for the declared count; and the reuse flag
    is honestly False. Returns ``{"authentic": bool, "checks": {...}, "reason": str}``.
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

    producer = engine_report.get("producer") if isinstance(engine_report.get("producer"), dict) else {}
    record("producer_report_path_match", producer.get("report_path") == str(report_path))
    record("producer_report_sha_match", producer.get("report_sha256") == report_sha)
    prot = artifacts.get("protected") if isinstance(artifacts, dict) else {}
    base = artifacts.get("baseline") if isinstance(artifacts, dict) else {}
    prot_sha = prot.get("sha256") if isinstance(prot, dict) else None
    base_sha = base.get("sha256") if isinstance(base, dict) else None
    p_prot = producer.get("protected") if isinstance(producer.get("protected"), dict) else {}
    p_base = producer.get("baseline") if isinstance(producer.get("baseline"), dict) else {}
    record("producer_protected_sha_match", bool(prot_sha) and p_prot.get("sha256") == prot_sha)
    record("producer_baseline_sha_match", bool(base_sha) and p_base.get("sha256") == base_sha)

    staging = engine_report.get("staging") if isinstance(engine_report.get("staging"), dict) else {}
    record("native_core_is_reused_protected", bool(prot_sha) and staging.get("native_core_sha256") == prot_sha)

    comparison = engine_report.get("comparison") if isinstance(engine_report.get("comparison"), dict) else {}
    record("comparison_status_passed", comparison.get("status") == "producer_bound_integration_passed")
    record("comparison_flags_present_true", all(comparison.get(flag) is True for flag in _COMPARISON_PASS_FLAGS))
    record("comparison_covers_all_cases", comparison.get("total_cases") == case_count)
    dep = comparison.get("deployable_app") if isinstance(comparison.get("deployable_app"), dict) else {}
    rc = dep.get("runtimeconfig") if isinstance(dep.get("runtimeconfig"), dict) else {}
    record("deployable_runtimeconfig_pin_present",
           isinstance(dep.get("sha256"), str) and isinstance(rc.get("sha256"), str) and isinstance(rc.get("path"), str))

    tiv = engine_report.get("trusted_inputs_verification")
    tiv = tiv if isinstance(tiv, dict) else {}
    record("trusted_inputs_verified", tiv.get("verified") is True and tiv.get("declared_count") == declared_trusted_count)
    record("fresh_protected_native_build_false", engine_report.get("fresh_protected_native_build") is False)

    authentic = all(checks.values())
    if reason is None and not authentic:
        reason = "failed checks: " + ", ".join(sorted(k for k, v in checks.items() if not v))
    return {"authentic": authentic, "checks": checks, "reason": reason or ""}


def _classify_child_issues(engine_report) -> dict:
    """Finding 5: expected nonzero/exception/route-control child returncodes are NOT
    failures (the engine's comparison + route proofs already account for them). Only
    infrastructure problems -- timeout, cancellation or unverified cleanup -- are
    child issues; comparison mismatch is reported separately via the pass flags."""
    infra = []
    cancelled = []
    if isinstance(engine_report, dict):
        comparison = engine_report.get("comparison") or {}
        for cmd in comparison.get("commands", []) or []:
            if not isinstance(cmd, dict):
                continue
            if cmd.get("cancelled"):
                cancelled.append(cmd.get("label"))
            unclean = (os.name == "nt"
                       and (cmd.get("cleanup_status") not in (None, "assigned_job_empty")
                            or cmd.get("job_handle_closed") is False))
            if cmd.get("timed_out") or cmd.get("cancelled") or unclean:
                infra.append({"label": cmd.get("label"), "timed_out": cmd.get("timed_out"),
                              "cancelled": cmd.get("cancelled"), "cleanup_status": cmd.get("cleanup_status"),
                              "job_handle_closed": cmd.get("job_handle_closed")})
        mismatch = comparison.get("status") == "failed" or any(
            comparison.get(flag) is not True for flag in _COMPARISON_PASS_FLAGS)
    else:
        mismatch = True
    return {"child_infrastructure_failures": infra, "child_cancellations": cancelled,
            "comparison_mismatch": bool(mismatch)}


def _base_pins_unchanged(base_trusted_inputs) -> bool:
    """Re-verify every original base trusted pin (source plan/result/report, spec,
    contract, application sources and service modules) against on-disk bytes with a
    bounded read. Returns False on any missing/changed pin; never refreshes a hash."""
    for rec in base_trusted_inputs:
        try:
            if _digest(_read(Path(rec["path"]), MAX_PROJECT_BYTES)) != rec["sha256"]:
                return False
        except Exception:
            return False
    return True


# --------------------------------------------------------------------------- #
# Independent raw child-evidence verification. A public pass must not stand on the
# engine's COPIED comparison booleans: the engine persists one raw process receipt
# per child (``comparison.commands[*].receipt_path`` = ``<label>.process.json``)
# plus raw ``<label>.stdout.log`` / ``.stderr.log`` captures (antirea.process.
# run_logged). This service re-derives every required per-case and control
# observation FROM those confined, bounded, persisted artifacts and binds them to
# the engine's claimed observations, the contract expectations and the fail-closed
# negative controls, so a report whose flags claim a pass but whose raw evidence
# contradicts it (or is missing / duplicated / substituted / unclean / timed-out /
# cancelled / out-of-root / malformed) is refused. Bounded, module-local verifier
# (not a copy of the JVM one); the trusted engine is unchanged.
MAX_RECEIPT_BYTES = 256 * 1024          # bounded per-child persisted process receipt
MAX_CHILD_LOG_BYTES = 4 * 1024 * 1024   # bounded raw stdout/stderr capture (empty allowed)
MAX_CHILD_COMMANDS = 4096               # bound on the number of recorded child commands
_EXC_FIND = re.compile(r"System\.[A-Za-z0-9_.]*Exception")   # same search as the engine
# The two fail-closed negative controls and the exact exception each must raise.
_ROUTE_CONTROL_EXPECTED = {"route-missing-core": "System.DllNotFoundException",
                           "route-unset-core": "System.InvalidOperationException"}
# The exact preparation children a genuine passed run records (compile/inspect/env
# probe); the full known identity set is these plus per-case orig/depl and the
# three route labels -- any other label is an unknown identity.
_KNOWN_PREP = ("csc-EnvProbe", "env-probe", "csc-original_app", "csc-deployable_app",
               "csc-Inspect", "il-original", "il-deployable")


def _canon_path(path) -> str:
    """Canonical key for path equality/uniqueness (case-insensitive on Windows)."""
    return os.path.normcase(os.path.abspath(str(path)))


def _confined_evidence(path, engine_out: Path, label: str) -> Path:
    """Reserved-guard, require confinement under the engine output, and reject
    symlink/reparse BEFORE any read; raises on an out-of-root/unsafe path."""
    if not isinstance(path, str) or not path:
        raise CSharpApplicationError(label + " path is missing")
    _reserved_guard(path)
    p = Path(os.path.abspath(path))
    if not p.is_relative_to(engine_out):
        raise CSharpApplicationError(label + " is not confined under the engine output directory: " + str(p))
    _no_links(p)
    return p


def _read_child_log(log_path, engine_out: Path, label: str, which: str) -> bytes:
    """Confined + bounded read of a captured child log (0 bytes allowed, so an
    observation comes from the ACTUAL captured output, never a returned boolean)."""
    p = _confined_evidence(log_path, engine_out, label + " " + which)
    info = p.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise CSharpApplicationError(label + " " + which + " is not a regular file")
    if info.st_size > MAX_CHILD_LOG_BYTES:
        raise CSharpApplicationError(label + " " + which + " exceeds the bounded size")
    with p.open("rb") as fh:
        data = fh.read(MAX_CHILD_LOG_BYTES + 1)
    if len(data) > MAX_CHILD_LOG_BYTES:
        raise CSharpApplicationError(label + " " + which + " grew while reading")
    return data


def _receipt_infra_clean(receipt: dict) -> bool:
    """Infrastructure-clean predicate over a FULL persisted raw receipt. Requires a
    real positive int pid and int returncode (bool rejected), timed_out/cancelled
    exactly False, no error fields, and the same complete owned-child cleanup record
    the engine's ``_clean_completion`` demands (full Windows Job accounting on nt; a
    confirmed parent exit elsewhere). A non-zero returncode is still clean --
    expected-exception cases and fail-closed controls exit non-zero yet cleanly."""
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
    c = receipt.get("cleanup")
    if not isinstance(c, dict) or c.get("parent_exit_confirmed") is not True:
        return False
    if os.name != "nt":
        return True
    return (c.get("method") == "windows_job" and c.get("job_assigned") is True
            and c.get("parent_pid") == pid
            and isinstance(c.get("active_after"), int) and not isinstance(c.get("active_after"), bool)
            and c.get("active_after") == 0 and c.get("status") == "assigned_job_empty"
            and c.get("job_handle_closed") is True)


def _derive_observation(receipt: dict, stdout_bytes: bytes, stderr_bytes: bytes):
    """Re-derive ``{rc, stdout(stripped), exc}`` from the raw bytes, plus the FULL
    (unstripped) stdout text used for the engine's byte-equal arm comparison."""
    stdout_text = stdout_bytes.decode("utf-8", "replace")
    stderr_text = stderr_bytes.decode("utf-8", "replace")
    m = _EXC_FIND.search(stderr_text)
    return ({"rc": receipt.get("returncode"), "stdout": stdout_text.strip(),
             "exc": m.group(0) if m else None}, stdout_text)


def _expectation_satisfied(expect, obs: dict) -> bool:
    """Mirror the engine's expected-observation check over the re-derived obs."""
    if not isinstance(expect, dict):
        return True
    if "returncode" in expect and obs["rc"] != expect["returncode"]:
        return False
    if "exception" in expect and obs["exc"] != expect["exception"]:
        return False
    if "stdout" in expect and obs["stdout"] != expect["stdout"]:
        return False
    if "stdout_is_integer" in expect:
        is_int = bool(re.fullmatch(r"-?\d+", obs["stdout"]))
        if is_int != bool(expect["stdout_is_integer"]):
            return False
    return True


def _bind_argv(argv, assembly: str, case_args: list, label: str) -> None:
    """Bind a persisted receipt to the actual ``<dotnet> exec <assembly> <args...>``
    command SHAPE -- the expected assembly must sit at the exec slot (index 2), with
    exactly the case args after it and nothing else -- so a receipt that executes a
    DIFFERENT assembly while merely listing the expected one as a later argument, or
    carries extra/short args (including zero-arg cases), cannot stand in."""
    args = [str(a) for a in case_args]
    if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        raise CSharpApplicationError(label + " receipt argv is missing or malformed")
    if len(argv) != 3 + len(args):
        raise CSharpApplicationError(label + " receipt argv shape is not an exec of the expected assembly")
    if not argv[0] or argv[1] != "exec":
        raise CSharpApplicationError(label + " receipt is not a dotnet-exec invocation")
    if _canon_path(argv[2]) != _canon_path(assembly):
        raise CSharpApplicationError(label + " receipt does not execute the expected assembly at the exec slot")
    if argv[3:] != args:
        raise CSharpApplicationError(label + " receipt arguments do not match the case arguments")


def _verify_child_evidence(engine_report, *, engine_out, cases) -> dict:
    """Independently prove, from the confined/bounded/persisted raw receipts+logs,
    that every required per-case ORIGINAL+PROTECTED observation and the three route
    controls are genuine, mutually byte-consistent, contract-satisfying and
    fail-closed -- never from the engine's copied booleans. Never raises; returns
    ``{"authentic": bool, "reason": str, "checks": {...}}``."""
    engine_out = Path(os.path.abspath(engine_out))
    try:
        if not isinstance(engine_report, dict) or not isinstance(engine_report.get("comparison"), dict):
            raise CSharpApplicationError("engine report has no comparison block")
        comparison = engine_report["comparison"]
        commands = comparison.get("commands")
        if not isinstance(commands, list) or not commands:
            raise CSharpApplicationError("comparison.commands is missing or empty")
        if len(commands) > MAX_CHILD_COMMANDS:
            raise CSharpApplicationError("comparison.commands exceeds the bounded command count")
        orig_asm = (comparison.get("original_app") or {}).get("dll")
        dep_asm = (comparison.get("deployable_app") or {}).get("dll")
        if not isinstance(orig_asm, str) or not isinstance(dep_asm, str):
            raise CSharpApplicationError("comparison is missing the original/deployable assembly pins")

        # Label map (reject duplicates), then bind+read EVERY command's receipt and
        # its OWN logs, enforce global path uniqueness and infrastructure-cleanness.
        cmd_map, receipts, seen_paths, pins = {}, {}, set(), {}
        for entry in commands:
            if not isinstance(entry, dict) or not isinstance(entry.get("label"), str) or not entry["label"]:
                raise CSharpApplicationError("malformed command entry")
            lbl = entry["label"]
            if lbl in cmd_map:
                raise CSharpApplicationError("duplicate command identity: " + lbl)
            cmd_map[lbl] = entry
        for lbl, entry in cmd_map.items():
            rp = _confined_evidence(entry.get("receipt_path"), engine_out, lbl + " receipt_path")
            rdata = _read(rp, MAX_RECEIPT_BYTES)      # bounded (limit+1), rejects empty
            receipt = _json(rdata)
            if not isinstance(receipt, dict):
                raise CSharpApplicationError(lbl + " receipt is not a JSON object")
            pins[_canon_path(rp)] = _digest(rdata)    # pin the exact raw receipt bytes
            logs = {}
            for which in ("stdout", "stderr"):
                cval, rval = entry.get(which), receipt.get(which)
                if not isinstance(cval, str) or not isinstance(rval, str) or _canon_path(cval) != _canon_path(rval):
                    raise CSharpApplicationError(lbl + " " + which + " is not bound to the receipt's own path")
                data = _read_child_log(rval, engine_out, lbl, which + "_log")
                pins[_canon_path(rval)] = _digest(data)   # pin the exact raw log bytes
                logs[which] = data
            for role_path in (entry.get("receipt_path"), receipt.get("stdout"), receipt.get("stderr")):
                key = _canon_path(role_path)
                if key in seen_paths:
                    raise CSharpApplicationError(lbl + " reuses an evidence path already bound to another identity")
                seen_paths.add(key)
            if not _receipt_infra_clean(receipt):
                raise CSharpApplicationError(lbl + " child did not complete cleanly (timeout/cancel/unclean)")
            receipts[lbl] = (receipt, logs["stdout"], logs["stderr"])

        # EXACT known identity set: the genuine preparation children + per-case
        # orig/depl + the three route controls; any extra label is an unknown identity.
        known = set(_KNOWN_PREP) | {"route-control", "route-missing-core", "route-unset-core"}
        for i in range(len(cases)):
            known.add("orig-%03d" % i)
            known.add("depl-%03d" % i)
        unknown = sorted(set(cmd_map) - known)
        if unknown:
            raise CSharpApplicationError("unknown command identities: " + ", ".join(unknown))
        missing = sorted(known - set(cmd_map))
        if missing:
            raise CSharpApplicationError("missing required child identities: " + ", ".join(missing))

        comparisons = comparison.get("comparisons")
        if not isinstance(comparisons, list) or len(comparisons) != len(cases):
            raise CSharpApplicationError("comparison.comparisons shape does not cover the cases")
        comp_by_case = {c.get("case"): c for c in comparisons if isinstance(c, dict)}

        for i, case in enumerate(cases):
            args = [str(a) for a in case["args"]]
            comp = comp_by_case.get(case["label"])
            if not isinstance(comp, dict) or [str(a) for a in comp.get("args", [])] != args:
                raise CSharpApplicationError("comparison entry missing/mismatched for case " + case["label"])
            o_rcpt, o_out, o_err = receipts["orig-%03d" % i]
            d_rcpt, d_out, d_err = receipts["depl-%03d" % i]
            _bind_argv(o_rcpt.get("argv"), orig_asm, case["args"], "orig-%03d" % i)
            _bind_argv(d_rcpt.get("argv"), dep_asm, case["args"], "depl-%03d" % i)
            o_obs, _ = _derive_observation(o_rcpt, o_out, o_err)
            d_obs, _ = _derive_observation(d_rcpt, d_out, d_err)
            if o_obs != comp.get("original") or d_obs != comp.get("protected"):
                raise CSharpApplicationError("re-derived observation disagrees with the claim for " + case["label"])
            # Compare the RAW stdout BYTES (not errors=replace decoded text, which would
            # collapse distinct invalid-UTF-8 outputs to equal replacement characters).
            if o_out != d_out or o_obs["rc"] != d_obs["rc"] or o_obs["exc"] != d_obs["exc"]:
                raise CSharpApplicationError("original/protected raw evidence is not equivalent for " + case["label"])
            if not _expectation_satisfied(case.get("expect"), o_obs):
                raise CSharpApplicationError("contract expectation not met by raw evidence for " + case["label"])

        # Gating route control (original arm) + two fail-closed negative controls.
        control_case = next((c for c in cases
                             if c["kind"] == "value" and (c.get("expect") or {}).get("returncode") == 0), None)
        if control_case is None:
            raise CSharpApplicationError("no gating value control case (expect.returncode==0) is present")
        control_args = control_case["args"]
        c_rcpt, c_out, c_err = receipts["route-control"]
        _bind_argv(c_rcpt.get("argv"), orig_asm, control_args, "route-control")
        c_obs, _ = _derive_observation(c_rcpt, c_out, c_err)
        if c_obs["rc"] != 0 or c_obs["exc"] is not None:
            raise CSharpApplicationError("route control did not succeed cleanly on the original arm")
        # The route control must also satisfy the control case's own expectation.
        if not _expectation_satisfied(control_case.get("expect"), c_obs):
            raise CSharpApplicationError("route control observation does not satisfy the control case expectation")
        for lbl, want_exc in _ROUTE_CONTROL_EXPECTED.items():
            r_rcpt, r_out, r_err = receipts[lbl]
            _bind_argv(r_rcpt.get("argv"), dep_asm, control_args, lbl)
            r_obs, _ = _derive_observation(r_rcpt, r_out, r_err)
            # A clean NON-ZERO exit with the expected exception is the fail-closed
            # proof. Output equality with the control is NOT a fallback signal -- a
            # genuinely quiet app is empty on both arms; the engine treats only a
            # rc==0 reproduction as a silent fallback, already excluded by rc!=0.
            if not (isinstance(r_obs["rc"], int) and r_obs["rc"] != 0):
                raise CSharpApplicationError(lbl + " negative control did not exit non-zero")
            if r_obs["exc"] != want_exc:
                raise CSharpApplicationError(lbl + " negative control did not raise " + want_exc)

        # Preparation children must each exit 0; env-probe's first two raw stdout
        # lines independently confirm the clean captured environment (sentinel
        # <unset>, dotnet opt-out 1) rather than trusting the engine's env_ok flag.
        for prep in _KNOWN_PREP:
            p_rcpt, p_out, _ = receipts[prep]
            if p_rcpt.get("returncode") != 0:
                raise CSharpApplicationError(prep + " preparation child did not exit 0")
            if prep == "env-probe" and p_out.decode("utf-8", "replace").splitlines()[:2] != ["<unset>", "1"]:
                raise CSharpApplicationError("env-probe did not show a clean captured environment (<unset>/1)")

        return {"authentic": True, "reason": "", "evidence_pins": pins,
                "checks": {"cases": len(cases), "commands": len(cmd_map)}}
    except CSharpApplicationError as exc:
        return {"authentic": False, "reason": str(exc), "checks": {}}
    except Exception as exc:  # noqa: BLE001 -- fail closed; never raise out of the verifier
        return {"authentic": False, "reason": "child-evidence error: " + type(exc).__name__ + ": " + str(exc)[:200],
                "checks": {}}


def _child_evidence_pins_stable(pins: dict, engine_out) -> bool:
    """Re-read every pinned raw receipt/log and require byte-for-byte equality with
    the hash captured at the pass gate. This refuses a post-package drift whose
    SEMANTICS stay valid (e.g. a changed receipt ``seconds`` or matching whitespace
    added to both arms) which a re-derivation alone would accept. Fail closed."""
    if not pins:
        return False
    engine_out = Path(os.path.abspath(engine_out))
    for canon, sha in pins.items():
        try:
            p = Path(canon)
            if not p.is_relative_to(engine_out):
                return False
            _no_links(p)
            with p.open("rb") as fh:
                data = fh.read(MAX_CHILD_LOG_BYTES + 1)
            if len(data) > MAX_CHILD_LOG_BYTES or _digest(data) != sha:
                return False
        except Exception:  # noqa: BLE001 -- any read/stat failure is drift
            return False
    return True


def _example_args(cases) -> list:
    for case in cases:
        if case.get("kind") == "value":
            return [str(a) for a in case.get("args", [])]
    return [str(a) for a in cases[0].get("args", [])] if cases else []


def _launch_instructions(deploy_dir: Path, bundle: dict, cases) -> list:
    """Generic launch guidance; the example arguments come from an explicit contract
    case, never a hardcoded seed/rounds pair."""
    native_path = str(deploy_dir / bundle["native_core"])
    managed_path = str(deploy_dir / bundle["managed_dll"])
    example = _example_args(cases)
    example_str = " ".join('"%s"' % a for a in example) if example else "<app-defined arguments>"
    return [
        "Set the native-core binding to the bundled native DLL:",
        "  (cmd)        set ANTIREA_NATIVE_CORE=" + native_path,
        "  (PowerShell) $env:ANTIREA_NATIVE_CORE = '" + native_path + "'",
        "Run the protected managed application with its application-defined arguments "
        "(see application-contract.json cases):",
        '  dotnet exec "' + managed_path + '" ' + example_str,
        "The arguments above are an example taken from the contract's first value case; "
        "argument meaning is application-defined, not a fixed seed/rounds pair.",
        "The managed DLL fails closed if ANTIREA_NATIVE_CORE is unset or the native core is absent.",
    ]


def integrate_source_application(service, plan_id, integration_spec_path, contract_path,
                                 *, timeout_seconds=120):
    """Explicitly compile/run an owned managed C# application around its reviewed
    native core and package a deployable protected bundle.

    ``service`` is an existing ``ProjectService``; ``plan_id`` names a successful
    ``dotnet_il_native`` source build. The integration spec and application
    contract must be owned regular files already inside the planned project's
    directory. Returns a compact public report (full evidence is retained on
    disk). This action executes the application; it is NOT a build-only step.
    """
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
        raise CSharpApplicationError("timeout_seconds must be an integer in 1..600")

    root = service.root
    directory = service._directory(plan_id)      # validates plan id format and existence

    with _job_lock(directory):
        # -- 1. Bind the existing successful source plan / result / build report --
        result_bytes = _read(directory / "result.json", MAX_PROJECT_BYTES)
        result = _json(result_bytes)
        if not isinstance(result, dict) or result.get("status") != "artifact_created_unvalidated":
            raise CSharpApplicationError("source plan has no successful artifact to integrate")
        backend = result.get("backend")
        if backend != "dotnet_il_native":
            raise CSharpApplicationError(
                "source-integrate supports only csharp/dotnet_il_native; refusing backend %r" % (backend,))

        plan_bytes = _read(directory / "plan.json", MAX_PROJECT_BYTES)
        plan = _json(plan_bytes)
        fingerprint = result.get("fingerprint")
        if (not isinstance(plan, dict) or not isinstance(fingerprint, str)
                or _digest(_encoded(plan)) != fingerprint
                or plan.get("plan_id") != plan_id or result.get("plan_id") != plan_id
                or plan.get("workspace_root") != str(root)
                or plan.get("kind") != "native_source_build"
                or not isinstance(plan.get("inputs"), list)
                or not isinstance(plan.get("inspection"), dict)
                or not isinstance(plan.get("toolchain"), dict)):
            raise CSharpApplicationError("source plan does not bind this csharp build result")

        report_path = directory / "build" / "report.json"
        report_bytes = _read(report_path, MAX_PROJECT_BYTES)
        report = _json(report_bytes)
        if (not isinstance(report, dict) or report.get("backend") != "dotnet_il_native"
                or report.get("status") != "artifact_created_unvalidated"):
            raise CSharpApplicationError("build report is not a successful csharp native artifact")
        if (not isinstance(result.get("build_report_sha256"), str)
                or _digest(report_bytes) != result["build_report_sha256"]
                or report.get("artifacts") != result.get("artifacts")
                or report.get("coverage") != result.get("coverage")):
            raise CSharpApplicationError("build report no longer matches the source plan result (refusing silent repinning)")
        if plan.get("inspection") != report.get("project"):
            raise CSharpApplicationError("source plan inspection does not match the build report project metadata")
        artifacts = result.get("artifacts")
        if not isinstance(artifacts, dict) or not {"baseline", "protected"} <= set(artifacts):
            raise CSharpApplicationError("csharp build result is missing baseline/protected artifacts")

        # -- 2. app_dir = planned project parent; recompute snapshot + toolchain BEFORE --
        # Lexically guard the planned project path AND every saved snapshot/toolchain
        # path BEFORE service._owned/_snapshot/_toolchain can stat/read anything, so a
        # malformed saved plan cannot steer them onto an excluded file.
        project_path = plan.get("project_path")
        if not isinstance(project_path, str):
            raise CSharpApplicationError("source plan has no project path")
        _reserved_guard(project_path)
        _guard_saved_plan_paths(plan)
        source = service._owned(project_path)
        if report.get("project", {}).get("project_path") != str(source):
            raise CSharpApplicationError("build report project path does not match the plan project")
        app_dir = source.parent
        inspection = plan["inspection"]
        # Guarded preflight (bounded streaming tree walk + fixed-toolchain-config check)
        # BEFORE the generic snapshot/toolchain recomputation can descend into or read
        # any reserved descendant or follow a redirected toolchain config.
        _guarded_preflight(service, app_dir, plan["toolchain"], inspection)
        snapshot_before = service._snapshot(source, inspection)
        if snapshot_before != plan["inputs"]:
            raise CSharpApplicationError("planned project source tree changed before integration")
        toolchain_before = service._toolchain(inspection)
        if toolchain_before != plan["toolchain"]:
            raise CSharpApplicationError("source toolchain changed before integration")
        snapshot_paths = {rec["path"] for rec in snapshot_before if isinstance(rec, dict) and "path" in rec}
        snapshot_sha = {rec["path"]: rec["sha256"] for rec in snapshot_before
                        if isinstance(rec, dict) and "path" in rec and "sha256" in rec}

        # -- 3. Validate integration spec + application contract (reserved guard BEFORE stat) --
        spec_path = _owned_app_file(service, integration_spec_path, app_dir, "integration spec", snapshot_paths)
        contract_file = _owned_app_file(service, contract_path, app_dir, "application contract", snapshot_paths)
        if spec_path == contract_file:
            raise CSharpApplicationError("integration spec and application contract must be distinct files")
        spec_bytes = _read(spec_path, MAX_JSON_BYTES)
        # Freshly read spec/contract bytes MUST equal their ORIGINAL fingerprinted
        # snapshot pins -- not merely be repinned to whatever is on disk now.
        if _digest(spec_bytes) != snapshot_sha.get(str(spec_path)):
            raise CSharpApplicationError("integration spec bytes differ from the original plan snapshot pin")
        spec = _json(spec_bytes)
        if (not isinstance(spec, dict) or spec.get("schema_version") != 1
                or not isinstance(spec.get("sources"), list) or not isinstance(spec.get("methods"), list)
                or not isinstance(spec.get("native_library"), str)):
            raise CSharpApplicationError("integration spec must be schema_version 1 with sources, methods and native_library")

        # -- 4. Validate the explicit application-sample contract + cases (BEFORE any child) --
        contract_bytes = _read(contract_file, MAX_JSON_BYTES)
        if _digest(contract_bytes) != snapshot_sha.get(str(contract_file)):
            raise CSharpApplicationError("application contract bytes differ from the original plan snapshot pin")
        cases = _validate_app_contract(_json(contract_bytes))
        value_cases = sum(1 for c in cases if c["kind"] == "value")
        exception_cases = sum(1 for c in cases if c["kind"] == "exception")

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
            raise CSharpApplicationError("integration directory already exists; retry")
        integ_dir.mkdir()
        engine_out = integ_dir / "engine"
        deploy_dir = integ_dir / "deployment"
        engine_report_path = engine_out / "integration.json"

        # -- 7. BASE trusted-input pins (path + sha256 + role), all under workspace. --
        # These are the plan's own base pins; the saved integration-plan is NOT among
        # them (that is added to a separate engine list below to avoid self-reference).
        base_trusted_inputs = [
            {"path": str(directory / "plan.json"), "sha256": _digest(plan_bytes), "role": "source_plan"},
            {"path": str(directory / "result.json"), "sha256": _digest(result_bytes), "role": "source_result"},
            {"path": str(report_path), "sha256": _digest(report_bytes), "role": "source_build_report"},
            {"path": str(spec_path), "sha256": _digest(spec_bytes), "role": "integration_spec"},
            {"path": str(contract_file), "sha256": _digest(contract_bytes), "role": "application_contract"},
        ]
        # Application sources: require a SAFE DIRECT name, owned containment and
        # original-snapshot membership, then a BOUNDED regular-file read whose hash
        # must equal the planned snapshot pin (no unbounded read, no silent repin).
        for name in spec["sources"]:
            _safe_direct_name(name, "integration spec source")
            src = app_dir / name
            key = str(src)
            if key not in snapshot_sha:
                raise CSharpApplicationError("integration spec source is not part of the fingerprinted plan snapshot: " + name)
            _no_links(src)
            if src.parent != app_dir or not src.is_file():
                raise CSharpApplicationError("integration spec source must be a regular file in the planned project directory: " + name)
            sha = _digest(_read(src, MAX_SOURCE_BYTES))
            if sha != snapshot_sha[key]:
                raise CSharpApplicationError("integration spec source changed from the planned snapshot pin: " + name)
            base_trusted_inputs.append({"path": key, "sha256": sha, "role": "application_source"})
        for mod in _SERVICE_MODULE_FILES:
            module_path = Path(__file__).with_name(mod)
            _no_links(module_path)
            if not module_path.is_file():
                raise CSharpApplicationError("owned service module missing: " + mod)
            base_trusted_inputs.append({"path": str(module_path), "sha256": _digest(_read(module_path, MAX_SOURCE_BYTES)),
                                        "role": "service_module"})

        # -- 8. Append-only integration plan (source/contract/spec + all execution fields). --
        # The saved plan records only BASE input pins; it never fingerprints itself
        # into the list it later anchors, so there is no self-referential pin.
        plan_record = {
            "schema_version": 1, "kind": "csharp_application_integration_plan",
            "plan_id": plan_id, "integration_id": integration_id,
            "workspace_root": str(root), "project_path": str(source), "app_dir": str(app_dir),
            "source_plan": {"path": str(directory / "plan.json"), "sha256": _digest(plan_bytes),
                            "fingerprint": fingerprint},
            "source_result": {"path": str(directory / "result.json"), "sha256": _digest(result_bytes)},
            "source_build_report": {"path": str(report_path), "sha256": result["build_report_sha256"]},
            "integration_spec": {"path": str(spec_path), "sha256": _digest(spec_bytes),
                                 "native_library": spec["native_library"], "sources": list(spec["sources"])},
            "application_contract": {"path": str(contract_file), "sha256": _digest(contract_bytes),
                                     "kind": APPLICATION_CONTRACT_KIND, "total_cases": len(cases),
                                     "value_cases": value_cases, "exception_cases": exception_cases},
            "cases": cases,
            "artifacts": artifacts, "coverage": result.get("coverage"),
            "exported_functions": result.get("exported_functions"),
            "snapshot_before_sha256": _digest(_encoded(snapshot_before)),
            "toolchain_before_sha256": _digest(_encoded(toolchain_before)),
            "trusted_input_pins": base_trusted_inputs,
            "engine_module": ENGINE_MODULE,
            "engine_out_dir": str(engine_out), "deployment_dir": str(deploy_dir),
            "timeout_seconds": timeout_seconds,
            "reused_native_core": True, "fresh_protected_native_build": False,
            "executes_application": True, "publishes": False, "stop_marker": str(stop),
            "limitations": [
                "Explicit application execution step; not an implicit part of source plan/build.",
                "Native core is the reused pinned producer artifact re-verified from disk, not a fresh build.",
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

        # -- 9. Drive the trusted engine (plan -> serialize -> load -> prepare -> validate) --
        execution_error = None
        engine_report = None
        try:
            engine = _load_engine()
            _require_trusted_inputs(engine)
            workspace = engine.WorkspacePlan.resolve(
                workspace_root=str(root), out_dir=str(engine_out),
                stop_file=str(stop), transform_module=engine.TRUSTED_TRANSFORM_MODULE)
            producer = engine.ProducerManifest.at(report_path)
            receipt = engine.ProtectedBuildReceipt.reused_from_report(report_path, workspace_root=str(root))
            toolchain_snapshot = engine.ToolchainSnapshot.discover(workspace_root=str(root))
            engine_report = engine.run_integration(
                producer, receipt, toolchain_snapshot, workspace, str(app_dir), str(spec_path),
                timeout_seconds=timeout_seconds, cases=cases, trusted_inputs=engine_trusted_inputs)
            if not isinstance(engine_report, dict):
                raise CSharpApplicationError("engine run_integration returned a non-dict report")
        except Exception as exc:    # capture execution-phase failures (incl. child failures)
            execution_error = type(exc).__name__ + ": " + str(exc)[:2048]

        # -- 10. Recompute snapshot + toolchain + pins AFTER execution (reject silent drift) --
        # Re-run the guarded preflight FIRST: a child that planted a reserved descendant
        # or redirected the fixed toolchain config is rejected before the generic
        # snapshot/toolchain recomputation touches any excluded data.
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

        # -- 11. Authenticate the engine report + recheck the saved plan (finding 4) --
        engine_status = engine_report.get("status") if isinstance(engine_report, dict) else None
        engine_report_sha256 = None
        if engine_report_path.is_file():
            try:
                engine_report_sha256 = _digest(_read(engine_report_path, MAX_PROJECT_BYTES))
            except Exception:
                engine_report_sha256 = None
        fresh_flag = engine_report.get("fresh_protected_native_build") if isinstance(engine_report, dict) else False

        report_verification = {"authentic": False, "checks": {}, "reason": "engine execution did not complete"}
        child_evidence = {"authentic": False, "checks": {}, "reason": "engine execution did not complete"}
        if execution_error is None:
            report_verification = _verify_engine_report(
                engine_report, engine_report_path, report_path=report_path, report_sha=_digest(report_bytes),
                artifacts=artifacts, case_count=len(cases), declared_trusted_count=len(engine_trusted_inputs))
            # Independently bind the confined raw per-case receipts/logs to the claims
            # and controls; a copied pass flag is never sufficient on its own.
            child_evidence = _verify_child_evidence(engine_report, engine_out=engine_out, cases=cases)
        try:
            plan_unchanged = _digest(_read(plan_file, MAX_PROJECT_BYTES)) == plan_file_sha
        except Exception:
            plan_unchanged = False

        stop_now = stop.exists()
        child_issues = _classify_child_issues(engine_report)
        passed = bool(execution_error is None and report_verification["authentic"]
                      and child_evidence["authentic"]
                      and engine_status == "producer_bound_integration_passed"
                      and fresh_flag is False and original_unchanged and plan_unchanged and not stop_now)

        # -- 12. Package the minimal deployable bundle (only on a clean, authenticated pass) --
        deployment_bundle = managed_runtime = launch_instructions = None
        package_error = None
        post_package_recheck = None
        if passed:
            try:
                comparison = engine_report.get("comparison") or {}
                staging = engine_report.get("staging") or {}
                dep = comparison["deployable_app"]
                rc_pin = dep["runtimeconfig"]
                bundle = _package_bundle(
                    deploy_dir, engine_out=engine_out, project_name=inspection["name"],
                    native_library=staging.get("native_library") or spec["native_library"],
                    protected_dll=Path(dep["dll"]), runtimeconfig=Path(rc_pin["path"]),
                    native_core=Path(staging["native_core"]),
                    expected_protected_sha=dep["sha256"], expected_runtimeconfig_sha=rc_pin["sha256"],
                    expected_native_sha=staging["native_core_sha256"])
                # Post-package rechecks must not leave a success standing on drift/STOP.
                # Re-run the guarded preflight before the guarded snapshot/toolchain
                # recomputation, and re-verify ALL original base trusted pins (source
                # plan/result/report, spec/contract/sources, service modules), the saved
                # integration plan, the engine report, and STOP. Hashes are never refreshed.
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
                # Re-bind the raw child evidence AFTER packaging too, so a raw
                # receipt/log drift between the pass gate and the bundle copy cannot
                # leave a success standing (kept out of the recheck dict to preserve
                # its public shape; reported as a distinct failed key).
                post_package_child = _verify_child_evidence(engine_report, engine_out=engine_out, cases=cases)
                pins_stable = _child_evidence_pins_stable(child_evidence.get("evidence_pins") or {}, engine_out)
                if not all(post_package_recheck.values()) or not post_package_child["authentic"] or not pins_stable:
                    failed_keys = sorted(k for k, v in post_package_recheck.items() if not v)
                    if not post_package_child["authentic"]:
                        failed_keys.append("child_evidence: " + post_package_child["reason"][:200])
                    if not pins_stable:
                        failed_keys.append("child_evidence_bytes_drifted")
                    raise CSharpApplicationError(
                        "post-package recheck detected drift/STOP: " + ", ".join(failed_keys))
                deployment_bundle = {"path": bundle["path"], "files": bundle["files"]}
                managed_runtime = {"runtime": "Microsoft.NETCore.App",
                                   "framework": comparison.get("framework"),
                                   "runtime_version": comparison.get("runtime_version"),
                                   "sdk_version": comparison.get("sdk_version"),
                                   "native_core_env": "ANTIREA_NATIVE_CORE"}
                launch_instructions = _launch_instructions(deploy_dir, bundle, cases)
            except Exception as exc:
                package_error = type(exc).__name__ + ": " + str(exc)[:2048]
                passed = False
                deployment_bundle = managed_runtime = launch_instructions = None

        # -- 13. Status string + append-only service result + compact public return --
        # No failure path reports success or a bundle; STOP (incl. post-package) -> cancelled.
        stop_now = stop_now or stop.exists()
        status = "cancelled" if stop_now else (PUBLIC_STATUS_PASSED if passed else "failed")
        # Any non-passed final status (incl. a late STOP -> cancelled) must carry no
        # deployment bundle, managed-runtime block or launch instructions.
        if status != PUBLIC_STATUS_PASSED:
            deployment_bundle = managed_runtime = launch_instructions = None

        result_record = {
            "schema_version": 1, "kind": "csharp_application_integration_result",
            "status": status, "plan_id": plan_id, "integration_id": integration_id,
            "engine_module": ENGINE_MODULE, "engine_status": engine_status,
            "engine_report_path": str(engine_report_path) if engine_report_path.is_file() else None,
            "engine_report_sha256": engine_report_sha256,
            "engine_report_verification": report_verification,
            "child_evidence_verification": child_evidence,
            "integration_plan_path": str(plan_file), "integration_plan_sha256": plan_file_sha,
            "integration_plan_fingerprint": plan_record["integration_plan_fingerprint"],
            "integration_plan_unchanged_after_run": plan_unchanged,
            "application_contract": plan_record["application_contract"],
            "total_cases": len(cases), "value_cases": value_cases, "exception_cases": exception_cases,
            "reused_native_core": True, "fresh_protected_native_build": fresh_flag,
            "original_inputs_unchanged": original_unchanged,
            "snapshot_after_sha256": (_digest(_encoded(snapshot_after)) if snapshot_after is not None else None),
            "toolchain_after_sha256": (_digest(_encoded(toolchain_after)) if toolchain_after is not None else None),
            "post_package_recheck": post_package_recheck,
            "deployment_bundle": deployment_bundle, "managed_runtime_requirements": managed_runtime,
            "launch_instructions": launch_instructions,
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
            "integration_report_path": str(result_file),
            "integration_report_sha256": _digest(result_file_bytes),
            "integration_plan_path": str(plan_file), "integration_plan_sha256": plan_file_sha,
            "engine_report_path": result_record["engine_report_path"],
            "engine_report_sha256": engine_report_sha256, "engine_status": engine_status,
            "engine_report_authentic": bool(report_verification["authentic"] and child_evidence["authentic"]),
            "child_evidence_authentic": bool(child_evidence["authentic"]),
            "deployment_bundle": deployment_bundle, "managed_runtime_requirements": managed_runtime,
            "launch_instructions": launch_instructions,
            "total_cases": len(cases), "value_cases": value_cases, "exception_cases": exception_cases,
            "reused_native_core": True, "fresh_protected_native_build": fresh_flag,
            "original_inputs_unchanged": original_unchanged,
            "comparison_mismatch": child_issues["comparison_mismatch"],
            "external_attack_evaluation": "not_evaluated", "performance_evaluation": "not_evaluated",
            "defense_strength_evaluation": "not_evaluated", "public_route": PUBLIC_ROUTE,
        }
