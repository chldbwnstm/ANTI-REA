"""Pinned, independent TypeScript transpile-reference helper for mixed validation.

The mixed-module validator (antirea.javascript_mixed_validate) must, for a
TypeScript build, compare the build's declared baseline against an *independently*
produced CommonJS transpilation of the owned source -- one that does NOT reuse the
mixed compiler's own VM-lowering code path. This module is that independent
reference. It is a reusable helper, not a private test harness: the production
validator calls :func:`build_reference` directly and binds :func:`helper_tool_pins`
across the whole validation.

What it does, bounded honestly:
  * The caller supplies only an owned source path, a fresh owned output directory,
    the trusted installed toolchain descriptor map (the mixed build report's
    ``toolchain.files``, with pinned ``node`` and ``typescript`` entries), and the
    RAW source SHA-256 from the trusted build plan. Nothing else is executed: the
    owned source is never run or required, and npm is never invoked or resolved.
  * The parent reads the owned source bytes under link/reparse/hardlink rejection
    and a bounded, grow/shrink-checked read, verifies the RAW hash against the
    trusted plan, strips a single UTF-8 BOM (``utf-8-sig``, exactly as the builder),
    and pins the Node runtime, the TypeScript bundle, this module and the CJS helper
    against their reviewed hashes BEFORE launch, re-checking every pin AFTER the
    child. Any pre-launch integrity problem raises ``ValueError``; any drift that
    lands while the child runs fails the reference closed (status ``failed``).
  * A single bounded Node child (antirea.process.run_logged: timeout, defense STOP
    cancellation, logs, best-effort owned-tree cleanup -- NOT an OS sandbox) runs
    tools/typescript_frontend/mixed_reference.cjs. That child transpiles the whole
    module to CommonJS with the exact pinned mixed compile options and emits the
    reference bytes (shebang held out and re-attached byte-for-byte, as
    compile_mixed.cjs) plus strict base64/length metadata on stdout. The parent
    decodes, bounds the sizes, writes the reference ``.cjs`` itself and computes
    every hash itself.

Not performed / not claimed: no import rewriting, no module evaluation, no type
checking, no generated VM runtime. ``reference_created`` is a faithful transpile
cross-check only; it is never a defense, equivalence or attack-resistance claim.
``reference.json`` is persisted in the owned output directory even on child failure.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import stat

from .process import run_logged
from .python_frontend import _no_links as _frontend_no_links, _pairs

# Resolve the owned helper and this module relative to the package so the pins do
# not depend on the current working directory. Copied to production this resolves
# to tools/typescript_frontend/mixed_reference.cjs beside the antirea package.
_MODULE = Path(__file__).resolve()
_HELPER = _MODULE.parents[1] / "tools" / "typescript_frontend" / "mixed_reference.cjs"

SUPPORTED_LANGUAGE = "typescript"
SUPPORTED_SUFFIX = ".ts"
REFERENCE_BASENAME = "reference.cjs"
REPORT_BASENAME = "reference.json"

MAX_SOURCE_BYTES = 512 * 1024              # mirrors compile_mixed.cjs 512 KiB cap
MAX_REFERENCE_BYTES = 16 * 1024 * 1024     # emitted CommonJS upper bound
MAX_REPLY_BYTES = 32 * 1024 * 1024         # child stdout budget
MAX_HASH_BYTES = 512 * 1024 * 1024         # node.exe-sized pin inputs
MIN_TIMEOUT, MAX_TIMEOUT = 1, 600

# Reserved private/received input names refused before any read, plus the received
# handoff trees _no_links already rejects (kept here for an explicit, early message).
_RESERVED_NAMES = {"env.setting", "linkrepro", "rea-analysis-reports", "attackerfolder", "defense-loop"}
_RECEIVED_TREES = {"rea-analysis-reports", "attackerfolder"}

LIMITATIONS = [
    "The independent reference is a whole-module ts.transpileModule CommonJS emission under the pinned mixed compile options; it performs no import rewriting, module evaluation/require, type checking or VM generation.",
    "The owned source is never executed and npm is never invoked or resolved; only the trusted installed TypeScript bundle and Node builtins are used.",
    "run_logged bounds the child with a timeout, defense STOP cancellation, logs and best-effort owned-tree cleanup; this is surface reduction, NOT an OS security sandbox.",
    "Source, Node, the TypeScript bundle, this module and the CJS helper are pinned before launch and re-checked after the child; these are before/after snapshots and do not prove the absence of a transient swap-and-restore inside a single child execution.",
    "reference_created is a faithful transpile cross-check only; it is never functional equivalence, performance acceptance or external attack resistance.",
]


class TypeScriptReferenceError(ValueError):
    """Malformed input or pre-execution integrity failure (raised before the child)."""


def _no_links(path):
    # Check lexical components before even the shared link guard can stat them.
    # This applies to installed tools, source/output, workspace and helper paths.
    path = Path(os.path.abspath(path))
    if any(part.casefold() in _RESERVED_NAMES for part in path.parts):
        raise TypeScriptReferenceError("reserved private/received path cannot be used")
    return _frontend_no_links(path)


# ---------------------------------------------------------------------------
# Bounded, link-rejecting IO (stdlib; no cross-module policy)
# ---------------------------------------------------------------------------

def _hash(path):
    path = _no_links(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_HASH_BYTES:
        raise TypeScriptReferenceError("hash input must be a bounded regular file")
    value = hashlib.sha256()
    remaining = before.st_size
    with path.open("rb") as stream:
        while remaining:
            block = stream.read(min(remaining, 1024 * 1024))
            if not block:
                raise TypeScriptReferenceError("hash input shrank during read")
            remaining -= len(block)
            value.update(block)
        if stream.read(1):
            raise TypeScriptReferenceError("hash input grew during read")
    after = _no_links(path).stat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    if identity(before) != identity(after):
        raise TypeScriptReferenceError("hash input changed during read")
    return value.hexdigest()


def _read(path, cap):
    path = _no_links(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise TypeScriptReferenceError("input must be a regular file: " + str(path))
    size = info.st_size
    if size > cap:
        raise TypeScriptReferenceError("input exceeds the byte budget: " + str(path))
    with path.open("rb") as stream:
        data = stream.read(size + 1)
    if len(data) != size or path.stat().st_size != size:
        raise TypeScriptReferenceError("input changed during read: " + str(path))
    return data


def _hex64(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _owned(path, root):
    path = _no_links(path)
    if not path.is_relative_to(root):
        raise TypeScriptReferenceError("path must stay inside the workspace: " + str(path))
    if any(part.casefold() in _RECEIVED_TREES for part in path.relative_to(root).parts):
        raise TypeScriptReferenceError("untrusted/received path is not an owned input/output: " + str(path))
    return path


def _reject_reserved(path, root):
    for part in path.relative_to(root).parts:
        if part.casefold() in _RESERVED_NAMES:
            raise TypeScriptReferenceError("reserved private/received input cannot be used: " + part)


# ---------------------------------------------------------------------------
# Tool pins
# ---------------------------------------------------------------------------

def helper_tool_pins():
    """Current {path, sha256} pins for this module and the CJS helper.

    The caller (the mixed validator) binds these across the whole validation,
    re-checking them before and after the reference step and at final completion.
    """
    return [{"path": str(_no_links(_MODULE)), "sha256": _hash(_MODULE)},
            {"path": str(_no_links(_HELPER)), "sha256": _hash(_HELPER)}]


def _toolchain_entry(toolchain_files, name):
    if not isinstance(toolchain_files, dict):
        raise TypeScriptReferenceError("toolchain_files must be the mixed report toolchain.files mapping")
    entry = toolchain_files.get(name)
    if not isinstance(entry, dict) or not isinstance(entry.get("path"), str) or not _hex64(entry.get("sha256")):
        raise TypeScriptReferenceError("toolchain.files must pin " + name + " with path and sha256")
    return entry


def _pin_installed(entry, label):
    """Resolve a pinned installed tool and verify its reviewed hash BEFORE launch."""
    path = _no_links(Path(entry["path"]))
    if not path.is_file():
        raise TypeScriptReferenceError("pinned " + label + " is missing: " + str(path))
    current = _hash(path)
    if current != entry["sha256"]:
        raise TypeScriptReferenceError("pinned " + label + " changed since the reviewed build")
    return path, current


def _child_env(private_temp):
    """A clean, allow-listed environment with a fresh private TEMP (never os.environ)."""
    private_temp.mkdir(parents=True, exist_ok=False)
    allow = ("SystemRoot", "SystemDrive", "windir", "NUMBER_OF_PROCESSORS",
             "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "COMSPEC", "PATHEXT",
             "LANG", "LC_ALL", "LC_CTYPE", "TZ")
    env = {key: os.environ[key] for key in allow if key in os.environ}
    if os.name == "nt":
        system_root = env.get("SystemRoot") or env.get("windir") or "C:\\Windows"
        env["PATH"] = os.pathsep.join([str(Path(system_root) / "System32"), str(Path(system_root))])
    else:
        env["PATH"] = "/usr/bin:/bin"
    env["TEMP"] = env["TMP"] = env["TMPDIR"] = str(private_temp)
    return env


# ---------------------------------------------------------------------------
# Strict child-reply validation (the parent trusts no child-asserted value)
# ---------------------------------------------------------------------------

def _require(condition, message):
    if not condition:
        raise TypeScriptReferenceError(message)


def _decode_b64(value, cap, label):
    _require(isinstance(value, str) and len(value) <= cap * 2, label + " must be a bounded base64 string")
    try:
        raw = base64.b64decode(value, validate=True)  # binascii.Error is a ValueError subclass
    except ValueError as exc:
        raise TypeScriptReferenceError(label + " is not valid base64: " + type(exc).__name__) from exc
    if len(raw) > cap:
        raise TypeScriptReferenceError(label + " exceeds the byte budget")
    return raw


def _validate_ok_reply(reply):
    """Validate a status=ok reply and return (shebang_bytes, working_bytes, reference_bytes, meta)."""
    _require(isinstance(reply, dict) and reply.get("status") == "ok", "reply must be a status=ok object")
    _require(reply.get("language") == SUPPORTED_LANGUAGE, "reply language must be typescript")
    _require(reply.get("transpiled") is True, "reply must declare transpiled=true")
    _require(reply.get("source_executed") is False, "reply must declare source_executed=false")
    _require(isinstance(reply.get("compiler_version"), str) and 0 < len(reply["compiler_version"]) <= 64,
             "reply must carry a bounded compiler_version string")
    _require(type(reply.get("shebang_present")) is bool, "reply must declare shebang_present as a boolean")
    for key in ("shebang_bytes", "working_bytes", "reference_bytes"):
        _require(type(reply.get(key)) is int and reply[key] >= 0, "reply." + key + " must be a non-negative integer")
    shebang = _decode_b64(reply.get("shebang_b64"), MAX_REFERENCE_BYTES, "reply.shebang_b64")
    working = _decode_b64(reply.get("working_b64"), MAX_REFERENCE_BYTES, "reply.working_b64")
    reference = _decode_b64(reply.get("reference_b64"), MAX_REFERENCE_BYTES, "reply.reference_b64")
    _require(len(shebang) == reply["shebang_bytes"], "reply shebang length disagrees with the emitted bytes")
    _require(len(working) == reply["working_bytes"], "reply working length disagrees with the emitted bytes")
    _require(len(reference) == reply["reference_bytes"], "reply reference length disagrees with the emitted bytes")
    _require(reply["shebang_present"] == bool(shebang), "reply shebang_present disagrees with the emitted shebang")
    # The reference is exactly the held-out shebang re-attached to the emitted JS
    # (byte-for-byte as compile_mixed.cjs / the mixed builder's baseline.cjs).
    _require(reference == shebang + working, "reference bytes must be the shebang re-attached to the working source")
    return shebang, working, reference, reply["compiler_version"]


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def _pin_snapshot(source_path, node_path, ts_path):
    return {"source": _hash(source_path), "node": _hash(node_path), "typescript": _hash(ts_path),
            "helper": _hash(_HELPER), "module": _hash(_MODULE)}


def _cleanup_ok(process):
    """Require verified owned process-tree cleanup before a reference may be trusted.

    On Windows the helper itself (not only the caller) refuses ``reference_created``
    unless run_logged confirmed an empty, closed, kill-on-close Job for the child.
    """
    if os.name != "nt":
        return True
    cleanup = process.get("cleanup") or {}
    return (cleanup.get("job_assigned") is True and cleanup.get("parent_exit_confirmed") is True
            and cleanup.get("job_handle_closed") is True and cleanup.get("active_after") == 0
            and cleanup.get("status") == "assigned_job_empty")


def build_reference(source_path, output_dir, *, workspace_root, toolchain_files,
                    expected_source_sha256, timeout_seconds=60):
    """Produce an independent pinned CommonJS transpile reference of one owned TS module.

    Returns a JSON-safe dict (also written to ``output_dir/reference.json``) with
    ``status`` one of ``reference_created``/``failed``/``cancelled``/``timed_out``.
    Malformed inputs or pre-launch integrity drift raise ``ValueError`` before the
    child runs; once the child has run, ``reference.json`` is always persisted.
    """
    root = _no_links(Path(workspace_root))
    if not root.is_dir():
        raise TypeScriptReferenceError("workspace_root must be an existing directory")
    if type(timeout_seconds) is not int or not MIN_TIMEOUT <= timeout_seconds <= MAX_TIMEOUT:
        raise TypeScriptReferenceError("timeout_seconds must be an integer in 1..600")
    if not _hex64(expected_source_sha256):
        raise TypeScriptReferenceError("expected_source_sha256 must be a 64-hex RAW source digest")

    source = _owned(source_path, root)
    _reject_reserved(source, root)
    if source.suffix.lower() != SUPPORTED_SUFFIX:
        raise TypeScriptReferenceError("the independent reference supports a single owned .ts module only")
    if not source.is_file():
        raise TypeScriptReferenceError("owned TypeScript source is missing: " + str(source))

    output = _owned(output_dir, root)
    _reject_reserved(output, root)
    # The reference output must be fresh, under <workspace>/.runs, and outside the
    # owned source tree so an emitted artifact can never overwrite or shadow owned
    # source and always lands in the defender run area.
    if not output.is_relative_to(root / ".runs"):
        raise TypeScriptReferenceError("reference output must be under <workspace>/.runs")
    if output.exists():
        raise TypeScriptReferenceError("reference output must be a fresh directory")
    if output == source.parent or output.is_relative_to(source.parent) or source.is_relative_to(output):
        raise TypeScriptReferenceError("reference output must be outside the owned source tree")

    node_entry = _toolchain_entry(toolchain_files, "node")
    ts_entry = _toolchain_entry(toolchain_files, "typescript")

    # --- Pin the owned source and the installed toolchain BEFORE launch. Any
    #     pre-execution integrity problem is a hard ValueError (no child runs). ---
    raw = _read(source, MAX_SOURCE_BYTES)
    source_sha256 = hashlib.sha256(raw).hexdigest()
    if source_sha256 != expected_source_sha256:
        raise TypeScriptReferenceError("owned source changed since the trusted build plan (RAW digest drift)")
    try:
        normalized_text = raw.decode("utf-8-sig")
    except UnicodeError as exc:
        raise TypeScriptReferenceError("owned source is not valid UTF-8: " + type(exc).__name__) from exc
    normalized_bytes = normalized_text.encode("utf-8")
    normalized_source_sha256 = hashlib.sha256(normalized_bytes).hexdigest()

    node_path, node_sha = _pin_installed(node_entry, "node runtime")
    ts_path, ts_sha = _pin_installed(ts_entry, "TypeScript bundle")
    if not _HELPER.is_file():
        raise TypeScriptReferenceError("trusted reference helper is missing: " + str(_HELPER))
    pins_before = _pin_snapshot(source, node_path, ts_path)
    # The pre-launch snapshot must equal the already-reviewed raw source and pinned
    # node/TypeScript hashes; any mismatch means the input changed between the
    # reviewed read and the snapshot, so fail closed before any child launches.
    if (pins_before["source"] != source_sha256 or pins_before["node"] != node_sha
            or pins_before["typescript"] != ts_sha):
        raise TypeScriptReferenceError(
            "source/toolchain changed between the reviewed read and the pre-launch pin snapshot")

    tool_pins = {
        "source": {"path": str(source), "sha256": source_sha256, "bytes": len(raw)},
        "node": {"path": str(node_path), "sha256": node_sha},
        "typescript": {"path": str(ts_path), "sha256": ts_sha},
        "helper": {"path": str(_no_links(_HELPER)), "sha256": pins_before["helper"]},
        "module": {"path": str(_no_links(_MODULE)), "sha256": pins_before["module"]},
    }

    result = {
        "schema_version": 1, "status": "failed",
        "backend": "typescript_independent_transpile_reference", "language": SUPPORTED_LANGUAGE,
        "source_path": str(source), "output_dir": str(output),
        "source_sha256": source_sha256, "normalized_source_sha256": normalized_source_sha256,
        "working_source_sha256": None, "shebang_present": None, "transpiled": None,
        "compiler": {"typescript_path": str(ts_path), "node_path": str(node_path), "typescript_version": None},
        "tool_pins": tool_pins, "pin_recheck": None, "reference": None,
        "process": None, "timeout_seconds": timeout_seconds,
        "source_executed": False, "type_checking": "not_performed_whole_module_transpile_only",
        "limitations": list(LIMITATIONS),
    }

    def _persist():
        (output / REPORT_BASENAME).write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        return result

    stop = root / ".runs" / "defense-loop" / "STOP"
    if stop.exists():
        output.mkdir(parents=True)
        result["status"] = "cancelled"
        result["reason"] = "defense STOP exists before launch"
        return _persist()

    output.mkdir(parents=True)
    env = _child_env(output / "tmp")
    request = json.dumps({"source": normalized_text, "language": SUPPORTED_LANGUAGE})
    command = [str(node_path), "--no-addons", "--max-old-space-size=256", str(_no_links(_HELPER)), str(ts_path)]

    process = run_logged(command, output, output / "worker", timeout_seconds,
                         env=env, stdin=request, cancel_file=stop)
    result["process"] = process

    # Re-check every pin AFTER the child; drift while the child ran fails closed.
    try:
        pins_after = _pin_snapshot(source, node_path, ts_path)
    except (ValueError, OSError) as exc:
        pins_after = {}
        result["pin_recheck"] = {"ok": False, "error": str(exc)}
    pin_drift = sorted(name for name in pins_before if pins_after.get(name) != pins_before[name])
    if result["pin_recheck"] is None:
        result["pin_recheck"] = {"ok": not pin_drift, "drift": pin_drift}

    if process.get("cancelled"):
        result["status"] = "cancelled"
        result["reason"] = "defense STOP observed during the child"
        return _persist()
    if process.get("timed_out"):
        result["status"] = "timed_out"
        result["error"] = "independent TypeScript reference child timed out"
        return _persist()
    if pin_drift:
        result["status"] = "failed"
        result["error"] = "pinned input changed while the child ran: " + ", ".join(pin_drift)
        return _persist()
    result["cleanup_verified"] = _cleanup_ok(process)
    if not result["cleanup_verified"]:
        result["status"] = "failed"
        result["error"] = "independent TypeScript compiler child-tree cleanup could not be verified"
        return _persist()

    # Parse and strictly validate the child reply from the captured stdout log.
    try:
        reply_bytes = _read(Path(process["stdout"]), MAX_REPLY_BYTES)
        reply = json.loads(reply_bytes.decode("utf-8"), object_pairs_hook=_pairs)
    except (TypeScriptReferenceError, UnicodeError, json.JSONDecodeError, ValueError, OSError) as exc:
        result["status"] = "failed"
        result["error"] = "could not read a valid child reply: " + type(exc).__name__ + ": " + str(exc)[:512]
        return _persist()

    if not isinstance(reply, dict) or reply.get("status") != "ok":
        result["status"] = "failed"
        detail = reply.get("error") if isinstance(reply, dict) else None
        result["error"] = "child rejected the transpile: " + str(detail)[:512] if detail else "child did not return status=ok"
        return _persist()
    if process.get("returncode") != 0:
        result["status"] = "failed"
        result["error"] = "child exited non-zero despite an ok reply (returncode "+ str(process.get("returncode")) + ")"
        return _persist()

    try:
        shebang, working, reference, compiler_version = _validate_ok_reply(reply)
    except TypeScriptReferenceError as exc:
        result["status"] = "failed"
        result["error"] = "malformed child reply: " + str(exc)[:512]
        return _persist()

    if len(reference) > MAX_REFERENCE_BYTES:
        result["status"] = "failed"
        result["error"] = "emitted reference exceeds the byte budget"
        return _persist()

    # The parent writes the reference file itself (exclusive create) and re-reads
    # it back to confirm the on-disk bytes, then computes every hash itself.
    reference_path = output / REFERENCE_BASENAME
    with reference_path.open("xb") as stream:
        stream.write(reference)
    written = _read(reference_path, MAX_REFERENCE_BYTES)
    if written != reference:
        result["status"] = "failed"
        result["error"] = "reference file on disk does not match the emitted bytes"
        return _persist()

    result["status"] = "reference_created"
    result.pop("error", None)
    result["transpiled"] = True
    result["shebang_present"] = bool(shebang)
    result["working_source_sha256"] = hashlib.sha256(working).hexdigest()
    result["compiler"]["typescript_version"] = compiler_version
    result["reference"] = {"path": str(reference_path),
                           "sha256": hashlib.sha256(reference).hexdigest(), "bytes": len(reference)}
    return _persist()
