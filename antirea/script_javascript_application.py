"""Stage an ordinary owned JavaScript/TypeScript application around one protected module.

Defender-only staging adapter for the phase24 script application integration
route (JAVASCRIPT lane; TypeScript routes through here too). :func:`prepare_application`
builds a fresh adapter-owned output directory with two runtime trees that the
shared engine runs and compares after root freeze:

* ``original`` -- the ordinary application with an INDEPENDENT, runnable CommonJS
  rendering of the original selected core at the core's runtime path; and
* ``protected`` -- the same application with that core replaced by the producer's
  reused protected CommonJS artifact, every other runtime file byte-identical.

The original core rendering is derived INDEPENDENTLY of the producer, never from
the producer baseline/IR (the pure producer baseline is an export-stripped,
printer/transpiler artifact, not the application truth):

* pure ``javascript_vm`` producer (JS or TS): the original exported core source is
  independently transpiled to CommonJS with the pinned compiler via the trusted
  ``tools/typescript_frontend/application_reference.cjs`` child (receipts recorded);
* mixed ``javascript_mixed_module_vm`` producer: a JavaScript original is copied
  raw byte-for-byte (BOM/CRLF retained); a TypeScript original is independently
  transpiled with the same pinned options (never the producer baseline as truth).

Ordinary surrounding files are handled per suffix: ``.ts`` are independently
transpiled to ``.js`` with the same pinned options in BOTH arms; ``.js``/``.cjs``/
``.json``/``.txt`` are preserved byte-for-byte in both arms. No original ``.ts``
source, source map, baseline, IR or report ever enters a runtime tree.

This module STAGES ONLY. It never runs the application. The only child process it
may launch is the reviewed, fixed transpile-reference compiler (TS, and pure JS
export->CJS), bounded under run_logged with a private env/TEMP and Windows Job
receipts; the engine runs and compares the arms. A successful staging is not
functional preservation, performance acceptance or attack-resistance evidence.

The security-critical path helpers (lexical reserved-component rejection,
symlink/reparse/hardlink rejection, bounded hashing, bounded tree inventory,
private dirs and the strict Windows-Job receipt predicate) are reused from
:mod:`antirea.jvm_app_integration` so every language route shares one audited
implementation; the bounded child runner is :mod:`antirea.process`.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import time

from . import jvm_app_integration as safe, process

LANGUAGES = ("javascript", "typescript")
PURE_BACKEND = "javascript_vm"
MIXED_BACKEND = "javascript_mixed_module_vm"
PRODUCER_BACKENDS = (PURE_BACKEND, MIXED_BACKEND)
PRODUCER_OK_STATUS = "artifact_created_unvalidated"
# Reused producer artifacts are CommonJS (.cjs) on both the baseline and protected
# arms. The adapter only ever overlays the ``protected`` artifact.
PRODUCER_ARTIFACT_SUFFIX = ".cjs"

# The trusted transpile-reference child (owned JAVASCRIPT lane tool), pinned here
# by its known in-repo path and re-hashed; cross-checked against trusted_inputs.
REFERENCE_HELPER = Path(__file__).resolve().parents[1] / "tools" / "typescript_frontend" / "application_reference.cjs"

# Authoring (spec) suffixes per language.
_APP_SUFFIXES = {
    "javascript": {".js", ".cjs", ".json", ".txt"},
    "typescript": {".ts", ".js", ".cjs", ".json", ".txt"},
}
_ENTRYPOINT_SUFFIXES = {"javascript": {".js", ".cjs"}, "typescript": {".ts", ".js", ".cjs"}}
_PROTECTED_SOURCE_SUFFIXES = {"javascript": {".js", ".cjs"}, "typescript": {".ts"}}
_CODE_RUNTIME_SUFFIXES = {".js", ".cjs"}
# Always-rejected authoring filenames (declaration/JSX/ESM-runtime/source maps),
# checked on the full lowercased basename (``.d.ts`` is two suffixes).
_REJECT_NAME_SUFFIXES = (".d.ts", ".tsx", ".mts", ".cts", ".mjs", ".map")
# Runtime module specifiers the staged CommonJS app must never require/import.
_REJECT_SPECIFIER_SUFFIXES = (".d.ts", ".ts", ".tsx", ".mts", ".cts", ".mjs")
_FORBIDDEN_COMPONENTS = frozenset({"__pycache__", "node_modules"})
_DOS_DEVICES = frozenset(
    {"con", "prn", "aux", "nul",
     *("com%d" % i for i in range(1, 10)), *("lpt%d" % i for i in range(1, 10))})

MAX_APPLICATION_FILES = 128
MAX_FILE_BYTES = 16 << 20            # 16 MiB per staged / transpiled file
MAX_TOTAL_BYTES = 64 << 20           # 64 MiB total across the staged file set
MAX_PREP_STDOUT_BYTES = 128 << 20    # bounded read of the helper reply (base64 inflation)
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


class ScriptJavaScriptApplicationError(ValueError):
    """Any spec/producer/identity/tool/staging inconsistency (fail closed)."""


def _wrap(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except safe.JvmIntegrateError as exc:
        raise ScriptJavaScriptApplicationError(str(exc)) from exc


def _sha(value) -> str:
    if not isinstance(value, str) or not _SHA256_RE.match(value):
        raise ScriptJavaScriptApplicationError("Missing or malformed SHA256 (64 lowercase hex): %r" % (value,))
    return value


def _relative(value) -> str:
    """Validate a clean forward-slash relative path and return its posix form.

    Rejects empty/whitespace-padded, backslash/drive, NUL/control, absolute,
    ``.``/``..``, reserved/received components, build caches and Windows DOS device
    names LEXICALLY, before any filesystem access.
    """
    if (not isinstance(value, str) or not value or value != value.strip()
            or "\\" in value or ":" in value or value.startswith("/")):
        raise ScriptJavaScriptApplicationError("Expected a clean relative forward-slash path: %r" % (value,))
    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in value):
        raise ScriptJavaScriptApplicationError("Relative path holds a control character: %r" % (value,))
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ScriptJavaScriptApplicationError("Relative path is empty or traverses: %r" % (value,))
    for part in parts:
        folded = part.casefold()
        if part != part.rstrip(" .") or part.startswith(" "):
            raise ScriptJavaScriptApplicationError("Relative path component has a trailing/leading dot or space: %r" % (value,))
        if folded in safe.RESERVED_PATH_COMPONENTS or folded in _FORBIDDEN_COMPONENTS:
            raise ScriptJavaScriptApplicationError("Relative path traverses a reserved/forbidden component %r: %s" % (part, value))
        if part.split(".", 1)[0].casefold() in _DOS_DEVICES:
            raise ScriptJavaScriptApplicationError("Relative path uses a reserved Windows device name: %r" % (value,))
    return "/".join(parts)


def _suffix(relative: str) -> str:
    name = relative.rsplit("/", 1)[-1].lower()
    return ("." + name.rsplit(".", 1)[-1]) if "." in name else ""


def _reject_name(relative: str) -> None:
    name = relative.rsplit("/", 1)[-1].lower()
    for bad in _REJECT_NAME_SUFFIXES:
        if name.endswith(bad):
            raise ScriptJavaScriptApplicationError("rejected declaration/JSX/ESM/source-map file: " + relative)


def _runtime_rel(relative: str, language: str) -> str:
    """Map an authoring relative path to its CommonJS runtime relative path."""
    if language == "typescript" and _suffix(relative) == ".ts":
        return relative[: -len(".ts")] + ".js"
    return relative


def _nolink(path) -> Path:
    return _wrap(safe._no_links, Path(os.path.abspath(path)))


def _fs(root: Path, rel: str) -> Path:
    target = _nolink(root / Path(*PurePosixPath(rel).parts))
    if not target.is_relative_to(root):
        raise ScriptJavaScriptApplicationError("Relative path escapes its root: %s" % (rel,))
    return target


def _ensure_dir(path) -> Path:
    p = _nolink(path)
    if p.exists():
        if not p.is_dir() or any(p.iterdir()):
            raise ScriptJavaScriptApplicationError("Adapter output must be a fresh empty directory: %s" % (p,))
    else:
        p.mkdir(parents=True)
    return p


def _stop(stop_file) -> None:
    # Existence probe ONLY; the real STOP lives under the reserved ``defense-loop``
    # component, so it must never be routed through the reserved-component guard.
    if stop_file is not None and Path(os.path.abspath(stop_file)).exists():
        raise ScriptJavaScriptApplicationError("defense STOP marker present; refusing to stage")


def _write_bytes(dest: Path, data: bytes, expected: str) -> str:
    _nolink(dest)
    if dest.exists():
        raise ScriptJavaScriptApplicationError("staged filename collision: %s" % (dest,))
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("xb") as stream:
        stream.write(data)
    written = _wrap(safe._hash_file, dest, limit=MAX_FILE_BYTES)
    if written != expected:
        raise ScriptJavaScriptApplicationError("staged file hash mismatch: %s" % (dest,))
    return written


def _verify_artifact(entry, arm: str) -> dict:
    if (not isinstance(entry, dict) or not isinstance(entry.get("path"), str) or not entry["path"]
            or type(entry.get("bytes")) is not int):
        raise ScriptJavaScriptApplicationError("producer %s artifact entry is malformed" % arm)
    claimed = _sha(entry.get("sha256"))
    path = _nolink(entry["path"])
    if path.suffix.lower() != PRODUCER_ARTIFACT_SUFFIX or not path.is_file():
        raise ScriptJavaScriptApplicationError("producer %s artifact is missing or not a .cjs file: %s" % (arm, path))
    data = _wrap(safe._read_bytes_bounded, path, limit=MAX_FILE_BYTES)
    if hashlib.sha256(data).hexdigest() != claimed or len(data) != entry["bytes"]:
        raise ScriptJavaScriptApplicationError("producer %s artifact bytes/size disagree with the saved hash" % arm)
    return {"path": str(path), "sha256": claimed, "bytes": len(data), "data": data}


def _bind_producer(producer) -> dict:
    """Authenticate the reused producer report; return language/mode/artifacts/roots."""
    if not isinstance(producer, dict):
        raise ScriptJavaScriptApplicationError("producer report must be a JSON object")
    if type(producer.get("schema_version")) is not int or producer["schema_version"] != 1:
        raise ScriptJavaScriptApplicationError("producer schema_version must be the integer 1")
    if producer.get("status") != PRODUCER_OK_STATUS:
        raise ScriptJavaScriptApplicationError("producer must be a successful unvalidated source build")
    backend = producer.get("backend")
    if backend not in PRODUCER_BACKENDS:
        raise ScriptJavaScriptApplicationError("producer backend is not a supported JavaScript/TypeScript VM backend")
    project = producer.get("project")
    if not isinstance(project, dict) or project.get("language") not in LANGUAGES:
        raise ScriptJavaScriptApplicationError("producer project identity is missing or not javascript/typescript")
    language = project["language"]
    source_sha = project.get("source_sha256")
    if not isinstance(source_sha, str) or not _SHA256_RE.match(source_sha):
        raise ScriptJavaScriptApplicationError("producer project is missing a valid original source_sha256")
    roots = project.get("functions")
    if (not isinstance(roots, list) or not roots
            or any(not isinstance(name, str) or not name for name in roots)):
        raise ScriptJavaScriptApplicationError("producer project must list the selected root function names")
    artifacts = producer.get("artifacts")
    if not isinstance(artifacts, dict) or not {"baseline", "protected"} <= set(artifacts):
        raise ScriptJavaScriptApplicationError("producer must record baseline and protected artifacts")
    baseline = _verify_artifact(artifacts["baseline"], "baseline")
    protected = _verify_artifact(artifacts["protected"], "protected")
    if baseline["sha256"] == protected["sha256"]:
        raise ScriptJavaScriptApplicationError("baseline and protected artifacts are byte-identical (no protection)")
    coverage = producer.get("coverage")
    if not isinstance(coverage, dict) or coverage.get("original_selected_bodies_in_protected_artifact") is not False:
        raise ScriptJavaScriptApplicationError("producer coverage is missing or retains original bodies in the artifact")
    return {"backend": backend, "mode": "pure" if backend == PURE_BACKEND else "mixed",
            "language": language, "original_source_sha256": source_sha, "roots": list(roots),
            "protected": protected, "baseline": {k: baseline[k] for k in ("path", "sha256", "bytes")}}


def _pin_tool(tools: dict, role: str, *, required: bool) -> dict | None:
    item = tools.get(role)
    if item is None:
        if required:
            raise ScriptJavaScriptApplicationError("tools must include %s as {path, sha256}" % role)
        return None
    if (not isinstance(item, dict) or not isinstance(item.get("path"), str) or not item["path"]
            or not _SHA256_RE.match(str(item.get("sha256", "")))):
        raise ScriptJavaScriptApplicationError("tool %r must be {path, sha256}" % role)
    path = _nolink(item["path"])
    if not path.is_file():
        raise ScriptJavaScriptApplicationError("tool %r is missing on disk" % role)
    actual = _wrap(safe._hash_file, path, limit=512 << 20)
    if actual != item["sha256"]:
        raise ScriptJavaScriptApplicationError("tool %r changed on disk since it was pinned" % role)
    return {"path": str(path), "sha256": actual}


def _pin_helper(trusted_inputs: dict) -> dict:
    """Require the transpile-reference helper to be a PLANNED trusted pin and match disk.

    The helper is the owned child the engine cannot re-verify from outside the
    adapter call, so it must be a planned input (fail closed if absent or drifted),
    never silently accepted.
    """
    helper = _nolink(REFERENCE_HELPER)
    if not helper.is_file():
        raise ScriptJavaScriptApplicationError("trusted transpile-reference helper is missing: %s" % helper)
    actual = _wrap(safe._hash_file, helper, limit=MAX_FILE_BYTES)
    normcase = os.path.normcase(str(helper))
    planned = None
    for raw, digest in trusted_inputs.items():
        try:
            candidate = _nolink(raw)
        except ScriptJavaScriptApplicationError:
            continue
        if os.path.normcase(str(candidate)) == normcase:
            planned = digest
            break
    if planned is None:
        raise ScriptJavaScriptApplicationError("transpile-reference helper is not a planned trusted input: %s" % helper)
    if planned != actual:
        raise ScriptJavaScriptApplicationError("planned transpile-reference helper disagrees with disk")
    return {"path": str(helper), "sha256": actual}


def _verify_pins(pins: dict, stop_file) -> None:
    """Re-check STOP and re-hash every planned pin from disk (fail closed).

    Called immediately before AND after the helper child. Large tools are NOT
    skipped: the adapter launches a single bounded child, so re-hashing every pin
    around it is tractable and required by the brief.
    """
    _stop(stop_file)
    for path, sha in pins.items():
        if _wrap(safe._hash_file, path, limit=512 << 20) != sha:
            raise ScriptJavaScriptApplicationError("pinned input changed on disk around the transpile child: " + path)


def _node_env(output_dir: Path, node_path: str) -> dict:
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    node_dir = str(Path(node_path).parent)
    priv_tmp, priv_home = safe._private_dirs(output_dir)
    return {
        "SystemRoot": sysroot, "windir": sysroot, "SystemDrive": "C:",
        "COMSPEC": str(Path(sysroot) / "System32" / "cmd.exe"),
        "PATHEXT": ".COM;.EXE;.BAT;.CMD",
        "PATH": os.pathsep.join([node_dir, sysroot + r"\System32", sysroot]),
        "TEMP": str(priv_tmp), "TMP": str(priv_tmp), "USERPROFILE": str(priv_home),
        "APPDATA": str(priv_home / "AppData" / "Roaming"),
        "LOCALAPPDATA": str(priv_home / "AppData" / "Local"),
        "PROCESSOR_ARCHITECTURE": os.environ.get("PROCESSOR_ARCHITECTURE", "AMD64"),
    }


def _reject_specifiers(specifiers, where: str) -> None:
    if not isinstance(specifiers, list) or len(specifiers) > 4096:
        raise ScriptJavaScriptApplicationError("helper did not report a bounded specifier list for " + where)
    for spec in specifiers:
        if not isinstance(spec, str):
            raise ScriptJavaScriptApplicationError("non-string require specifier reported for " + where)
        # Strip a trailing query/fragment before the suffix test, as the root
        # verifier does, so `./x.ts?v=1` / `./x.ts#frag` cannot slip through.
        base = spec.split("?", 1)[0].split("#", 1)[0].lower()
        if any(base.endswith(bad) for bad in _REJECT_SPECIFIER_SUFFIXES):
            raise ScriptJavaScriptApplicationError(
                "%s requires an unsupported non-CommonJS runtime specifier: %s" % (where, spec))


def _run_reference(*, helper: dict, node: dict, typescript: dict, language: str, files: list,
                   output_dir: Path, logs_dir: Path, pins: dict, deadline: float, stop_file) -> tuple:
    """Run the fixed transpile-reference child once; return (results_by_key, prep_entry, reply, request_record).

    Every planned pin (input sources, node, typescript, helper, trusted_inputs) and
    the persisted request are re-verified from disk, with the STOP marker and the
    total monotonic preparation deadline, immediately before AND after the child.
    """
    request = {"language": language, "files": files}
    request_text = json.dumps(request, ensure_ascii=True, allow_nan=False, sort_keys=True)
    request_bytes = request_text.encode("utf-8")
    request_path = output_dir / "transpile.request.json"
    with request_path.open("xb") as stream:
        stream.write(request_bytes)
    request_sha = hashlib.sha256(request_bytes).hexdigest()
    request_record = {"path": str(request_path), "sha256": request_sha, "receipt_index": 0}
    # The persisted request joins the pin set so tampering with it around the child
    # also fails closed.
    pins = {**pins, str(request_path): request_sha}

    _verify_pins(pins, stop_file)                                   # pre-child integrity
    remaining = deadline - time.monotonic()
    if remaining < 1:
        raise ScriptJavaScriptApplicationError("preparation deadline exceeded before the transpile child")
    argv = [node["path"], "--no-addons", helper["path"], typescript["path"]]
    prefix = logs_dir / "001"
    proc = process.run_logged([str(a) for a in argv], output_dir, prefix, min(int(remaining), 600),
                              env=_node_env(output_dir, node["path"]), stdin=request_text,
                              cancel_file=Path(os.path.abspath(stop_file)) if stop_file is not None else None)
    _verify_pins(pins, stop_file)                                   # post-child integrity
    if time.monotonic() > deadline:
        raise ScriptJavaScriptApplicationError("preparation deadline exceeded during the transpile child")
    record = _wrap(safe._persisted_receipt, proc, prefix)
    if proc != record["parsed"]:
        raise ScriptJavaScriptApplicationError("returned and persisted transpile receipts differ")
    if not safe._strict_receipt_clean(record["parsed"]) or record["parsed"].get("returncode") != 0:
        raise ScriptJavaScriptApplicationError("transpile-reference child did not exit cleanly with returncode 0")
    reply_bytes = _wrap(safe._read_bytes_bounded, record["stdout_log"], limit=MAX_PREP_STDOUT_BYTES)
    _wrap(safe._read_bytes_bounded, record["stderr_log"], limit=MAX_PREP_STDOUT_BYTES)
    try:
        reply = json.loads(reply_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScriptJavaScriptApplicationError("transpile-reference reply is not valid JSON: %s" % exc)
    if not isinstance(reply, dict) or reply.get("status") != "ok" or reply.get("language") != language:
        raise ScriptJavaScriptApplicationError("transpile-reference rejected the request: %r"
                                               % (reply.get("error") if isinstance(reply, dict) else reply,))
    results = reply.get("results")
    if not isinstance(results, list) or len(results) != len(files):
        raise ScriptJavaScriptApplicationError("transpile-reference returned the wrong number of results")
    results_by_key = {}
    for row in results:
        if not isinstance(row, dict) or not isinstance(row.get("key"), str):
            raise ScriptJavaScriptApplicationError("transpile-reference result row is malformed")
        if row["key"] in results_by_key:
            raise ScriptJavaScriptApplicationError("duplicate transpile result key: " + row["key"])
        results_by_key[row["key"]] = row
    if set(results_by_key) != {f["key"] for f in files}:
        raise ScriptJavaScriptApplicationError("transpile results do not cover exactly the requested files")
    prep_entry = {"label": "transpile-" + language, "kind": "transpile",
                  "receipt_path": record["receipt_path"], "receipt_sha256": record["receipt_sha256"],
                  "stdout_log": record["stdout_log"], "stderr_log": record["stderr_log"],
                  "returncode": record["parsed"]["returncode"], "argv": [str(a) for a in argv]}
    return results_by_key, prep_entry, reply, request_record


def _decode_output(row: dict, where: str) -> bytes:
    b64 = row.get("output_b64")
    if not isinstance(b64, str):
        raise ScriptJavaScriptApplicationError("transpile result missing output for " + where)
    try:
        data = base64.b64decode(b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise ScriptJavaScriptApplicationError("transpile output for %s is not valid base64: %s" % (where, exc))
    if type(row.get("output_bytes")) is not int or row["output_bytes"] != len(data):
        raise ScriptJavaScriptApplicationError("transpile output byte count disagrees for " + where)
    if len(data) > MAX_FILE_BYTES:
        raise ScriptJavaScriptApplicationError("transpile output exceeds the per-file bound for " + where)
    return data


def prepare_application(*, source_root, input_files, protected_source, entrypoint, producer,
                        output_dir, tools, trusted_inputs, timeout_seconds, stop_file) -> dict:
    """Stage the original and protected JS/TS application trees (no app execution).

    Returns exactly the 11 adapter keys documented in the phase24 brief. The engine
    runs/compares the arms after root freeze and independently re-derives every
    result from the retained receipts, request bytes and runtime-tree inventories.
    """
    if type(timeout_seconds) is not int or isinstance(timeout_seconds, bool) or not 1 <= timeout_seconds <= 600:
        raise ScriptJavaScriptApplicationError("timeout_seconds must be an int in 1..600")
    deadline = time.monotonic() + timeout_seconds
    _stop(stop_file)
    source_root = _nolink(source_root)
    if not source_root.is_dir():
        raise ScriptJavaScriptApplicationError("source_root must be an existing directory")
    if not isinstance(input_files, dict) or not 1 <= len(input_files) <= MAX_APPLICATION_FILES:
        raise ScriptJavaScriptApplicationError("input_files must map 1..%d relative paths to SHA256" % MAX_APPLICATION_FILES)
    if not isinstance(tools, dict):
        raise ScriptJavaScriptApplicationError("tools must be a mapping")
    if not isinstance(trusted_inputs, dict):
        raise ScriptJavaScriptApplicationError("trusted_inputs must be a mapping of absolute paths to SHA256")
    for value in trusted_inputs.values():
        _sha(value)

    bound = _bind_producer(producer)
    language = bound["language"]

    # Validate the explicit relative file set (lexical, before any copy/traversal).
    rels, casefold = {}, {}
    for value, digest in input_files.items():
        rel = _relative(value)
        _reject_name(rel)
        if _suffix(rel) not in _APP_SUFFIXES[language]:
            raise ScriptJavaScriptApplicationError("unsupported %s application file suffix: %s" % (language, rel))
        folded = rel.casefold()
        if folded in casefold:
            raise ScriptJavaScriptApplicationError("duplicate or case-folding file collision: %s vs %s" % (rel, casefold[folded]))
        casefold[folded] = rel
        rels[rel] = _sha(digest)

    prot_rel = _relative(protected_source)
    entry_rel = _relative(entrypoint)
    if prot_rel not in rels or entry_rel not in rels:
        raise ScriptJavaScriptApplicationError("protected_source and entrypoint must be listed application files")
    if prot_rel == entry_rel:
        raise ScriptJavaScriptApplicationError("entrypoint must differ from protected_source so an ordinary caller runs it")
    if _suffix(prot_rel) not in _PROTECTED_SOURCE_SUFFIXES[language]:
        raise ScriptJavaScriptApplicationError("protected_source suffix is not valid for " + language)
    if _suffix(entry_rel) not in _ENTRYPOINT_SUFFIXES[language]:
        raise ScriptJavaScriptApplicationError("entrypoint suffix is not a runnable source for " + language)

    protected_relative = _runtime_rel(prot_rel, language)
    runtime_entrypoint = _runtime_rel(entry_rel, language)
    if _suffix(protected_relative) not in _CODE_RUNTIME_SUFFIXES or _suffix(runtime_entrypoint) not in _CODE_RUNTIME_SUFFIXES:
        raise ScriptJavaScriptApplicationError("core/entrypoint runtime path is not a runnable CommonJS module")
    if protected_relative == runtime_entrypoint:
        raise ScriptJavaScriptApplicationError("runtime entrypoint must differ from the protected module path")

    # Verify every on-disk input against its frozen snapshot hash; read bytes/text.
    total = 0
    raw_bytes, text_source, source_pins = {}, {}, {}
    for rel, digest in rels.items():
        path = _fs(source_root, rel)
        if not path.is_file():
            raise ScriptJavaScriptApplicationError("declared application file is missing: %s" % rel)
        data = _wrap(safe._read_bytes_bounded, path, limit=MAX_FILE_BYTES)
        if hashlib.sha256(data).hexdigest() != digest:
            raise ScriptJavaScriptApplicationError("application file changed since the snapshot: %s" % rel)
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise ScriptJavaScriptApplicationError("staged application exceeds the total byte bound")
        raw_bytes[rel] = data
        text_source[rel] = data.decode("utf-8-sig")
        source_pins[str(path)] = digest

    # Decide, per file, how each arm is produced. `transpile[key]=plan` collects the
    # files that go through the pinned compiler child.
    core_original_transpiled = bound["mode"] == "pure" or language == "typescript"
    transpile, plan = [], {}
    # Ordinary (non-core) files.
    for rel in rels:
        if rel == prot_rel:
            continue
        if language == "typescript" and _suffix(rel) == ".ts":
            transpile.append({"key": rel, "source": text_source[rel]})
            plan[rel] = {"runtime_rel": _runtime_rel(rel, language), "arms": ("original", "protected"),
                         "is_core": False}
    # Core original rendering.
    if core_original_transpiled:
        transpile.append({"key": prot_rel, "source": text_source[prot_rel]})
        plan[prot_rel] = {"runtime_rel": protected_relative, "arms": ("original",), "is_core": True}

    # Only the transpile route consumes the node/typescript/helper tools; the
    # mixed-JavaScript raw-copy route needs none, so unused/absent pins never block it.
    if transpile:
        helper_pin = _pin_helper(trusted_inputs)
        node = _pin_tool(tools, "node", required=True)
        typescript = _pin_tool(tools, "typescript", required=True)
    else:
        helper_pin = node = typescript = None

    output = _ensure_dir(output_dir)
    original_root = _ensure_dir(output / "original")
    protected_root = _ensure_dir(output / "protected")
    logs_dir = output / "logs"

    preparation_commands, requests, transpiled_evidence = [], [], []
    results_by_key, reply = {}, None
    if transpile:
        # Every planned pin re-verified around the child: input sources, the node and
        # typescript tools, the helper, and all declared trusted_inputs.
        pins = dict(source_pins)
        pins[node["path"]] = node["sha256"]
        pins[typescript["path"]] = typescript["sha256"]
        pins[helper_pin["path"]] = helper_pin["sha256"]
        for raw, digest in trusted_inputs.items():
            pins[str(_nolink(raw))] = digest
        logs_dir.mkdir()
        results_by_key, prep_entry, reply, request_record = _run_reference(
            helper=helper_pin, node=node, typescript=typescript, language=language, files=transpile,
            output_dir=output, logs_dir=logs_dir, pins=pins, deadline=deadline, stop_file=stop_file)
        preparation_commands.append(prep_entry)
        requests.append(request_record)

    original_map, protected_map = {}, {}

    def place(rel_runtime: str, data: bytes, arms) -> str:
        digest = hashlib.sha256(data).hexdigest()
        if "original" in arms:
            original_map[rel_runtime] = _write_bytes(_fs(original_root, rel_runtime), data, digest)
        if "protected" in arms:
            protected_map[rel_runtime] = _write_bytes(_fs(protected_root, rel_runtime), data, digest)
        return digest

    # Ordinary copied files (byte-for-byte, both arms).
    for rel in rels:
        if rel == prot_rel or rel in plan:
            continue
        place(rel, raw_bytes[rel], ("original", "protected"))

    # Ordinary transpiled files (both arms, identical bytes).
    for rel, info in plan.items():
        if info["is_core"]:
            continue
        row = results_by_key[rel]
        _reject_specifiers(row.get("require_specifiers"), rel)
        data = _decode_output(row, rel)
        sha = place(info["runtime_rel"], data, info["arms"])
        transpiled_evidence.append({"relative": rel, "runtime_relative": info["runtime_rel"],
                                    "source_sha256": rels[rel], "runtime_sha256": sha,
                                    "arms": list(info["arms"]),
                                    "require_specifiers": list(row.get("require_specifiers") or []),
                                    "exported_names": list(row.get("exported_names") or [])})

    # Original-arm core: independent transpile (pure / mixed-TS) or raw copy (mixed-JS).
    core_exported_names = None
    if core_original_transpiled:
        row = results_by_key[prot_rel]
        _reject_specifiers(row.get("require_specifiers"), prot_rel)
        core_exported_names = list(row.get("exported_names") or [])
        if bound["mode"] == "pure":
            missing = [name for name in bound["roots"] if name not in core_exported_names]
            if missing:
                raise ScriptJavaScriptApplicationError(
                    "pure original core does not explicitly export selected root(s): " + ", ".join(missing))
        core_data = _decode_output(row, prot_rel)
        original_strategy = "independent_commonjs_transpile"
    else:  # mixed JavaScript: the raw original is already runnable CommonJS.
        core_data = raw_bytes[prot_rel]
        original_strategy = "raw_commonjs_copy"
    original_core_sha256 = place(protected_relative, core_data, ("original",))

    # Protected-arm core: the EXACT reused producer protected artifact.
    protected_sha256 = place(protected_relative, bound["protected"]["data"], ("protected",))
    if protected_sha256 != bound["protected"]["sha256"]:
        raise ScriptJavaScriptApplicationError("staged protected core hash disagrees with the producer artifact")
    if protected_sha256 == original_core_sha256:
        raise ScriptJavaScriptApplicationError("protected and original core are byte-identical (no protection applied)")

    _stop(stop_file)
    # Independently re-derive each tree's inventory and require membership agreement.
    disk_original = {rel: e["sha256"] for rel, e in _wrap(safe._tree_inventory, original_root).items()}
    disk_protected = {rel: e["sha256"] for rel, e in _wrap(safe._tree_inventory, protected_root).items()}
    if disk_original != original_map or disk_protected != protected_map:
        raise ScriptJavaScriptApplicationError("staged tree inventory disagrees with the written file map")
    if set(original_map) != set(protected_map):
        raise ScriptJavaScriptApplicationError("original and protected trees disagree on membership")
    if runtime_entrypoint not in original_map:
        raise ScriptJavaScriptApplicationError("runtime entrypoint is missing from the staged trees")
    if original_map[runtime_entrypoint] != protected_map[runtime_entrypoint]:
        raise ScriptJavaScriptApplicationError("runtime entrypoint differs between arms (not fixed caller code)")
    for rel in original_map:
        if rel == protected_relative:
            if original_map[rel] != original_core_sha256 or protected_map[rel] != protected_sha256:
                raise ScriptJavaScriptApplicationError("core module was not substituted at the runtime path")
        elif original_map[rel] != protected_map[rel]:
            raise ScriptJavaScriptApplicationError("an unselected runtime file was not preserved byte-for-byte: " + rel)
    # No original selected source bytes may travel in a runtime tree beyond the
    # independent original rendering placed only in the original arm.
    forbidden_in_protected = {original_core_sha256, bound["original_source_sha256"]}
    if forbidden_in_protected & set(protected_map.values()):
        raise ScriptJavaScriptApplicationError("protected arm contains the original/baseline core bytes")

    reference_evidence = {
        "schema_version": 1, "kind": "javascript_application_reference", "language": language,
        "producer_backend": bound["backend"],
        "producer": {"backend": bound["backend"], "mode": bound["mode"],
                     "protected_artifact": {"path": bound["protected"]["path"],
                                            "sha256": bound["protected"]["sha256"],
                                            "bytes": bound["protected"]["bytes"]},
                     "baseline": bound["baseline"], "original_source_sha256": bound["original_source_sha256"],
                     "selected_roots": list(bound["roots"]),
                     "baseline_reused_as_original_truth": False},
        "core": {"relative": prot_rel, "runtime_relative": protected_relative,
                 "original_strategy": original_strategy, "original_core_sha256": original_core_sha256,
                 "protected_overlay_sha256": protected_sha256,
                 "original_typescript_in_runtime_tree": False,
                 "exported_names": core_exported_names},
        "transpiled_files": transpiled_evidence,
        "copied_files": [{"relative": rel, "runtime_relative": rel, "sha256": rels[rel],
                          "arms": ["original", "protected"]}
                         for rel in rels if rel != prot_rel and rel not in plan],
        "requests": requests,
        "compiler": None if not transpile else {
            "helper": helper_pin, "node": node, "typescript": typescript,
            "typescript_version": reply.get("compiler_version"),
            "pinned_compiler_options": reply.get("pinned_compiler_options"),
            "source_executed": reply.get("source_executed"),
            "type_checking": reply.get("type_checking"),
            "loaded_files": reply.get("loaded_files")},
        "staging": {"application_file_count": len(rels), "total_source_bytes": total,
                    "source_root": str(source_root), "runtime_entrypoint": runtime_entrypoint},
        "trusted_inputs_declared": len(trusted_inputs),
    }
    limitations = [
        "Adapter stages only; it never runs the application. The sole child it may launch is the fixed, reviewed transpile-reference compiler, bounded under run_logged with a private env/TEMP and Windows-Job receipts.",
        "The original core is an INDEPENDENT runnable CommonJS rendering (pure: pinned export->CJS transpile; mixed-JS: raw bytes; mixed-TS: pinned transpile); the producer baseline/IR is never used as application truth.",
        "The protected core is the EXACT reused producer protected artifact; original selected bodies are not present in it (per producer coverage) and the original/baseline core bytes are excluded from the protected arm.",
        "Ordinary .ts files are independently transpiled to .js with one pinned option set in both arms (type erasure + runtime-construct emission only; no full type check, no project graph, no declaration/JSX/ESM-runtime files); .js/.cjs/.json/.txt are preserved byte-for-byte.",
        "No original .ts source, source map, node_modules or __pycache__ enters a runtime tree; explicit .ts/.tsx/.mts/.cts/.d.ts/.mjs runtime require/import specifiers are rejected rather than leaking original sources.",
        "Pure integration requires the selected roots to be explicitly exported by the original core; a missing export is rejected. This is source-library API integration, not a claim of unchanged full raw-application semantics.",
        "Per-function VM hardening is referenced from the producer coverage, not re-verified here; whole_application_verified=false and functional/performance/external resistance are not evaluated by this adapter.",
    ]
    result = {
        "language": language,
        "original_root": str(original_root),
        "protected_root": str(protected_root),
        "runtime_entrypoint": runtime_entrypoint,
        "protected_relative": protected_relative,
        "preparation_commands": preparation_commands,
        "file_maps": {"original": original_map, "protected": protected_map},
        "protected_sha256": protected_sha256,
        "original_core_sha256": original_core_sha256,
        "reference_evidence": reference_evidence,
        "limitations": limitations,
    }
    if time.monotonic() > deadline:
        raise ScriptJavaScriptApplicationError("preparation deadline exceeded during staging")
    with (output / "preparation.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, indent=2, ensure_ascii=True, allow_nan=False, sort_keys=True)
        stream.write("\n")
    return result
