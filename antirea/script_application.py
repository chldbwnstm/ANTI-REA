"""Explicit, plan-bound Python/JS/TS application integration.

The service independently binds source plans, generated artifacts and execution
receipts. An engine success flag alone never authorizes a public pass. Source
planning/building does not authorize application execution; callers must invoke
source-integrate with an unchanged explicit application contract.
"""
from __future__ import annotations

import base64
import hashlib
import importlib
import os
from pathlib import Path
import re
import stat
import uuid

from .native_application import (
    _guard_saved_plan_paths, _guarded_tree_preflight, _receipt_clean,
)
from .protectors import _job_lock, _json, _no_links
from .projects import _create_json, _encoded

ENGINE_MODULE = "antirea.script_app_integration"
PUBLIC_STATUS_PASSED = "script_application_samples_passed"
MAX_JSON = 64 * 1024 * 1024
MAX_FILE = 16 * 1024 * 1024
MAX_HASH = 512 * 1024 * 1024
_HEX = re.compile(r"[a-f0-9]{64}\Z")
_RESERVED = {"env.setting", "linkrepro", "attackerfolder", "rea-analysis-reports"}
_BACKENDS = {
    "python": {"python_vm", "python_mixed_module_vm"},
    "javascript": {"javascript_vm", "javascript_mixed_module_vm"},
    "typescript": {"javascript_vm", "javascript_mixed_module_vm"},
}
_MODULES = ("script_application", "script_app_integration",
            "script_python_application", "script_javascript_application")


class ScriptApplicationError(ValueError):
    """An ineligible application request or unverified result."""


def _require(value, message):
    if not value:
        raise ScriptApplicationError(message)


def _path(value, *, inside=None):
    _require(isinstance(value, (str, Path)) and bool(str(value)), "missing path")
    raw = str(value)
    _require(not any(ord(c) < 32 for c in raw), "control character in path")
    _require(not any(p.casefold() in _RESERVED for p in raw.replace("\\", "/").split("/")),
             "reserved/excluded path component")
    path = Path(os.path.abspath(raw))
    if inside is not None:
        _require(path.is_relative_to(Path(inside)), "path escapes owned directory")
    _no_links(path)
    return path


def _read(value, limit=MAX_JSON):
    path = _path(value)
    before = path.stat()
    _require(stat.S_ISREG(before.st_mode) and before.st_size <= limit,
             "input must be a bounded regular file")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(limit + 1)
        closed = os.fstat(stream.fileno())
    after = _path(path).stat()
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    _require(len(data) <= limit and len(data) == before.st_size and
             identity(before) == identity(opened) == identity(closed) == identity(after),
             "input changed during bounded read")
    return data


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _hash(value):
    path = _path(value)
    before = path.stat()
    _require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_HASH,
             "pin must name a bounded regular file")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        result = hashlib.file_digest(stream, "sha256").hexdigest()
        closed = os.fstat(stream.fileno())
    after = _path(path).stat()
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    _require(identity(before) == identity(opened) == identity(closed) == identity(after),
             "pin changed during hashing")
    return result


def _pins_match(pins):
    return all(isinstance(expected, str) and _HEX.fullmatch(expected) and
               _hash(path) == expected for path, expected in pins.items())


def _app_file(service, raw, root, snapshot):
    # Lexical guard deliberately precedes generic ProjectService._owned.
    value = Path(raw)
    path = _path(value if value.is_absolute() else service.root / value, inside=root)
    path = service._owned(path)
    _require(str(path) in snapshot, "application input is not in the saved source snapshot")
    _require(_hash(path) == snapshot[str(path)], "application input changed from the saved snapshot")
    return path


def _producer_artifacts(report, directory, snapshot):
    """Bind exact generated files and the original source, never silently repin."""
    project = report["project"]
    sources = project.get("sources")
    _require(isinstance(sources, list) and len(sources) == 1,
             "script integration requires exactly one protected source")
    source = _path(sources[0], inside=Path(project["project_path"]).parent)
    raw_source = _read(source, MAX_FILE)
    raw_hash = _digest(raw_source)
    _require(snapshot.get(str(source)) == project.get("input_hashes", {}).get(str(source)) == raw_hash,
             "protected source does not match the original raw plan hash")
    if report["backend"] == "python_vm":
        # The pure Python producer historically hashes text after utf-8-sig and
        # universal-newline decoding. Keep that binding separate from the raw
        # source inventory; mixed Python and both JS producers hash raw bytes.
        normalized = raw_source.decode("utf-8-sig").replace("\r\n", "\n").replace("\r", "\n")
        producer_source_hash = _digest(normalized.encode("utf-8"))
    else:
        producer_source_hash = raw_hash
    _require(project.get("source_sha256") == producer_source_hash,
             "producer source hash differs from its documented decoding")
    extension = ".py" if project["language"] == "python" else ".cjs"
    artifacts = report.get("artifacts")
    _require(isinstance(artifacts, dict) and set(artifacts) == {"baseline", "protected"},
             "producer must identify baseline and protected modules")
    for arm in ("baseline", "protected"):
        item = artifacts[arm]
        _require(isinstance(item, dict), "malformed producer artifact")
        path = _path(item.get("path"), inside=directory / "build")
        _require(path == directory / "build" / (arm + extension),
                 "unexpected producer artifact path")
        raw = _read(path, MAX_FILE)
        _require(type(item.get("bytes")) is int and len(raw) == item["bytes"] and
                 _digest(raw) == item.get("sha256") ==
                 report.get("artifact_hashes", {}).get(path.name),
                 "producer artifact bytes do not match saved hashes")
    coverage_path = _path(report.get("coverage_path"), inside=directory / "build")
    _require(coverage_path == directory / "build" / "coverage.json",
             "unexpected producer coverage path")
    raw = _read(coverage_path)
    coverage = report.get("coverage")
    _require(_digest(raw) == report.get("artifact_hashes", {}).get("coverage.json") and
             _json(raw) == coverage and isinstance(coverage, dict),
             "producer coverage differs from its persisted bytes")
    _require(coverage.get("artifacts") == artifacts and coverage.get("backend") == report["backend"],
             "coverage is not bound to producer artifacts/backend")
    roots = project.get("functions")
    closure = coverage.get("helper_closure")
    _require(isinstance(roots, list) and roots and len(set(roots)) == len(roots) and
             isinstance(closure, list) and closure and len(set(closure)) == len(closure) and
             set(roots) <= set(closure), "invalid selected/helper closure evidence")
    functions = coverage.get("functions")
    _require(isinstance(functions, dict) and set(functions) == set(closure) and
             all(isinstance(v, dict) and v.get("virtualized") is True for v in functions.values()),
             "not every selected/helper function has VM coverage")
    hard = coverage.get("runtime_hardening")
    _require(isinstance(hard, dict) and
             hard.get("profile") == "per_function_flattened_dispatch_v1" and
             hard.get("stage") == "generated_source" and
             hard.get("kagura_passes_applied") is False and
             hard.get("external_resistance") == "not_evaluated",
             "producer lacks the required generated-source script hardening profile")
    engines = hard.get("engines")
    _require(type(hard.get("engine_count")) is int and
             isinstance(engines, list) and len(engines) == hard["engine_count"] == len(closure) and
             all(isinstance(e, dict) and type(e.get("vm_function_id")) is int for e in engines) and
             sorted(e["vm_function_id"] for e in engines) == list(range(len(closure))),
             "incomplete per-function runtime engine evidence")
    _require(coverage.get("dispatcher") == "per_function_flattened_indirect_dispatch" and
             coverage.get("decode_scope") == "current_instruction" and
             coverage.get("decoded_instruction_cache") is False,
             "producer script VM profile was downgraded")
    return source, coverage_path


def _tools(plan, report):
    recorded = plan["toolchain"].get("tools")
    _require(isinstance(recorded, dict), "missing planned tool pins")
    pins = {}
    for item in recorded.values():
        if isinstance(item, dict) and "sha256" in item:
            path = _path(item.get("path"))
            _require(_hash(path) == item["sha256"], "planned tool changed")
            pins[str(path)] = item["sha256"]
    for module in _MODULES:
        item = recorded.get("engine_" + module)
        own = _path(Path(__file__).with_name(module + ".py"))
        _require(isinstance(item, dict) and item.get("path") == str(own) and
                 item.get("sha256") == pins.get(str(own)), "required script engine was not pinned at planning")
    python = recorded.get("python_executable")
    _require(isinstance(python, dict) and python.get("path") in pins,
             "missing pinned Python interpreter")
    tools = {"python_executable": {"path": python["path"], "sha256": python["sha256"]}}
    if report["project"]["language"] != "python":
        files = report.get("toolchain", {}).get("files", {})
        for name in ("node", "typescript"):
            item = files.get(name)
            _require(isinstance(item, dict) and item.get("path") in pins and
                     item.get("sha256") == pins[item["path"]],
                     "JavaScript tools are not bound to the source plan")
            tools[name] = {"path": item["path"], "sha256": item["sha256"]}
    if report["project"]["language"] in {"javascript", "typescript"}:
        item = recorded.get("script_typescript_reference_helper")
        own = Path(__file__).absolute().parents[1] / "tools/typescript_frontend/application_reference.cjs"
        _require(isinstance(item, dict) and item.get("path") == str(own) and
                 item.get("sha256") == pins.get(str(own)), "script reference helper was not planned")
    return tools, pins


def _relative(value):
    _require(isinstance(value, str) and value and "\\" not in value and ":" not in value and
             not value.startswith("/") and not any(ord(c) < 32 for c in value),
             "runtime inventory requires ordinary relative POSIX names")
    parts = value.split("/")
    _require(all(p not in ("", ".", "..") and p == p.strip() and
                 not p.endswith((".", " ")) and
                 p.casefold() not in (_RESERVED | {"__pycache__", "node_modules"}) and
                 not re.fullmatch(r"(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", p)
                 for p in parts),
             "invalid or reserved relative runtime path")
    return value


def _inventory(directory, expected):
    directory = _path(directory)
    _require(isinstance(expected, dict) and 1 <= len(expected) <= 128,
             "runtime inventory must contain 1..128 files")
    names = [_relative(name) for name in expected]
    _require(len({name.casefold() for name in names}) == len(names),
             "case-colliding runtime inventory")
    _require(all(isinstance(sha, str) and _HEX.fullmatch(sha) for sha in expected.values()),
             "runtime inventory hashes must be SHA-256 values")
    pending, seen, entries, size = [directory], {}, 0, 0
    while pending:
        current = pending.pop()
        with os.scandir(current) as iterator:
            for entry in iterator:
                entries += 1
                _require(entries <= 4096, "runtime inventory entry limit")
                path = _path(entry.path, inside=directory)
                info = path.lstat()
                if stat.S_ISDIR(info.st_mode):
                    pending.append(path)
                else:
                    _require(stat.S_ISREG(info.st_mode), "runtime inventory contains non-regular input")
                    size += info.st_size
                    _require(info.st_size <= MAX_FILE and size <= 64 * 1024 * 1024,
                             "runtime inventory byte limit")
                    relative = path.relative_to(directory).as_posix()
                    _relative(relative)
                    _require(relative in expected, "runtime inventory has an unlisted file")
                    seen[relative] = _hash(path)
    _require(seen == expected, "runtime inventory differs from its expected exact file map")
    return seen


def _receipt_evidence(process, engine_out, seen_paths, pins, *, expected_argv=None,
                      stdout_limit=1024 * 1024):
    """Derive observations from a distinct, complete persisted process receipt."""
    _require(isinstance(process, dict) and _receipt_clean(process),
             "missing or incomplete Windows Job process receipt")
    stdout = _path(process.get("stdout"), inside=engine_out)
    stderr = _path(process.get("stderr"), inside=engine_out)
    suffix = ".stdout.log"
    _require(stdout.name.endswith(suffix), "unexpected process stdout naming")
    receipt = stdout.with_name(stdout.name[:-len(suffix)] + ".process.json")
    receipt = _path(receipt, inside=engine_out)
    for path in (stdout, stderr, receipt):
        key = os.path.normcase(str(path))
        _require(key not in seen_paths, "process receipt/log reused across observations")
        seen_paths.add(key)
    receipt_bytes = _read(receipt, 256 * 1024)
    recorded = _json(receipt_bytes)
    _require(_encoded(recorded) == _encoded(process),
             "returned process differs from its persisted raw receipt")
    if expected_argv is not None:
        _require(recorded.get("argv") == expected_argv, "process argv differs from its expected case")
    out = _read(stdout, stdout_limit)
    err = _read(stderr, 1024 * 1024)
    pins.update({str(receipt): _digest(receipt_bytes), str(stdout): _digest(out), str(stderr): _digest(err)})
    # Only line-ending normalization, never trimming whitespace or ignoring errors.
    normalized = out.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    return {"returncode": recorded["returncode"], "stdout": normalized,
            "stderr": err.decode("utf-8"), "pid": recorded["pid"], "receipt": str(receipt),
            "stdout_sha256": _digest(out), "stdout_bytes": len(out)}


def _command_evidence(entry, engine_out, seen, pins, *, expected_argv=None,
                      stdout_limit=1024 * 1024):
    _require(isinstance(entry, dict), "command evidence must be an object")
    path = _path(entry.get("receipt_path"), inside=engine_out)
    data = _read(path, 256 * 1024)
    _require(_digest(data) == entry.get("receipt_sha256"), "command receipt hash differs")
    raw = _json(data)
    _require(raw.get("stdout") == entry.get("stdout_log") and
             raw.get("stderr") == entry.get("stderr_log"),
             "command logs differ from its raw receipt")
    observed = _receipt_evidence(raw, engine_out, seen, pins, expected_argv=expected_argv,
                                 stdout_limit=stdout_limit)
    _require(observed["receipt"] == str(path), "command receipt has an unexpected filename")
    if "argv" in entry:
        _require(entry["argv"] == raw["argv"], "command argv differs from raw receipt")
    if "returncode" in entry:
        _require(type(entry["returncode"]) is int and entry["returncode"] == observed["returncode"],
                 "command return code differs from raw receipt")
    for name in ("stdout_sha256", "stdout_bytes"):
        if name in entry:
            _require(entry[name] == observed[name], "command stdout evidence differs")
    return observed


def _javascript_reference_map(staging, engine_out, *, spec, producer, input_files, source_root,
                              tools, trusted_inputs, seen, pins):
    """Bind independent compiler stdin/stdout to original files and runtime maps."""
    reference = staging.get("reference_evidence")
    _require(isinstance(reference, dict) and reference.get("schema_version") == 1 and
             reference.get("kind") == "javascript_application_reference" and
             reference.get("language") == spec["language"] and
             reference.get("producer_backend") == producer["backend"],
             "missing or mismatched independent script reference")
    commands, requests = staging.get("preparation_commands"), reference.get("requests")
    _require(isinstance(commands, list) and isinstance(requests, list) and
             1 <= len(commands) == len(requests) <= 128,
             "compiler requests must map one-to-one to bounded preparation receipts")
    helper = _path(Path(__file__).absolute().parents[1] /
                   "tools/typescript_frontend/application_reference.cjs")
    _require(trusted_inputs.get(str(helper)) == _hash(helper),
             "independent reference helper is not the planned tool")
    language = spec["language"]
    expected_sources = ({name for name in input_files if name.lower().endswith(".ts")}
                        if language == "typescript" else {spec["protected_source"]})
    _require(expected_sources, "no original source was selected for independent transpilation")
    options = {"target": "ES2022", "module": "CommonJS", "sourceMap": False,
               "inlineSourceMap": False, "removeComments": False, "alwaysStrict": False,
               "isolatedModules": True, "esModuleInterop": True, "allowJs": language == "javascript"}
    original_map = {name: sha for name, sha in input_files.items() if name not in expected_sources}
    compiled, indices, total_output = set(), set(), 0
    preparation = _json(_read(engine_out / "staging/preparation.json"))
    adapter_commands = preparation.get("preparation_commands")
    _require(isinstance(adapter_commands, list) and len(adapter_commands) == len(commands),
             "persisted adapter/compiler receipt count differs")
    for request_record in requests:
        _require(isinstance(request_record, dict) and
                 set(request_record) == {"path", "sha256", "receipt_index"},
                 "compiler request descriptor has unexpected fields")
        index = request_record["receipt_index"]
        _require(type(index) is int and 0 <= index < len(commands) and index not in indices,
                 "compiler request receipt mapping is invalid or repeated")
        indices.add(index)
        request_path = _path(request_record["path"], inside=engine_out / "staging")
        request_key = os.path.normcase(str(request_path))
        _require(request_key not in seen, "compiler request reuses another evidence file")
        seen.add(request_key)
        data = _read(request_path, 64 * 1024 * 1024)
        _require(_digest(data) == request_record["sha256"], "compiler request bytes changed")
        pins[str(request_path)] = _digest(data)
        request = _json(data)
        _require(isinstance(request, dict) and set(request) == {"language", "files"} and
                 request["language"] == language and isinstance(request["files"], list) and
                 1 <= len(request["files"]) <= 128, "compiler stdin has an unexpected schema")
        requested = {}
        for file in request["files"]:
            _require(isinstance(file, dict) and set(file) == {"key", "source"},
                     "compiler source request has unexpected fields")
            name = _relative(file["key"])
            _require(name in expected_sources and name not in compiled and name not in requested,
                     "compiler request includes an unexpected or duplicate original")
            raw_source = _read(source_root / name, MAX_FILE)
            _require(_digest(raw_source) == input_files[name] and
                     file["source"] == raw_source.decode("utf-8-sig"),
                     "compiler stdin does not contain the planned original source text")
            requested[name] = file["source"]
        command = commands[index]
        _require(isinstance(command, dict) and isinstance(adapter_commands[index], dict),
                 "malformed compiler command descriptor")
        for key in ("receipt_path", "receipt_sha256", "stdout_log", "stderr_log", "returncode"):
            _require(command.get(key) == adapter_commands[index].get(key),
                     "engine preparation receipt differs from persisted adapter evidence")
        expected_argv = [tools["node"]["path"], "--no-addons", str(helper), tools["typescript"]["path"]]
        observed = _command_evidence(command, engine_out, seen, pins,
                                     expected_argv=expected_argv, stdout_limit=128 * 1024 * 1024)
        _require(observed["returncode"] == 0, "independent compiler did not complete successfully")
        reply = _json(observed["stdout"].encode("utf-8"))
        _require(isinstance(reply, dict) and reply.get("status") == "ok" and
                 reply.get("language") == language and reply.get("source_executed") is False and
                 reply.get("type_checking") == "not_performed_whole_module_transpile_only" and
                 reply.get("pinned_compiler_options") == options and
                 isinstance(reply.get("compiler_version"), str) and reply["compiler_version"],
                 "compiler reply disagrees with the reviewed reference protocol")
        loaded = reply.get("loaded_files")
        _require(isinstance(loaded, list) and len(loaded) == 2 and all(isinstance(p, str) for p in loaded),
                 "compiler loaded unexpected file modules")
        loaded_paths = {_path(path) for path in loaded}
        _require(loaded_paths == {helper, _path(tools["typescript"]["path"])},
                 "compiler loaded modules other than its planned helper and bundle")
        rows = reply.get("results")
        _require(isinstance(rows, list) and len(rows) == len(requested),
                 "compiler output count differs from original-source requests")
        emitted = set()
        for row in rows:
            _require(isinstance(row, dict) and row.get("key") in requested and row["key"] not in emitted,
                     "compiler output key is unexpected or repeated")
            name = row["key"]
            emitted.add(name)
            decoded = {}
            for kind in ("shebang", "working", "output"):
                encoded = row.get(kind + "_b64")
                _require(isinstance(encoded, str) and len(encoded) <= 3 * 1024 * 1024,
                         "compiler base64 output exceeds its bound")
                value = base64.b64decode(encoded, validate=True)
                _require(type(row.get(kind + "_bytes")) is int and
                         len(value) == row[kind + "_bytes"] <= 2 * 1024 * 1024,
                         "compiler output byte count differs")
                decoded[kind] = value
            text = requested[name]
            newline = text.find("\n")
            shebang = (text if newline == -1 else text[:newline + 1]) if text.startswith("#!") else ""
            _require(decoded["shebang"] == shebang.encode("utf-8") and
                     row.get("shebang_present") is bool(shebang) and
                     decoded["output"] == decoded["shebang"] + decoded["working"],
                     "compiler shebang/output reconstruction differs")
            specifiers = row.get("require_specifiers")
            _require(isinstance(specifiers, list) and len(specifiers) <= 20000 and
                     all(isinstance(s, str) and not re.search(r"\.(?:ts|tsx|mts|cts|mjs)(?:[?#].*)?$",
                                                             s, re.IGNORECASE) for s in specifiers),
                     "compiler output includes unsupported explicit TypeScript runtime imports")
            runtime_name = name[:-3] + ".js" if language == "typescript" and name.lower().endswith(".ts") else name
            _require(runtime_name not in original_map, "compiler output collides with a copied file")
            original_map[runtime_name] = _digest(decoded["output"])
            total_output += len(decoded["output"])
            _require(total_output <= 32 * 1024 * 1024, "compiler total output exceeds reviewed bound")
        _require(emitted == set(requested), "compiler omitted an original source")
        compiled.update(emitted)
    _require(compiled == expected_sources and indices == set(range(len(commands))) and
             len(original_map) == len(input_files),
             "independent compilation did not cover the exact original source set")
    return original_map


def _verify_engine_evidence(report, engine_out, *, cases, producer, spec, trusted_inputs, tools):
    """Re-derive app observations from persisted bytes, never pass flags alone."""
    engine_out = _path(engine_out)
    pins, seen = {}, set()
    report_path = engine_out / "integration.json"
    raw = _read(report_path)
    _require(isinstance(report, dict) and _json(raw) == report,
             "returned engine report differs from persisted evidence")
    pins[str(report_path)] = _digest(raw)
    language = spec["language"]
    _require(type(report.get("schema_version")) is int and report["schema_version"] == 1 and
             report.get("kind") == "script_application_integration" and
             report.get("language") == language and report.get("status") == PUBLIC_STATUS_PASSED,
             "engine did not report a completed script application integration")
    for key, expected in (("fresh_protected_build", False), ("reused_protected_artifact", True),
                          ("whole_application_verified", False), ("published", False)):
        _require(report.get(key) is expected, "engine qualification scope is inconsistent")
    for key in ("external_resistance", "performance_acceptance"):
        _require(report.get(key) == "not_evaluated", "engine overclaims unevaluated protection")
    recorded_producer = report.get("producer", {})
    _require(recorded_producer.get("backend") == producer["backend"] and
             recorded_producer.get("baseline") == producer["artifacts"]["baseline"] and
             recorded_producer.get("protected") == producer["artifacts"]["protected"] and
             recorded_producer.get("original_source_sha256") == producer["project"]["source_sha256"],
             "engine producer differs from the bound build")
    adapter_name = ("antirea.script_python_application" if language == "python"
                    else "antirea.script_javascript_application")
    support = report.get("support_modules")
    expected_support = {"antirea.script_app_integration", "antirea.jvm_app_integration",
                        "antirea.process", adapter_name}
    _require(isinstance(support, dict) and set(support) == expected_support,
             "engine support-module evidence differs from the fixed implementation")
    for name, item in support.items():
        path = _path(Path(__file__).with_name(name.split(".")[-1] + ".py"))
        _require(isinstance(item, dict) and item.get("path") == str(path) and
                 item.get("sha256") == trusted_inputs.get(str(path)) == _hash(path),
                 "engine support module is not the planned implementation")
    adapter = report.get("adapter", {})
    _require(adapter == {"name": adapter_name, **support[adapter_name]},
             "engine adapter differs from its pinned implementation")
    staging = report.get("staging")
    _require(isinstance(staging, dict) and staging.get("adapter") == adapter_name and
             staging.get("adapter_sha256") == support[adapter_name]["sha256"],
             "staging did not identify the trusted adapter")
    preparation_path = engine_out / "staging/preparation.json"
    preparation_bytes = _read(preparation_path)
    preparation = _json(preparation_bytes)
    pins[str(preparation_path)] = _digest(preparation_bytes)
    _require(isinstance(preparation, dict) and preparation.get("language") == language,
             "adapter preparation evidence is missing")
    for key in ("original_root", "protected_root", "runtime_entrypoint", "protected_relative",
                "protected_sha256", "original_core_sha256", "file_maps",
                "reference_evidence", "limitations"):
        _require(key in staging and staging[key] == preparation.get(key),
                 "engine staging differs from the persisted adapter evidence: " + key)
    source_root = _path(Path(producer["project"]["project_path"]).parent)
    input_files = {}
    for name in spec["application_files"]:
        name = _relative(name)
        path = _path(source_root / name, inside=source_root)
        sha = trusted_inputs.get(str(path))
        _require(sha == _hash(path), "application source is not bound to the saved plan")
        input_files[name] = sha
    protected_relative = spec["protected_source"]
    entrypoint = spec["entrypoint"]
    if language == "typescript":
        protected_relative = protected_relative[:-3] + ".js"
        if entrypoint.lower().endswith(".ts"):
            entrypoint = entrypoint[:-3] + ".js"
    if language == "typescript" or (language == "javascript" and producer["backend"] == "javascript_vm"):
        original_map = _javascript_reference_map(
            staging, engine_out, spec=spec, producer=producer, input_files=input_files, source_root=source_root,
            tools=tools, trusted_inputs=trusted_inputs, seen=seen, pins=pins)
    else:
        _require(staging.get("preparation_commands") == preparation.get("preparation_commands") == [],
                 "Python/JavaScript application staging must not execute preparation children")
        original_map = input_files
    protected_sha = producer["artifacts"]["protected"]["sha256"]
    protected_map = {**original_map, protected_relative: protected_sha}
    _require(staging["runtime_entrypoint"] == entrypoint and
             staging["protected_relative"] == protected_relative and
             staging["original_core_sha256"] == original_map[protected_relative] and
             staging["protected_sha256"] == protected_sha and
             staging["file_maps"] == {"original": original_map, "protected": protected_map},
             "staged maps do not preserve original files and the exact protected module")
    _require(protected_sha != original_map[protected_relative],
             "protected module equals the original module")
    private_core_hashes = {input_files[spec["protected_source"]],
                          original_map[protected_relative],
                          producer["artifacts"]["baseline"]["sha256"]}
    _require(not private_core_hashes.intersection(protected_map.values()),
             "protected bundle includes an exact original/baseline core copy")
    roots = {"original": engine_out / "staging/original",
             "protected": engine_out / "staging/protected", "deployment": engine_out / "deployment"}
    for arm in ("original", "protected"):
        _require(staging[arm + "_root"] == str(roots[arm]), "unexpected staging root")
    for arm, root in roots.items():
        expected = original_map if arm == "original" else protected_map
        _inventory(root, expected)
        pins.update({str(root / name): sha for name, sha in expected.items()})
    deployment = report.get("deployment", {})
    expected_files = [{"relative_path": name, "sha256": sha,
                       "bytes": _path(roots["deployment"] / name).stat().st_size}
                      for name, sha in sorted(protected_map.items())]
    _require(deployment.get("path") == str(roots["deployment"]) and
             deployment.get("files") == expected_files and
             deployment.get("allowlist") == sorted(protected_map) and
             deployment.get("protected_module") == protected_relative and
             deployment.get("runtime_entrypoint") == entrypoint,
             "deployment description differs from its independent exact inventory")

    bootstrap = None
    module = None
    if language == "python":
        adapter_module = importlib.import_module(adapter_name)
        bootstrap = engine_out / "staging/bootstrap.py"
        bootstrap_bytes = _read(bootstrap, MAX_FILE)
        _require(bootstrap_bytes == adapter_module.RUNPY_BOOTSTRAP.encode("utf-8"),
                 "Python runpy bootstrap is not fixed trusted code")
        pins[str(bootstrap)] = _digest(bootstrap_bytes)
        module = entrypoint[:-3].replace("/", ".")
        for depth in range(1, len(entrypoint.split("/"))):
            init = "/".join(entrypoint.split("/")[:depth] + ["__init__.py"])
            _require(init in original_map, "Python package entry lacks explicit package initializer")
        reference = staging["reference_evidence"]
        _require(reference.get("module_execution", {}).get("module") == module and
                 reference.get("runpy_bootstrap", {}).get("path") == str(bootstrap) and
                 reference.get("runpy_bootstrap", {}).get("sha256") == pins[str(bootstrap)],
                 "Python execution evidence differs from the derived package entry")

    def argv(root, case):
        if language == "python":
            return [tools["python_executable"]["path"], "-I", "-S", "-B",
                    str(bootstrap), str(root), module, *case["args"]]
        return [tools["node"]["path"], "--no-addons", str(root / entrypoint), *case["args"]]

    comparison = report.get("comparison", {})
    commands, records = comparison.get("commands"), comparison.get("cases")
    _require(isinstance(commands, list) and len(commands) == 3 * len(cases) + 1 and
             isinstance(records, list) and len(records) == len(cases) and
             comparison.get("arms") == ["original", "protected", "deployment"],
             "missing or extra application cases/commands")
    observations, ordinal = [], 0
    for case, record in zip(cases, records):
        _require(isinstance(record, dict) and record.get("label") == case["label"] and
                 record.get("args") == case["args"] and record.get("expect") == case["expect"] and
                 isinstance(record.get("results"), dict) and set(record["results"]) == set(roots),
                 "case summary differs from the explicit contract")
        arms = {}
        expected_stdout = case["expect"]["stdout"].replace("\r\n", "\n").replace("\r", "\n")
        for arm, root in roots.items():
            command = commands[ordinal]
            ordinal += 1
            _require(command.get("label") == "case:" + case["label"] + ":" + arm and
                     command.get("kind") == "case_arm" and command.get("arm") == arm and
                     command.get("case_label") == case["label"] and command.get("control") is None,
                     "case command identity differs")
            observed = _command_evidence(command, engine_out, seen, pins, expected_argv=argv(root, case))
            _require(observed["returncode"] == case["expect"]["returncode"] and
                     observed["stdout"] == expected_stdout,
                     "raw output/return code does not match the explicit application case")
            summary = record["results"][arm]
            _require(summary == {"returncode": observed["returncode"],
                                 "stdout_sha256": observed["stdout_sha256"],
                                 "stdout_bytes": observed["stdout_bytes"],
                                 "stdout_preview": observed["stdout"]},
                     "case summary differs from raw process evidence")
            arms[arm] = observed
        _require(record.get("match") is True, "case summary contradicts its raw evidence")
        observations.append({"label": case["label"], "arms": arms})
    control_case = next(case for case in cases if case["expect"]["returncode"] == 0)
    control_root = engine_out / "control"
    control_map = {name: sha for name, sha in protected_map.items() if name != protected_relative}
    _inventory(control_root, control_map)
    pins.update({str(control_root / name): sha for name, sha in control_map.items()})
    command = commands[-1]
    _require(command.get("label") == "control:missing_protected_module" and
             command.get("kind") == "control" and command.get("control") == "missing_module" and
             command.get("arm") is None and command.get("case_label") == control_case["label"],
             "missing-module control identity differs")
    observed = _command_evidence(command, engine_out, seen, pins,
                                 expected_argv=argv(control_root, control_case))
    _require(observed["returncode"] != 0, "missing-module control did not fail the successful case")
    controls = comparison.get("controls")
    expected_control = {"label": "missing_protected_module", "control": "missing_module",
                        "case_label": control_case["label"], "returncode": observed["returncode"],
                        "stdout_sha256": observed["stdout_sha256"], "reproduced_success": False,
                        "failed_as_required": True}
    control_metadata = {"control_root": str(control_root), "removed_module": protected_relative,
                        "inventory": [{"relative_path": name, "sha256": sha}
                                      for name, sha in sorted(control_map.items())]}
    _require(isinstance(controls, list) and len(controls) == 1 and isinstance(controls[0], dict) and
             set(expected_control) <= set(controls[0]) <= set(expected_control) | set(control_metadata) and
             all(controls[0][key] == value for key, value in expected_control.items()) and
             all(controls[0][key] == control_metadata[key]
                 for key in set(controls[0]) - set(expected_control)),
             "control summary differs from its raw observation")
    _require(_pins_match(trusted_inputs) and _pins_match(pins),
             "bound source/tool or audited evidence changed during verification")
    return {"report": {"path": str(report_path), "sha256": pins[str(report_path)]},
            "raw_cases": observations, "missing_module_control": observed,
            "deployment": {"path": str(roots["deployment"]), "file_map": protected_map},
            "evidence_pins": pins, "raw_processes_verified": len(commands) + len(staging["preparation_commands"]),
            "dependency_presence_verified": True, "vm_call_tracing": "not_performed",
            "whole_application_verified": False}


def integrate_source_application(service, plan_id, integration_spec_path, contract_path,
                                 *, timeout_seconds=120):
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
        raise ScriptApplicationError("timeout_seconds must be an integer in 1..600")
    directory = service._directory(plan_id)
    with _job_lock(directory):
        result_path, plan_path = directory / "result.json", directory / "plan.json"
        result_bytes, plan_bytes = _read(result_path), _read(plan_path)
        result, plan = _json(result_bytes), _json(plan_bytes)
        _require(isinstance(result, dict) and result.get("status") == "artifact_created_unvalidated",
                 "source plan has no successful artifact to integrate")
        _require(isinstance(plan, dict) and isinstance(plan.get("inspection"), dict) and
                 isinstance(plan.get("inputs"), list) and isinstance(plan.get("toolchain"), dict),
                 "malformed source plan")
        _require(_digest(_encoded(plan)) == result.get("fingerprint") and
                 plan.get("plan_id") == result.get("plan_id") == plan_id and
                 plan.get("workspace_root") == str(service.root),
                 "source plan does not bind this build result")
        _guard_saved_plan_paths(plan)
        language = plan["inspection"].get("language")
        _require(language in _BACKENDS and result.get("backend") in _BACKENDS[language],
                 "source-integrate script route requires a Python/JS/TS producer")
        _require(plan.get("kind") == ("python_source_build" if language == "python" else "javascript_source_build"),
                 "producer plan kind differs from its language")
        report_path = directory / "build" / "report.json"
        report_bytes = _read(report_path)
        producer = _json(report_bytes)
        _require(isinstance(producer, dict) and
                 producer.get("backend") == result["backend"] and
                 producer.get("status") == "artifact_created_unvalidated" and
                 _digest(report_bytes) == result.get("build_report_sha256") and
                 producer.get("project") == plan["inspection"] and
                 producer.get("artifacts") == result.get("artifacts") and
                 producer.get("coverage") == result.get("coverage"),
                 "saved producer report differs from the source result/plan")
        project_path = _path(plan.get("project_path"), inside=service.root)
        _require(str(project_path) == producer["project"].get("project_path"),
                 "producer project origin differs from saved plan")
        source_root = project_path.parent
        _require(source_root != service.root, "application requires a dedicated project directory")
        _guarded_tree_preflight(source_root)
        snapshot_before = service._snapshot(project_path, plan["inspection"])
        _require(snapshot_before == plan["inputs"], "planned project changed before integration")
        toolchain_before = service._toolchain(plan["inspection"])
        _require(toolchain_before == plan["toolchain"], "planned source toolchain changed")
        snapshot = {row["path"]: row["sha256"] for row in snapshot_before}
        core, coverage_path = _producer_artifacts(producer, directory, snapshot)
        tools, trusted = _tools(plan, producer)
        spec_path = _app_file(service, integration_spec_path, source_root, snapshot)
        contract_file = _app_file(service, contract_path, source_root, snapshot)
        _require(spec_path != contract_file, "spec and contract must be distinct")
        spec_bytes, contract_bytes = _read(spec_path, 256 * 1024), _read(contract_file, 256 * 1024)
        engine = importlib.import_module(ENGINE_MODULE)
        spec = engine.validate_spec(_json(spec_bytes))
        contract = _json(contract_bytes)
        cases = engine.validate_contract(contract)
        _require(spec["language"] == language, "integration language differs from producer")
        _require(_path(source_root / spec["protected_source"], inside=source_root) == core,
                 "spec protected_source does not match the reviewed producer")
        input_files = {}
        for relative in spec["application_files"]:
            path = _app_file(service, str(source_root / relative), source_root, snapshot)
            _require(path not in {spec_path, contract_file, project_path},
                     "deployment inventory may not contain its private plan/spec/contract")
            input_files[relative] = snapshot[str(path)]
        trusted.update(snapshot)
        for path, data in ((plan_path, plan_bytes), (result_path, result_bytes),
                           (report_path, report_bytes), (spec_path, spec_bytes),
                           (contract_file, contract_bytes)):
            trusted[str(path)] = _digest(data)
        trusted[str(coverage_path)] = _hash(coverage_path)
        for item in producer["artifacts"].values():
            trusted[item["path"]] = item["sha256"]
        stop = service.root / ".runs/defense-loop/STOP"
        if stop.exists():
            return {"status": "cancelled", "reason": "defense STOP exists",
                    "plan_id": plan_id, "integration_id": None}
        _require(_pins_match(trusted), "inputs changed before explicit execution")
        integration_id = "integration-" + uuid.uuid4().hex[:12]
        out = _path(directory / integration_id, inside=directory)
        out.mkdir()
        engine_out = out / "engine"
        invocation = {
            "schema_version": 1, "kind": "script_application_integration_plan",
            "plan_id": plan_id, "integration_id": integration_id, "language": language,
            "source_root": str(source_root), "source_plan_fingerprint": result["fingerprint"],
            "spec": spec, "contract": contract, "input_files": input_files,
            "trusted_inputs": trusted, "tools": tools, "timeout_seconds": timeout_seconds,
            "protected_sha256": producer["artifacts"]["protected"]["sha256"],
            "executes_application": True, "published": False,
        }
        invocation_path = out / "integration-plan.json"
        _create_json(invocation_path, invocation)
        trusted[str(invocation_path)] = _hash(invocation_path)
        public = {
            "schema_version": 1, "status": "failed", "language": language,
            "backend": producer["backend"], "plan_id": plan_id,
            "integration_id": integration_id, "public_route": "explicit_source_integrate_execution",
            "source_build_report": {"path": str(report_path), "sha256": _digest(report_bytes)},
            "integration_plan": {"path": str(invocation_path), "sha256": trusted[str(invocation_path)]},
            "artifacts": producer["artifacts"], "runtime_hardening": producer["coverage"]["runtime_hardening"],
            "fresh_protected_build": False, "reused_protected_artifact": True,
            "external_resistance": "not_evaluated", "performance_acceptance": "not_evaluated",
            "whole_application_verified": False, "published": False, "trusted_inputs": dict(trusted),
        }
        try:
            report = engine.run_integration(
                language=language, source_root=source_root, input_files=dict(input_files),
                producer=_json(_encoded(producer)), spec=_json(_encoded(spec)),
                contract=_json(_encoded(contract)), output_dir=engine_out,
                tools=_json(_encoded(tools)), trusted_inputs=dict(trusted), timeout_seconds=timeout_seconds,
                stop_file=stop)
            public["engine_evidence"] = _verify_engine_evidence(
                report, engine_out, cases=cases, producer=producer, spec=spec,
                trusted_inputs=trusted, tools=tools)
            public["status"] = PUBLIC_STATUS_PASSED
        except Exception as exc:
            public["error"] = type(exc).__name__ + ": " + str(exc)[:4096]
        try:
            _guarded_tree_preflight(source_root)
            snapshot_after = service._snapshot(project_path, plan["inspection"])
            toolchain_after = service._toolchain(plan["inspection"])
            unchanged = (snapshot_after == snapshot_before and
                         toolchain_after == toolchain_before and _pins_match(trusted))
            public["source_and_tools_unchanged"] = unchanged
            if not unchanged:
                public["status"] = "failed_input_drift"
            if stop.exists():
                public["status"] = "cancelled"
        except Exception as exc:
            public["status"] = "failed_postflight"
            public["postflight_error"] = type(exc).__name__ + ": " + str(exc)[:4096]
        result_file = out / "integration.json"
        public["report_path"] = str(result_file)
        _create_json(result_file, public)
        return public
