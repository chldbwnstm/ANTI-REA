"""Explicit ordinary Go/Swift application integration around an owned native core.

This route executes owned compiler/application inputs. Windows Job ownership is
cleanup evidence, not an OS sandbox. A passing sample comparison is not an attack
evaluation or a whole-language correctness proof.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import shutil

from . import bindings, jvm_app_integration as safe, process

BACKENDS = {"go": "go_typed_native", "swift": "swift_llvm_native"}
OK_BUILD = "artifact_created_unvalidated"
SPEC_KIND = "native_application_integration"
CASE_KIND = "native_application_samples"
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_LOG_BYTES = 4 * 1024 * 1024


class NativeIntegrateError(ValueError):
    pass


def _safe_call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except safe.JvmIntegrateError as exc:
        raise NativeIntegrateError(str(exc)) from exc


def _path(value) -> Path:
    if not isinstance(value, (str, os.PathLike)) or not os.fspath(value) or "\x00" in os.fspath(value):
        raise NativeIntegrateError("Expected a nonempty ordinary filesystem path")
    return _safe_call(safe._no_links, Path(os.path.abspath(value)))


def _sha(path) -> str:
    return _safe_call(safe._hash_file, path, limit=MAX_FILE_BYTES)


def _json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise NativeIntegrateError("Duplicate JSON field")
            result[key] = value
        return result
    def nonfinite(value):
        raise NativeIntegrateError("Nonfinite JSON value")
    return json.loads(_safe_call(safe._read_bytes_bounded, path, limit=16 * 1024 * 1024),
                      object_pairs_hook=pairs, parse_constant=nonfinite)


def _write(path, value):
    with _path(path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=True, allow_nan=False)
        stream.write("\n")


def _relative(value) -> Path:
    if (not isinstance(value, str) or not value or value != value.strip()
            or "\\" in value or ":" in value or "\x00" in value):
        raise NativeIntegrateError("Expected a clean relative slash path")
    rel = Path(value)
    if rel.is_absolute() or any(part in ("", ".", "..") for part in value.split("/")):
        raise NativeIntegrateError("Relative path escapes or is not canonical")
    _safe_call(safe._reserved_guard, rel)
    return rel


def _claim(path, digest, *, parent=None):
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise NativeIntegrateError("Missing or invalid claimed SHA256")
    path = _path(path)
    if parent is not None and not path.is_relative_to(parent):
        raise NativeIntegrateError("Claimed input escapes its authorized directory")
    if _sha(path) != digest:
        raise NativeIntegrateError("Input hash mismatch: " + str(path))
    return path


def load_producer_report(report_path, *, workspace_root) -> dict:
    """Authenticate origin and selected protected closure, never repair claims."""
    root, path = _path(workspace_root), _path(report_path)
    if not path.is_relative_to(root / ".runs"):
        raise NativeIntegrateError("Producer must be a private workspace/.runs report")
    report = _json(path)
    if (not isinstance(report, dict) or type(report.get("schema_version")) is not int
            or report["schema_version"] != 1 or report.get("language") not in BACKENDS):
        raise NativeIntegrateError("Expected a Go or Swift producer")
    language = report["language"]
    if report.get("backend") != BACKENDS[language] or report.get("status") != OK_BUILD:
        raise NativeIntegrateError("A successful matching source build is required")
    project = report.get("project")
    if not isinstance(project, dict) or project.get("language") != language:
        raise NativeIntegrateError("Producer project identity mismatch")
    project_root = _path(project["project_root"])
    if not project_root.is_relative_to(root) or project_root.is_relative_to(root / ".runs"):
        raise NativeIntegrateError("Original project must be an owned source tree")
    source_hashes = project.get("input_hashes")
    if (not isinstance(source_hashes, dict) or not 1 <= len(source_hashes) <= 4096
            or report.get("source_hashes") != source_hashes):
        raise NativeIntegrateError("Producer source snapshot missing or contradictory")
    pins = {str(path): _sha(path)}
    for value, digest in source_hashes.items():
        pins[str(_claim(value, digest, parent=project_root))] = digest
    _verify_source_tree(project_root, source_hashes)
    sources = project.get("sources")
    if not isinstance(sources, list) or not 1 <= len(sources) <= 32:
        raise NativeIntegrateError("Producer core source list missing or unbounded")
    cores = [_path(value) for value in sources]
    if (len(set(map(os.path.normcase, map(str, cores)))) != len(cores)
            or any(str(p) not in pins or p.suffix != "." + language for p in cores)):
        raise NativeIntegrateError("Core sources are not unique pinned language inputs")
    contract_path = _path(report["contract_path"])
    hashes = report.get("frontend_artifact_hashes" if language == "go" else "artifact_hashes")
    key = "contract.json" if language == "go" else "frontend/contract.json"
    if not isinstance(hashes, dict):
        raise NativeIntegrateError("Producer frontend artifact hashes missing")
    _claim(contract_path, hashes.get(key), parent=path.parent)
    contract = _json(contract_path)
    bindings.validate_contract(contract)
    if language == "go" and contract != report.get("contract"):
        raise NativeIntegrateError("Inline Go contract differs from pinned contract")
    pins[str(contract_path)] = hashes[key]
    nrp = _claim(report.get("native_report"), report.get("native_report_sha256"), parent=path.parent)
    native = _json(nrp)
    if not isinstance(native, dict) or native.get("status") != OK_BUILD:
        raise NativeIntegrateError("Native origin is not a successful build")
    pins[str(nrp)] = report["native_report_sha256"]
    artifacts = {}
    for arm in ("baseline", "protected"):
        entry = report.get("artifacts", {}).get(arm)
        original_entry = native.get("artifacts", {}).get(arm)
        if not isinstance(entry, dict) or original_entry != entry:
            raise NativeIntegrateError("Native artifact origin mismatch")
        file = _claim(entry.get("path"), entry.get("sha256"), parent=nrp.parent)
        pins[str(file)] = entry["sha256"]
        artifacts[arm] = {"path": str(file), "sha256": entry["sha256"], "bytes": file.stat().st_size}
    exports = project.get("functions")
    if (not isinstance(exports, list) or not exports or len(set(exports)) != len(exports)
            or sorted(exports) != sorted(f["name"] for f in contract["functions"])):
        raise NativeIntegrateError("Project exports and contract disagree")
    coverage = native.get("coverage")
    if not isinstance(coverage, dict):
        raise NativeIntegrateError("Native VM coverage missing")
    expected_coverage = {**coverage, "exported_functions": exports} if language == "go" else coverage
    if report.get("coverage") != expected_coverage:
        raise NativeIntegrateError("Producer and native VM coverage disagree")
    if language == "go":
        methods = report.get("methods")
        if not isinstance(methods, list) or not methods or any(not isinstance(m, dict) for m in methods):
            raise NativeIntegrateError("Lowered Go methods missing")
        selected = [m.get("export") for m in methods]
        metadata = contract_path.parent / "metadata.json"
        pins[str(_claim(metadata, hashes.get("metadata.json"), parent=path.parent))] = hashes["metadata.json"]
    else:
        normalization = report.get("normalization")
        if not isinstance(normalization, dict):
            raise NativeIntegrateError("Swift normalization evidence missing")
        selected = normalization.get("selected_functions")
        interface = report.get("public_interface")
        if not isinstance(interface, dict):
            raise NativeIntegrateError("Swift compiler interface missing")
        ip = _claim(interface.get("path"), interface.get("sha256"), parent=path.parent)
        pins[str(ip)] = interface["sha256"]
    if (not isinstance(selected, list) or not selected or any(not isinstance(s, str) for s in selected)
            or not isinstance(coverage.get("selected_functions"), list)
            or set(selected) != set(coverage["selected_functions"])
            or not set(exports) <= set(selected)):
        raise NativeIntegrateError("Selected native closure does not match lowered roots and helpers")
    if any(not coverage.get(key) for key in ("functions", "original_vm", "final_vm")):
        raise NativeIntegrateError("Native VM structure evidence missing")
    return {"report": report, "language": language, "backend": BACKENDS[language],
            "report_path": str(path), "report_sha256": pins[str(path)],
            "project_root": str(project_root), "core_sources": list(map(str, cores)),
            "source_hashes": source_hashes, "pins": pins, "artifacts": artifacts,
            "contract_path": str(contract_path), "contract_sha256": hashes[key],
            "contract": contract, "native_report": {"path": str(nrp), "sha256": pins[str(nrp)]}}


def load_integration_spec(spec_path, *, workspace_root, pinned) -> dict:
    path, root = _path(spec_path), _path(workspace_root)
    if not path.is_relative_to(root) or not path.is_relative_to(Path(pinned["project_root"])):
        raise NativeIntegrateError("Application spec must be in the same owned project")
    data = _json(path)
    if (not isinstance(data, dict)
            or set(data) != {"schema_version", "kind", "language", "application_sources"}
            or type(data["schema_version"]) is not int or data["schema_version"] != 1
            or data["kind"] != SPEC_KIND or data["language"] != pinned["language"]):
        raise NativeIntegrateError("Unsupported native application spec")
    values = data["application_sources"]
    if not isinstance(values, list) or not 1 <= len(values) <= 32:
        raise NativeIntegrateError("Application requires 1..32 explicit source files")
    rows, seen = [], set()
    cores = {os.path.normcase(value) for value in pinned["core_sources"]}
    for value in values:
        rel = _relative(value)
        file = _path(path.parent / rel)
        key = os.path.normcase(str(file))
        if (file.suffix != "." + pinned["language"] or key in seen or key in cores
                or not file.is_relative_to(Path(pinned["project_root"]))
                or str(file) not in pinned["source_hashes"]):
            raise NativeIntegrateError("Application source is duplicate, core, or outside the planned snapshot")
        digest = pinned["source_hashes"][str(file)]
        _claim(file, digest)
        rows.append({"path": str(file), "relative": value, "sha256": digest})
        seen.add(key)
    if pinned["language"] == "swift" and sum(Path(r["path"]).name == "main.swift" for r in rows) != 1:
        raise NativeIntegrateError("Swift application requires exactly one explicit main.swift")
    return {"path": str(path), "sha256": _sha(path), "language": pinned["language"], "application_sources": rows}


def load_application_contract(path, *, workspace_root) -> dict:
    path, root = _path(path), _path(workspace_root)
    if not path.is_relative_to(root):
        raise NativeIntegrateError("Application contract escapes workspace")
    data = _json(path)
    if (not isinstance(data, dict) or set(data) != {"schema_version", "kind", "cases"}
            or type(data["schema_version"]) is not int or data["schema_version"] != 1
            or data["kind"] != CASE_KIND):
        raise NativeIntegrateError("Unsupported application case contract")
    cases = _safe_call(safe.validate_cases, data["cases"])
    _safe_call(safe._select_control_case, cases)
    return {"path": str(path), "sha256": _sha(path), "cases": cases}


def _verify_pins(pins, stop):
    if stop.exists():
        raise NativeIntegrateError("Defense STOP set")
    for value, digest in pins.items():
        _claim(value, digest)


def _verify_source_tree(root, expected):
    actual = {str(Path(root) / name): entry["sha256"]
              for name, entry in _safe_call(safe._tree_inventory, root).items()}
    if actual != expected:
        raise NativeIntegrateError("Original project membership or content changed")


def _facade_manifest(producer, output) -> dict:
    language = producer["language"]
    module = importlib.import_module(".%s_application_facade" % language, __package__)
    result = module.generate_facade(producer, output)
    if result != _json(output / "facade.json"):
        raise NativeIntegrateError("Generator return differs from persisted facade")
    keys = {"schema_version", "kind", "status", "language", "files", "compile_sources", "c_sources",
            "include_dirs", "source_roots", "loader_environment", "original_core_sources_included", "limitations"}
    if (not isinstance(result, dict) or set(result) != keys
            or type(result.get("schema_version")) is not int or result["schema_version"] != 1
            or result["kind"] != "native_application_facade"
            or result["status"] != "generated_not_validated" or result["language"] != language
            or result["loader_environment"] != "ANTIREA_NATIVE_CORE"
            or result["original_core_sources_included"] is not False):
        raise NativeIntegrateError("Invalid generated facade manifest")
    files = result["files"]
    if not isinstance(files, dict) or not 1 <= len(files) <= 128:
        raise NativeIntegrateError("Facade file inventory missing or unbounded")
    expected = {}
    for value, digest in files.items():
        path = output / _relative(value)
        _claim(path, digest, parent=output)
        expected[value] = digest
    actual = _safe_call(safe._tree_inventory, output)
    if set(actual) != {*expected, "facade.json"}:
        raise NativeIntegrateError("Facade inventory has unlisted files")
    for key, suffix in (("compile_sources", "." + language), ("c_sources", ".c")):
        values = result[key]
        if (not isinstance(values, list) or len(values) > 32 or len(set(values)) != len(values)
                or any(v not in files or _relative(v).suffix != suffix for v in values)):
            raise NativeIntegrateError("Invalid facade compile source inventory")
    if not result["compile_sources"] or (language == "go" and (result["c_sources"] or result["include_dirs"])):
        raise NativeIntegrateError("Missing facade sources or unexpected Go native bridge")
    if language == "swift" and (len(result["c_sources"]) != 1 or not result["include_dirs"]):
        raise NativeIntegrateError("Swift requires one trusted C bridge and its module directory")
    if (not isinstance(result["include_dirs"], list) or len(result["include_dirs"]) > 4
            or len(set(result["include_dirs"])) != len(result["include_dirs"])):
        raise NativeIntegrateError("Invalid generated include directories")
    for value in result["include_dirs"]:
        if not _path(output / _relative(value)).is_dir():
            raise NativeIntegrateError("Generated include directory missing")
    contract = _json(producer["contract_path"])
    functions = {f["name"]: f for f in contract["functions"]}
    roots = result["source_roots"]
    if (not isinstance(roots, list) or len(roots) != len(functions)
            or any(not isinstance(r, dict) or set(r) !=
                   {"source_name", "export", "return_type", "parameters", "external_labels"} for r in roots)):
        raise NativeIntegrateError("Facade root metadata does not describe the public ABI")
    names = ({m["export"]: m["name"] for m in producer["methods"] if m["is_root"]} if language == "go"
             else {f["name"]: f["swift_name"] for f in producer["source_functions"]})
    if len({r["export"] for r in roots}) != len(functions):
        raise NativeIntegrateError("Duplicate facade root exports")
    for row in roots:
        function = functions.get(row["export"])
        labels = row["external_labels"]
        if (function is None or names.get(row["export"]) != row["source_name"]
                or row["parameters"] != function["parameters"] or row["return_type"] != function["return_type"]
                or not isinstance(labels, list)
                or (language == "go" and labels != [])
                or (language == "swift" and (len(labels) != len(function["parameters"])
                    or any(not isinstance(v, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", v) for v in labels)))):
            raise NativeIntegrateError("Facade roots differ from producer names/ABI/labels")
    return result


def _base_env(output):
    windows = Path(os.environ.get("SystemRoot", "C:/Windows"))
    tmp, home = safe._private_dirs(output)
    return {"SystemRoot": str(windows), "windir": str(windows), "SystemDrive": windows.drive,
            "COMSPEC": str(windows / "System32/cmd.exe"), "PATHEXT": ".COM;.EXE;.BAT;.CMD",
            "PATH": os.pathsep.join(map(str, (windows / "System32", windows))),
            "TEMP": str(tmp), "TMP": str(tmp), "USERPROFILE": str(home),
            "APPDATA": str(home / "AppData/Roaming"), "LOCALAPPDATA": str(home / "AppData/Local"),
            "PROCESSOR_ARCHITECTURE": "AMD64"}


def _compiler(language):
    module = importlib.import_module(".%s_frontend" % language, __package__)
    compiler = module._compiler()
    if compiler.get("blockers"):
        raise NativeIntegrateError("Installed language compiler is incomplete")
    return compiler


def _receipt(proc, prefix, seen):
    record = _safe_call(safe._persisted_receipt, proc, prefix)
    if proc != record["parsed"] or not safe._strict_receipt_clean(record["parsed"]):
        raise NativeIntegrateError("Returned/persisted child receipt mismatch or unclean Windows Job")
    for key, raw in (("stdout_log", "stdout"), ("stderr_log", "stderr")):
        if str(_path(record[key])) != str(_path(record["parsed"].get(raw))):
            raise NativeIntegrateError("Child raw log path mismatch")
    for key in ("receipt_path", "stdout_log", "stderr_log"):
        path = _path(record[key])
        if not path.is_relative_to(prefix.parent):
            raise NativeIntegrateError("Child evidence escaped its log directory")
        normal = os.path.normcase(str(path))
        if normal in seen:
            raise NativeIntegrateError("Duplicated child evidence reference")
        seen.add(normal)
    return {key: record[key] for key in ("receipt_path", "receipt_sha256", "stdout_log", "stderr_log")}


def _copy(source, destination, pins):
    source, destination = _path(source), _path(destination)
    expected = _sha(source)
    if str(source) in pins and pins[str(source)] != expected:
        raise NativeIntegrateError("Source changed before staging: " + str(source))
    if destination.exists():
        raise NativeIntegrateError("Staged filename collision: " + str(destination))
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as src, destination.open("xb") as dst:
        shutil.copyfileobj(src, dst)
    _claim(destination, expected)
    pins[str(source)] = expected
    pins[str(destination)] = expected
    return destination


def _deployment(directory, allowlist, forbidden):
    inventory = _safe_call(safe._tree_inventory, directory)
    if set(inventory) != set(allowlist) or len(allowlist) != len(set(allowlist)):
        raise NativeIntegrateError("Deployment does not have exactly the reviewed allowlist")
    rows = []
    for name in sorted(allowlist):
        path = directory / _relative(name)
        sha = _sha(path)
        if path.suffix.lower() not in (".dll", ".exe") or sha in forbidden:
            raise NativeIntegrateError("Deployment contains forbidden original/private content")
        rows.append({"relative_path": name, "sha256": sha, "bytes": path.stat().st_size})
    return {"path": str(directory), "files": rows, "allowlist": sorted(allowlist), "forbidden_absent": True,
            "executable": "app.exe", "native_core": "protected.dll",
            "runtime_files": sorted(set(allowlist) - {"app.exe", "protected.dll"})}


def _swift_module_maps(compiler, sdk_env, output, pins):
    """Private copies of the pinned portable SDK maps, never global SDK edits.

    The portable installation intentionally does not install these maps beside
    Windows headers. Rebase only fixed SDK templates, as the qualified binding
    fixture already does. Pin the explicit header files; this is not a complete
    transitive SDK-header attestation.
    """
    sdk = _path(compiler.get("sdk"))
    includes = [Path(value) for value in sdk_env.get("INCLUDE", "").split(os.pathsep) if value]
    templates = (("ucrt.modulemap", "ucrt", "corecrt.h"),
                 ("winsdk_shared.modulemap", "shared", "guiddef.h"),
                 ("winsdk_um.modulemap", "um", "Windows.h"))
    prepared = []
    for name, part, marker in templates:
        source = sdk / "usr/share" / name
        expected = compiler.get("input_hashes", {}).get(str(source))
        _claim(source, expected, parent=sdk)
        data = safe._read_bytes_bounded(source, limit=1024 * 1024)
        if hashlib.sha256(data).hexdigest() != expected:
            raise NativeIntegrateError("Swift module-map template changed while reading")
        matches = [p for p in includes if p.name.casefold() == part and _path(p / marker).is_file()]
        if len(matches) != 1:
            raise NativeIntegrateError("Expected one installed SDK header root for " + name)
        header_root = _path(matches[0])
        headers = {}

        def rebase(match):
            relative = match[1]
            sibling = re.fullmatch(r"\.\./(shared|winrt)/([^/\\:]+)", relative)
            header_base = header_root
            if name == "winsdk_um.modulemap" and sibling:
                # Reviewed upstream UM templates reference these two sibling
                # SDK directories. Both must be in the captured INCLUDE list
                # and in the same installed SDK version, never arbitrary ../.
                header_base = _path(header_root.parent / sibling[1])
                if sum(_path(p) == header_base for p in includes) != 1:
                    raise NativeIntegrateError("Swift SDK sibling header root is missing or ambiguous")
                relative = sibling[2]
            header = _path(header_base / _relative(relative))
            if not header.is_relative_to(header_base) or not header.is_file():
                raise NativeIntegrateError("Swift module-map header missing or escaping root")
            headers[str(header)] = _sha(header)
            return "header " + json.dumps(header.as_posix())

        rendered = re.sub(r'header\s+"([^"]+)"', rebase, data.decode("utf-8"))
        if not headers:
            raise NativeIntegrateError("Swift module-map template declares no headers")
        prepared.append((source, expected, header_root, headers, rendered))
    maps = _path(output / "swift-module-maps")
    maps.mkdir()
    result = {"flags": [], "maps": [], "transitive_header_inventory_claimed": False}
    for source, expected, header_root, headers, rendered in prepared:
        target = maps / source.name
        with target.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(rendered)
        pins.update({str(source): expected, str(target): _sha(target), **headers})
        result["flags"].extend(["-Xcc", "-fmodule-map-file=" + str(target)])
        result["maps"].append({"original": str(source), "original_sha256": expected,
                               "private": str(target), "private_sha256": pins[str(target)],
                               "header_root": str(header_root), "headers": headers})
    return result


def run_integration(*, producer_report_path, integration_spec_path, application_contract_path,
                    output_dir, workspace_root, timeout_seconds=120, trusted_inputs=None) -> dict:
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
        raise NativeIntegrateError("timeout_seconds must be 1..600")
    root, output = _path(workspace_root), _path(output_dir)
    stop = root / ".runs/defense-loop/STOP"
    if (os.name != "nt" or not output.is_relative_to(root / ".runs") or output == root / ".runs"
            or output.exists() or stop.exists()):
        raise NativeIntegrateError("Requires fresh private Windows output and no defense STOP")
    trusted = safe._normalize_trusted_inputs(trusted_inputs)
    safe._verify_trusted_inputs(trusted, workspace_root=root, phase="preflight")
    pinned = load_producer_report(producer_report_path, workspace_root=root)
    spec = load_integration_spec(integration_spec_path, workspace_root=root, pinned=pinned)
    cases = load_application_contract(application_contract_path, workspace_root=root)
    language, report = pinned["language"], pinned["report"]
    compiler = _compiler(language)
    if compiler != report["project"].get("compiler"):
        raise NativeIntegrateError("Installed compiler differs from the producer snapshot")
    pins = {**pinned["pins"], spec["path"]: spec["sha256"], cases["path"]: cases["sha256"],
            **compiler["input_hashes"], **{r["path"]: r["sha256"] for r in trusted}}
    for name in ("native_app_integration", "jvm_app_integration", "bindings", "process",
                 "native_build", language + "_frontend", language + "_application_facade"):
        module = Path(__file__).with_name(name + ".py")
        pins[str(module)] = _sha(module)
    _verify_pins(pins, stop)
    output.mkdir(parents=True)
    generated, original, protected = (output / name for name in ("generated", "original", "protected"))
    original.mkdir()
    protected.mkdir()
    result = {"schema_version": 1, "kind": SPEC_KIND, "status": "failed", "language": language,
              "fresh_protected_native_build": False,
              "producer": {key: pinned[key] for key in
                           ("backend", "report_path", "report_sha256", "artifacts", "contract_path",
                            "contract_sha256", "native_report")},
              "preparation_commands": [], "comparison": {"status": "failed", "commands": [], "cases": []},
              "trusted_inputs_verification": {"verified": True, "declared_count": len(trusted)}}
    seen = set()
    ordinal = 0

    def check():
        _verify_pins(pins, stop)
        _verify_source_tree(Path(pinned["project_root"]), pinned["source_hashes"])
        # Go's stdlib/tool inventory is a content digest, not merely the go.exe hash.
        if language == "go" and _compiler("go") != compiler:
            raise NativeIntegrateError("Go compiler/standard library inventory changed")

    def child(argv, cwd, env, metadata, prep=False):
        nonlocal ordinal
        check()
        ordinal += 1
        prefix = output / "logs" / ("%03d" % ordinal)
        proc = process.run_logged(list(map(str, argv)), cwd, prefix, timeout_seconds,
                                  env=env, cancel_file=stop)
        record = _receipt(proc, prefix, seen)
        target = result["preparation_commands"] if prep else result["comparison"]["commands"]
        target.append({**metadata, **record})
        for key in ("receipt_path", "stdout_log", "stderr_log"):
            pins[record[key]] = _sha(record[key])
        check()
        stdout = safe._read_bytes_bounded(record["stdout_log"], limit=MAX_LOG_BYTES).decode("utf-8")
        safe._read_bytes_bounded(record["stderr_log"], limit=MAX_LOG_BYTES)
        if prep and proc["returncode"] != 0:
            raise NativeIntegrateError("Compilation failed: " + record["stderr_log"])
        return {"returncode": proc["returncode"], "stdout": stdout}

    try:
        facade = _facade_manifest(report, generated)
        for rel, digest in facade["files"].items():
            pins[str(generated / rel)] = digest
        pins[str(generated / "facade.json")] = _sha(generated / "facade.json")
        apps = []
        for row in spec["application_sources"]:
            source = Path(row["path"])
            _copy(source, original / source.name, pins)
            apps.append(_copy(source, protected / source.name, pins))
        original_sources = [original / Path(row["path"]).name for row in spec["application_sources"]]
        for value in pinned["core_sources"]:
            original_sources.append(_copy(value, original / Path(value).name, pins))
        facade_sources = []
        for rel in facade["compile_sources"]:
            file = generated / rel
            # Go explicit file lists must all be in one directory. Swift uses the
            # same staging layout; trusted modulemap/header stays in generated/.
            facade_sources.append(_copy(file, protected / file.name, pins))
        dll = _copy(pinned["artifacts"]["protected"]["path"], protected / "protected.dll", pins)
        runtime = []
        env = _base_env(output)
        original_argv, protected_argv = [], []
        if language == "go":
            go_root = compiler["go_root"]
            env.update(GOROOT=go_root, GOENV="off", GOTOOLCHAIN="local", GOPROXY="off",
                       GOSUMDB="off", GOTELEMETRY="off", GOWORK="off", GO111MODULE="off",
                       CGO_ENABLED="0", GOOS="windows", GOARCH="amd64")
            for key, value in (("GOCACHE", "go-cache"), ("GOPATH", "go-path"),
                               ("GOMODCACHE", "go-modcache"), ("GOTMPDIR", "go-tmp")):
                directory = output / value
                directory.mkdir()
                env[key] = str(directory)
            base = [compiler["go"], "build", "-trimpath", "-buildvcs=false"]
            original_argv = [*base, "-o", original / "app.exe", *original_sources]
            protected_argv = [*base, "-o", protected / "app.exe", *apps, *facade_sources]
        else:
            native_tools = safe._discover_native_toolchain(root)
            pins.update(native_tools["tool_hashes"])
            powershell = shutil.which("powershell.exe")
            if not powershell:
                raise NativeIntegrateError("Installed Windows PowerShell missing")
            pins[str(_path(powershell))] = _sha(powershell)
            check()
            capture = safe._capture_native_sdk_env(native_tools, output, real_stop=stop,
                                                   timeout=min(timeout_seconds, 60))
            entry = capture["prep_entry"]
            raw = _json(entry["receipt_path"])
            rec = _receipt(raw, Path(entry["receipt_path"]).with_suffix("").with_suffix(""), seen)
            if rec != {key: entry[key] for key in rec} or raw["returncode"] != 0:
                raise NativeIntegrateError("SDK capture receipt identity mismatch")
            result["preparation_commands"].append(entry)
            for key in ("receipt_path", "stdout_log", "stderr_log"):
                pins[entry[key]] = _sha(entry[key])
            check()
            env = safe._clean_native_env(output, capture["sdk_env"])
            env["PATH"] = os.pathsep.join([*compiler["search_dirs"], env["PATH"]])
            cl = safe._which_in("cl.exe", env["PATH"])
            link = safe._which_in("link.exe", env["PATH"])
            for tool in (cl, link):
                pins[tool] = _sha(tool)
            bridge = generated / facade["c_sources"][0]
            obj = output / "bridge.obj"
            child([cl, "/nologo", "/c", "/O2", "/MD", str(bridge), "/Fo" + str(obj)],
                  output, env, {"label": "compile-bridge", "kind": "compile", "tool": cl,
                                "cwd": str(output)}, prep=True)
            pins[str(obj)] = _sha(obj)
            cache = output / "swift-cache"
            cache.mkdir()
            base = [compiler["swiftc"], "-O", "-language-mode", "6", "-emit-executable",
                    "-module-name", "AntireaApplication", "-module-cache-path", str(cache)]
            if compiler.get("sdk"):
                base.extend(["-sdk", compiler["sdk"]])
                module_maps = _swift_module_maps(compiler, capture["sdk_env"], output, pins)
                base.extend(module_maps["flags"])
                result["swift_private_module_maps"] = module_maps
            original_argv = [*base, *original_sources, "-o", original / "app.exe"]
            includes = [item for rel in facade["include_dirs"] for item in ("-I", generated / rel)]
            protected_argv = [*base, *includes, *apps, *facade_sources, obj, "-o", protected / "app.exe"]
            for name, value in compiler["runtime_files"].items():
                if Path(name).name != name or not name.lower().endswith(".dll") or name.lower() == "protected.dll":
                    raise NativeIntegrateError("Invalid Swift runtime deployment filename")
                _copy(value, original / name, pins)
                _copy(value, protected / name, pins)
                runtime.append(name)
        if any(os.path.normcase(str(p)) in {os.path.normcase(v) for v in pinned["core_sources"]}
               for p in protected_argv):
            raise NativeIntegrateError("Original core entered protected compiler argv")
        for arm, argv, cwd in (("original", original_argv, original), ("protected", protected_argv, protected)):
            child(argv, cwd, env, {"label": "compile-" + arm, "kind": "compile",
                                  "tool": str(argv[0]), "cwd": str(cwd)}, prep=True)
            pins[str(cwd / "app.exe")] = _sha(cwd / "app.exe")
        result["staging"] = {"native_core_sha256": _sha(dll),
                             "application_source_hashes": {r["path"]: r["sha256"] for r in spec["application_sources"]},
                             "original_core_excluded_from_protected_compile": True}
        run_env = _base_env(output / "execution")
        for case in cases["cases"]:
            results = {}
            for arm, directory in (("original", original), ("protected", protected)):
                child_env = dict(run_env)
                if arm == "protected":
                    child_env["ANTIREA_NATIVE_CORE"] = str(dll)
                results[arm] = child([directory / "app.exe", *case["args"]], directory, child_env,
                    {"label": "case:" + case["label"] + ":" + arm, "kind": "case_arm",
                     "arm": arm, "case_label": case["label"], "control": None})
            match = results["original"] == results["protected"] == case["expect"]
            result["comparison"]["cases"].append({**case, "baseline": results["original"],
                                                 "protected": results["protected"], "match": match})
            if not match:
                raise NativeIntegrateError("Original/protected/expected output mismatch: " + case["label"])
        control_case = safe._select_control_case(cases["cases"])
        for control in ("missing_core", "unset_core"):
            child_env = dict(run_env)
            if control == "missing_core":
                absent = output / "absent" / "missing.dll"
                if absent.exists():
                    raise NativeIntegrateError("Missing-core control path unexpectedly exists")
                child_env["ANTIREA_NATIVE_CORE"] = str(absent)
            value = child([protected / "app.exe", *control_case["args"]], protected, child_env,
                          {"label": "control:" + control, "kind": "control", "control": control,
                           "arm": None, "case_label": None})
            if value["returncode"] == 0:
                raise NativeIntegrateError("Protected app succeeded without native core: " + control)
        deployment = output / "deployment"
        deployment.mkdir()
        for name in ["app.exe", "protected.dll", *runtime]:
            _copy(protected / name, deployment / name, pins)
        forbidden = {pinned["artifacts"]["baseline"]["sha256"], _sha(original / "app.exe"),
                     *(pinned["source_hashes"].values()), _sha(pinned["report_path"])}
        result["deployment"] = _deployment(deployment, ["app.exe", "protected.dll", *runtime], forbidden)
        check()
        safe._verify_trusted_inputs(trusted, workspace_root=root, phase="postflight")
        result["comparison"].update(status="producer_bound_integration_passed", all_match=True,
            expectations_ok=True, route_proof_ok=True, env_ok=True, integrity_verified_before_and_after=True,
            missing_core_control_ok=True, stop_cancellations=[], total_cases=len(cases["cases"]))
        result["status"] = "native_application_samples_passed"
    except Exception as exc:
        result.update(status="cancelled" if stop.exists() else "failed",
                      error=type(exc).__name__ + ": " + str(exc))
    _write(output / "integration.json", result)
    return result
