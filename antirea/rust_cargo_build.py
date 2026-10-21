"""Owned Cargo build/IR capture, separate from protection and execution.

Uses an already verified metadata receipt, an explicitly selected local MSVC
linker/library inventory, and a compiled trusted rustc recorder. No project
hooks, package downloads, target execution, or publication are authorized here.
Successful capture is NOT a protected build or a functional-equivalence result.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import sys

from . import rust_cargo as metadata
from .process import run_logged

LINKER_VARIABLE = "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER"
MAX_FILES = 100000
MAX_DIRECTORIES = 20000
MAX_BYTES = 8 * 1024**3
MAX_FILE_BYTES = 512 * 1024**2


def _check(condition, message):
    if not condition:
        raise ValueError(message)


def _path(value, *, existing=True, hardlinks=False):
    path = Path(value)
    _check(path.is_absolute() and ".." not in path.parts, "absolute normalized path required")
    _check(not str(path).startswith(("\\\\", "//")) and
           not any(":" in part for part in path.parts[1:]), "device/UNC/stream path rejected")
    _check(path.name.lower() != "env.setting", "environment dump is not a capture input")
    for item in reversed([path, *path.parents]):
        try:
            info = item.lstat()
        except FileNotFoundError:
            _check(not existing and item == path, "missing path ancestor")
            continue
        _check(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
               "linked capture path rejected")
        if stat.S_ISREG(info.st_mode):
            _check(hardlinks or info.st_nlink == 1, "hardlinked trusted input rejected")
    return path.resolve(strict=existing)


def _file(value, *, hardlinks=False):
    path = _path(value, hardlinks=hardlinks)
    before = path.stat()
    _check(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_FILE_BYTES,
           "capture file type/size limit")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    after = path.stat()
    _check((before.st_ino, before.st_size, before.st_mtime_ns) ==
           (after.st_ino, after.st_size, after.st_mtime_ns), "file changed during capture hash")
    return {"path": str(path), "sha256": digest, "bytes": before.st_size}


def _read(value, *, limit=32 * 1024**2):
    path = _path(value)
    before = _file(path)
    _check(before["bytes"] <= limit, "structured capture input exceeds limit")
    raw = path.read_bytes()
    _check(metadata._digest(raw) == before["sha256"], "structured input changed while reading")
    return metadata._json(raw)


def _bound_bytes(item, *, limit=32 * 1024**2):
    _check(isinstance(item, dict) and set(item) in ({"path", "sha256"}, {"path", "sha256", "bytes"})
           and isinstance(item["path"], str) and isinstance(item["sha256"], str)
           and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None,
           "malformed evidence descriptor")
    _check("bytes" not in item or type(item["bytes"]) is int and item["bytes"] >= 0,
           "evidence byte count must be a nonnegative integer")
    _check(type(limit) is int and 0 <= limit <= MAX_FILE_BYTES, "bounded evidence read limit required")
    path = _path(item["path"])
    current = _file(path)
    _check(current["sha256"] == item["sha256"] and
           ("bytes" not in item or current["bytes"] == item["bytes"]), "evidence descriptor changed before consumption")
    _check(current["bytes"] <= limit, "evidence exceeds read limit")
    raw = path.read_bytes()
    _check(metadata._digest(raw) == current["sha256"], "evidence changed during consumption")
    return raw


def _write(path, value):
    _path(path, existing=False)
    with path.open("xb") as stream:
        stream.write(metadata._canonical(value) + b"\n")


def inventory_trees(roots):
    """Bound selected SDK/output trees; OS and Cargo hardlinks are permitted.

    Names and contents are both observed. This is not an OS file-read trace or
    a guarantee that another same-account process cannot race these checks.
    """
    roots = sorted({_path(root, hardlinks=True) for root in roots}, key=str)
    _check(bool(roots) and all(root.is_dir() for root in roots), "inventory directories required")
    _check(not any(a != b and a in b.parents for a in roots for b in roots), "overlapping inventory roots")
    names, directories, total = {}, set(), 0
    for root in roots:
        for current, children, leaves in os.walk(root, followlinks=False):
            current = _path(current, hardlinks=True)
            directories.add(str(current))
            _check(len(directories) + len(children) <= MAX_DIRECTORIES, "capture directory inventory limit")
            for name in children:
                _check(_path(current / name, hardlinks=True).is_dir(), "invalid directory entry")
            for name in sorted(leaves):
                path = _path(current / name, hardlinks=True)
                total += path.stat().st_size
                _check(len(names) < MAX_FILES and total <= MAX_BYTES, "capture inventory limit")
                names[str(path)] = _file(path, hardlinks=True)
    result = {"roots": [str(path) for path in roots], "directories": sorted(directories),
              "files": [names[name] for name in sorted(names)]}
    return {**result, "sha256": metadata._hash(result)}


def native_link_context(config_path, *, workspace_root):
    """Read a fixed operator configuration; never run SDK discovery scripts."""
    root = _path(workspace_root)
    path = _path(config_path)
    _check(path == root / ".tools" / "rust-cargo-build-toolchain.json", "fixed operator link configuration required")
    config = _read(path, limit=1024**2)
    _check(isinstance(config, dict) and set(config) == {"schema_version", "linker", "library_directories"}
           and type(config["schema_version"]) is int and config["schema_version"] == 1,
           "native link configuration schema mismatch")
    _check(isinstance(config["linker"], str), "explicit linker path required")
    linker = _path(config["linker"], hardlinks=True)
    _check(linker.is_file() and linker.name.lower() == "link.exe", "MSVC link.exe required")
    libraries = config["library_directories"]
    _check(isinstance(libraries, list) and 1 <= len(libraries) <= 16 and
           all(isinstance(item, str) and item for item in libraries), "explicit library directories required")
    libraries = [_path(item, hardlinks=True) for item in libraries]
    _check(len(set(libraries)) == len(libraries) and all(item.is_dir() for item in libraries),
           "duplicate/invalid library directory")
    for item in [linker, *libraries]:
        _check(not set(part.lower() for part in item.parts) & metadata.FORBIDDEN_PARTS,
               "received paths cannot select compiler/linker inputs")
        _check(not any(token in str(item) for token in (";", "\n", "\r", "\x00")),
               "native path cannot contain environment separators")
    inventory = inventory_trees([linker.parent, *libraries])
    return {"configuration": _file(path), "selection": {"linker": str(linker),
            "library_directories": [str(item) for item in libraries]}, "inventory": inventory,
            "qualification": "Selected linker-bin and library trees; not the full OS loader/read closure."}


def build_environment(tools, native, *, host_environment, private_root):
    """Exact child environment; no inherited credentials, wrappers or flags."""
    private = _path(private_root)
    host = metadata._normalize_environment(host_environment)
    _check(set(host) == {"SYSTEMROOT", "WINDIR", "PATH"}, "metadata host controls required")
    windows = _path(host["SYSTEMROOT"])
    _check(_path(host["WINDIR"]) == windows, "ambiguous Windows directory")
    selection = native["selection"]
    linker = _path(selection["linker"], hardlinks=True)
    backend_bin = _path(Path(tools["selection"]["rustc"]).parent)
    path = ";".join(str(item) for item in (backend_bin, linker.parent, windows / "System32"))
    return {**host, **metadata._overrides(tools, private), "PATH": path,
            "LIB": ";".join(selection["library_directories"]), LINKER_VARIABLE: str(linker)}


def _command(argv, cwd, prefix, environment, stop, *, timeout):
    _check(not stop.exists(), "STOP set before Cargo capture command")
    result = run_logged(argv, cwd, prefix, timeout=timeout, env=environment, cancel_file=stop)
    files = {key: _file(Path(str(prefix) + suffix)) for key, suffix in
             (("stdout", ".stdout.log"), ("stderr", ".stderr.log"), ("process", ".process.json"))}
    _check(metadata._canonical(_read(files["process"]["path"])) == metadata._canonical(result),
           "process receipt differs from saved command")
    _check(result.get("argv") == argv and result.get("stdout") == files["stdout"]["path"] and
           result.get("stderr") == files["stderr"]["path"], "process recipe/log path mismatch")
    return {"process": result, "files": files, "clean": metadata._clean(result)}


def capture_project(plan, *, plan_path, workspace_root, output_dir, env=None, timeout=600):
    """Build original and derivative library units, collecting actual IR/edges.

    `plan` is the saved INNER metadata inspection, not ProjectService's outer
    job envelope. Output must be a fresh private .runs child. The selected
    project's library is never loaded or executed. Failed/partial jobs persist.
    """
    from . import rust_cargo_units as units
    from . import rust_cargo_artifacts as artifacts

    _check(os.name == "nt", "Cargo capture currently requires Windows")
    _check(type(timeout) is int and 1 <= timeout <= 3600, "bounded integer command timeout required")
    root = _path(workspace_root)
    plan_path = _path(plan_path)
    inspection = plan["inspection"]
    tools = inspection["toolchain"]
    source_environment = dict(os.environ if env is None else env)  # discovery only, NEVER a child environment
    verification = metadata.verify_plan(plan, plan_path=plan_path, workspace_root=root,
                                        toolchain=tools["selection"], env=source_environment)
    _check(verification["metadata_succeeded"] and not inspection["blockers"], "successful unblocked metadata required")
    output = _path(output_dir, existing=False)
    _check(not output.exists() and output.is_relative_to(root / ".runs") and
           not output.is_relative_to(root / ".runs" / "defense-loop"), "fresh private capture output required")
    for item in inspection["input_snapshot"]["roots"]:
        source = Path(item)
        _check(not output.is_relative_to(source) and not source.is_relative_to(output), "capture/source roots overlap")
    stop = root / ".runs" / "defense-loop" / "STOP"
    _check(not stop.exists(), "STOP set")
    native_path = root / ".tools" / "rust-cargo-build-toolchain.json"
    native = native_link_context(native_path, workspace_root=root)
    recorder_source = root / "tools" / "rust_cargo_recorder" / "wrapper.rs"
    engine_files = [Path(__file__), Path(metadata.__file__), Path(units.__file__), Path(artifacts.__file__),
                    Path(__file__).with_name("process.py"), Path(__file__).with_name("__init__.py"),
                    Path(sys.executable), recorder_source, plan_path, native_path]
    pins = [_file(path) for path in engine_files]
    output.mkdir()
    report = {"schema_version": 1, "status": "failed_capture", "commands": [], "arms": {}, "evidence_files": [],
              "inspection_receipt": _file(plan_path), "initial_verification": verification,
              "engine_inputs": pins, "native_link_context": native,
              "target_executed": False, "vm_applied": False, "published": False,
              "functional_validation": "not_performed", "external_attack_evaluation": "not_evaluated"}
    execution_pins = []

    def recheck():
        _check(not stop.exists(), "STOP set")
        _check([_file(item["path"]) for item in pins] == pins, "capture engine/configuration changed")
        _check([_file(item["path"]) for item in execution_pins] == execution_pins, "compiled recorder changed")
        _check(native_link_context(native_path, workspace_root=root) == native, "native linker/library inventory changed")
        return metadata.verify_plan(plan, plan_path=plan_path, workspace_root=root,
                                    toolchain=tools["selection"], env=source_environment)

    def run(argv, prefix, environment, *, command_timeout=timeout, cwd=root):
        _check([_file(item["path"]) for item in execution_pins] == execution_pins,
               "compiled recorder changed before command")
        row = _command(argv, cwd, prefix, environment, stop, timeout=command_timeout)
        report["commands"].append(row)
        _check(row["clean"], "capture command failed or owned cleanup unverified")
        return row

    try:
        context = output / "context"
        context.mkdir()
        for directory in metadata._private_environment_directories(context):
            directory.mkdir()
        _, _, host, blockers = metadata._metadata_environment(source_environment, tools)
        _check(not blockers, "unsupported compiler environment selectors")
        environment = build_environment(tools, native, host_environment=host, private_root=context)
        report["build_environment"] = metadata._environment(environment)
        backend = tools["selection"]["rustc"]
        recheck()
        host_row = run([backend, "-vV"], context / "host", environment, command_timeout=60)
        host_proof = {"triple": metadata.TARGET, "rustc_sha256": tools["compiler_inputs"][backend], **host_row["files"]}
        units.verify_backend_host(host_proof, backend=backend,
            backend_sha256=tools["compiler_inputs"][backend], workspace_root=str(root))
        wrapper = context / "rustc-recorder.exe"
        compile_argv = [backend, str(recorder_source), "--edition=2021", "--crate-name", "antirea_rustc_recorder",
                        "--target", metadata.TARGET, "-Copt-level=2", "-Clinker=" + native["selection"]["linker"], "-o", str(wrapper)]
        recheck()
        run(compile_argv, context / "compile-recorder", environment)
        wrapper_item = _file(wrapper)
        execution_pins.append(wrapper_item)
        recheck()
        selftest = run([str(wrapper), "--self-test"], context / "recorder-selftest", environment, command_timeout=60)
        units.verify_wrapper_selftest(_read(selftest["files"]["stdout"]["path"]))
        report["recorder"] = {"source": _file(recorder_source), "binary": wrapper_item, "selftest": selftest}
        sdk_hashes = {item["path"]: item["sha256"] for item in native["inventory"]["files"]}
        sdk_hashes[native["configuration"]["path"]] = native["configuration"]["sha256"]
        receipt = units.create_build_environment_receipt(inspection, environment,
            sdk_input_hashes=sdk_hashes, evidence_files=[_file(plan_path), *host_row["files"].values()])
        capture_plan = units.plan_invocations(inspection, wrapper=units.Tool(str(wrapper), wrapper_item["sha256"]),
            output_root=output / "build", environment=environment, build_environment_receipt=receipt, backend_host=host_proof)
        _write(output / "capture-plan.json", capture_plan)
        report["capture_plan"] = _file(output / "capture-plan.json")
        report["evidence_files"].append(report["capture_plan"])
        (output / "build").mkdir()
        actual_records = {}
        for mode in ("original", "derivative"):
            arm = capture_plan["arms"][mode]
            arm_root = _path(arm["root"], existing=False)
            arm_root.mkdir()
            for key in ("target_root", "record_root"):
                _path(arm["policy"][key], existing=False).mkdir()
            policy_path = Path(arm["environment_overrides"]["ANTIREA_RUST_UNIT_POLICY"])
            with policy_path.open("xb") as stream:
                stream.write(arm["policy_text"].encode())
            _check(_file(policy_path)["sha256"] == arm["policy_sha256"], "wrapper policy materialization mismatch")
            report["evidence_files"].append(_file(policy_path))
            row = {"prelaunch_verification": recheck()}
            report["arms"][mode] = row
            effective = {**environment, **arm["environment_overrides"]}
            _check(units.environment_digest(effective) == arm["environment_sha256"], "build environment differs from plan")
            command = run(arm["argv"], arm_root / "cargo", effective, cwd=Path(arm["cwd"]))
            row["command"] = command
            row["postlaunch_verification"] = recheck()
            row["unit_verification"] = units.inspect_unit_records(Path(arm["policy"]["record_root"]), arm)
            row["target_inventory"] = inventory_trees([arm["policy"]["target_root"]])
            observations = {item["path"]: {"sha256": item["sha256"], "bytes": item["bytes"]}
                            for item in row["target_inventory"]["files"]}
            for item in [*inspection["input_snapshot"]["files"], *tools["inventory"]["files"],
                         *native["inventory"]["files"], native["configuration"], wrapper_item]:
                observations[item["path"]] = {"sha256": item["sha256"], "bytes": item["bytes"]}
            bundles = [{"unit": item["unit"], "start_bytes": _bound_bytes(item["start"], limit=4 * 1024**2),
                        "finish_bytes": _bound_bytes(item["finish"], limit=4 * 1024**2)}
                       for item in row["unit_verification"]["units"]]
            for item in row["unit_verification"]["units"]:
                report["evidence_files"].extend(_file(item[key]["path"]) for key in ("start", "finish"))
            dep_info = {item["path"]: _bound_bytes(item)
                        for item in row["target_inventory"]["files"] if item["path"].endswith(".d")}
            compiler_inputs = dict(tools["compiler_inputs"])
            for name, digest in sdk_hashes.items():
                _check(name not in compiler_inputs or compiler_inputs[name] == digest, "conflicting Rust/SDK input identity")
                compiler_inputs[name] = digest
            row["artifacts"] = artifacts.collect_cargo_artifacts(bundles, _bound_bytes(command["files"]["stdout"]),
                arm=arm, source_snapshot={item["path"]: item["sha256"] for item in inspection["input_snapshot"]["files"]},
                compiler_snapshot=compiler_inputs, packages=[item["package"] for item in inspection["resolution"]["closure"]],
                observed_files=observations, dep_info_contents=dep_info)
            actual_records[mode] = [metadata._json(item["start_bytes"]) for item in bundles
                                    if metadata._json(item["start_bytes"])["kind"] == "crate"]
            _write(arm_root / "captured.json", row)
            row["receipt"] = _file(arm_root / "captured.json")
        def identities(records):
            result = {}
            for item in records:
                parsed = units.parse_rustc_args(item["original_argv"][1:])
                key = (item["cargo_identity"]["CARGO_MANIFEST_DIR"], parsed["values"]["--crate-name"][0])
                _check(key not in result, "ambiguous repeated original/derivative unit identity")
                result[key] = item
            return result
        original, derivative = (identities(actual_records[mode]) for mode in ("original", "derivative"))
        _check(bool(original) and original.keys() == derivative.keys(), "original/derivative unit sets differ")
        report["decisions"] = [units.compare_cargo_decisions(original[key], derivative[key],
            capture_plan["arms"]["original"], capture_plan["arms"]["derivative"]) for key in sorted(original)]
        report["terminal_verification"] = recheck()
        _check(_file(wrapper) == wrapper_item, "recorder binary changed")
        for mode, row in report["arms"].items():
            _check(inventory_trees([capture_plan["arms"][mode]["policy"]["target_root"]]) == row["target_inventory"],
                   "captured target tree changed")
            _check(_file(row["receipt"]["path"]) == row["receipt"], "arm receipt changed")
        for row in report["commands"]:
            _check({key: _file(item["path"]) for key, item in row["files"].items()} == row["files"], "command evidence changed")
        _check([_file(item["path"]) for item in report["evidence_files"]] == report["evidence_files"],
               "policy/plan/unit evidence changed after capture")
        report["status"] = "cargo_original_derivative_captured_not_protected"
    except Exception as exc:
        report["error"] = type(exc).__name__ + ": " + str(exc)[:4096]
        try:
            report["failure_recheck"] = recheck()
        except Exception as terminal:
            report["terminal_error"] = type(terminal).__name__ + ": " + str(terminal)[:4096]
    report["limitations"] = ["Library units only; accepted metadata must reject hooks/nonlocal dependencies.",
        "Derivative compilation is not a source-equivalence proof or protected build.",
        "Compiler dep-info is not a complete filesystem/native-link read trace.",
        "Windows Job ownership checks are not an OS sandbox or atomic prelaunch containment.",
        "Public source-build remains disabled until protection, linking and original-runtime validation are integrated."]
    _write(output / "capture.json", report)
    return report
