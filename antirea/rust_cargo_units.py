"""Cargo unit recipes and evidence checks; this module launches no process.

This module has no subprocess entry point. It creates fixed invocation recipes
and checks records from a trusted wrapper execution. Calling Cargo,
compiling the wrapper, final linking and VM integration remain caller-owned and
unimplemented here. Do not infer effective rustc flags from Cargo metadata.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat

TARGET = "x86_64-pc-windows-msvc"
VALUE_OPTIONS = {"--crate-name", "--crate-type", "--edition", "--emit", "--out-dir", "--extern", "--cfg",
                 "--check-cfg", "--target", "--error-format", "--json", "--cap-lints", "--color",
                 "--diagnostic-width", "--remap-path-prefix", "--sysroot", "--print", "-C", "-L", "-l", "-A", "-W", "-D", "-F"}
UNIT_SWITCHES = {"-g", "-O", "--test"}
PROBE_NAMES = {"cfg", "sysroot", "target-libdir", "file-names", "split-debuginfo", "crate-name", "target-list"}
DERIVATIVE_CODEGEN = {"no-prepopulate-passes": None, "embed-bitcode": "no", "codegen-units": "1"}
HEX = re.compile(r"[0-9a-f]{64}\Z")
FORBIDDEN_PARTS = {"rea-analysis-reports", "attackerfolder"}
CODEGEN_OPTIONS = {"opt-level", "debug-assertions", "overflow-checks", "debuginfo", "split-debuginfo", "linker",
                   "incremental", "metadata", "extra-filename", "codegen-units", "panic", "strip", "lto",
                   "embed-bitcode", "no-prepopulate-passes", "target-cpu", "target-feature", "relocation-model"}
SHA_SAMPLES = ["", "abc", "a\x00b", "한글/Ω",
               "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


SHA_SAMPLES.append(canonical({"PATH": "C:\\tools\\한글", "PRIVATE_SAMPLE": "not-a-secret",
                              "ZZ_CONTROL": "line\nNUL\x00quote\"slash\\"}).decode("utf-8"))


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_hash(path):
    hasher = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_wrapper_selftest(payload):
    """Pure hashlib cross-check of future compiled wrapper --self-test stdout.

    This checks supplied vectors only, not producer/tool identity or successful
    child cleanup. The caller must separately bind the output to the pinned
    wrapper and its bounded completed process. This function executes nothing.
    """
    expected = [{"input": value, "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest()}
                for value in SHA_SAMPLES]
    if payload != expected:
        raise ValueError("wrapper SHA-256/JSON self-test differs from Python hashlib")
    return {"status": "supplied_sha_vectors_match_hashlib", "vectors": len(expected), "producer_verified": False}


def environment_digest(environment):
    normalized = {str(key).upper(): str(value) for key, value in environment.items()}
    if len(normalized) != len(environment):
        raise ValueError("case-ambiguous Windows environment")
    return digest(normalized)


def inspector_environment_digest(environment):
    """Frozen inspector uses ASCII JSON; wrapper records separately use UTF-8.

    The encoding identifier matters for non-ASCII environment values. Do not
    compare these two formats as though they were the same byte representation.
    """
    normalized = {str(key).upper(): str(value) for key, value in environment.items()}
    if len(normalized) != len(environment):
        raise ValueError("case-ambiguous Windows environment")
    raw = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(raw).hexdigest()


LINKER_SELECTOR = "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER"
BUILD_ENVIRONMENT_KEYS = frozenset({"SYSTEMROOT", "WINDIR", "PATH", "LIB", "RUSTC",
    "CARGO_NET_OFFLINE", "CARGO_TERM_COLOR", "CARGO_TARGET_DIR", "CARGO_HOME", "USERPROFILE",
    "HOME", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", LINKER_SELECTOR})


def _ascii_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()


def _inspection_identity(inspection):
    if (not isinstance(inspection, dict) or inspection.get("backend") != "rust_cargo_native"
            or inspection.get("status") != "inspected_build_not_implemented"
            or type(inspection.get("schema_version")) is not int or inspection["schema_version"] != 1):
        raise ValueError("requires a successful metadata-only inspection")
    fields = dict(inspection)
    expected = fields.pop("fingerprint", None)
    if not isinstance(expected, str) or _ascii_digest(fields) != expected:
        raise ValueError("metadata inspection fingerprint mismatch")
    policy = inspection.get("environment")
    if (not isinstance(policy, dict) or type(policy.get("schema_version")) is not int
            or policy["schema_version"] != 1 or policy.get("policy") != "windows_metadata_minimal_v1"):
        raise ValueError("expected the explicit production metadata environment policy")
    fields = dict(policy)
    expected = fields.pop("sha256", None)
    if not isinstance(expected, str) or _ascii_digest(fields) != expected:
        raise ValueError("metadata environment policy fingerprint mismatch")


def _build_environment(inspection, environment):
    if not isinstance(environment, dict):
        raise ValueError("explicit minimal build environment is required")
    normalized = {}
    for key, value in environment.items():
        if (not isinstance(key, str) or not isinstance(value, str) or not value
                or any(ch in key for ch in "\x00=") or "\x00" in value or key.upper() in normalized):
            raise ValueError("malformed or case-ambiguous build environment")
        normalized[key.upper()] = value
    if set(normalized) != BUILD_ENVIRONMENT_KEYS:
        raise ValueError("build environment must contain exactly the 16 approved controls")
    tools = inspection["toolchain"]["selection"]
    if (normalized["RUSTC"] != tools["rustc"] or normalized["CARGO_NET_OFFLINE"] != "true"
            or normalized["CARGO_TERM_COLOR"] != "never"):
        raise ValueError("fixed compiler/offline/terminal build controls mismatch")
    windows = _absolute(normalized["SYSTEMROOT"])
    if windows != _absolute(normalized["WINDIR"]) or not windows.is_dir():
        raise ValueError("Windows build host directory mismatch")
    linker = _absolute(normalized[LINKER_SELECTOR], allow_owned_hardlinks=True)
    if linker.name.lower() != "link.exe" or not linker.is_file():
        raise ValueError("an explicitly pinned installed MSVC link.exe is required")
    expected_path = [str(Path(tools["rustc"]).parent), str(linker.parent), str(windows / "System32")]
    if normalized["PATH"].split(";") != expected_path or any(not _absolute(x).is_dir() for x in expected_path):
        raise ValueError("build PATH must be backend bin, pinned linker bin, then System32 exactly")
    libraries = normalized["LIB"].split(";")
    if (not libraries or len(set(libraries)) != len(libraries)
            or any(not value or not _absolute(value).is_dir() for value in libraries)):
        raise ValueError("LIB must name explicit nonempty unique installed library directories")
    root = _absolute(inspection["workspace_root"])
    inputs = [_absolute(value) for value in inspection["input_snapshot"]["roots"]]
    for name in ("CARGO_TARGET_DIR", "CARGO_HOME", "USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP"):
        path = _absolute(normalized[name])
        if (path == root / ".runs" or not path.is_relative_to(root / ".runs")
                or set(part.lower() for part in path.relative_to(root).parts) & (FORBIDDEN_PARTS | {"defense-loop"})
                or any(path.is_relative_to(item) or item.is_relative_to(path) for item in inputs)
                or (name != "CARGO_TARGET_DIR" and not path.is_dir())):
            raise ValueError("build home/temp/target controls must be private owned paths outside source inputs")
    home = Path(normalized["USERPROFILE"])
    if (Path(normalized["HOME"]) != home or Path(normalized["APPDATA"]) != home / "AppData/Roaming"
            or Path(normalized["LOCALAPPDATA"]) != home / "AppData/Local"
            or normalized["TEMP"] != normalized["TMP"]):
        raise ValueError("private build home/temp controls are inconsistent")
    return normalized


def create_build_environment_receipt(inspection, environment, *, sdk_input_hashes, evidence_files):
    """Bind a caller-created minimal environment; never initialize an SDK.

    Metadata uses a separate policy hash. SDK selection, inventory completeness
    and the metadata/process history must be authenticated by the coordinator;
    this helper rechecks supplied file bytes and exact inspection/receipt binding.
    It neither inherits os.environ nor executes tools or creates directories.
    """
    _inspection_identity(inspection)
    env = _build_environment(inspection, environment)
    if not isinstance(sdk_input_hashes, dict) or not 1 <= len(sdk_input_hashes) <= 20000:
        raise ValueError("nonempty bounded SDK input pins are required")
    pins = {}
    sdk_directories = [Path(env[LINKER_SELECTOR]).parent, *map(Path, env["LIB"].split(";"))]
    for name, expected in sdk_input_hashes.items():
        # OS-maintained SDK aliases are not Cargo-owned output aliases. Only
        # the explicitly selected SDK trees allow them; config/evidence/source
        # paths retain the ordinary no-hardlink rule. Content pins still apply.
        if not isinstance(name, str):
            raise ValueError("SDK input pin path must be text")
        sdk_file = any(Path(name).is_relative_to(directory) for directory in sdk_directories)
        path = _absolute(name, allow_owned_hardlinks=sdk_file)
        if (path.name.lower() == "env.setting" or not isinstance(expected, str) or not HEX.fullmatch(expected)
                or not path.is_file() or file_hash(path) != expected):
            raise ValueError("SDK input pin is missing or changed")
        pins[str(path)] = expected
    if len(pins) != len(sdk_input_hashes) or env[LINKER_SELECTOR] not in pins:
        raise ValueError("SDK pins must include the exact linker and unambiguous file identities")
    for directory in env["LIB"].split(";"):
        if not any(Path(name).is_relative_to(Path(directory)) for name in pins):
            raise ValueError("every selected library directory needs SDK input pins")
    if not isinstance(evidence_files, list) or not 1 <= len(evidence_files) <= 128:
        raise ValueError("metadata and SDK/context evidence descriptors are required")
    evidence, metadata, paths = [], [], set()
    root = _absolute(inspection["workspace_root"])
    for item in evidence_files:
        if (not isinstance(item, dict) or set(item) != {"path", "sha256", "bytes"}
                or not isinstance(item["sha256"], str) or not HEX.fullmatch(item["sha256"])
                or type(item["bytes"]) is not int or not 0 <= item["bytes"] <= 32 * 1024 * 1024):
            raise ValueError("malformed build context evidence descriptor")
        path = _absolute(item["path"])
        if (not path.is_relative_to(root / ".runs") or path.is_relative_to(root / ".runs/defense-loop")
                or set(part.lower() for part in path.parts) & FORBIDDEN_PARTS
                or path.name.lower() == "env.setting" or str(path) in paths or not path.is_file()
                or path.stat().st_size != item["bytes"] or file_hash(path) != item["sha256"]):
            raise ValueError("build context evidence is missing, changed, duplicated or unowned")
        paths.add(str(path))
        evidence.append(dict(item))
        if path.name == "plan.json":
            document = _json(path.read_bytes())
            if (canonical(document.get("inspection")) == canonical(inspection)
                    and isinstance(document.get("metadata_evidence"), dict)):
                metadata.append(dict(item))
    if len(metadata) != 1 or len(evidence) < 2:
        raise ValueError("exactly one matching inner metadata plan plus SDK/context evidence is required")
    result = {"schema_version": 1, "kind": "cargo_build_environment_v1",
        "inspection_fingerprint": inspection["fingerprint"],
        "metadata_environment_policy_sha256": inspection["environment"]["sha256"],
        "environment_sha256": environment_digest(environment),
        "environment_value_sha256": {key: hashlib.sha256(value.encode("utf-8")).hexdigest() for key, value in sorted(env.items())},
        "sdk_input_hashes": dict(sorted(pins.items())), "evidence_files": sorted(evidence, key=lambda x: x["path"]),
        "metadata_plan": metadata[0], "sdk_selection_independently_verified": False,
        "sdk_hardlink_policy": "caller-selected linker-bin/LIB trees permit OS aliases with content pins; config/evidence/source remain no-hardlink",
        "qualification": "Caller-selected SDK/context pins checked; not original ambient-environment equivalence, complete SDK closure or process attestation."}
    result["sha256"] = digest(result)
    return result


def verify_build_environment_receipt(inspection, environment, receipt):
    if not isinstance(receipt, dict):
        raise ValueError("separate build environment receipt is required")
    expected = create_build_environment_receipt(inspection, environment,
        sdk_input_hashes=receipt.get("sdk_input_hashes"), evidence_files=receipt.get("evidence_files"))
    if canonical(receipt) != canonical(expected):
        raise ValueError("build environment changed or its receipt was altered")
    return expected


def _absolute(value, *, allow_owned_hardlinks=False):
    if not isinstance(value, (str, Path)):
        raise ValueError("path must be text or Path")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path):
        raise ValueError("absolute normalized owned paths required")
    if str(path).startswith(("\\\\", "//")) or any(":" in part for part in path.parts[1:]):
        raise ValueError("device/alternate-stream paths are not supported")
    for item in [path, *path.parents]:
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("symlink/reparse path is not permitted")
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1 and not allow_owned_hardlinks:
            raise ValueError("hardlinked path is not permitted")
    return path


def _file_identity(path):
    """Read a regular file's link identity; never invokes a process."""
    if os.name == "nt":
        import ctypes
        import msvcrt
        class Info(ctypes.Structure):
            _fields_ = [("attributes", ctypes.c_uint32), ("creation", ctypes.c_uint32 * 2),
                        ("access", ctypes.c_uint32 * 2), ("write", ctypes.c_uint32 * 2),
                        ("volume", ctypes.c_uint32), ("size_high", ctypes.c_uint32),
                        ("size_low", ctypes.c_uint32), ("links", ctypes.c_uint32),
                        ("index_high", ctypes.c_uint32), ("index_low", ctypes.c_uint32)]
        fn = ctypes.WinDLL("kernel32", use_last_error=True).GetFileInformationByHandle
        fn.argtypes, fn.restype = [ctypes.c_void_p, ctypes.POINTER(Info)], ctypes.c_int
        with Path(path).open("rb") as stream:
            info = Info()
            if not fn(msvcrt.get_osfhandle(stream.fileno()), ctypes.byref(info)):
                raise ValueError("cannot inspect target file handle identity")
            if info.attributes & (0x400 | 0x10):
                raise ValueError("target file handle is reparse/directory")
        return (f"{info.volume:08x}:{info.index_high:08x}{info.index_low:08x}", int(info.links))
    info = Path(path).stat()
    return (f"{info.st_dev:x}:{info.st_ino:x}", info.st_nlink)


def check_target_tree(root):
    """Permit only fully accounted aliases in an owned target tree.

    Two bounded no-follow scans must agree. This detects pre-existing external
    aliases, not malicious swaps after the check; no filesystem sandbox claim.
    """
    root = _absolute(root)
    if not root.is_dir():
        raise ValueError("target root must be an existing owned directory")
    def scan():
        found, directories, pending = [], [], [root]
        while pending:
            current = pending.pop()
            _absolute(current)
            directories.append(str(current))
            if len(directories) > 10000:
                raise ValueError("target tree directory-count limit")
            for path in sorted(current.iterdir()):
                _absolute(path, allow_owned_hardlinks=True)
                info = path.lstat()
                if stat.S_ISDIR(info.st_mode):
                    pending.append(path)
                elif stat.S_ISREG(info.st_mode):
                    identity, links = _file_identity(path)
                    found.append({"path": str(path), "identity": identity, "links": links})
                    if len(found) > 10000:
                        raise ValueError("target tree file-count limit")
                else:
                    raise ValueError("unsupported target leaf type")
        aliases = {}
        for row in found:
            aliases.setdefault(row["identity"], []).append(row)
        for rows in aliases.values():
            if any(row["links"] != len(rows) for row in rows):
                raise ValueError("target hardlinks have unaccounted/external aliases")
        return {"root": str(root), "directories": sorted(directories),
                "files": sorted(found, key=lambda row: row["path"])}
    first, second = scan(), scan()
    if first != second:
        raise ValueError("target alias tree changed while inspected")
    return first


def validate_target_tree_record(value, root):
    """Validate historical inventory structure; live identity recheck is separate."""
    root = _absolute(root)
    if not isinstance(value, dict) or set(value) != {"root", "directories", "files"} or value["root"] != str(root):
        raise ValueError("missing/malformed target alias inventory")
    directories, rows = value["directories"], value["files"]
    if (not isinstance(directories, list) or not directories or len(directories) > 10000 or
            any(not isinstance(x, str) or not _absolute(x).is_relative_to(root) for x in directories) or
            directories != sorted(set(directories)) or str(root) not in directories or not isinstance(rows, list) or len(rows) > 10000):
        raise ValueError("malformed target directory inventory")
    aliases, paths = {}, []
    for row in rows:
        if (not isinstance(row, dict) or set(row) != {"path", "identity", "links"} or
                not isinstance(row["path"], str) or not _absolute(row["path"], allow_owned_hardlinks=True).is_relative_to(root) or
                not isinstance(row["identity"], str) or not re.fullmatch(r"[0-9a-f]+:[0-9a-f]+", row["identity"]) or
                type(row["links"]) is not int or row["links"] <= 0):
            raise ValueError("malformed target file identity")
        paths.append(row["path"])
        aliases.setdefault(row["identity"], []).append(row)
    if paths != sorted(set(paths)) or any(row["links"] != len(group) for group in aliases.values() for row in group):
        raise ValueError("recorded target aliases are incomplete or duplicated")
    return value


def _json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate record JSON key")
            result[key] = value
        return result
    value = json.loads(data, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("record JSON must be an object")
    return value


def verify_backend_host(proof, *, backend, backend_sha256, workspace_root):
    if not isinstance(proof, dict) or set(proof) != {"triple", "rustc_sha256", "stdout", "stderr", "process"}:
        raise ValueError("explicit completed backend-host proof required")
    if proof["triple"] != TARGET or proof["rustc_sha256"] != backend_sha256:
        raise ValueError("backend-host proof identity mismatch")
    contents, paths = {}, {}
    root = _absolute(workspace_root)
    for key in ("stdout", "stderr", "process"):
        descriptor = proof[key]
        if not isinstance(descriptor, dict) or set(descriptor) not in ({"path", "sha256"}, {"path", "sha256", "bytes"}):
            raise ValueError("malformed backend-host evidence descriptor")
        path = _absolute(descriptor["path"])
        if (not path.is_relative_to(root / ".runs") or path.is_relative_to(root / ".runs" / "defense-loop") or
                not path.is_file() or path.stat().st_size > 1024 * 1024 or file_hash(path) != descriptor["sha256"]):
            raise ValueError("backend-host evidence path/hash mismatch")
        if "bytes" in descriptor and (type(descriptor["bytes"]) is not int or descriptor["bytes"] != path.stat().st_size):
            raise ValueError("backend-host evidence byte count mismatch")
        contents[key], paths[key] = path.read_bytes(), path
    process_path = str(paths["process"])
    if not process_path.endswith(".process.json"):
        raise ValueError("backend-host process evidence requires run_logged prefix")
    prefix = process_path[:-len(".process.json")]
    if str(paths["stdout"]) != prefix + ".stdout.log" or str(paths["stderr"]) != prefix + ".stderr.log":
        raise ValueError("backend-host evidence must share one process/log prefix")
    result = _json(contents["process"])
    cleanup = result.get("cleanup", {})
    if (result.get("argv") != [backend, "-vV"] or result.get("stdout") != str(paths["stdout"]) or
            result.get("stderr") != str(paths["stderr"]) or type(result.get("returncode")) is not int or result["returncode"] != 0 or
            type(result.get("pid")) is not int or result["pid"] <= 0 or result.get("timed_out") is not False or
            result.get("cancelled") is not False or result.get("error") or result.get("post_cleanup_wait_error") or
            not isinstance(cleanup, dict) or cleanup.get("method") != "windows_job" or cleanup.get("status") != "assigned_job_empty" or
            cleanup.get("job_assigned") is not True or type(cleanup.get("active_after")) is not int or cleanup["active_after"] != 0 or
            type(cleanup.get("parent_pid")) is not int or cleanup["parent_pid"] != result["pid"] or
            cleanup.get("parent_exit_confirmed") is not True or cleanup.get("job_handle_closed") is not True or
            any(value for key, value in cleanup.items() if "error" in key)):
        raise ValueError("backend-host probe did not complete with fixed command and verified owned cleanup")
    hosts = [line for line in contents["stdout"].decode("utf-8-sig").splitlines() if line.startswith("host:")]
    if hosts != ["host: " + TARGET]:
        raise ValueError("actual backend host is missing, ambiguous or foreign")
    if file_hash(_absolute(backend)) != backend_sha256:
        raise ValueError("backend changed since host proof")
    return proof


def parse_rustc_args(argv):
    """Structural argv parsing, not Rust/Cargo semantic/profile inference.

    Unknown options and response files are explicit blockers for this first
    recorder profile. Original invocation records still preserve every byte of
    the accepted arguments; option order and repeated cfg flags are not sorted.
    """
    if not isinstance(argv, list) or not argv or any(not isinstance(x, str) or "\x00" in x for x in argv):
        raise ValueError("malformed rustc argv")
    if any(x.startswith("@") for x in argv):
        raise ValueError("response-file expansion is not pinned by this profile")
    rows, positionals, index = [], [], 0
    while index < len(argv):
        item = argv[index]
        if item in {"-vV", "-V", "--version"}:
            rows.append({"key": item, "value": None, "tokens": [item]})
            index += 1
            continue
        if item in UNIT_SWITCHES:
            rows.append({"key": item, "value": None, "tokens": [item]})
            index += 1
            continue
        key, sep, val = item.partition("=")
        if key in VALUE_OPTIONS and sep:
            if not val:
                raise ValueError("empty rustc option")
            rows.append({"key": key, "value": val, "tokens": [item]})
            index += 1
            continue
        if item in VALUE_OPTIONS:
            if index + 1 == len(argv) or not argv[index + 1]:
                raise ValueError("missing rustc option value")
            rows.append({"key": item, "value": argv[index + 1], "tokens": argv[index:index + 2]})
            index += 2
            continue
        if len(item) > 2 and item[:2] in {"-C", "-L", "-l", "-A", "-W", "-D", "-F"}:
            rows.append({"key": item[:2], "value": item[2:], "tokens": [item]})
            index += 1
            continue
        if item.startswith("-") and item != "-":
            raise ValueError("unsupported rustc option, not silently forwarded: " + item)
        positionals.append(item)
        rows.append({"key": "source", "value": item, "tokens": [item]})
        index += 1
    values = {}
    for row in rows:
        values.setdefault(row["key"], []).append(row["value"])
        if row["key"] == "-C" and row["value"].split("=", 1)[0] not in CODEGEN_OPTIONS:
            raise ValueError("unsupported rustc codegen selector: " + row["value"].split("=", 1)[0])
        if row["key"] == "-l":
            raise ValueError("explicit native library arguments need a separate pinned link contract")
    version = any(x in values for x in ("-vV", "-V", "--version"))
    prints = values.get("--print", [])
    targets = values.get("--target", [])
    if len(targets) > 1 or targets and targets != [TARGET]:
        raise ValueError("target must be exactly one fixed Windows x64 triple, never a custom JSON target")
    if version:
        if len(argv) != 1:
            raise ValueError("ambiguous rustc version probe")
        kind = "probe"
    elif prints:
        if (set(prints) - PROBE_NAMES or "--emit" in values or "--out-dir" in values or
                positionals not in ([], ["-"])):
            raise ValueError("ambiguous rustc print probe")
        kind = "probe"
    else:
        for key in ("--crate-name", "--emit", "--out-dir", "--target"):
            if len(values.get(key, [])) != 1:
                raise ValueError("crate unit requires exactly one " + key)
        if len(positionals) != 1 or positionals[0] == "-" or "--test" in values:
            raise ValueError("only explicit library source units are supported")
        kinds = [kind for value in values.get("--crate-type", []) for kind in value.split(",")]
        if not kinds or len(set(kinds)) != len(kinds) or set(kinds) - {"lib", "rlib", "cdylib", "staticlib"}:
            raise ValueError("build-script/bin/proc-macro/test unit is not allowed")
        emit = values["--emit"][0].split(",")
        if (len(set(emit)) != len(emit) or set(emit) - {"dep-info", "metadata", "link", "llvm-ir"} or
                not {"dep-info", "link"}.issubset(emit)):
            raise ValueError("explicit emit destinations/unsupported modes are not allowed in either arm")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", values["--crate-name"][0]):
            raise ValueError("unsupported crate-name/output spelling")
        for value in values.get("-C", []):
            if value.startswith("extra-filename=") and not re.fullmatch(r"extra-filename=[A-Za-z_0-9.-]*", value):
                raise ValueError("unsupported extra-filename/output spelling")
        kind = "crate"
    return {"kind": kind, "rows": rows, "values": values, "positionals": positionals}


def derive_recipe(argv, mode):
    if mode not in {"original", "derivative"}:
        raise ValueError("invalid recorder mode")
    parsed = parse_rustc_args(argv)
    if mode == "original" or parsed["kind"] == "probe":
        return {"kind": parsed["kind"], "forwarded_argv": list(argv), "changes": []}
    forwarded, changes = [], []
    for row in parsed["rows"]:
        if row["key"] == "--emit":
            emit = row["value"].split(",")
            if (not emit or len(set(emit)) != len(emit) or
                    any(x not in {"dep-info", "metadata", "link", "llvm-ir"} for x in emit)):
                raise ValueError("explicit emit paths/unknown emit modes need separate output provenance support")
            if "dep-info" not in emit or "link" not in emit:
                raise ValueError("dependency and normal Cargo link artifacts are required")
            updated = emit + ([] if "llvm-ir" in emit else ["llvm-ir"])
            replacement = ["--emit=" + ",".join(updated)]
            forwarded += replacement
            changes.append({"option": "--emit", "before": row["tokens"], "after": replacement})
        elif row["key"] == "-C" and row["value"].split("=", 1)[0] in DERIVATIVE_CODEGEN:
            changes.append({"option": "-C " + row["value"].split("=", 1)[0], "before": row["tokens"], "after": []})
        else:
            forwarded += row["tokens"]
    # Every removed occurrence is retained in changes; no opt-level/overflow/
    # panic/debug-assertion/cfg/feature/metadata/extern setting is rewritten.
    for key, value in DERIVATIVE_CODEGEN.items():
        option = "-C" + key + ("=" + value if value is not None else "")
        forwarded.append(option)
        changes.append({"option": "-C " + key, "before": [], "after": [option]})
    return {"kind": "crate", "forwarded_argv": forwarded, "changes": changes}


def validate_linker_args(parsed, policy):
    """Pure exact fixed-linker gate shared with the artifact collector."""
    if (not isinstance(parsed, dict) or parsed.get("kind") not in {"crate", "probe"}
            or not isinstance(policy, dict) or not isinstance(policy.get("linker"), str)
            or not isinstance(policy.get("linker_sha256"), str) or not HEX.fullmatch(policy["linker_sha256"])):
        raise ValueError("explicit pinned linker policy is required")
    values = [value.split("=", 1)[1] if "=" in value else "" for value in
              parsed.get("values", {}).get("-C", []) if value.split("=", 1)[0] == "linker"]
    if ((parsed["kind"] == "crate" and values != [policy["linker"]])
            or (parsed["kind"] == "probe" and values not in ([], [policy["linker"]]))):
        raise ValueError("actual rustc linker differs from the single pinned linker policy")


@dataclass(frozen=True)
class Tool:
    path: str
    sha256: str


def plan_invocations(inspection, *, wrapper: Tool, output_root: Path, environment,
                     build_environment_receipt, backend_host):
    """Pure plan renderer: NEVER creates directories or launches a process.

    The caller still must call the production Cargo inspector's verify_plan with its
    trusted plan_path immediately before each actual build, re-pin the complete
    engine/tool closure, create each root freshly and run via bounded run_logged.
    """
    if inspection.get("status") != "inspected_build_not_implemented" or inspection.get("backend") != "rust_cargo_native":
        raise ValueError("requires a successful metadata-only inspection")
    if type(wrapper) is not Tool or not HEX.fullmatch(wrapper.sha256):
        raise ValueError("actual compiled trusted wrapper identity is required")
    wrapper_path = _absolute(wrapper.path)
    if not wrapper_path.is_file() or file_hash(wrapper_path) != wrapper.sha256:
        raise ValueError("wrapper executable is missing or differs from its trusted hash")
    root = _absolute(inspection["workspace_root"])
    output = _absolute(output_root)
    if (not output.is_relative_to(root / ".runs") or output.exists() or
            output.is_relative_to(root / ".runs" / "defense-loop")):
        raise ValueError("future build output must be fresh private .runs")
    roots = [_absolute(x) for x in inspection["input_snapshot"]["roots"]]
    for source_root in roots:
        if (source_root == root or not source_root.is_relative_to(root) or
                set(part.lower() for part in source_root.parts) & FORBIDDEN_PARTS or
                source_root.is_relative_to(root / ".runs" / "defense-loop")):
            raise ValueError("unowned/broad/received source input root")
    if any(output.is_relative_to(x) or x.is_relative_to(output) for x in roots):
        raise ValueError("output roots overlap source inputs")
    cfg = inspection["selection"]
    toolchain = inspection["toolchain"]["selection"]
    if toolchain.get("target") != TARGET:
        raise ValueError("inspected toolchain target differs from fixed unit-recorder target")
    cargo, backend = toolchain["cargo"], toolchain["rustc"]
    receipt = verify_build_environment_receipt(inspection, environment, build_environment_receipt)
    normalized = {key.upper(): value for key, value in environment.items()}
    linker = normalized[LINKER_SELECTOR]
    verify_backend_host(backend_host, backend=backend, backend_sha256=inspection["toolchain"]["compiler_inputs"][backend], workspace_root=root)
    manifest = str(Path(inspection["project_path"]).parent / cfg["manifest_path"])
    argv = [cargo, "build", "--offline", "--locked", "--jobs", "1", "--message-format=json-render-diagnostics",
            "--manifest-path", manifest, "--package", cfg["package"], "--lib", "--target", TARGET, "--profile", cfg["profile"]]
    if cfg["features"]:
        argv += ["--features", ",".join(cfg["package"] + "/" + name for name in cfg["features"])]
    if not cfg["default_features"]:
        argv += ["--no-default-features"]
    allowed_sources = sorted({target["src_path"] for unit in inspection["resolution"]["closure"]
                              for target in unit["package"]["targets"] if set(target["kind"]) <= {"lib", "rlib", "cdylib", "staticlib"}})
    arms = {}
    for mode in ("original", "derivative"):
        directory = output / mode
        config = {"schema": "1", "mode": mode, "backend": backend,
                  "backend_sha256": inspection["toolchain"]["compiler_inputs"][backend],
                  "wrapper": str(wrapper_path), "wrapper_sha256": wrapper.sha256,
                  "linker": linker, "linker_sha256": receipt["sdk_input_hashes"][linker],
                  "workspace": str(root), "record_root": str(directory / "units"),
                  "target_root": str(directory / "target"), "sysroot": toolchain["sysroot"],
                  "backend_host": TARGET,
                  "stop": str(root / ".runs" / "defense-loop" / "STOP")}
        lines = [f"{key}={value}" for key, value in sorted(config.items())]
        lines += ["input_root=" + str(x) for x in roots]
        lines += ["source=" + x for x in allowed_sources]
        if any("\n" in line or "\r" in line for line in lines):
            raise ValueError("newlines in wrapper policy values are not supported")
        policy = "\n".join(lines) + "\n"
        overrides = {"RUSTC": backend, "RUSTC_WRAPPER": str(wrapper_path),
                     "CARGO_TARGET_DIR": config["target_root"], "CARGO_NET_OFFLINE": "true",
                     "ANTIREA_RUST_UNIT_POLICY": str(directory / "wrapper-policy.txt")}
        effective = {key: value for key, value in environment.items() if key.upper() not in overrides}
        effective.update(overrides)
        arms[mode] = {"argv": argv, "cwd": str(Path(manifest).parent), "shell": False, "executed": False,
                      "root": str(directory), "policy": config, "policy_text": policy,
                      "policy_sha256": hashlib.sha256(policy.encode()).hexdigest(),
                      "environment_overrides": overrides, "environment_sha256": environment_digest(effective),
                      "environment_digest_format": "uppercase-names-sorted-utf8-json-v1",
                      "recorded_sources": allowed_sources}
    return {"schema_version": 1, "status": "recipes_only_not_executed", "arms": arms,
            "inspection_fingerprint": inspection["fingerprint"], "wrapper": wrapper.__dict__, "backend_host": backend_host,
            "metadata_environment_policy_sha256": inspection["environment"]["sha256"],
            "build_environment_receipt": receipt, "cargo_jobs": 1,
            "required_prelaunch_gates": ["fresh original/derivative roots", "inspector verify_plan with trusted plan_path",
                "source/config/env/tool/engine pins", "STOP", "no unsupported hooks or external dependencies"],
            "required_postlaunch_gates": ["Cargo and every recorded backend successful with exact owned cleanup",
                "compiler-artifact JSON bound to unit identities", "consumed source/extern/sysroot dep-info closure",
                "no missing/incrementally reused local units", "original/derivative Cargo decisions compared",
                "original reference and protection-object link provenance (not implemented)"]}


def validate_diagnostic_environment(record):
    """Pure recording check; return no private values and access no filesystem."""
    env_values = record.get("environment_value_sha256") if isinstance(record, dict) else None
    if (not isinstance(env_values, dict) or any(not isinstance(key, str) or key != key.upper() or
            not isinstance(value, str) or not HEX.fullmatch(value) for key, value in env_values.items())):
        raise ValueError("unit diagnostic environment hash map malformed")
    diagnostics = record.get("diagnostic_environment")
    diagnostic_keys = {"PATH", "CARGO_MAKEFLAGS"}.intersection(env_values)
    if (not isinstance(diagnostics, dict) or set(diagnostics) != diagnostic_keys or
            any(not isinstance(value, str) or
                hashlib.sha256(value.encode("utf-8")).hexdigest() != env_values[key]
                for key, value in diagnostics.items())):
        # Do not include the private raw values in exception text or stdout.
        raise ValueError("unit diagnostic environment presence/hash mismatch")


def validate_start_record(record, arm):
    """Validate structural recipe identity; no child process or artifact loading."""
    policy = arm["policy"]
    if (not isinstance(record, dict) or type(record.get("schema_version")) is not int or
            record["schema_version"] != 1 or record.get("mode") != policy["mode"]):
        raise ValueError("unit schema/mode mismatch")
    validate_target_tree_record(record.get("target_tree_before"), policy["target_root"])
    target_now = check_target_tree(policy["target_root"])
    for kind in ("backend", "wrapper", "linker"):
        if record.get(kind) != {"path": policy[kind], "sha256": policy[kind + "_sha256"]}:
            raise ValueError("unit actual tool identity mismatch")
    if record.get("policy_sha256") != arm["policy_sha256"]:
        raise ValueError("unit policy differs from planned arm")
    if not isinstance(record.get("environment_sha256"), str) or not HEX.fullmatch(record["environment_sha256"]):
        raise ValueError("actual per-unit environment fingerprint required")
    if record.get("environment_digest_format") != "uppercase-names-sorted-utf8-json-v1":
        raise ValueError("unknown per-unit environment digest encoding")
    env_values = record.get("environment_value_sha256")
    controls = record.get("control_environment")
    expected_controls = {key: arm["environment_overrides"][key] for key in
                         ("CARGO_TARGET_DIR", "ANTIREA_RUST_UNIT_POLICY", "RUSTC", "RUSTC_WRAPPER")}
    if (not isinstance(env_values, dict) or any(not isinstance(k, str) or k != k.upper() or
            not isinstance(v, str) or not HEX.fullmatch(v) for k, v in env_values.items()) or
            controls != expected_controls or any(env_values.get(k) != hashlib.sha256(v.encode()).hexdigest() for k, v in controls.items())):
        raise ValueError("unit environment/control identity mismatch")
    validate_diagnostic_environment(record)
    # Cargo legitimately adds per-crate environment variables. Do not falsely
    # compare the unit digest with the pre-Cargo parent environment digest.
    args = record.get("original_argv")
    if not isinstance(args, list) or not args or args[0] != policy["backend"]:
        raise ValueError("unexpected actual compiler command")
    derived = derive_recipe(args[1:], policy["mode"])
    if record.get("forwarded_argv") != [policy["backend"], *derived["forwarded_argv"]] or record.get("changes") != derived["changes"]:
        raise ValueError("unit altered unsupported original semantics or omitted derivative changes")
    if record.get("kind") != derived["kind"]:
        raise ValueError("probe/compile classification mismatch")
    validate_linker_args(parse_rustc_args(args[1:]), policy)
    cwd = _absolute(record.get("cwd", ""))
    if derived["kind"] == "crate":
        parsed = parse_rustc_args(args[1:])
        source = Path(parsed["positionals"][0])
        source = source if source.is_absolute() else cwd / source
        if str(source.resolve()) not in {str(Path(x).resolve()) for x in arm["recorded_sources"]}:
            raise ValueError("crate source not selected by metadata closure")
        out_dir = _absolute(parsed["values"]["--out-dir"][0])
        if not out_dir.is_relative_to(_absolute(policy["target_root"])):
            raise ValueError("crate output is outside its own arm")
        for value in parsed["values"].get("--sysroot", []):
            if _absolute(value).resolve() != _absolute(policy.get("sysroot", "")).resolve():
                raise ValueError("explicit sysroot differs from pinned compiler inputs")
        for value in parsed["values"].get("-C", []):
            if value.startswith("incremental=") and not _absolute(value.split("=", 1)[1]).is_relative_to(_absolute(policy["target_root"])):
                raise ValueError("incremental output is outside its own arm")
        for value in parsed["values"].get("-L", []):
            label, separator, path = value.partition("=")
            if label != "dependency" or not separator or not _absolute(path).is_relative_to(_absolute(policy["target_root"])):
                raise ValueError("only own-arm dependency library searches are supported")
        identity = record.get("cargo_identity", {})
        if not isinstance(identity, dict) or not isinstance(identity.get("CARGO_MANIFEST_DIR"), str):
            raise ValueError("missing Cargo package identity")
        manifest_dir = _absolute(identity["CARGO_MANIFEST_DIR"]).resolve()
        if not source.resolve().is_relative_to(manifest_dir):
            raise ValueError("crate source/Cargo package identity not connected")
        consumed = record.get("consumed_inputs")
        if not isinstance(consumed, dict) or consumed.get(str(source)) != file_hash(_absolute(source)):
            raise ValueError("crate source hash not connected to observed argv")
        for extern in parsed["values"].get("--extern", []):
            _, separator, value = extern.partition("=")
            if not separator:
                raise ValueError("implicit extern search is unsupported")
            path = _absolute(value, allow_owned_hardlinks=True)
            if (not path.is_relative_to(_absolute(policy["target_root"])) or path.suffix not in {".rlib", ".rmeta"} or
                    str(path) not in {row["path"] for row in target_now["files"]} or
                    consumed.get(str(path)) != file_hash(path)):
                raise ValueError("extern input is not a hash-bound local Cargo artifact")
    return derived


def _host_profile_deps(arm):
    """Derive the one observed host PATH entry from the actual Cargo recipe."""
    argv = arm.get("argv")
    if (not isinstance(argv, list) or any(not isinstance(value, str) for value in argv) or
            argv.count("--profile") != 1 or any(value.startswith("--profile=") for value in argv)):
        raise ValueError("unit environments differ: one explicit Cargo profile is required")
    index = argv.index("--profile") + 1
    profile = argv[index] if index < len(argv) else None
    if (not isinstance(profile, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", profile) or
            ".." in profile):
        raise ValueError("unit environments differ: unsafe Cargo profile segment")
    folder = "debug" if profile == "dev" else profile
    return profile, str(Path(arm["policy"]["target_root"]) / folder / "deps")


def _recognized_environment_rules(original, derivative, original_arm, derivative_arm):
    """Recognize only two observed process-control changes; return digests only."""
    rules = []
    for key in ("PATH", "CARGO_MAKEFLAGS"):
        a_hash, b_hash = (record["environment_value_sha256"].get(key) for record in (original, derivative))
        if a_hash == b_hash:
            continue
        if key not in original["diagnostic_environment"] or key not in derivative["diagnostic_environment"]:
            raise ValueError("unit environments differ: diagnostic counterpart is absent")
        a, b = (record["diagnostic_environment"][key] for record in (original, derivative))
        if key == "PATH":
            a_profile, a_owned = _host_profile_deps(original_arm)
            b_profile, b_owned = _host_profile_deps(derivative_arm)
            a_entries, b_entries = a.split(";"), b.split(";")
            if (a_profile != b_profile or a_entries.count(a_owned) != 1 or b_entries.count(b_owned) != 1 or
                    len(a_entries) != len(b_entries) or a_entries.index(a_owned) != b_entries.index(b_owned)):
                raise ValueError("unit environments differ: owned host profile PATH entry mismatch")
            index = a_entries.index(a_owned)
            if a_entries[:index] != b_entries[:index] or a_entries[index + 1:] != b_entries[index + 1:]:
                raise ValueError("unit environments differ: unexplained PATH entry/order/spelling change")
            normalized = [*a_entries[:index], {"own_host_profile_deps": True}, *a_entries[index + 1:]]
            rule = "exact_owned_host_profile_deps_v1"
        else:
            pattern = r"-j --jobserver-fds=(__rust_jobserver_semaphore_[0-9]+) --jobserver-auth=\1"
            if re.fullmatch(pattern, a) is None or re.fullmatch(pattern, b) is None:
                raise ValueError("unit environments differ: unrecognized Cargo jobserver controls")
            normalized = {"flags": "-j", "fds_and_auth": "same_windows_rust_jobserver_semaphore"}
            rule = "exact_windows_rust_jobserver_semaphore_v1"
        rules.append({"variable": key, "rule": rule, "original_value_sha256": a_hash,
                      "derivative_value_sha256": b_hash, "normalized_sha256": digest(normalized)})
    return rules


def compare_cargo_decisions(original, derivative, original_arm, derivative_arm):
    """Compare captured Cargo recipes, not post-transform compiler recipes.

    Arguments normalize only own output-root operands. Environment comparison
    recognizes exact planned arm controls and two observed Cargo process-control
    forms; no environment or functional equivalence is inferred from this.
    """
    validate_start_record(original, original_arm)
    validate_start_record(derivative, derivative_arm)
    if original["kind"] != "crate" or derivative["kind"] != "crate":
        raise ValueError("crate comparison does not score probes")
    def normalized(record, arm):
        old = arm["policy"]["target_root"]
        def owned_path(value):
            if value == old:
                return "<OWN_TARGET_ROOT>"
            if value.startswith(old + "\\") or value.startswith(old + "/"):
                return "<OWN_TARGET_ROOT>" + value[len(old):]
            return value
        tokens = []
        for row in parse_rustc_args(record["original_argv"][1:])["rows"]:
            value = row["value"]
            if row["key"] == "--out-dir":
                value = owned_path(value)
            elif row["key"] in {"--extern", "-L"} and "=" in value:
                label, path = value.split("=", 1)
                value = label + "=" + owned_path(path)
            elif row["key"] == "-C" and value.startswith("incremental="):
                value = "incremental=" + owned_path(value[len("incremental="):])
            # cfg literals, metadata, debuginfo, symbols, source operands and
            # all other values are NOT arbitrary substring-normalized.
            changed_tokens = list(row["tokens"])
            if value != row["value"]:
                if len(changed_tokens) == 2:
                    changed_tokens[1] = value
                else:
                    original_value = row["value"]
                    if not isinstance(original_value, str) or not changed_tokens[0].endswith(original_value):
                        raise ValueError("normalization token/value binding mismatch")
                    changed_tokens[0] = changed_tokens[0][:-len(original_value)] + value
            tokens.extend(changed_tokens)
        return [record["original_argv"][0], *tokens]
    if normalized(original, original_arm) != normalized(derivative, derivative_arm):
        raise ValueError("Cargo original/derivative decisions differ beyond their own output roots")
    if original["cargo_identity"] != derivative["cargo_identity"] or original["cwd"] != derivative["cwd"]:
        raise ValueError("Cargo crate identity/cwd differs")
    original_env, derivative_env = [dict(x["environment_value_sha256"]) for x in (original, derivative)]
    for key in ("CARGO_TARGET_DIR", "ANTIREA_RUST_UNIT_POLICY"):
        original_env[key] = derivative_env[key] = "<explicit arm control path>"
    rules = _recognized_environment_rules(original, derivative, original_arm, derivative_arm)
    for rule in rules:
        original_env[rule["variable"]] = derivative_env[rule["variable"]] = rule["normalized_sha256"]
    if original_env != derivative_env:
        raise ValueError("unit environments differ beyond explicit arm controls and recognized Cargo process controls")
    return {"status": "captured_cargo_argv_matched", "original_environment_sha256": original["environment_sha256"],
            "derivative_environment_sha256": derivative["environment_sha256"],
            "recognized_environment_rules": rules,
            "environment_equivalence": "not_claimed: raw process controls differ; source env!/option_env! behavior still needs original comparison",
            "functional_equivalence": "not_evaluated"}


def inspect_unit_records(directory, arm):
    """Check finished invocation records only; NOT complete Cargo-unit coverage.

    Future collector must additionally bind Cargo compiler-artifact JSON, source
    dep-info, every local crate/extern edge, outputs and outer process cleanup.
    """
    directory = _absolute(directory)
    if directory != Path(arm["policy"]["record_root"]):
        raise ValueError("unit record root differs from its trusted arm")
    rows = []
    for unit in sorted(directory.iterdir()):
        if not unit.is_dir() or unit.is_symlink() or not re.fullmatch(r"[1-9][0-9]*-[0-9]+", unit.name):
            raise ValueError("unexpected unit record entry")
        if {path.name for path in unit.iterdir()} != {"start.json", "finish.json"}:
            raise ValueError("incomplete/crashed unit record; never count as a compiled unit")
        start_path, finish_path = unit / "start.json", unit / "finish.json"
        for path in (start_path, finish_path):
            if path.is_symlink() or path.stat().st_size > 4 * 1024 * 1024:
                raise ValueError("invalid unit record path/size")
        start, finish = _json(_absolute(start_path).read_bytes()), _json(_absolute(finish_path).read_bytes())
        validate_start_record(start, arm)
        validate_target_tree_record(finish.get("target_tree_after"), arm["policy"]["target_root"])
        if (type(finish.get("schema_version")) is not int or finish["schema_version"] != 1 or
                type(finish.get("compiler_pid")) is not int or finish["compiler_pid"] <= 0 or
                type(finish.get("compiler_exit_code")) is not int or finish["compiler_exit_code"] != 0 or
                finish.get("cancelled") is not False or finish.get("succeeded") is not True or
                finish.get("changed_inputs") != [] or finish.get("start_sha256") != file_hash(start_path)):
            raise ValueError("unit did not complete with unchanged input/tool evidence")
        consumed = start.get("consumed_inputs")
        if not isinstance(consumed, dict) or any(not isinstance(x, str) or not isinstance(h, str) or not HEX.fullmatch(h) for x, h in consumed.items()):
            raise ValueError("missing unit source/extern consumed-input hashes")
        for value, expected in consumed.items():
            path = _absolute(value, allow_owned_hardlinks=Path(value).is_relative_to(Path(arm["policy"]["target_root"])))
            if not path.is_file() or file_hash(path) != expected:
                raise ValueError("recorded unit input changed")
        rows.append({"unit": unit.name, "kind": start["kind"], "start": {"path": str(start_path), "sha256": file_hash(start_path)},
                     "finish": {"path": str(finish_path), "sha256": file_hash(finish_path)}})
    if not rows:
        raise ValueError("no wrapper records; Cargo cache/no-op is not unit coverage")
    return {"status": "invocation_records_checked_not_build_validated", "units": rows,
            "complete_crate_graph": False, "dep_info_closure_verified": False, "outer_job_cleanup_verified": False,
            "original_reference_linked": False, "protected_artifact_created": False}

