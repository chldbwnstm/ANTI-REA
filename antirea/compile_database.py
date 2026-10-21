"""Read-only, closed-option compilation database normalizer.

No command, compiler, configure step, or build hook is executed here. This is
not a linker/whole-project adapter. Normalization does not establish compiler
or application compatibility. A dependency scan must establish that the
compiler consumed only the approved snapshot before any build is accepted.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import stat

TARGET = "x86_64-pc-windows-msvc"
MAX_DATABASE_BYTES = 4 * 1024 * 1024
MAX_ENTRIES = 4096
MAX_FILES = 4096
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_TRUSTED_HEADER_FILES = 200000
MAX_TRUSTED_HEADER_BYTES = 2 * 1024 * 1024 * 1024
DEPENDENCY_TARGET = "ANTIREA_COMPDB_DEPENDENCIES"
DRIVERS = {"clang": {"clang", "clang.exe"}, "clangxx": {"clang++", "clang++.exe"},
           "clangcl": {"clang-cl", "clang-cl.exe"}}
STANDARDS = {"c89", "c90", "c99", "c11", "c17", "c18", "c2x", "c23",
             "gnu89", "gnu90", "gnu99", "gnu11", "gnu17", "gnu18", "gnu2x", "gnu23",
             "c++98", "c++03", "c++11", "c++14", "c++17", "c++20", "c++23", "c++26", "c++2b", "c++2c",
             "gnu++98", "gnu++03", "gnu++11", "gnu++14", "gnu++17", "gnu++20", "gnu++23", "gnu++26"}
GNU_FLAGS = {"-fexceptions", "-fno-exceptions", "-fcxx-exceptions", "-fno-cxx-exceptions",
             "-frtti", "-fno-rtti", "-fsigned-char", "-funsigned-char", "-fshort-wchar", "-fno-short-wchar",
             "-fshort-enums", "-fno-short-enums", "-fwrapv", "-fno-wrapv", "-fstrict-aliasing", "-fno-strict-aliasing",
             "-fms-extensions", "-fno-ms-extensions", "-fms-compatibility", "-fno-ms-compatibility",
             "-fno-inline", "-finline-functions", "-fno-inline-functions", "-fPIC", "-fpic", "-fno-PIC", "-fno-pic",
             "-m64", "-g", "-g0", "-gline-tables-only", "-gcodeview", "-fcolor-diagnostics", "-fno-color-diagnostics"}
CL_FLAGS = {"/EHsc", "/EHs", "/EHa", "/EHs-c-", "/EHsc-", "/GR", "/GR-", "/MD", "/MDd", "/MT", "/MTd",
            "/utf-8", "/source-charset:utf-8", "/execution-charset:utf-8", "/permissive-", "/Zc:__cplusplus",
            "/Zc:wchar_t", "/Zc:wchar_t-", "/Zc:threadSafeInit", "/Zc:threadSafeInit-", "/Zc:forScope", "/Zc:forScope-",
            "/J", "/Zi", "/Z7", "/Od", "/O1", "/O2", "/Ox", "/Os", "/Ot", "/Oi", "/Oi-", "/Oy", "/Oy-"}


class CompilationDatabaseError(ValueError):
    pass


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _text(value, label):
    if not isinstance(value, str) or not value or len(value) > 32768 or any(ord(c) < 32 for c in value):
        raise CompilationDatabaseError(f"Invalid {label}")
    return value


def _path(value, base, *, exists=True, directory=False, tool=False):
    if not isinstance(value, (str, Path)):
        raise CompilationDatabaseError("Path must be a string or Path")
    _text(str(value), "path")
    raw = str(value)
    if raw.startswith(("\\\\", "//")) or PureWindowsPath(raw).drive and not PureWindowsPath(raw).is_absolute():
        raise CompilationDatabaseError("Network/device/drive-relative paths are unsupported")
    path = Path(os.path.abspath(base / Path(str(value).replace("\\", "/"))))
    if ":" in str(path)[len(path.drive):]:
        raise CompilationDatabaseError("Alternate stream/device path is unsupported")
    for item in (path, *path.parents):
        if item.exists() or item.is_symlink():
            info = item.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise CompilationDatabaseError(f"Link/reparse path is unsupported: {item}")
    if exists and not (path.is_dir() if directory else path.is_file()):
        raise CompilationDatabaseError(f"Missing input: {path}")
    if path.is_file() and (not stat.S_ISREG(path.stat().st_mode) or (not tool and path.stat().st_nlink != 1)):
        raise CompilationDatabaseError("Inputs must be ordinary non-hardlinked files")
    return path


def _inside(path, roots):
    return any(path.is_relative_to(root) for root in roots)


def _owned(path, workspace):
    if not path.is_relative_to(workspace) or any(p.casefold() in {"rea-analysis-reports", "attackerfolder"} for p in path.parts):
        raise CompilationDatabaseError("Input must stay in the owned workspace")
    relative = [p.casefold() for p in path.relative_to(workspace).parts]
    if relative[:2] == [".runs", "defense-loop"]:
        raise CompilationDatabaseError("Defense-loop inbox/state is not a source input")
    return path


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CompilationDatabaseError("Duplicate JSON field: " + key)
        result[key] = value
    return result


def _json_constant(value):
    raise CompilationDatabaseError("Non-finite JSON constant: " + value)


def split_windows_command(command):
    """Parse a command line using Windows CRT quote/backslash rules, not a shell.

    Shell wrappers/operators are never executed; wrapper executables and unknown
    resulting arguments are rejected later. Unbalanced quotes fail closed.
    """
    if not isinstance(command, str) or not command or len(command) > 131072 or any(ord(c) < 32 and c != "\t" for c in command):
        raise CompilationDatabaseError("Invalid Windows command string")
    args, i, length = [], 0, len(command)
    while i < length:
        while i < length and command[i] in " \t":
            i += 1
        if i == length:
            break
        chars, quoted = [], False
        while i < length and (quoted or command[i] not in " \t"):
            count = 0
            while i < length and command[i] == "\\":
                count += 1
                i += 1
            if i < length and command[i] == '"':
                chars.extend("\\" * (count // 2))
                if count % 2:
                    chars.append('"')
                    i += 1
                elif quoted and i + 1 < length and command[i + 1] == '"':
                    chars.append('"')
                    i += 2
                else:
                    quoted = not quoted
                    i += 1
            else:
                chars.extend("\\" * count)
                if i < length and (quoted or command[i] not in " \t"):
                    chars.append(command[i])
                    i += 1
        if quoted:
            raise CompilationDatabaseError("Unbalanced Windows command quotes")
        args.append("".join(chars))
    return args


def _argv(entry):
    if not isinstance(entry, dict) or set(entry) - {"directory", "file", "output", "arguments", "command"}:
        raise CompilationDatabaseError("Unknown/malformed compilation database entry")
    args = entry.get("arguments")
    if "arguments" in entry:
        if not isinstance(args, list) or not args or len(args) > 4096:
            raise CompilationDatabaseError("arguments must be a bounded nonempty array")
        for value in args:
            _text(value, "argument")
    command = split_windows_command(entry["command"]) if "command" in entry else None
    if args is not None and command is not None and args != command:
        raise CompilationDatabaseError("arguments and command disagree")
    args = args if args is not None else command
    if not args or len(args) > 4096:
        raise CompilationDatabaseError("No bounded compiler arguments")
    if any(arg.startswith("@") for arg in args):
        raise CompilationDatabaseError("Response files are not supported or expanded")
    return args


def _tool_registry(toolchain):
    if not isinstance(toolchain, dict) or not toolchain or set(toolchain) - set(DRIVERS):
        raise CompilationDatabaseError("Only explicit pinned Clang drivers are supported")
    result = {}
    for key, record in toolchain.items():
        if (not isinstance(record, dict) or set(record) != {"path", "sha256"}
                or not isinstance(record["path"], str) or not Path(record["path"]).is_absolute()
                or not isinstance(record["sha256"], str)):
            raise CompilationDatabaseError("Driver requires absolute path and SHA-256")
        path = _path(record["path"], Path.cwd(), tool=True)
        if path.name.casefold() not in DRIVERS[key] or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"]):
            raise CompilationDatabaseError("Driver filename/hash does not match its profile")
        if path.stat().st_size > 512 * 1024 * 1024 or _sha(path.read_bytes()) != record["sha256"]:
            raise CompilationDatabaseError("Pinned driver changed")
        result[key] = {"path": str(path), "sha256": record["sha256"]}
    return result


def _select_driver(token, directory, tools):
    name = token.replace("\\", "/").rsplit("/", 1)[-1].casefold()
    choices = [key for key, names in DRIVERS.items() if name in names and key in tools]
    if len(choices) != 1:
        raise CompilationDatabaseError("Compiler wrapper/non-pinned compiler is unsupported")
    key = choices[0]
    if "/" in token or "\\" in token or Path(token).is_absolute():
        if _path(token, directory, tool=True) != Path(tools[key]["path"]):
            raise CompilationDatabaseError("Compilation command names a different compiler")
    return key


def _normal_unit(entry, workspace, roots, tools, trusted_roots=()):
    args = _argv(entry)
    directory = _owned(_path(entry.get("directory"), workspace, directory=True), workspace)
    source = _owned(_path(entry.get("file"), directory), workspace)
    if not _inside(source, roots) or source.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
        raise CompilationDatabaseError("Source is outside approved roots or has unsupported language")
    driver = _select_driver(args[0], directory, tools)
    cl = driver == "clangcl"
    language = "cpp" if driver == "clangxx" or source.suffix.lower() != ".c" else "c"
    retained, options, dropped = [], [], []
    output = None
    source_seen = False
    source_operand = None
    compile_only = False
    i = 1

    def value_for(flag):
        nonlocal i
        if i + 1 >= len(args):
            raise CompilationDatabaseError("Missing value for " + flag)
        i += 1
        return _text(args[i], "option value")

    def keep(kind, values, value=None):
        if source_seen:
            raise CompilationDatabaseError("Semantic option after source needs explicit positional handling")
        retained.extend(values)
        options.append({"kind": kind, "argv": values, "value": value})

    def include(flag, value, *, forced=False):
        path = _path(value, directory, directory=not forced)
        if _inside(path, roots):
            _owned(path, workspace)
        elif not _inside(path, trusted_roots):
            raise CompilationDatabaseError("Include input is outside approved/pinned roots")
        # Canonical paths establish ownership/hash identity only. Rewriting
        # compiler operands can change __FILE__/__BASE_FILE__ string semantics.
        keep("forced_include" if forced else "include", [flag, value], str(path))
        options[-1]["lexical_value"] = value

    while i < len(args):
        arg = args[i]
        # Match the actual source before interpreting leading '/' as a CL flag.
        candidate = _path(arg, directory, exists=False) if not arg.startswith(("-", "/")) or Path(arg).is_absolute() else None
        if candidate == source:
            if source_seen:
                raise CompilationDatabaseError("Duplicate source operand")
            source_seen = True
            source_operand = arg
            i += 1
            continue
        if arg == "--":
            if source_seen or i + 2 != len(args) or _path(args[i + 1], directory) != source:
                raise CompilationDatabaseError("Only the selected source may follow --")
            source_seen = True
            source_operand = args[i + 1]
            i += 2
            continue
        if arg in ("-c", "/c"):
            compile_only = True
            dropped.append({"argv": [arg], "reason": "replaced_by_explicit_LLVM_emission"})
        elif arg == "-o" or (cl and arg.startswith(("/Fo", "-Fo"))):
            value = value_for(arg) if arg == "-o" or len(arg) == 3 else arg[3:]
            current = _owned(_path(value, directory, exists=False), workspace)
            if output is not None and output != current:
                raise CompilationDatabaseError("Conflicting object outputs")
            output = current
            dropped.append({"argv": [arg, value] if arg == "-o" else [arg], "reason": "original_output_never_written"})
        elif not cl and arg in {"-MD", "-MMD", "-MP"}:
            dropped.append({"argv": [arg], "reason": "dependency_output_replaced_by_separate_build_gate"})
        elif not cl and arg in {"-MF", "-MT", "-MQ"}:
            dropped.append({"argv": [arg, value_for(arg)], "reason": "dependency_output_never_written"})
        elif cl and (arg.startswith(("/Fd", "-Fd")) or arg in {"/FS", "-FS", "/nologo", "-nologo", "/showIncludes", "-showIncludes"}):
            if arg in {"/Fd", "-Fd"}:
                value_for(arg)
            dropped.append({"argv": [arg], "reason": "diagnostic_or_debug_database_output"})
        elif arg in {"-target", "--target"} or arg.startswith("--target="):
            value = arg.split("=", 1)[1] if "=" in arg else value_for(arg)
            if value != TARGET:
                raise CompilationDatabaseError("Unsupported target")
            keep("target", ["--target=" + value], value)
        elif arg == "-x" or (cl and arg in {"/TC", "-TC", "/TP", "-TP"}):
            value = value_for(arg) if arg == "-x" else ("c" if arg.endswith("TC") else "c++")
            if value not in {"c", "c++"}:
                raise CompilationDatabaseError("Unsupported language override")
            language = "c" if value == "c" else "cpp"
            keep("language", ["/TC" if value == "c" else "/TP"] if cl else ["-x", value], value)
        elif arg.startswith("-std=") or cl and arg.startswith(("/std:", "-std:")):
            value = arg.split("=" if arg.startswith("-std=") else ":", 1)[1]
            if value not in STANDARDS:
                raise CompilationDatabaseError("Unsupported language standard")
            keep("standard", [("/std:" if cl else "-std=") + value], value)
        elif arg.startswith(("-D", "-U")) or cl and arg.startswith(("/D", "/U")):
            kind = arg[1]
            value = arg[2:] or value_for(arg)
            pattern = r"[A-Za-z_][A-Za-z0-9_]*(?:[=(].*)?" if kind == "D" else r"[A-Za-z_][A-Za-z0-9_]*"
            if not re.fullmatch(pattern, value):
                raise CompilationDatabaseError("Malformed macro definition/undefinition")
            keep("define" if kind == "D" else "undefine", [("/" if cl else "-") + kind, value], value)
        elif arg.startswith("-I") or cl and arg.startswith("/I"):
            include("/I" if cl else "-I", arg[2:] or value_for(arg))
        elif arg in {"-isystem", "-iquote", "-idirafter", "-include", "-imacros"}:
            if cl:
                raise CompilationDatabaseError("GNU include option requires GNU driver")
            include(arg, value_for(arg), forced=arg in {"-include", "-imacros"})
        elif cl and arg.startswith(("/FI", "-FI", "/imsvc", "-imsvc", "/external:I", "-external:I")):
            flag = next(flag for flag in ("/external:I", "-external:I", "/imsvc", "-imsvc", "/FI", "-FI") if arg.startswith(flag))
            include("/" + flag[1:], arg[len(flag):] or value_for(arg), forced=flag.endswith("FI"))
        elif not cl and (arg in GNU_FLAGS or re.fullmatch(r"-O[0123sgz]", arg) or re.fullmatch(r"-W(?:no-)?[A-Za-z0-9_-]+(?:=[A-Za-z0-9_-]+)?", arg)):
            keep("preserved_flag", [arg], arg)
        elif cl and (("/" + arg[1:]) in CL_FLAGS or re.fullmatch(r"[/\-](?:Ob[0123]|W[0-4]|WX-?|wd[0-9]+)", arg)):
            keep("preserved_flag", ["/" + arg[1:]], "/" + arg[1:])
        else:
            raise CompilationDatabaseError("Unsupported compiler option/operand (not ignored): " + arg)
        i += 1
    if not compile_only or not source_seen:
        raise CompilationDatabaseError("Exactly one selected source and a compile-only action are required")
    declared_output = _owned(_path(entry["output"], directory, exists=False), workspace) if "output" in entry else None
    if declared_output is not None and output is not None and declared_output != output:
        raise CompilationDatabaseError("Entry output disagrees with compiler output")
    return {"entry_sha256": _sha(_encoded(entry)), "source": str(source), "source_operand": source_operand, "directory": str(directory),
            "driver": driver, "compiler": tools[driver], "language": language, "ordered_options": options,
            "frontend_argv": retained, "dropped_options": dropped,
            "original_output": str(declared_output or output) if declared_output or output else None,
            "original_argv": args, "target": TARGET}


def _inventory(roots, extra_files=(), *, max_files=None, max_bytes=None):
    max_files = MAX_FILES if max_files is None else max_files
    max_bytes = MAX_INPUT_BYTES if max_bytes is None else max_bytes
    files, directories, total = set(), set(), 0
    for root in roots:
        _path(root, Path.cwd(), directory=True)
        for directory, dirs, names in os.walk(root, followlinks=False):
            for name in dirs:
                directories.add(str(_path(Path(directory) / name, Path.cwd(), directory=True)))
            for name in names:
                files.add(_path(Path(directory) / name, Path.cwd()))
            if len(files) + len(directories) > max_files:
                raise CompilationDatabaseError("Input snapshot exceeds bounded file/directory count")
    files.update(extra_files)
    records = []
    for path in sorted(files):
        path = _path(path, Path.cwd())
        size = path.stat().st_size
        total += size
        if total > max_bytes:
            raise CompilationDatabaseError("Input snapshot exceeds byte budget")
        records.append({"path": str(path), "bytes": size, "sha256": _sha(path.read_bytes())})
    return {"files": records, "directories": sorted(directories), "bytes": total}


def _trusted_header_inventory(roots):
    summaries, files = [], {}
    for root in roots:
        inventory = _inventory([root], max_files=MAX_TRUSTED_HEADER_FILES, max_bytes=MAX_TRUSTED_HEADER_BYTES)
        summaries.append({"path": str(root), "sha256": _sha(_encoded(inventory)),
                          "files": len(inventory["files"]), "bytes": inventory["bytes"]})
        for record in inventory["files"]:
            files[record["path"]] = record
    return {"roots": summaries, "files": [files[path] for path in sorted(files)]}


def normalize_database(database, *, workspace_root, project_root, toolchain, selections,
                       extra_input_roots=(), scope_policy=None, trusted_header_roots=()):
    """Inspect selected entries without executing anything or writing files.

    selections=[{"file": relative_to_project, "entry_sha256": optional_digest}].
    Repeated configurations need an exact entry digest, never first-entry wins.
    User include roots must be explicitly owned and snapshotted. The trusted
    builder, NOT a project manifest, may supply absolute SDK/resource roots after
    deriving/pinning compiler installation metadata. Their complete inventories
    are hashed compactly, not silently treated as system/header exceptions.
    """
    workspace = _path(workspace_root, Path.cwd(), directory=True)
    project = _owned(_path(project_root, workspace, directory=True), workspace)
    if project == workspace:
        raise CompilationDatabaseError("Use a dedicated project input root")
    if not isinstance(extra_input_roots, (tuple, list)):
        raise CompilationDatabaseError("extra_input_roots must be an explicit sequence")
    roots = [project]
    for value in extra_input_roots:
        root = _owned(_path(value, workspace, directory=True), workspace)
        if root == workspace:
            raise CompilationDatabaseError("Workspace root is not a bounded include root")
        if root not in roots:
            roots.append(root)
    if not isinstance(trusted_header_roots, (tuple, list)):
        raise CompilationDatabaseError("trusted_header_roots must be a trusted explicit sequence")
    trusted_roots = []
    for value in trusted_header_roots:
        if not isinstance(value, (str, Path)) or not Path(value).is_absolute():
            raise CompilationDatabaseError("Trusted header roots must be absolute")
        root = _path(value, Path.cwd(), directory=True)
        if root not in trusted_roots:
            trusted_roots.append(root)
    trusted_inventory = _trusted_header_inventory(trusted_roots)
    database = _owned(_path(database, workspace), workspace)
    if database.stat().st_size > MAX_DATABASE_BYTES:
        raise CompilationDatabaseError("Compilation database exceeds input bound")
    raw = database.read_bytes()
    try:
        entries = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_pairs, parse_constant=_json_constant)
    except (ValueError, UnicodeError) as exc:
        raise CompilationDatabaseError("Invalid compilation database JSON") from exc
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_ENTRIES:
        raise CompilationDatabaseError("Compilation database must be a bounded nonempty array")
    if not isinstance(selections, list) or not 1 <= len(selections) <= 64:
        raise CompilationDatabaseError("Explicit selection of 1..64 translation units is required")
    tools = _tool_registry(toolchain)
    units, selected_sources = [], set()
    for selection in selections:
        if not isinstance(selection, dict) or set(selection) - {"file", "entry_sha256"}:
            raise CompilationDatabaseError("Invalid explicit translation unit selection")
        source = _owned(_path(selection.get("file"), project), workspace)
        if source in selected_sources:
            raise CompilationDatabaseError("Duplicate selected source")
        selected_sources.add(source)
        matching = []
        for entry in entries:
            if not isinstance(entry, dict) or "directory" not in entry or "file" not in entry:
                raise CompilationDatabaseError("Malformed database entry")
            directory = _path(entry["directory"], database.parent, directory=True)
            entry_source = _path(entry["file"], directory, exists=False)
            if entry_source == source:
                matching.append(entry)
        if "entry_sha256" in selection:
            expected = selection["entry_sha256"]
            if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise CompilationDatabaseError("Invalid entry selector hash")
            matching = [entry for entry in matching if _sha(_encoded(entry)) == expected]
        if len(matching) != 1:
            raise CompilationDatabaseError("Missing/ambiguous compilation configuration; select an exact entry hash")
        # Directory semantics in the DB are relative to its location, not the
        # newly generated build directory. Retain normalized cwd explicitly.
        entry = dict(matching[0])
        original_digest = _sha(_encoded(entry))
        entry["directory"] = str(_path(entry["directory"], database.parent, directory=True))
        unit = _normal_unit(entry, workspace, roots, tools, trusted_roots)
        unit["entry_sha256"] = original_digest
        units.append(unit)
    scope = _owned(_path(scope_policy, project), workspace) if scope_policy is not None else None
    if scope is not None and not _inside(scope, roots):
        raise CompilationDatabaseError("Scope policy must be inside the approved input roots")
    inputs = _inventory(roots, [database] + ([scope] if scope else []))
    plan = {"schema_version": 1, "status": "normalized_not_built",
            "workspace_root": str(workspace), "project_root": str(project), "database": str(database),
            "database_sha256": _sha(raw), "input_roots": list(map(str, roots)), "inputs": inputs,
            "trusted_headers": {"roots": trusted_inventory["roots"]},
            "tools": tools, "scope_policy": str(scope) if scope else None,
            "adapter": {"path": str(Path(__file__).resolve()), "sha256": _sha(Path(__file__).read_bytes())},
            "translation_units": units, "commands_executed": False, "application_linked": False,
            "build_gates": ["pin_compiler_environment_resource_and_SDK_inputs", "verify_actual_dependency_closure",
                            "validate_pinned_driver_IR_emission_and_preprocessor_parity", "establish_explicit_link_contract",
                            "apply_preoptimization_scope_and_per_selected_function_VM_gates", "validate_original_and_protected_behavior"],
            "limitations": ["No CMake/configure/Cargo/build hooks or original commands are executed.",
                            "Compilation databases do not contain a complete target/link/dependency contract.",
                            "This normalizer does not prove preprocessing, ABI, function coverage or whole-application equivalence.",
                            "Ambient compiler headers/environment must be pinned and checked by the future build adapter."]}
    plan["fingerprint"] = _sha(_encoded(plan))
    verify_snapshot(plan)
    return plan


def _verify_plan_fingerprint(plan):
    if not isinstance(plan, dict):
        raise CompilationDatabaseError("Normalized plan must be an object")
    expected = plan.get("fingerprint")
    current = {key: value for key, value in plan.items() if key != "fingerprint"}
    if expected != _sha(_encoded(current)):
        raise CompilationDatabaseError("Normalized plan fingerprint changed")


def verify_snapshot(plan, *, return_trusted_inventory=False):
    """Full current-input inventory check; call at plan/build trust boundaries."""
    _verify_plan_fingerprint(plan)
    if _sha(Path(plan["database"]).read_bytes()) != plan["database_sha256"]:
        raise CompilationDatabaseError("Database/source/header/scope snapshot changed: database content")
    extra = [Path(plan["database"])] + ([Path(plan["scope_policy"])] if plan["scope_policy"] else [])
    if _inventory([Path(value) for value in plan["input_roots"]], extra) != plan["inputs"]:
        raise CompilationDatabaseError("Database/source/header/scope snapshot changed")
    _tool_registry(plan["tools"])
    trusted = trusted_header_inventory(plan)
    adapter = plan["adapter"]
    if _sha(Path(adapter["path"]).read_bytes()) != adapter["sha256"]:
        raise CompilationDatabaseError("Normalizer implementation changed")
    return trusted if return_trusted_inventory else None


def verify_recorded_plan(plan, *, database_bytes=None):
    """Replay recorded recipes against exact original DB bytes, without SDK scan.

    Historical validation should supply the build's private raw DB snapshot.
    None reads the current DB. This checks entry/configuration identity, not
    current source/header/tool contents; use verify_snapshot for those. Existing
    path/ownership checks remain, so deleted source trees are not supported.
    """
    _verify_plan_fingerprint(plan)
    raw = Path(plan["database"]).read_bytes() if database_bytes is None else database_bytes
    if not isinstance(raw, bytes) or len(raw) > MAX_DATABASE_BYTES or _sha(raw) != plan["database_sha256"]:
        raise CompilationDatabaseError("Recorded compilation database bytes differ from the plan")
    try:
        entries = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_pairs, parse_constant=_json_constant)
    except (ValueError, UnicodeError) as exc:
        raise CompilationDatabaseError("Invalid recorded compilation database JSON") from exc
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_ENTRIES:
        raise CompilationDatabaseError("Invalid recorded compilation database entries")
    units = plan.get("translation_units")
    if not isinstance(units, list) or not 1 <= len(units) <= 64:
        raise CompilationDatabaseError("Invalid recorded translation unit selection")
    workspace = Path(plan["workspace_root"])
    roots = [Path(value) for value in plan["input_roots"]]
    trusted = [Path(record["path"]) for record in plan["trusted_headers"]["roots"]]
    seen = set()
    for recorded in units:
        if not isinstance(recorded, dict) or recorded.get("source") in seen:
            raise CompilationDatabaseError("Malformed/duplicate recorded translation unit")
        seen.add(recorded.get("source"))
        candidates = [entry for entry in entries if isinstance(entry, dict)
                      and _sha(_encoded(entry)) == recorded.get("entry_sha256")]
        if len(candidates) != 1:
            raise CompilationDatabaseError("Recorded translation unit has no unique original entry")
        entry = dict(candidates[0])
        entry["directory"] = str(_path(entry.get("directory"), Path(plan["database"]).parent, directory=True))
        rebuilt = _normal_unit(entry, workspace, roots, plan["tools"], trusted)
        rebuilt["entry_sha256"] = recorded["entry_sha256"]
        if rebuilt != recorded:
            raise CompilationDatabaseError("Recorded translation unit differs from original entry normalization")


def trusted_header_inventory(plan):
    """Return full private SDK/resource file records after compact-hash checks.

    A production caller may save this as a private sidecar. Do not put the full
    SDK inventory into MCP results. This does not derive trustworthy SDK roots.
    """
    expected = plan.get("trusted_headers", {"roots": []})
    inventory = _trusted_header_inventory([Path(row["path"]) for row in expected["roots"]])
    if inventory["roots"] != expected["roots"]:
        raise CompilationDatabaseError("Trusted header inventory changed")
    return inventory


def _compile_argv(plan, unit_index, output_path, *, emit_ir, preoptimization):
    """Return a proposed shell=False invocation; NEVER execute it.

    Preserve original frontend optimization/language options (predefines may
    depend on them), but request raw LLVM before its optimizer via an authored
    internal flag. This action still requires an actual pinned-driver test.
    """
    # Pure recipe generation must not repeatedly read the full SDK inventory.
    # The native builder checks full snapshots at start/end and hashes consumed
    # dependencies; normalization itself also performs a full snapshot check.
    _verify_plan_fingerprint(plan)
    if type(unit_index) is not int or not 0 <= unit_index < len(plan["translation_units"]):
        raise CompilationDatabaseError("Invalid translation unit index")
    workspace = Path(plan["workspace_root"])
    output = _owned(_path(output_path, workspace, exists=False), workspace)
    if output.exists() or not output.is_relative_to(workspace / ".runs") or _inside(output, [Path(p) for p in plan["input_roots"]]):
        raise CompilationDatabaseError("Compiler output must be fresh private output outside all input roots")
    return render_compile_argv(plan, unit_index, output, emit_ir=emit_ir, preoptimization=preoptimization)


def render_compile_argv(plan, unit_index, output_path, *, emit_ir, preoptimization=False):
    """Render exact recorded argv/cwd without file reads, execution or freshness.

    Validator callers may render already-existing output paths after independently
    binding the saved plan to original DB bytes. Builder helpers separately check
    fresh owned outputs. Rendering is not authorization or a snapshot validation.
    """
    _verify_plan_fingerprint(plan)
    if type(unit_index) is not int or not 0 <= unit_index < len(plan["translation_units"]):
        raise CompilationDatabaseError("Invalid translation unit index")
    if type(emit_ir) is not bool or type(preoptimization) is not bool or (preoptimization and not emit_ir):
        raise CompilationDatabaseError("Invalid authored compiler action")
    output = Path(output_path)
    _text(str(output), "output path")
    if not output.is_absolute():
        raise CompilationDatabaseError("Rendered output path must be absolute")
    unit = plan["translation_units"][unit_index]
    args = [unit["compiler"]["path"], *unit["frontend_argv"]]
    if unit["driver"] == "clangcl":
        if emit_ir:
            args += ["/clang:-S", "/clang:-emit-llvm"]
        if preoptimization:
            args += ["/clang:-Xclang", "/clang:-disable-llvm-passes"]
        # clang-cl ignores /Fo (and plain -o) for -S LLVM output and may
        # silently write <source>.ll into cwd despite returning success.
        # Forward the output option to the Clang driver for IR actions only.
        args += (["/clang:-o", "/clang:" + str(output)] if emit_ir
                 else ["/Fo" + str(output), "-c"])
        args += ["--", unit["source_operand"]]
    else:
        if preoptimization:
            args += ["-Xclang", "-disable-llvm-passes"]
        args += (["-S", "-emit-llvm"] if emit_ir else ["-c"]) + ["-o", str(output), "--", unit["source_operand"]]
    return {"argv": args, "cwd": unit["directory"], "shell": False, "executed": False,
            "plan_fingerprint": plan["fingerprint"], "requires_build_gates": list(plan["build_gates"])}


def compile_ir_argv(plan, unit_index, output_ir):
    """Proposed raw/pre-optimization LLVM action; no original option override."""
    return _compile_argv(plan, unit_index, output_ir, emit_ir=True, preoptimization=True)


def original_compile_argv(plan, unit_index, output_object):
    """Independent source-to-object reference action, no protection/IR path."""
    return _compile_argv(plan, unit_index, output_object, emit_ir=False, preoptimization=False)


def original_signature_ir_argv(plan, unit_index, output_ir):
    """Original-settings optimized IR for ABI inspection, never scope selection."""
    return _compile_argv(plan, unit_index, output_ir, emit_ir=True, preoptimization=False)


def dependency_scan_argv(plan, unit_index, depfile):
    """Proposed compiler-only dependency action, not a build-hook invocation."""
    # Reuse all path/fingerprint checks, then replace only the authored action.
    checked = _compile_argv(plan, unit_index, depfile, emit_ir=False, preoptimization=False)
    unit = plan["translation_units"][unit_index]
    output = str(_path(depfile, Path(plan["workspace_root"]), exists=False))
    args = [unit["compiler"]["path"], *unit["frontend_argv"]]
    if unit["driver"] == "clangcl":
        args += ["/clang:-M", "/clang:-MF", "/clang:" + output, "/clang:-MT", "/clang:" + DEPENDENCY_TARGET, "--", unit["source_operand"]]
    else:
        args += ["-M", "-MF", output, "-MT", DEPENDENCY_TARGET, "--", unit["source_operand"]]
    return {**checked, "argv": args, "dependency_target": DEPENDENCY_TARGET}


def parse_dependencies(path, cwd):
    """Read one bounded compiler Make dependency rule; never evaluate Make.

    The scanner emits a fixed target so drive-letter colons in filenames cannot
    be confused with target delimiters. Only continuation and filename escapes
    are decoded. Variables, comments, extra rules and missing files are rejected.
    The returned paths still require matching against owned + trusted snapshots.
    """
    path = _path(path, Path.cwd())
    cwd = _path(cwd, Path.cwd(), directory=True)
    if path.stat().st_size > 8 * 1024 * 1024:
        raise CompilationDatabaseError("Dependency output exceeds input bound")
    try:
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeError as exc:
        raise CompilationDatabaseError("Dependency output must be UTF-8") from exc
    if "\x00" in text:
        raise CompilationDatabaseError("NUL in dependency output")
    text = re.sub(r"\\\r?\n[ \t]*", " ", text).strip()
    prefix = DEPENDENCY_TARGET + ":"
    if not text.startswith(prefix) or "\n" in text or "\r" in text:
        raise CompilationDatabaseError("Expected exactly one authored dependency target")
    text = text[len(prefix):]
    values, word, i = [], [], 0
    while i < len(text):
        c = text[i]
        if c in " \t":
            if word:
                values.append("".join(word)); word = []
        elif c == "\\":
            if i + 1 == len(text):
                raise CompilationDatabaseError("Dangling dependency escape")
            next_char = text[i + 1]
            if next_char in " \t#:\\":
                word.append(next_char); i += 1
            else:
                word.append(c)
        elif c == "$":
            if i + 1 == len(text) or text[i + 1] != "$":
                raise CompilationDatabaseError("Make expansion is forbidden")
            word.append("$"); i += 1
        elif c == "#":
            raise CompilationDatabaseError("Unescaped dependency comment is unsupported")
        else:
            word.append(c)
        i += 1
    if word:
        values.append("".join(word))
    if not values or len(values) > MAX_TRUSTED_HEADER_FILES:
        raise CompilationDatabaseError("Missing/oversized dependency list")
    result = []
    for value in values:
        resolved = _path(value, cwd)
        if resolved not in result:
            result.append(resolved)
    return result
