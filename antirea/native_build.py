"""Reviewed source projects -> Windows native DLLs with per-function VM evidence.

Only trusted local source is accepted. This is a compiler driver, not a source
sandbox or a whole-language compatibility claim. It never runs built libraries,
attacks, installs tools, publishes artifacts, or executes project build hooks.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import stat
import time

from antirea import cpp_symbols, diversify, hardening, native_objects, scope
from antirea.process import run_logged


TARGET = "x86_64-pc-windows-msvc"
LANGUAGES = {"c", "cpp", "rust", "swift"}
FIELDS = {"schema_version", "name", "language", "sources", "functions",
          "include_dirs", "defines", "target", "artifact", "scope_policy", "compile_commands"}
SYMBOL = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_INPUT_FILES = 4096
LIMITATIONS = [
    "Trusted local source only; compilers and system SDK headers are not sandboxed.",
    "Windows x86-64 shared libraries only; no arbitrary build scripts, dependencies, or linker hooks.",
    "Selected functions must expose unmangled external C ABI symbols supported by the pinned Kagura VM.",
    "Unsupported LLVM features can leave a function unvirtualized; this driver rejects that result.",
    "Explicit selection or reviewed graph expansion covers supplied IR only, not whole-application semantics.",
    "Selecting functions does not encrypt their referenced global data or public interfaces.",
    "Source/IR/VM evidence is not functional equivalence, performance acceptance, or defense effectiveness.",
    "System SDK headers/libraries and recursively included files outside the project are not fully hash-pinned.",
]


class NativeBuildError(ValueError):
    pass


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _no_links(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    for part in (path, *path.parents):
        if part.exists() or part.is_symlink():
            info = part.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise NativeBuildError(f"Links/reparse points are not supported: {part}")
    return path


def _relative(root: Path, value, *, directory=False) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise NativeBuildError("Project paths must be nonempty relative strings")
    win = PureWindowsPath(value)
    if Path(value).is_absolute() or win.is_absolute() or win.drive or ".." in win.parts or ":" in value:
        raise NativeBuildError(f"Path must stay inside the project: {value}")
    path = _no_links(root / Path(value.replace("\\", "/")))
    if not path.is_relative_to(root) or not (path.is_dir() if directory else path.is_file()):
        raise NativeBuildError(f"Missing or invalid project path: {value}")
    return path


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise NativeBuildError(f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> dict:
    if path.stat().st_size > 1024 * 1024:
        raise NativeBuildError("Configuration exceeds 1 MiB")
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise NativeBuildError(f"Invalid UTF-8 JSON: {path}") from exc
    if not isinstance(value, dict):
        raise NativeBuildError("Configuration must be an object")
    return value


def _snapshot(roots: list[Path], extra: list[Path]) -> dict[str, str]:
    files = set(extra)
    for root in roots:
        for directory, dirs, names in os.walk(root, followlinks=False):
            for name in dirs:
                _no_links(Path(directory) / name)
            for name in names:
                path = _no_links(Path(directory) / name)
                if not path.is_file():
                    raise NativeBuildError(f"Non-regular project input: {path}")
                files.add(path)
                if len(files) > MAX_INPUT_FILES:
                    raise NativeBuildError("Project input count exceeds 4096 files")
    if sum(path.stat().st_size for path in files) > MAX_INPUT_BYTES:
        raise NativeBuildError("Project input snapshot exceeds 64 MiB")
    return {str(path): _hash(path) for path in sorted(files)}


def inspect_project(project_path: Path, *, workspace_root: Path | None = None) -> dict:
    """Validate a v1 project without executing compilers or creating files."""
    path = _no_links(Path(project_path))
    if not path.is_file() or "rea-analysis-reports" in {p.lower() for p in path.parts}:
        raise NativeBuildError("A trusted local project JSON file is required")
    project = _read_json(path)
    unknown = set(project) - FIELDS
    if unknown:
        raise NativeBuildError("Unknown project fields: " + ", ".join(sorted(unknown)))
    if type(project.get("schema_version")) is not int or project["schema_version"] != 1:
        raise NativeBuildError("schema_version must be 1")
    name, language = project.get("name"), project.get("language")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name):
        raise NativeBuildError("name must be a short ASCII project identifier")
    if not isinstance(language, str) or language not in LANGUAGES:
        raise NativeBuildError("language must be c, cpp, rust, or swift")
    source_values, functions = project.get("sources"), project.get("functions")
    if "compile_commands" not in project and (not isinstance(source_values, list) or not 1 <= len(source_values) <= 64):
        raise NativeBuildError("sources must contain 1..64 relative source files")
    if not isinstance(functions, list) or not 1 <= len(functions) <= 64:
        raise NativeBuildError("functions must contain 1..64 selected C ABI symbols")
    if any(not isinstance(fn, str) or not SYMBOL.fullmatch(fn) or fn.startswith(("kagura_", "antirea_dispatch_")) for fn in functions):
        raise NativeBuildError("functions must be ordinary, non-reserved C ABI symbols")
    if len(set(functions)) != len(functions):
        raise NativeBuildError("Duplicate selected functions")
    if "compile_commands" in project:
        return _inspect_compilation_database(path, project, workspace_root=workspace_root)
    root = path.parent
    policy_path, policy_hash = None, None
    if "scope_policy" in project:
        policy_path = _relative(root, project["scope_policy"])
        if policy_path.stat().st_nlink != 1:
            raise NativeBuildError("Scope policy must not be hard-linked")
        _read_json(policy_path)
        policy_hash = _hash(policy_path)
    sources = [_relative(root, item) for item in source_values]
    if len(set(sources)) != len(sources):
        raise NativeBuildError("Duplicate source files")
    suffixes = {"c": {".c"}, "cpp": {".c", ".cpp", ".cc", ".cxx"},
                "rust": {".rs"}, "swift": {".swift"}}[language]
    if any(item.suffix.lower() not in suffixes for item in sources):
        raise NativeBuildError("Source extension does not match the declared language")
    include_values = project.get("include_dirs", [])
    if not isinstance(include_values, list) or len(include_values) > 64:
        raise NativeBuildError("include_dirs must be a list of at most 64 relative paths")
    includes = [_relative(root, item, directory=True) for item in include_values]
    defines = project.get("defines", {})
    if not isinstance(defines, dict) or len(defines) > 64:
        raise NativeBuildError("defines must be an object with at most 64 entries")
    for key, value in defines.items():
        if not SYMBOL.fullmatch(key) or type(value) not in (str, int) or len(str(value)) > 1024 or any(c in str(value) for c in "\x00\r\n"):
            raise NativeBuildError("Invalid preprocessor definition")
    if language in {"rust", "swift"} and (includes or defines):
        raise NativeBuildError("include_dirs/defines only apply to C/C++ routes")
    target, artifact = project.get("target", TARGET), project.get("artifact", "shared_library")
    if not isinstance(target, str) or not isinstance(artifact, str):
        raise NativeBuildError("target and artifact must be strings")
    blockers = []
    if target != TARGET:
        blockers.append("unsupported_target:" + str(target))
    if artifact != "shared_library":
        blockers.append("unsupported_artifact:" + str(artifact))
    if language == "swift":
        blockers.append("swift_frontend_and_runtime_linking_not_implemented")
    if language == "rust" and len(sources) != 1:
        blockers.append("rust_route_requires_one_crate_root_without_cargo_hooks")
    return {"schema_version": 1, "project_path": str(path), "project_root": str(root),
            "name": name, "language": language, "sources": list(map(str, sources)),
            "source_files": list(map(str, sources)), "functions": functions,
            "exported_functions": list(functions),
            "scope_mode": "expanded" if policy_path else "explicit",
            "scope_policy": str(policy_path) if policy_path else None,
            "scope_policy_sha256": policy_hash,
            "scope_analysis_status": "requires_compilation" if policy_path else "not_requested",
            "include_dirs": list(map(str, includes)), "defines": defines,
            "target": target, "artifact": artifact,
            "route_status": "unsupported" if blockers else "available", "blockers": blockers,
            "experimental": language == "rust",
            "input_hashes": _snapshot([root], [path]), "limitations": list(LIMITATIONS)}


def _content_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()


_SELECTION_NAMES = {
    "PATH", "PATHEXT", "INCLUDE", "LIB", "LIBPATH", "IFCPATH", "COMSPEC",
    "SYSTEMROOT", "WINDIR", "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMW6432",
    "PROGRAMDATA", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP",
    "VSINSTALLDIR", "VSAPPIDDIR", "VCINSTALLDIR", "VCTOOLSINSTALLDIR", "VCTOOLSVERSION",
    "VISUALSTUDIOVERSION", "DEVENVDIR", "WINDOWSSDKDIR", "WINDOWSSDKVERSION",
    "WINDOWSSDKBINPATH", "WINDOWSSDKVERBINPATH", "WINDOWSLIBPATH", "WINDOWSSDKLIBVERSION",
    "UNIVERSALCRTSDKDIR", "UCRTVERSION", "NETFXSDKDIR", "FRAMEWORKDIR", "FRAMEWORKDIR32",
    "FRAMEWORKDIR64", "FRAMEWORKVERSION", "FRAMEWORKVERSION32", "FRAMEWORKVERSION64",
    "PLATFORM", "PREFERREDTOOLARCHITECTURE", "PROCESSOR_ARCHITECTURE", "PROCESSOR_ARCHITEW6432",
    "MSBUILDEXTENSIONSPATH", "MSBUILDSDKSPATH", "SOURCE_DATE_EPOCH", "CL", "_CL_", "LINK", "_LINK_",
    "CCC_OVERRIDE_OPTIONS", "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH",
    "LIBRARY_PATH", "GCC_EXEC_PREFIX", "COMPILER_PATH",
}
_SELECTION_PREFIXES = ("VSCMD_", "__VSCMD_", "__VCVARS_", "VCINCLUDE_", "VCLIB_", "CLANG_")


def _environment_selection_inputs(environment=None, *, referenced_names=()):
    """Hash selection values exactly, including search order and absent values.

    Do not reject or normalize an ordinary developer environment. Do not record
    arbitrary environment values/secrets. This is an explicit reviewed selection
    subset, not a proof that every ambient OS input is hermetically modeled.
    """
    environment = os.environ if environment is None else environment
    canonical = {}
    for key, value in environment.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise NativeBuildError("Environment names/values must be strings")
        name = key.upper()
        if name in canonical and canonical[name] != value:
            raise NativeBuildError("Conflicting Windows environment name spellings")
        canonical[name] = value
    names = set(_SELECTION_NAMES)
    names.update(name.upper() for name in referenced_names)
    names.update(name for name in canonical if name.startswith(_SELECTION_PREFIXES))
    records = {}
    for name in sorted(names):
        value = canonical.get(name)
        raw = value.encode("utf-8") if value is not None else None
        records[name] = {"present": raw is not None,
                         "sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None,
                         "bytes": len(raw) if raw is not None else 0}
    return {"schema_version": 1, "variables": records,
            "qualification": "Exact reviewed environment selectors; no secret values, no hermetic OS claim."}


def _devshell_selection_metadata(installation, developer_shell, environment=None):
    """Pin installed selection scripts/defaults without executing them.

    Launch-VsDevShell may consult vswhere, a DevShell DLL, VsDevCmd scripts and
    multiple VCTools default props/txt files. Include directory inventories so
    new selector files cannot silently change the default decision.
    """
    environment = os.environ if environment is None else environment
    environment = {key.upper(): value for key, value in environment.items()}
    installation, shell = _no_links(Path(installation)), _no_links(Path(developer_shell))
    fixed = [shell, installation / "Common7/Tools/VsDevCmd.bat"]
    optional = [installation / "Common7/Tools/Microsoft.VisualStudio.DevShell.dll",
                installation / "Common7/Tools/vsdevshell/Microsoft.VisualStudio.DevShell.dll"]
    trees = [installation / "Common7/Tools/vsdevcmd", installation / "VC/Auxiliary/Build"]
    records, directories, presence, referenced = {}, [], {}, set()
    total = 0

    def record(path, *, required=True):
        nonlocal total
        path = _no_links(Path(path))
        presence[str(path)] = path.is_file()
        if not path.is_file():
            if required:
                raise NativeBuildError("Installed selection metadata missing: " + str(path))
            return
        size = path.stat().st_size
        total += size
        if total > 64 * 1024 * 1024 or len(records) >= 4096:
            raise NativeBuildError("Installed selection metadata exceeds bounded inventory")
        records[str(path)] = _hash(path)
        if path.suffix.lower() in {".bat", ".cmd", ".ps1"}:
            # Add literal variable references, including absent selector values.
            # Prefix families above cover common dynamically composed names.
            text = path.read_text(encoding="utf-8-sig", errors="replace")
            referenced.update(re.findall(r"[%!]([A-Za-z_][A-Za-z0-9_()]*)", text))

    for path in fixed:
        record(path)
    for path in optional:
        record(path, required=False)
    if not any(presence[str(path)] for path in optional):
        raise NativeBuildError("Installed DevShell module is missing")
    for root in trees:
        root = _no_links(root)
        if not root.is_dir():
            raise NativeBuildError("Installed selector directory missing: " + str(root))
        for directory, subdirs, names in os.walk(root, followlinks=False):
            directories.append(str(_no_links(Path(directory))))
            for name in subdirs:
                _no_links(Path(directory) / name)
            for name in names:
                record(Path(directory) / name)
    # Match the launcher's documented default vswhere path, but make it visible
    # and hash-pinned. Build should pass this path explicitly (no Latest fallback).
    program_files_x86 = environment.get("PROGRAMFILES(X86)")
    if not program_files_x86 or not Path(program_files_x86).is_absolute():
        raise NativeBuildError("Cannot resolve the installed vswhere selection tool")
    vswhere = _no_links(Path(program_files_x86) / "Microsoft Visual Studio/Installer/vswhere.exe")
    record(vswhere)
    # vswhere selects a setup instance using these installation records. Only
    # known metadata filenames are hashed, not arbitrary user/project trees.
    program_data = environment.get("PROGRAMDATA")
    if not program_data or not Path(program_data).is_absolute():
        raise NativeBuildError("Cannot resolve installed Visual Studio setup metadata")
    instances = _no_links(Path(program_data) / "Microsoft/VisualStudio/Packages/_Instances")
    if not instances.is_dir():
        raise NativeBuildError("Visual Studio setup instance metadata is missing")
    for instance in sorted(instances.iterdir()):
        instance = _no_links(instance)
        if not instance.is_dir():
            continue
        directories.append(str(instance))
        for name in ("state.json", "catalog.json", "product.json"):
            record(instance / name, required=False)
    return {"files": records, "directories": sorted(directories), "presence": presence,
            "referenced_environment_names": sorted(name.upper() for name in referenced),
            "vswhere": str(vswhere), "installation": str(installation),
            "qualification": "Read-only selector metadata inventory; indirect library/OS state is not fully hermetic."}


def _reject_assembly_before_original_codegen(source, llvm_library):
    """Parse every TU before original object emission; never assemble its text.

    Header -M output cannot account for assembler .incbin/.include inputs. This
    route therefore rejects all module/function inline assembly, including
    unselected functions. It is an input-closure gate, not a source sandbox.
    """
    import ctypes
    from antirea.swift_frontend import _LLVM
    llvm = _LLVM(llvm_library)
    context, module = None, ctypes.c_void_p()
    count = 0
    try:
        context = llvm.LLVMContextCreate()
        data = Path(source).read_bytes()
        buffer = llvm.LLVMCreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"compile-database-assembly-gate")
        error = ctypes.c_void_p()
        if llvm.LLVMParseIRInContext(context, buffer, ctypes.byref(module), ctypes.byref(error)):
            raise NativeBuildError("Raw compilation-database IR parse failed: " + llvm.string(error.value))
        if llvm.LLVMVerifyModule(module, 2, ctypes.byref(error)):
            raise NativeBuildError("Raw compilation-database IR verification failed: " + llvm.string(error.value))
        length = ctypes.c_size_t()
        llvm.LLVMGetModuleInlineAsm(module, ctypes.byref(length))
        if length.value:
            raise NativeBuildError("Compilation-database module assembly is unsupported before code generation")
        is_asm = llvm.dll.LLVMIsAInlineAsm
        is_asm.restype, is_asm.argtypes = ctypes.c_void_p, [ctypes.c_void_p]
        for function in llvm.functions(module):
            for instruction in llvm.instructions(function):
                count += 1
                # Covers call, invoke and callbr, without assuming printed IR
                # token layouts or treating string literals as instructions.
                for index in range(llvm.LLVMGetNumOperands(instruction)):
                    if is_asm(llvm.LLVMGetOperand(instruction, index)):
                        raise NativeBuildError("Compilation-database inline assembly is unsupported in " + llvm.name(function))
        return {"path": str(source), "sha256": _hash(Path(source)), "status": "no_module_or_function_inline_assembly",
                "instructions_inspected": count, "scope": "every function in this raw TU, selected or unselected",
                "stage": "after source-to-raw-IR, before original object emission",
                "qualification": "Assembly input exclusion only; no general source sandbox claim."}
    finally:
        if module:
            llvm.LLVMDisposeModule(module)
        if context:
            llvm.LLVMContextDispose(context)
        llvm.close()


def _direct_reference_commands(language, source, compiler, object_path, signature_path, *,
                               include_dirs, defines):
    """Normal direct recipe for the independent original reference; never the
    scope-analysis O0/opt-level-0 downgrade used by the protection path.

    ``language`` only separates the Rust route from the Clang family; inside the
    Clang family the frontend and flags follow the translation-unit suffix exactly
    as the protection compile does, so a ``.c`` unit inside a cpp project keeps the
    C frontend. Returns ``(object_argv, signature_argv)`` and runs nothing.
    """
    source, object_path, signature_path = Path(source), Path(object_path), Path(signature_path)
    if language == "rust":
        base = [str(compiler), "--crate-name", "antirea_native_module", "--crate-type=lib", "--edition=2021"]
        tail = ["-Copt-level=1", "-Cpanic=abort", "-Ccodegen-units=1", "--target", TARGET, str(source)]
        return ([*base, "--emit=obj", *tail, "-o", str(object_path)],
                [*base, "--emit=llvm-ir", *tail, "-o", str(signature_path)])
    is_c = source.suffix.lower() == ".c"
    flags = ["-std=c11" if is_c else "-std=c++17", "-O1", "-fno-inline", "-fno-exceptions"]
    if not is_c:
        flags.append("-fno-rtti")
    for include in include_dirs:
        flags.extend(["-I", include])
    flags.extend(f"-D{key}={value}" for key, value in sorted(defines.items()))
    head = [str(compiler), *flags, "-target", TARGET]
    return ([*head, "-c", str(source), "-o", str(object_path)],
            [*head, "-S", "-emit-llvm", str(source), "-o", str(signature_path)])


def _emit_direct_original_reference(project, index, source, module, output, *, compiler,
                                    compiler_sha256, llvm_library, run, commands):
    """Reject raw assembly BEFORE emitting the original object, then compile the
    independent source-only original object and signature IR with the normal
    direct recipe. ``run(program, *args)`` must append its record to ``commands``.

    Returns ``(assembly_check, translation_unit, object_path, signature_path)``.
    The caller links the collected objects into the original reference DLL after
    every translation unit compiles.
    """
    assembly_check = _reject_assembly_before_original_codegen(module, Path(llvm_library))
    source = Path(source)
    object_path = output / f"original-{index:03d}.obj"
    signature_path = output / f"original-signature-{index:03d}.ll"
    object_argv, signature_argv = _direct_reference_commands(
        project["language"], source, compiler, object_path, signature_path,
        include_dirs=project["include_dirs"], defines=project["defines"])
    run(object_argv[0], *object_argv[1:])
    object_command_index = len(commands) - 1
    run(signature_argv[0], *signature_argv[1:])
    signature_command_index = len(commands) - 1
    unit = {"source": str(source), "source_operand": str(source),
            "entry_sha256": _hash(source), "compiler": str(compiler),
            "compiler_sha256": compiler_sha256, "cwd": str(output),
            "object_path": str(object_path), "signature_ir_path": str(signature_path),
            "object_command_index": object_command_index,
            "signature_ir_command_index": signature_command_index}
    return assembly_check, unit, object_path, signature_path


def _compile_database_environment(config: dict) -> dict:
    """Read installed metadata only; never execute a database command or SDK hook.

    Root identities come from the pinned compiler/developer-shell installation
    and the OS SDK registry. A manifest cannot designate arbitrary external
    directories as trusted headers. The normalizer binds root contents.
    """
    if os.name != "nt":
        raise NativeBuildError("Compilation database integration currently requires Windows")
    import winreg
    llvm_root = _no_links(Path(config["llvm_root"]))
    compiler_root = _no_links(Path(config["clang"])).parent.parent
    if compiler_root != llvm_root:
        raise NativeBuildError("Pinned Clang must belong to the configured LLVM distribution")
    major = config["llvm_version"].split(".")[0]
    if not major.isdecimal():
        raise NativeBuildError("Invalid pinned LLVM version")
    resource = _no_links(llvm_root / "lib" / "clang" / major / "include")
    shell = _no_links(Path(config["developer_shell"]))
    if shell.name.casefold() != "launch-vsdevshell.ps1" or shell.parent.name.casefold() != "tools" or shell.parent.parent.name.casefold() != "common7":
        raise NativeBuildError("Cannot derive a Visual Studio installation from the pinned developer shell")
    installation = shell.parents[2]
    version_path = _no_links(installation / "VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt")
    if not version_path.is_file() or version_path.stat().st_size > 1024:
        raise NativeBuildError("Installed MSVC version metadata is missing or oversized")
    version = version_path.read_text(encoding="utf-8-sig").strip()
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", version):
        raise NativeBuildError("Unsupported MSVC version metadata")
    msvc = _no_links(installation / "VC/Tools/MSVC" / version)
    selection_metadata = _devshell_selection_metadata(installation, shell)
    metadata = {"files": {str(version_path): _hash(version_path), **selection_metadata["files"]},
                "registry": [], "selection_context": selection_metadata}

    def registry_directory(key, name, *, required):
        found = set()
        for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ | view) as handle:
                    value, kind = winreg.QueryValueEx(handle, name)
            except FileNotFoundError:
                continue
            if kind not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) or not isinstance(value, str):
                raise NativeBuildError("Unsupported installed SDK metadata")
            candidate = Path(os.path.expandvars(value))
            if not candidate.is_absolute():
                raise NativeBuildError("Installed SDK root must be absolute")
            found.add(str(_no_links(candidate)))
        if len(found) > 1 or (required and not found):
            raise NativeBuildError("Missing or conflicting installed SDK root: " + key)
        value = next(iter(found), None)
        metadata["registry"].append({"key": key, "name": name, "path": value})
        return Path(value) if value else None

    sdk = registry_directory(r"SOFTWARE\Microsoft\Windows Kits\Installed Roots", "KitsRoot10", required=True)
    roots = [{"kind": "clang_resource", "path": str(resource)},
             {"kind": "msvc", "path": str(msvc / "include")},
             {"kind": "windows_sdk", "path": str(sdk / "Include")}]
    if (msvc / "atlmfc/include").is_dir():
        roots.append({"kind": "msvc_atlmfc", "path": str(msvc / "atlmfc/include")})
    auxiliary = installation / "VC/Auxiliary/VS/include"
    if auxiliary.is_dir():
        roots.append({"kind": "msvc_auxiliary", "path": str(auxiliary)})
    netfx = registry_directory(r"SOFTWARE\Microsoft\Microsoft SDKs\NETFXSDK\4.8",
                              "KitsInstallationFolder", required=False)
    if netfx is not None and (netfx / "Include").is_dir():
        roots.append({"kind": "netfx_sdk", "path": str(netfx / "Include")})
    for record in roots:
        root = _no_links(Path(record["path"]))
        if not root.is_dir():
            raise NativeBuildError("Installed header root is missing: " + str(root))
        record["path"] = str(root)
    return {"schema_version": 1, "roots": roots, "metadata": metadata,
            "environment_selection_inputs": _environment_selection_inputs(
                referenced_names=selection_metadata["referenced_environment_names"]),
            "environment_policy": "pinned reviewed selectors and installed metadata; realized SDK paths recorded at build, not a hermetic OS claim",
            "link_libraries": "installed defaults recorded but not hermetically inventoried"}


def _inspect_compilation_database(path, project, *, workspace_root):
    from . import compile_database
    if project["language"] not in {"c", "cpp"}:
        raise NativeBuildError("compile_commands applies only to the C/C++ route")
    if any(key in project for key in ("sources", "include_dirs", "defines")):
        raise NativeBuildError("compile_commands cannot be combined with global sources/include_dirs/defines")
    if workspace_root is None:
        raise NativeBuildError("compile_commands inspection requires an explicit workspace_root")
    workspace = _no_links(Path(workspace_root))
    if not path.is_relative_to(workspace):
        raise NativeBuildError("Compilation database manifest must stay inside the owned workspace")
    spec = project["compile_commands"]
    if not isinstance(spec, dict) or set(spec) - {"path", "selections", "input_roots"} or not {"path", "selections"} <= set(spec):
        raise NativeBuildError("compile_commands requires path, selections and optional input_roots")
    roots = spec.get("input_roots", [])
    if not isinstance(roots, list) or len(roots) > 64 or any(not isinstance(item, str) or not item for item in roots):
        raise NativeBuildError("input_roots must be a bounded list of owned workspace-relative directories")
    root = path.parent
    database = _relative(root, spec["path"])
    policy = _relative(root, project["scope_policy"]) if "scope_policy" in project else None
    if policy is not None:
        _read_json(policy)
        if policy.stat().st_nlink != 1:
            raise NativeBuildError("Scope policy must not be hard-linked")
    config, hashes = _toolchain(workspace)
    environment = _compile_database_environment(config)
    drivers = {key: {"path": config[key], "sha256": hashes[config[key]]}
               for key in ("clang", "clangxx")}
    clangcl = _no_links(Path(config["clang"]).with_name("clang-cl.exe"))
    if clangcl.is_file():
        drivers["clangcl"] = {"path": str(clangcl), "sha256": _hash(clangcl)}
    llvm_c = _no_links(Path(config["llvm_root"]) / "bin/LLVM-C.dll")
    if not llvm_c.is_file():
        raise NativeBuildError("Pinned LLVM-C parser is required to retain selected scope")
    try:
        normalized = compile_database.normalize_database(
            database, workspace_root=workspace, project_root=root, toolchain=drivers,
            selections=spec["selections"], extra_input_roots=roots, scope_policy=policy,
            trusted_header_roots=[entry["path"] for entry in environment["roots"]])
    except compile_database.CompilationDatabaseError as exc:
        raise NativeBuildError(str(exc)) from exc
    target, artifact = project.get("target", TARGET), project.get("artifact", "shared_library")
    if not isinstance(target, str) or not isinstance(artifact, str):
        raise NativeBuildError("target and artifact must be strings")
    blockers = []
    if target != TARGET:
        blockers.append("unsupported_target:" + target)
    if artifact != "shared_library":
        blockers.append("compile_database_link_contract_requires_shared_library")
    compiler_inputs = {record["path"]: record["sha256"] for record in normalized["tools"].values()}
    compiler_inputs.update(environment["metadata"]["files"])
    compiler_inputs.update({normalized["adapter"]["path"]: normalized["adapter"]["sha256"],
                            str(llvm_c): _hash(llvm_c),
                            str(Path(__file__).with_name("swift_frontend.py")): _hash(Path(__file__).with_name("swift_frontend.py")),
                            str(workspace / ".tools/kagura-toolchain.json"): hashes[str(workspace / ".tools/kagura-toolchain.json")]})
    return {"schema_version": 1, "backend": "compile_database_native", "project_path": str(path),
            "project_root": str(root), "name": project["name"], "language": project["language"],
            "sources": [unit["source"] for unit in normalized["translation_units"]],
            "source_files": [unit["source"] for unit in normalized["translation_units"]],
            "functions": project["functions"], "exported_functions": list(project["functions"]),
            "scope_mode": "expanded" if policy else "explicit", "scope_policy": str(policy) if policy else None,
            "scope_policy_sha256": _hash(policy) if policy else None,
            "scope_analysis_status": "requires_compilation" if policy else "not_requested",
            "include_dirs": [], "defines": {}, "target": target, "artifact": artifact,
            "route_status": "unsupported" if blockers else "available", "blockers": blockers,
            "experimental": True, "compilation_database": normalized,
            "compiler_environment_metadata": environment,
            "input_hashes": {record["path"]: record["sha256"] for record in normalized["inputs"]["files"]},
            "compiler_inputs": compiler_inputs,
            "limitations": list(LIMITATIONS) + [
                "Per-TU recorded compilation settings, not an original application linker/build-system replay.",
                "Original direct-source DLL comparison is required in addition to baseline/protected equality.",
                "Source signedness still comes from the reviewed user ABI contract, not LLVM integer types.",
                "SDK header inventories are pinned; installed linker/runtime libraries are not fully hermetic."]}


class _BoundaryIR:
    """Small parsed-IR adapter for reviewed call/return-only public boundaries.

    It never copies module globals, constructors, aliases, COMDAT or metadata to
    the forwarding module. Both modules share a context only during construction.
    """

    def __init__(self, source, library):
        import ctypes
        from .swift_frontend import _LLVM
        self.ctypes, self.llvm = ctypes, _LLVM(library)
        p, u, s = ctypes.c_void_p, ctypes.c_uint, ctypes.c_char_p
        signatures = {
            "LLVMModuleCreateWithNameInContext": (p, [s, p]),
            "LLVMGetDataLayoutStr": (s, [p]), "LLVMSetDataLayout": (None, [p, s]),
            "LLVMGetNamedFunction": (p, [p, s]), "LLVMAddFunction": (p, [p, s, p]),
            "LLVMDeleteFunction": (None, [p]), "LLVMReplaceAllUsesWith": (None, [p, p]),
            "LLVMCountParams": (u, [p]), "LLVMGetParam": (p, [p, u]),
            "LLVMPrintTypeToString": (p, [p]), "LLVMIsAFunction": (p, [p]),
            "LLVMIsAConstantInt": (p, [p]), "LLVMGetNumArgOperands": (u, [p]),
            "LLVMGetTailCallKind": (u, [p]), "LLVMSetTailCallKind": (None, [p, u]),
            "LLVMGetAttributeCountAtIndex": (u, [p, u]),
            "LLVMGetAttributesAtIndex": (None, [p, u, ctypes.POINTER(p)]),
            "LLVMGetCallSiteAttributeCount": (u, [p, u]),
            "LLVMGetCallSiteAttributes": (None, [p, u, ctypes.POINTER(p)]),
            "LLVMGetCallSiteEnumAttribute": (p, [p, u, u]),
            "LLVMRemoveCallSiteEnumAttribute": (None, [p, u, u]),
            "LLVMAddCallSiteAttribute": (None, [p, u, p]),
            "LLVMIsEnumAttribute": (ctypes.c_int, [p]),
            "LLVMGetEnumAttributeKind": (u, [p]),
            "LLVMGetEnumAttributeValue": (ctypes.c_ulonglong, [p]),
            "LLVMGetLinkage": (u, [p]), "LLVMGetVisibility": (u, [p]),
            "LLVMGetDLLStorageClass": (u, [p]),
            "LLVMCreateBuilderInContext": (p, [p]), "LLVMDisposeBuilder": (None, [p]),
            "LLVMAppendBasicBlockInContext": (p, [p, p, s]),
            "LLVMPositionBuilderAtEnd": (None, [p, p]),
            "LLVMBuildCall2": (p, [p, p, p, ctypes.POINTER(p), u, s]),
            "LLVMBuildRet": (p, [p, p]), "LLVMBuildRetVoid": (p, [p]),
        }
        for name, (restype, argtypes) in signatures.items():
            function = getattr(self.llvm.dll, name)
            function.restype, function.argtypes = restype, argtypes
            setattr(self, name, function)
        self.context = self.llvm.LLVMContextCreate()
        self.module, self.other_module = p(), None
        try:
            data, error = Path(source).read_bytes(), p()
            buffer = self.llvm.LLVMCreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"boundary-transit")
            if self.llvm.LLVMParseIRInContext(self.context, buffer, ctypes.byref(self.module), ctypes.byref(error)):
                raise NativeBuildError("Boundary IR parse failed: " + self.llvm.string(error.value))
            self.verify(self.module)
        except Exception:
            self.close()
            raise

    def verify(self, module):
        error = self.ctypes.c_void_p()
        if self.llvm.LLVMVerifyModule(module, 2, self.ctypes.byref(error)):
            raise NativeBuildError("Boundary IR verification failed: " + self.llvm.string(error.value))

    def close(self):
        if self.other_module:
            self.llvm.LLVMDisposeModule(self.other_module)
        if self.module:
            self.llvm.LLVMDisposeModule(self.module)
        self.llvm.LLVMContextDispose(self.context)
        self.llvm.close()

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()

    def abi(self, value, count, *, call=False, destination=None):
        # This route's public ABI is scalar integer/void. Preserve the integer
        # calling-convention attributes, not inferred returned/readnone facts.
        names = {self.llvm.LLVMGetEnumAttributeKindForName(name, len(name)): name.decode()
                 for name in (b"zeroext", b"signext", b"inreg")}
        count_fn = self.LLVMGetCallSiteAttributeCount if call else self.LLVMGetAttributeCountAtIndex
        get_fn = self.LLVMGetCallSiteAttributes if call else self.LLVMGetAttributesAtIndex
        add_fn = self.LLVMAddCallSiteAttribute if call else self.llvm.LLVMAddAttributeAtIndex
        result = []
        for index in range(count + 1):
            attributes = (self.ctypes.c_void_p * count_fn(value, index))()
            get_fn(value, index, attributes)
            row = []
            for attribute in attributes:
                if self.LLVMIsEnumAttribute(attribute):
                    kind = self.LLVMGetEnumAttributeKind(attribute)
                    if kind in names:
                        row.append({"name": names[kind], "value": self.LLVMGetEnumAttributeValue(attribute)})
                        if destination:
                            add_fn(destination, index, attribute)
            result.append(sorted(row, key=lambda item: item["name"]))
        return result

    def contract(self, names, expected_calls=None):
        llvm, records, details = self.llvm, {}, {}
        for name in names:
            function = self.LLVMGetNamedFunction(self.module, name.encode())
            if not function or llvm.LLVMIsDeclaration(function):
                raise NativeBuildError("Boundary transit definition missing: " + name)
            signature = llvm.LLVMGlobalGetValueType(function)
            if llvm.LLVMIsFunctionVarArg(signature) or llvm.LLVMGetFunctionCallConv(function) != 0:
                raise NativeBuildError("Boundary transit requires a fixed C ABI: " + name)
            params = [self.LLVMGetParam(function, index) for index in range(self.LLVMCountParams(function))]
            return_type = llvm.LLVMGetReturnType(signature)
            types = [llvm.LLVMTypeOf(param) for param in params]
            if llvm.LLVMGetTypeKind(return_type) != 0:
                types.append(return_type)
            if any(llvm.LLVMGetTypeKind(kind) != 8 or llvm.LLVMGetIntTypeWidth(kind) > 64 for kind in types):
                raise NativeBuildError("Boundary transit requires the supported scalar integer/void ABI: " + name)
            block = llvm.LLVMGetFirstBasicBlock(function)
            if not block or llvm.LLVMGetNextBasicBlock(block):
                raise NativeBuildError("Boundary transit is not a single reviewed call/return block: " + name)
            instructions, instruction = [], llvm.LLVMGetFirstInstruction(block)
            while instruction:
                instructions.append(instruction)
                instruction = llvm.LLVMGetNextInstruction(instruction)
            call = None
            if len(instructions) == 2 and llvm.LLVMGetInstructionOpcode(instructions[0]) == 45:
                call = instructions[0]
            elif len(instructions) != 1:
                raise NativeBuildError("Boundary transit contains non-forwarding instructions: " + name)
            ret = instructions[-1]
            if llvm.LLVMGetInstructionOpcode(ret) != 1:
                raise NativeBuildError("Boundary transit has no ordinary return: " + name)
            record = {"signature": llvm.string(self.LLVMPrintTypeToString(signature)),
                      "abi_attributes": self.abi(function, len(params)), "callee": None,
                      "argument_indices": [], "return": {"kind": "void"}}
            target = None
            if call:
                target = llvm.LLVMGetCalledValue(call)
                if not self.LLVMIsAFunction(target) or llvm.LLVMGetNumOperandBundles(call) or llvm.LLVMGetInstructionCallConv(call) != 0:
                    raise NativeBuildError("Boundary transit is not an ordinary direct C call: " + name)
                target_type = llvm.LLVMGlobalGetValueType(target)
                if llvm.LLVMGetFunctionCallConv(target) != 0:
                    raise NativeBuildError("Boundary transit callee no longer has the C calling convention: " + name)
                if llvm.LLVMGetCalledFunctionType(call) != target_type:
                    raise NativeBuildError("Boundary transit call type differs from its callee declaration/definition: " + name)
                arguments = [llvm.LLVMGetOperand(call, index) for index in range(self.LLVMGetNumArgOperands(call))]
                if arguments != params:
                    raise NativeBuildError("Boundary transit changed ordered parameters: " + name)
                record.update(callee=llvm.name(target), argument_indices=list(range(len(params))),
                              call_abi_attributes=self.abi(call, len(params), call=True),
                              callee_signature=llvm.string(self.LLVMPrintTypeToString(target_type)),
                              callee_calling_convention=llvm.LLVMGetFunctionCallConv(target),
                              callee_abi_attributes=self.abi(target, self.LLVMCountParams(target)))
                tail_kind = self.LLVMGetTailCallKind(call)
                if tail_kind in (2, 3):
                    record["tail_requirement"] = "musttail" if tail_kind == 2 else "notail"
                if llvm.LLVMGetNumOperands(ret):
                    if llvm.LLVMGetOperand(ret, 0) != call:
                        raise NativeBuildError("Boundary transit no longer returns the call result: " + name)
                    record["return"] = {"kind": "call_result"}
                elif llvm.LLVMGetTypeKind(llvm.LLVMTypeOf(call)) != 0:
                    raise NativeBuildError("Boundary transit dropped the call result: " + name)
            elif llvm.LLVMGetNumOperands(ret):
                value = llvm.LLVMGetOperand(ret, 0)
                if value in params:
                    record["return"] = {"kind": "parameter", "index": params.index(value)}
                elif self.LLVMIsAConstantInt(value):
                    record["return"] = {"kind": "constant", "llvm": llvm.string(llvm.LLVMPrintValueToString(value))}
                else:
                    raise NativeBuildError("Boundary transit has an unsupported public return value: " + name)
            if expected_calls is not None and (name not in expected_calls or set(expected_calls[name]) != ({record["callee"]} if call else set())):
                raise NativeBuildError("Boundary transit differs from approved scope graph: " + name)
            records[name] = record
            details[name] = {"function": function, "params": params, "call": call, "target": target, "ret": ret}
        return {"schema_version": 1, "functions": records}, details


def _boundary_contract(source_ir: Path, names: list[str], llvm_library: Path, *, expected_calls: dict | None = None) -> dict:
    if not isinstance(names, list) or any(not isinstance(name, str) or not name for name in names) or len(set(names)) != len(names):
        raise NativeBuildError("Invalid boundary transit names")
    if not names:
        return {"schema_version": 1, "functions": {}}
    with _BoundaryIR(source_ir, llvm_library) as parsed:
        return parsed.contract(names, expected_calls)[0]


def _boundary_transit_evidence(final_ir: Path, contract: dict, llvm_library: Path, *, symbol_map: dict | None = None) -> dict:
    if (not isinstance(contract, dict) or contract.get("schema_version") != 1 or not isinstance(contract.get("functions"), dict)):
        raise NativeBuildError("Invalid boundary transit contract")
    expected = json.loads(json.dumps(contract))
    for record in expected["functions"].values():
        if record.get("callee") is not None and symbol_map:
            record["callee"] = symbol_map.get(record["callee"], record["callee"])
    actual = _boundary_contract(final_ir, list(expected["functions"]), llvm_library)
    if actual != expected:
        raise NativeBuildError("Final boundary transit differs from the original reviewed forwarding contract")
    return {"status": "verified" if actual["functions"] else "no_boundaries",
            "functions": {name: {"callee": record["callee"], "ordered_arguments": True,
                                 "return_preserved": True, "signature_preserved": True}
                          for name, record in actual["functions"].items()},
            "qualification": "Parsed final call/parameter/return relation matches the reviewed boundary; not an all-input call-frequency or resistance claim."}


def _isolate_public_boundaries(source: Path, core_output: Path, boundary_output: Path,
                               names: list[str], llvm_library: Path, *, expected_calls: dict | None = None) -> dict:
    """Keep approved forwarding bodies outside pre-VM interprocedural optimization."""
    with _BoundaryIR(source, llvm_library) as parsed:
        llvm, c = parsed.llvm, parsed.ctypes
        contract, details = parsed.contract(names, expected_calls)
        public = parsed.LLVMModuleCreateWithNameInContext(b"antirea-reviewed-boundaries", parsed.context)
        parsed.other_module = public
        llvm.LLVMSetTarget(public, llvm.LLVMGetTarget(parsed.module))
        parsed.LLVMSetDataLayout(public, parsed.LLVMGetDataLayoutStr(parsed.module))
        functions = {}

        def declare(original):
            name = llvm.name(original)
            if name not in functions:
                functions[name] = parsed.LLVMAddFunction(public, name.encode(), llvm.LLVMGlobalGetValueType(original))
                parsed.abi(original, parsed.LLVMCountParams(original), destination=functions[name])
            return functions[name]

        for info in details.values():
            declare(info["function"])
        for name, info in details.items():
            old, function = info["function"], functions[name]
            if parsed.LLVMGetLinkage(old) in (8, 9):
                llvm.LLVMSetVisibility(function, 1)
            else:
                llvm.LLVMSetVisibility(function, parsed.LLVMGetVisibility(old))
            llvm.LLVMSetDLLStorageClass(function, parsed.LLVMGetDLLStorageClass(old))
            for attribute in (b"noinline", b"optnone"):
                kind = llvm.LLVMGetEnumAttributeKindForName(attribute, len(attribute))
                llvm.LLVMAddAttributeAtIndex(function, 0xffffffff, llvm.LLVMCreateEnumAttribute(parsed.context, kind, 0))
            builder = parsed.LLVMCreateBuilderInContext(parsed.context)
            try:
                block = parsed.LLVMAppendBasicBlockInContext(parsed.context, function, b"entry")
                parsed.LLVMPositionBuilderAtEnd(builder, block)
                params = [parsed.LLVMGetParam(function, index) for index in range(len(info["params"]))]
                if info["call"]:
                    target = declare(info["target"])
                    array = (c.c_void_p * len(params))(*params)
                    is_void = llvm.LLVMGetTypeKind(llvm.LLVMTypeOf(info["call"])) == 0
                    value = parsed.LLVMBuildCall2(builder, llvm.LLVMGlobalGetValueType(target), target, array, len(params), b"" if is_void else b"forwarded")
                    parsed.abi(info["call"], len(params), call=True, destination=value)
                    parsed.LLVMSetTailCallKind(value, parsed.LLVMGetTailCallKind(info["call"]))
                elif llvm.LLVMGetNumOperands(info["ret"]):
                    original = llvm.LLVMGetOperand(info["ret"], 0)
                    value = params[info["params"].index(original)] if original in info["params"] else original
                if llvm.LLVMGetNumOperands(info["ret"]):
                    parsed.LLVMBuildRet(builder, value)
                else:
                    parsed.LLVMBuildRetVoid(builder)
            finally:
                parsed.LLVMDisposeBuilder(builder)
        # Replace only reviewed boundary definitions in the business module.
        # An empty declaration carries no inferred constant/returned/readnone
        # facts that could remove a call before VM insertion.
        for name, info in details.items():
            old = info["function"]
            llvm.LLVMSetValueName2(old, b"", 0)
            declaration = parsed.LLVMAddFunction(parsed.module, name.encode(), llvm.LLVMGlobalGetValueType(old))
            parsed.abi(old, len(info["params"]), destination=declaration)
            if parsed.LLVMGetLinkage(old) in (8, 9):
                llvm.LLVMSetVisibility(declaration, 1)
            parsed.LLVMReplaceAllUsesWith(old, declaration)
            parsed.LLVMDeleteFunction(old)
        for module, path in ((parsed.module, core_output), (public, boundary_output)):
            parsed.verify(module)
            with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(llvm.string(llvm.LLVMPrintModuleToString(module)))
    return {"contract": contract, "method": "parsed_pure_forwarder_module_isolation",
            "qualification": "Only reviewed scalar call/return bodies reconstructed; no source, baseline, global, ctor, alias or COMDAT copies."}


def _retain_database_scope(source, output, selected, llvm_library):
    """Retain selected definitions only in the protection IR, never rewrite source.

    This is an LLVM-C parsed attribute/linkage edit, not text replacement.
    Baseline and original-reference compilation do not use this adjusted IR.
    """
    import ctypes
    from .swift_frontend import _LLVM
    llvm = _LLVM(llvm_library)
    context, module = llvm.LLVMContextCreate(), ctypes.c_void_p()
    error = ctypes.c_void_p()
    changes, callsite_changes = [], []
    try:
        data = Path(source).read_bytes()
        buffer = llvm.LLVMCreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"compile-database-scope")
        if llvm.LLVMParseIRInContext(context, buffer, ctypes.byref(module), ctypes.byref(error)):
            raise NativeBuildError("LLVM parsing failed: " + llvm.string(error.value))
        get_attribute = llvm.dll.LLVMGetEnumAttributeAtIndex
        get_attribute.restype, get_attribute.argtypes = ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint]
        get_linkage = llvm.dll.LLVMGetLinkage
        get_linkage.restype, get_linkage.argtypes = ctypes.c_uint, [ctypes.c_void_p]
        get_call_attribute = llvm.dll.LLVMGetCallSiteEnumAttribute
        get_call_attribute.restype, get_call_attribute.argtypes = ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint]
        remove_call_attribute = llvm.dll.LLVMRemoveCallSiteEnumAttribute
        remove_call_attribute.restype, remove_call_attribute.argtypes = None, [ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint]
        found = set()
        function = llvm.LLVMGetFirstFunction(module)
        while function:
            name = llvm.name(function)
            if name in selected:
                if llvm.LLVMIsDeclaration(function) or llvm.LLVMGetFunctionCallConv(function) != 0:
                    raise NativeBuildError("Selected compilation-database function needs a defined C calling convention: " + name)
                removed = []
                for attribute in (b"alwaysinline", b"inlinehint", b"optnone"):
                    kind = llvm.LLVMGetEnumAttributeKindForName(attribute, len(attribute))
                    if get_attribute(function, 0xffffffff, kind):
                        removed.append(attribute.decode("ascii"))
                        llvm.LLVMRemoveEnumAttributeAtIndex(function, 0xffffffff, kind)
                kind = llvm.LLVMGetEnumAttributeKindForName(b"noinline", 8)
                llvm.LLVMAddAttributeAtIndex(function, 0xffffffff, llvm.LLVMCreateEnumAttribute(context, kind, 0))
                linkage = get_linkage(function)
                # Stop LLVM GlobalOpt from promoting a private selected C helper
                # to an unsupported fastcc helper after scope analysis.
                if linkage in (8, 9):
                    llvm.LLVMSetLinkage(function, 0)
                    llvm.LLVMSetVisibility(function, 1)
                changes.append({"function": name, "removed_attributes": removed, "added_attributes": ["noinline"],
                                "original_linkage": linkage,
                                "linkage_change": "external_hidden" if linkage in (8, 9) else "unchanged"})
                found.add(name)
            block = llvm.LLVMGetFirstBasicBlock(function)
            while block:
                instruction = llvm.LLVMGetFirstInstruction(block)
                while instruction:
                    if llvm.LLVMGetInstructionOpcode(instruction) in (5, 45):
                        target = llvm.name(llvm.LLVMGetCalledValue(instruction))
                        if target in selected:
                            removed = []
                            for attribute in (b"alwaysinline", b"inlinehint"):
                                kind = llvm.LLVMGetEnumAttributeKindForName(attribute, len(attribute))
                                if get_call_attribute(instruction, 0xffffffff, kind):
                                    remove_call_attribute(instruction, 0xffffffff, kind)
                                    removed.append(attribute.decode())
                            if removed:
                                callsite_changes.append({"caller": name, "callee": target, "removed_attributes": removed})
                    instruction = llvm.LLVMGetNextInstruction(instruction)
                block = llvm.LLVMGetNextBasicBlock(block)
            function = llvm.LLVMGetNextFunction(function)
        if found != set(selected):
            raise NativeBuildError("Selected scope disappeared before protection attributes were applied")
        if llvm.LLVMVerifyModule(module, 2, ctypes.byref(error)):
            raise NativeBuildError("Adjusted protection IR failed verification: " + llvm.string(error.value))
        text = llvm.string(llvm.LLVMPrintModuleToString(module))
        with Path(output).open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
    finally:
        if module:
            llvm.LLVMDisposeModule(module)
        llvm.LLVMContextDispose(context)
        llvm.close()
    return {"input": {"path": str(source), "sha256": _hash(Path(source))},
            "output": {"path": str(output), "sha256": _hash(Path(output))}, "functions": changes,
            "callsite_adjustments": callsite_changes,
            "qualification": "Protection IR retention only; source/preprocessor flags and original reference are unchanged."}


def _write(path: Path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def _body(ir: str, name: str, *, allow_internal: bool = False) -> str:
    match = re.search(r"^define\s+([^\n]*)@" + re.escape(name) + r"\([^\n]*\)[^\n]*\{\n(.*?)^\}", ir, re.M | re.S)
    if match is None or (not allow_internal and re.search(r"\b(internal|private)\b", match.group(1))):
        raise NativeBuildError(f"Selected exported C ABI definition not found: {name}")
    return match.group(2)


def _layer_evidence(ir: str, name: str) -> dict:
    body = _body(ir, name, allow_internal=True)
    return {"function": name, "requested_passes": ["fla", "sub", "co"],
            "fla_dispatcher": "kagura.loop:" in body and "switch i32" in body,
            "substitution_instructions": len(re.findall(r"^\s+%sub\.[^\n]*=", body, re.M)),
            "constant_obfuscation_instructions": len(re.findall(r"^\s+%co\.[^\n]*=", body, re.M)),
            "qualification": "Structural evidence; individual passes may not apply to every function shape."}


def _vm_evidence(ir: str, functions: list[str], dispatcher: str) -> dict:
    result, used = {}, set()
    for name in functions:
        body = _body(ir, name, allow_internal=True)
        calls = re.findall(r"\bcall\s+i64\s+@" + re.escape(dispatcher)
                           + r"\(ptr\s+(?:nonnull\s+)?@(kagura_vm_bc_[A-Za-z0-9_]+),\s*i32\s+(\d+)", body)
        if len(calls) != 1:
            raise NativeBuildError(f"Selected function lacks exactly one supported VM call: {name}")
        blob, size = calls[0]
        declaration = re.search(r"^@" + re.escape(blob) + r' = private constant \[(\d+) x i8\] c"([^"\n]*)"', ir, re.M)
        if declaration is None or int(size) <= 0 or int(size) != int(declaration[1]) or len(diversify.llvm_bytes(declaration[2])) != int(size):
            raise NativeBuildError(f"Missing/nonmatching bytecode blob for {name}")
        if blob in used:
            raise NativeBuildError("Selected VM wrappers unexpectedly share bytecode")
        used.add(blob)
        result[name] = {"virtualized": True, "dispatcher": dispatcher,
                        "bytecode_global": blob, "bytecode_size": int(size)}
    all_blobs = set(re.findall(r"^@(kagura_vm_bc_[A-Za-z0-9_]+) =", ir, re.M))
    if used != all_blobs:
        raise NativeBuildError("VM bytecode exists outside the explicit function selection")
    return result


def _select_scope(project: dict, raw_ir: Path, canonical_ir: Path) -> dict:
    """Inspect canonicalized pre-optimization IR; never infer data encryption."""
    if project.get("language") == "llvm_ir":
        return {"mode": "frontend_verified_llvm_closure", "status": "ready",
                "selected_functions": list(project["ir_selected_functions"]),
                "exported_functions": list(project["functions"]), "scope_plan": None,
                "public_boundaries": [], "global_data_protection": "not_applied",
                "qualification": "Explicit frontend selection; frontend closure proof and original-runtime comparison are separate requirements."}
    if not project.get("scope_policy"):
        return {"mode": "explicit", "status": "ready",
                "selected_functions": list(project["functions"]),
                "exported_functions": list(project["functions"]), "scope_plan": None,
                "public_boundaries": [], "global_data_protection": "not_applied"}
    policy_path = _no_links(Path(project["scope_policy"]))
    if _hash(policy_path) != project["scope_policy_sha256"]:
        raise NativeBuildError("Scope policy changed after inspection")
    policy = _read_json(policy_path)
    plan = scope.analyze_scope([canonical_ir], policy, mode="expanded")
    selected = plan.get("selected_functions", [])
    reviewed_entries = {name for name, state in plan["boundary_functions"].items()
                        if state.get("reached") and not state.get("issues")}
    uncovered_exports = set(project["functions"]) - set(selected) - reviewed_entries
    if uncovered_exports:
        plan["unresolved"].append({"kind": "uncovered_export", "symbol": ",".join(sorted(uncovered_exports)),
                                   "detail": "Each export must be selected or a reached reviewed public boundary.",
                                   "relevant": True, "severity": "review"})
        plan["status"] = "needs_review"
    symbol_issues = [name for name in selected if not SYMBOL.fullmatch(name)
                     or name.startswith(("kagura_", "antirea_dispatch_"))]
    mapping_required = (symbol_issues if project.get("compilation_database")
                        and not any(name.startswith(("kagura_", "__kg_", "antirea_dispatch_", "antirea_cpp_fn_"))
                                    for name in selected) else [])
    if symbol_issues and not mapping_required:
        plan["unresolved"].append({"kind": "unsupported_native_scope_symbol", "symbol": ",".join(symbol_issues),
                                   "detail": "Native VM allowlist requires exact ordinary C symbol names.",
                                   "relevant": True, "severity": "review"})
        plan["status"] = "needs_review"
    if not selected or len(selected) > 64:
        plan["unresolved"].append({"kind": "native_scope_size", "symbol": "",
                                   "detail": "Native build requires 1..64 selected functions; selection was not truncated.",
                                   "relevant": True, "severity": "review"})
        plan["status"] = "needs_review"
    return {"mode": "expanded",
            "status": "requires_symbol_mapping" if plan["status"] == "ready" and mapping_required else plan["status"],
            "selected_functions": selected, "symbol_mapping_required": mapping_required,
            "exported_functions": list(project["functions"]), "scope_plan": plan,
            "policy_path": str(policy_path), "policy_sha256": project["scope_policy_sha256"],
            "raw_ir": {"path": str(raw_ir), "sha256": _hash(raw_ir)},
            "canonical_ir": {"path": str(canonical_ir), "sha256": _hash(canonical_ir)},
            "analysis_stage": "linked frontend IR; mem2reg only before general optimization/protection",
            "public_boundaries": sorted(set(plan["boundary_functions"]) - set(selected)),
            "global_data_protection": "not_applied",
            "qualification": "Supported structural graph expansion, not semantic completeness or data encryption."}


def _manifest_vm_evidence(ir: str, functions: list[str], manifest: dict) -> dict:
    if manifest.get("engine_mode") != "per_function_indirect":
        return _vm_evidence(ir, functions, manifest["dispatcher_symbol"])
    try:
        evidence = diversify.inspect_vm_bindings(ir, manifest)
    except (ValueError, KeyError, TypeError) as exc:
        raise NativeBuildError(f"Invalid per-function VM binding: {exc}") from exc
    if set(evidence) != set(functions):
        raise NativeBuildError("Per-function VM bindings differ from the complete selected scope")
    return evidence


def _runtime_evidence(ir: str, dispatchers: list[str]) -> dict:
    if (not dispatchers or len(set(dispatchers)) != len(dispatchers)
            or any(not re.fullmatch(r"antirea_dispatch_[0-9a-f]{16}", name) for name in dispatchers)):
        raise NativeBuildError("Unexpected or duplicate generated dispatcher names")
    engines = {name: _layer_evidence(ir, name) for name in dispatchers}
    if any(not item["fla_dispatcher"] or not item["substitution_instructions"]
           or not item["constant_obfuscation_instructions"] for item in engines.values()):
        raise NativeBuildError("A generated runtime lacks required FLA/SUB/CO structural evidence")
    if len(engines) == 1:
        return next(iter(engines.values()))
    return {"functions": dispatchers, "engines": engines, "engine_count": len(engines),
            "requested_passes": ["fla", "sub", "co"], "fla_dispatcher": True,
            "substitution_instructions": sum(item["substitution_instructions"] for item in engines.values()),
            "constant_obfuscation_instructions": sum(item["constant_obfuscation_instructions"] for item in engines.values()),
            "qualification": "Every engine passed separately; instruction counts are totals, not resistance evidence."}


def _boundary_evidence(ir: str, names: list[str], dispatcher: str | list[str], slots: list[str] | None = None) -> dict:
    dispatchers = [dispatcher] if isinstance(dispatcher, str) else dispatcher
    references = ["kagura_vm_execute", *dispatchers, *(slots or [])]
    evidence = {}
    for name in names:
        body = _body(ir, name, allow_internal=True)
        if "@kagura_vm_bc_" in body or any(re.search(r"@" + re.escape(symbol) + r"\b", body) for symbol in references):
            raise NativeBuildError(f"Reviewed public boundary unexpectedly virtualized: {name}")
        evidence[name] = {"defined": True, "virtualized": False,
                          "qualification": "No VM call in this body; source forwarding review is in scope_plan."}
    return evidence


def _toolchain(workspace: Path) -> tuple[dict, dict]:
    path = _no_links(workspace / ".tools/kagura-toolchain.json")
    if not path.is_file():
        raise NativeBuildError("Missing .tools/kagura-toolchain.json; bootstrap Kagura explicitly first")
    config = _read_json(path)
    if config.get("kagura_commit") != diversify.PINNED_COMMIT or config.get("target") != TARGET:
        raise NativeBuildError("Unsupported pinned Kagura toolchain/target")
    config["llvm_link"] = str(Path(config["llvm_root"]) / "bin/llvm-link.exe")
    config["scope_optimizer"] = str(Path(config["llvm_root"]) / "bin/opt.exe")
    config["llvm_library"] = str(Path(config["llvm_root"]) / "bin/LLVM-C.dll")
    config["lld_link"] = str(Path(config["llvm_root"]) / "bin/lld-link.exe")
    config["runtime_source"] = str(Path(config["kagura_source"]) / "runtime/core/vm_interpreter.c")
    config["opcode_source"] = str(Path(config["kagura_source"]) / "include/kagura/VMOpcodes.def")
    hashes = {str(path): _hash(path)}
    for key in ("clang", "clangxx", "optimizer", "llvm_link", "scope_optimizer", "llvm_library", "lld_link", "runtime_source", "opcode_source", "developer_shell"):
        tool = _no_links(Path(config[key]))
        if not tool.is_file():
            raise NativeBuildError(f"Missing toolchain input: {key}")
        hashes[str(tool)] = _hash(tool)
    if hashes[config["optimizer"]] != config.get("optimizer_sha256"):
        raise NativeBuildError("Kagura optimizer hash differs from toolchain manifest")
    return config, hashes


def build_project(project_path: Path, output_dir: Path, *, workspace_root: Path, seed: int = 1729) -> dict:
    return _build_project(inspect_project(project_path, workspace_root=workspace_root),
                          output_dir, workspace_root=workspace_root, seed=seed)


def build_llvm_project(ir_path: Path, output_dir: Path, *, workspace_root: Path,
                       name: str, selected_functions: list[str], exported_functions: list[str],
                       seed: int = 1729, input_hashes: dict[str, str]) -> dict:
    """Fixed private LLVM handoff for trusted source frontends, not arbitrary flags.

    The frontend must establish the owned source/IR provenance and complete core
    helper closure, then compare against its original language runtime separately.
    This API records the explicit selection and applies the existing native gates.
    It does not make precompiled IR a public source-manifest language.
    """
    workspace, ir = _no_links(Path(workspace_root)), _no_links(Path(ir_path))
    if (not workspace.is_dir() or not ir.is_relative_to(workspace / ".runs")
            or any(p.casefold() in {"rea-analysis-reports", "attackerfolder", "defense-loop"} for p in ir.parts)
            or ir.suffix != ".ll" or not ir.is_file() or ir.stat().st_size > 32 * 1024 * 1024):
        raise NativeBuildError("Frontend LLVM input must be an owned private .runs/*.ll file <=32 MiB")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", name):
        raise NativeBuildError("Frontend LLVM project requires a bounded ordinary name")
    for label, values in (("selected", selected_functions), ("exported", exported_functions)):
        if (not isinstance(values, list) or not 1 <= len(values) <= 64
                or any(not isinstance(value, str) or not SYMBOL.fullmatch(value)
                       or value.startswith(("kagura_", "antirea_dispatch_")) for value in values)
                or len(set(values)) != len(values)):
            raise NativeBuildError(f"Frontend LLVM {label} functions must be unique ordinary symbols")
    if not set(exported_functions) <= set(selected_functions):
        raise NativeBuildError("Every frontend LLVM export must be selected for protection")
    if not isinstance(input_hashes, dict) or not 1 <= len(input_hashes) <= 4096:
        raise NativeBuildError("Frontend source/IR provenance hashes are required")
    hashes = {}
    for value, digest in input_hashes.items():
        if not isinstance(value, str) or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise NativeBuildError("Invalid frontend provenance entry")
        source = _no_links(Path(value))
        if (not source.is_relative_to(workspace) or not source.is_file()
                or any(p.casefold() in {"rea-analysis-reports", "attackerfolder"} for p in source.parts)
                or _hash(source) != digest):
            raise NativeBuildError("Frontend provenance input changed or escaped the owned workspace")
        hashes[str(source)] = digest
    if str(ir) not in hashes or hashes[str(ir)] != _hash(ir):
        raise NativeBuildError("Frontend LLVM handoff must include its exact IR hash")
    project = {"schema_version": 1, "name": name, "language": "llvm_ir", "project_root": str(ir.parent),
               "sources": [str(ir)], "target": TARGET, "artifact": "shared_library",
               "functions": list(exported_functions), "exported_functions": list(exported_functions),
               "ir_selected_functions": list(selected_functions), "include_dirs": [], "defines": {},
               "scope_policy": None, "input_hashes": hashes, "blockers": [],
               "route_status": "available", "experimental": True,
               "limitations": ["Frontend-supplied private LLVM; original-language equivalence is not established by this builder."]}
    return _build_project(project, output_dir, workspace_root=workspace, seed=seed)


def _run_build_command(program, args, *, output, records, stop, environment, timeout=600, cwd=None):
    """One internal execution journal for source, object and caller-owned link steps.

    Not a public command API: only authored backend recipes invoke this helper.
    Preserve historical argv/cwd/log numbering and failure/cleanup semantics.
    """
    directory = output if cwd is None else _no_links(Path(cwd))
    result = run_logged([str(program), *map(str, args)], directory,
                        output / "logs" / f"{len(records) + 1:03d}",
                        timeout=timeout, cancel_file=stop, env=environment)
    result["cwd"] = str(directory)
    records.append(result)
    if result.get("cancelled"):
        raise NativeBuildError("Build cancelled by defense STOP marker")
    if result.get("returncode") != 0 or result.get("timed_out") or result.get("error"):
        raise NativeBuildError(f"Build command failed; inspect {result['stderr']}")
    cleanup = result.get("cleanup", {})
    if not cleanup.get("parent_exit_confirmed") or cleanup.get("status") != "assigned_job_empty" or cleanup.get("job_handle_closed") is not True:
        raise NativeBuildError("Compiler process cleanup could not be verified")
    return Path(result["stdout"]).read_text(encoding="utf-8", errors="replace")[:65536]


def _build_project(project: dict, output_dir: Path, *, workspace_root: Path, seed: int) -> dict:
    """Build baseline and protected DLLs; never load or evaluate either library.

    Preflight errors raise NativeBuildError. After output creation, failures are
    retained in report.json and returned as failed/cancelled, never as success.
    """
    if project["blockers"]:
        raise NativeBuildError("; ".join(project["blockers"]))
    if os.name != "nt":
        raise NativeBuildError("Native source build currently requires a Windows host")
    if type(seed) is not int or not 1 <= seed <= 2147483647:
        raise NativeBuildError("seed must be an integer in 1..2147483647")
    workspace = _no_links(Path(workspace_root))
    output = _no_links(Path(output_dir))
    if not workspace.is_dir() or not output.is_relative_to(workspace / ".runs"):
        raise NativeBuildError("Output must be a fresh descendant of workspace/.runs")
    if output == workspace / ".runs" or output.exists() or output.is_relative_to(Path(project["project_root"])):
        raise NativeBuildError("Output must be fresh and outside the source project")
    if "rea-analysis-reports" in {p.lower() for p in workspace.parts}:
        raise NativeBuildError("Incoming report roots cannot be build workspaces")
    toolchain, tool_hashes = _toolchain(workspace)
    database = project.get("compilation_database")
    selection_environment = os.environ.copy()
    if database:
        from . import compile_database
        verified_header_inventory = compile_database.verify_snapshot(database, return_trusted_inventory=True)
        if _compile_database_environment(toolchain) != project["compiler_environment_metadata"]:
            raise NativeBuildError("Installed compiler environment changed after inspection")
        metadata = project["compiler_environment_metadata"]
        if _environment_selection_inputs(selection_environment,
                referenced_names=metadata["metadata"]["selection_context"]["referenced_environment_names"]) != metadata["environment_selection_inputs"]:
            raise NativeBuildError("ambient compiler selection environment changed after inspection")
        for value, expected in project["compiler_inputs"].items():
            pinned_input = _no_links(Path(value))
            if not pinned_input.is_file() or _hash(pinned_input) != expected:
                raise NativeBuildError("Compilation-database compiler input changed after inspection: " + value)
        tool_hashes.update(project["compiler_inputs"])
        override_names = {"CL", "_CL_", "LINK", "_LINK_", "CCC_OVERRIDE_OPTIONS", "CPATH",
                          "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH",
                          "LIBRARY_PATH", "GCC_EXEC_PREFIX", "COMPILER_PATH"}
        if any(name.upper() in override_names and value for name, value in os.environ.items()):
            raise NativeBuildError("Compilation-database build refuses unrecorded ambient compiler override variables")
    from antirea import swift_frontend
    for module_path in (Path(__file__), Path(diversify.__file__), Path(hardening.__file__), Path(scope.__file__),
                        Path(cpp_symbols.__file__), Path(swift_frontend.__file__), Path(native_objects.__file__)):
        tool_hashes[str(module_path.resolve())] = _hash(module_path)
    stop = workspace / ".runs/defense-loop/STOP"
    if stop.exists():
        raise NativeBuildError("Defense STOP marker exists")
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    report = {"schema_version": 1, "coverage_schema_version": 2, "status": "building", "project": project,
              "started_utc": datetime.now(timezone.utc).isoformat(), "seed": seed,
              "output_dir": str(output), "commands": [], "toolchain": toolchain,
              "tool_hashes": tool_hashes, "functional_evaluation": "not_performed",
              "performance_evaluation": "not_performed", "external_attack_evaluation": "not_performed",
              "limitations": list(LIMITATIONS)}
    process_env = selection_environment

    def run(program, *args, timeout=600, cwd=None):
        return _run_build_command(program, args, output=output, records=report["commands"],
                                  stop=stop, environment=process_env, timeout=timeout, cwd=cwd)

    try:
        # Fixed SDK environment initialization, not a user/project shell hook.
        # Only compiler search-path variables are exported, never arbitrary env secrets.
        powershell = shutil.which("powershell.exe")
        if powershell is None:
            raise NativeBuildError("Windows PowerShell is required for installed Visual Studio SDK initialization")
        sdk_names = ("INCLUDE", "LIB", "LIBPATH", "PATH", "VCINSTALLDIR", "VCToolsInstallDir",
                     "WindowsSdkDir", "WindowsSDKVersion", "UniversalCRTSdkDir", "UCRTVersion")
        process_env["ANTIREA_NATIVE_DEVSHELL"] = toolchain["developer_shell"]
        selection_args = ""
        if database:
            selection_context = project["compiler_environment_metadata"]["metadata"]["selection_context"]
            process_env["ANTIREA_NATIVE_VSINSTALL"] = selection_context["installation"]
            process_env["ANTIREA_NATIVE_VSWHERE"] = selection_context["vswhere"]
            # Explicit parameter set avoids Launch-VsDevShell's Default -> Latest
            # -> interactive List fallback if installation discovery fails.
            selection_args = " -VsInstallationPath $env:ANTIREA_NATIVE_VSINSTALL -VsWherePath $env:ANTIREA_NATIVE_VSWHERE"
        sdk_script = ("$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); "
                      "& $env:ANTIREA_NATIVE_DEVSHELL" + selection_args + " -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null; "
                      "$nativeSdk=@{}; foreach($nativeKey in @('" + "','".join(sdk_names) + "')) { "
                      "$nativeValue=[Environment]::GetEnvironmentVariable($nativeKey); "
                      "if($nativeValue) { $nativeSdk[$nativeKey]=$nativeValue } }; "
                      "$nativeSdk | ConvertTo-Json -Compress")
        sdk_env = json.loads(run(powershell, "-NoProfile", "-NonInteractive", "-Command", sdk_script, timeout=60))
        process_env.pop("ANTIREA_NATIVE_DEVSHELL", None)
        process_env.pop("ANTIREA_NATIVE_VSINSTALL", None)
        process_env.pop("ANTIREA_NATIVE_VSWHERE", None)
        if not isinstance(sdk_env, dict) or set(sdk_env) - set(sdk_names) or not sdk_env.get("INCLUDE") or not sdk_env.get("LIB"):
            raise NativeBuildError("Visual Studio SDK environment is incomplete")
        # Windows environment names are case-insensitive; avoid duplicate Path/PATH.
        for key, value in sdk_env.items():
            for existing in list(process_env):
                if existing.upper() == key.upper():
                    del process_env[existing]
            process_env[key] = value
        report["sdk_environment"] = sdk_env
        original_objects, original_signature_modules, original_units = [], [], []
        if database:
            header_inventory = verified_header_inventory
            approved_roots = [Path(value) for value in database["input_roots"]]
            approved_roots += [Path(entry["path"]) for entry in header_inventory["roots"]]
            for value in sdk_env["INCLUDE"].split(";"):
                if value and not any(_no_links(Path(value)).is_relative_to(root) for root in approved_roots):
                    raise NativeBuildError("Installed SDK INCLUDE contains an unapproved header search root: " + value)
            dependency_hashes = {entry["path"]: entry["sha256"]
                                 for entry in database["inputs"]["files"] + header_inventory["files"]}
            _write(output / "compile-database-inputs.json",
                   {"project": database["inputs"], "trusted_headers": header_inventory})
            _write(output / "compile-database-plan.json", database)
            raw_database = Path(database["database"]).read_bytes()
            if hashlib.sha256(raw_database).hexdigest() != database["database_sha256"]:
                raise NativeBuildError("Raw compilation database changed before private snapshot")
            raw_snapshot = output / "compile-database-raw.json"
            with raw_snapshot.open("xb") as stream:
                stream.write(raw_database)
            report.update(backend="compile_database_native", compilation_database=database,
                          compilation_database_source={"path": str(raw_snapshot), "sha256": _hash(raw_snapshot)},
                          compiler_environment_metadata=project["compiler_environment_metadata"],
                          header_inventory={"path": str(output / "compile-database-inputs.json"),
                                            "sha256": _hash(output / "compile-database-inputs.json")},
                          dependency_evidence=[], raw_ir_assembly_checks=[], original_reference_evaluation="not_performed")

            def database_action(action):
                if action.get("shell") is not False or action.get("executed") is not False:
                    raise NativeBuildError("Invalid authored compilation-database action")
                run(action["argv"][0], *action["argv"][1:], cwd=action["cwd"])
                return len(report["commands"]) - 1
        report["compiler_version"] = run(toolchain["clang"], "--version", timeout=30)
        if f"clang version {toolchain['llvm_version']}" not in report["compiler_version"]:
            raise NativeBuildError("Clang version differs from pinned toolchain manifest")
        modules = []
        for index, source_value in enumerate(project["sources"]):
            source, module = Path(source_value), output / f"source-{index:03d}.ll"
            if database:
                unit = database["translation_units"][index]
                dependency_file = output / f"source-{index:03d}.d"
                dependency_command = database_action(compile_database.dependency_scan_argv(database, index, dependency_file))
                dependencies = compile_database.parse_dependencies(dependency_file, unit["directory"])
                if not dependencies or source not in {Path(value) for value in dependencies}:
                    raise NativeBuildError("Dependency scan omitted its source")
                for value in dependencies:
                    dependency = _no_links(Path(value))
                    if str(dependency) not in dependency_hashes or _hash(dependency) != dependency_hashes[str(dependency)]:
                        raise NativeBuildError("Consumed dependency is outside the pinned input closure or changed: " + str(dependency))
                report["dependency_evidence"].append({"source": str(source), "command_index": dependency_command,
                    "path": str(dependency_file), "sha256": _hash(dependency_file), "files": list(map(str, dependencies)),
                    "status": "matched_project_or_trusted_header_inventory"})
                database_action(compile_database.compile_ir_argv(database, index, module))
                report["raw_ir_assembly_checks"].append(_reject_assembly_before_original_codegen(
                    module, Path(toolchain["llvm_root"]) / "bin/LLVM-C.dll"))
                original_object = output / f"original-{index:03d}.obj"
                original_signature = output / f"original-signature-{index:03d}.ll"
                object_index = database_action(compile_database.original_compile_argv(database, index, original_object))
                signature_index = database_action(compile_database.original_signature_ir_argv(database, index, original_signature))
                original_objects.append(original_object)
                original_signature_modules.append(original_signature)
                original_units.append({"source": str(source), "entry_sha256": unit["entry_sha256"],
                    "source_operand": unit["source_operand"],
                    "compiler": unit["compiler"]["path"], "compiler_sha256": unit["compiler"]["sha256"],
                    "cwd": unit["directory"], "object_command_index": object_index,
                    "signature_ir_command_index": signature_index, "object_path": str(original_object),
                    "signature_ir_path": str(original_signature)})
            elif project["language"] == "llvm_ir":
                # Parse and normalize with the pinned reader; no user-supplied
                # compiler flags, libraries, shell hooks or target execution.
                run(toolchain["llvm_link"], "-S", source, "-o", module)
            elif project["language"] == "rust":
                rustc = shutil.which("rustc")
                if rustc is None:
                    raise NativeBuildError("rustc is not installed; no automatic installation is performed")
                rustc = str(_no_links(Path(rustc)))
                report["rustc_sha256"] = _hash(Path(rustc))
                tool_hashes[rustc] = report["rustc_sha256"]
                version = run(rustc, "-vV", timeout=30)
                llvm = re.search(r"^LLVM version: (\d+\.\d+\.\d+)", version, re.M)
                if llvm is None or llvm[1].split(".")[:2] != toolchain["llvm_version"].split(".")[:2]:
                    raise NativeBuildError("Rust LLVM major/minor does not match the pinned LLVM reader")
                report["rust_toolchain"] = {"rustc": rustc, "version": version,
                    "llvm_patch_match": llvm[1] == toolchain["llvm_version"],
                    "compatibility": "Experimental: reader, selected VM coverage and separate functional gates required"}
                run(rustc, "--crate-name", "antirea_native_module", "--crate-type=lib", "--edition=2021",
                    "--emit=llvm-ir", "-Copt-level=0" if project["scope_policy"] else "-Copt-level=1", "-Cpanic=abort", "-Ccodegen-units=1",
                    "--target", TARGET, source, "-o", module)
                reference_compiler, reference_compiler_sha = rustc, report["rustc_sha256"]
            else:
                is_c = source.suffix.lower() == ".c"
                flags = ["-std=c11" if is_c else "-std=c++17", "-O1", "-fno-inline", "-fno-exceptions"]
                if project["scope_policy"]:
                    flags[1:2] = ["-O0", "-Xclang", "-disable-O0-optnone"]
                if not is_c:
                    flags.append("-fno-rtti")
                for include in project["include_dirs"]:
                    flags.extend(["-I", include])
                flags.extend(f"-D{key}={value}" for key, value in sorted(project["defines"].items()))
                run(toolchain["clang"] if is_c else toolchain["clangxx"], *flags,
                    "-target", TARGET, "-S", "-emit-llvm", source, "-o", module)
                reference_compiler = toolchain["clang"] if is_c else toolchain["clangxx"]
                reference_compiler_sha = tool_hashes[reference_compiler]
            # Direct C/C++/Rust routes carry an independent source-compiled original
            # reference; the raw-IR assembly gate precedes its object codegen.
            if not database and project["language"] != "llvm_ir":
                assembly_check, unit, object_path, signature_path = _emit_direct_original_reference(
                    project, index, source, module, output, compiler=reference_compiler,
                    compiler_sha256=reference_compiler_sha,
                    llvm_library=Path(toolchain["llvm_root"]) / "bin/LLVM-C.dll",
                    run=run, commands=report["commands"])
                report.setdefault("raw_ir_assembly_checks", []).append(assembly_check)
                original_objects.append(object_path)
                original_signature_modules.append(signature_path)
                original_units.append(unit)
            modules.append(module)
        before = output / "module.before.ll"
        raw = output / "module.raw.ll" if project["scope_policy"] or database else before
        run(toolchain["llvm_link"], "-S", *modules, "-o", raw)
        source_module_link_record = report["commands"][-1]
        canonicalize_record = None
        if project["scope_policy"] or database:
            run(toolchain["scope_optimizer"], "-passes=mem2reg", "-S", raw, "-o", before)
            canonicalize_record = report["commands"][-1]
        before_text = before.read_text(encoding="utf-8")
        triple = re.search(r'^target triple = "([^"]+)"$', before_text, re.M)
        if triple is None or not re.fullmatch(r"x86_64-pc-windows-msvc(?:[0-9]+(?:\.[0-9]+)*)?", triple[1]):
            raise NativeBuildError("LLVM module target differs from the requested Windows target")
        report["actual_llvm_target"] = triple[1]
        for function in project["functions"]:
            _body(before_text, function)
        selection = _select_scope(project, raw, before)
        report["scope"] = selection
        if selection["status"] not in {"ready", "requires_symbol_mapping"}:
            _write(output / "scope.json", selection)
            raise NativeBuildError("Expanded protection scope needs review; see scope.json")
        selected_functions = selection["selected_functions"]
        llvm_library = Path(toolchain["llvm_root"]) / "bin/LLVM-C.dll"
        expected_calls = (selection.get("scope_plan") or {}).get("graph", {}).get("calls")
        # Always derive the source contract before protection-only renaming.
        # This original contract and module.before.ll remain unchanged.
        boundary_contract = _boundary_contract(before, selection["public_boundaries"], llvm_library,
                                                expected_calls=expected_calls)
        symbol_mapping, mapping_descriptor, symbol_map = None, None, {}
        protection_source = before
        if selection["status"] == "requires_symbol_mapping":
            if not database or canonicalize_record is None:
                raise NativeBuildError("C++ helper mapping requires a closed compilation-database DLL build")
            if any(not SYMBOL.fullmatch(name) for name in selection["public_boundaries"]):
                raise NativeBuildError("This C++ mapping route preserves ordinary public boundary names only")
            _write(output / "scope.pre-map.json", selection)
            link_boundary = cpp_symbols.make_link_boundary(
                workspace=workspace, build_dir=output, database=database, module_paths=modules,
                raw_ir=raw, input_ir=before, module_link_record=source_module_link_record,
                canonicalize_record=canonicalize_record, toolchain=toolchain, exports=project["functions"])
            mapped_bytes, symbol_mapping = cpp_symbols.remap_protection_symbols(
                before.read_bytes(), selected_symbols=selected_functions, exported_symbols=project["functions"],
                llvm_library=llvm_library, link_boundary=link_boundary, workspace_root=workspace)
            symbol_map = {source: row["protected_symbol"] for source, row in symbol_mapping["functions"].items()}
            if any(symbol_map.get(name, name) != name
                   for name in [*project["functions"], *selection["public_boundaries"]]):
                raise NativeBuildError("Public C ABI and reviewed boundary names must remain unchanged")
            protection_source = output / "module.symbol-mapped.ll"
            with protection_source.open("xb") as stream:
                stream.write(mapped_bytes)
            mapping_path = output / "cpp-symbol-mapping.json"
            _write(mapping_path, symbol_mapping)
            mapping_descriptor = {"path": str(mapping_path), "sha256": _hash(mapping_path)}
            selection["source_selected_functions"] = list(selected_functions)
            selected_functions = symbol_mapping["protected_selected_functions"]
            selection.update(status="ready", selected_functions=selected_functions,
                             symbol_mapping_path=str(mapping_path))
            report["cpp_symbol_mapping"] = symbol_mapping
            report["cpp_symbol_mapping_descriptor"] = mapping_descriptor
        _write(output / "scope.json", selection)
        selected_ir_text = protection_source.read_text(encoding="utf-8")
        for function in selected_functions:
            _body(selected_ir_text, function, allow_internal=True)
        # Preserve the entire common contract (including future callee ABI
        # fields); rename only its explicit callee identity, never public keys.
        mapped_boundary_contract = json.loads(json.dumps(boundary_contract))
        for row in mapped_boundary_contract["functions"].values():
            if row.get("callee") is not None:
                row["callee"] = symbol_map.get(row["callee"], row["callee"])
        mapped_expected_calls = ({symbol_map.get(caller, caller): [symbol_map.get(callee, callee) for callee in callees]
                                  for caller, callees in expected_calls.items()}
                                 if expected_calls is not None else None)
        if symbol_mapping is not None:
            _boundary_transit_evidence(protection_source, boundary_contract, llvm_library, symbol_map=symbol_map)
        boundary_ir = None
        business_ir = protection_input = protection_source
        if selection["public_boundaries"]:
            business_ir = protection_input = output / "module.protection-business.ll"
            boundary_ir = output / "module.public-boundaries.ll"
            report["public_boundary_isolation"] = _isolate_public_boundaries(
                protection_source, business_ir, boundary_ir, selection["public_boundaries"], llvm_library,
                expected_calls=mapped_expected_calls)
            if report["public_boundary_isolation"]["contract"] != mapped_boundary_contract:
                raise NativeBuildError("Boundary isolation changed the mapped original contract")
        if database or selection["public_boundaries"]:
            protection_attributes = output / "module.protection-attributes.ll"
            protection_input = output / "module.protection-input.ll"
            report["protection_ir_adjustments"] = _retain_database_scope(
                business_ir, protection_attributes, selected_functions, llvm_library)
            # O0 may put optnone on selected definitions, causing the earlier
            # scope-stage mem2reg to skip them. Promote again after the parsed
            # protection-only attribute edit; never depend on Kagura accepting
            # residual frontend allocas. Baseline/original inputs stay intact.
            run(toolchain["scope_optimizer"], "-passes=mem2reg", "-S", protection_attributes, "-o", protection_input)
            report["protection_ir_adjustments"]["post_attribute_mem2reg"] = {
                "path": str(protection_input), "sha256": _hash(protection_input),
                "command_index": len(report["commands"]) - 1}
        object_request = native_objects.ObjectRequest(
            source_ir=native_objects.IRInput(before, _hash(before)),
            protection_ir=native_objects.IRInput(protection_input, _hash(protection_input)),
            selected_functions=tuple(selected_functions), seed=seed,
            public_boundary_ir=native_objects.IRInput(boundary_ir, _hash(boundary_ir)) if boundary_ir is not None else None)
        object_pipeline = native_objects.ObjectPipeline(object_request, workspace_root=workspace, output_dir=output,
            command_records=report["commands"], environment=process_env, build_tool_hashes=tool_hashes)
        object_pipeline.prepare()
        original_vm, actual_vm = object_pipeline.original_vm, object_pipeline.actual_vm
        pre_text, diversification = object_pipeline.pre_text, object_pipeline.diversification
        dispatchers, runtime_evidence = object_pipeline.dispatchers, object_pipeline.runtime_evidence
        definition = output / "exports.def"
        with definition.open("x", encoding="ascii", newline="\n") as stream:
            stream.write("EXPORTS\n" + "\n".join(project["functions"]) + "\n")
        runtime_obj = output / "runtime.obj"
        object_pipeline.compile_runtime()
        artifacts = {}
        for arm in ("baseline", "protected"):
            obj, library = output / f"{arm}.obj", output / f"{arm}.dll"
            object_pipeline.compile_arm(arm)
            objects = [obj, runtime_obj] if arm == "protected" else [obj]
            run(toolchain["clangxx"], "-target", TARGET, "-shared", "-fuse-ld=lld", *objects,
                f"-Wl,/DEF:{definition}", "-Wl,/DEBUG:NONE", "-Wl,/INCREMENTAL:NO", "-o", library)
            if symbol_mapping is not None and arm == "protected":
                report["cpp_symbol_link_evidence"] = cpp_symbols.verify_final_link(
                    symbol_mapping["link_boundary"], report["commands"][-1], library.read_bytes(), definition.read_bytes(),
                    workspace_root=workspace)
            artifacts[arm] = {"path": str(library), "sha256": _hash(library), "bytes": library.stat().st_size}
        if database:
            original_library = output / "original-reference.dll"
            original_signature = output / "original-reference-signature.ll"
            run(toolchain["llvm_link"], "-S", *original_signature_modules, "-o", original_signature)
            for function in project["functions"]:
                _body(original_signature.read_text(encoding="utf-8"), function)
            run(toolchain["clangxx"], "-target", TARGET, "-shared", "-fuse-ld=lld", *original_objects,
                f"-Wl,/DEF:{definition}", "-Wl,/DEBUG:NONE", "-Wl,/INCREMENTAL:NO", "-o", original_library)
            artifacts["original_reference"] = {"path": str(original_library), "sha256": _hash(original_library),
                                                "bytes": original_library.stat().st_size}
            report["original_reference_signature_ir"] = {"path": str(original_signature), "sha256": _hash(original_signature)}
            report["original_reference_provenance"] = {
                "schema_version": 1, "method": "direct_source_compile",
                "source_semantics": "recorded_compilation_database_arguments",
                "uses_protection_normalized_ir": False, "exported_functions": list(project["functions"]),
                "compilation_database_sha256": database["database_sha256"],
                "compilation_plan_fingerprint": database["fingerprint"],
                "source_input_snapshot_sha256": _content_digest(database["inputs"]),
                "compiler_inputs": {record["path"]: record["sha256"] for record in database["tools"].values()},
                "header_context_sha256": _content_digest(database["trusted_headers"]),
                "translation_units": original_units, "link_command_index": len(report["commands"]) - 1,
                "link_contract": {"kind": "restricted_windows_shared_library", "target": TARGET,
                                  "complete_application_link": False}}
        elif original_units:
            # Direct C/C++/Rust route: link the independent source-only objects
            # into the original reference DLL with the same fixed trusted recipe.
            original_library = output / "original-reference.dll"
            run(toolchain["clangxx"], "-target", TARGET, "-shared", "-fuse-ld=lld", *original_objects,
                f"-Wl,/DEF:{definition}", "-Wl,/DEBUG:NONE", "-Wl,/INCREMENTAL:NO", "-o", original_library)
            link_command_index = len(report["commands"]) - 1
            if len(original_signature_modules) == 1:
                original_signature = original_signature_modules[0]
            else:
                original_signature = output / "original-reference-signature.ll"
                run(toolchain["llvm_link"], "-S", *original_signature_modules, "-o", original_signature)
            for function in project["functions"]:
                _body(original_signature.read_text(encoding="utf-8"), function)
            artifacts["original_reference"] = {"path": str(original_library), "sha256": _hash(original_library),
                                               "bytes": original_library.stat().st_size}
            report["original_reference_signature_ir"] = {"path": str(original_signature),
                "sha256": _hash(original_signature), "bytes": original_signature.stat().st_size}
            report["original_reference_provenance"] = {
                "schema_version": 1, "method": "direct_source_compile",
                "source_semantics": "recorded_direct_source_arguments",
                "uses_protection_normalized_ir": False,
                "reference_optimization": "normal_direct_recipe_no_scope_normalization",
                "language": project["language"], "exported_functions": list(project["functions"]),
                "compiler_inputs": {unit["compiler"]: unit["compiler_sha256"] for unit in original_units},
                "translation_units": original_units, "link_command_index": link_command_index,
                "link_contract": {"kind": "restricted_windows_shared_library", "target": TARGET,
                                  "complete_application_link": False}}
        object_evidence = object_pipeline.finalize()
        report["native_object_pipeline"] = {key: object_evidence[key] for key in (
            "schema_version", "status", "source_ir", "protection_ir", "selected_functions", "watched_outputs")}
        retained = object_evidence["hardening_evidence"]
        final_core = (output / "protected.codegen.ll").read_text(encoding="utf-8")
        final_vm = object_evidence["final_vm"]
        if symbol_mapping is not None:
            report["cpp_symbol_coverage"] = cpp_symbols.bind_coverage(
                symbol_mapping, post_vm=original_vm, diversified=actual_vm, final_codegen=final_vm)
            export_sets = {arm: cpp_symbols.pe_exports(Path(entry["path"]).read_bytes())
                           for arm, entry in artifacts.items()}
            if any(names != sorted(project["functions"]) for names in export_sets.values()):
                raise NativeBuildError("A C++ mapped arm exposes additional or missing public exports")
            report["cpp_symbol_export_sets"] = export_sets
        boundaries = _boundary_evidence(final_core, selection["public_boundaries"], dispatchers,
                                        [item["dispatch_slot"] for item in diversification.get("engines", [])])
        final_ir = output / "protected.codegen.ll"
        transit_evidence = _boundary_transit_evidence(final_ir, boundary_contract, llvm_library, symbol_map=symbol_map)
        def ir_record(path):
            return {"path": str(path), "sha256": _hash(path)} if path is not None else None
        boundary_transit = {"schema_version": 1, "status": transit_evidence["status"],
                            "contract": boundary_contract, "evidence": transit_evidence,
                            "original_ir": ir_record(before), "business_ir": ir_record(business_ir),
                            "boundary_ir": ir_record(boundary_ir), "final_ir": ir_record(final_ir),
                            "protection_ir": ir_record(protection_source), "symbol_mapping": mapping_descriptor}
        report["boundary_transit"] = boundary_transit
        coverage = {"schema_version": 2, "protection": "native-diversified-layered",
                    "functions": actual_vm, "original_vm": original_vm,
                    "pre_vm_evidence": {fn: _layer_evidence(pre_text, fn) for fn in selected_functions},
                    "runtime_evidence": runtime_evidence, "engine_mode": diversification.get("engine_mode", "shared_direct"),
                    "requested_core_passes": ["fla", "sub", "co", "vm"],
                    "selected_functions": selected_functions, "exported_functions": project["functions"],
                    "scope_mode": selection["mode"], "scope_plan": selection["scope_plan"],
                    "scope_evidence": selection, "public_boundaries": boundaries, "boundary_transit": boundary_transit,
                    "final_vm": final_vm, "global_data_protection": "not_applied", "artifacts": artifacts,
                    "hardening_evidence": retained,
                    "hardening_evidence_stages": {"runtime": "runtime.after.ll: post FLA/SUB/CO, O0 codegen",
                                                   "core": "protected.codegen.ll: post Clang O1, O0 codegen"},
                    "diversification_manifest": str(output / "diversification.json"),
                    "qualification": "Per-function transformation evidence only; functional/performance/external evaluation not performed."}
        if symbol_mapping is not None:
            coverage["by_source_symbol"] = report["cpp_symbol_coverage"]
            coverage["source_selected_functions"] = symbol_mapping["source_selected_functions"]
            coverage["symbol_mapping"] = mapping_descriptor
        _write(output / "coverage.json", coverage)
        report.update(status="artifact_created_unvalidated", artifacts=artifacts,
                      baseline=artifacts["baseline"]["path"], protected=artifacts["protected"]["path"],
                      coverage_path=str(output / "coverage.json"), coverage=coverage)
    except Exception as exc:
        report.update(status="cancelled" if stop.exists() else "failed", error=f"{type(exc).__name__}: {exc}")
    finally:
        changed = []
        if database:
            try:
                compile_database.verify_snapshot(database)
                if _compile_database_environment(toolchain) != project["compiler_environment_metadata"]:
                    raise NativeBuildError("Installed compiler environment changed during build")
            except Exception as exc:
                changed.append("compilation_database_or_implicit_header_context")
                report["compilation_database_integrity_error"] = type(exc).__name__ + ": " + str(exc)
        for name, digest in {**project["input_hashes"], **tool_hashes}.items():
            try:
                candidate = _no_links(Path(name))
                if not candidate.is_file() or _hash(candidate) != digest:
                    changed.append(name)
            except (OSError, NativeBuildError):
                changed.append(name)
        report["changed_inputs"] = changed
        if changed:
            report.update(status="failed", error="Original inputs or pinned tools changed during build")
        report["seconds"] = round(time.monotonic() - started, 3)
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        report["artifact_hashes"] = {str(path.relative_to(output)): _hash(path)
                                     for path in output.iterdir() if path.is_file()}
        _write(output / "report.json", report)
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    inspect = sub.add_parser("inspect")
    inspect.add_argument("--project", type=Path, required=True)
    inspect.add_argument("--workspace", type=Path, default=Path.cwd())
    build = sub.add_parser("build")
    build.add_argument("--project", type=Path, required=True)
    build.add_argument("--output-dir", type=Path, required=True)
    build.add_argument("--workspace", type=Path, default=Path.cwd())
    build.add_argument("--seed", type=int, default=1729)
    args = parser.parse_args(argv)
    try:
        result = inspect_project(args.project, workspace_root=args.workspace) if args.action == "inspect" else build_project(
            args.project, args.output_dir, workspace_root=args.workspace, seed=args.seed)
    except (NativeBuildError, OSError) as exc:
        result = {"status": "rejected", "error": str(exc)}
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result.get("route_status") == "available" or result.get("status") == "artifact_created_unvalidated" else 2


if __name__ == "__main__":
    raise SystemExit(main())
