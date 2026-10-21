"""Protection-only names for a closed owned C++ scalar helper graph.

No source/ABI lowering is performed. A mapping is not VM or resistance evidence.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import re
import struct
from pathlib import Path


PLAIN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
TARGET = "x86_64-pc-windows-msvc"
MAX_IR = 16 * 1024 * 1024
MAX_TOOL = 512 * 1024 * 1024
PREFIX = "antirea_cpp_fn_"


class SymbolMappingError(ValueError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def _json_digest(value):
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode())


def _symbols(values, label, *, plain=False):
    if (not isinstance(values, list) or not 1 <= len(values) <= 64
            or any(not isinstance(value, str) or not value or len(value) > 4096
                   or any(ord(char) < 32 or ord(char) > 126 for char in value) for value in values)
            or len(set(values)) != len(values)
            or plain and any(not PLAIN.fullmatch(value) for value in values)):
        raise SymbolMappingError("Invalid exact symbol list: " + label)
    if any(value.startswith(("kagura_", "__kg_", "antirea_dispatch_", PREFIX)) for value in values):
        raise SymbolMappingError("Source symbol overlaps a reserved generated namespace")
    return set(values)


def _mapped_name(raw_name, input_hash):
    return PREFIX + digest(b"ANTI-REA cpp symbol v1\0" + bytes.fromhex(input_hash) + b"\0" + raw_name)[:32]


def _completed(record, expected_argv, cwd):
    if (not isinstance(record, dict) or record.get("argv") != expected_argv or record.get("cwd") != str(cwd)
            or type(record.get("returncode")) is not int or record["returncode"] != 0
            or record.get("timed_out") is not False or record.get("cancelled") is not False
            or type(record.get("pid")) is not int or record["pid"] <= 0
            or record.get("error") or record.get("post_cleanup_wait_error")):
        raise SymbolMappingError("Closed-link evidence command differs from the authored action")
    cleanup = record.get("cleanup", {})
    if not (isinstance(cleanup, dict) and cleanup.get("method") == "windows_job"
            and cleanup.get("status") == "assigned_job_empty"
            and cleanup.get("assignment_timing") == "immediately_after_launch"
            and type(cleanup.get("parent_pid")) is int and cleanup["parent_pid"] == record["pid"]
            and cleanup.get("job_assigned") is True and type(cleanup.get("active_after")) is int
            and cleanup["active_after"] == 0 and cleanup.get("parent_exit_confirmed") is True
            and cleanup.get("job_handle_closed") is True
            and not any(cleanup.get(key) for key in ("error", "job_setup_error", "job_close_error", "parent_kill_error"))):
        raise SymbolMappingError("Closed-link command cleanup is unverified")


def _canonical_file(value, label):
    from antirea.protectors import _no_links
    if not isinstance(value, (str, Path)):
        raise SymbolMappingError("Missing trusted path: " + label)
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise SymbolMappingError("Trusted path must be absolute and normalized: " + label)
    _no_links(path)
    if not path.is_file() or path != path.resolve(strict=True):
        raise SymbolMappingError("Trusted path must be a canonical regular file: " + label)
    return path


def _trusted_link_tools(workspace_root):
    """Read the caller's trusted local config, never a report-selected config.

    This hashes only fixed tool files, not the SDK tree. No tools are executed.
    Like the existing source-plan boundary, the local configuration is trusted;
    this is reproducibility binding, not hostile-operator attestation.
    """
    from antirea.protectors import _no_links
    workspace = Path(workspace_root)
    if (not workspace.is_absolute() or ".." in workspace.parts or not workspace.is_dir()
            or workspace != workspace.resolve(strict=True)
            or any(part.casefold() in {"rea-analysis-reports", "attackerfolder"} for part in workspace.parts)):
        raise SymbolMappingError("An explicit trusted workspace is required")
    _no_links(workspace)
    config_path = _canonical_file(workspace / ".tools/kagura-toolchain.json", "toolchain config")
    with config_path.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise SymbolMappingError("Trusted toolchain configuration exceeds bound")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise SymbolMappingError("Duplicate trusted toolchain key")
            result[key] = value
        return result
    config = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=pairs)
    if (not isinstance(config, dict) or type(config.get("schema_version")) is not int
            or config["schema_version"] != 1 or config.get("target") != TARGET
            or not isinstance(config.get("llvm_root"), str)):
        raise SymbolMappingError("Trusted toolchain target/schema is unsupported")
    llvm_root = Path(config["llvm_root"])
    if not llvm_root.is_absolute() or ".." in llvm_root.parts:
        raise SymbolMappingError("Trusted LLVM root must be absolute and normalized")
    _no_links(llvm_root)
    paths = {"llvm_link": llvm_root / "bin/llvm-link.exe", "scope_optimizer": llvm_root / "bin/opt.exe",
             "clangxx": llvm_root / "bin/clang++.exe", "llvm_library": llvm_root / "bin/LLVM-C.dll",
             "lld_link": llvm_root / "bin/lld-link.exe"}
    if config.get("clangxx") != str(paths["clangxx"]):
        raise SymbolMappingError("Trusted clang++ must belong to the configured LLVM distribution")
    records = {}
    for role, value in paths.items():
        path = _canonical_file(value, role)
        before = path.stat()
        if not 0 < before.st_size <= MAX_TOOL:
            raise SymbolMappingError("Trusted tool size exceeds bound: " + role)
        hashed, total = hashlib.sha256(), 0
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_TOOL:
                    raise SymbolMappingError("Trusted tool grew beyond bound: " + role)
                hashed.update(chunk)
        after = path.stat()
        if (total != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ino, before.st_dev)
                != (after.st_size, after.st_mtime_ns, after.st_ino, after.st_dev)):
            raise SymbolMappingError("Trusted tool changed while hashing: " + role)
        records[role] = {"path": str(path), "sha256": hashed.hexdigest(), "bytes": total}
    with config_path.open("rb") as stream:
        if stream.read(1024 * 1024 + 1) != raw:
            raise SymbolMappingError("Trusted toolchain configuration changed while hashing")
    return {"schema_version": 1, "workspace_root": str(workspace), "target": TARGET,
            "llvm_root": str(llvm_root), "config": {"path": str(config_path), "sha256": digest(raw)},
            "tools": records}


def _check_trusted_link_tools(boundary, workspace_root):
    trusted = _trusted_link_tools(workspace_root)
    if (boundary.get("workspace_root") != trusted["workspace_root"]
            or _json_digest(boundary.get("trusted_link_tools")) != _json_digest(trusted)):
        raise SymbolMappingError("Closed-link tool paths/hashes differ from the trusted local toolchain")
    return trusted


def _protected_link_argv(build, trusted):
    return [trusted["tools"]["clangxx"]["path"], "-target", TARGET, "-shared", "-fuse-ld=lld",
            str(build / "protected.obj"), str(build / "runtime.obj"), f"-Wl,/DEF:{build / 'exports.def'}",
            "-Wl,/DEBUG:NONE", "-Wl,/INCREMENTAL:NO", "-o", str(build / "protected.dll")]


def _build_directory(value, workspace_root):
    from antirea.protectors import _no_links
    build, owned = Path(value), Path(workspace_root) / ".runs"
    _no_links(build)
    if (not build.is_absolute() or ".." in build.parts or not build.is_dir()
            or build != build.resolve(strict=True) or build == owned or not build.is_relative_to(owned)):
        raise SymbolMappingError("Closed link must belong to a canonical private owned build")
    return build


def make_link_boundary(*, workspace, build_dir, database, module_paths, raw_ir, input_ir,
                       module_link_record, canonicalize_record, toolchain, exports):
    """Bind actual source modules/commands to one fixed no-extra-object DLL link.

    Called by the trusted builder, never directly from a project-supplied policy.
    Reads owned generated IR and saved plan only; does not compile or execute it.
    Final link and PE export verification below remain mandatory before success.
    """
    from antirea.protectors import _no_links
    workspace, build_dir = Path(workspace), Path(build_dir)
    trusted = _trusted_link_tools(workspace)
    build_dir = _build_directory(build_dir, workspace)
    if any(toolchain.get(role) != trusted["tools"][role]["path"]
           for role in ("llvm_link", "scope_optimizer", "clangxx")):
        raise SymbolMappingError("Builder tool paths differ from the trusted local toolchain")
    exported = _symbols(exports, "exports", plain=True)
    if Path(raw_ir) != build_dir / "module.raw.ll" or Path(input_ir) != build_dir / "module.before.ll":
        raise SymbolMappingError("Closed link requires the builder's exact raw and canonical IR paths")
    if (database.get("workspace_root") != str(workspace)
            or database.get("fingerprint") != _json_digest({k: v for k, v in database.items() if k != "fingerprint"})):
        raise SymbolMappingError("Closed link requires the exact normalized source plan")
    saved = build_dir / "compile-database-plan.json"
    _no_links(saved)
    if json.loads(saved.read_text(encoding="utf-8")) != database:
        raise SymbolMappingError("Closed link differs from the saved compilation plan")
    units = database.get("translation_units", [])
    if not 1 <= len(units) <= 64 or len(module_paths) != len(units):
        raise SymbolMappingError("Closed link does not contain every selected translation unit")

    def artifact(path):
        path = Path(path)
        _no_links(path)
        if not path.is_absolute() or not path.is_relative_to(build_dir) or not path.is_file():
            raise SymbolMappingError("Closed-link IR must be a build-contained regular file")
        if path.stat().st_size > MAX_IR:
            raise SymbolMappingError("Closed-link IR exceeds bound")
        data = path.read_bytes()
        return {"path": str(path), "sha256": digest(data)}

    modules = []
    for index, (path, unit) in enumerate(zip(module_paths, units)):
        expected = build_dir / f"source-{index:03d}.ll"
        if Path(path) != expected:
            raise SymbolMappingError("Closed-link source module order/path is not the owned builder output")
        modules.append({**artifact(path), "source": unit["source"], "entry_sha256": unit["entry_sha256"]})
    raw, canonical = artifact(raw_ir), artifact(input_ir)
    _completed(module_link_record, [toolchain["llvm_link"], "-S", *map(str, module_paths), "-o", str(raw_ir)], build_dir)
    _completed(canonicalize_record, [toolchain["scope_optimizer"], "-passes=mem2reg", "-S", str(raw_ir), "-o", str(input_ir)], build_dir)
    definition = build_dir / "exports.def"
    definition_bytes = ("EXPORTS\n" + "\n".join(exports) + "\n").encode()
    # This exact recipe must be used unchanged by the later protected link.
    argv = _protected_link_argv(build_dir, trusted)
    return {"schema_version": 1, "kind": "closed_owned_source_dll",
            "workspace_root": str(workspace), "trusted_link_tools": trusted,
            "target": TARGET, "build_directory": str(build_dir), "plan_fingerprint": database["fingerprint"],
            "source_modules": modules, "raw_ir": raw, "input_ir": canonical,
            "module_link_record": module_link_record, "canonicalize_record": canonicalize_record,
            "exported_functions": sorted(exported), "definition_path": str(definition),
            "definition_sha256": digest(definition_bytes), "protected_link_argv": argv,
            "complete_application_link": False, "final_link_verified": False}


def _api(library):
    # Reuse only the pinned LLVM-C binding, not Swift normalization/CC rewriting.
    from antirea.swift_frontend import _LLVM
    llvm = _LLVM(library)
    p, u = ctypes.c_void_p, ctypes.c_uint
    additions = {"LLVMGetLinkage": (u, [p]), "LLVMGetVisibility": (u, [p]),
        "LLVMGetDLLStorageClass": (u, [p]), "LLVMGetComdat": (p, [p]),
        "LLVMHasPersonalityFn": (ctypes.c_int, [p]), "LLVMGetNextUse": (p, [p]),
        "LLVMGetUser": (p, [p]), "LLVMGetInstructionParent": (p, [p]),
        "LLVMGetBasicBlockParent": (p, [p])}
    for name, (result, args) in additions.items():
        callback = getattr(llvm.dll, name)
        callback.restype, callback.argtypes = result, args
        setattr(llvm, name, callback)
    return llvm


def _parse(llvm, context, data):
    module, error = ctypes.c_void_p(), ctypes.c_void_p()
    buffer = llvm.LLVMCreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"cpp-protection-symbols")
    if llvm.LLVMParseIRInContext(context, buffer, ctypes.byref(module), ctypes.byref(error)):
        raise SymbolMappingError("LLVM parse failed: " + llvm.string(error.value))
    if llvm.LLVMVerifyModule(module, 2, ctypes.byref(error)):
        llvm.LLVMDisposeModule(module)
        raise SymbolMappingError("LLVM verify failed: " + llvm.string(error.value))
    return module


def _name_bytes(llvm, value):
    length = ctypes.c_size_t()
    pointer = llvm.LLVMGetValueName2(value, ctypes.byref(length))
    return ctypes.string_at(pointer, length.value) if pointer else b""


def _signature(llvm, function):
    result = llvm.signature(function)  # checked scalar widths/arity/special ABI attrs
    if llvm.LLVMGetFunctionCallConv(function) != 0 or llvm.LLVMHasPersonalityFn(function):
        raise SymbolMappingError("C++ helper requires ordinary C CC and no exception personality")
    if llvm.LLVMGetComdat(function) or llvm.LLVMGetLinkage(function) not in (0, 8, 9):
        raise SymbolMappingError("COMDAT/weak/linkonce/available-externally helper is not supported")
    return {**result, "calling_convention": 0, "linkage": llvm.LLVMGetLinkage(function),
            "visibility": llvm.LLVMGetVisibility(function), "dll_storage": llvm.LLVMGetDLLStorageClass(function)}


def _uses(llvm, function):
    calls = []
    use = llvm.LLVMGetFirstUse(function)
    while use:
        user = llvm.LLVMGetUser(use)
        # Every occurrence must be solely the direct callee of an ordinary call.
        if (llvm.LLVMGetValueKind(user) != 24 or llvm.LLVMGetInstructionOpcode(user) != 45
                or llvm.LLVMGetCalledValue(user) != function
                or sum(llvm.LLVMGetOperand(user, i) == function for i in range(llvm.LLVMGetNumOperands(user))) != 1
                or llvm.LLVMGetCalledFunctionType(user) != llvm.LLVMGlobalGetValueType(function)
                or llvm.LLVMGetInstructionCallConv(user) != 0 or llvm.LLVMGetNumOperandBundles(user)):
            raise SymbolMappingError("Address-taken/aliased/exceptional helper use is unsupported")
        caller = llvm.LLVMGetBasicBlockParent(llvm.LLVMGetInstructionParent(user))
        calls.append({"instruction": user, "caller": caller, "source_caller": llvm.name(caller)})
        use = llvm.LLVMGetNextUse(use)
    return calls


def _module_name_directives(llvm, module):
    length = ctypes.c_size_t()
    llvm.LLVMGetModuleInlineAsm(module, ctypes.byref(length))
    if length.value or llvm.LLVMGetFirstGlobalAlias(module) or llvm.LLVMGetFirstGlobalIFunc(module):
        raise SymbolMappingError("Module assembly/aliases/ifuncs are unsupported for symbol mapping")
    count = llvm.LLVMGetNamedMetadataNumOperands(module, b"llvm.linker.options")
    nodes = (ctypes.c_void_p * count)()
    llvm.LLVMGetNamedMetadataOperands(module, b"llvm.linker.options", nodes)
    allowed_lib = r"(?:libcmt[d]?|msvcrt[d]?|oldnames|libcpmt[d]?|msvcprt[d]?|vcruntime[d]?|ucrt[d]?)\.lib"
    for node in nodes:
        values = (ctypes.c_void_p * llvm.LLVMGetMDNodeNumOperands(node))()
        llvm.LLVMGetMDNodeOperands(node, values)
        for value in values:
            size = ctypes.c_uint()
            ptr = llvm.LLVMGetMDString(value, ctypes.byref(size))
            text = ctypes.string_at(ptr, size.value).decode("ascii") if ptr else ""
            if not re.fullmatch(r"/DEFAULTLIB:" + allowed_lib, text, re.I):
                raise SymbolMappingError("Unreviewed symbol-affecting linker metadata is unsupported")
    for function in llvm.functions(module):
        if llvm.LLVMIsDeclaration(function):
            continue
        for instruction in llvm.instructions(function):
            if llvm.LLVMGetInstructionOpcode(instruction) == 45:
                callee = llvm.LLVMGetCalledValue(instruction)
                if callee and llvm.LLVMGetValueKind(callee) == 23:  # InlineAsm
                    raise SymbolMappingError("Inline asm can contain hidden name references")


def _verify_boundary_files(boundary, input_hash, exported, *, workspace_root):
    from antirea.protectors import _no_links
    if (not isinstance(boundary, dict) or boundary.get("schema_version") != 1
            or boundary.get("kind") != "closed_owned_source_dll" or boundary.get("target") != TARGET
            or boundary.get("input_ir", {}).get("sha256") != input_hash
            or boundary.get("exported_functions") != sorted(exported)
            or boundary.get("complete_application_link") is not False):
        raise SymbolMappingError("A builder-derived closed source/link boundary is required")
    trusted = _check_trusted_link_tools(boundary, workspace_root)
    build = _build_directory(boundary["build_directory"], trusted["workspace_root"])
    if (boundary["raw_ir"]["path"] != str(build / "module.raw.ll")
            or boundary["input_ir"]["path"] != str(build / "module.before.ll")):
        raise SymbolMappingError("Closed-link raw/canonical paths differ from the owned builder outputs")
    saved = build / "compile-database-plan.json"
    _no_links(saved)
    database = json.loads(saved.read_text(encoding="utf-8"))
    if (database.get("fingerprint") != boundary.get("plan_fingerprint")
            or database.get("workspace_root") != trusted["workspace_root"]
            or not build.is_relative_to(Path(trusted["workspace_root"]) / ".runs")
            or database["fingerprint"] != _json_digest({k: v for k, v in database.items() if k != "fingerprint"})):
        raise SymbolMappingError("Closed-link saved source plan changed")
    modules = boundary["source_modules"]
    if not modules or len(modules) != len(database["translation_units"]):
        raise SymbolMappingError("Closed-link module inventory is incomplete")
    for index, (row, unit) in enumerate(zip(modules, database["translation_units"])):
        if (row["source"] != unit["source"] or row["entry_sha256"] != unit["entry_sha256"]
                or row["path"] != str(build / f"source-{index:03d}.ll")):
            raise SymbolMappingError("Closed-link module/source identities differ")
    for row in [*modules, boundary["raw_ir"], boundary["input_ir"]]:
        path = Path(row["path"])
        _no_links(path)
        if not path.is_relative_to(build) or path.stat().st_size > MAX_IR or digest(path.read_bytes()) != row["sha256"]:
            raise SymbolMappingError("Closed-link module artifact changed")
    link = boundary["module_link_record"]
    canonical = boundary["canonicalize_record"]
    _completed(link, [trusted["tools"]["llvm_link"]["path"], "-S", *[row["path"] for row in modules], "-o", boundary["raw_ir"]["path"]], build)
    _completed(canonical, [trusted["tools"]["scope_optimizer"]["path"], "-passes=mem2reg", "-S", boundary["raw_ir"]["path"],
                           "-o", boundary["input_ir"]["path"]], build)
    definition = build / "exports.def"
    final = boundary["protected_link_argv"]
    expected = _protected_link_argv(build, trusted)
    if final != expected or boundary["definition_path"] != str(definition):
        raise SymbolMappingError("Closed link contains extra object/library/export options")
    return trusted


def remap_protection_symbols(ir_bytes, *, selected_symbols, exported_symbols, llvm_library, link_boundary, workspace_root):
    selected = _symbols(selected_symbols, "selected")
    exported = _symbols(exported_symbols, "exports", plain=True)
    if not isinstance(ir_bytes, bytes) or not 0 < len(ir_bytes) <= MAX_IR:
        raise SymbolMappingError("Invalid bounded LLVM input")
    input_hash = digest(ir_bytes)
    trusted = _verify_boundary_files(link_boundary, input_hash, exported, workspace_root=workspace_root)
    if str(Path(llvm_library)) != trusted["tools"]["llvm_library"]["path"]:
        raise SymbolMappingError("Parser path differs from the trusted local LLVM library")
    llvm, context, module, checked = _api(llvm_library), None, None, None
    try:
        context = llvm.LLVMContextCreate()
        module = _parse(llvm, context, ir_bytes)
        triple = llvm.LLVMGetTarget(module).decode("ascii")
        if not re.fullmatch(r"x86_64-pc-windows-msvc(?:[0-9]+(?:\.[0-9]+)*)?", triple):
            raise SymbolMappingError("C++ symbol mapping requires the pinned Windows x64 target")
        _module_name_directives(llvm, module)
        functions = {llvm.name(value): value for value in llvm.functions(module)}
        definitions = {name: value for name, value in functions.items() if not llvm.LLVMIsDeclaration(value)}
        if not (selected | exported) <= set(definitions):
            raise SymbolMappingError("Selected/exported definition is missing from the linked module")
        for name, value in functions.items():
            if llvm.LLVMGetDLLStorageClass(value) == 2 and name not in exported:
                raise SymbolMappingError("Additional DLL export is outside the closed public contract")
        values = [*functions.values(), *llvm.values(llvm.LLVMGetFirstGlobal, llvm.LLVMGetNextGlobal, module)]
        occupied = {_name_bytes(llvm, value) for value in values}
        renames, before, uses = {}, {}, {}
        for name in sorted(selected):
            function = definitions[name]
            raw = _name_bytes(llvm, function)
            if raw != name.encode("ascii"):
                raise SymbolMappingError("Policy and LLVM byte-level symbol identities disagree")
            before[name] = _signature(llvm, function)
            if before[name]["dll_storage"] and name not in exported:
                raise SymbolMappingError("Imported/exported helper cannot be privately renamed")
            uses[name] = _uses(llvm, function)
            mapped = name if name in exported or PLAIN.fullmatch(name) else _mapped_name(raw, input_hash)
            if mapped != name and mapped.encode() in occupied:
                raise SymbolMappingError("Generated symbol collides with the LLVM global namespace")
            occupied.add(mapped.encode())
            renames[name] = mapped
        if len(set(renames.values())) != len(selected):
            raise SymbolMappingError("Symbol mapping is not one-to-one")
        for name, mapped in renames.items():
            llvm.LLVMSetValueName2(definitions[name], mapped.encode(), len(mapped))
            if llvm.name(definitions[name]) != mapped or _signature(llvm, definitions[name]) != before[name]:
                raise SymbolMappingError("LLVM name/signature/linkage changed beyond the mapping")
            for call in uses[name]:
                if llvm.LLVMGetCalledValue(call["instruction"]) != definitions[name]:
                    raise SymbolMappingError("A helper call did not retain its exact target Value")
        serialized = llvm.string(llvm.LLVMPrintModuleToString(module)).encode()
        checked = _parse(llvm, context, serialized)
        roundtrip = {llvm.name(value): value for value in llvm.functions(checked) if not llvm.LLVMIsDeclaration(value)}
        expected_definitions = {renames.get(name, name) for name in definitions}
        if set(roundtrip) != expected_definitions:
            raise SymbolMappingError("Definitions changed during mapping round-trip")
        records = {}
        for name in sorted(selected):
            mapped = renames[name]
            if _signature(llvm, roundtrip[mapped]) != before[name]:
                raise SymbolMappingError("Mapped definition ABI changed during serialization")
            records[name] = {"source_symbol": name, "source_symbol_bytes_hex": name.encode().hex(),
                "protected_symbol": mapped, "renamed": mapped != name, "signature": before[name],
                "source_callers": sorted({call["source_caller"] for call in uses[name]}),
                "protected_callers": sorted({renames.get(call["source_caller"], call["source_caller"]) for call in uses[name]}),
                "direct_use_count": len(uses[name]), "all_uses_checked": True}
        return serialized, {"schema_version": 1, "status": "mapped_not_protected", "input_sha256": input_hash,
            "output_sha256": digest(serialized), "source_selected_functions": sorted(selected),
            "protected_selected_functions": sorted(renames.values()), "exported_functions": sorted(exported),
            "functions": records,
            "link_boundary": link_boundary, "calling_convention_rewritten": False,
            "source_or_baseline_modified": False, "target_executed": False,
            "source_symbol_identity": "exact_linked_LLVM_symbol_not_demangled_source_declaration",
            "qualification": "Symbol identity mapping only; actual VM coverage, fixed link/export verification and original comparison remain required."}
    finally:
        if checked:
            llvm.LLVMDisposeModule(checked)
        if module:
            llvm.LLVMDisposeModule(module)
        if context:
            llvm.LLVMContextDispose(context)
        llvm.close()


def bind_coverage(manifest, **stages):
    """Connect exact source identities to independently checked VM stages."""
    records = manifest["functions"]
    sources = set(manifest["source_selected_functions"])
    targets = {record["protected_symbol"] for record in records.values()}
    if (set(records) != sources or len(targets) != len(sources)
            or targets != set(manifest["protected_selected_functions"])):
        raise SymbolMappingError("Source/protected coverage mapping is not a bijection")
    if set(stages) != {"post_vm", "diversified", "final_codegen"}:
        raise SymbolMappingError("All three actual VM evidence stages are mandatory")
    for name, evidence in stages.items():
        if set(evidence) != targets or any(value.get("virtualized") is not True for value in evidence.values()):
            raise SymbolMappingError("Incomplete mapped VM coverage at " + name)
    return {source: {"protected_symbol": records[source]["protected_symbol"],
                     "stages": {stage: evidence[records[source]["protected_symbol"]] for stage, evidence in stages.items()}}
            for source in sorted(sources)}


def pe_exports(data):
    """Bounded PE32+ AMD64 export names; reject ordinal-only/forwarded exports."""
    def unpack(fmt, offset):
        if offset < 0 or offset + struct.calcsize(fmt) > len(data):
            raise SymbolMappingError("Truncated PE export evidence")
        return struct.unpack_from(fmt, data, offset)
    if not isinstance(data, bytes) or not 0 < len(data) <= 128 * 1024 * 1024 or data[:2] != b"MZ":
        raise SymbolMappingError("Invalid bounded PE image")
    pe, = unpack("<I", 0x3c)
    if data[pe:pe + 4] != b"PE\0\0":
        raise SymbolMappingError("Missing PE signature")
    machine, count = unpack("<HH", pe + 4)
    optional_size, = unpack("<H", pe + 20)
    optional = pe + 24
    magic, = unpack("<H", optional)
    directories, = unpack("<I", optional + 108)
    if machine != 0x8664 or magic != 0x20b or not 1 <= count <= 96 or optional_size < 120 or directories < 1:
        raise SymbolMappingError("Unsupported PE target/header")
    exports_rva, exports_size = unpack("<II", optional + 112)
    sections = []
    for index in range(count):
        start = optional + optional_size + index * 40
        virtual_size, virtual_address, raw_size, raw_pointer = unpack("<IIII", start + 8)
        sections.append((virtual_address, raw_size, raw_pointer))
    def file_offset(rva, size):
        matches = [raw + rva - va for va, length, raw in sections if va <= rva and rva + size <= va + length]
        if len(matches) != 1 or matches[0] + size > len(data):
            raise SymbolMappingError("Ambiguous or unbacked PE RVA")
        return matches[0]
    table = file_offset(exports_rva, 40)
    functions, names, address_functions, address_names, address_ordinals = unpack("<IIIII", table + 20)
    if not 1 <= functions == names <= 64:
        raise SymbolMappingError("Ordinal-only/oversized/empty exports are unsupported")
    rows = []
    ordinals = set()
    for index in range(names):
        name_rva, = unpack("<I", file_offset(address_names + index * 4, 4))
        ordinal, = unpack("<H", file_offset(address_ordinals + index * 2, 2))
        if ordinal >= functions or ordinal in ordinals:
            raise SymbolMappingError("Invalid/duplicate export ordinal")
        ordinals.add(ordinal)
        function_rva, = unpack("<I", file_offset(address_functions + ordinal * 4, 4))
        if not function_rva or exports_rva <= function_rva < exports_rva + exports_size:
            raise SymbolMappingError("Missing/forwarded export is unsupported")
        file_offset(function_rva, 1)
        encoded = bytearray()
        for position in range(4097):
            value = data[file_offset(name_rva + position, 1)]
            if value == 0:
                break
            encoded.append(value)
        else:
            raise SymbolMappingError("Unbounded export name")
        name = encoded.decode("ascii")
        if not PLAIN.fullmatch(name) or name in rows:
            raise SymbolMappingError("Unexpected or duplicate public export")
        rows.append(name)
    return sorted(rows)


def verify_final_link(boundary, record, binary_bytes, definition_bytes, *, workspace_root):
    trusted = _check_trusted_link_tools(boundary, workspace_root)
    build = _build_directory(boundary["build_directory"], trusted["workspace_root"])
    expected = _protected_link_argv(build, trusted)
    if boundary.get("protected_link_argv") != expected:
        raise SymbolMappingError("Final link executable/recipe differs from the trusted toolchain")
    _completed(record, expected, build)
    if digest(definition_bytes) != boundary["definition_sha256"]:
        raise SymbolMappingError("Export definition changed after symbol mapping")
    actual = pe_exports(binary_bytes)
    if actual != boundary["exported_functions"]:
        raise SymbolMappingError("Protected PE exports differ from the public C ABI contract")
    return {"status": "fixed_link_and_exports_verified", "binary_sha256": digest(binary_bytes),
            "exported_functions": actual, "complete_application_link": False}
