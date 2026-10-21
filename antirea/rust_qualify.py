"""Owner-qualified Rust crate symbols. No compiler/target/file writes.

The caller authenticates Cargo ownership BEFORE calling this module and runs it
in a bounded worker. Evidence pins are not a substitute for Cargo authentication.
LLVM parsing is opt-in execution of a reviewed library, never target execution.
"""
from __future__ import annotations

import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

TARGET = "x86_64-pc-windows-msvc"
MAX_IR = 16 * 1024 * 1024
MAX_UNITS = 64
MAX_SYMBOLS = 4096
MAX_INSTRUCTIONS = 100000
LOCAL_LINKAGES = {8, 9}  # LLVMInternalLinkage, LLVMPrivateLinkage
PREFIX = "antirea_crate_"
MAPPER = "antirea/rust_ir.py"


class QualificationError(ValueError):
    pass


def require(value, message):
    if not value:
        raise QualificationError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def path_identity(value):
    return str(Path(value)).replace("/", "\\").casefold() if os.name == "nt" else str(Path(value))


def _sha(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "Exact SHA-256 required")
    return value


def owner_identity(owner):
    require(type(owner) is dict and set(owner) == {"package_id", "target_name", "source", "unit"},
            "Exact caller-authenticated owner fields required")
    require(all(type(v) is str and 0 < len(v) <= 8192 and "\0" not in v for v in owner.values()),
            "Malformed owner identity")
    # PID/time-bearing recorder unit IDs are retained as evidence, not namespace.
    return {"package_id": owner["package_id"], "target_name": owner["target_name"],
            "source": path_identity(owner["source"])}


def qualified_name(owner, input_sha256, original):
    require(type(original) is str and original and len(original.encode("utf-8")) <= 4096,
            "Bounded nonempty LLVM identity required")
    identity = {"owner": owner_identity(owner), "input_sha256": _sha(input_sha256), "symbol": original}
    return PREFIX + digest(canonical(identity))


def _declaration_abi(row):
    result = {k: row[k] for k in ("kind", "type")}
    if row["kind"] == "function":
        result["calling_convention"] = row["calling_convention"]
        result["attributes"] = {k: v for k, v in row["attributes"].items() if k != "4294967295"}
    else:
        result["constant"] = row.get("constant")
        result["thread_local_mode"] = row.get("thread_local_mode")
    return result


def plan_qualification(owners, input_hashes, inventories):
    """Pure plan: never equate local definitions by name or equal body."""
    require(type(owners) is list and type(input_hashes) is list and type(inventories) is list
            and 1 <= len(owners) <= MAX_UNITS and len(owners) == len(input_hashes) == len(inventories),
            "Bounded matching unit lists required")
    identities = [canonical(owner_identity(owner)) for owner in owners]
    require(len(set(identities)) == len(identities), "Duplicate stable crate owner, even if unit IDs differ")
    require(len({owner["unit"] for owner in owners}) == len(owners), "Duplicate recorded unit ID")
    reserved, occurrences, external_definitions = set(), {}, {}
    for index, inventory in enumerate(inventories):
        require(type(inventory) is dict and type(inventory.get("symbols")) is dict,
                "Malformed symbol inventory")
        for name, row in inventory["symbols"].items():
            require(type(name) is str and name and type(row) is dict
                    and row.get("kind") in {"function", "global", "alias", "ifunc"}
                    and type(row.get("declaration")) is bool and type(row.get("linkage")) is int,
                    "Malformed LLVM symbol identity")
            require(not name.startswith(PREFIX), "Original symbol occupies reserved qualification namespace")
            reserved.add(name)
            occurrences.setdefault(name, []).append({"index": index, "kind": row["kind"],
                                                      "declaration": row["declaration"], "linkage": row["linkage"]})
            if not row["declaration"] and row["linkage"] not in LOCAL_LINKAGES:
                require(name not in external_definitions, "Unsupported duplicate external definition: " + name)
                external_definitions[name] = (index, row)
    require(len(reserved) <= MAX_SYMBOLS, "Symbol inventory exceeds bound")
    declarations, unresolved = {}, []
    for index, inventory in enumerate(inventories):
        for name, row in inventory["symbols"].items():
            if not row["declaration"]:
                continue
            require(row["linkage"] not in LOCAL_LINKAGES, "Local declaration unsupported")
            abi = _declaration_abi(row)
            require(name not in declarations or declarations[name] == abi,
                    "Cross-unit declaration ABI/kind mismatch: " + name)
            declarations[name] = abi
            if name in external_definitions:
                require(abi == _declaration_abi(external_definitions[name][1]),
                        "Cross-unit declaration/external definition mismatch: " + name)
            else:
                unresolved.append({"index": index, "name": name,
                    "same_named_local_owners": [r["index"] for r in occurrences[name]
                                               if not r["declaration"] and r["linkage"] in LOCAL_LINKAGES]})
    mappings, generated = [], set()
    for owner, sha, inventory in zip(owners, input_hashes, inventories):
        _sha(sha)
        mapping = {}
        for name, row in sorted(inventory["symbols"].items()):
            if not row["declaration"] and row["linkage"] in LOCAL_LINKAGES:
                new = qualified_name(owner, sha, name)
                require(new not in reserved and new not in generated, "Qualified identity collision")
                generated.add(new)
                mapping[name] = new
        mappings.append(mapping)
    return {"maps": mappings, "collisions": {name: rows for name, rows in sorted(occurrences.items())
            if sum(not row["declaration"] for row in rows) > 1},
            "unresolved_external_declarations": unresolved,
            "external_resolution": {name: row[0] for name, row in sorted(external_definitions.items())}}


def check_contract(before, after, mapping):
    """ABI and ordered caller contracts, separate from exact whole-module proof."""
    require(before["target"] == after["target"] and before["data_layout"] == after["data_layout"],
            "Module target/data layout changed")
    expected = {mapping.get(name, name): row for name, row in before["symbols"].items()}
    require(expected == after["symbols"], "Symbol kind/declaration/linkage/ABI/attributes changed")
    calls = {}
    for owner, rows in before["calls"].items():
        calls[mapping.get(owner, owner)] = [
            {**row, "callee": mapping.get(row["callee"], row["callee"])} for row in rows]
    require(calls == after["calls"], "Ordered caller contract changed outside symbol mapping")
    require(before["definition_count"] == after["definition_count"], "Definition count changed")


def _stop(path):
    if path is not None:
        require(not Path(path).exists(), "STOP requested")


def _path(value, root=None):
    path = Path(value)
    text = str(value)
    require(path.is_absolute() and ".." not in path.parts and not text.startswith(("\\\\", "//"))
            and ":" not in text[2:] and path.name.casefold() != "env.setting"
            and not any(p.casefold() in {"rea-analysis-reports", "attackerfolder", "shared", "linkrepro"}
                        for p in path.parts), "Unsafe/received/private-environment path")
    for item in (path, *path.parents):
        info = item.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
                "Links/reparse points prohibited")
        if item == path and stat.S_ISREG(info.st_mode):
            require(info.st_nlink == 1, "Hardlinked input prohibited; supply owned byte-identical copy")
    require(path == path.resolve(strict=True), "Noncanonical path")
    if root is not None:
        require(path.is_relative_to(root), "Input outside owned workspace")
    return path


def _read(path, limit=512 * 1024 * 1024):
    path = _path(path)
    before = path.stat()
    require(path.is_file() and before.st_size <= limit, "Input is not a bounded regular file")
    raw = path.read_bytes()
    after = path.stat()
    require((before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_ino, after.st_size, after.st_mtime_ns), "Input changed while reading")
    return raw


def _descriptor(value, root, *, limit=MAX_IR):
    require(type(value) is dict and set(value) == {"path", "sha256", "bytes"}
            and type(value["path"]) is str and type(value["bytes"]) is int and value["bytes"] > 0,
            "Exact nonempty file descriptor required")
    path = _path(value["path"], root)
    raw = _read(path, limit)
    require(len(raw) == value["bytes"] and digest(raw) == _sha(value["sha256"]), "Evidence/input pin mismatch")
    return raw


def _pairs(rows):
    result = {}
    for key, value in rows:
        require(key not in result, "Duplicate JSON key")
        result[key] = value
    return result


def _loaded(root, pins):
    result = []
    for name, module in sorted(sys.modules.items()):
        if name != "antirea" and not name.startswith("antirea."):
            continue
        require(name == "antirea" or re.fullmatch(r"antirea\.[a-z][a-z0-9_]*", name),
                "Unsupported preloaded production module")
        expected = root / "antirea" / ("__init__.py" if name == "antirea" else name.split(".")[1] + ".py")
        require(module is not None and getattr(module, "__file__", None)
                and path_identity(module.__file__) == path_identity(expected), "Incompatible preloaded module origin")
        if name == "antirea":
            require([path_identity(x) for x in getattr(module, "__path__", ())] ==
                    [path_identity(root / "antirea")], "Incompatible preloaded package search path")
        require(path_identity(expected) in pins and digest(_read(expected)) == pins[path_identity(expected)]["sha256"],
                "Preloaded module pin mismatch")
        result.append({"module": name, **pins[path_identity(expected)]})
    return result


def _bootstrap(root, library, library_sha, config_sha, pins):
    root = _path(root)
    require(root.is_dir(), "Workspace directory required")
    require(type(pins) is dict and pins, "Complete caller-reviewed engine pin map required")
    index = {}
    for name, sha in pins.items():
        path = _path(name)
        key = path_identity(path)
        require(key not in index, "Duplicate case-insensitive engine identity")
        raw = _read(path)
        require(digest(raw) == _sha(sha), "Engine pin changed before import")
        index[key] = {"path": str(path), "sha256": sha, "bytes": len(raw)}
    config = root / ".tools/kagura-toolchain.json"
    mapper = root / MAPPER
    required = [*sorted((root / "antirea").rglob("*.py")), Path(__file__).resolve(),
                root / "antirea/__init__.py", config, mapper, Path(library)]
    require(all(path_identity(path) in index for path in required), "Complete production/helper/config/library pins required")
    require(index[path_identity(config)]["sha256"] == _sha(config_sha)
            and index[path_identity(library)]["sha256"] == _sha(library_sha), "Reviewed helper/config/library pin mismatch")
    settings = json.loads(_read(config, 1024 * 1024).decode("utf-8-sig"), object_pairs_hook=_pairs)
    require(type(settings) is dict and type(settings.get("schema_version")) is int
            and settings["schema_version"] == 1 and settings.get("target") == TARGET
            and type(settings.get("llvm_root")) is str, "Unsupported local LLVM configuration")
    wanted = _path(Path(settings["llvm_root"]) / "bin/LLVM-C.dll")
    require(path_identity(wanted) == path_identity(library), "LLVM library differs from trusted configuration")
    _loaded(root, index)
    # These two fixed modules have no top-level third-party/native imports.
    # Compile the reviewed source bytes directly: -B alone still reads .pyc.
    created = []
    try:
        for name, path in (("antirea", root / "antirea/__init__.py"),
                           ("antirea.rust_ir", mapper)):
            if name in sys.modules:
                continue
            source = _read(path)
            require(digest(source) == index[path_identity(path)]["sha256"],
                    "Package source changed before direct compilation")
            spec = importlib.util.spec_from_file_location(name, path,
                submodule_search_locations=[str(path.parent)] if name == "antirea" else None)
            require(spec is not None and spec.loader is not None, "Fixed package source loader unavailable")
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            created.append(name)
            exec(compile(source, str(path), "exec", dont_inherit=True), module.__dict__)
        module = sys.modules["antirea.rust_ir"]
        module.verify_engine_snapshot(root, pins, additional_paths=(Path(__file__).resolve(),))
        _loaded(root, index)
        return module, index
    except BaseException:
        for name in reversed(created):
            sys.modules.pop(name, None)
        raise


def _extra(llvm):
    p, u, s = ctypes.c_void_p, ctypes.c_uint, ctypes.c_char_p
    for name, (result, args) in {
        "LLVMGetDataLayoutStr": (s, [p]), "LLVMGetNextGlobalIFunc": (p, [p]),
        "LLVMGetInitializer": (p, [p]), "LLVMIsGlobalConstant": (ctypes.c_int, [p]),
        "LLVMGetThreadLocalMode": (u, [p]), "LLVMGetSection": (s, [p]),
    }.items():
        callback = getattr(llvm.dll, name)
        callback.restype, callback.argtypes = result, args
        setattr(llvm, name, callback)


def _symbols(llvm, module):
    values = [("function", x) for x in llvm.functions(module)]
    for kind, first, following in (("global", llvm.LLVMGetFirstGlobal, llvm.LLVMGetNextGlobal),
            ("alias", llvm.LLVMGetFirstGlobalAlias, llvm.LLVMGetNextGlobalAlias),
            ("ifunc", llvm.LLVMGetFirstGlobalIFunc, llvm.LLVMGetNextGlobalIFunc)):
        values.extend((kind, x) for x in llvm.values(first, following, module))
    require(len(values) <= MAX_SYMBOLS, "Module symbol count exceeds bound")
    names = [llvm.name(value) for _, value in values]
    require(all(names) and len(set(names)) == len(names), "Unnamed/duplicate module symbol")
    return {name: (kind, value) for name, (kind, value) in zip(names, values)}


def _inventory(mapper, llvm, module):
    length = ctypes.c_size_t()
    llvm.LLVMGetModuleInlineAsm(module, ctypes.byref(length))
    require(not length.value and not llvm.LLVMGetNamedMetadataNumOperands(module, b"llvm.linker.options"),
            "Symbol-string module assembly/linker directives cannot be qualified by LLVM uses")
    inventory, calls, structure = {}, {}, []
    all_values = _symbols(llvm, module)
    by_value = {value: name for name, (_, value) in all_values.items()}
    instructions = 0
    for name, (kind, value) in all_values.items():
        require(not llvm.LLVMGetComdat(value) if kind in {"function", "global"} else True,
                "COMDAT selection semantics require a separate linker contract")
        ty = llvm.LLVMGlobalGetValueType(value)
        row = {"kind": kind, "type": llvm.string(llvm.LLVMPrintTypeToString(ty)),
               "declaration": bool(llvm.LLVMIsDeclaration(value)), "linkage": llvm.LLVMGetLinkage(value),
               "visibility": llvm.LLVMGetVisibility(value), "dll_storage": llvm.LLVMGetDLLStorageClass(value)}
        if kind == "function":
            row.update(calling_convention=llvm.LLVMGetFunctionCallConv(value),
                       attributes=_attributes(mapper, llvm, value, llvm.LLVMCountParamTypes(ty)))
            calls[name] = []
            for index, instruction in enumerate(llvm.instructions(value)):
                instructions += 1
                require(instructions <= MAX_INSTRUCTIONS, "Module instruction bound exceeded")
                opcode = llvm.LLVMGetInstructionOpcode(instruction)
                operands = tuple(llvm.LLVMGetOperand(instruction, n)
                                 for n in range(llvm.LLVMGetNumOperands(instruction)))
                # Same-context identity check includes every operand, not only calls.
                structure.append((value, instruction, opcode, llvm.LLVMTypeOf(instruction), operands))
                if opcode in {5, 45, 67}:  # invoke, call, callbr
                    callee = llvm.LLVMGetCalledValue(instruction)
                    require(not callee or llvm.LLVMGetValueKind(callee) != 23,
                            "Inline assembly may embed symbol strings")
                    count = llvm.LLVMGetNumArgOperands(instruction)
                    calls[name].append({"instruction_index": index, "opcode": opcode,
                        "callee": by_value.get(callee), "callee_value_kind": llvm.LLVMGetValueKind(callee),
                        "type": llvm.string(llvm.LLVMPrintTypeToString(llvm.LLVMGetCalledFunctionType(instruction))),
                        "calling_convention": llvm.LLVMGetInstructionCallConv(instruction),
                        "argument_count": count, "operand_count": len(operands),
                        "operand_bundles": llvm.LLVMGetNumOperandBundles(instruction),
                        "attributes": _attributes(mapper, llvm, instruction, count, call=True)})
        elif kind == "global":
            row.update(constant=bool(llvm.LLVMIsGlobalConstant(value)),
                       thread_local_mode=llvm.LLVMGetThreadLocalMode(value))
            structure.append((value, llvm.LLVMGetInitializer(value)))
        else:
            structure.append((value, tuple(llvm.LLVMGetOperand(value, n)
                                           for n in range(llvm.LLVMGetNumOperands(value)))))
        inventory[name] = row
    result = {"target": llvm.LLVMGetTarget(module).decode(), "data_layout": llvm.LLVMGetDataLayoutStr(module).decode(),
              "symbols": inventory, "calls": calls,
              "definition_count": sum(not x["declaration"] for x in inventory.values()),
              "function_definition_count": sum(k == "function" and not inventory[n]["declaration"]
                                                for n, (k, _) in all_values.items())}
    require(result["target"] == TARGET, "Unexpected LLVM target")
    return result, tuple(structure)


def _attributes(mapper, llvm, value, count, *, call=False):
    return {key: sorted(rows, key=canonical)
            for key, rows in mapper._attrs(llvm, value, count, call=call).items()}


def _call_details(llvm, module):
    """Serialized exact call/argument evidence; structural pointer proof is separate."""
    globals_by_value = {value: name for name, (_, value) in _symbols(llvm, module).items()}
    result, printed = {}, 0
    for function in llvm.functions(module):
        if llvm.LLVMIsDeclaration(function):
            continue
        rows = []
        for index, instruction in enumerate(llvm.instructions(function)):
            if llvm.LLVMGetInstructionOpcode(instruction) not in {5, 45, 67}:
                continue
            text = llvm.string(llvm.LLVMPrintValueToString(instruction))
            arguments = []
            for i in range(llvm.LLVMGetNumArgOperands(instruction)):
                value = llvm.LLVMGetOperand(instruction, i)
                if value in globals_by_value:
                    arguments.append({"global_symbol": globals_by_value[value]})
                else:
                    arguments.append({"value_ir": llvm.string(llvm.LLVMPrintValueToString(value))})
            row = {"instruction_index": index, "instruction_ir": text,
                   "instruction_sha256": digest(text.encode("utf-8")), "arguments": arguments}
            printed += len(canonical(row))
            require(printed <= 4 * MAX_IR, "Serialized caller evidence exceeds bound")
            rows.append(row)
        result[llvm.name(function)] = rows
    return result


def _print(llvm, module):
    return llvm.string(llvm.LLVMPrintModuleToString(module)).encode("utf-8")


def _rename(llvm, module, mapping):
    values = _symbols(llvm, module)
    require(set(mapping) <= set(values) and not set(mapping.values()) & set(values),
            "Missing rename source or occupied destination")
    for old, new in mapping.items():
        data = new.encode("utf-8")
        llvm.LLVMSetValueName2(values[old][1], data, len(data))
        require(llvm.name(values[old][1]) == new, "LLVM changed requested qualified name")


def _verify(llvm, module):
    error = ctypes.c_void_p()
    require(not llvm.LLVMVerifyModule(module, 2, ctypes.byref(error)),
            "LLVM verification failed: " + llvm.string(error.value))


def qualify_modules(units, *, workspace_root, llvm_library, llvm_sha256,
                    toolchain_config_sha256, trusted_engine_pins, stop_file=None):
    """Return qualified bytes in input order plus a hash-bound, unlinked receipt.

    All inputs must be fresh owned copies (no Cargo hardlink alias). The caller
    supplies authenticated owners; this helper verifies pins, not Cargo lineage.
    It performs no LLVM passes, compiler/linker execution, or file writes.
    """
    _stop(stop_file)
    root = _path(workspace_root)
    require(type(units) is list and 1 <= len(units) <= MAX_UNITS, "Bounded unit list required")
    raw_inputs, owners, inputs, evidence, watched = [], [], [], [], {}
    for unit in units:
        require(type(unit) is dict and set(unit) == {"owner", "input", "evidence"}, "Exact unit schema required")
        owner_identity(unit["owner"])
        require(type(unit["evidence"]) is list and 1 <= len(unit["evidence"]) <= 32,
                "Caller-authenticated evidence descriptors required")
        require(_path(unit["owner"]["source"], root).is_file(), "Owned source identity must be a regular file")
        _stop(stop_file)
        raw_inputs.append(_descriptor(unit["input"], root))
        require(Path(unit["input"]["path"]).is_relative_to(root / ".runs"), "IR must be an owned private artifact")
        for item in [unit["input"], *unit["evidence"]]:
            _descriptor(item, root, limit=64 * 1024 * 1024)
            key = path_identity(item["path"])
            require(key not in watched or (watched[key]["sha256"], watched[key]["bytes"]) ==
                    (item["sha256"], item["bytes"]), "Conflicting input/evidence identity")
            watched.setdefault(key, dict(item))
        owners.append(dict(unit["owner"]))
        inputs.append(dict(unit["input"]))
        evidence.append([dict(x) for x in unit["evidence"]])
    require(sum(map(len, raw_inputs)) <= 64 * 1024 * 1024, "Aggregate IR input bound exceeded")
    mapper, engine = _bootstrap(root, llvm_library, llvm_sha256,
                                     toolchain_config_sha256, trusted_engine_pins)
    llvm, contexts, modules = None, [], []
    try:
        _stop(stop_file)
        llvm = mapper.open_llvm(workspace_root=root, llvm_library=Path(llvm_library),
                                trusted_engine_pins=trusted_engine_pins)
        _extra(llvm)
        inventories, originals, structures, original_calls = [], [], [], []
        for raw in raw_inputs:
            _stop(stop_file)
            context = llvm.LLVMContextCreate()
            contexts.append(context)
            module = mapper._parse(llvm, context, raw)
            modules.append(module)
            inventory, structure = _inventory(mapper, llvm, module)
            inventories.append(inventory)
            originals.append(_print(llvm, module))
            structures.append(structure)
            original_calls.append(_call_details(llvm, module))
        require(len({row["data_layout"] for row in inventories}) == 1, "Crate data layouts differ")
        plan = plan_qualification(owners, [x["sha256"] for x in inputs], inventories)
        outputs, rows = [], []
        for index, (module, mapping) in enumerate(zip(modules, plan["maps"])):
            _stop(stop_file)
            _rename(llvm, module, mapping)
            _verify(llvm, module)
            after, structure = _inventory(mapper, llvm, module)
            check_contract(inventories[index], after, mapping)
            require(structure == structures[index], "Instruction/operand/initializer identity changed")
            qualified = _print(llvm, module)
            qualified_calls = _call_details(llvm, module)
            reverse = {new: old for old, new in mapping.items()}
            _rename(llvm, module, reverse)
            _verify(llvm, module)
            require(_print(llvm, module) == originals[index], "Canonical exact name restoration failed")
            # Independently round-trip the actual serialized handoff, not only the live module.
            context = llvm.LLVMContextCreate()
            contexts.append(context)
            reparsed = mapper._parse(llvm, context, qualified)
            modules.append(reparsed)
            check_contract(inventories[index], _inventory(mapper, llvm, reparsed)[0], mapping)
            require(_call_details(llvm, reparsed) == qualified_calls, "Serialized full caller evidence changed")
            _rename(llvm, reparsed, reverse)
            _verify(llvm, reparsed)
            require(_print(llvm, reparsed) == originals[index], "Serialized exact name restoration failed")
            outputs.append(qualified)
            rows.append({"owner": owners[index], "stable_owner": owner_identity(owners[index]),
                "input": inputs[index], "evidence": evidence[index],
                "input_canonical_sha256": digest(originals[index]),
                "qualified_sha256": digest(qualified), "qualified_bytes": len(qualified),
                "symbol_map": mapping, "reverse_symbol_map": reverse,
                "before": inventories[index], "after": after,
                "caller_details_before": original_calls[index], "caller_details_after": qualified_calls,
                "definition_count_before": inventories[index]["definition_count"],
                "definition_count_after": after["definition_count"],
                "unchanged_external_definitions": sorted(name for name, row in inventories[index]["symbols"].items()
                    if not row["declaration"] and row["linkage"] not in LOCAL_LINKAGES),
                "unchanged_declarations": sorted(name for name, row in inventories[index]["symbols"].items()
                    if row["declaration"]),
                "exact_restore_roundtrip": True, "serialized_restore_roundtrip": True,
                "all_instruction_operand_initializer_identities_preserved": True})
        _stop(stop_file)
        for item in watched.values():
            _descriptor(item, root, limit=64 * 1024 * 1024)
        for item in engine.values():
            require(digest(_read(item["path"])) == item["sha256"], "Engine changed during qualification")
        mapper._recheck_engine(trusted_engine_pins, root)
        loaded = _loaded(root, engine)
        report = {"schema_version": 1, "status": "crate_symbols_qualified_unlinked_unvalidated",
            "identity_authority": "caller_supplied_authenticated_Cargo_units_not_reauthenticated_here",
            "units": rows, "collision_groups": plan["collisions"],
            "unresolved_external_declarations": plan["unresolved_external_declarations"],
            "external_definition_owners": plan["external_resolution"],
            "definition_count_before": sum(x["definition_count_before"] for x in rows),
            "definition_count_after": sum(x["definition_count_after"] for x in rows),
            "reviewed_engine_inputs": [engine[k] for k in sorted(engine)],
            "checked_inputs": [watched[k] for k in sorted(watched)], "loaded_production_modules": loaded,
            "inputs_unchanged": True, "calling_convention_rewritten": False,
            "linkage_rewritten": False, "passes_executed": False, "vm_applied": False,
            "target_executed": False, "native_link_verified": False,
            "limitations": ["Names only; not scalar acceptance, code/data protection, or functional validation.",
                "Unresolved external declarations are recorded, never resolved to a same-named local definition.",
                "Module/inline assembly, linker directives and COMDAT selection require a separate contract.",
                "Caller pins helpers before first import and supplies a bounded worker and Cargo authentication.",
                "Preloaded module origin/current bytes are checked; arbitrary in-memory monkeypatches are not attested.",
                "This receipt does not prove a future linker preserved this symbol/ABI graph."]}
        return tuple(outputs), report
    finally:
        if llvm is not None:
            for module in reversed(modules):
                llvm.LLVMDisposeModule(module)
            for context in reversed(contexts):
                llvm.LLVMContextDispose(context)
            llvm.close()
