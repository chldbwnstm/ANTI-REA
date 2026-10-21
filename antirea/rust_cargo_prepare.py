"""Private generic Cargo IR preparation, not native linking or validation.

Only the explicit prepare_capture entry may run pinned opt/llvm-link/LLVM-C.
No Cargo, rustc, target, native linker or received code is executed here.
"""
from __future__ import annotations

import ctypes
import copy
import hashlib
import importlib.util
import importlib.machinery
import importlib
import json
import ntpath
import os
from pathlib import Path
import re
import stat
import sys
import time

TARGET = "x86_64-pc-windows-msvc"
PASSES = "function(sroa,mem2reg),strip-dead-prototypes"
HEX = re.compile(r"[0-9a-f]{64}\Z")
SYMBOL = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")
LIFETIMES = {"llvm.lifetime.start.p0", "llvm.lifetime.end.p0"}
SEMANTIC = "antirea/rust_cargo_semantic.py"
MAPPER = "antirea/rust_ir.py"
NORMALIZER = "antirea/rust_normalize.py"
QUALIFIER = "antirea/rust_qualify.py"
PACKAGE_ROLES = ("rust_cargo", "scope", "process", "rust_cargo_artifacts",
                 "rust_cargo_build", "rust_cargo_units", "rust_cargo_semantic",
                 "rust_ir", "rust_normalize", "rust_qualify")
SOURCE_IR_KIND = "qualified_raw_linked_baseline"
MAX_UNITS, MAX_IR = 64, 16 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("utf-8")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def json_bytes(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def nonfinite(_):
        raise ValueError("nonfinite JSON")
    require(isinstance(raw, bytes) and 0 < len(raw) <= 64 * 1024 * 1024, "bounded JSON bytes required")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)


def schema(value):
    require(isinstance(value, dict) and type(value.get("schema_version")) is int
            and value["schema_version"] == 1, "schema 1 object required")


def absolute(value):
    require(isinstance(value, (str, Path)), "path text required")
    path = Path(value)
    require(path.is_absolute() and ".." not in path.parts and not str(path).startswith(("\\\\", "//"))
            and not any(":" in part for part in path.parts[1:])
            and not any(ord(char) < 32 for char in str(path)), "absolute ordinary path required")
    require(not set(part.casefold() for part in path.parts) & {"rea-analysis-reports", "attackerfolder", "linkrepro", "shared"}
            and path.name.casefold() != "env.setting", "received/environment-dump path forbidden")
    return path


def descriptor(value):
    require(isinstance(value, dict) and isinstance(value.get("path"), str)
            and isinstance(value.get("sha256"), str) and HEX.fullmatch(value["sha256"]),
            "file descriptor path/SHA required")
    absolute(value["path"])
    if "bytes" in value:
        require(type(value["bytes"]) is int and value["bytes"] >= 0, "strict byte count required")
    return {key: value[key] for key in ("path", "sha256", "bytes") if key in value}


def path_key(value):
    """Windows identity for comparisons only; never rewrite recorded argv/path."""
    return ntpath.normcase(ntpath.normpath(str(absolute(value))))


path_identity = path_key


def pin_index(items):
    """Collapse same-identity spellings only when every supplied pin agrees."""
    result = {}
    for raw in items:
        item = descriptor(raw)
        key = path_key(item["path"])
        if key in result:
            prior = result[key]
            require(prior["sha256"] == item["sha256"]
                    and ("bytes" not in prior or "bytes" not in item or prior["bytes"] == item["bytes"]),
                    "conflicting hash/count for one Windows path identity")
            if "bytes" not in prior and "bytes" in item:
                result[key] = {**prior, "bytes": item["bytes"]}
        else:
            result[key] = item
    return result


def under(path, roots):
    return any(path.is_relative_to(root) for root in roots)


def unit_key(unit):
    for key in ("package_id", "target_name", "source"):
        require(isinstance(unit.get(key), str) and unit[key], "complete actual unit identity required")
    return unit["package_id"], unit["target_name"], path_key(unit["source"])


def _arm_closure(artifact, inspection, mode):
    """Pure graph selection from actual artifacts, never metadata node count."""
    schema(artifact)
    require(artifact.get("status") == "artifacts_bound_not_build_validated"
            and artifact.get("mode") == mode, "actual bound collector arm required")
    units = artifact.get("units")
    require(isinstance(units, list) and 1 <= len(units) <= MAX_UNITS
            and type(artifact.get("actual_compiled_units")) is int
            and artifact["actual_compiled_units"] == len(units), "bounded exact actual unit count required")
    inputs = inspection["input_snapshot"]
    roots = [absolute(item) for item in inputs["roots"]]
    source_pins = pin_index(inputs["files"])
    packages = {}
    for row in inspection["resolution"]["closure"]:
        package = row["package"]
        require(package["id"] not in packages, "ambiguous metadata package")
        packages[package["id"]] = package
    by_id, keys, producers = {}, set(), {}
    for unit in units:
        require(isinstance(unit, dict) and isinstance(unit.get("unit"), str) and unit["unit"]
                and unit["unit"] not in by_id, "missing/duplicate actual unit identity")
        identity = unit_key(unit)
        require(identity not in keys, "ambiguous repeated package/target unit")
        keys.add(identity)
        package = packages.get(unit["package_id"])
        require(package is not None, "actual unit outside inspected package closure")
        matches = [target for target in package["targets"]
                   if target.get("name") == unit["target_name"]
                   and path_key(target.get("src_path")) == identity[2]
                   and target.get("crate_types") == unit.get("crate_types")]
        require(len(matches) == 1, "actual unit/metadata target identity is missing or ambiguous")
        source = absolute(unit["source"])
        require(under(source, roots) and path_key(source) in source_pins, "actual crate source outside owned snapshot")
        declared = unit.get("declared_dependencies")
        require(isinstance(declared, list), "compiler-declared dependencies required")
        pin_index(declared)
        source_rows = [row for row in declared if path_key(row["path"]) == path_key(source)]
        require(len(source_rows) == 1 and source_rows[0]["sha256"] == source_pins[path_key(source)]["sha256"]
                and source_rows[0].get("classification") == "owned_source", "root source provenance differs")
        for row in declared:
            if row.get("classification") == "owned_source":
                path = absolute(row["path"])
                expected = source_pins.get(path_key(path))
                require(under(path, roots) and expected is not None and expected["sha256"] == row["sha256"]
                        and ("bytes" not in row or "bytes" not in expected or row["bytes"] == expected["bytes"]),
                        "consumed owned source is not snapshot-bound")
        require(isinstance(unit.get("externs"), list) and isinstance(unit.get("declared_outputs"), list)
                and isinstance(unit.get("outputs"), list), "actual extern/output inventory required")
        for row in [*unit["declared_outputs"], *unit["outputs"]]:
            item = descriptor(row)
            name = path_key(item["path"])
            if name in producers:
                prior = producers[name]
                require(prior[0] == unit["unit"], "ambiguous actual artifact producer")
                pin_index([prior[1], item])
            producers[name] = unit["unit"], item
        by_id[unit["unit"]] = unit
    edges = {}
    for identity, unit in by_id.items():
        aliases, edges[identity] = set(), []
        for edge in unit["externs"]:
            require(isinstance(edge, dict) and isinstance(edge.get("alias"), str)
                    and SYMBOL.fullmatch(edge["alias"]) and edge["alias"] not in aliases,
                    "missing/duplicate extern alias")
            aliases.add(edge["alias"])
            producer = edge.get("producer_unit")
            require(producer in by_id and producer != identity, "missing/self extern producer")
            item = descriptor(edge)
            actual = producers.get(path_key(item["path"]))
            require(actual is not None and actual[0] == producer and actual[1]["sha256"] == item["sha256"]
                    and ("bytes" not in actual[1] or "bytes" not in item or actual[1]["bytes"] == item["bytes"]),
                    "extern edge does not identify its actual output producer")
            pin_index([actual[1], item])
            edges[identity].append({"alias": edge["alias"], "producer_unit": producer, "artifact": item})
    resolution, selected = inspection["resolution"], inspection["resolution"]["selected_target"]
    candidates = [unit for unit in units if unit["package_id"] == resolution["selected_package_id"]
                  and unit["target_name"] == selected["name"]
                  and absolute(unit["source"]) == absolute(selected["src_path"])]
    require(len(candidates) == 1, "explicit selected Cargo target lacks one actual unit")
    ordered, active, visited = [], set(), set()
    def visit(identity):
        require(identity not in active, "cyclic actual extern producer graph")
        if identity in visited:
            return
        active.add(identity)
        for edge in sorted(edges[identity], key=lambda item: (item["alias"], item["producer_unit"])):
            visit(edge["producer_unit"])
        active.remove(identity)
        visited.add(identity)
        ordered.append(identity)
    visit(candidates[0]["unit"])
    chosen = [by_id[identity] for identity in ordered]
    if mode == "derivative":
        for unit in chosen:
            ir = descriptor(unit.get("llvm_ir"))
            require(absolute(ir["path"]).suffix == ".ll" and type(ir.get("bytes")) is int
                    and 0 < ir["bytes"] <= MAX_IR, "bounded declared derivative LLVM IR required")
            exact = [descriptor(row) for row in unit["declared_outputs"] if path_key(row["path"]) == path_key(ir["path"])]
            require(len(exact) == 1 and exact[0]["sha256"] == ir["sha256"]
                    and exact[0].get("bytes") == ir["bytes"], "LLVM IR is not the exact compiler-declared output")
            pin_index([exact[0], ir])
    return {"root_unit": candidates[0]["unit"], "units": chosen,
            "edges": {identity: edges[identity] for identity in ordered},
            "unselected_actual_units": sorted(set(by_id) - visited)}


def select_capture(capture, inner_plan, *, check_environment):
    """Pure contract/graph check; caller authenticates files and processes."""
    schema(capture)
    require(capture.get("status") == "cargo_original_derivative_captured_not_protected"
            and all(capture.get(key) is False for key in ("target_executed", "vm_applied", "published")),
            "successful unprotected production capture required")
    inspection = inner_plan["inspection"]
    schema(inspection)
    require(inspection.get("backend") == "rust_cargo_native"
            and inspection.get("status") == "inspected_build_not_implemented"
            and inspection.get("blockers") == [], "successful metadata inspection required")
    fields = dict(inspection)
    require(fields.pop("fingerprint", None) == digest(canonical(fields)), "inspection fingerprint mismatch")
    require(inspection["toolchain"]["selection"]["target"] == TARGET, "unsupported explicit target")
    exports = inspection["project"].get("functions")
    require(isinstance(exports, list) and 1 <= len(exports) <= 64
            and all(isinstance(name, str) and SYMBOL.fullmatch(name) for name in exports)
            and len(set(exports)) == len(exports), "unique explicit public C ABI roots required")
    require(set(capture.get("arms", {})) == {"original", "derivative"}, "both actual arms required")
    artifacts = {mode: capture["arms"][mode]["artifacts"] for mode in ("original", "derivative")}
    gate = check_environment(artifacts["original"], artifacts["derivative"])
    require(gate.get("status") == "declared_source_environment_dependencies_matched"
            and gate.get("handoff_allowed") is True, "compiler-consumed environment differs; no protection handoff")
    arms = {mode: _arm_closure(artifacts[mode], inspection, mode) for mode in artifacts}
    require({unit_key(unit) for unit in arms["original"]["units"]}
            == {unit_key(unit) for unit in arms["derivative"]["units"]}, "original/derivative selected unit closure differs")
    return {"schema_version": 1, "target": TARGET, "public_exports": sorted(exports), "arms": arms,
            "source_environment_handoff": gate, "native_link_validated": False,
            "selection_basis": "explicit metadata target plus actual extern producer edges; not all metadata nodes"}


class Reader:
    def __init__(self, workspace):
        self.root = absolute(workspace)
        self.stop = self.root / ".runs/defense-loop/STOP"
        self.watched = {}

    def check_stop(self):
        require(not self.stop.exists(), "STOP set")

    def path(self, value, *, owned=True, fresh=False, hardlinks=False, terminal=False):
        if not terminal:
            self.check_stop()
        path = absolute(value)
        require(not owned or path.is_relative_to(self.root), "path outside owned workspace")
        require(not path.is_relative_to(self.root / ".runs/defense-loop"), "controller path cannot be an artifact")
        for item in [path, *path.parents]:
            try:
                info = item.lstat()
            except FileNotFoundError:
                continue
            require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
                    "symlink/reparse artifact rejected")
            if stat.S_ISREG(info.st_mode):
                require(hardlinks or info.st_nlink == 1, "hardlinked trusted artifact rejected")
        if fresh:
            require(not os.path.lexists(path) and path.parent.is_dir(), "fresh output with existing parent required")
        else:
            require(path.exists(), "missing input")
        return path

    def read(self, item, *, owned=True, hardlinks=False, limit=64 * 1024 * 1024):
        item = descriptor(item)
        path = self.path(item["path"], owned=owned, hardlinks=hardlinks)
        before = path.stat()
        require(path.is_file() and 0 <= before.st_size <= limit, "input type/size bound")
        raw = path.read_bytes()
        after = path.stat()
        require((before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_ino, after.st_size, after.st_mtime_ns), "input changed during read")
        require(digest(raw) == item["sha256"] and ("bytes" not in item or len(raw) == item["bytes"]),
                "input descriptor changed")
        self.remember_verified({**item, "bytes": len(raw)}, owned=owned, hardlinks=hardlinks)
        return raw

    def remember_verified(self, item, *, owned, hardlinks):
        """Record a descriptor just independently hashed by a trusted inventory."""
        item = descriptor(item)
        path = self.path(item["path"], owned=owned, hardlinks=hardlinks)
        require(type(item.get("bytes")) is int, "verified inventory byte count required")
        key = path_key(path)
        prior = self.watched.get(key)
        record = {"path": str(path), "sha256": item["sha256"], "bytes": item["bytes"],
                  "owned": owned, "hardlinks": hardlinks}
        if prior is not None:
            pin_index([prior, record])
            # Preserve first observed spelling and the strongest access policy.
            record.update(path=prior["path"], owned=owned or prior["owned"],
                          hardlinks=hardlinks and prior["hardlinks"])
        self.watched[key] = record

    def current(self, value, *, owned=True, hardlinks=False):
        path = self.path(value, owned=owned, hardlinks=hardlinks)
        require(path.is_file(), "file required")
        with path.open("rb") as handle:
            sha = hashlib.file_digest(handle, "sha256").hexdigest()
        item = {"path": str(path), "sha256": sha, "bytes": path.stat().st_size}
        self.read(item, owned=owned, hardlinks=hardlinks, limit=512 * 1024 * 1024)
        return item

    def write(self, path, raw, *, terminal=False):
        path = self.path(path, fresh=True, terminal=terminal)
        with path.open("xb") as handle:
            handle.write(raw)
        if terminal:
            return {"path": str(path), "sha256": digest(raw), "bytes": len(raw)}
        return self.current(path)

    def recheck(self):
        for row in list(self.watched.values()):
            self.read(row, owned=row["owned"], hardlinks=row["hardlinks"], limit=512 * 1024 * 1024)


class _PackageSourceImporter:
    """Fixed antirea namespace only, compiling exact caller-approved source.

    A trusted source-only parent must load this entry itself. Cache origin and
    current source identity are checked, not arbitrary live Python object state.
    """

    def __init__(self, reader, pins):
        self.reader, self.pins, self.executed = reader, pins, []

    def source(self, name):
        require(re.fullmatch(r"antirea(?:\.[A-Za-z_][A-Za-z0-9_]*)*", name) is not None,
                "invalid production module identity")
        stem = self.reader.root / Path(*name.split("."))
        choices = [(stem / "__init__.py", True), (Path(str(stem) + ".py"), False)]
        found = [(self.pins[path_key(path)], package) for path, package in choices
                 if path_key(path) in self.pins]
        require(len(found) == 1 and (name != "antirea" or found[0][1]),
                "unknown/ambiguous production source module: " + name)
        item, package = found[0]
        self.reader.path(item["path"])
        return item, package

    def find_spec(self, fullname, path=None, target=None):
        if fullname != "antirea" and not fullname.startswith("antirea."):
            return None
        item, package = self.source(fullname)
        spec = importlib.machinery.ModuleSpec(fullname, self, origin=item["path"], is_package=package)
        spec.has_location = True
        if package:
            spec.submodule_search_locations = [str(Path(item["path"]).parent)]
        return spec

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        item, _ = self.source(module.__name__)
        raw = self.reader.read(item)
        module.__cached__ = None
        exec(compile(raw, item["path"], "exec", dont_inherit=True), module.__dict__)
        self.executed.append({"module": module.__name__, **descriptor(item),
                              "loader": "verified_source_bytes_no_bytecode_cache"})


def check_loaded_modules(reader, pins):
    result = []
    for name, module in sorted(list(sys.modules.items())):
        if name != "antirea" and not name.startswith("antirea."):
            continue
        require(re.fullmatch(r"antirea(?:\.[A-Za-z_][A-Za-z0-9_]*)*", name) is not None,
                "invalid loaded production module name")
        relative = reader.root / Path(*name.split("."))
        package_paths = getattr(module, "__path__", None)
        expected = relative / "__init__.py" if package_paths is not None else Path(str(relative) + ".py")
        location, spec = getattr(module, "__file__", None), getattr(module, "__spec__", None)
        origin = getattr(spec, "origin", None)
        require(location and origin and getattr(spec, "_initializing", False) is False
                and path_key(location) == path_key(expected) and path_key(origin) == path_key(expected)
                and path_key(expected) in pins,
                "incompatible/partial preloaded production module: " + name)
        if name == "antirea" or package_paths is not None:
            require(package_paths is not None and list(package_paths) == [str(relative)],
                    "production package search path differs")
        item = pins[path_key(expected)]
        reader.read(item)
        result.append({"module": name, **item})
    return result


def _check_package_inventory(reader, pins):
    current = {path_key(path) for path in (reader.root / "antirea").rglob("*.py")}
    recorded = {key for key, item in pins.items()
                if absolute(item["path"]).is_relative_to(reader.root / "antirea")
                and Path(item["path"]).suffix == ".py"}
    require(current == recorded and path_key(reader.root / "antirea/__init__.py") in current,
            "complete production module pin closure/inventory required before import")
    for key in sorted(current):
        reader.read(pins[key])
    return current


def load_production(reader, pins):
    """Load fixed package roles using reviewed source bytes, never .pyc.

    Existing canonical, complete modules may be reused in a fresh reviewed
    worker. This is not in-memory-code attestation or a shared plugin-host API.
    Failed new imports are rolled back; pre-existing modules are never purged.
    """
    check_loaded_modules(reader, pins)
    _check_package_inventory(reader, pins)
    importer = _PackageSourceImporter(reader, pins)
    old_path, old_meta = list(sys.path), list(sys.meta_path)
    old_modules = {name for name in sys.modules if name == "antirea" or name.startswith("antirea.")}
    try:
        sys.path.insert(0, str(reader.root))
        sys.meta_path.insert(0, importer)
        loaded = {name: importlib.import_module("antirea." + name) for name in PACKAGE_ROLES}
        check_loaded_modules(reader, pins)
        _check_package_inventory(reader, pins)
        reader.recheck()
        # No arbitrary caller module names or external plugin paths are accepted.
        loaded["_source_imports"] = list(importer.executed)
        return loaded
    except BaseException:
        for name in sorted(set(sys.modules) - old_modules, key=len, reverse=True):
            if name != "antirea" and not name.startswith("antirea."):
                continue
            removed = sys.modules.pop(name, None)
            parent_name, _, child = name.rpartition(".")
            parent = sys.modules.get(parent_name)
            if parent is not None and child in vars(parent) and vars(parent)[child] is removed:
                delattr(parent, child)
        raise
    finally:
        sys.meta_path[:] = old_meta
        sys.path[:] = old_path


def authenticate(reader, capture, inner, capture_plan, inner_path):
    """Rehash inventories and replay the existing pure artifact collector."""
    from antirea import rust_cargo as metadata, rust_cargo_artifacts as artifacts
    from antirea import rust_cargo_build as build, rust_cargo_units as units
    require(path_key(capture["inspection_receipt"]["path"]) == path_key(inner_path), "capture points to different metadata")
    reader.read(capture["inspection_receipt"])
    require(capture_plan.get("inspection_fingerprint") == inner["inspection"]["fingerprint"],
            "capture recipe points to different inspection")
    for item in capture["engine_inputs"] + capture["evidence_files"]:
        reader.read(item, owned=False, limit=512 * 1024 * 1024)
    require(isinstance(capture.get("commands"), list) and capture["commands"], "actual commands required")
    for row in capture["commands"]:
        require(metadata._clean(row["process"]), "capture process/owned cleanup not successful")
        saved = json_bytes(reader.read(row["files"]["process"]))
        require(canonical(saved) == canonical(row["process"]), "saved process receipt mismatch")
        for key in ("stdout", "stderr"):
            require(saved[key] == row["files"][key]["path"], "process/log path mismatch")
            reader.read(row["files"][key])
    inspection = inner["inspection"]
    for snapshot in (inspection["input_snapshot"], inspection["toolchain"]["inventory"]):
        require(build.inventory_trees(snapshot["roots"])["files"] == snapshot["files"],
                "source/compiler file-name/content inventory changed")
        for item in snapshot["files"]:
            reader.remember_verified(item, owned=snapshot is inspection["input_snapshot"], hardlinks=False)
    native = capture["native_link_context"]
    require(build.native_link_context(native["configuration"]["path"], workspace_root=reader.root) == native,
            "selected native link context changed")
    for item in native["inventory"]["files"]:
        reader.remember_verified(item, owned=False, hardlinks=True)
    reader.read(native["configuration"])
    for item in (capture["recorder"]["source"], capture["recorder"]["binary"]):
        reader.read(item)
    recipes = {}
    for mode in ("original", "derivative"):
        arm, row = capture_plan["arms"][mode], capture["arms"][mode]
        require(row["command"]["process"]["argv"] == arm["argv"]
                and canonical(row["command"]) in [canonical(item) for item in capture["commands"]],
                "arm command is not the recorded Cargo recipe")
        require(build.inventory_trees([arm["policy"]["target_root"]]) == row["target_inventory"],
                "captured target tree changed")
        for item in row["target_inventory"]["files"]:
            reader.remember_verified(item, owned=True, hardlinks=True)
        saved = json_bytes(reader.read(row["receipt"]))
        require(canonical(saved) == canonical({key: value for key, value in row.items() if key != "receipt"}),
                "arm private receipt differs from capture")
        checked = units.inspect_unit_records(Path(arm["policy"]["record_root"]), arm)
        require(canonical(checked) == canonical(row["unit_verification"]), "unit receipts changed")
        bundles = [{"unit": item["unit"], "start_bytes": reader.read(item["start"]),
                    "finish_bytes": reader.read(item["finish"])} for item in checked["units"]]
        observations = {item["path"]: {"sha256": item["sha256"], "bytes": item["bytes"]}
                        for item in row["target_inventory"]["files"]}
        extra = [*inspection["input_snapshot"]["files"], *inspection["toolchain"]["inventory"]["files"],
                 *native["inventory"]["files"], native["configuration"], capture["recorder"]["binary"]]
        for item in extra:
            observations[item["path"]] = {"sha256": item["sha256"], "bytes": item["bytes"]}
        depinfo = {item["path"]: reader.read(item, hardlinks=True) for item in row["target_inventory"]["files"]
                   if item["path"].endswith(".d")}
        compiler = dict(inspection["toolchain"]["compiler_inputs"])
        for item in [*native["inventory"]["files"], native["configuration"]]:
            require(item["path"] not in compiler or compiler[item["path"]] == item["sha256"], "conflicting compiler pin")
            compiler[item["path"]] = item["sha256"]
        replay = artifacts.collect_cargo_artifacts(bundles, reader.read(row["command"]["files"]["stdout"]),
            arm=arm, source_snapshot={item["path"]: item["sha256"] for item in inspection["input_snapshot"]["files"]},
            compiler_snapshot=compiler, packages=[item["package"] for item in inspection["resolution"]["closure"]],
            observed_files=observations, dep_info_contents=depinfo)
        require(canonical(replay) == canonical(row["artifacts"]), "actual collector replay differs")
        recipes[mode] = {item["unit"]: json_bytes(item["start_bytes"]) for item in bundles
                         if json_bytes(item["start_bytes"])["kind"] == "crate"}
    # Do not trust the capture's summarized comparison without replaying it.
    expected = []
    left, right = {}, {}
    for mode, result in (("original", left), ("derivative", right)):
        for start in recipes[mode].values():
            parsed = units.parse_rustc_args(start["original_argv"][1:])
            identity = start["cargo_identity"]["CARGO_MANIFEST_DIR"], parsed["values"]["--crate-name"][0]
            require(identity not in result, "ambiguous actual recipe identity")
            result[identity] = start
    require(left and left.keys() == right.keys(), "actual recipe unit sets differ")
    for identity in sorted(left):
        expected.append(units.compare_cargo_decisions(left[identity], right[identity],
            capture_plan["arms"]["original"], capture_plan["arms"]["derivative"]))
    require(canonical(expected) == canonical(capture["decisions"]), "Cargo decision summary differs from actual records")
    return recipes


def inspect_ir(mapper, library, raw, *, workspace_root, trusted_engine_pins):
    """Raw inventory only; personality/EH suitability is proved after linking.

    Cross-crate declarations are still unresolved here. This is NOT a scalar
    acceptance gate and must never be used as the final mapper contract.
    """
    llvm = mapper.open_llvm(workspace_root=workspace_root, llvm_library=library,
                            trusted_engine_pins=trusted_engine_pins)
    context, module = None, None
    try:
        get_layout = llvm.dll.LLVMGetDataLayoutStr
        get_layout.restype, get_layout.argtypes = ctypes.c_char_p, [ctypes.c_void_p]
        personality = llvm.dll.LLVMGetPersonalityFn
        personality.restype, personality.argtypes = ctypes.c_void_p, [ctypes.c_void_p]
        context = llvm.LLVMContextCreate()
        module = mapper._parse(llvm, context, raw)
        length = ctypes.c_size_t()
        llvm.LLVMGetModuleInlineAsm(module, ctypes.byref(length))
        require(not length.value and not llvm.LLVMGetFirstGlobal(module)
                and not llvm.LLVMGetFirstGlobalAlias(module) and not llvm.LLVMGetFirstGlobalIFunc(module)
                and not llvm.LLVMGetNamedMetadataNumOperands(module, b"llvm.linker.options"),
                "unsupported global/alias/ifunc/assembly/linker metadata; no data protection claim")
        functions = {llvm.name(value): value for value in llvm.functions(module)}
        definitions, declarations, graph, calls = {}, {}, {}, {}
        for name, function in functions.items():
            signature = llvm.LLVMGlobalGetValueType(function)
            count = llvm.LLVMCountParamTypes(signature)
            row = {"type": llvm.string(llvm.LLVMPrintTypeToString(signature)),
                "calling_convention": llvm.LLVMGetFunctionCallConv(function),
                "linkage": llvm.LLVMGetLinkage(function), "visibility": llvm.LLVMGetVisibility(function),
                "dll_storage": llvm.LLVMGetDLLStorageClass(function), "attributes": mapper._attrs(llvm, function, count)}
            if llvm.LLVMIsDeclaration(function):
                declarations[name] = row
                continue
            require(not llvm.LLVMGetComdat(function), "unsupported COMDAT definition: " + name)
            row["personality"] = llvm.name(personality(function)) if llvm.LLVMHasPersonalityFn(function) else None
            definitions[name], graph[name], calls[name] = row, [], []
            for instruction in llvm.instructions(function):
                if llvm.LLVMGetInstructionOpcode(instruction) != 45:
                    continue
                callee = llvm.LLVMGetCalledValue(instruction)
                target = llvm.name(callee) if callee else ""
                require(functions.get(target) == callee and llvm.LLVMGetValueKind(callee) == 5
                        and not llvm.LLVMGetNumOperandBundles(instruction)
                        and llvm.LLVMGetCalledFunctionType(instruction) == llvm.LLVMGlobalGetValueType(callee)
                        and llvm.LLVMGetInstructionCallConv(instruction) == llvm.LLVMGetFunctionCallConv(callee),
                        "unsupported indirect/asm/type/CC call in " + name)
                if target in LIFETIMES and llvm.LLVMGetIntrinsicID(callee):
                    continue
                graph[name].append(target)
                calls[name].append({"callee": target, "calling_convention": llvm.LLVMGetInstructionCallConv(instruction),
                    "type": llvm.string(llvm.LLVMPrintTypeToString(llvm.LLVMGetCalledFunctionType(instruction))),
                    "attributes": mapper._attrs(llvm, instruction, llvm.LLVMGetNumArgOperands(instruction), call=True)})
        result = {"target": llvm.LLVMGetTarget(module).decode(), "data_layout": get_layout(module).decode(),
                  "definitions": definitions, "declarations": declarations, "graph": graph, "calls": calls}
        require(result["target"] == TARGET, "parsed IR target differs from explicit Windows target")
        return result
    finally:
        if module:
            llvm.LLVMDisposeModule(module)
        if context:
            llvm.LLVMContextDispose(context)
        llvm.close()


def check_preservation(before, after):
    for field in ("target", "data_layout", "definitions", "graph", "calls"):
        require(canonical(before[field]) == canonical(after[field]), "canonicalization changed parsed contract: " + field)
    removed = set(before["declarations"]) - set(after["declarations"])
    require(removed <= LIFETIMES, "canonicalization removed non-lifetime declarations")
    for name, row in after["declarations"].items():
        require(before["declarations"].get(name) == row, "canonicalization changed declaration ABI")
    return {"function_contract_preserved": True, "calling_convention_rewritten": False,
            "removed_lifetime_declarations": sorted(removed)}


def check_linked_contract(parts, linked):
    require(linked["target"] == TARGET and all(row["target"] == TARGET for row in parts),
            "crate IR target mismatch")
    require(parts and len({row["data_layout"] for row in parts}) == 1
            and linked["data_layout"] == parts[0]["data_layout"], "crate IR data-layout mismatch")
    definitions, graph, calls = {}, {}, {}
    for part in parts:
        for name, signature in part["definitions"].items():
            require(name not in definitions, "duplicate crate definition needs explicit linkage resolution: " + name)
            definitions[name], graph[name], calls[name] = signature, part["graph"][name], part["calls"][name]
    for field, expected in (("definitions", definitions), ("graph", graph), ("calls", calls)):
        require(canonical(linked[field]) == canonical(expected), "LLVM linking changed parsed contract: " + field)
    for part in parts:
        for name, declaration in part["declarations"].items():
            if name in definitions:
                definition = definitions[name]
                for key in ("type", "calling_convention"):
                    require(declaration[key] == definition[key], "cross-crate declaration/definition ABI mismatch: " + name)
                declaration_abi = {key: rows for key, rows in declaration.get("attributes", {}).items()
                                   if key != "4294967295"}
                definition_abi = {key: rows for key, rows in definition.get("attributes", {}).items()
                                  if key != "4294967295"}
                require(declaration_abi == definition_abi,
                        "cross-crate parameter/return ABI attributes differ: " + name)
    return {"definitions": sorted(definitions), "definition_and_call_contracts_preserved": True,
            "native_link_verified": False}


def inspect_scalar_ir(mapper, library, raw, exports, *, workspace_root, trusted_engine_pins):
    """Independent final LLVM-C scalar and exact typed-intrinsic gate."""
    llvm = mapper.open_llvm(workspace_root=workspace_root, llvm_library=library,
                            trusted_engine_pins=trusted_engine_pins)
    context, module = None, None
    try:
        get_layout = llvm.dll.LLVMGetDataLayoutStr
        get_layout.restype, get_layout.argtypes = ctypes.c_char_p, [ctypes.c_void_p]
        context = llvm.LLVMContextCreate()
        module = mapper._parse(llvm, context, raw)
        _, signatures, graph, calls, _ = mapper._inspect(llvm, module, set(exports))
        intrinsic = mapper.intrinsic_inventory(llvm, module)
        return {"target": llvm.LLVMGetTarget(module).decode(), "data_layout": get_layout(module).decode(),
                "definitions": signatures, "graph": graph, "calls": calls,
                "declarations": intrinsic["declarations"], "intrinsics": intrinsic["declarations"],
                "intrinsic_calls": intrinsic["calls"]}
    finally:
        if module:
            llvm.LLVMDisposeModule(module)
        if context:
            llvm.LLVMContextDispose(context)
        llvm.close()


ABI_FIELDS = ("type", "calling_convention", "linkage", "visibility", "dll_storage", "attributes")


def _attribute_sets(attributes):
    # LLVM attributes at one parameter/function index are sets, not ordered
    # arguments. The normalizer sorts them; the mapper retains LLVM API order.
    # Preserve every key, value and duplicate count while comparing these APIs.
    require(type(attributes) is dict and all(type(rows) is list for rows in attributes.values()),
            "malformed attribute-set inventory")
    return {key: sorted(rows, key=canonical) for key, rows in attributes.items()}


def _abi(row):
    return {key: _attribute_sets(row[key]) if key == "attributes" else row[key] for key in ABI_FIELDS}


def _call_contract(row):
    return {"callee": row["callee"], "type": row["type"], "attributes": _attribute_sets(row["attributes"])}


def _surviving_callers(name, removed, calls):
    """Recompute transitive destinations from recorded original call occurrences."""
    visiting = set()
    def visit(target):
        require(target not in visiting, "cyclic inline provenance")
        visiting.add(target)
        direct = {owner for owner, rows in calls.items() if any(row["callee"] == target for row in rows)}
        found = set()
        for owner in direct:
            found.update(visit(owner) if owner in removed else {owner})
        visiting.remove(target)
        return found
    return sorted(visit(name))


CALL_COMPARISON = "llvm_typed_attribute_resolved_call_operands"


def _operand_text(text, contract):
    """Recompute the v3 typed operand representation without importing its code.

    LLVM-C produced the recorded type/attributes in the pinned child. This
    receipt check is not a second LLVM parse. It binds that record to every
    byte of the printed operand, resolving (not deleting) a call's #N label.
    """
    require(type(text) is str and type(contract) is dict
            and set(contract) == {"type", "value_kind", "ir", "call_attributes"}
            and type(contract["type"]) is str and bool(contract["type"])
            and type(contract["value_kind"]) is int and contract["value_kind"] >= 0
            and type(contract["ir"]) is str, "malformed typed operand provenance")
    refs, cursor, quoted = [], 0, False
    while cursor < len(text):
        ch = text[cursor]
        if quoted:
            if ch == "\\":
                require(cursor + 1 < len(text), "malformed quoted operand provenance")
                cursor += 2
                continue
            if ch == '"':
                quoted = False
        elif ch == '"':
            quoted = True
        elif ch == "#":
            token = re.match(r"#[0-9]+", text[cursor:])
            require(token is not None and cursor > 0 and text[cursor - 1].isspace(),
                    "malformed operand attribute reference")
            end = cursor + len(token.group())
            require(end == len(text) or text[end].isspace() or text[end] == ",",
                    "ambiguous operand attribute reference")
            refs.append((cursor, end))
            cursor = end
            continue
        cursor += 1
    require(not quoted, "unclosed quoted operand provenance")
    attrs = contract["call_attributes"]
    if attrs is None:
        require(not refs, "non-call operand cannot resolve attribute reference")
        return text
    require(contract["value_kind"] == 24 and type(attrs) is dict
            and type(attrs.get("4294967295")) is list,
            "call operand requires actual structured attributes")
    function_attrs = attrs["4294967295"]
    require(len(refs) == (1 if function_attrs else 0),
            "operand attribute reference/actual attributes disagree")
    if not refs:
        return text
    start, end = refs[0]
    return text[:start] + "<LLVM_CALL_FUNCTION_ATTRIBUTES:" + canonical(function_attrs).decode("ascii") + ">" + text[end:]


def _typed_call(row):
    require(type(row) is dict and all(type(row.get(key)) is str and row[key]
            for key in ("caller", "callee", "type")) and type(row.get("attributes")) is dict
            and type(row.get("noinline")) is bool
            and type(row.get("argument_ir")) is list and type(row.get("argument_contracts")) is list
            and len(row["argument_ir"]) == len(row["argument_contracts"]),
            "malformed typed call provenance")
    for text, contract in zip(row["argument_ir"], row["argument_contracts"]):
        require(_operand_text(text, contract) == contract["ir"],
                "typed operand provenance disagrees with original text")
    return {key: row[key] for key in ("caller", "callee", "type", "attributes", "argument_contracts", "noinline")}


def recompute_call_provenance(raw_calls, post_calls):
    """Pure, strict-JSON rederivation of the helper's retained comparison proof."""
    require(type(raw_calls) is list and type(post_calls) is list and len(raw_calls) == len(post_calls),
            "inline helper caller provenance count mismatch")
    before, after = [_typed_call(row) for row in raw_calls], [_typed_call(row) for row in post_calls]
    require(canonical(before) == canonical(after), "typed call provenance changed through EH cleanup")
    return {"schema_version": 1, "comparison": CALL_COMPARISON,
            "raw_count": len(raw_calls), "post_eh_count": len(post_calls),
            "raw_semantics": before, "post_eh_semantics": after,
            "call_order_and_multiplicity_preserved": True, "typed_semantics_equal": True,
            "argument_ir_text_changed": any(a["argument_ir"] != b["argument_ir"]
                                             for a, b in zip(raw_calls, post_calls))}


def _calls_by_caller(rows, callee):
    require(type(rows) is list, "inline helper caller provenance list required")
    grouped = {}
    for row in rows:
        _typed_call(row)
        require(row["callee"] == callee, "inline helper caller provenance callee mismatch")
        grouped.setdefault(row["caller"], []).append(row)
    return grouped


def check_call_provenance(receipt):
    """Rebind raw/post occurrences to both snapshots, then recompute every proof.

    Snapshot dictionaries have no semantic iteration order after JSON sorting.
    Caller lists do: retain their order and duplicates. The saved flat raw and
    post lists must additionally correspond in exact order to each other.
    """
    require(type(receipt.get("call_provenance_revision")) is int
            and receipt["call_provenance_revision"] == 2
            and receipt.get("argument_comparison") == CALL_COMPARISON,
            "normalization call provenance revision/comparison required")
    raw, post = receipt.get("raw_contract"), receipt.get("pre_inline_contract")
    require(type(raw) is dict and type(post) is dict
            and type(raw.get("definitions")) is dict and type(post.get("definitions")) is dict
            and set(raw["definitions"]) == set(post["definitions"])
            and type(raw.get("calls")) is dict and type(post.get("calls")) is dict
            and set(raw["calls"]) == set(post["calls"]) == set(raw["definitions"]),
            "raw/post-EH snapshot call inventory required")
    for caller in sorted(raw["calls"]):
        for snapshot in (raw, post):
            rows = snapshot["calls"][caller]
            require(type(rows) is list, "snapshot call list required")
            previous = -1
            for row in rows:
                _typed_call(row)
                require(row["caller"] == caller and type(row.get("instruction_index")) is int
                        and row["instruction_index"] > previous
                        and type(row.get("block_index")) is int and row["block_index"] >= 0
                        and type(row.get("reachable")) is bool,
                        "snapshot call order/owner provenance mismatch")
                previous = row["instruction_index"]
        # Nonselected calls in proven-unreachable EH blocks may be removed by
        # the pinned normalizer. Do not invent an all-call equality rule here:
        # the new proof contract is specifically for every inlined helper.
    require(type(receipt.get("inlining")) is dict, "inline helper provenance map required")
    proofs = {}
    for name, row in receipt["inlining"].items():
        require(type(row) is dict, "inline helper provenance record required")
        raw_rows, post_rows = row.get("raw_call_occurrences"), row.get("post_eh_call_occurrences")
        for snapshot, records in ((raw, raw_rows), (post, post_rows)):
            expected = {caller: [call for call in rows if call["callee"] == name]
                        for caller, rows in snapshot["calls"].items() if any(call["callee"] == name for call in rows)}
            require(expected and canonical(_calls_by_caller(records, name)) == canonical(expected),
                    "inline helper caller provenance differs from raw/post snapshot")
        require(canonical(row.get("call_occurrences")) == canonical(post_rows),
                "inline helper post-EH occurrence alias mismatch")
        proof = recompute_call_provenance(raw_rows, post_rows)
        require(canonical(row.get("call_provenance")) == canonical(proof),
                "inline helper recorded proof differs from independent recomputation")
        proofs[name] = {"raw_count": proof["raw_count"], "post_eh_count": proof["post_eh_count"],
                        "proof_sha256": digest(canonical(proof)),
                        "argument_ir_text_changed": proof["argument_ir_text_changed"]}
    return {"revision": 2, "comparison": CALL_COMPARISON, "helpers": proofs,
            "raw_post_snapshot_occurrences_bound": True, "proof_recomputed": True,
            "independent_llvm_reexecution": False}


def check_normalization(raw_item, normalized_item, before, after, receipt, exports):
    """Validate the transformation receipt, not falsely assert raw graph equality."""
    schema(receipt)
    require(receipt.get("status") == "normalized_ir_unlinked_unvalidated"
            and receipt.get("raw_sha256") == raw_item["sha256"]
            and receipt.get("normalized_sha256") == normalized_item["sha256"]
            and type(receipt.get("raw_bytes")) is int and receipt["raw_bytes"] == raw_item["bytes"]
            and type(receipt.get("normalized_bytes")) is int and receipt["normalized_bytes"] == normalized_item["bytes"],
            "normalization input/output binding mismatch")
    require(all(receipt.get(key) is True for key in ("public_abi_preserved", "surviving_helper_abi_preserved"))
            and all(receipt.get(key) is False for key in ("calling_convention_rewritten", "noinline_helpers_removed",
                                                         "vm_applied", "native_link_verified", "target_executed"))
            and receipt.get("public_exports") == list(exports), "normalization structural claim mismatch")
    require(type(receipt.get("inputs_before")) is dict and receipt["inputs_before"]
            and canonical(receipt["inputs_before"]) == canonical(receipt.get("inputs_after"))
            and receipt.get("changed_inputs") == [], "normalization watched inputs missing or changed")
    original, final = receipt["raw_contract"], receipt["normalized_contract"]
    for contract, observed in ((original, before), (final, after)):
        require(contract["target"] == observed["target"] == TARGET
                and contract["data_layout"] == observed["data_layout"], "normalization target/layout mismatch")
        require(set(contract["definitions"]) == set(observed["definitions"]), "normalization definition inventory mismatch")
        for name, row in contract["definitions"].items():
            require(canonical(_abi(row)) == canonical(_abi(observed["definitions"][name])),
                    "normalization ABI differs from independently parsed IR: " + name)
        defined = set(contract["definitions"])
        require({name: sorted(set(edges) & defined) for name, edges in observed["graph"].items()}
                == contract["graph"], "normalization defined call graph mismatch")
    for name, row in original["definitions"].items():
        require(row.get("personality") == before["definitions"][name].get("personality"),
                "raw personality inventory changed")
        observed_calls = [_call_contract(call) for call in before["calls"][name]]
        reported_calls = [_call_contract(call) for call in original["calls"][name] if call["callee"] not in LIFETIMES]
        require(canonical(observed_calls) == canonical(reported_calls), "raw ordered call inventory changed")
    removed = set(original["definitions"]) - set(final["definitions"])
    require(not set(final["definitions"]) - set(original["definitions"])
            and receipt.get("inlined_functions") == sorted(removed)
            and set(receipt.get("inlining", {})) == removed and not set(exports) & removed,
            "normalization removed/introduced unexpected definitions")
    inline = receipt["inlining"]
    for name in sorted(removed):
        row = inline[name]
        expected = _surviving_callers(name, removed, original["calls"])
        occurrences = [call for rows in original["calls"].values() for call in rows if call["callee"] == name]
        require(expected and row.get("surviving_callers") == expected
                and set(expected) <= set(final["definitions"])
                and row.get("definition_removed_after_no_uses") is True
                and type(row.get("raw_call_occurrences")) is list
                and canonical(sorted(row["raw_call_occurrences"], key=canonical))
                    == canonical(sorted(occurrences, key=canonical)),
                "inline helper caller provenance mismatch: " + name)
        require(canonical(row.get("original_signature")) == canonical({key: original["definitions"][name][key]
                    for key in ("type", "shapes", "calling_convention", "attributes")}),
                "inline helper original signature mismatch")
    for name in final["definitions"]:
        require(canonical(_abi(original["definitions"][name])) == canonical(_abi(final["definitions"][name])),
                "surviving original ABI changed")
    require(set(final["declarations"]) == set(final["intrinsics"]) == set(after["intrinsics"]),
            "typed final declaration inventory differs")
    for name, typed in after["intrinsics"].items():
        require(all(final["intrinsics"][name].get(key) == typed.get(key)
                    for key in ("name", "base", "intrinsic_id", "type")), "typed intrinsic identity changed")
    call_provenance = check_call_provenance(receipt)
    return {"raw_definitions": sorted(original["definitions"]), "surviving_definitions": sorted(final["definitions"]),
            "inlined_functions": sorted(removed),
            "inlined_into": {name: inline[name]["surviving_callers"] for name in sorted(removed)},
            "surviving_abi_preserved": True, "raw_graph_equal_to_normalized": False,
            "call_provenance": call_provenance,
            "semantic_equivalence": "requires_original_reference_validation"}


def project_scope_policy(policy, normalization):
    """Preserve explicit source roles and project inlined sensitive roots to callers.

    A presentation boundary is not silently inlined away. Its separate object
    semantics need a different adapter, so this route remains fail-closed.
    """
    require(type(policy) is dict, "scope policy object required")
    projected, projections = copy.deepcopy(policy), []
    original = set(normalization["raw_contract"]["definitions"])
    inline = normalization["inlining"]
    public = policy.get("public_presentation", {})
    require(type(public) is dict, "public_presentation must be a reviewed reason map")
    require(not set(public) & set(inline), "inlined presentation boundary requires explicit preservation")
    for role in ("core_roots", "sensitive_functions", "entry_points"):
        names = policy.get(role, [])
        require(isinstance(names, (list, dict)) and all(isinstance(name, str) and name for name in names),
                "invalid policy function names: " + role)
        if role == "core_roots":
            require(bool(names), "core_roots cannot be empty")
        require(set(names) <= original, "scope policy names absent from raw source: " + role)
        values = []
        for name in names:
            targets = inline[name]["surviving_callers"] if name in inline else [name]
            require(targets, "policy-selected inline helper has no surviving caller")
            values.extend(targets)
            if name in inline:
                projections.append({"role": role, "source_function": name, "surviving_callers": list(targets),
                    "meaning": "source symbol existed; body incorporated in callers, not a separate VM wrapper"})
        if role in policy:
            projected[role] = sorted(set(values))
    return projected, {"original_policy": copy.deepcopy(policy), "projected_policy": copy.deepcopy(projected),
                       "inlined_policy_functions": projections, "source_roles_not_discarded": True}


def qualification_owner(unit):
    """Caller-authenticated Cargo identity, never inferred from LLVM spelling."""
    unit_key(unit)
    require(type(unit.get("unit")) is str and bool(unit["unit"]), "actual recorder unit ID required")
    return {key: unit[key] for key in ("package_id", "target_name", "source", "unit")}


def stable_owner(owner):
    require(type(owner) is dict and set(owner) == {"package_id", "target_name", "source", "unit"}
            and all(type(value) is str and value for value in owner.values()), "complete qualified owner required")
    return {"package_id": owner["package_id"], "target_name": owner["target_name"],
            "source": _qualification_path_identity(owner["source"])}


def _qualification_path_identity(value):
    # Frozen qualifier namespace rule; do not change Reader's path identity.
    return str(Path(value)).replace("/", "\\").casefold() if os.name == "nt" else str(Path(value))


def _qualified_name(owner, input_sha256, name):
    value = {"owner": stable_owner(owner), "input_sha256": input_sha256, "symbol": name}
    return "antirea_crate_" + digest(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                               ensure_ascii=False, allow_nan=False).encode("utf-8"))


def _mapped_parsed_contract(before, after, mapping):
    """Independent raw LLVM-C inventories: only selected local identities differ."""
    require(before["target"] == after["target"] == TARGET
            and before["data_layout"] == after["data_layout"], "qualification target/layout changed")
    expected_definitions = {}
    for name, row in before["definitions"].items():
        renamed = mapping.get(name, name)
        require(renamed not in expected_definitions, "qualification collapsed definitions")
        expected_definitions[renamed] = row
        require(renamed in after["definitions"] and _abi(row) == _abi(after["definitions"][renamed]),
                "qualification changed definition ABI: " + name)
        personality = row.get("personality")
        require(after["definitions"][renamed].get("personality") == mapping.get(personality, personality),
                "qualification changed personality identity")
    require(set(expected_definitions) == set(after["definitions"]), "qualification definition inventory changed")
    require(before["declarations"] == after["declarations"], "qualification changed external declarations")
    for name, edges in before["graph"].items():
        renamed = mapping.get(name, name)
        require(after["graph"].get(renamed) == [mapping.get(x, x) for x in edges],
                "qualification changed ordered graph")
        expected_calls = [{**row, "callee": mapping.get(row["callee"], row["callee"])}
                          for row in before["calls"][name]]
        require(canonical(after["calls"].get(renamed)) == canonical(expected_calls),
                "qualification changed ordered call ABI")


def check_qualification(units, outputs, before, after, receipt, exports, engine):
    """Bind caller ownership and serialized bytes before accepting name-only IR.

    The pinned helper proves whole-module body/use restoration. This independent
    gate checks all raw parsed function contracts and the exact name bijection;
    it does not pretend ABI/call inventories alone prove arithmetic equivalence.
    """
    schema(receipt)
    require(receipt.get("status") == "crate_symbols_qualified_unlinked_unvalidated"
            and receipt.get("identity_authority") == "caller_supplied_authenticated_Cargo_units_not_reauthenticated_here",
            "successful exact qualification receipt required")
    require(receipt.get("inputs_unchanged") is True
            and all(receipt.get(k) is False for k in ("calling_convention_rewritten", "linkage_rewritten",
                "passes_executed", "vm_applied", "target_executed", "native_link_verified")),
            "qualification transformation overclaim or mutation")
    require(type(units) is list and 1 <= len(units) <= MAX_UNITS
            and len(units) == len(outputs) == len(before) == len(after) == len(receipt.get("units", [])),
            "qualification exact unit count differs")
    observed_engine = pin_index(receipt.get("reviewed_engine_inputs", []))
    require(set(observed_engine) == set(engine)
            and all(observed_engine[key]["sha256"] == engine[key]["sha256"] for key in engine),
            "qualification engine identity differs")
    checked = pin_index(receipt.get("checked_inputs", []))
    expected_inputs = pin_index([item for unit in units for item in [unit["input"], *unit["evidence"]]])
    require(set(checked) == set(expected_inputs)
            and all(checked[k] == expected_inputs[k] for k in checked), "qualification checked input closure differs")
    owners, identities, all_targets, rows, count = set(), set(), set(), [], 0
    for index, (unit, item, raw, qualified, row) in enumerate(zip(units, outputs, before, after, receipt["units"])):
        owner = unit["owner"]
        stable = stable_owner(owner)
        require(owner["unit"] not in owners and canonical(stable) not in identities, "qualification duplicate owner")
        owners.add(owner["unit"])
        identities.add(canonical(stable))
        require(row.get("owner") == owner and row.get("stable_owner") == stable
                and row.get("input") == unit["input"] and row.get("evidence") == unit["evidence"],
                "qualification reordered/substituted source owner")
        require(row.get("qualified_sha256") == item["sha256"]
                and type(row.get("qualified_bytes")) is int and row["qualified_bytes"] == item["bytes"]
                and type(row.get("input_canonical_sha256")) is str
                and HEX.fullmatch(row["input_canonical_sha256"]), "qualification serialized bytes differ")
        require(all(row.get(k) is True for k in ("exact_restore_roundtrip", "serialized_restore_roundtrip",
                                               "all_instruction_operand_initializer_identities_preserved")),
                "qualification body/use restoration not proved")
        expected_map = {name: _qualified_name(owner, unit["input"]["sha256"], name)
                        for name, signature in raw["definitions"].items() if signature["linkage"] in {8, 9}}
        require(row.get("symbol_map") == expected_map
                and row.get("reverse_symbol_map") == {value: key for key, value in expected_map.items()},
                "qualification source/name bijection differs")
        require(not set(expected_map.values()) & all_targets, "cross-unit qualified identity collision")
        all_targets.update(expected_map.values())
        _mapped_parsed_contract(raw, qualified, expected_map)
        for inventory, parsed in ((row.get("before"), raw), (row.get("after"), qualified)):
            require(type(inventory) is dict and inventory.get("target") == parsed["target"]
                    and inventory.get("data_layout") == parsed["data_layout"], "qualification inventory target/layout differs")
            expected_names = set(parsed["definitions"]) | set(parsed["declarations"])
            symbols = inventory.get("symbols", {})
            require(set(symbols) == expected_names and all(symbols[name].get("kind") == "function"
                    and symbols[name].get("declaration") is (name in parsed["declarations"])
                    for name in symbols), "qualification symbol inventory differs from supported raw IR")
            for name, signature in {**parsed["declarations"], **parsed["definitions"]}.items():
                require(_abi(symbols[name]) == _abi(signature), "qualification inventory ABI differs")
        total = len(raw["definitions"])
        require(type(row.get("definition_count_before")) is int and row["definition_count_before"] == total
                and type(row.get("definition_count_after")) is int and row["definition_count_after"] == total,
                "qualification definition count differs")
        count += total
        rows.append({"owner": copy.deepcopy(owner), "stable_owner": stable,
                     "raw_input": unit["input"], "qualified_ir": item,
                     "symbol_map": expected_map, "reverse_symbol_map": {v: k for k, v in expected_map.items()},
                     "function_definitions": [{"source_symbol": name, "qualified_symbol": expected_map.get(name, name),
                        "linkage": signature["linkage"]} for name, signature in sorted(raw["definitions"].items())]})
    require(type(receipt.get("definition_count_before")) is int and receipt["definition_count_before"] == count
            and type(receipt.get("definition_count_after")) is int and receipt["definition_count_after"] == count,
            "qualification total definition count differs")
    for name in exports:
        found = [(index, part["definitions"][name]) for index, part in enumerate(before)
                 if name in part["definitions"] and part["definitions"][name]["linkage"] not in {8, 9}]
        require(len(found) == 1 and name in after[found[0][0]]["definitions"]
                and name not in rows[found[0][0]]["symbol_map"], "qualification lost/remapped public export")
    return {"status": "qualified_source_contracts_bound", "source_ir_kind": SOURCE_IR_KIND,
            "units": rows, "definition_count": count, "public_exports": list(exports),
            "public_exports_identity": True, "calling_convention_rewritten": False,
            "body_preservation_authority": "pinned qualifier exact canonical+serialized restore and live operand checks",
            "semantic_equivalence": "requires_captured_original_Cargo_reference_validation"}


def qualify_scope_policy(policy, qualification):
    """Resolve original policy identities before existing inline projection.

    Optional symbol_owners[name]={package_id,target_name,source} selects one
    stable Cargo owner. External names stay global; ambiguous local names never
    silently select the first crate or merge independent helpers.
    """
    require(type(policy) is dict, "scope policy object required")
    result, hints = copy.deepcopy(policy), copy.deepcopy(policy.get("symbol_owners", {}))
    require(type(hints) is dict, "symbol_owners must be an explicit source-owner map")
    definitions = {}
    for unit in qualification["units"]:
        for definition in unit["function_definitions"]:
            definitions.setdefault(definition["source_symbol"], []).append((unit, definition))
    used, resolutions = set(), []
    def resolve(name, role):
        require(type(name) is str and name in definitions, "scope policy symbol absent from original crate definitions")
        candidates = definitions[name]
        if name in hints:
            hint = hints[name]
            require(type(hint) is dict and set(hint) == {"package_id", "target_name", "source"}
                    and all(type(value) is str and value for value in hint.values()), "exact stable policy owner required")
            identity = {**hint, "source": _qualification_path_identity(hint["source"])}
            candidates = [item for item in candidates if item[0]["stable_owner"] == identity]
            used.add(name)
        else:
            external = [item for item in candidates if item[1]["linkage"] not in {8, 9}]
            candidates = external if external else candidates
        require(len(candidates) == 1, "ambiguous policy source symbol requires symbol_owners: " + name)
        unit, definition = candidates[0]
        resolutions.append({"role": role, "source_symbol": name, "owner": unit["owner"],
                            "stable_owner": unit["stable_owner"], "qualified_symbol": definition["qualified_symbol"]})
        return definition["qualified_symbol"]
    for role in ("core_roots", "sensitive_functions", "entry_points"):
        if role not in policy:
            continue
        values = policy[role]
        require(type(values) in (list, dict), "policy function role must be a list/reason map")
        result[role] = ({resolve(name, role): reason for name, reason in values.items()}
                        if type(values) is dict else [resolve(name, role) for name in values])
    public = policy.get("public_presentation", {})
    require(type(public) is dict, "public_presentation must be a reviewed reason map")
    if "public_presentation" in policy:
        result["public_presentation"] = {resolve(name, "public_presentation"): reason for name, reason in public.items()}
    require(used == set(hints), "unused/unknown policy owner hint")
    result.pop("symbol_owners", None)
    return result, {"original_policy": copy.deepcopy(policy), "qualified_policy": copy.deepcopy(result),
                    "source_owner_resolutions": resolutions, "source_roles_not_discarded": True}


def source_definition_lineage(qualification, normalization, mapping):
    """Compose owner/name -> qualification -> inline destinations -> VM names."""
    records = mapping.get("functions", {})
    surviving = set(normalization["normalized_contract"]["definitions"])
    require(type(records) is dict and set(records) == surviving
            and mapping.get("source_selected_functions") == sorted(surviving), "mapper survivor identity inventory differs")
    protected = []
    for name, row in records.items():
        require(type(row) is dict and row.get("source_symbol") == name
                and type(row.get("protected_symbol")) is str and row["protected_symbol"], "mapper name relation missing")
        protected.append(row["protected_symbol"])
    require(len(set(protected)) == len(protected) and sorted(protected) == mapping.get("protected_selected_functions"),
            "mapper survivor/protected bijection differs")
    result = []
    for unit in qualification["units"]:
        for row in unit["function_definitions"]:
            name = row["qualified_symbol"]
            targets = normalization["inlining"][name]["surviving_callers"] if name in normalization["inlining"] else [name]
            require(targets and set(targets) <= surviving, "qualified source body lacks protected destinations")
            result.append({"owner": unit["owner"], "source_symbol": row["source_symbol"], "qualified_symbol": name,
                           "surviving_symbols": list(targets),
                           "protected_symbols": [records[target]["protected_symbol"] for target in targets],
                           "inlined_not_a_separate_wrapper": name in normalization["inlining"]})
    require(len(result) == qualification["definition_count"], "source definitions were silently omitted")
    return result


def typed_scope_plan(scope_plan, parsed):
    """Only discharge exact LLVM-C-validated intrinsic call issues; retain all else."""
    result = copy.deepcopy(scope_plan)
    typed = parsed.get("intrinsics", {})
    calls = parsed.get("intrinsic_calls", {})
    accepted = []
    for issue in result.get("unresolved", []):
        owner, name = issue.get("symbol"), issue.get("detail")
        if issue.get("kind") != "external_call" or name not in typed:
            continue
        require(any(row.get("callee") == name and row.get("intrinsic_id") == typed[name]["intrinsic_id"]
                    and row.get("type") == typed[name]["type"] for row in calls.get(owner, [])),
                "scope intrinsic issue has no exact parsed call witness")
        issue["relevant"] = False
        issue["resolution"] = "exact LLVM-C intrinsic ID/signature/direct-call validation"
        accepted.append({"owner": owner, "callee": name, "intrinsic": typed[name]})
    # Cross-check every owned edge; arbitrary external declarations must not be
    # concealed by a text parser disagreement or an llvm.* name prefix.
    observed = result.get("graph", {}).get("calls", {})
    require(set(observed) == set(parsed["definitions"]), "scope/LLVM definition inventory differs")
    for owner, edges in observed.items():
        expected = set(parsed["graph"][owner]) | {row["callee"] for row in calls.get(owner, [])}
        require(set(edges) == expected, "scope/LLVM typed call graph differs")
    result["status"] = "needs_review" if result.get("data_risks") or any(
        row.get("relevant") for row in result.get("unresolved", [])) else "ready"
    result["typed_intrinsic_resolutions"] = accepted
    return result


def choose_scope(parsed, scope_plan, exports):
    require(scope_plan.get("status") == "ready", "scope needs review: " + json.dumps(scope_plan.get("unresolved", [])))
    all_defs = set(parsed["definitions"])
    require(set(exports) <= all_defs, "requested public ABI root absent after canonical linking")
    require(set(scope_plan.get("selected_functions", [])) <= all_defs, "scope selected an absent definition")
    require(not [name for name, row in scope_plan.get("boundary_functions", {}).items()
                 if not row.get("overridden_by_sensitive_or_core")],
            "public boundary requires separate module/object preservation before this strict mapper")
    require(1 <= len(all_defs) <= 64 and len(all_defs) <= scope_plan.get("max_functions", 64), "closed mapper function limit")
    require(set(parsed["declarations"]) == set(parsed.get("intrinsics", {})),
            "unresolved declarations/runtime calls remain after closure canonicalization")
    return {"selected_functions": sorted(all_defs), "required_relevant_functions": scope_plan["selected_functions"],
        "conservative_additions": sorted(all_defs - set(scope_plan["selected_functions"])),
        "reason": "existing strict Rust mapper protects every definition in the selected closed crate graph",
        "public_exports": sorted(exports), "calling_convention_rewritten": False}


def build_mapper_request(mapper, canonical_ir, parsed, chosen, provenance):
    """Use the existing typed API without changing ABI or inventing recipes."""
    for name, signature in parsed["definitions"].items():
        require(signature["calling_convention"] == 0,
                "unsupported existing helper calling convention (never rewritten): " + name)
    require(set(chosen["selected_functions"]) == set(parsed["definitions"]),
            "strict mapper requires complete closed definitions")
    graph = {name: tuple(sorted(set(edges))) for name, edges in parsed["graph"].items()}
    require(set(graph) == set(chosen["selected_functions"])
            and all(set(edges) <= set(graph) for edges in graph.values()), "nonclosed mapping request graph")
    return mapper.RustIRRequest(Path(canonical_ir["path"]), canonical_ir["sha256"],
        tuple(chosen["selected_functions"]), tuple(chosen["public_exports"]), graph, provenance)


def prepare_capture(capture_path, capture_sha256, plan_path, plan_sha256, *, workspace_root,
                    output_dir, trusted_engine_pins, source_environment, compiler_environment, runner=None):
    """Explicit bounded LLVM preparation; caller owns lease and outer Job.

    runner is a trusted Python test seam, never a project-controlled callback.
    Source environment is metadata revalidation only, never a child environment.
    """
    reader = Reader(workspace_root)
    root, output = reader.root, reader.path(output_dir, fresh=True)
    require(output.is_relative_to(root / ".runs") and output != root / ".runs", "private preparation output required")
    require(isinstance(source_environment, dict), "explicit metadata revalidation environment required")
    capture_path, plan_path = absolute(capture_path), absolute(plan_path)
    capture = json_bytes(reader.read({"path": str(capture_path), "sha256": capture_sha256}))
    inner = json_bytes(reader.read({"path": str(plan_path), "sha256": plan_sha256}))
    inspection = inner["inspection"]
    require(not any(output.is_relative_to(absolute(item)) or absolute(item).is_relative_to(output)
                    for item in inspection["input_snapshot"]["roots"]), "preparation overlaps owned source")
    require(isinstance(trusted_engine_pins, dict), "reviewed engine pin map required")
    engine = pin_index([{"path": name, "sha256": expected} for name, expected in trusted_engine_pins.items()])
    required = {path_key(path) for path in (root / "antirea").rglob("*.py")}
    required |= {path_key(__file__), path_key(root / SEMANTIC), path_key(root / MAPPER), path_key(root / NORMALIZER),
                 path_key(root / QUALIFIER),
                 path_key(root / ".tools/kagura-toolchain.json")}
    require(required <= set(engine), "incomplete trusted engine/helper closure")
    for key in sorted(engine):
        reader.read(engine[key], owned=False, limit=512 * 1024 * 1024)
    config = json_bytes(reader.read(engine[path_key(root / ".tools/kagura-toolchain.json")]))
    require(config.get("target") == TARGET, "LLVM config target mismatch")
    llvm_root = absolute(config["llvm_root"])
    tools = {name: llvm_root / "bin" / filename for name, filename in
             (("opt", "opt.exe"), ("link", "llvm-link.exe"), ("library", "LLVM-C.dll"))}
    require(all(path_key(path) in engine for path in tools.values()), "pinned LLVM tool roles required")
    require(isinstance(compiler_environment, dict)
            and set(compiler_environment) == {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP"}
            and all(isinstance(value, str) and value and "\x00" not in value for value in compiler_environment.values()),
            "five explicit nonsecret LLVM process controls required")
    windows = reader.path(compiler_environment["SYSTEMROOT"], owned=False)
    require(absolute(compiler_environment["WINDIR"]) == windows
            and compiler_environment["PATH"] == str(llvm_root / "bin") + ";" + str(windows / "System32")
            and compiler_environment["TEMP"] == compiler_environment["TMP"], "fixed LLVM process environment mismatch")
    temporary = reader.path(compiler_environment["TEMP"])
    require(temporary.is_dir() and temporary.is_relative_to(root / ".runs")
            and not under(temporary, [absolute(item) for item in inspection["input_snapshot"]["roots"]]),
            "LLVM temporary directory must be private and outside sources")
    modules = load_production(reader, engine)
    metadata, scope = modules["rust_cargo"], modules["scope"]
    run_logged = modules["process"].run_logged
    verification = metadata.verify_plan(inner, plan_path=plan_path, workspace_root=root,
        toolchain=inspection["toolchain"]["selection"], env=source_environment)
    require(verification["metadata_succeeded"] is True, "metadata verification failed")
    capture_plan = json_bytes(reader.read(capture["capture_plan"]))
    recipes = authenticate(reader, capture, inner, capture_plan, plan_path)
    semantic = modules["rust_cargo_semantic"]
    selected = select_capture(capture, inner, check_environment=semantic.check_consumed_environment)
    mapper = modules["rust_ir"]
    normalizer = modules["rust_normalize"]
    qualifier = modules["rust_qualify"]
    output.mkdir()
    report = {"schema_version": 1, "status": "failed_ir_preparation", "commands": [], "selection": selected,
        "capture": {"path": str(capture_path), "sha256": capture_sha256},
        "inner_plan": {"path": str(plan_path), "sha256": plan_sha256}, "lineage": {},
        "vm_applied": False, "target_executed": False, "native_linked": False, "published": False,
        "functional_validation": "not_performed", "protection_effectiveness": "not_evaluated",
        "import_contract": "fresh reviewed worker; canonical complete preloads checked; fixed package source-only imports",
        "package_port_revision": 1,
        "source_import_policy": "fixed_antirea_namespace_reviewed_source_bytes",
        "verified_source_imports": modules["_source_imports"],
        "reviewed_engine_inputs": [descriptor(reader.watched[key]) for key in sorted(engine)],
        "llvm_environment": {"keys": sorted(compiler_environment),
            "sha256": digest(canonical(compiler_environment)),
            "value_sha256": {key: digest(value.encode("utf-8")) for key, value in sorted(compiler_environment.items())}},
        "checked_inputs": [], "loaded_production_modules": []}
    deadline = time.monotonic() + 300
    runner = run_logged if runner is None else runner

    def command(argv):
        reader.recheck()
        remaining = int(deadline - time.monotonic())
        require(remaining > 0, "preparation total command deadline exhausted")
        prefix = output / ("command-%03d" % len(report["commands"]))
        for suffix in (".stdout.log", ".stderr.log", ".process.json"):
            reader.path(Path(str(prefix) + suffix), fresh=True)
        reader.check_stop()
        result = runner(list(map(str, argv)), output, prefix, timeout=min(30, remaining),
                        env=dict(compiler_environment), cancel_file=reader.stop)
        files = {key: reader.current(Path(str(prefix) + suffix)) for key, suffix in
                 (("stdout", ".stdout.log"), ("stderr", ".stderr.log"), ("process", ".process.json"))}
        report["commands"].append({"argv": list(map(str, argv)), "cwd": str(output), "process": result, "files": files})
        require(metadata._clean(result) and result.get("argv") == list(map(str, argv))
                and result.get("stdout") == files["stdout"]["path"] and result.get("stderr") == files["stderr"]["path"]
                and canonical(json_bytes(reader.read(files["process"]))) == canonical(result),
                "LLVM command failed or process/owned cleanup evidence mismatched")
        reader.check_stop()

    try:
        raw_contracts, lineage, qualification_units = [], [], []
        qualification_evidence = [reader.current(capture_path), reader.current(plan_path)]
        for index, unit in enumerate(selected["arms"]["derivative"]["units"]):
            source = unit["llvm_ir"]
            raw = reader.read(source, hardlinks=True, limit=MAX_IR)
            raw_item = reader.write(output / ("crate-%03d.raw.ll" % index), raw)
            before = inspect_ir(mapper, tools["library"], raw,
                                workspace_root=root, trusted_engine_pins=trusted_engine_pins)
            raw_contracts.append(before)
            start = recipes["derivative"][unit["unit"]]
            owner = qualification_owner(unit)
            qualification_units.append({"owner": owner, "input": raw_item, "evidence": qualification_evidence})
            lineage.append({"unit": unit["unit"], "identity": unit_key(unit), "owner": owner, "captured_ir": source,
                "raw_copy": raw_item, "parsed_raw": before,
                "original_rustc_argv": start["original_argv"], "derivative_rustc_argv": start["forwarded_argv"],
                "rustc_cwd": start["cwd"], "metadata_only_ir": not bool(before["definitions"])})
        reader.recheck()
        reader.check_stop()
        qualified_bytes, qualification = qualifier.qualify_modules(qualification_units,
            workspace_root=root, llvm_library=tools["library"],
            llvm_sha256=engine[path_key(tools["library"])]["sha256"],
            toolchain_config_sha256=engine[path_key(root / ".tools/kagura-toolchain.json")]["sha256"],
            trusted_engine_pins=trusted_engine_pins, stop_file=reader.stop)
        reader.check_stop()
        reader.recheck()
        require(type(qualified_bytes) is tuple and len(qualified_bytes) == len(qualification_units)
                and all(type(raw) is bytes and 0 < len(raw) <= MAX_IR for raw in qualified_bytes),
                "qualifier returned incomplete/nonbytes/oversized modules")
        qualified_items, qualified_contracts = [], []
        for index, raw in enumerate(qualified_bytes):
            qualified_items.append(reader.write(output / ("crate-%03d.qualified.ll" % index), raw))
            qualified_contracts.append(inspect_ir(mapper, tools["library"], raw,
                                workspace_root=root, trusted_engine_pins=trusted_engine_pins))
        qualification_gate = check_qualification(qualification_units, qualified_items, raw_contracts,
            qualified_contracts, qualification, selected["public_exports"], engine)
        for row, qualified_item, parsed_qualified, names in zip(lineage, qualified_items, qualified_contracts,
                                                               qualification_gate["units"]):
            row.update(qualified_ir=qualified_item, parsed_qualified=parsed_qualified,
                       symbol_map=names["symbol_map"], reverse_symbol_map=names["reverse_symbol_map"])
        qualification_item = reader.write(output / "qualification.json", canonical(qualification) + b"\n")
        qualified_linked, canonical_linked = output / "module.qualified.ll", output / "module.normalized.ll"
        reader.path(qualified_linked, fresh=True)
        command([tools["link"], "-S", *[item["path"] for item in qualified_items], "-o", qualified_linked])
        qualified_linked_item = reader.current(qualified_linked)
        qualified_parsed = inspect_ir(mapper, tools["library"], reader.read(qualified_linked_item),
                                      workspace_root=root, trusted_engine_pins=trusted_engine_pins)
        qualified_link_gate = check_linked_contract(qualified_contracts, qualified_parsed)
        reader.recheck()
        reader.check_stop()
        normalized_bytes, normalization = normalizer.normalize_ir(reader.read(qualified_linked_item),
            workspace_root=root, llvm_library=tools["library"],
            llvm_sha256=engine[path_key(tools["library"])]["sha256"],
            toolchain_config_sha256=engine[path_key(root / ".tools/kagura-toolchain.json")]["sha256"],
            public_exports=tuple(selected["public_exports"]), expected_raw_sha256=qualified_linked_item["sha256"],
            trusted_engine_pins=trusted_engine_pins)
        reader.check_stop()
        reader.recheck()
        canonical_linked_item = reader.write(canonical_linked, normalized_bytes)
        normalization_item = reader.write(output / "normalization.json", canonical(normalization) + b"\n")
        parsed = inspect_scalar_ir(mapper, tools["library"], reader.read(canonical_linked_item), selected["public_exports"],
                                   workspace_root=root, trusted_engine_pins=trusted_engine_pins)
        normalization_gate = check_normalization(qualified_linked_item, canonical_linked_item, qualified_parsed, parsed,
                                                normalization, selected["public_exports"])
        policy = {"schema_version": 1, "core_roots": selected["public_exports"],
                  "public_presentation": {}, "max_functions": 64}
        policy_name = inspection["project"].get("scope_policy")
        if policy_name is not None:
            policy_path = absolute(Path(inspection["project_path"]).parent / policy_name)
            pins = pin_index(inspection["input_snapshot"]["files"])
            require(path_key(policy_path) in pins, "scope policy outside owned snapshot")
            policy = json_bytes(reader.read(pins[path_key(policy_path)]))
        qualified_policy, policy_qualification = qualify_scope_policy(policy, qualification_gate)
        projected_policy, policy_projection = project_scope_policy(qualified_policy, normalization)
        original_scope_plan = scope.analyze_scope([canonical_linked], projected_policy, mode="expanded")
        scope_plan = typed_scope_plan(original_scope_plan, parsed)
        chosen = choose_scope(parsed, scope_plan, selected["public_exports"])
        require(all(set(row["surviving_callers"]) <= set(chosen["selected_functions"])
                    for row in policy_projection["inlined_policy_functions"]), "projected policy callers not protected")
        context_item = reader.write(output / "source-context.json", canonical({
            "capture": report["capture"], "inner_plan": report["inner_plan"], "selection": selected,
            "crates": lineage, "scope_policy": policy, "scope_plan": scope_plan,
            "scope_analysis_before_typed_resolution": original_scope_plan, "policy_qualification": policy_qualification,
            "policy_projection": policy_projection, "source_ir_kind": SOURCE_IR_KIND,
            "qualification": qualification_item, "qualification_gate": qualification_gate,
            "qualified_llvm_link": qualified_link_gate, "qualified_linked_ir": qualified_linked_item,
            "normalization": normalization_item,
            "normalization_gate": normalization_gate, "typed_intrinsics": parsed["intrinsics"]}) + b"\n")
        pin = mapper.PinnedFile
        compiler_paths = [root / ".tools/kagura-toolchain.json",
                          *(tools[role] for role in ("opt", "link", "library")),
                          Path(inspection["toolchain"]["selection"]["rustc"])]
        sources = pin_index([item for unit in selected["arms"]["derivative"]["units"]
                             for item in unit["declared_dependencies"] if item["classification"] == "owned_source"])
        require(len(sources) <= 256, "current mapper provenance source count exceeded; no silent truncation")
        compiler_records = []
        rust_pins = pin_index([{"path": name, "sha256": sha}
                              for name, sha in inspection["toolchain"]["compiler_inputs"].items()])
        for path in compiler_paths:
            record = engine.get(path_key(path), rust_pins.get(path_key(path)))
            require(record is not None, "missing compiler provenance pin")
            if path_key(path) in engine and path_key(path) in rust_pins:
                pin_index([engine[path_key(path)], rust_pins[path_key(path)]])
            reader.read(record, owned=False, limit=512 * 1024 * 1024)
            compiler_records.append(pin(Path(record["path"]), record["sha256"]))
        evidence = [report["capture"], report["inner_plan"], context_item, qualification_item,
                    qualified_linked_item, normalization_item]
        root_recipe = recipes["derivative"][selected["arms"]["derivative"]["root_unit"]]
        # Existing mapper has one frontend_flags tuple: it contains the exact
        # selected root recipe. Every other unit's recipe is preserved separately
        # in hash-bound source-context, never flattened/inferred from metadata.
        provenance = mapper.RustSourceProvenance(tuple(compiler_records),
            tuple(pin(Path(sources[key]["path"]), sources[key]["sha256"]) for key in sorted(sources)),
            tuple(pin(Path(item["path"]), item["sha256"]) for item in evidence),
            tuple(root_recipe["forwarded_argv"][1:]), target=selected["target"])
        request = build_mapper_request(mapper, canonical_linked_item, parsed, chosen, provenance)
        mapped, mapping = mapper.normalize_protection_ir(request, workspace_root=root, llvm_library=tools["library"],
            trusted_engine_pins=trusted_engine_pins)
        require(mapping.get("exact_restore_roundtrip") is True and mapping.get("calling_convention_rewritten") is False
                and mapping.get("vm_applied") is False and mapping.get("intrinsic_contract_preserved") is True
                and mapping.get("intrinsic_backend_validated") is False
                and mapping.get("input_sha256") == canonical_linked_item["sha256"]
                and mapping.get("output_sha256") == digest(mapped)
                and canonical(mapping.get("intrinsic_declarations")) == canonical(parsed["intrinsics"]),
                "strict mapping proof missing")
        mapped_item = reader.write(output / "module.protection-input.ll", mapped)
        mapping_item = reader.write(output / "mapping.json", canonical(mapping) + b"\n")
        source_lineage = source_definition_lineage(qualification_gate, normalization, mapping)
        report.update(status="cargo_ir_prepared_unlinked_unvalidated", preparation_revision=5,
            source_ir_kind=SOURCE_IR_KIND, scope_plan=scope_plan, scope=chosen,
            qualification_gate=qualification_gate, policy_qualification=policy_qualification,
            qualified_link_gate=qualified_link_gate, policy_projection=policy_projection,
            source_definition_lineage=source_lineage,
            normalization_gate=normalization_gate, typed_intrinsics=parsed["intrinsics"],
            lineage={"crates": lineage, "qualification": qualification_item,
                     "qualified_linked_ir": qualified_linked_item, "canonical_linked_ir": canonical_linked_item,
                     "normalized_ir": canonical_linked_item, "normalization": normalization_item,
                     "mapped_ir": mapped_item, "mapping": mapping_item, "source_context": context_item},
            object_handoff={"source_ir": qualified_linked_item, "source_ir_kind": SOURCE_IR_KIND,
                            "protection_ir": mapped_item, "qualification": qualification_item,
                            "captured_raw_crates": [row["raw_copy"] for row in lineage],
                            "source_definition_lineage": source_lineage,
                            "original_reference_kind": "separate_captured_original_Cargo_DLL_required",
                            "normalized_ir": canonical_linked_item, "normalization": normalization_item,
                            "inlined_source_functions": normalization_gate["inlined_into"],
                            "call_provenance": normalization_gate["call_provenance"],
                            "intrinsic_backend_validated": False,
                            "selected_functions": mapping["protected_selected_functions"],
                            "public_exports": mapping["exported_functions"], "object_pipeline_executed": False})
    except Exception as exc:
        report["error"] = type(exc).__name__ + ": " + str(exc)[:8192]
    finally:
        try:
            reader.recheck()
            metadata.verify_plan(inner, plan_path=plan_path, workspace_root=root,
                toolchain=inspection["toolchain"]["selection"], env=source_environment)
            authenticate(reader, capture, inner, capture_plan, plan_path)
            _check_package_inventory(reader, engine)
            report["loaded_production_modules"] = check_loaded_modules(reader, engine)
            reader.recheck()
            report["inputs_unchanged"] = True
        except Exception as exc:
            report["status"] = "failed_ir_preparation"
            report["terminal_error"] = type(exc).__name__ + ": " + str(exc)[:8192]
        report["checked_inputs"] = [dict(reader.watched[key]) for key in sorted(reader.watched)]
        report["requirements_not_fulfilled"] = ["Native VM/object pipeline execution and actual coverage",
            "Actual ordered Rust native-link inputs/archives and complete object replacement",
            "Public export isolation and original Cargo/baseline/protected runtime comparison",
            "General Rust runtime/object/exception/COMDAT and non-C calling-convention support",
            "Separate public boundary preservation when requested by policy", "External protection evaluation"]
        report["qualification"] = ("Closed scalar graph preparation only; baseline source is qualified raw modules linked once, "
            "not byte-identical captured IR. Original source execution requires the separately captured original Cargo DLL. "
            "Metadata-only IR does not prove empty native rlib code. No complete Rust/application support claim.")
        reader.write(output / "preparation.json", canonical(report) + b"\n", terminal=True)
    return report

def _receipt_bound(reader, item, *, hardlinks=False):
    raw = reader.read(item, owned=False, hardlinks=hardlinks, limit=512 * 1024 * 1024)
    return {**descriptor(item), "bytes": len(raw)}


def _receipt_json(reader, path):
    # Callers bind authority first; Reader rejects pin drift on every reread.
    return json_bytes(reader.read(reader.current(path, owned=False), owned=False))


def verify_call_provenance_handoff(report, normalization):
    require(type(report.get('preparation_revision')) is int and report['preparation_revision'] == 5,
            'v5 preparation receipt required')
    provenance = check_call_provenance(normalization)
    require(canonical(provenance) == canonical(report['normalization_gate'].get('call_provenance'))
            and canonical(provenance) == canonical(report['object_handoff'].get('call_provenance')),
            'parent-recomputed raw/post call provenance differs')
    return provenance


def _verify_saved_qualification(reader, output, report, engine, plan, semantic):
    """Parent-side byte/owner/receipt binding, not a second LLVM body proof.

    Replay pure selection/gates from pinned modules in the parent AFTER the
    bounded worker has exited. No LLVM parser/pass, compiler or target is run.
    """
    captured = _receipt_json(reader, report['capture']['path'])
    expected_selection = select_capture(captured, plan,
                                               check_environment=semantic.check_consumed_environment)
    require(canonical(report['selection']) == canonical(expected_selection),
            'selection not reproduced from pinned capture and PLAN')
    units = expected_selection['arms']['derivative']['units']
    lineage, handoff = report['lineage'], report['object_handoff']
    crates = lineage['crates']
    require(len(crates) == len(units) and 1 <= len(units) <= MAX_UNITS,
            'qualification source unit count differs')
    expected_evidence = [_receipt_bound(reader, report['capture']), _receipt_bound(reader, report['inner_plan'])]
    qualified_items, inputs, before, after = [], [], [], []
    for index, (unit, crate) in enumerate(zip(units, crates)):
        owner = qualification_owner(unit)
        require(crate['unit'] == unit['unit'] and crate['owner'] == owner
                and canonical(crate['identity']) == canonical(unit_key(unit))
                and crate['captured_ir'] == unit['llvm_ir'], 'qualified source owner/order differs')
        raw = _receipt_bound(reader, crate['raw_copy'])
        captured_ir = _receipt_bound(reader, crate['captured_ir'], hardlinks=True)
        qualified = _receipt_bound(reader, crate['qualified_ir'])
        require(raw['path'] == str(output / ('crate-%03d.raw.ll' % index))
                and qualified['path'] == str(output / ('crate-%03d.qualified.ll' % index))
                and (raw['sha256'], raw['bytes']) == (captured_ir['sha256'], captured_ir['bytes']),
                'raw copy changed or qualified artifact path substituted')
        inputs.append({'owner': owner, 'input': raw, 'evidence': expected_evidence})
        qualified_items.append(qualified)
        before.append(crate['parsed_raw'])
        after.append(crate['parsed_qualified'])
    qualification = _receipt_json(reader, lineage['qualification']['path'])
    require(pin_index(report['reviewed_engine_inputs']) == engine,
            'qualification parent engine authority differs')
    expected_gate = check_qualification(inputs, qualified_items, before, after, qualification,
                                              expected_selection['public_exports'], engine)
    require(canonical(expected_gate) == canonical(report['qualification_gate']),
            'qualification gate receipt drift')
    for crate, row in zip(crates, expected_gate['units']):
        require(crate['symbol_map'] == row['symbol_map']
                and crate['reverse_symbol_map'] == row['reverse_symbol_map'], 'per-crate name bijection drift')
    # Qualification has already verified unchanged body/uses in the child. The
    # parent rebinds its exact receipt and output bytes, not that live LLVM state.
    source_context = _receipt_json(reader, lineage['source_context']['path'])
    policy = {'schema_version': 1, 'core_roots': expected_selection['public_exports'],
              'public_presentation': {}, 'max_functions': 64}
    inspection = plan['inspection']
    if inspection['project'].get('scope_policy') is not None:
        policy_path = Path(inspection['project_path']).parent / inspection['project']['scope_policy']
        source_pins = pin_index(inspection['input_snapshot']['files'])
        require(path_key(policy_path) in source_pins, 'policy not pinned in original source snapshot')
        _receipt_bound(reader, source_pins[path_key(policy_path)])
        policy = _receipt_json(reader, policy_path)
    projected, policy_receipt = qualify_scope_policy(policy, expected_gate)
    require(source_context['scope_policy'] == policy
            and report['policy_qualification'] == policy_receipt, 'original owner policy was rewritten/omitted')
    normalization = _receipt_json(reader, lineage['normalization']['path'])
    provenance = verify_call_provenance_handoff(report, normalization)
    _, inline_receipt = project_scope_policy(projected, normalization)
    require(report['policy_projection'] == inline_receipt, 'owner-qualified inline policy differs')
    mapping = _receipt_json(reader, lineage['mapping']['path'])
    source_lineage = source_definition_lineage(expected_gate, normalization, mapping)
    require(report['source_definition_lineage'] == source_lineage
            and handoff['source_definition_lineage'] == source_lineage,
            'source/qualified/surviving/protected identity chain differs')
    require(source_context['qualification'] == lineage['qualification']
            and source_context['qualified_linked_ir'] == lineage['qualified_linked_ir']
            and source_context['qualified_llvm_link'] == report['qualified_link_gate'],
            'qualified link source-context binding differs')
    qualified_definitions = {name for part in after for name in part['definitions']}
    require(qualified_definitions == set(normalization['raw_contract']['definitions'])
            and len(qualified_definitions) == sum(len(part['definitions']) for part in after),
            'qualified definition disappeared or collapsed at linked baseline')
    for item in qualification['reviewed_engine_inputs']:
        _receipt_bound(reader, item)
    for item in qualification['checked_inputs']:
        _receipt_bound(reader, item)
    _receipt_bound(reader, lineage['qualification'])
    return {'status': 'qualified_receipt_bytes_and_source_owners_bound',
            'source_ir_kind': SOURCE_IR_KIND, 'units': len(units),
            'definition_count': expected_gate['definition_count'],
            'qualified_local_definitions': sum(len(x['symbol_map']) for x in expected_gate['units']),
            'qualification': lineage['qualification'], 'independent_llvm_body_reexecution': False,
            'call_provenance': provenance,
            'body_proof_authority': 'pinned child helper exact restoration and operand identity checks',
            'original_reference': 'separate original Cargo DLL still requires functional comparison'}


def _verify_saved_lineage(reader, output, report, mapping, plan):
    require(type(report.get('preparation_revision')) is int and report['preparation_revision'] == 5,
            'v5 preparation receipt required')
    require(report.get('source_ir_kind') == SOURCE_IR_KIND, 'qualified baseline identity required')
    lineage, handoff = report['lineage'], report['object_handoff']
    expected_files = {'qualification': 'qualification.json', 'qualified_linked_ir': 'module.qualified.ll', 'normalized_ir': 'module.normalized.ll',
                      'normalization': 'normalization.json', 'mapped_ir': 'module.protection-input.ll',
                      'mapping': 'mapping.json', 'source_context': 'source-context.json'}
    for role, filename in expected_files.items():
        require(lineage[role]['path'] == str(output / filename), 'foreign preparation artifact')
        _receipt_bound(reader, lineage[role])
    require(lineage['canonical_linked_ir'] == lineage['normalized_ir'], 'normalized compatibility alias differs')
    units = report['selection']['arms']['derivative']['units']
    crates = lineage['crates']
    require(1 <= len(crates) == len(units) <= MAX_UNITS and len({x['unit'] for x in crates}) == len(units),
            'all authenticated selected Cargo units are required')
    for index, (crate, unit) in enumerate(zip(crates, units)):
        require(crate['unit'] == unit['unit'] and crate['captured_ir'] == unit['llvm_ir'],
                'crate capture selection mismatch')
        original = _receipt_bound(reader, crate['captured_ir'], hardlinks=True)
        copy = _receipt_bound(reader, crate['raw_copy'])
        require(copy['path'] == str(output / ('crate-%03d.raw.ll' % index))
                and (copy['sha256'], copy['bytes']) == (original['sha256'], original['bytes']),
                'raw crate copy differs from captured input')
    normalization = _receipt_json(reader, lineage['normalization']['path'])
    require(normalization['status'] == 'normalized_ir_unlinked_unvalidated'
            and normalization['raw_sha256'] == lineage['qualified_linked_ir']['sha256']
            and normalization['normalized_sha256'] == lineage['normalized_ir']['sha256']
            and normalization['raw_bytes'] == lineage['qualified_linked_ir']['bytes']
            and normalization['normalized_bytes'] == lineage['normalized_ir']['bytes'],
            'normalization raw/output identity mismatch')
    require(normalization['inputs_before'] == normalization['inputs_after']
            and normalization['changed_inputs'] == [], 'normalizer inputs changed')
    for name, sha in normalization['inputs_before'].items():
        _receipt_bound(reader, {'path': name, 'sha256': sha})
    require(all(normalization.get(k) is True for k in ('public_abi_preserved', 'surviving_helper_abi_preserved'))
            and all(normalization.get(k) is False for k in ('calling_convention_rewritten',
                'noinline_helpers_removed', 'vm_applied', 'target_executed', 'native_link_verified')),
            'normalization proof flags missing')
    exports = sorted(plan['inspection']['project']['functions'])
    require(normalization['public_exports'] == exports and mapping['exported_functions'] == exports,
            'public ABI export set differs')
    before, after = normalization['raw_contract'], normalization['normalized_contract']
    original, surviving = set(before['definitions']), set(after['definitions'])
    removed = original - surviving
    require(surviving <= original and not removed & set(exports)
            and normalization['inlined_functions'] == sorted(removed)
            and set(normalization['inlining']) == removed, 'definition removal lacks exact inline provenance')
    inline = {name: normalization['inlining'][name]['surviving_callers'] for name in sorted(removed)}
    require(all(callers and set(callers) <= surviving for callers in inline.values()), 'missing inline destinations')
    gate = report['normalization_gate']
    require(gate['raw_definitions'] == sorted(original) and gate['surviving_definitions'] == sorted(surviving)
            and gate['inlined_functions'] == sorted(removed) and gate['inlined_into'] == inline
            and gate['surviving_abi_preserved'] is True
            and gate['raw_graph_equal_to_normalized'] is False
            and gate['semantic_equivalence'] == 'requires_original_reference_validation',
            'normalization gate overclaims or drifts')
    require(mapping['input_sha256'] == lineage['normalized_ir']['sha256']
            and mapping['output_sha256'] == lineage['mapped_ir']['sha256']
            and mapping['source_selected_functions'] == sorted(surviving)
            and mapping['source_graph'] == after['graph']
            and mapping['intrinsic_declarations'] == report['typed_intrinsics']
            and mapping['intrinsic_contract_preserved'] is True
            and mapping['intrinsic_backend_validated'] is False,
            'mapper input/output/graph/intrinsic lineage mismatch')
    require(handoff['normalized_ir'] == lineage['normalized_ir'] and handoff['normalization'] == lineage['normalization']
            and handoff['inlined_source_functions'] == inline and handoff['intrinsic_backend_validated'] is False,
            'normalization handoff differs')
    context = _receipt_json(reader, lineage['source_context']['path'])
    for key in ('capture', 'inner_plan', 'selection', 'scope_plan', 'policy_projection', 'normalization_gate', 'typed_intrinsics',
                'policy_qualification', 'qualification_gate', 'source_ir_kind'):
        require(context[key] == report[key], 'source context mismatch: ' + key)
    require(context['crates'] == crates and context['normalization'] == lineage['normalization']
            and context['scope_policy'] == report['policy_qualification']['original_policy']
            and report['policy_projection']['original_policy'] == report['policy_qualification']['qualified_policy'],
            'source context drops original policy/crate/normalization')
    root_unit = report['selection']['arms']['derivative']['root_unit']
    roots = [crate for crate in crates if crate['unit'] == root_unit]
    require(len(roots) == 1 and mapping['provenance']['frontend_flags'] == roots[0]['derivative_rustc_argv'][1:],
            'mapper root compiler recipe mismatch')
    expected_evidence = [report['capture'], report['inner_plan'], lineage['source_context'],
                         lineage['qualification'], lineage['qualified_linked_ir'], lineage['normalization']]
    require(mapping['provenance']['evidence_files'] ==
            [{k: item[k] for k in ('path', 'sha256')} for item in expected_evidence],
            'mapper evidence closure mismatch')
    for item in expected_evidence:
        _receipt_bound(reader, item)
    return {'raw_definitions': len(original), 'normalized_definitions': len(surviving),
            'inlined_functions': sorted(removed), 'normalization': lineage['normalization'],
            'semantic_equivalence': 'not_functionally_validated', 'intrinsic_backend_validated': False}



def verify_preparation_receipt(report_path, report_sha256, *, capture_path, capture_sha256,
                               plan_path, plan_sha256, workspace_root, trusted_engine_pins,
                               source_environment, compiler_environment):
    """Rebind a completed preparation after the caller's bounded worker exits.

    No compiler, LLVM library, target or native link executes. This replays the
    pure v5 receipt gates; LLVM body proof remains the pinned child helper's
    proof. The caller separately verifies the outer worker's process/Job receipt.
    """
    reader = Reader(workspace_root)
    root = reader.root
    report_path = reader.path(report_path)
    output = report_path.parent
    require(output.is_relative_to(root / ".runs") and output != root / ".runs"
            and report_path.name == "preparation.json", "private preparation receipt required")
    require(type(trusted_engine_pins) is dict and trusted_engine_pins,
            "caller-reviewed engine pins required")
    engine = pin_index([{"path": name, "sha256": sha} for name, sha in trusted_engine_pins.items()])
    required = {path_key(path) for path in (root / "antirea").rglob("*.py")}
    required |= {path_key(__file__), path_key(root / ".tools/kagura-toolchain.json"),
                 *(path_key(root / path) for path in (SEMANTIC, MAPPER, NORMALIZER, QUALIFIER))}
    require(required <= set(engine), "incomplete receipt-verifier engine closure")
    for key in sorted(engine):
        reader.read(engine[key], owned=False, limit=512 * 1024 * 1024)
    config = json_bytes(reader.read(engine[path_key(root / ".tools/kagura-toolchain.json")]))
    require(config.get("target") == TARGET, "LLVM config target mismatch")
    llvm_root = absolute(config["llvm_root"])
    for name in ("opt.exe", "llvm-link.exe", "LLVM-C.dll"):
        require(path_key(llvm_root / "bin" / name) in engine, "LLVM role absent from reviewed snapshot")
    require(type(source_environment) is dict, "explicit source selector environment required")
    require(type(compiler_environment) is dict
            and set(compiler_environment) == {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP"}
            and all(type(value) is str and value and "\x00" not in value for value in compiler_environment.values()),
            "five explicit nonsecret LLVM process controls required")
    windows = reader.path(compiler_environment["SYSTEMROOT"], owned=False)
    require(absolute(compiler_environment["WINDIR"]) == windows
            and compiler_environment["PATH"] == str(llvm_root / "bin") + ";" + str(windows / "System32")
            and compiler_environment["TEMP"] == compiler_environment["TMP"],
            "fixed LLVM process environment mismatch")
    temporary = reader.path(compiler_environment["TEMP"])
    require(temporary.is_dir() and temporary.is_relative_to(root / ".runs"),
            "private LLVM temporary directory required")
    modules = load_production(reader, engine)
    metadata, semantic = modules["rust_cargo"], modules["rust_cargo_semantic"]
    report = json_bytes(reader.read({"path": str(report_path), "sha256": report_sha256}))
    capture_item = {"path": str(absolute(capture_path)), "sha256": capture_sha256}
    plan_item = {"path": str(absolute(plan_path)), "sha256": plan_sha256}
    capture = json_bytes(reader.read(capture_item))
    inner = json_bytes(reader.read(plan_item))
    require(report.get("capture") == capture_item and report.get("inner_plan") == plan_item,
            "receipt capture/plan differs from caller authority")
    require(report.get("status") == "cargo_ir_prepared_unlinked_unvalidated"
            and report.get("inputs_unchanged") is True and type(report.get("package_port_revision")) is int
            and report["package_port_revision"] == 1, "completed package preparation required")
    require(all(report.get(key) is False for key in ("vm_applied", "target_executed", "native_linked", "published")),
            "unexpected side-effect claim")
    inspection = inner["inspection"]
    require(not under(output, [absolute(path) for path in inspection["input_snapshot"]["roots"]])
            and not under(temporary, [absolute(path) for path in inspection["input_snapshot"]["roots"]]),
            "preparation/temporary directory overlaps owned sources")
    verified = metadata.verify_plan(inner, plan_path=absolute(plan_path), workspace_root=root,
        toolchain=inspection["toolchain"]["selection"], env=source_environment)
    require(verified["metadata_succeeded"] is True, "metadata verification failed")
    capture_plan = json_bytes(reader.read(capture["capture_plan"]))
    recipes = authenticate(reader, capture, inner, capture_plan, absolute(plan_path))
    reported_engine = pin_index(report["reviewed_engine_inputs"])
    require(set(reported_engine) == set(engine) and len(report["reviewed_engine_inputs"]) == len(engine),
            "engine lineage incomplete")
    for key in engine:
        pin_index([engine[key], reported_engine[key]])
        _receipt_bound(reader, reported_engine[key])
    env = report["llvm_environment"]
    require(env == {"keys": sorted(compiler_environment),
                    "sha256": digest(canonical(compiler_environment)),
                    "value_sha256": {key: digest(value.encode("utf-8"))
                                     for key, value in sorted(compiler_environment.items())}},
            "LLVM environment lineage mismatch")
    require(report["checked_inputs"] and report["loaded_production_modules"],
            "terminal checked-input/module evidence missing")
    reported_modules = report["loaded_production_modules"]
    names = [row["module"] for row in reported_modules]
    require(len(names) == len(set(names))
            and {"antirea", "antirea.swift_frontend", *("antirea." + name for name in PACKAGE_ROLES)} <= set(names),
            "loaded package closure missing or duplicated")
    importer = _PackageSourceImporter(reader, engine)
    for row in reported_modules:
        item, _ = importer.source(row["module"])
        require(canonical(row) == canonical({"module": row["module"], **item}),
                "loaded module name/origin/pin mismatch")
        _receipt_bound(reader, item)
    require(report.get("source_import_policy") == "fixed_antirea_namespace_reviewed_source_bytes"
            and type(report.get("verified_source_imports")) is list,
            "source-only import receipt missing")
    for row in report["verified_source_imports"]:
        item, _ = importer.source(row["module"])
        require(canonical(row) == canonical({"module": row["module"], **descriptor(item),
                                            "loader": "verified_source_bytes_no_bytecode_cache"}),
                "source-only import identity mismatch")
    for item in report["checked_inputs"]:
        _receipt_bound(reader, item, hardlinks=item.get("hardlinks") is True)
    lineage, handoff = report["lineage"], report["object_handoff"]
    crates = lineage["crates"]
    expected = [[str(llvm_root / "bin/llvm-link.exe"), "-S",
                 *[row["qualified_ir"]["path"] for row in crates], "-o", lineage["qualified_linked_ir"]["path"]]]
    require(len(report["commands"]) == len(expected), "unexpected LLVM command count")
    for index, (row, argv) in enumerate(zip(report["commands"], expected)):
        require(row["argv"] == argv and row["cwd"] == str(output)
                and metadata._clean(row["process"]), "LLVM command/cleanup mismatch")
        for role, suffix in (("stdout", ".stdout.log"), ("stderr", ".stderr.log"), ("process", ".process.json")):
            require(row["files"][role]["path"] == str(output / ("command-%03d%s" % (index, suffix))),
                    "LLVM command evidence path differs")
            _receipt_bound(reader, row["files"][role])
        process = _receipt_json(reader, row["files"]["process"]["path"])
        require(canonical(process) == canonical(row["process"]) and process["argv"] == argv
                and process["stdout"] == row["files"]["stdout"]["path"]
                and process["stderr"] == row["files"]["stderr"]["path"], "saved LLVM process mismatch")
    fixed_artifacts = {"qualification": "qualification.json", "qualified_linked_ir": "module.qualified.ll",
        "canonical_linked_ir": "module.normalized.ll", "normalized_ir": "module.normalized.ll",
        "normalization": "normalization.json", "mapped_ir": "module.protection-input.ll",
        "mapping": "mapping.json", "source_context": "source-context.json"}
    for role, name in fixed_artifacts.items():
        require(lineage[role]["path"] == str(output / name), "foreign preparation artifact")
        _receipt_bound(reader, lineage[role])
    mapping = _receipt_json(reader, lineage["mapping"]["path"])
    require(mapping["exact_restore_roundtrip"] is True and mapping["calling_convention_rewritten"] is False
            and mapping["vm_applied"] is False, "mapper proof fields missing")
    exports = inspection["project"]["functions"]
    require(sorted(handoff["public_exports"]) == sorted(exports)
            and handoff["object_pipeline_executed"] is False
            and handoff["source_ir"] == lineage["qualified_linked_ir"]
            and handoff["source_ir_kind"] == SOURCE_IR_KIND
            and handoff["qualification"] == lineage["qualification"]
            and handoff["captured_raw_crates"] == [row["raw_copy"] for row in crates]
            and handoff["original_reference_kind"] == "separate_captured_original_Cargo_DLL_required"
            and handoff["protection_ir"] == lineage["mapped_ir"]
            and handoff["selected_functions"] == mapping["protected_selected_functions"]
            and handoff["public_exports"] == mapping["exported_functions"], "object handoff boundary mismatch")
    for row in crates:
        start = recipes["derivative"][row["unit"]]
        require(row["original_rustc_argv"] == start["original_argv"]
                and row["derivative_rustc_argv"] == start["forwarded_argv"]
                and row["rustc_cwd"] == start["cwd"], "crate recipe drift")
    # Use byte-count-complete rows, exactly as the child qualifier received.
    qualification = _verify_saved_qualification(reader, output, report, reported_engine, inner, semantic)
    normalized = _verify_saved_lineage(reader, output, report, mapping, inner)
    _check_package_inventory(reader, engine)
    check_loaded_modules(reader, engine)
    reader.recheck()
    require(metadata.verify_plan(inner, plan_path=absolute(plan_path), workspace_root=root,
        toolchain=inspection["toolchain"]["selection"], env=source_environment)["metadata_succeeded"] is True,
        "terminal metadata verification failed")
    reader.recheck()
    return {"schema_version": 1, "status": "preparation_receipt_rechecked_unlinked_unvalidated",
            "receipt": {"path": str(report_path), "sha256": report_sha256},
            "normalization": normalized, "crate_qualification": qualification,
            "source_ir_kind": SOURCE_IR_KIND, "selected_functions": handoff["selected_functions"],
            "public_exports": handoff["public_exports"], "independent_llvm_reexecution": False,
            "outer_process_cleanup": "caller_must_verify_separately",
            "checked_inputs": [dict(reader.watched[key]) for key in sorted(reader.watched)]}


