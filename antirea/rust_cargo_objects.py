"""Authored internal Cargo preparation -> native objects adapter; not a linker.

Intended package role: antirea.rust_cargo_objects. The caller initially loads
this reviewed source, owns a bounded fresh worker/Windows Job and verifies its
terminal receipt. No project callback, tool override, shell or public CLI exists.
"""
from __future__ import annotations

from contextlib import contextmanager
import copy
import hashlib
import importlib
import importlib.machinery
import json
import os
from pathlib import Path
import re
import stat
import sys

SOURCE_KIND = "qualified_raw_linked_baseline"
TARGET = "x86_64-pc-windows-msvc"
ROLES = ("rust_cargo_prepare", "native_objects", "native_build", "rust_cargo_build")
PASSES = ["fla", "sub", "co"]
MAX_FILE = 512 * 1024**2
STAGES = {name: "preparing" for name in (
    "baseline.ll", "module.prevm.ll", "module.after.ll", "core.diversified.ll",
    "runtime.generated.c", "diversification.json", "runtime.before.ll", "runtime.after.ll")}
STAGES.update({"runtime.obj": "runtime_compiling", "baseline.codegen.ll": "baseline_compiling",
               "baseline.obj": "baseline_compiling", "protected.codegen.ll": "protected_compiling",
               "protected.obj": "protected_compiling"})


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def json_bytes(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, "duplicate JSON key")
            out[key] = value
        return out
    def invalid(_):
        raise ValueError("nonfinite JSON")
    require(type(raw) is bytes and 0 < len(raw) <= 64 * 1024**2, "bounded JSON required")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def path(value, *, fresh=False, hardlinks=False):
    return _checked_path(value, fresh=fresh, hardlinks=hardlinks)


def _sdk_path(value, approved_roots):
    # Only caller-approved SDK/resource inventory roots grant this exception.
    candidate = Path(value)
    matches = [root for root in approved_roots if candidate.is_relative_to(root)]
    require(len(matches) == 1, "path outside/ambiguous approved SDK/resource roots")
    path(matches[0].parent, hardlinks=True)
    return _checked_path(candidate, hardlinks=True, sdk_shared=True)


def _checked_path(value, *, fresh=False, hardlinks=False, sdk_shared=False):
    require(isinstance(value, (str, Path)), "ordinary path required")
    result = Path(value)
    require(result.is_absolute() and ".." not in result.parts
            and not str(result).startswith(("\\\\", "//"))
            and not any(":" in item for item in result.parts[1:])
            and not any(ord(c) < 32 for c in str(result)), "absolute local path required")
    require(not {part.casefold() for part in result.parts} &
            ({"rea-analysis-reports", "attackerfolder", "linkrepro"} |
             (set() if sdk_shared else {"shared"}))
            and result.name.casefold() != "env.setting", "forbidden input path")
    for item in reversed([result, *result.parents]):
        try:
            info = item.lstat()
        except FileNotFoundError:
            require(fresh and item == result, "missing path ancestor/input")
            continue
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
                "symlink/reparse path forbidden")
        if stat.S_ISREG(info.st_mode):
            require(hardlinks or info.st_nlink == 1, "hardlinked private input forbidden")
    if fresh:
        require(not os.path.lexists(result) and result.parent.is_dir(), "fresh output required")
    else:
        require(result == result.resolve(strict=True), "canonical existing path required")
    return result


def descriptor(item):
    require(type(item) is dict and set(item) in ({"path", "sha256"}, {"path", "sha256", "bytes"})
            and type(item.get("path")) is str and type(item.get("sha256")) is str
            and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None,
            "strict file descriptor required")
    require("bytes" not in item or type(item["bytes"]) is int and item["bytes"] >= 0,
            "strict byte count required")
    return dict(item)


class Reader:
    def __init__(self, root):
        self.root = path(root)
        require(self.root.is_dir(), "workspace directory required")
        self.stop = self.root / ".runs/defense-loop/STOP"
        self.watched = {}

    def check_stop(self):
        require(not os.path.lexists(self.stop), "defense STOP set")

    def read(self, item, *, hardlinks=False, limit=MAX_FILE):
        self.check_stop()
        item = descriptor(item)
        target = path(item["path"], hardlinks=hardlinks)
        require(not target.is_relative_to(self.root / ".runs/defense-loop"), "controller is not an artifact")
        before = target.stat()
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit, "file type/size limit")
        raw = target.read_bytes()
        after = target.stat()
        require((before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_ino, after.st_size, after.st_mtime_ns), "file changed during read")
        require(sha(raw) == item["sha256"] and ("bytes" not in item or len(raw) == item["bytes"]),
                "file hash/size changed")
        current = {"path": str(target), "sha256": item["sha256"], "bytes": len(raw)}
        old = self.watched.get(str(target))
        require(old is None or old[0] == current, "conflicting file authority")
        self.watched[str(target)] = (current, hardlinks if old is None else hardlinks and old[1])
        return raw

    def current(self, target):
        target = path(target)
        require(target.is_file() and target.stat().st_size <= MAX_FILE, "bounded output required")
        raw = target.read_bytes()
        item = {"path": str(target), "sha256": sha(raw), "bytes": len(raw)}
        self.read(item)
        return item

    def write(self, target, raw):
        self.check_stop()
        target = path(target, fresh=True)
        require(target.is_relative_to(self.root / ".runs"), "private output required")
        with target.open("xb") as stream:
            stream.write(raw)
        return self.current(target)

    def recheck(self):
        self.check_stop()
        for item, hardlinks in list(self.watched.values()):
            self.read(item, hardlinks=hardlinks)


class _SourceImporter:
    def __init__(self, reader, pins):
        self.reader, self.pins = reader, pins

    def source(self, name):
        require(re.fullmatch(r"antirea(?:\.[A-Za-z_][A-Za-z0-9_]*)*", name) is not None,
                "fixed package namespace only")
        stem = self.reader.root / Path(*name.split("."))
        found = [(p, package) for p, package in ((stem / "__init__.py", True), (Path(str(stem) + ".py"), False))
                 if str(p) in self.pins]
        require(len(found) == 1, "unknown/ambiguous package source")
        p, package = found[0]
        return {"path": str(p), "sha256": self.pins[str(p)]}, package

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
        module.__cached__ = None
        exec(compile(self.reader.read(item), item["path"], "exec", dont_inherit=True), module.__dict__)

    def check_loaded(self):
        for name, module in list(sys.modules.items()):
            if name != "antirea" and not name.startswith("antirea."):
                continue
            item, package = self.source(name)
            spec = getattr(module, "__spec__", None)
            require(getattr(module, "__file__", None) == item["path"] and spec is not None
                    and spec.origin == item["path"] and getattr(spec, "_initializing", False) is False,
                    "foreign/partial package preload")
            if package:
                require(list(getattr(module, "__path__", [])) == [str(Path(item["path"]).parent)],
                        "foreign package search path")
            self.reader.read(item)


def _engine_check(reader, pins):
    require(type(pins) is dict and pins and len(pins) <= 16384, "caller-reviewed engine pins required")
    for name, digest in pins.items():
        reader.read({"path": name, "sha256": digest})
    required = {str(p) for p in (reader.root / "antirea").rglob("*.py")}
    recorded = {name for name in pins if Path(name).is_relative_to(reader.root / "antirea") and Path(name).suffix == ".py"}
    require(required == recorded and str(Path(__file__).resolve()) in pins,
            "complete package and initial-entry source pins required")


@contextmanager
def _modules(reader, pins):
    _engine_check(reader, pins)
    importer = _SourceImporter(reader, pins)
    importer.check_loaded()
    previous = set(sys.modules)
    old_meta, old_path = list(sys.meta_path), list(sys.path)
    try:
        sys.meta_path.insert(0, importer)
        sys.path.insert(0, str(reader.root))
        modules = {name: importlib.import_module("antirea." + name) for name in ROLES}
        importer.check_loaded()
        _engine_check(reader, pins)
        yield modules
        importer.check_loaded()
        _engine_check(reader, pins)
    except BaseException:
        for name in sorted(set(sys.modules) - previous, key=len, reverse=True):
            if name != "antirea" and not name.startswith("antirea."):
                continue
            removed = sys.modules.pop(name, None)
            parent_name, _, child = name.rpartition(".")
            parent = sys.modules.get(parent_name)
            if parent is not None and vars(parent).get(child) is removed:
                delattr(parent, child)
        raise
    finally:
        sys.meta_path[:] = old_meta
        sys.path[:] = old_path


def environment_receipt(environment):
    return {"keys": sorted(environment), "sha256": sha(canonical(environment)),
            "value_sha256": {key: sha(value.encode("utf-8")) for key, value in sorted(environment.items())}}


def _header_inventory(roots, capture):
    # Reject sensitive names and reparse entries BEFORE the existing inventory
    # helper opens any file. Exclusive caller-owned checkpoints, not a sandbox
    # against hostile concurrent replacement between enumeration and hashing.
    files, directories = 0, 0
    for root in roots:
        for current, children, leaves in os.walk(root, followlinks=False):
            _sdk_path(current, roots)
            directories += 1
            require(directories <= 20000, "SDK directory count limit")
            for name in children:
                require(_sdk_path(Path(current) / name, roots).is_dir(), "SDK directory required")
            for name in leaves:
                candidate = _sdk_path(Path(current) / name, roots)
                require(candidate.is_file(), "SDK ordinary file required")
                files += 1
                require(files <= 100000, "SDK file count limit")
    return capture.inventory_trees(roots)


def _native_context(reader, context, environment, modules, engine_pins, source_roots):
    require(type(context) is dict and set(context) == {"schema_version", "configuration", "toolchain",
            "tool_pins", "header_inventory", "compiler_environment"}
            and type(context["schema_version"]) is int and context["schema_version"] == 1,
            "trusted native context schema mismatch")
    config_path = reader.root / ".tools/kagura-toolchain.json"
    require(context["configuration"]["path"] == str(config_path), "fixed current configuration required")
    reader.read(context["configuration"])
    config, tools = modules["native_build"]._toolchain(reader.root)
    require(canonical(config) == canonical(context["toolchain"]) and tools == context["tool_pins"],
            "current native toolchain differs from caller-approved context")
    require(config.get("target") == TARGET and all(engine_pins.get(name) == digest for name, digest in tools.items()),
            "native tools/config not in caller-reviewed engine authority")
    for name, digest in tools.items():
        reader.read({"path": name, "sha256": digest})
    require(type(environment) is dict and set(environment) == {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP", "INCLUDE"}
            and all(type(v) is str and v and "\x00" not in v for v in environment.values()),
            "exact six-key native object environment required")
    windows, llvm_root = path(environment["SYSTEMROOT"]), path(config["llvm_root"])
    temporary = path(environment["TEMP"])
    require(path(environment["WINDIR"]) == windows and environment["TEMP"] == environment["TMP"]
            and environment["PATH"] == str(llvm_root / "bin") + ";" + str(windows / "System32")
            and temporary.is_dir() and temporary.is_relative_to(reader.root / ".runs")
            and not any(temporary.is_relative_to(root) or root.is_relative_to(temporary) for root in source_roots),
            "native environment paths differ or overlap sources")
    include = environment["INCLUDE"].split(";")
    require(1 <= len(include) <= 16 and all(include) and len(set(include)) == len(include),
            "explicit ordered INCLUDE roots required")
    candidates = [llvm_root / "lib/clang", *map(Path, include)]
    approved = context["header_inventory"]
    require(type(approved) is dict and type(approved.get("roots")) is list
            and all(type(item) is str for item in approved["roots"])
            and len(set(candidates)) == len(candidates)
            and not any(a != b and a.is_relative_to(b) for a in candidates for b in candidates)
            and approved["roots"] == sorted(approved["roots"])
            and len(approved["roots"]) == len(candidates)
            and set(candidates) == {Path(item) for item in approved["roots"]},
            "exact caller-approved SDK/resource inventory roots required")
    roots = [_sdk_path(item, candidates) for item in candidates]
    require(all(root.is_dir() for root in roots) and not any(root.is_relative_to(source) or source.is_relative_to(root)
            for root in roots for source in source_roots), "native resource/SDK roots overlap project")
    require(not any(root.is_relative_to(reader.root / ".runs/defense-loop")
                    or (reader.root / ".runs/defense-loop").is_relative_to(root) for root in roots),
            "controller cannot be a header root")
    observed = _header_inventory(roots, modules["rust_cargo_build"])
    require(canonical(observed) == canonical(context["header_inventory"]), "SDK/resource inventory changed")
    require(environment_receipt(environment) == context["compiler_environment"], "native environment changed")
    return dict(config), dict(tools)


def _handoff(reader, report, verified):
    require(report.get("status") == "cargo_ir_prepared_unlinked_unvalidated"
            and report.get("inputs_unchanged") is True
            and verified.get("status") == "preparation_receipt_rechecked_unlinked_unvalidated",
            "completed independently rebound preparation required")
    handoff = report["object_handoff"]
    require(handoff["source_ir_kind"] == verified["source_ir_kind"] == SOURCE_KIND
            and handoff["source_ir"] == report["lineage"]["qualified_linked_ir"]
            and handoff["protection_ir"] == report["lineage"]["mapped_ir"]
            and handoff["object_pipeline_executed"] is False
            and handoff["original_reference_kind"] == "separate_captured_original_Cargo_DLL_required",
            "qualified baseline/mapped protection boundary differs")
    selected, exports = handoff["selected_functions"], handoff["public_exports"]
    require(type(selected) is list and 1 <= len(selected) <= 64 and len(set(selected)) == len(selected)
            and all(type(name) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) for name in selected)
            and type(exports) is list and exports and len(set(exports)) == len(exports)
            and set(exports) <= set(selected) and selected == verified["selected_functions"]
            and exports == verified["public_exports"], "complete selected/export sets required")
    lineage = handoff["source_definition_lineage"]
    require(lineage == report["source_definition_lineage"] and type(lineage) is list and lineage,
            "source definition lineage missing")
    owners, covered = set(), set()
    for row in lineage:
        require(type(row) is dict and type(row.get("owner")) is dict
                and type(row.get("source_symbol")) is str and row["source_symbol"]
                and type(row.get("qualified_symbol")) is str and row["qualified_symbol"]
                and type(row.get("inlined_not_a_separate_wrapper")) is bool
                and type(row.get("protected_symbols")) is list and row["protected_symbols"]
                and type(row.get("surviving_symbols")) is list
                and len(row["surviving_symbols"]) == len(row["protected_symbols"])
                and len(set(row["protected_symbols"])) == len(row["protected_symbols"])
                and set(row["protected_symbols"]) <= set(selected), "invalid owner/inlining coverage relation")
        identity = canonical([row["owner"], row["source_symbol"]])
        require(identity not in owners, "duplicate original source definition")
        owners.add(identity)
        covered.update(row["protected_symbols"])
    require(covered == set(selected), "source lineage omits a selected wrapper")
    source = reader.read(handoff["source_ir"], limit=32 * 1024**2)
    protected = reader.read(handoff["protection_ir"], limit=32 * 1024**2)
    require(source and protected, "empty pipeline input")
    return handoff, source, protected


def _layer(item, name, *, mandatory):
    require(type(item) is dict and item.get("function") == name and item.get("requested_passes") == PASSES
            and type(item.get("fla_dispatcher")) is bool
            and all(type(item.get(key)) is int and item[key] >= 0 for key in
                    ("substitution_instructions", "constant_obfuscation_instructions")),
            "malformed structural layer evidence")
    if mandatory:
        require(item["fla_dispatcher"] and item["substitution_instructions"] > 0
                and item["constant_obfuscation_instructions"] > 0, "runtime layer evidence incomplete")


def bind_coverage(handoff, evidence, core_layers, dispatchers):
    selected = handoff["selected_functions"]
    require(evidence.get("status") == "native_objects_created_unlinked"
            and evidence.get("selected_functions") == selected, "object result selection/status differs")
    require(type(core_layers) is dict and set(core_layers) == set(selected), "core layer selection differs")
    for name, item in core_layers.items():
        _layer(item, name, mandatory=False)
    stages = {key: evidence[key] for key in ("original_vm", "functions", "final_vm")}
    for label, rows in stages.items():
        require(type(rows) is dict and set(rows) == set(selected)
                and all(type(row) is dict and row.get("virtualized") is True for row in rows.values()),
                "missing/extra/unvirtualized function at " + label)
    require(type(dispatchers) is list and dispatchers and len(set(dispatchers)) == len(dispatchers),
            "unique runtime dispatchers required")
    for label in ("functions", "final_vm"):
        require({row["dispatcher"] for row in stages[label].values()} == set(dispatchers),
                "runtime dispatcher coverage differs")
    runtime = evidence["runtime_evidence"]
    engines = runtime.get("engines") if len(dispatchers) > 1 else {dispatchers[0]: runtime}
    require(type(engines) is dict and set(engines) == set(dispatchers), "runtime engine set differs")
    for name, item in engines.items():
        _layer(item, name, mandatory=True)
    rows = []
    for source in handoff["source_definition_lineage"]:
        rows.append({**copy.deepcopy(source), "wrappers": {
            name: {key: copy.deepcopy(items[name]) for key, items in stages.items()}
            for name in source["protected_symbols"]}})
    return {"schema_version": 1, "selected_functions": list(selected), "public_exports": handoff["public_exports"],
            "by_source_definition": rows, "requested_core_passes": [*PASSES, "vm"],
            "pre_vm_evidence": core_layers, **stages, "runtime_evidence": runtime,
            "hardening_evidence": evidence["hardening_evidence"],
            "qualification": "Structural all-function evidence; inline sources share recorded surviving wrappers. No functional or defense result."}


def _command_recipes(config, output, selected, seed, dispatchers):
    o = lambda name: str(output / name)
    flags = ["-O1", "-kagura-fla", "-kagura-sub", "-kagura-co",
             "-kagura-allow=" + ",".join(selected), f"-kagura-seed={seed}"]
    return [
        [config["optimizer"], "-O1", "-S", o("module.before.ll"), "-o", o("baseline.ll")],
        [config["optimizer"], *flags, "-S", o("module.protection-input.ll"), "-o", o("module.prevm.ll")],
        [config["optimizer"], *flags, "-kagura-vm", "-S", o("module.protection-input.ll"), "-o", o("module.after.ll")],
        [config["clang"], "-target", TARGET, "-std=c11", "-O1", "-fno-inline", "-S", "-emit-llvm",
         o("runtime.generated.c"), "-o", o("runtime.before.ll")],
        [config["optimizer"], "-O1", "-kagura-fla", "-kagura-sub", "-kagura-co",
         "-kagura-allow=" + ",".join(dispatchers), f"-kagura-seed={seed}", "-S", o("runtime.before.ll"), "-o", o("runtime.after.ll")],
        [config["clang"], "-target", TARGET, "-O0", "-c", o("runtime.after.ll"), "-o", o("runtime.obj")],
        *[argv for arm in ("baseline", "protected") for argv in (
            [config["clangxx"], "-target", TARGET, "-O1", "-S", "-emit-llvm",
             o("baseline.ll" if arm == "baseline" else "core.diversified.ll"), "-o", o(arm + ".codegen.ll")],
            [config["clangxx"], "-target", TARGET, "-O0", "-c", o(arm + ".codegen.ll"), "-o", o(arm + ".obj")])]]


def _completed_process(row):
    """Require internally consistent real run_logged Windows Job evidence.

    cleanup.parent_pid is the launched child PID, not the coordinator's PID.
    Status labels do not override missing identity/accounting or later errors.
    Apply to both in-memory journal and decoded JSON: Python equality alone
    treats True/1 and integral float/int as equal.
    """
    require(type(row) is dict and type(row.get("pid")) is int and row["pid"] > 0
            and type(row.get("returncode")) is int and row["returncode"] == 0
            and row.get("timed_out") is False and row.get("cancelled") is False
            and "error" not in row and "post_cleanup_wait_error" not in row,
            "native command identity/exit or post-cleanup error differs")
    cleanup = row.get("cleanup")
    require(type(cleanup) is dict
            and type(cleanup.get("parent_pid")) is int and cleanup["parent_pid"] == row["pid"]
            and cleanup.get("method") == "windows_job" and cleanup.get("job_assigned") is True
            and cleanup.get("assignment_timing") == "immediately_after_launch"
            and type(cleanup.get("active_before")) is int and cleanup["active_before"] >= 0
            and type(cleanup.get("active_after")) is int and cleanup["active_after"] == 0
            and cleanup.get("status") == "assigned_job_empty"
            and cleanup.get("parent_exit_confirmed") is True and cleanup.get("job_handle_closed") is True
            and not any(type(key) is not str or key == "error" or key.endswith("_error") for key in cleanup),
            "native command Windows Job identity/accounting/cleanup differs")


def _bind_outputs(reader, output, result, commands, recipes):
    watched = result["watched_outputs"]
    require(type(watched) is dict and set(watched) == set(STAGES), "stage output set differs")
    for name, item in watched.items():
        require(type(item) is dict and set(item) == {"path", "sha256", "bytes", "observed_stage"}
                and item["path"] == str(output / name) and item["observed_stage"] == STAGES[name],
                "stage output path/phase differs")
        reader.read({key: item[key] for key in ("path", "sha256", "bytes")})
    require(set(result["objects"]) == {"baseline", "protected", "runtime"}, "object set differs")
    for arm, item in result["objects"].items():
        require(item == {key: watched[arm + ".obj"][key] for key in ("path", "sha256", "bytes")},
                "object not bound to observed stage")
    require(result["final_ir"] == {key: watched["protected.codegen.ll"][key] for key in ("path", "sha256", "bytes")},
            "final codegen IR differs")
    require(len(commands) == len(recipes), "missing/extra pipeline command")
    records = []
    for index, (row, argv) in enumerate(zip(commands, recipes), 1):
        _completed_process(row)
        require(row.get("argv") == argv and row.get("cwd") == str(output),
                "pipeline command recipe differs")
        prefix = output / "logs" / f"{index:03d}"
        files = {role: reader.current(Path(str(prefix) + suffix)) for role, suffix in
                 (("stdout", ".stdout.log"), ("stderr", ".stderr.log"), ("process", ".process.json"))}
        process = json_bytes(reader.read(files["process"]))
        _completed_process(process)
        require(row == {**process, "cwd": str(output)} and row["stdout"] == files["stdout"]["path"]
                and row["stderr"] == files["stderr"]["path"], "saved process/log identity differs")
        records.append({"command_index": index - 1, "files": files})
    return records


def build_prepared_objects(preparation_path, preparation_sha256, *, capture_path, capture_sha256,
        plan_path, plan_sha256, workspace_root, output_dir, trusted_engine_pins, trusted_native_context,
        source_environment, preparation_environment, compiler_environment, seed=1729):
    """Explicit native compilation only; this entry never links or loads a target.

    Context/pins are trusted caller authority, never fields from user Cargo JSON.
    Caller must verify the preparation worker and this worker's outer Job/exit.
    Preflight raises without creating output. Later failures retain report.json.
    """
    reader = Reader(workspace_root)
    output = path(output_dir, fresh=True)
    require(output.is_relative_to(reader.root / ".runs") and output != reader.root / ".runs"
            and not output.is_relative_to(reader.root / ".runs/defense-loop"), "fresh private object directory required")
    require(type(seed) is int and 1 <= seed <= 2147483647, "bounded nonboolean seed required")
    preparation_item = {"path": str(path(preparation_path)), "sha256": preparation_sha256}
    arguments = dict(capture_path=capture_path, capture_sha256=capture_sha256,
        plan_path=plan_path, plan_sha256=plan_sha256, workspace_root=reader.root,
        trusted_engine_pins=trusted_engine_pins, source_environment=source_environment,
        compiler_environment=preparation_environment)
    report = None
    try:
        with _modules(reader, trusted_engine_pins) as modules:
            prep, native = modules["rust_cargo_prepare"], modules["native_objects"]
            verified = prep.verify_preparation_receipt(preparation_path, preparation_sha256, **arguments)
            prepared = json_bytes(reader.read(preparation_item))
            require(verified.get("receipt") == preparation_item, "consumer verified another preparation")
            handoff, source, protection = _handoff(reader, prepared, verified)
            inner = json_bytes(reader.read({"path": str(path(plan_path)), "sha256": plan_sha256}))
            roots = [path(p) for p in inner["inspection"]["input_snapshot"]["roots"]]
            require(not any(output.is_relative_to(root) or root.is_relative_to(output) for root in roots),
                    "object output overlaps source")
            require(output != Path(preparation_path).parent and not Path(preparation_path).parent.is_relative_to(output),
                    "output overlaps preparation")
            config, _ = _native_context(reader, trusted_native_context, compiler_environment,
                                        modules, trusted_engine_pins, roots)
            reader.recheck()
            output.mkdir()
            report = {"schema_version": 1, "status": "failed_native_objects_unlinked", "seed": seed,
                "preparation": preparation_item, "preparation_verification": verified,
                "source_ir_kind": SOURCE_KIND, "commands": [], "native_context": copy.deepcopy(trusted_native_context),
                "compiler_environment": environment_receipt(compiler_environment), "native_linked": False,
                "target_executed": False, "published": False, "functional_validation": "not_performed",
                "performance_validation": "not_performed", "protection_effectiveness": "not_evaluated",
                "preparation_outer_process_cleanup": "caller_must_verify_separately",
                "outer_process_cleanup": "caller_must_verify_separately"}
            staged_source = reader.write(output / "module.before.ll", source)
            staged_protection = reader.write(output / "module.protection-input.ll", protection)
            report["staging"] = {"source": {"original": handoff["source_ir"], "staged": staged_source},
                                 "protection": {"original": handoff["protection_ir"], "staged": staged_protection}}
            request = native.ObjectRequest(native.IRInput(Path(staged_source["path"]), staged_source["sha256"]),
                native.IRInput(Path(staged_protection["path"]), staged_protection["sha256"]),
                tuple(handoff["selected_functions"]), seed)
            pipeline = native.ObjectPipeline(request, workspace_root=reader.root, output_dir=output,
                command_records=report["commands"], environment=compiler_environment,
                build_tool_hashes=trusted_engine_pins)
            pipeline.prepare()
            core_layers = {name: modules["native_build"]._layer_evidence(pipeline.pre_text, name)
                           for name in handoff["selected_functions"]}
            pipeline.compile_runtime()
            pipeline.compile_arm("baseline")
            pipeline.compile_arm("protected")
            evidence = pipeline.finalize()
            require(evidence["source_ir"] == {key: staged_source[key] for key in ("path", "sha256")}
                    and evidence["protection_ir"] == {key: staged_protection[key] for key in ("path", "sha256")},
                    "pipeline consumed a different staged IR")
            report["native_object_pipeline"] = evidence
            report["coverage"] = bind_coverage(handoff, evidence, core_layers, pipeline.dispatchers)
            report["command_evidence"] = _bind_outputs(reader, output, evidence, report["commands"],
                _command_recipes(config, output, handoff["selected_functions"], seed, pipeline.dispatchers))
            # Rebind preparation after all native stages. No status success before
            # nested verifiers, complete stage hashes, header/context and imports.
            report["terminal_preparation_verification"] = prep.verify_preparation_receipt(
                preparation_path, preparation_sha256, **arguments)
            require(canonical(report["terminal_preparation_verification"]) == canonical(verified),
                    "preparation verification changed during object creation")
            _native_context(reader, trusted_native_context, compiler_environment, modules, trusted_engine_pins, roots)
            reader.recheck()
        reader.recheck()  # also after source-import context's terminal checks
        report["inputs_unchanged"] = True
        report["status"] = "native_objects_created_unlinked"
    except Exception as exc:
        if report is None:
            raise
        report["status"] = "failed_native_objects_unlinked"
        report["error"] = type(exc).__name__ + ": " + str(exc)[:8192]
    if report is not None:
        report["checked_inputs"] = [dict(item) for item, _ in reader.watched.values()]
        report["qualification"] = ("Native objects only; qualified linked baseline is not original Cargo output. "
            "Required next: actual unit-bound native link, code-carrier removal, public exports/ABI, original Cargo "
            "versus baseline/protected behavior, performance and external defense evaluation. "
            "Typed intrinsic acceptance and VM structure alone are not intrinsic semantic validation.")
        terminal = path(output / "report.json", fresh=True)
        with terminal.open("xb") as stream:
            stream.write(canonical(report) + b"\n")
    return report
