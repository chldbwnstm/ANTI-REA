"""Cargo metadata planning foundation; no compilation or protection entry point.

Cargo, not this module, resolves dependencies/features. TOML is read only for
input inventory and explicit unsupported-hook checks. Metadata is not a Cargo
build plan; the original/derivative rustc recipes and consumed dep-info closure
remain unimplemented. A successful inspection must never be reported as a build.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tomllib
from typing import Callable

TARGET = "x86_64-pc-windows-msvc"
LIMITS = {"files": 20000, "bytes": 1536 * 1024 * 1024, "file_bytes": 512 * 1024 * 1024}
FORBIDDEN_PARTS = {"rea-analysis-reports", "attackerfolder"}
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\Z")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _hash(value):
    return _digest(_canonical(value))


def _json(data):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate JSON key: {key}")
            out[key] = value
        return out
    def invalid_constant(_):
        raise ValueError("non-finite JSON number")
    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid_constant)


def _under(path, root):
    return path == root or root in path.parents


def _path(value, *, directory=None, must_exist=True):
    """Reject links in every lexical component before canonicalizing."""
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("an absolute trusted/resolved path is required")
    if str(path).startswith(("\\\\?\\", "\\\\.\\")) or any(":" in part for part in path.parts[1:]):
        raise ValueError("device/extended/alternate-stream paths are not permitted")
    for part in reversed([path, *path.parents]):
        try:
            info = part.lstat()
        except FileNotFoundError:
            if must_exist or part != path:
                raise ValueError(f"missing path: {part}")
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError(f"symlink/reparse path is not permitted: {part}")
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise ValueError(f"hardlinked input is not permitted: {part}")
    path = path.resolve(strict=must_exist)
    if must_exist and directory is True and not path.is_dir():
        raise ValueError(f"expected directory: {path}")
    if must_exist and directory is False and not path.is_file():
        raise ValueError(f"expected regular file: {path}")
    return path


def _owned(value, workspace, *, directory=None, must_exist=True):
    path = _path(value, directory=directory, must_exist=must_exist)
    if not _under(path, workspace) or path == workspace:
        raise ValueError("owned input must be a bounded path inside the workspace")
    parts = {x.lower() for x in path.relative_to(workspace).parts}
    if parts & FORBIDDEN_PARTS or _under(path, workspace / ".runs" / "defense-loop"):
        raise ValueError("received/controller folders are not source inputs")
    return path


def _file(path):
    path = _path(path, directory=False)
    size = path.stat().st_size
    if size > LIMITS["file_bytes"]:
        raise ValueError("file exceeds inventory limit")
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    if path.stat().st_size != size:
        raise ValueError("input size changed during hashing")
    return {"path": str(path), "bytes": size, "sha256": hasher.hexdigest()}


def _inventory(roots, *, owned_workspace=None):
    files, directories = {}, set()
    for value in roots:
        root = _path(value, directory=True)
        for current, names, leaves in os.walk(root, followlinks=False):
            current = _path(Path(current), directory=True)
            if owned_workspace is not None:
                _owned(current, owned_workspace, directory=True)
            directories.add(str(current))
            for name in sorted(names):
                _path(current / name, directory=True)
                if owned_workspace is not None:
                    _owned(current / name, owned_workspace, directory=True)
            for name in sorted(leaves):
                item = _file(current / name)
                files[item["path"]] = item
                if len(files) > LIMITS["files"]:
                    raise ValueError("input inventory file-count limit exceeded")
    ordered = [files[key] for key in sorted(files)]
    if sum(x["bytes"] for x in ordered) > LIMITS["bytes"]:
        raise ValueError("input inventory byte limit exceeded")
    result = {"roots": sorted(str(Path(x)) for x in roots),
              "directories": sorted(directories), "files": ordered}
    result["sha256"] = _hash(result)
    return result


def _relative(base, value, workspace, *, directory=None):
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise ValueError("manifest paths must be nonempty relative paths")
    return _owned(base / value, workspace, directory=directory)


def _read_project(path, workspace):
    path = _owned(path, workspace, directory=False)
    value = _json(path.read_bytes())
    allowed = {"schema_version", "name", "language", "rust_cargo", "functions", "scope_policy"}
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValueError("unknown or malformed project fields")
    if type(value.get("schema_version")) is not int or value["schema_version"] != 1 or value.get("language") != "rust":
        raise ValueError("expected schema 1 Rust project")
    if not isinstance(value.get("name"), str) or not NAME.fullmatch(value["name"]):
        raise ValueError("invalid project name")
    cfg = value.get("rust_cargo")
    fields = {"manifest_path", "package", "target_kind", "target_name", "profile", "features",
              "default_features", "local_dependency_roots"}
    if not isinstance(cfg, dict) or set(cfg) - fields:
        raise ValueError("unknown or malformed rust_cargo fields")
    if cfg.get("target_kind") != "lib":
        raise ValueError("this inspector selects a library target; executable build is not implemented")
    for key in ("package", "profile"):
        if not isinstance(cfg.get(key), str) or not NAME.fullmatch(cfg[key]):
            raise ValueError(f"explicit {key} selection is required")
    if "target_name" in cfg and (not isinstance(cfg["target_name"], str) or not NAME.fullmatch(cfg["target_name"])):
        raise ValueError("invalid target name")
    features = cfg.get("features")
    if not isinstance(features, list) or any(not isinstance(x, str) or not NAME.fullmatch(x) for x in features):
        raise ValueError("features must be an explicit list of package-local feature names")
    if len(set(features)) != len(features) or type(cfg.get("default_features")) is not bool:
        raise ValueError("duplicate features or missing default_features boolean")
    functions = value.get("functions")
    if not isinstance(functions, list) or not functions or any(not isinstance(x, str) or not IDENTIFIER.fullmatch(x) for x in functions) or len(set(functions)) != len(functions):
        raise ValueError("functions must name unique external ABI entries")
    cargo_manifest = _relative(path.parent, cfg.get("manifest_path"), workspace, directory=False)
    if cargo_manifest.name != "Cargo.toml":
        raise ValueError("manifest_path must select Cargo.toml")
    extras = cfg.get("local_dependency_roots", [])
    if not isinstance(extras, list):
        raise ValueError("local_dependency_roots must be a list")
    roots = [path.parent] + [_relative(path.parent, x, workspace, directory=True) for x in extras]
    roots = sorted(set(roots))
    roots = [x for x in roots if not any(x != y and _under(x, y) for y in roots)]
    if not any(_under(cargo_manifest, x) for x in roots):
        raise ValueError("Cargo manifest is outside declared input roots")
    if "scope_policy" in value:
        policy = _relative(path.parent, value["scope_policy"], workspace, directory=False)
        if not any(_under(policy, root) for root in roots):
            raise ValueError("scope_policy must stay inside declared input roots")
    return path, value, cargo_manifest, roots


def _toolchain(toolchain):
    if not isinstance(toolchain, dict) or set(toolchain) != {"cargo", "rustc", "sysroot", "target"}:
        raise ValueError("trusted toolchain must supply cargo/rustc/sysroot/target exactly")
    if toolchain["target"] != TARGET:
        raise ValueError("only Windows x64 target inspection is implemented")
    root = _path(toolchain["sysroot"], directory=True)
    cargo, rustc = [_path(toolchain[x], directory=False) for x in ("cargo", "rustc")]
    if cargo != root / "bin" / "cargo.exe" or rustc != root / "bin" / "rustc.exe":
        raise ValueError("use actual installed backend executables, not rustup/PATH launchers")
    # Full backend bin inventory includes rustc_driver/backend DLLs. Include target
    # libraries + rustlib metadata; no assumption that cargo.exe pins the sysroot.
    inventory = _inventory([root / "bin", root / "lib" / "rustlib"])
    target_lib = root / "lib" / "rustlib" / TARGET / "lib"
    _path(target_lib, directory=True)
    if not any(Path(x["path"]).parent == target_lib for x in inventory["files"]):
        raise ValueError("empty target sysroot")
    return {"selection": {"cargo": str(cargo), "rustc": str(rustc), "sysroot": str(root), "target": TARGET},
            "inventory": inventory,
            "compiler_inputs": {x["path"]: x["sha256"] for x in inventory["files"]}}


def _environment(env):
    normalized = {str(k).upper(): str(v) for k, v in env.items()}
    if len(normalized) != len(env):
        raise ValueError("ambiguous case-insensitive environment variables")
    # Never serialize tokens, secrets, PATH contents, or arbitrary environment
    # values. Whole-map digest also detects env!/option_env! input changes.
    selectors = {key: _digest(value.encode()) for key, value in normalized.items()
                 if key.startswith(("CARGO", "RUST", "CC", "CXX", "SDK", "VCTOOLS", "VSINSTALL")) or key in {"PATH", "INCLUDE", "LIB", "LIBPATH", "HOME", "USERPROFILE"}}
    return {"sha256": _hash(normalized), "selector_value_sha256": dict(sorted(selectors.items()))}


def _normalize_environment(env):
    normalized = {}
    for key, value in env.items():
        if (not isinstance(key, str) or not isinstance(value, str) or not key
                or any(ch in key for ch in "\x00=") or "\x00" in value):
            raise ValueError("invalid host environment entry")
        name = key.upper()
        if name in normalized:
            raise ValueError("ambiguous case-insensitive environment variables")
        normalized[name] = value
    return normalized


def _metadata_environment(source, tools):
    """Select a minimal Windows environment, never inherit the caller's map.

    Ambient home selectors are used only to discover and reject global Cargo
    configuration. Other Cargo/Rust overrides block the query. Job-local paths
    appear as control placeholders in semantic identity, not as random job IDs.
    The actual child-map digest is separately bound to the execution receipt.
    """
    if os.name != "nt":
        raise ValueError("Cargo metadata planning currently requires a Windows host")
    env = _normalize_environment(source)
    if not any(env.get(key) for key in ("CARGO_HOME", "USERPROFILE", "HOME")):
        raise ValueError("Explicit CARGO_HOME, USERPROFILE or HOME is required for global Cargo config discovery")
    windows = env.get("SYSTEMROOT") or env.get("WINDIR")
    if not windows:
        raise ValueError("Windows SYSTEMROOT or WINDIR is required")
    windows = _path(windows, directory=True)
    if env.get("SYSTEMROOT") and _path(env["SYSTEMROOT"], directory=True) != windows:
        raise ValueError("conflicting Windows host directories")
    if env.get("WINDIR") and _path(env["WINDIR"], directory=True) != windows:
        raise ValueError("conflicting Windows host directories")
    system32 = _path(windows / "System32", directory=True)
    host = {"SYSTEMROOT": str(windows), "WINDIR": str(windows),
            "PATH": str(Path(tools["selection"]["cargo"]).parent) + ";" + str(system32)}
    selectors, dispositions, blockers = {}, {}, []
    for name, value in sorted(env.items()):
        if name.startswith(("CARGO", "RUST")) or name in {"HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR"}:
            selectors[name] = _digest(value.encode("utf-8"))
            if name in {"CARGO_HOME", "HOME", "USERPROFILE"}:
                dispositions[name] = "private_replacement; ambient_config_discovery_checked"
            elif name in {"SYSTEMROOT", "WINDIR"}:
                dispositions[name] = "validated_host_directory"
            elif value:
                dispositions[name] = "rejected_override"
                blockers.append("unsupported_environment_selector:" + name)
            else:
                dispositions[name] = "empty_not_inherited"
    template = {**host, **_overrides(tools, Path("<inspection>"))}
    policy = {"schema_version": 1, "policy": "windows_metadata_minimal_v1",
              "ambient_selector_value_sha256": selectors, "ambient_dispositions": dispositions,
              "child_template": template, "inherits_other_variables": False,
              "qualification": "Metadata-only environment, not the original Cargo build environment; no OS sandbox or hermetic Windows runtime claim."}
    policy["sha256"] = _hash(policy)
    return env, policy, host, sorted(blockers)


def _configuration(cwd, env):
    candidates = []
    for parent in [cwd, *cwd.parents]:
        candidates.extend(parent / ".cargo" / x for x in ("config", "config.toml"))
        candidates.extend(parent / x for x in ("rust-toolchain", "rust-toolchain.toml"))
    home = env.get("CARGO_HOME") or str(Path(env.get("USERPROFILE") or env["HOME"]) / ".cargo")
    if not Path(home).is_absolute():
        home = str(cwd / home)
    candidates.extend(Path(home) / x for x in ("config", "config.toml"))
    records, blockers = [], []
    for path in dict.fromkeys(candidates):
        # Missing files are part of discovery identity: new ancestor config must
        # invalidate a prior plan even when no previous config was consumed.
        if not path.exists() and not path.is_symlink():
            records.append({"path": str(path), "exists": False})
            continue
        record = _file(path)
        record["exists"] = True
        records.append(record)
        if path.name.startswith("rust-toolchain"):
            # Actual backend is caller-selected, not rustup-resolved. Do not
            # silently claim this matches a project's channel override.
            blockers.append(f"toolchain_override_requires_explicit_resolution:{path}")
            continue
        # Do not hide ambient global configuration by using a private home.
        # This first production slice rejects every discovered Cargo config,
        # including otherwise harmless settings, before querying the tool.
        # Hash only: config contents may include credentials and are not logged.
        blockers.append(f"unsupported_cargo_configuration:{path}")
    return {"discovery": records, "sha256": _hash(records)}, blockers


def _workspace_discovery(cwd, roots):
    """Record Cargo's ancestor workspace candidates, including absent files.

    This is not workspace resolution; Cargo still owns that decision. A candidate
    outside inventoried roots blocks execution rather than letting metadata read
    an unpinned parent workspace and rejecting it only afterwards.
    """
    records, blockers = [], []
    for parent in [cwd, *cwd.parents]:
        candidate = parent / "Cargo.toml"
        if candidate.exists() or candidate.is_symlink():
            record = _file(candidate)
            records.append(record)
            if not any(_under(candidate, x) for x in roots):
                blockers.append(f"ancestor_manifest_outside_declared_roots:{candidate}")
        else:
            records.append({"path": str(candidate), "exists": False})
    return records, blockers


def _preflight(snapshot, roots, env, toolchain):
    blockers, manifests = [], []
    expected_rustc = toolchain["selection"]["rustc"]
    for key, value in env.items():
        upper = key.upper()
        if not value:
            continue
        if upper in {"RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS", "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "RUSTDOCFLAGS", "CARGO_ENCODED_RUSTDOCFLAGS", "RUSTC_BOOTSTRAP"} or (upper.startswith("CARGO_TARGET_") and upper.endswith(("_LINKER", "_RUNNER", "_RUSTFLAGS"))):
            blockers.append(f"unsupported_environment_selector:{upper}")
        if upper == "RUSTC" and Path(value) != Path(expected_rustc):
            blockers.append("ambient_rustc_differs_from_pinned_backend")
        if upper in {"CARGO_BUILD_TARGET", "RUSTUP_TOOLCHAIN"}:
            blockers.append(f"ambient_target_or_toolchain_requires_resolution:{upper}")
    for record in snapshot["files"]:
        path = Path(record["path"])
        if path.name not in {"Cargo.toml", "Cargo.lock"}:
            continue
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        if path.name == "Cargo.lock":
            if any(x.get("source") for x in data.get("package", [])):
                blockers.append(f"nonlocal_lockfile_package:{path}")
            continue
        package = data.get("package", {})
        if not isinstance(package, dict):
            raise ValueError("malformed Cargo package table")
        if package.get("build") not in (None, False) or (package.get("build") is not False and (path.parent / "build.rs").exists()):
            blockers.append(f"build_script_not_supported:{path}")
        if package.get("links"):
            blockers.append(f"native_links_not_supported:{path}")
        if "workspace" in package:
            target = _path(path.parent / package["workspace"], directory=True)
            if not any(_under(target, x) for x in roots):
                blockers.append(f"explicit_workspace_outside_declared_roots:{path}")
        if data.get("lib", {}).get("proc-macro"):
            blockers.append(f"proc_macro_not_supported:{path}")
        if "patch" in data or "replace" in data:
            blockers.append(f"cargo_source_override_not_supported:{path}")
        def walk_dependencies(obj):
            if not isinstance(obj, dict):
                return
            for key, val in obj.items():
                if key in {"dependencies", "dev-dependencies", "build-dependencies"} and isinstance(val, dict):
                    for name, dep in val.items():
                        if key == "build-dependencies":
                            blockers.append(f"build_dependency_not_supported:{path}:{name}")
                        if not isinstance(dep, dict) or not ("path" in dep or dep.get("workspace") is True):
                            blockers.append(f"nonlocal_dependency_not_supported:{path}:{name}")
                        elif "path" in dep:
                            target = _path(path.parent / dep["path"], directory=True)
                            if not any(_under(target, x) for x in roots):
                                blockers.append(f"dependency_outside_declared_roots:{path}:{name}")
                        if isinstance(dep, dict) and any(key in dep for key in ("git", "registry", "registry-index")):
                            blockers.append(f"dependency_source_override_not_supported:{path}:{name}")
                else:
                    walk_dependencies(val)
        walk_dependencies(data)
        workspace = data.get("workspace", {})
        if isinstance(workspace, dict):
            for member in workspace.get("members", []):
                if not isinstance(member, str) or any(ch in member for ch in "*?["):
                    blockers.append(f"workspace_member_glob_requires_inventory_support:{path}")
                else:
                    target = _path(path.parent / member, directory=True)
                    if not any(_under(target, x) for x in roots):
                        blockers.append(f"workspace_member_outside_declared_roots:{path}")
        manifests.append({"path": str(path), "sha256": record["sha256"],
                          "package": package, "workspace": workspace,
                          "profile_tables": data.get("profile", {})})
    return sorted(set(blockers)), manifests


def _resolve(metadata, selection, roots):
    if not isinstance(metadata, dict) or metadata.get("version") != 1:
        raise ValueError("expected Cargo metadata format version 1")
    packages = metadata.get("packages")
    resolve = metadata.get("resolve")
    if not isinstance(packages, list) or not isinstance(resolve, dict) or not isinstance(resolve.get("nodes"), list):
        raise ValueError("complete Cargo dependency resolution is required; --no-deps is not accepted")
    package_map, node_map, blockers = {}, {}, []
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("id"), str) or package["id"] in package_map:
            raise ValueError("malformed/duplicate package identity")
        package_map[package["id"]] = package
    for node in resolve["nodes"]:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str) or node["id"] in node_map:
            raise ValueError("malformed/duplicate resolved node identity")
        node_map[node["id"]] = node
    matches = [x for x in packages if x.get("name") == selection["package"]]
    if len(matches) != 1:
        raise ValueError("package selection is missing or ambiguous")
    selected = matches[0]
    targets = [x for x in selected.get("targets", []) if isinstance(x, dict) and
               any(k in x.get("kind", []) for k in ("lib", "rlib", "cdylib", "staticlib")) and
               (not selection.get("target_name") or x.get("name") == selection["target_name"])]
    if len(targets) != 1:
        raise ValueError("library target selection is missing or ambiguous")
    selected_target = targets[0]
    closure, pending = {}, [selected["id"]]
    while pending:
        identity = pending.pop()
        if identity in closure:
            continue
        if identity not in package_map or identity not in node_map:
            raise ValueError("resolved dependency is missing package or node")
        package, node = package_map[identity], node_map[identity]
        manifest = _path(package.get("manifest_path", ""), directory=False)
        if not any(_under(manifest, x) for x in roots):
            raise ValueError("resolved manifest outside declared owned input roots")
        if package.get("source") is not None:
            blockers.append(f"resolved_nonlocal_package:{identity}")
        if package.get("links"):
            blockers.append(f"resolved_native_links:{identity}")
        for target in package.get("targets", []):
            kinds = target.get("kind", [])
            if "custom-build" in kinds or "proc-macro" in kinds:
                blockers.append(f"resolved_build_hook:{identity}")
            source = _path(target.get("src_path", ""), directory=False)
            if not any(_under(source, x) for x in roots):
                raise ValueError("resolved crate root outside declared input roots")
        deps, features = node.get("deps"), node.get("features")
        if not isinstance(deps, list) or not isinstance(features, list) or any(not isinstance(x, str) for x in features):
            raise ValueError("malformed resolved dependencies/features")
        for dep in deps:
            if not isinstance(dep, dict) or not isinstance(dep.get("pkg"), str) or not isinstance(dep.get("dep_kinds"), list):
                raise ValueError("malformed resolved dependency edge")
            if any(x.get("kind") == "build" for x in dep["dep_kinds"]):
                blockers.append(f"resolved_build_dependency:{identity}")
            pending.append(dep["pkg"])
        closure[identity] = {"package": package, "node": node}
    workspace_root = _path(metadata.get("workspace_root", ""), directory=True)
    if not any(_under(workspace_root, x) for x in roots):
        raise ValueError("Cargo workspace root is not an inventoried owned root")
    lock = workspace_root / "Cargo.lock"
    if not lock.is_file():
        raise ValueError("Cargo.lock is required; planning does not create it")
    return {"selected_package_id": selected["id"], "selected_target": selected_target,
            "workspace_root": str(workspace_root), "workspace_members": metadata.get("workspace_members", []),
            "closure": [closure[x] for x in sorted(closure)],
            "resolution_scope": "Cargo metadata graph, including recorded dev/target kinds; not effective rustc build units",
            "profile_resolution": "pending_actual_build_recipe"}, sorted(set(blockers))


def _clean(result):
    cleanup = result.get("cleanup", {})
    return (type(result.get("returncode")) is int and result["returncode"] == 0 and
            result.get("timed_out") is False and result.get("cancelled") is False and
            not result.get("error") and not result.get("post_cleanup_wait_error") and
            type(result.get("pid")) is int and result["pid"] > 0 and
            cleanup.get("method") == "windows_job" and cleanup.get("status") == "assigned_job_empty" and
            cleanup.get("job_assigned") is True and type(cleanup.get("active_after")) is int and cleanup["active_after"] == 0 and
            type(cleanup.get("parent_pid")) is int and cleanup["parent_pid"] == result["pid"] and
            cleanup.get("parent_exit_confirmed") is True and cleanup.get("job_handle_closed") is True and
            not any(value for key, value in cleanup.items() if "error" in key))


def _metadata_argv(tools, manifest, selection):
    argv = [tools["selection"]["cargo"], "metadata", "--offline", "--locked", "--format-version", "1",
            "--manifest-path", str(manifest), "--filter-platform", TARGET]
    if selection["features"]:
        argv += ["--features", ",".join(selection["package"] + "/" + x for x in selection["features"])]
    if not selection["default_features"]:
        argv.append("--no-default-features")
    return argv


def _overrides(tools, out):
    return {"RUSTC": tools["selection"]["rustc"], "CARGO_NET_OFFLINE": "true",
            "CARGO_TARGET_DIR": str(out / "cargo-target-unused"), "CARGO_TERM_COLOR": "never",
            "CARGO_HOME": str(out / "cargo-home"), "USERPROFILE": str(out / "user-profile"),
            "HOME": str(out / "user-profile"),
            "APPDATA": str(out / "user-profile" / "AppData" / "Roaming"),
            "LOCALAPPDATA": str(out / "user-profile" / "AppData" / "Local"),
            "TEMP": str(out / "temp"), "TMP": str(out / "temp")}


def _private_environment_directories(out):
    return (out / "cargo-home", out / "temp", out / "user-profile",
            out / "user-profile" / "AppData", out / "user-profile" / "AppData" / "Roaming",
            out / "user-profile" / "AppData" / "Local")


def _capture_execution(out, result):
    return {kind: _file(out / f"cargo-metadata.{suffix}") for kind, suffix in
            (("stdout", "stdout.log"), ("stderr", "stderr.log"), ("process_record", "process.json"))}


def _write(path, value):
    with path.open("xb") as handle:
        handle.write(json.dumps(value, indent=2, sort_keys=True).encode() + b"\n")


def inspect_project(project_path, *, workspace_root, toolchain, output_dir,
                    env=None, runner: Callable | None = None, timeout=60):
    """Create one metadata-backed plan. No Cargo build/rustc command is exposed.

    `runner` is an injection seam for tests, never project JSON. The trusted caller
    must hold the existing controller lease. Only output_dir is written here.
    Returned `inspection` is deterministic; execution paths/PID/time stay in
    `metadata_evidence`, not a ProjectService equality comparison.
    """
    workspace = _path(workspace_root, directory=True)
    stop = workspace / ".runs" / "defense-loop" / "STOP"
    if stop.exists():
        raise ValueError("STOP is set; no metadata process started")
    if type(timeout) not in (int, float) or not 0 < timeout <= 120:
        raise ValueError("metadata timeout must be between 0 and 120 seconds")
    environment_source = os.environ if env is None else env
    path, project, manifest, roots = _read_project(Path(project_path), workspace)
    out = _owned(Path(output_dir), workspace, must_exist=False)
    if out.exists() or not _under(out, workspace / ".runs") or any(_under(out, x) or _under(x, out) for x in roots):
        raise ValueError("metadata output must be a fresh private .runs directory outside all inputs")
    snapshot, tools = _inventory(roots, owned_workspace=workspace), _toolchain(toolchain)
    env, environment_policy, host_environment, env_blockers = _metadata_environment(environment_source, tools)
    config, cfg_blockers = _configuration(manifest.parent, env)
    discovery, discovery_blockers = _workspace_discovery(manifest.parent, roots)
    blockers, tables = _preflight(snapshot, roots, env, tools)
    blockers += cfg_blockers + discovery_blockers + env_blockers
    # Cargo may discover a parent workspace; require a pre-existing owned lock
    # before starting, then bind its exact resolved workspace path after metadata.
    locks = [x for x in snapshot["files"] if Path(x["path"]).name == "Cargo.lock"]
    if not locks:
        blockers.append("Cargo.lock_required_no_generation")
    selection = dict(project["rust_cargo"])
    selection["features"] = sorted(selection["features"])
    semantic = {"schema_version": 1, "backend": "rust_cargo_native", "project_path": str(path),
                "workspace_root": str(workspace), "project": project, "selection": selection,
                "input_snapshot": snapshot, "toolchain": tools, "configuration": config,
                "workspace_discovery": discovery,
                "planner_inputs": [_file(Path(__file__).resolve())],
                "environment": environment_policy, "manifest_semantic_inputs": tables,
                "implementation": {"inspection": "metadata_only", "build": "not_implemented",
                    "original_reference": "not_implemented", "derivative": "not_implemented",
                    "protection": "not_applied", "functional_validation": "not_performed"},
                "recipe_handoff": {"original_recipe": None, "derivative_recipe": None,
                    "crate_units": None, "required_unit_fields": ["package_id", "crate_identity", "source_root",
                    "original_recipe", "ir_recipe", "rlib", "llvm_ir", "dep_info", "extern_edges"]},
                "limitations": ["Root inventory is preflight ownership, not proof of consumed Rust include!/env!/module closure.",
                    "Actual dep-info and consumed source/system/native library closure gates are not implemented.",
                    "Cargo metadata features/profile are not a complete Cargo build-unit/rustc recipe.",
                    "No compilation, original-reference linking, VM transformation, target execution or protection assessment.",
                    "Cargo internal cache/lock bookkeeping is not an OS-isolated read-only filesystem guarantee.",
                    "Metadata uses isolated job-local homes/temp and rejects discovered Cargo configs or unsupported Cargo/Rust environment overrides; not an equivalent original-build environment.",
                    "Input/tool/config hashing is not an OS sandbox or fully hermetic compiler execution."]}
    out.mkdir()
    evidence = None
    if blockers:
        semantic.update(status="blocked", blockers=sorted(set(blockers)), resolution=None)
    else:
        argv = _metadata_argv(tools, manifest, selection)
        execution_env = {**host_environment, **_overrides(tools, out)}
        for directory in _private_environment_directories(out):
            _path(directory, must_exist=False)
            directory.mkdir()
        if runner is None:
            from antirea.process import run_logged
            runner = run_logged
        if stop.exists():
            raise ValueError("STOP is set before metadata launch")
        result = runner(argv, manifest.parent, out / "cargo-metadata", timeout=timeout,
                        env=execution_env, cancel_file=stop)
        evidence = {"argv": argv, "cwd": str(manifest.parent), "process": result,
                    "environment_overrides": _overrides(tools, out),
                    "execution_environment": _environment(execution_env),
                    "files": _capture_execution(out, result),
                    "overrides_scope": "metadata query only; these are not a future original build recipe"}
        unchanged = (_inventory(roots, owned_workspace=workspace) == snapshot and _toolchain(toolchain) == tools and
                     _configuration(manifest.parent, env)[0] == config and
                     _workspace_discovery(manifest.parent, roots)[0] == discovery and
                     _metadata_environment(environment_source, tools)[1] == semantic["environment"] and
                     [_file(Path(x["path"])) for x in semantic["planner_inputs"]] == semantic["planner_inputs"])
        evidence["stop_observed_after_process"] = stop.exists()
        if not unchanged:
            semantic.update(status="inputs_changed", blockers=["input/tool/config changed during metadata"], resolution=None)
        elif stop.exists() or result.get("cancelled"):
            semantic.update(status="cancelled", blockers=["metadata cancelled"], resolution=None)
        elif not _clean(result):
            semantic.update(status="metadata_failed", blockers=["metadata process failed or owned cleanup unverified"], resolution=None)
        else:
            raw_path = out / "cargo-metadata.stdout.log"
            raw = raw_path.read_bytes()
            if len(raw) > 32 * 1024 * 1024:
                raise ValueError("metadata output limit exceeded")
            resolution, blockers = _resolve(_json(raw), selection, roots)
            semantic.update(status="blocked" if blockers else "inspected_build_not_implemented",
                            blockers=blockers, resolution=resolution)
            evidence["metadata"] = _file(raw_path)
    semantic["fingerprint"] = _hash(semantic)
    plan = {"inspection": semantic, "metadata_evidence": evidence}
    _write(out / "plan.json", plan)
    return plan


def verify_plan(plan, *, plan_path, workspace_root, toolchain, env=None):
    """No subprocess. The caller supplies the trusted actual plan.json location.

    A success record without the exact same-job process/stdout/stderr evidence is
    invalid. This verifies recorded evidence, not an OS-attested process history;
    production integration must pin this engine and the plan artifact itself.
    """
    workspace = _path(workspace_root, directory=True)
    plan_path = _owned(Path(plan_path), workspace, directory=False)
    if plan_path.name != "plan.json" or not _under(plan_path, workspace / ".runs"):
        raise ValueError("trusted plan_path must name the private job's plan.json")
    if _json(plan_path.read_bytes()) != plan:
        raise ValueError("plan object differs from trusted plan_path")
    semantic = plan["inspection"]
    check = dict(semantic)
    fingerprint = check.pop("fingerprint")
    if _hash(check) != fingerprint:
        raise ValueError("plan fingerprint mismatch")
    if str(workspace) != semantic["workspace_root"]:
        raise ValueError("workspace identity changed")
    if (workspace / ".runs" / "defense-loop" / "STOP").exists():
        raise ValueError("STOP is set")
    env, policy, host_environment, env_blockers = _metadata_environment(
        os.environ if env is None else env, semantic["toolchain"])
    _, project, manifest, roots = _read_project(Path(semantic["project_path"]), workspace)
    out = plan_path.parent
    if any(_under(out, x) or _under(x, out) for x in roots):
        raise ValueError("plan evidence directory overlaps source inputs")
    if project != semantic["project"] or _inventory(roots, owned_workspace=workspace) != semantic["input_snapshot"]:
        raise ValueError("source/project inventory changed")
    if _toolchain(toolchain) != semantic["toolchain"]:
        raise ValueError("compiler/sysroot changed")
    if [_file(Path(x["path"])) for x in semantic["planner_inputs"]] != semantic["planner_inputs"]:
        raise ValueError("planner implementation changed")
    if _configuration(manifest.parent, env)[0] != semantic["configuration"] or policy != semantic["environment"]:
        raise ValueError("configuration/environment changed")
    if _workspace_discovery(manifest.parent, roots)[0] != semantic["workspace_discovery"]:
        raise ValueError("ancestor workspace discovery changed")
    evidence = plan.get("metadata_evidence")
    status = semantic.get("status")
    if status not in {"inspected_build_not_implemented", "blocked", "metadata_failed", "cancelled", "inputs_changed"}:
        raise ValueError("unknown inspection status")
    if status == "blocked" and semantic.get("resolution") is None:
        # Only preflight-blocked inspections have no query evidence. Recompute
        # their concrete blockers instead of accepting an arbitrary status label.
        blockers, _ = _preflight(semantic["input_snapshot"], roots, env, semantic["toolchain"])
        blockers += _configuration(manifest.parent, env)[1] + _workspace_discovery(manifest.parent, roots)[1] + env_blockers
        if not any(Path(x["path"]).name == "Cargo.lock" for x in semantic["input_snapshot"]["files"]):
            blockers.append("Cargo.lock_required_no_generation")
        if evidence is not None or not blockers or sorted(set(blockers)) != semantic.get("blockers"):
            raise ValueError("preflight-blocked evidence contract mismatch")
    else:
        if not isinstance(evidence, dict):
            raise ValueError("metadata execution evidence is required")
        if type(evidence.get("stop_observed_after_process")) is not bool:
            raise ValueError("metadata STOP observation is required")
        expected = _metadata_argv(semantic["toolchain"], manifest, semantic["selection"])
        if evidence.get("argv") != expected or evidence.get("cwd") != str(manifest.parent) or evidence.get("environment_overrides") != _overrides(semantic["toolchain"], out):
            raise ValueError("metadata fixed argv/cwd/tool/environment evidence mismatch")
        execution_env = {**host_environment, **_overrides(semantic["toolchain"], out)}
        if evidence.get("execution_environment") != _environment(execution_env):
            raise ValueError("metadata execution environment receipt mismatch")
        for directory in _private_environment_directories(out):
            _owned(directory, workspace, directory=True)
        result = evidence.get("process")
        if not isinstance(result, dict):
            raise ValueError("metadata process record is required")
        actual_files = _capture_execution(out, result)
        if evidence.get("files") != actual_files:
            raise ValueError("metadata execution files changed or belong to another job")
        if _canonical(_json(Path(actual_files["process_record"]["path"]).read_bytes())) != _canonical(result):
            raise ValueError("metadata process record does not match hash-bound file")
        if (result.get("argv") != expected or result.get("stdout") != str(out / "cargo-metadata.stdout.log") or
                result.get("stderr") != str(out / "cargo-metadata.stderr.log")):
            raise ValueError("metadata process argv/output path mismatch")
        if status in {"inspected_build_not_implemented", "blocked"}:
            if not _clean(result) or evidence["stop_observed_after_process"]:
                raise ValueError("successful metadata requires verified owned cleanup")
            if evidence.get("metadata") != actual_files["stdout"]:
                raise ValueError("metadata raw stdout descriptor is required and must match")
            raw = Path(actual_files["stdout"]["path"]).read_bytes()
            if len(raw) > 32 * 1024 * 1024:
                raise ValueError("metadata output limit exceeded")
            resolution, blockers = _resolve(_json(raw), semantic["selection"], roots)
            if resolution != semantic["resolution"] or blockers != semantic["blockers"]:
                raise ValueError("resolved metadata does not match plan")
            if (status == "blocked") != bool(blockers):
                raise ValueError("metadata status disagrees with resolved blockers")
        elif status == "metadata_failed" and (_clean(result) or semantic.get("resolution") is not None):
            raise ValueError("failed metadata status disagrees with process record")
        elif status == "cancelled" and result.get("cancelled") is not True and not evidence["stop_observed_after_process"]:
            raise ValueError("cancelled metadata lacks process cancellation evidence")
    return {"status": "unchanged", "fingerprint": fingerprint,
            "inspection_status": status,
            "metadata_succeeded": status == "inspected_build_not_implemented",
            "build_implemented": False, "consumed_dependency_closure_verified": False}
