"""Pure binding of recorded Cargo artifacts and declared source dependencies.

No filesystem reads, writes, target imports, or child processes occur here.
The trusted caller supplies complete observations under its own pinned,
no-link, stability and process-cleanup gates. Metadata packages are possible
identities, not a claim that every metadata node was compiled.

This bounded Windows x64 collector is not a Cargo builder, native linker,
semantic-equivalence validator, source sandbox, or protection-effectiveness
measurement.
"""
from __future__ import annotations

import hashlib
import json
import ntpath
import re

from . import rust_cargo_units as cargo_units

HEX = re.compile(r"[0-9a-f]{64}\Z")
ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")
MAX_BYTES = 16 * 1024 * 1024
MAX_ITEMS = 100_000
TARGET = "x86_64-pc-windows-msvc"


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _json(raw):
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_BYTES:
        raise ValueError("missing/oversized private JSON evidence")

    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError("duplicate JSON key")
            out[key] = value
        return out

    def invalid(_):
        raise ValueError("nonfinite JSON value")

    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid)


def _path(value, cwd=None):
    """Windows lexical identity only; this is NOT a reparse/hardlink check."""
    if not isinstance(value, str) or not value or any(ord(ch) < 32 for ch in value):
        raise ValueError("invalid path text")
    value = value.replace("/", "\\")
    if value.startswith("\\") or ".." in value.split("\\"):
        raise ValueError("UNC/device/root-relative/traversal path unsupported")
    if not ntpath.isabs(value):
        if cwd is None or ntpath.splitdrive(value)[0]:
            raise ValueError("absolute drive path required")
        value = ntpath.join(cwd, value)
    drive, tail = ntpath.splitdrive(value)
    if not re.fullmatch(r"[A-Za-z]:", drive) or not tail.startswith("\\") or ":" in tail:
        raise ValueError("drive/device/alternate-stream path unsupported")
    for part in tail.split("\\"):
        if part and (part.endswith((".", " ")) or re.fullmatch(r"(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part)):
            raise ValueError("ambiguous Windows filename")
    return ntpath.normpath(value).casefold()


def _inside(path, root):
    return path == root or path.startswith(root + "\\")


def _hash_map(values):
    if not isinstance(values, dict) or len(values) > MAX_ITEMS:
        raise ValueError("invalid bounded snapshot")
    result = {}
    for path, digest in values.items():
        key = _path(path)
        if key in result or not isinstance(digest, str) or not HEX.fullmatch(digest):
            raise ValueError("ambiguous snapshot identity/hash")
        result[key] = digest
    return result


def _observations(values):
    if not isinstance(values, dict) or len(values) > MAX_ITEMS:
        raise ValueError("invalid bounded observations")
    result = {}
    for path, item in values.items():
        key = _path(path)
        if (key in result or not isinstance(item, dict) or
                not isinstance(item.get("sha256"), str) or not HEX.fullmatch(item["sha256"]) or
                type(item.get("bytes")) is not int or item["bytes"] < 0):
            raise ValueError("invalid observed file")
        result[key] = {"sha256": item["sha256"], "bytes": item["bytes"]}
    return result


def _env_value(value):
    # rustc's dep-info environment comments escape LF, CR and backslash. Keep
    # this grammar deliberately narrow until an actual Cargo capture confirms
    # it; unknown escapes are rejected, never guessed or exposed in errors.
    out = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\":
            index += 1
            if index == len(value) or value[index] not in {"\\", "n", "r"}:
                raise ValueError("unsupported env-dep escape")
            char = {"\\": "\\", "n": "\n", "r": "\r"}[value[index]]
        out.append(char)
        index += 1
    return "".join(out)


def _rule_tokens(line):
    """Tokenize a narrow rustc Make-rule dialect, preserving Windows slashes.

    A colon immediately after one drive letter and before slash is path data.
    Backslash before whitespace/#/colon is a Make escape; before ordinary path
    characters it stays a Windows separator. UNC/doubled-backslash ambiguity
    and single-dollar Make expansion are deliberately unsupported.
    """
    left, right, token = [], [], []
    separator = False
    index = 0

    def emit():
        if token:
            (right if separator else left).append("".join(token))
            token.clear()

    while index < len(line):
        ch = line[index]
        if ch == "\\":
            if index + 1 == len(line):
                raise ValueError("dangling dep-info escape")
            following = line[index + 1]
            if following in " \t#:":
                token.append(following)
                index += 2
                continue
            if following == "\\":
                raise ValueError("ambiguous doubled backslash in dep-info path")
            token.append(ch)
        elif ch == "$":
            if index + 1 == len(line) or line[index + 1] != "$":
                raise ValueError("Make variable expansion unsupported")
            token.append("$")
            index += 2
            continue
        elif ch == ":":
            drive = len(token) == 1 and token[0].isascii() and token[0].isalpha() and index + 1 < len(line) and line[index + 1] in "\\/"
            if drive:
                token.append(ch)
            elif not separator:
                emit()
                separator = True
            else:
                raise ValueError("unexpected dep-info colon")
        elif ch in " \t":
            emit()
        elif ch == "#":
            raise ValueError("unescaped dep-info comment/path hash")
        else:
            token.append(ch)
        index += 1
    emit()
    if not separator or not left:
        raise ValueError("malformed dep-info rule")
    return {"targets": left, "dependencies": right}


def parse_dep_info(raw_bytes):
    """Return declared rules and hashed environment claims, never env values."""
    if not isinstance(raw_bytes, bytes) or not raw_bytes or len(raw_bytes) > MAX_BYTES:
        raise ValueError("missing/oversized dep-info")
    body = raw_bytes.decode("utf-8")
    if "\x00" in body or any(ord(ch) < 32 and ch not in "\n\r\t" for ch in body):
        raise ValueError("binary/control bytes in dep-info")
    body = body.replace("\r\n", "\n")
    if "\r" in body:
        raise ValueError("bare CR in dep-info")
    rules, environments = [], {}
    pending = ""
    for physical in body.split("\n"):
        if not pending and physical.startswith("# env-dep:"):
            entry = physical[len("# env-dep:"):]
            name, present, value = entry.partition("=")
            if not ENV_NAME.fullmatch(name) or name.upper() in environments:
                raise ValueError("invalid/duplicate env-dep name")
            environments[name.upper()] = {"name": name, "present": bool(present),
                "value_sha256": _sha(_env_value(value).encode("utf-8")) if present else None}
            continue
        if physical.endswith("\\"):
            # Multiple trailing slashes have ambiguous path/continuation intent.
            if physical.endswith("\\\\"):
                raise ValueError("ambiguous dep-info continuation")
            pending += physical[:-1] + " "
            continue
        logical, pending = pending + physical, ""
        if not logical.strip():
            continue
        rules.append(_rule_tokens(logical))
        if len(rules) > MAX_ITEMS:
            raise ValueError("too many dep-info rules")
    if pending or not rules:
        raise ValueError("unfinished/empty dep-info")
    return {"schema_version": 1, "raw_sha256": _sha(raw_bytes), "bytes": len(raw_bytes),
            "rules": rules, "env_dependencies": environments,
            "meaning": "compiler-declared dependencies, not an OS file-read trace"}


def _cargo_messages(raw):
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_BYTES:
        raise ValueError("missing/oversized Cargo JSONL")
    artifacts, finished = [], False
    for line in raw.splitlines():
        if not line.strip():
            continue
        record = _json(line)
        if not isinstance(record, dict) or finished:
            raise ValueError("Cargo message after completion/invalid message")
        reason = record.get("reason")
        if reason == "build-finished":
            if record.get("success") is not True:
                raise ValueError("Cargo build did not succeed")
            finished = True
        elif reason == "compiler-artifact":
            if record.get("fresh") is not False or record.get("executable") is not None:
                raise ValueError("cache/no-op/executable artifact is not captured library compilation")
            artifacts.append(record)
        elif reason == "compiler-message":
            if not isinstance(record.get("message"), dict) or record["message"].get("level") in {"error", "failure-note"}:
                raise ValueError("Cargo compiler error message")
        else:
            raise ValueError("unsupported Cargo message/build hook")
    if not finished or not artifacts or len(artifacts) > 4096:
        raise ValueError("Cargo completion/artifact evidence missing")
    return artifacts


def _package_target(artifact, packages):
    matches = [item for item in packages if item.get("id") == artifact.get("package_id")]
    if len(matches) != 1:
        raise ValueError("Cargo artifact package not in exact inspected local graph")
    package = matches[0]
    target = artifact.get("target")
    if not isinstance(target, dict):
        raise ValueError("Cargo target identity missing")
    fields = ("name", "kind", "crate_types", "src_path", "edition")

    def equal(candidate):
        return all(_path(candidate[key]) == _path(target[key]) if key == "src_path" else candidate.get(key) == target.get(key) for key in fields)

    if sum(equal(candidate) for candidate in package.get("targets", [])) != 1:
        raise ValueError("Cargo target differs from inspected metadata")
    if artifact.get("manifest_path") is not None and _path(artifact["manifest_path"]) != _path(package["manifest_path"]):
        raise ValueError("Cargo manifest identity differs")
    if not isinstance(target.get("crate_types"), list) or not target["crate_types"] or set(target["crate_types"]) - {"lib", "rlib", "cdylib", "staticlib"}:
        raise ValueError("unsupported Cargo target kind")
    return package, target


def _transitive_dependencies(units):
    """Exact captured extern-producer DAG closure; never infer metadata units."""
    by_id = {unit["unit"]: unit for unit in units}
    if len(by_id) != len(units):
        raise ValueError("duplicate dependency owner")
    edges = {key: sorted({edge["producer_unit"] for edge in unit["externs"]}) for key, unit in by_id.items()}
    if any(producer not in by_id for producers in edges.values() for producer in producers):
        raise ValueError("dependency producer outside captured graph")
    states, closure = {}, {}
    for root in by_id:
        stack = [(root, False)]
        while stack:
            key, leaving = stack.pop()
            if leaving:
                dependencies, included = {}, {key}
                rows = list(by_id[key]["declared_dependencies"])
                for producer in edges[key]:
                    included.update(closure[producer]["units"])
                    rows.extend(closure[producer]["dependencies"])
                for row in rows:
                    previous = dependencies.get(row["path"])
                    if previous is not None and previous != row:
                        raise ValueError("conflicting transitive dependency identity/hash")
                    dependencies[row["path"]] = row
                if len(dependencies) > MAX_ITEMS:
                    raise ValueError("transitive dependency set exceeds bound")
                closure[key] = {"units": sorted(included),
                    "dependencies": [dependencies[path] for path in sorted(dependencies)]}
                states[key] = 2
                continue
            if states.get(key) == 2:
                continue
            if states.get(key) == 1:
                raise ValueError("cycle in captured extern-producer graph")
            states[key] = 1
            stack.append((key, True))
            for producer in reversed(edges[key]):
                if states.get(producer) != 2:
                    stack.append((producer, False))
    return closure


def _aggregate_dep_info(raw_deps, units, observations):
    """Classify extra Cargo-published .d files, not rustc per-unit dep-info."""
    closure = _transitive_dependencies(units)  # Reject cycles even without aggregates.
    unit_dep_files = {unit["dep_info"]["path"] for unit in units}
    candidates = {}
    for unit in units:
        for output in unit["outputs"]:
            published = output["path"]
            if published.endswith((".dll", ".rlib")) and output["declared_output"] is not None:
                aggregate = ntpath.splitext(published)[0] + ".d"
                candidates.setdefault(aggregate, []).append((unit["unit"], output))
    evidence = []
    for path in sorted(set(raw_deps) - unit_dep_files):
        owners = candidates.get(path, [])
        if len(owners) != 1:
            raise ValueError("unexplained dep-info files or ambiguous published aggregate owner")
        owner, output = owners[0]
        parsed = raw_deps[path]
        if parsed["env_dependencies"] or len(parsed["rules"]) != 1:
            raise ValueError("aggregate dep-info must have one rule, no env-dep or phony rules")
        rule = parsed["rules"][0]
        if len(rule["targets"]) != 1 or _path(rule["targets"][0]) != output["path"] or not rule["dependencies"]:
            raise ValueError("aggregate target is not its exact published primary output")
        actual = [_path(item) for item in rule["dependencies"]]
        expected = {item["path"] for item in closure[owner]["dependencies"]}
        if len(set(actual)) != len(actual) or set(actual) != expected:
            raise ValueError("aggregate dependencies differ from exact transitive declared-source union")
        evidence.append({"classification": "cargo_published_aggregate_dep_info", "path": path,
            **observations[path], "owner_unit": owner,
            "published_output": {key: output[key] for key in ("path", "sha256", "bytes")},
            "transitive_units": closure[owner]["units"], "declared_dependencies": closure[owner]["dependencies"],
            "meaning": "Cargo aggregate declaration matched to captured extern DAG; not an OS file-read trace"})
    if unit_dep_files | {item["path"] for item in evidence} != set(raw_deps):
        raise ValueError("unaccounted dep-info declaration")
    return evidence


def collect_cargo_artifacts(unit_records, cargo_jsonl_bytes, *, arm, source_snapshot,
                            compiler_snapshot, packages, observed_files, dep_info_contents):
    """Bind one arm's actual units/artifacts and declared source dependencies.

    unit_records: [{unit: str, start_bytes: bytes, finish_bytes: bytes}].
    Source/compiler snapshots map absolute path to pre-build SHA-256.
    observed_files maps absolute path to {sha256, bytes}, read after the Job.
    dep_info_contents maps absolute path to the private raw .d bytes. `arm` is
    the exact trusted plan_invocations()['arms'][mode] object. All observations
    need an independently pinned caller and no-link/stability/cleanup gates.
    """
    if not isinstance(unit_records, list) or not 1 <= len(unit_records) <= 4096:
        raise ValueError("invalid unit collection")
    if not isinstance(packages, list) or not packages or len(packages) > 4096 or any(not isinstance(item, dict) for item in packages):
        raise ValueError("invalid inspected package graph")
    policy = arm["policy"]
    root = _path(policy["target_root"])
    source = _hash_map(source_snapshot)
    compiler = _hash_map(compiler_snapshot)
    observed = _observations(observed_files)
    if set(source) & set(compiler):
        raise ValueError("source/compiler snapshot identity overlaps")
    for path, digest in {**source, **compiler}.items():
        if path not in observed or observed[path]["sha256"] != digest:
            raise ValueError("snapshot input missing/changed in post-build observations")
    raw_deps = {}
    if not isinstance(dep_info_contents, dict):
        raise ValueError("dep-info raw observations missing")
    for path, raw in dep_info_contents.items():
        key = _path(path)
        if key in raw_deps or not _inside(key, root) or not key.endswith(".d"):
            raise ValueError("ambiguous/unowned dep-info observation")
        parsed = parse_dep_info(raw)
        if observed.get(key) != {"sha256": parsed["raw_sha256"], "bytes": parsed["bytes"]}:
            raise ValueError("dep-info bytes/hash differ from file inventory")
        raw_deps[key] = parsed
    if set(raw_deps) != {path for path in observed if _inside(path, root) and path.endswith(".d")}:
        raise ValueError("observed dep-info inventory and supplied raw files differ")
    artifacts = _cargo_messages(cargo_jsonl_bytes)
    units, probes, ids = [], [], set()
    for bundle in unit_records:
        if not isinstance(bundle, dict) or not isinstance(bundle.get("unit"), str) or bundle["unit"] in ids:
            raise ValueError("missing/duplicate unit identity")
        ids.add(bundle["unit"])
        start, finish = _json(bundle["start_bytes"]), _json(bundle["finish_bytes"])
        if not isinstance(start, dict) or not isinstance(finish, dict):
            raise ValueError("invalid unit records")
        if (type(start.get("schema_version")) is not int or start["schema_version"] != 1 or
                type(finish.get("schema_version")) is not int or finish["schema_version"] != 1 or
                start.get("mode") != policy["mode"] or start.get("policy_sha256") != arm["policy_sha256"] or
                finish.get("start_sha256") != _sha(bundle["start_bytes"]) or
                type(finish.get("compiler_pid")) is not int or finish["compiler_pid"] <= 0 or
                type(finish.get("compiler_exit_code")) is not int or finish["compiler_exit_code"] != 0 or
                finish.get("succeeded") is not True or finish.get("cancelled") is not False or finish.get("changed_inputs") != []):
            raise ValueError("unit is incomplete/failed/changed/unbound")
        for kind in ("backend", "wrapper", "linker"):
            expected = {"path": policy[kind], "sha256": policy[kind + "_sha256"]}
            if start.get(kind) != expected or observed.get(_path(expected["path"]), {}).get("sha256") != expected["sha256"]:
                raise ValueError("recorded compiler/wrapper/linker identity missing or changed")
        args = start.get("original_argv")
        if not isinstance(args, list) or not args or args[0] != policy["backend"]:
            raise ValueError("unit compiler argv mismatch")
        derived = cargo_units.derive_recipe(args[1:], policy["mode"])
        if (start.get("forwarded_argv") != [policy["backend"], *derived["forwarded_argv"]] or
                start.get("changes") != derived["changes"] or start.get("kind") != derived["kind"]):
            raise ValueError("unit original/forwarded argv rewrite mismatch")
        parsed = cargo_units.parse_rustc_args(args[1:])
        cargo_units.validate_linker_args(parsed, policy)
        env = start.get("environment_value_sha256")
        if (start.get("environment_digest_format") != "uppercase-names-sorted-utf8-json-v1" or
                not isinstance(start.get("environment_sha256"), str) or not HEX.fullmatch(start["environment_sha256"]) or
                not isinstance(env, dict) or any(not isinstance(k, str) or k != k.upper() or not isinstance(v, str) or not HEX.fullmatch(v) for k, v in env.items())):
            raise ValueError("unit environment hashes missing/malformed")
        controls = {key: arm["environment_overrides"][key] for key in ("CARGO_TARGET_DIR", "ANTIREA_RUST_UNIT_POLICY", "RUSTC", "RUSTC_WRAPPER")}
        if start.get("control_environment") != controls or any(env.get(k) != _sha(v.encode()) for k, v in controls.items()):
            raise ValueError("unit environment controls mismatch")
        # Shared pure validator: only the recorder's two allowlisted raw
        # diagnostics may appear, and their present values must hash-match.
        # Do not copy those raw values into this collector's result.
        cargo_units.validate_diagnostic_environment(start)
        consumed = _hash_map(start.get("consumed_inputs"))
        for path, digest in consumed.items():
            if observed.get(path, {}).get("sha256") != digest:
                raise ValueError("unit consumed input missing/changed")
        if derived["kind"] == "probe":
            if consumed:
                raise ValueError("probe unexpectedly claims source inputs")
            probes.append(bundle["unit"])
            continue
        forwarded = cargo_units.parse_rustc_args(derived["forwarded_argv"])
        values = parsed["values"]
        if values.get("--target") != [TARGET]:
            raise ValueError("unsupported target")
        cwd = _path(start["cwd"])
        source_path = _path(parsed["positionals"][0], cwd)
        if source_path not in source or consumed.get(source_path) != source[source_path]:
            raise ValueError("root source not hash-bound to inspected input snapshot")
        out_dir = _path(values["--out-dir"][0])
        if not _inside(out_dir, root):
            raise ValueError("unit output outside trusted arm")
        for explicit in values.get("--sysroot", []):
            if _path(explicit) != _path(policy["sysroot"]):
                raise ValueError("explicit sysroot differs from pinned compiler")
        name = values["--crate-name"][0]
        types = [kind for value in values["--crate-type"] for kind in value.split(",")]
        extras = [value.split("=", 1)[1] for value in values.get("-C", []) if value.startswith("extra-filename=")]
        if len(extras) > 1:
            raise ValueError("ambiguous output extra-filename")
        stem = name + (extras[0] if extras else "")
        dep_path = _path(stem + ".d", out_dir)
        if dep_path not in raw_deps:
            raise ValueError("unit's exact dep-info file missing")
        dependency = raw_deps[dep_path]
        targets, declarations, phony = set(), None, set()
        for rule in dependency["rules"]:
            lhs = [_path(path, cwd) for path in rule["targets"]]
            rhs = {_path(path, cwd) for path in rule["dependencies"]}
            if not rhs:
                phony.update(lhs)
                continue
            if any(not _inside(path, out_dir) for path in lhs) or targets.intersection(lhs):
                raise ValueError("dep-info output escape/duplicate declaration")
            targets.update(lhs)
            if declarations is not None and rhs != declarations:
                raise ValueError("dep-info outputs have inconsistent source dependencies")
            declarations = rhs
        if declarations is None or source_path not in declarations or dep_path not in targets or phony - declarations:
            raise ValueError("root/dep-info/phony dependency coverage inconsistent")
        declared = []
        for path in sorted(declarations):
            if path in source:
                classification, digest = "owned_source", source[path]
            elif path in compiler:
                classification, digest = "pinned_compiler_or_sysroot_file", compiler[path]
            else:
                raise ValueError("dep-info names an unpinned consumed file")
            declared.append({"path": path, "sha256": digest, "classification": classification})
        for key, entry in dependency["env_dependencies"].items():
            if entry["present"] and env.get(key) != entry["value_sha256"] or not entry["present"] and key in env:
                raise ValueError("env-dep claim does not match recorded environment hash")
        for path in targets:
            if path not in observed:
                raise ValueError("declared output missing from post-build inventory")
        llvm = "llvm-ir" in forwarded["values"]["--emit"][0].split(",")
        llvm_path = _path(stem + ".ll", out_dir)
        if llvm and (llvm_path not in targets or observed.get(llvm_path, {}).get("bytes", 0) <= 0):
            raise ValueError("forwarded LLVM IR emit has no exact hash-bound .ll output")
        externs = []
        for value in values.get("--extern", []):
            alias, separator, path = value.partition("=")
            path = _path(path) if separator else ""
            if not alias or not separator or not _inside(path, root) or not path.endswith((".rlib", ".rmeta")) or consumed.get(path) != observed.get(path, {}).get("sha256"):
                raise ValueError("extern is not a hash-bound own-arm artifact")
            externs.append({"alias": alias, "path": path, **observed[path]})
        if set(consumed) != {source_path, *(item["path"] for item in externs)}:
            raise ValueError("unexpected/missing recorded consumed-input identity")
        units.append({"unit": bundle["unit"], "start": start, "parsed": parsed, "source": source_path,
                      "name": name, "types": types, "targets": targets, "dep_info": dep_path,
                      "dep_info_sha256": dependency["raw_sha256"], "dependencies": declared,
                      "env_dependencies": dependency["env_dependencies"], "externs": externs,
                      "llvm_ir": {"path": llvm_path, **observed[llvm_path]} if llvm else None,
                      "start_sha256": _sha(bundle["start_bytes"]), "finish_sha256": _sha(bundle["finish_bytes"])})
    if not units or len(units) != len(artifacts):
        raise ValueError("actual crate/artifact counts differ; probes/metadata nodes are not build units")
    result, matched_units, output_owners = [], set(), {}
    for artifact in artifacts:
        package, target = _package_target(artifact, packages)
        candidates = [unit for unit in units if unit["source"] == _path(target["src_path"]) and
                      unit["name"] == target["name"].replace("-", "_") and unit["types"] == target["crate_types"] and
                      unit["start"].get("cargo_identity", {}).get("CARGO_PKG_NAME") == package.get("name") and
                      unit["start"].get("cargo_identity", {}).get("CARGO_PKG_VERSION") == package.get("version") and
                      _path(unit["start"].get("cargo_identity", {}).get("CARGO_MANIFEST_DIR", "")) == ntpath.dirname(_path(package["manifest_path"]))]
        if len(candidates) != 1 or candidates[0]["unit"] in matched_units:
            raise ValueError("artifact/unit identity is missing/ambiguous/reused")
        unit = candidates[0]
        matched_units.add(unit["unit"])
        identity = unit["start"]["cargo_identity"]
        if identity.get("CARGO_MANIFEST_PATH") is not None and _path(identity["CARGO_MANIFEST_PATH"]) != _path(package["manifest_path"]):
            raise ValueError("unit manifest identity differs")
        if unit["parsed"]["values"].get("--edition") != [target["edition"]]:
            raise ValueError("unit/Cargo/metadata edition differs")
        features = artifact.get("features")
        cfg_features = []
        for cfg in unit["parsed"]["values"].get("--cfg", []):
            if cfg.startswith("feature="):
                feature = _json(cfg[len("feature="):].encode())
                if not isinstance(feature, str):
                    raise ValueError("invalid feature cfg")
                cfg_features.append(feature)
        if not isinstance(features, list) or any(not isinstance(x, str) for x in features) or len(set(features)) != len(features) or set(features) != set(cfg_features):
            raise ValueError("Cargo artifact features differ from actual unit cfg")
        filenames = artifact.get("filenames")
        if not isinstance(filenames, list) or not filenames:
            raise ValueError("Cargo filenames missing")
        outputs, primary = [], 0
        for filename in filenames:
            path = _path(filename)
            if not _inside(path, root) or path not in observed or observed[path]["bytes"] <= 0 or path in output_owners:
                raise ValueError("Cargo output missing/empty/unowned/ambiguous")
            # Cargo may publish a copy/hardlink from deps/ to its parent. Bind
            # content+exact basename, never infer OS file identity from hashes.
            matches = [declared for declared in unit["targets"] if ntpath.basename(declared) == ntpath.basename(path) and observed[declared] == observed[path]]
            primary_kind = path.endswith((".rlib", ".rmeta", ".dll", ".lib", ".a")) and not path.endswith(".dll.lib")
            if primary_kind and len(matches) != 1:
                raise ValueError("primary Cargo artifact lacks exact declared-output content binding")
            if not primary_kind and not path.endswith((".pdb", ".dll.lib", ".dll.exp")):
                raise ValueError("unsupported auxiliary Cargo output")
            primary += int(primary_kind)
            output_owners[path] = unit["unit"]
            outputs.append({"path": path, **observed[path], "declared_output": matches[0] if len(matches) == 1 else None,
                            "binding": "dep-info path/content" if len(matches) == 1 else "Cargo auxiliary output only"})
        if not primary:
            raise ValueError("Cargo artifact has no primary library output")
        for path in unit["targets"]:
            if path in output_owners and output_owners[path] != unit["unit"]:
                raise ValueError("multiple units claim same output")
            output_owners[path] = unit["unit"]
        result.append({"unit": unit["unit"], "package_id": package["id"], "target_name": target["name"],
                       "source": unit["source"], "crate_types": unit["types"], "features": features,
                       "start_sha256": unit["start_sha256"], "finish_sha256": unit["finish_sha256"],
                       "dep_info": {"path": unit["dep_info"], "sha256": unit["dep_info_sha256"]},
                       "declared_dependencies": unit["dependencies"], "env_dependencies": unit["env_dependencies"],
                       "llvm_ir": unit["llvm_ir"], "outputs": outputs,
                       "declared_outputs": [{"path": path, **observed[path]} for path in sorted(unit["targets"])],
                       "externs": unit["externs"]})
    for unit in result:
        for extern in unit["externs"]:
            producer = output_owners.get(extern["path"])
            if producer is None or producer == unit["unit"]:
                raise ValueError("extern edge has no distinct captured local producer")
            extern["producer_unit"] = producer
    aggregates = _aggregate_dep_info(raw_deps, result, observed)
    return {"schema_version": 1, "status": "artifacts_bound_not_build_validated", "mode": policy["mode"],
            "cargo_jsonl_sha256": _sha(cargo_jsonl_bytes), "units": result, "probe_units": probes,
            "aggregate_dep_info": aggregates,
            "diagnostic_environment_binding": "allowlisted present values hash-checked; raw diagnostic values omitted from result",
            "actual_compiled_units": len(result), "metadata_nodes_required_to_compile": False,
            "declared_source_dependencies_bound": True, "os_file_read_trace": False,
            "full_sysroot_native_linker_closure": False, "outer_job_cleanup_verified": False,
            "filesystem_no_links_verified_by_this_pure_collector": False,
            "original_reference_validated": False, "protected_artifact_created": False,
            "limitations": ["Observations and tool/record producer authenticity require the trusted caller.",
                "dep-info is compiler-declared source dependency data, not all filesystem reads.",
                "Cargo auxiliary files are bound to JSON+hash, not fully explained native-link outputs.",
                "Content-bound published copies do not establish hardlink/file identity.",
                "Ambiguous repeated same-package/target units are rejected; no fabricated resolution.",
                "Only captured local library units on Windows x64 are supported.",
                "Environment dependency equality across arms requires a separate semantic gate."]}


