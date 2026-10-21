"""Pure source-observed environment handoff gate for bound Cargo units.

No filesystem/process/environment reads and no target imports. The trusted caller
must first authenticate the capture and collector inputs. A blocked handoff does
not undo a successful historical capture or artifact-binding status.
"""
from __future__ import annotations

import hashlib
import json
import ntpath
import re

HEX = re.compile(r"[0-9a-f]{64}\Z")
NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")
NORMALIZED_VARIABLES = frozenset({"PATH", "CARGO_MAKEFLAGS", "CARGO_TARGET_DIR", "ANTIREA_RUST_UNIT_POLICY"})
PASS = "declared_source_environment_dependencies_matched"
BLOCKED = "blocked_source_environment_handoff"
MAX_UNITS = 10000
MAX_DEPENDENCIES = 4096
MAX_TOTAL_DEPENDENCIES = 100000


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _path(value):
    if (not isinstance(value, str) or not re.fullmatch(r"[A-Za-z]:[\\/].*", value)
            or ":" in value[2:] or any(ord(ch) < 32 for ch in value)
            or any(part in {".", ".."} for part in value.replace("\\", "/").split("/"))):
        raise ValueError("noncanonical source/dep-info path")
    return ntpath.normcase(ntpath.normpath(value))


def _string(value, maximum=8192):
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or any(ord(ch) < 32 for ch in value):
        raise ValueError("missing or malformed unit identity")
    return value


def _hash(value):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise ValueError("missing or malformed evidence SHA256")
    return value


def _dependencies(value):
    if not isinstance(value, dict) or len(value) > MAX_DEPENDENCIES:
        raise ValueError("missing or excessive env-dependency map")
    result = {}
    for key, entry in value.items():
        if (not isinstance(key, str) or not NAME.fullmatch(key) or key != key.upper()
                or not isinstance(entry, dict) or set(entry) != {"name", "present", "value_sha256"}
                or not isinstance(entry.get("name"), str) or not NAME.fullmatch(entry["name"])
                or entry["name"].upper() != key or type(entry.get("present")) is not bool):
            raise ValueError("malformed environment dependency declaration")
        if entry["present"]:
            _hash(entry["value_sha256"])
        elif entry["value_sha256"] is not None:
            raise ValueError("absent environment value must have a null digest")
        result[key] = dict(entry)
    return result


def _units(arm, mode):
    if (not isinstance(arm, dict) or type(arm.get("schema_version")) is not int or arm["schema_version"] != 1
            or arm.get("mode") != mode or arm.get("status") != "artifacts_bound_not_build_validated"):
        raise ValueError("expected a bound original/derivative collector arm")
    units = arm.get("units")
    if (not isinstance(units, list) or not 1 <= len(units) <= MAX_UNITS
            or type(arm.get("actual_compiled_units")) is not int or arm["actual_compiled_units"] != len(units)):
        raise ValueError("nonempty exact actual compiled-unit count required")
    mapped, ids, total_dependencies = {}, set(), 0
    for unit in units:
        if not isinstance(unit, dict):
            raise ValueError("malformed compiled unit")
        unit_id = _string(unit.get("unit"), 512)
        key = (_string(unit.get("package_id")), _string(unit.get("target_name"), 512), _path(unit.get("source")))
        if key in mapped or unit_id in ids:
            raise ValueError("ambiguous repeated compiled-unit identity")
        ids.add(unit_id)
        types, features = unit.get("crate_types"), unit.get("features")
        if (not isinstance(types, list) or not types or len(types) > 16
                or any(not isinstance(value, str) or value not in {"lib", "rlib", "cdylib", "staticlib", "dylib"} for value in types)
                or len(set(types)) != len(types)
                or not isinstance(features, list) or len(features) > 4096
                or any(not isinstance(value, str) or not value or len(value) > 512 for value in features)
                or len(set(features)) != len(features)):
            raise ValueError("malformed crate kind or resolved features")
        dep_info = unit.get("dep_info")
        if not isinstance(dep_info, dict) or set(dep_info) != {"path", "sha256"}:
            raise ValueError("missing dep-info provenance")
        _path(dep_info["path"])
        _hash(dep_info["sha256"])
        dependencies = _dependencies(unit.get("env_dependencies"))
        total_dependencies += len(dependencies)
        if total_dependencies > MAX_TOTAL_DEPENDENCIES:
            raise ValueError("total env-dependency count exceeds bound")
        mapped[key] = {"unit": unit_id, "crate_types": list(types), "features": list(features),
            "start_sha256": _hash(unit.get("start_sha256")), "finish_sha256": _hash(unit.get("finish_sha256")),
            "dep_info": dict(dep_info), "env_dependencies": dependencies}
    return mapped


def check_consumed_environment(original, derivative):
    """Compare matched actual units' compiler-declared env! dependencies.

    Every declared variable is compared, not just the four currently recognized
    capture controls. No caller-controlled ignore list exists. 'Not declared' is
    distinct from option_env! explicitly observing absence. Malformed or ambiguous
    inputs raise ValueError; valid unequal records return a blocking result.
    """
    left, right = _units(original, "original"), _units(derivative, "derivative")
    inputs = {"original_collector_sha256": digest(original), "derivative_collector_sha256": digest(derivative)}
    result = {"schema_version": 1, "status": PASS, "handoff_allowed": True, "input_digests": inputs,
        "matched_units": [], "blockers": [], "declared_variable_comparisons": 0,
        "capture_status_reinterpreted": False, "artifact_binding_status_reinterpreted": False,
        "functional_equivalence": "not_evaluated", "full_environment_equivalence": False,
        "runtime_environment_access_covered": False, "vm_applied": False,
        "limitations": [
            "Pure comparison of authenticated compiler-declared env-dep records; caller owns all provenance and filesystem/process gates.",
            "Equal declarations or no declarations do not prove complete compile-time/runtime environment behavior.",
            "Capture/binder statuses remain unchanged; this is a separate gate before a semantic/protection handoff.",
        ]}
    if left.keys() != right.keys():
        result["blockers"].append({"reason": "actual_compiled_unit_sets_differ",
            "original_only": [list(key) for key in sorted(left.keys() - right.keys())],
            "derivative_only": [list(key) for key in sorted(right.keys() - left.keys())]})
    for key in sorted(left.keys() & right.keys()):
        a, b = left[key], right[key]
        identity = {"package_id": key[0], "target_name": key[1], "source": key[2]}
        unit_record = {"identity": identity, "original_unit": a["unit"], "derivative_unit": b["unit"],
            "original_evidence": {name: a[name] for name in ("start_sha256", "finish_sha256", "dep_info")},
            "derivative_evidence": {name: b[name] for name in ("start_sha256", "finish_sha256", "dep_info")},
            "declared_variables": [], "matched": True}
        if a["crate_types"] != b["crate_types"] or a["features"] != b["features"]:
            result["blockers"].append({"identity": identity, "reason": "crate_kind_or_resolved_features_differ"})
            unit_record["matched"] = False
        for name in sorted(a["env_dependencies"].keys() | b["env_dependencies"].keys()):
            first, second = a["env_dependencies"].get(name), b["env_dependencies"].get(name)
            item = {"name": name, "capture_normalized_control": name in NORMALIZED_VARIABLES,
                "original": {"declared": first is not None, **(first or {})},
                "derivative": {"declared": second is not None, **(second or {})}, "matched": first == second}
            unit_record["declared_variables"].append(item)
            result["declared_variable_comparisons"] += 1
            if first != second:
                if first is None or second is None:
                    reason = "source_environment_dependency_declarations_differ"
                elif first["present"] != second["present"]:
                    reason = "source_observed_environment_presence_differs"
                elif first["value_sha256"] != second["value_sha256"]:
                    reason = "source_observed_environment_value_differs"
                else:
                    reason = "source_environment_literal_name_differs"
                result["blockers"].append({"identity": identity, "name": name, "reason": reason,
                    "capture_normalized_control": name in NORMALIZED_VARIABLES})
                unit_record["matched"] = False
        result["matched_units"].append(unit_record)
    if result["blockers"]:
        result["status"], result["handoff_allowed"] = BLOCKED, False
    return result
