"""Installed-package pure/mock regressions; no historical run files are required.

No LLVM, Cargo, compiler or target is launched. Historical RED controls remain
in their private evidence; these tests assert current package behavior.
"""
from __future__ import annotations

import copy
from contextlib import ExitStack
from dataclasses import dataclass
import importlib.util
import importlib.machinery
import marshal
import struct
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
# Support both the authoring directory and its final tests/ location. This
# locates only this checkout's source package; it reads no historical artifacts.
ROOT = next(parent for parent in HERE.parents if (parent / "antirea/__init__.py").is_file())


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(path.read_bytes(), str(path), "exec", dont_inherit=True), module.__dict__)
    return module


m = load("generic_cargo_ir_under_test", ROOT / "antirea/rust_cargo_prepare.py")
semantic = load("generic_cargo_env_under_test", ROOT / "antirea/rust_cargo_semantic.py")
qualification_helper = load("generic_crate_qualification_under_test", ROOT / m.QUALIFIER)


def sha(text):
    return m.digest(text.encode())


def file(path, text="inert"):
    return {"path": str(path), "sha256": sha(text), "bytes": len(text.encode())}


def fixture():
    root = Path("C:/owned/workspace")
    source = root / "project"
    packages = []
    for index, name in enumerate(("component", "pricing", "rounding")):
        folder = source if index == 0 else source / name
        target = {"name": name, "src_path": str(folder / "src/lib.rs"), "kind": ["lib"],
                  "crate_types": ["rlib", "cdylib"] if index == 0 else ["lib"], "edition": "2021"}
        package = {"id": "path+file:///" + folder.as_posix() + "#" + name + "@1.0.0",
                   "name": name, "version": "1.0.0", "manifest_path": str(folder / "Cargo.toml"),
                   "targets": [target]}
        packages.append(package)
    inspection = {"schema_version": 1, "backend": "rust_cargo_native",
        "status": "inspected_build_not_implemented", "blockers": [], "workspace_root": str(root),
        "project_path": str(source / "project.json"), "project": {"functions": ["calculate"]},
        "input_snapshot": {"roots": [str(source)],
            "files": [file(Path(package["targets"][0]["src_path"]), "source" + str(i))
                      for i, package in enumerate(packages)]},
        "toolchain": {"selection": {"target": m.TARGET}},
        "resolution": {"selected_package_id": packages[0]["id"], "selected_target": packages[0]["targets"][0],
                       "closure": [{"package": item, "node": {}} for item in packages]}}
    capture = {"schema_version": 1, "status": "cargo_original_derivative_captured_not_protected",
               "target_executed": False, "vm_applied": False, "published": False, "arms": {}}
    for mode in ("original", "derivative"):
        units = []
        for i, package in enumerate(packages):
            directory = root / ".runs/capture/build" / mode / "target" / m.TARGET / "release/deps"
            rlib = file(directory / (package["name"] + ".rlib"), mode + package["name"])
            ir = file(directory / (package["name"] + ".ll"), "owned scalar IR" + str(i)) if mode == "derivative" else None
            target = package["targets"][0]
            units.append({"unit": mode + "-" + str(i), "package_id": package["id"], "target_name": target["name"],
                "source": target["src_path"], "crate_types": target["crate_types"], "features": ["chosen"],
                "start_sha256": sha(mode + "start" + str(i)), "finish_sha256": sha(mode + "finish" + str(i)),
                "dep_info": {"path": str(directory / (package["name"] + ".d")), "sha256": sha(mode + "dep" + str(i))},
                "declared_dependencies": [{**inspection["input_snapshot"]["files"][i], "classification": "owned_source"}],
                "env_dependencies": {}, "llvm_ir": ir, "outputs": [rlib],
                "declared_outputs": [rlib] + ([ir] if ir else []), "externs": []})
        units[0]["externs"] = [{**units[1]["outputs"][0], "alias": "money_rules", "producer_unit": units[1]["unit"]}]
        units[1]["externs"] = [{**units[2]["outputs"][0], "alias": "rounding_alias", "producer_unit": units[2]["unit"]}]
        capture["arms"][mode] = {"artifacts": {"schema_version": 1, "mode": mode,
            "status": "artifacts_bound_not_build_validated", "actual_compiled_units": len(units), "units": units}}
    reseal(inspection)
    return capture, {"inspection": inspection, "metadata_evidence": {"mock_only": True}}


def reseal(inspection):
    inspection.pop("fingerprint", None)
    inspection["fingerprint"] = m.digest(m.canonical(inspection))


def parsed(functions=("calculate", "_RNv_pricing", "_RNv_rounding")):
    signatures = {name: {"type": "i64 (i64)", "calling_convention": 0, "linkage": 0 if i == 0 else 8,
                        "visibility": 0, "dll_storage": 0, "attributes": {"0": [], "1": [], "4294967295": []}}
                  for i, name in enumerate(functions)}
    graph = {name: ([functions[i + 1]] if i + 1 < len(functions) else []) for i, name in enumerate(functions)}
    return {"target": m.TARGET, "data_layout": "e-p:64:64", "definitions": signatures,
            "declarations": {}, "graph": graph, "intrinsics": {}, "intrinsic_calls": {name: [] for name in functions},
            "calls": {name: [{"callee": callee, "type": "i64 (i64)", "calling_convention": 0, "attributes": {}} for callee in edges]
                      for name, edges in graph.items()}}


def normalization_fixture(before=None, after=None, raw=b"linked mock IR", normalized=b"normalized mock IR"):
    before = copy.deepcopy(parsed() if before is None else before)
    after = copy.deepcopy(before if after is None else after)
    original, final = copy.deepcopy(before), copy.deepcopy(after)
    for contract in (original, final):
        for row in contract["definitions"].values():
            row.setdefault("shapes", [{"kind": "integer", "bits": 64}] * 2)
            row.setdefault("personality", None)
        for caller, rows in contract["calls"].items():
            for index, row in enumerate(rows):
                row.update(caller=caller, block_index=0, instruction_index=index, reachable=True, noinline=False,
                           argument_ir=["i64 %value"], argument_contracts=[{
                               "type": "i64", "value_kind": 0, "ir": "i64 %value", "call_attributes": None}])
    pre_inline = copy.deepcopy(original)
    inlining = {}
    removed = set(original["definitions"]) - set(final["definitions"])
    for name in sorted(removed):
        inlining[name] = {"original_signature": {key: original["definitions"][name][key]
                         for key in ("type", "shapes", "calling_convention", "attributes")},
            "raw_call_occurrences": copy.deepcopy([row for rows in original["calls"].values() for row in rows if row["callee"] == name]),
            "surviving_callers": m._surviving_callers(name, removed, original["calls"]),
            "definition_removed_after_no_uses": True}
        record = inlining[name]
        record["post_eh_call_occurrences"] = copy.deepcopy([row for rows in pre_inline["calls"].values()
                                               for row in rows if row["callee"] == name])
        record["call_occurrences"] = copy.deepcopy(record["post_eh_call_occurrences"])
        record["call_provenance"] = copy.deepcopy(m.recompute_call_provenance(record["raw_call_occurrences"],
                                                               record["post_eh_call_occurrences"]))
    return {"schema_version": 1, "status": "normalized_ir_unlinked_unvalidated",
        "raw_sha256": m.digest(raw), "normalized_sha256": m.digest(normalized),
        "raw_bytes": len(raw), "normalized_bytes": len(normalized), "public_exports": ["calculate"],
        "inputs_before": {"owned-reviewed-helper": "a" * 64}, "inputs_after": {"owned-reviewed-helper": "a" * 64},
        "changed_inputs": [], "public_abi_preserved": True, "surviving_helper_abi_preserved": True,
        "calling_convention_rewritten": False, "noinline_helpers_removed": False,
        "vm_applied": False, "native_link_verified": False, "target_executed": False,
        "raw_contract": original, "pre_inline_contract": pre_inline, "normalized_contract": final,
        "call_provenance_revision": 2, "argument_comparison": m.CALL_COMPARISON,
        "inlined_functions": sorted(removed), "inlining": inlining}


def renamed_contract(part, names):
    result = copy.deepcopy(part)
    result["definitions"] = {names.get(name, name): row for name, row in result["definitions"].items()}
    result["graph"] = {names.get(name, name): [names.get(callee, callee) for callee in edges]
                       for name, edges in part["graph"].items()}
    result["calls"] = {names.get(name, name): [{**row, "callee": names.get(row["callee"], row["callee"])}
                       for row in rows] for name, rows in part["calls"].items()}
    return result


def qualification_inventory(part):
    symbols = {}
    for declaration, field in ((True, "declarations"), (False, "definitions")):
        for name, signature in part[field].items():
            symbols[name] = {**{key: copy.deepcopy(signature[key]) for key in m.ABI_FIELDS},
                             "kind": "function", "declaration": declaration}
    return {"target": part["target"], "data_layout": part["data_layout"], "symbols": symbols,
            "calls": copy.deepcopy(part["calls"]), "definition_count": len(part["definitions"]),
            "function_definition_count": len(part["definitions"])}


def qualification_receipt(units, before, qualified_raw, engine):
    """Mock only: no LLVM. The real helper's pure namespace planner is reused."""
    inventories = [qualification_inventory(part) for part in before]
    plan = qualification_helper.plan_qualification([unit["owner"] for unit in units],
        [unit["input"]["sha256"] for unit in units], inventories)
    after = [renamed_contract(part, names) for part, names in zip(before, plan["maps"])]
    rows = []
    for unit, original, converted, raw, names in zip(units, before, after, qualified_raw, plan["maps"]):
        rows.append({"owner": copy.deepcopy(unit["owner"]), "stable_owner": m.stable_owner(unit["owner"]),
                     "input": copy.deepcopy(unit["input"]), "evidence": copy.deepcopy(unit["evidence"]),
                     "input_canonical_sha256": unit["input"]["sha256"],
                     "qualified_sha256": m.digest(raw), "qualified_bytes": len(raw),
                     "symbol_map": names, "reverse_symbol_map": {v: k for k, v in names.items()},
                     "before": qualification_inventory(original), "after": qualification_inventory(converted),
                     "definition_count_before": len(original["definitions"]),
                     "definition_count_after": len(converted["definitions"]),
                     "exact_restore_roundtrip": True, "serialized_restore_roundtrip": True,
                     "all_instruction_operand_initializer_identities_preserved": True})
    checked = m.pin_index([item for unit in units for item in [unit["input"], *unit["evidence"]]])
    receipt = {"schema_version": 1, "status": "crate_symbols_qualified_unlinked_unvalidated",
               "identity_authority": "caller_supplied_authenticated_Cargo_units_not_reauthenticated_here",
               "units": rows, "collision_groups": plan["collisions"],
               "unresolved_external_declarations": plan["unresolved_external_declarations"],
               "external_definition_owners": plan["external_resolution"],
               "definition_count_before": sum(len(part["definitions"]) for part in before),
               "definition_count_after": sum(len(part["definitions"]) for part in after),
               "reviewed_engine_inputs": list(engine.values()), "checked_inputs": list(checked.values()),
               "loaded_production_modules": [], "inputs_unchanged": True,
               **{key: False for key in ("calling_convention_rewritten", "linkage_rewritten", "passes_executed",
                                         "vm_applied", "target_executed", "native_link_verified")}}
    return after, receipt


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.before = [parsed(("public_a", "same_local")), parsed(("public_b", "same_local"))]
        self.units = [{"owner": {"package_id": "pkg-" + str(i), "target_name": "crate_" + str(i),
                       "source": str(Path("C:/owned/workspace") / ("crate%d/src/lib.rs" % i)), "unit": "record-" + str(i)},
                       "input": file("C:/owned/workspace/.runs/crate%d.raw.ll" % i, "raw%d" % i),
                       "evidence": [file("C:/owned/workspace/.runs/capture.json", "capture")]}
                      for i in range(2)]
        self.engine = m.pin_index([file("C:/owned/workspace/qualify.py", "engine")])
        self.raw = (b"qualified0", b"qualified1")
        self.outputs = [file("C:/owned/workspace/.runs/crate%d.qualified.ll" % i, raw.decode())
                        for i, raw in enumerate(self.raw)]
        self.after, self.receipt = qualification_receipt(self.units, self.before, self.raw, self.engine)

    def check(self):
        return m.check_qualification(self.units, self.outputs, self.before, self.after,
                                     self.receipt, ["public_a", "public_b"], self.engine)

    def test_duplicate_local_names_remain_distinct_and_publics_unchanged(self):
        gate = self.check()
        targets = [row["symbol_map"]["same_local"] for row in gate["units"]]
        self.assertEqual(len(set(targets)), 2)
        self.assertEqual(gate["definition_count"], 4)
        self.assertTrue(gate["public_exports_identity"])
        self.assertEqual(gate["source_ir_kind"], "qualified_raw_linked_baseline")
        linked = parsed(())
        for field in ("definitions", "graph", "calls"):
            linked[field] = {name: row for part in self.after for name, row in part[field].items()}
        m.check_linked_contract(self.after, linked)

    def test_duplicate_collapse_after_link_is_rejected(self):
        linked = parsed(())
        for field in ("definitions", "graph", "calls"):
            linked[field] = {name: row for part in self.after for name, row in part[field].items()}
        local = self.receipt["units"][0]["symbol_map"]["same_local"]
        del linked["definitions"][local]
        with self.assertRaises(ValueError):
            m.check_linked_contract(self.after, linked)

    def test_body_restoration_failure_is_not_abi_success(self):
        for key in ("exact_restore_roundtrip", "serialized_restore_roundtrip", "all_instruction_operand_initializer_identities_preserved"):
            with self.subTest(key=key):
                original = self.receipt["units"][0][key]
                self.receipt["units"][0][key] = False
                with self.assertRaises(ValueError):
                    self.check()
                self.receipt["units"][0][key] = original

    def test_output_body_bytes_hash_mismatch_rejected(self):
        self.outputs[0]["sha256"] = sha("changed arithmetic")
        with self.assertRaises(ValueError):
            self.check()

    def test_abi_change_even_with_matching_receipt_inventory_rejected(self):
        self.after[0]["definitions"]["public_a"]["calling_convention"] = 8
        self.receipt["units"][0]["after"] = qualification_inventory(self.after[0])
        with self.assertRaises(ValueError):
            self.check()

    def test_ordered_call_edge_change_rejected(self):
        self.after[0]["calls"]["public_a"][0]["callee"] = "public_b"
        with self.assertRaises(ValueError):
            self.check()

    def test_public_export_loss_rejected(self):
        del self.after[0]["definitions"]["public_a"]
        with self.assertRaises(ValueError):
            self.check()

    def test_reverse_bijection_change_rejected(self):
        self.receipt["units"][0]["reverse_symbol_map"] = {}
        with self.assertRaises(ValueError):
            self.check()

    def test_owner_reorder_rejected(self):
        self.receipt["units"].reverse()
        with self.assertRaises(ValueError):
            self.check()

    def test_duplicate_owner_cannot_be_given_another_recorder_id(self):
        self.units[1]["owner"] = {**self.units[0]["owner"], "unit": "another-record"}
        self.receipt["units"][1]["owner"] = copy.deepcopy(self.units[1]["owner"])
        with self.assertRaises(ValueError):
            self.check()

    def test_engine_and_input_closure_are_required(self):
        for key in ("reviewed_engine_inputs", "checked_inputs"):
            with self.subTest(key=key):
                prior = self.receipt[key]
                self.receipt[key] = []
                with self.assertRaises(ValueError):
                    self.check()
                self.receipt[key] = prior

    def test_bool_count_and_claim_fields_are_not_numbers(self):
        self.receipt["units"][0]["definition_count_before"] = True
        with self.assertRaises(ValueError):
            self.check()

    def test_public_only_policy_unchanged(self):
        policy = {"schema_version": 1, "core_roots": ["public_a", "public_b"], "public_presentation": {}, "max_functions": 64}
        projected, evidence = m.qualify_scope_policy(policy, self.check())
        self.assertEqual(projected, policy)
        self.assertEqual(evidence["original_policy"], policy)

    def test_ambiguous_internal_policy_requires_explicit_owner(self):
        with self.assertRaisesRegex(ValueError, "symbol_owners"):
            m.qualify_scope_policy({"core_roots": ["same_local"]}, self.check())

    def test_explicit_internal_owner_retains_reason_and_original_policy(self):
        hint = {key: self.units[1]["owner"][key] for key in ("package_id", "target_name", "source")}
        policy = {"core_roots": ["same_local"], "sensitive_functions": {"same_local": "business secret"},
                  "entry_points": ["public_b"], "symbol_owners": {"same_local": hint}}
        result, evidence = m.qualify_scope_policy(policy, self.check())
        name = self.receipt["units"][1]["symbol_map"]["same_local"]
        self.assertEqual(result["core_roots"], [name])
        self.assertEqual(result["sensitive_functions"], {name: "business secret"})
        self.assertEqual(result["entry_points"], ["public_b"])
        self.assertNotIn("symbol_owners", result)
        self.assertEqual(evidence["original_policy"], policy)

    def test_unused_or_foreign_owner_hint_rejected(self):
        hint = {key: self.units[1]["owner"][key] for key in ("package_id", "target_name", "source")}
        with self.assertRaises(ValueError):
            m.qualify_scope_policy({"core_roots": ["public_a"], "symbol_owners": {"same_local": hint}}, self.check())
        hint["package_id"] = "foreign"
        with self.assertRaises(ValueError):
            m.qualify_scope_policy({"core_roots": ["same_local"], "symbol_owners": {"same_local": hint}}, self.check())

    def test_unicode_namespace_and_owner_hint_match_frozen_qualifier(self):
        self.units[1]["owner"]["source"] = "C:/owned/workspace/Straße/src/lib.rs"
        owner = self.units[1]["owner"]
        self.assertEqual(m.stable_owner(owner), qualification_helper.owner_identity(owner))
        self.assertEqual(m._qualified_name(owner, self.units[1]["input"]["sha256"], "same_local"),
                         qualification_helper.qualified_name(owner, self.units[1]["input"]["sha256"], "same_local"))
        self.after, self.receipt = qualification_receipt(self.units, self.before, self.raw, self.engine)
        hint = {key: owner[key] for key in ("package_id", "target_name", "source")}
        result, _ = m.qualify_scope_policy({"core_roots": ["same_local"], "symbol_owners": {"same_local": hint}}, self.check())
        self.assertEqual(result["core_roots"], [self.receipt["units"][1]["symbol_map"]["same_local"]])

    def test_each_original_definition_has_exact_protected_destination(self):
        gate = self.check()
        names = sorted(name for part in self.after for name in part["definitions"])
        normalization = {"normalized_contract": {"definitions": dict.fromkeys(names)}, "inlining": {}}
        mapping = {"source_selected_functions": names, "protected_selected_functions": sorted("vm_" + name for name in names),
                   "functions": {name: {"source_symbol": name, "protected_symbol": "vm_" + name} for name in names}}
        rows = m.source_definition_lineage(gate, normalization, mapping)
        self.assertEqual(len(rows), 4)
        self.assertEqual(len({(row["owner"]["unit"], row["source_symbol"]) for row in rows}), 4)
        self.assertEqual(len({name for row in rows for name in row["protected_symbols"]}), 4)
        mapping["functions"].pop(names[0])
        with self.assertRaises(ValueError):
            m.source_definition_lineage(gate, normalization, mapping)

    def test_inlined_local_definition_points_to_surviving_wrapper_without_double_count(self):
        gate = self.check()
        removed = self.receipt["units"][0]["symbol_map"]["same_local"]
        names = sorted(name for part in self.after for name in part["definitions"] if name != removed)
        normalization = {"normalized_contract": {"definitions": dict.fromkeys(names)},
                         "inlining": {removed: {"surviving_callers": ["public_a"]}}}
        mapping = {"source_selected_functions": names, "protected_selected_functions": names,
                   "functions": {name: {"source_symbol": name, "protected_symbol": name} for name in names}}
        rows = m.source_definition_lineage(gate, normalization, mapping)
        row = next(row for row in rows if row["qualified_symbol"] == removed)
        self.assertEqual(row["protected_symbols"], ["public_a"])
        self.assertTrue(row["inlined_not_a_separate_wrapper"])


class ClosureTests(unittest.TestCase):
    def setUp(self):
        self.capture, self.plan = fixture()
        self.never = mock.patch("subprocess.Popen", side_effect=AssertionError("no process"))
        self.never.start()
        self.addCleanup(self.never.stop)

    def choose(self):
        return m.select_capture(self.capture, self.plan, check_environment=semantic.check_consumed_environment)

    def units(self, mode="derivative"):
        return self.capture["arms"][mode]["artifacts"]["units"]

    def test_three_actual_crates_and_renamed_dependencies_preserved(self):
        result = self.choose()
        arm = result["arms"]["derivative"]
        self.assertEqual([unit["target_name"] for unit in arm["units"]], ["rounding", "pricing", "component"])
        self.assertEqual(arm["edges"]["derivative-0"][0]["alias"], "money_rules")
        self.assertEqual(arm["edges"]["derivative-1"][0]["alias"], "rounding_alias")
        self.assertFalse(result["native_link_validated"])

    def test_actual_collector_lowercase_spelling_fails_v1_passes_v2_unchanged_evidence(self):
        for mode in ("original", "derivative"):
            for unit in self.units(mode):
                unit["source"] = unit["source"].lower()
                for row in unit["declared_dependencies"]:
                    row["path"] = row["path"].lower()
        before = m.canonical(self.capture)
        # Preserve the historical test identity, not a private old-engine dependency.
        # Its exact v1 RED replay remains in the immutable investigation evidence.
        result = self.choose()
        self.assertEqual(len(result["arms"]["derivative"]["units"]), 3)
        self.assertEqual(m.canonical(self.capture), before)
        self.assertEqual(self.units()[0]["source"], self.units()[0]["source"].lower())

    def test_same_source_identity_conflicting_hash_rejected(self):
        pins = self.plan["inspection"]["input_snapshot"]["files"]
        pins.append({**pins[0], "path": pins[0]["path"].lower(), "sha256": "0" * 64})
        reseal(self.plan["inspection"])
        with self.assertRaisesRegex(ValueError, "conflicting hash/count"):
            self.choose()

    def test_same_source_identity_conflicting_count_rejected(self):
        pins = self.plan["inspection"]["input_snapshot"]["files"]
        pins.append({**pins[0], "path": pins[0]["path"].lower(), "bytes": pins[0]["bytes"] + 1})
        reseal(self.plan["inspection"])
        with self.assertRaisesRegex(ValueError, "conflicting hash/count"):
            self.choose()

    def test_extern_and_ir_identity_case_does_not_rewrite_spelling(self):
        unit = self.units()[0]
        unit["externs"][0]["path"] = unit["externs"][0]["path"].upper()
        unit["llvm_ir"] = {**unit["llvm_ir"], "path": unit["llvm_ir"]["path"].lower()}
        before = m.canonical(self.capture)
        self.choose()
        self.assertEqual(m.canonical(self.capture), before)

    def test_artifact_identity_conflicting_count_rejected(self):
        unit = self.units()[0]
        unit["declared_outputs"][0] = {**unit["declared_outputs"][0],
            "path": unit["outputs"][0]["path"].lower(), "bytes": unit["outputs"][0]["bytes"] + 1}
        with self.assertRaisesRegex(ValueError, "conflicting hash/count"):
            self.choose()

    def test_case_variant_duplicate_metadata_target_remains_ambiguous(self):
        package = self.plan["inspection"]["resolution"]["closure"][0]["package"]
        package["targets"].append({**package["targets"][0], "src_path": package["targets"][0]["src_path"].lower()})
        reseal(self.plan["inspection"])
        with self.assertRaisesRegex(ValueError, "metadata target identity"):
            self.choose()

    def test_two_aliases_to_same_actual_producer_are_not_two_crates(self):
        for mode in self.capture["arms"]:
            edge = copy.deepcopy(self.units(mode)[0]["externs"][0])
            edge["alias"] = "second_public_alias"
            self.units(mode)[0]["externs"].append(edge)
        result = self.choose()
        self.assertEqual(len(result["arms"]["derivative"]["units"]), 3)
        self.assertEqual(len(result["arms"]["derivative"]["edges"]["derivative-0"]), 2)

    def test_metadata_only_node_is_not_invented_as_compiled_unit(self):
        metadata = self.plan["inspection"]
        extra = copy.deepcopy(metadata["resolution"]["closure"][2])
        extra["package"]["id"] += "-unused"
        metadata["resolution"]["closure"].append(extra)
        reseal(metadata)
        self.assertEqual(len(self.choose()["arms"]["derivative"]["units"]), 3)

    def test_missing_producer_rejected(self):
        self.units()[0]["externs"][0]["producer_unit"] = "not-recorded"
        with self.assertRaisesRegex(ValueError, "missing/self"):
            self.choose()

    def test_self_producer_rejected(self):
        self.units()[0]["externs"][0]["producer_unit"] = "derivative-0"
        with self.assertRaisesRegex(ValueError, "missing/self"):
            self.choose()

    def test_foreign_artifact_with_existing_producer_rejected(self):
        self.units()[0]["externs"][0]["path"] = "C:/outside/foreign.rlib"
        with self.assertRaisesRegex(ValueError, "actual output producer"):
            self.choose()

    def test_extern_content_change_rejected(self):
        self.units()[0]["externs"][0]["sha256"] = "a" * 64
        with self.assertRaisesRegex(ValueError, "actual output producer"):
            self.choose()

    def test_ambiguous_same_path_producer_rejected(self):
        self.units()[2]["declared_outputs"].append(copy.deepcopy(self.units()[1]["outputs"][0]))
        with self.assertRaisesRegex(ValueError, "ambiguous actual artifact"):
            self.choose()

    def test_duplicate_extern_alias_rejected(self):
        self.units()[0]["externs"] *= 2
        with self.assertRaisesRegex(ValueError, "duplicate extern alias"):
            self.choose()

    def test_cycle_rejected(self):
        first, last = self.units()[0], self.units()[2]
        last["externs"] = [{**first["outputs"][0], "alias": "backedge", "producer_unit": first["unit"]}]
        with self.assertRaisesRegex(ValueError, "cyclic"):
            self.choose()

    def test_source_outside_owned_roots_rejected_even_if_added_to_pins(self):
        inspection = self.plan["inspection"]
        target = inspection["resolution"]["closure"][1]["package"]["targets"][0]
        target["src_path"] = "C:/outside/source.rs"
        inspection["input_snapshot"]["files"][1]["path"] = target["src_path"]
        for mode in self.capture["arms"]:
            unit = self.units(mode)[1]
            unit["source"] = target["src_path"]
            unit["declared_dependencies"][0]["path"] = target["src_path"]
        reseal(inspection)
        with self.assertRaisesRegex(ValueError, "outside owned snapshot"):
            self.choose()

    def test_source_hash_change_rejected(self):
        self.units()[1]["declared_dependencies"][0]["sha256"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "source provenance"):
            self.choose()

    def test_ir_must_be_exact_declared_output(self):
        self.units()[2]["llvm_ir"] = {**self.units()[2]["llvm_ir"], "sha256": "b" * 64}
        with self.assertRaisesRegex(ValueError, "exact compiler-declared"):
            self.choose()

    def test_missing_dependency_ir_is_not_silently_dropped(self):
        self.units()[2]["llvm_ir"] = None
        with self.assertRaisesRegex(ValueError, "descriptor"):
            self.choose()

    def test_explicit_target_not_first_unit_determines_root(self):
        for mode in self.capture["arms"]:
            self.units(mode).reverse()
        self.assertEqual(self.choose()["arms"]["derivative"]["root_unit"], "derivative-0")

    def test_unrecorded_selected_target_rejected(self):
        inspection = self.plan["inspection"]
        inspection["resolution"]["selected_target"] = {**inspection["resolution"]["selected_target"], "name": "other"}
        reseal(inspection)
        with self.assertRaisesRegex(ValueError, "selected Cargo target"):
            self.choose()

    def test_foreign_target_triple_rejected(self):
        inspection = self.plan["inspection"]
        inspection["toolchain"]["selection"]["target"] = "aarch64-pc-windows-msvc"
        reseal(inspection)
        with self.assertRaisesRegex(ValueError, "explicit target"):
            self.choose()

    def test_changed_inspection_fingerprint_rejected(self):
        self.plan["inspection"]["project"]["functions"] = ["other"]
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            self.choose()

    def test_consumed_environment_drift_blocks_even_recognized_capture_control(self):
        for mode in self.capture["arms"]:
            self.units(mode)[1]["env_dependencies"] = {"CARGO_TARGET_DIR": {
                "name": "CARGO_TARGET_DIR", "present": True, "value_sha256": sha(mode)}}
        with self.assertRaisesRegex(ValueError, "consumed environment differs"):
            self.choose()

    def test_option_env_absent_versus_present_empty_blocks(self):
        self.units("original")[2]["env_dependencies"] = {"MODE": {"name": "MODE", "present": False, "value_sha256": None}}
        self.units()[2]["env_dependencies"] = {"MODE": {"name": "MODE", "present": True, "value_sha256": sha("")}}
        with self.assertRaisesRegex(ValueError, "consumed environment differs"):
            self.choose()

    def test_equal_consumed_environment_is_not_functional_equivalence(self):
        for mode in self.capture["arms"]:
            self.units(mode)[2]["env_dependencies"] = {"MODE": {"name": "MODE", "present": True, "value_sha256": sha("same")}}
        result = self.choose()["source_environment_handoff"]
        self.assertTrue(result["handoff_allowed"])
        self.assertEqual(result["functional_equivalence"], "not_evaluated")

    def test_bool_success_fields_not_accepted(self):
        self.capture["vm_applied"] = 0
        with self.assertRaisesRegex(ValueError, "unprotected"):
            self.choose()


class ContractTests(unittest.TestCase):
    def test_scalar_canonicalization_preserves_abi_and_removes_only_lifetime_declarations(self):
        before, after = parsed(), parsed()
        before["declarations"] = {"llvm.lifetime.start.p0": {"type": "void(i64,ptr)"}}
        result = m.check_preservation(before, after)
        self.assertEqual(result["removed_lifetime_declarations"], ["llvm.lifetime.start.p0"])
        self.assertFalse(result["calling_convention_rewritten"])

    def test_canonicalization_cannot_change_helper_calling_convention(self):
        before, after = parsed(), parsed()
        after["definitions"]["_RNv_pricing"]["calling_convention"] = 8
        with self.assertRaisesRegex(ValueError, "definitions"):
            m.check_preservation(before, after)

    def test_canonicalization_cannot_change_extension_or_ordered_call_metadata(self):
        for field in ("attributes", "calling_convention"):
            before, after = parsed(), parsed()
            after["calls"]["calculate"][0][field] = {"changed": True}
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "calls"):
                m.check_preservation(before, after)

    def test_non_lifetime_runtime_declaration_not_silently_removed(self):
        before, after = parsed(), parsed()
        before["declarations"] = {"panic_runtime": {"type": "void()"}}
        with self.assertRaisesRegex(ValueError, "non-lifetime"):
            m.check_preservation(before, after)

    def test_linking_three_crate_function_graph_preserves_all_defs(self):
        whole = parsed()
        parts = []
        for name in whole["definitions"]:
            part = parsed(())
            for field in ("definitions", "graph", "calls"):
                part[field] = {name: copy.deepcopy(whole[field][name])}
            parts.append(part)
        result = m.check_linked_contract(parts, whole)
        self.assertEqual(len(result["definitions"]), 3)
        self.assertFalse(result["native_link_verified"])

    def test_duplicate_crate_definition_requires_explicit_resolution(self):
        part = parsed(("calculate",))
        with self.assertRaisesRegex(ValueError, "duplicate crate definition"):
            m.check_linked_contract([part, part], part)

    def test_link_cannot_drop_a_dependency_helper(self):
        part, after = parsed(), parsed(("calculate",))
        with self.assertRaisesRegex(ValueError, "definitions"):
            m.check_linked_contract([part], after)

    def test_cross_crate_calling_convention_mismatch_rejected(self):
        first, last = parsed(("calculate",)), parsed(("_RNv_helper",))
        first["declarations"] = {"_RNv_helper": {"type": "i64 (i64)", "calling_convention": 8}}
        merged = parsed(())
        for field in ("definitions", "graph", "calls"):
            merged[field] = {**first[field], **last[field]}
        with self.assertRaisesRegex(ValueError, "ABI mismatch"):
            m.check_linked_contract([first, last], merged)

    def test_cross_crate_parameter_attribute_mismatch_rejected(self):
        first, last = parsed(("calculate",)), parsed(("_RNv_helper",))
        declaration = copy.deepcopy(last["definitions"]["_RNv_helper"])
        declaration["attributes"]["1"] = [{"kind": "zeroext"}]
        first["declarations"] = {"_RNv_helper": declaration}
        merged = parsed(())
        for field in ("definitions", "graph", "calls"):
            merged[field] = {**first[field], **last[field]}
        with self.assertRaisesRegex(ValueError, "ABI attributes"):
            m.check_linked_contract([first, last], merged)

    def scope(self):
        return {"status": "ready", "selected_functions": ["calculate", "_RNv_pricing"],
                "boundary_functions": {}, "max_functions": 64}

    def test_required_helpers_and_conservative_extra_defs_are_selected(self):
        chosen = m.choose_scope(parsed(), self.scope(), ["calculate"])
        self.assertEqual(chosen["selected_functions"], ["_RNv_pricing", "_RNv_rounding", "calculate"])
        self.assertEqual(chosen["conservative_additions"], ["_RNv_rounding"])

    def test_public_boundary_not_silently_virtualized(self):
        scope = self.scope()
        scope["boundary_functions"] = {"calculate": {"overridden_by_sensitive_or_core": False}}
        with self.assertRaisesRegex(ValueError, "public boundary"):
            m.choose_scope(parsed(), scope, ["calculate"])

    def test_sensitive_policy_override_is_respected(self):
        scope = self.scope()
        scope["boundary_functions"] = {"calculate": {"overridden_by_sensitive_or_core": True}}
        self.assertIn("calculate", m.choose_scope(parsed(), scope, ["calculate"])["selected_functions"])

    def test_missing_export_needs_review_and_unresolved_runtime_fail_closed(self):
        cases = [(parsed(), {**self.scope(), "status": "needs_review"}, ["calculate"]),
                 (parsed(), self.scope(), ["missing"]),
                 ({**parsed(), "declarations": {"runtime": {}}}, self.scope(), ["calculate"])]
        for module, scope, exports in cases:
            with self.subTest(exports=exports), self.assertRaises(ValueError):
                m.choose_scope(module, scope, exports)

    def test_existing_mapper_request_api_preserves_graph_and_provenance(self):
        mapper = SimpleNamespace(RustIRRequest=mock.Mock(return_value="request"))
        module, provenance = parsed(), object()
        chosen = m.choose_scope(module, self.scope(), ["calculate"])
        ir = file(Path("C:/owned/.runs/prepared/module.canonical.ll"))
        self.assertEqual(m.build_mapper_request(mapper, ir, module, chosen, provenance), "request")
        args = mapper.RustIRRequest.call_args.args
        self.assertEqual(args[0:2], (Path(ir["path"]), ir["sha256"]))
        self.assertEqual(args[2], tuple(chosen["selected_functions"]))
        self.assertEqual(args[3], ("calculate",))
        self.assertEqual(args[4]["calculate"], ("_RNv_pricing",))
        self.assertIs(args[5], provenance)

    def test_non_c_helper_is_rejected_not_rewritten(self):
        module = parsed()
        module["definitions"]["_RNv_pricing"]["calling_convention"] = 8
        mapper = SimpleNamespace(RustIRRequest=mock.Mock())
        chosen = m.choose_scope(module, self.scope(), ["calculate"])
        with self.assertRaisesRegex(ValueError, "never rewritten"):
            m.build_mapper_request(mapper, file(Path("C:/owned/.runs/module.ll")), module, chosen, object())
        mapper.RustIRRequest.assert_not_called()
        self.assertEqual(module["definitions"]["_RNv_pricing"]["calling_convention"], 8)


class CallProvenanceTests(unittest.TestCase):
    def setUp(self):
        before = parsed()
        after = parsed(("calculate", "_RNv_rounding"))
        after["definitions"]["_RNv_rounding"] = copy.deepcopy(before["definitions"]["_RNv_rounding"])
        self.receipt = normalization_fixture(before, after)
        self.helper = self.receipt["inlining"]["_RNv_pricing"]

    def check(self):
        return m.check_call_provenance(self.receipt)

    def post(self, row):
        self.receipt["pre_inline_contract"]["calls"]["calculate"] = [copy.deepcopy(row)]
        self.helper["post_eh_call_occurrences"] = [copy.deepcopy(row)]
        self.helper["call_occurrences"] = [copy.deepcopy(row)]

    def nested(self):
        attrs = {"0": [], "1": [], "4294967295": [{"kind": "enum", "id": 90, "value": 0}]}
        row = copy.deepcopy(self.helper["raw_call_occurrences"][0])
        row["argument_ir"] = ["%nested = call i64 @nested(i64 %value) #7"]
        resolved = "%nested = call i64 @nested(i64 %value) <LLVM_CALL_FUNCTION_ATTRIBUTES:" + m.canonical(attrs["4294967295"]).decode() + ">"
        row["argument_contracts"] = [{"type": "i64", "value_kind": 24,
                                      "ir": resolved, "call_attributes": attrs}]
        self.receipt["raw_contract"]["calls"]["calculate"] = [copy.deepcopy(row)]
        self.helper["raw_call_occurrences"] = [copy.deepcopy(row)]
        post = copy.deepcopy(row)
        post["argument_ir"] = [row["argument_ir"][0].replace("#7", "#6")]
        self.post(post)
        self.helper["call_provenance"] = m.recompute_call_provenance([row], [post])
        return row, post

    def test_missing_revision_is_not_legacy_success(self):
        del self.receipt["call_provenance_revision"]
        with self.assertRaisesRegex(ValueError, "revision"):
            self.check()

    def test_revision_requires_integer_two_not_bool_or_float(self):
        for value in (True, 2.0, "2", 1):
            self.receipt["call_provenance_revision"] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "revision"):
                self.check()

    def test_comparison_marker_cannot_be_omitted_or_changed(self):
        for value in (None, "raw_text", "strip_attribute_numbers"):
            self.receipt["argument_comparison"] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "comparison"):
                self.check()

    def test_post_eh_snapshot_is_mandatory(self):
        del self.receipt["pre_inline_contract"]
        with self.assertRaisesRegex(ValueError, "snapshot"):
            self.check()

    def test_snapshot_caller_label_must_match_owning_function(self):
        self.receipt["pre_inline_contract"]["calls"]["calculate"][0]["caller"] = "_RNv_rounding"
        with self.assertRaisesRegex(ValueError, "owner"):
            self.check()

    def test_same_count_changed_post_eh_operand_is_rejected(self):
        row = copy.deepcopy(self.helper["post_eh_call_occurrences"][0])
        row["argument_ir"] = ["i64 %other"]
        row["argument_contracts"][0]["ir"] = "i64 %other"
        self.post(row)
        with self.assertRaisesRegex(ValueError, "typed call provenance changed"):
            self.check()

    def test_same_count_changed_call_attributes_are_rejected(self):
        row = copy.deepcopy(self.helper["post_eh_call_occurrences"][0])
        row["attributes"] = {"4294967295": [{"kind": "enum", "id": 90, "value": 0}]}
        self.post(row)
        with self.assertRaisesRegex(ValueError, "typed call provenance changed"):
            self.check()

    def test_missing_proof_rejected_even_when_true_labels_elsewhere(self):
        del self.helper["call_provenance"]
        with self.assertRaisesRegex(ValueError, "independent recomputation"):
            self.check()

    def test_proof_booleans_are_not_integer_one(self):
        for field in ("typed_semantics_equal", "call_order_and_multiplicity_preserved"):
            saved = copy.deepcopy(self.helper["call_provenance"])
            self.helper["call_provenance"][field] = 1
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "independent recomputation"):
                self.check()
            self.helper["call_provenance"] = saved

    def test_proof_count_is_not_boolean_true(self):
        self.helper["call_provenance"]["raw_count"] = True
        with self.assertRaisesRegex(ValueError, "independent recomputation"):
            self.check()

    def test_proof_semantics_are_recomputed_not_trusted(self):
        self.helper["call_provenance"]["raw_semantics"][0]["type"] = "i32 (i32)"
        with self.assertRaisesRegex(ValueError, "independent recomputation"):
            self.check()

    def test_raw_occurrence_omission_does_not_pass_equal_post_lists(self):
        self.helper["raw_call_occurrences"] = []
        with self.assertRaisesRegex(ValueError, "caller provenance"):
            self.check()

    def test_post_occurrence_omission_is_rejected(self):
        del self.helper["post_eh_call_occurrences"]
        with self.assertRaisesRegex(ValueError, "caller provenance"):
            self.check()

    def test_legacy_occurrence_alias_must_equal_post_eh_records(self):
        self.helper["call_occurrences"] = []
        with self.assertRaisesRegex(ValueError, "occurrence alias"):
            self.check()

    def test_stale_typed_operand_cannot_hide_raw_ssa_change(self):
        self.receipt["raw_contract"]["calls"]["calculate"][0]["argument_ir"] = ["i64 %different"]
        with self.assertRaisesRegex(ValueError, "original text"):
            self.check()

    def test_operand_kind_boolean_is_not_integer_identity(self):
        self.receipt["raw_contract"]["calls"]["calculate"][0]["argument_contracts"][0]["value_kind"] = False
        with self.assertRaisesRegex(ValueError, "typed operand"):
            self.check()

    def test_attribute_number_relabel_accepts_only_same_actual_attributes(self):
        self.nested()
        result = self.check()
        self.assertTrue(result["helpers"]["_RNv_pricing"]["argument_ir_text_changed"])
        self.assertTrue(result["proof_recomputed"])
        self.assertFalse(result["independent_llvm_reexecution"])
        self.assertEqual(m.check_call_provenance(m.json_bytes(m.canonical(self.receipt))), result)

    def test_attribute_reference_cannot_be_erased(self):
        _, row = self.nested()
        row["argument_ir"][0] = row["argument_ir"][0].replace(" #6", "")
        self.post(row)
        with self.assertRaisesRegex(ValueError, "reference/actual"):
            self.check()

    def test_resolved_actual_attribute_change_is_rejected(self):
        _, row = self.nested()
        attrs = row["argument_contracts"][0]["call_attributes"]
        attrs["4294967295"][0]["value"] = 1
        row["argument_contracts"][0]["ir"] = "%nested = call i64 @nested(i64 %value) <LLVM_CALL_FUNCTION_ATTRIBUTES:" + m.canonical(attrs["4294967295"]).decode() + ">"
        self.post(row)
        with self.assertRaisesRegex(ValueError, "typed call provenance changed"):
            self.check()

    def test_same_count_occurrence_reordering_is_not_set_equality(self):
        first = copy.deepcopy(self.helper["raw_call_occurrences"][0])
        second = copy.deepcopy(first)
        second["instruction_index"] = 1
        second["argument_ir"] = ["i64 %second"]
        second["argument_contracts"][0]["ir"] = "i64 %second"
        self.receipt["raw_contract"]["calls"]["calculate"] = [first, second]
        self.receipt["pre_inline_contract"]["calls"]["calculate"] = copy.deepcopy([first, second])
        self.helper["raw_call_occurrences"] = copy.deepcopy([first, second])
        self.helper["post_eh_call_occurrences"] = copy.deepcopy([second, first])
        self.helper["call_occurrences"] = copy.deepcopy([second, first])
        with self.assertRaisesRegex(ValueError, "caller provenance"):
            self.check()

    def test_unbound_instruction_position_is_rejected(self):
        self.helper["post_eh_call_occurrences"][0]["instruction_index"] = 99
        with self.assertRaisesRegex(ValueError, "caller provenance"):
            self.check()

    def test_empty_inlining_still_requires_v3_provenance_contract(self):
        receipt = normalization_fixture()
        self.assertEqual(m.check_call_provenance(receipt)["helpers"], {})
        del receipt["argument_comparison"]
        with self.assertRaisesRegex(ValueError, "comparison"):
            m.check_call_provenance(receipt)

    def test_quoted_hash_is_never_resolved_as_attribute_group(self):
        text = 'i64 %"value#7"'
        contract = {"type": "i64", "value_kind": 0, "ir": text, "call_attributes": None}
        self.assertEqual(m._operand_text(text, contract), text)

    def test_golden_proof_is_exact_and_extra_fields_are_not_accepted(self):
        row = self.helper["raw_call_occurrences"][0]
        semantics = {key: copy.deepcopy(row[key]) for key in
                     ("caller", "callee", "type", "attributes", "argument_contracts", "noinline")}
        golden = {"schema_version": 1, "comparison": "llvm_typed_attribute_resolved_call_operands",
                  "raw_count": 1, "post_eh_count": 1, "raw_semantics": [semantics],
                  "post_eh_semantics": [copy.deepcopy(semantics)],
                  "call_order_and_multiplicity_preserved": True, "typed_semantics_equal": True,
                  "argument_ir_text_changed": False}
        self.assertEqual(m.recompute_call_provenance([row], [copy.deepcopy(row)]), golden)
        self.helper["call_provenance"]["unexpected_claim"] = True
        with self.assertRaisesRegex(ValueError, "independent recomputation"):
            self.check()

    def test_parent_json_handoff_recomputes_proof(self):
        parent = m
        proof = self.check()
        report = {"preparation_revision": 5, "normalization_gate": {"call_provenance": proof},
                  "object_handoff": {"call_provenance": copy.deepcopy(proof)}}
        saved = m.json_bytes(m.canonical({"report": report, "normalization": self.receipt}))
        self.assertEqual(parent.verify_call_provenance_handoff(saved["report"], saved["normalization"]), proof)

    def test_parent_rejects_child_proof_or_handoff_labels_without_correspondence(self):
        parent = m
        for key in ("normalization_gate", "object_handoff"):
            proof = self.check()
            report = {"preparation_revision": 5, "normalization_gate": {"call_provenance": copy.deepcopy(proof)},
                      "object_handoff": {"call_provenance": copy.deepcopy(proof)}}
            report[key]["call_provenance"]["helpers"]["_RNv_pricing"]["proof_sha256"] = "f" * 64
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "parent-recomputed"):
                parent.verify_call_provenance_handoff(report, self.receipt)


class NormalizationTests(unittest.TestCase):
    def setUp(self):
        self.before = parsed()
        self.after = parsed(("calculate", "_RNv_rounding"))
        # Preserve the surviving helper's original linkage/ABI, not its index.
        self.after["definitions"]["_RNv_rounding"] = copy.deepcopy(self.before["definitions"]["_RNv_rounding"])
        self.receipt = normalization_fixture(self.before, self.after)
        self.raw = file(Path("C:/owned/raw.ll"), "linked mock IR")
        self.normalized = file(Path("C:/owned/normalized.ll"), "normalized mock IR")

    def check(self):
        return m.check_normalization(self.raw, self.normalized, self.before, self.after, self.receipt, ["calculate"])

    def test_explicit_inline_provenance_replaces_false_graph_equality(self):
        with self.assertRaisesRegex(ValueError, "definitions"):
            m.check_preservation(self.before, self.after)
        result = self.check()
        self.assertEqual(result["inlined_into"], {"_RNv_pricing": ["calculate"]})
        self.assertFalse(result["raw_graph_equal_to_normalized"])

    def test_normalization_wrong_source_hash_rejected(self):
        self.receipt["raw_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "binding"):
            self.check()

    def test_normalization_wrong_output_hash_rejected(self):
        self.receipt["normalized_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "binding"):
            self.check()

    def test_true_not_integer_one_required_for_abi_claim(self):
        self.receipt["public_abi_preserved"] = 1
        with self.assertRaisesRegex(ValueError, "structural"):
            self.check()

    def test_absent_before_after_maps_are_not_success(self):
        del self.receipt["inputs_before"]
        del self.receipt["inputs_after"]
        with self.assertRaisesRegex(ValueError, "watched"):
            self.check()

    def test_changed_inputs_rejected(self):
        self.receipt["inputs_after"]["owned-reviewed-helper"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "watched"):
            self.check()

    def test_wrong_surviving_caller_rejected(self):
        self.receipt["inlining"]["_RNv_pricing"]["surviving_callers"] = ["_RNv_rounding"]
        with self.assertRaisesRegex(ValueError, "caller provenance"):
            self.check()

    def test_missing_original_call_occurrence_rejected(self):
        self.receipt["inlining"]["_RNv_pricing"]["raw_call_occurrences"] = []
        with self.assertRaisesRegex(ValueError, "caller provenance"):
            self.check()

    def test_changed_original_helper_signature_rejected(self):
        self.receipt["inlining"]["_RNv_pricing"]["original_signature"]["calling_convention"] = 8
        with self.assertRaisesRegex(ValueError, "original signature"):
            self.check()

    def test_surviving_abi_change_rejected(self):
        self.after["definitions"]["calculate"]["calling_convention"] = 8
        with self.assertRaisesRegex(ValueError, "ABI differs"):
            self.check()

    def test_attribute_set_order_difference_between_helpers_is_not_abi_drift(self):
        attrs = [{"kind": "enum", "id": 90, "value": 0}, {"kind": "enum", "id": 11, "value": 0}]
        for module in (self.before, self.after):
            module["definitions"]["calculate"]["attributes"]["4294967295"] = copy.deepcopy(attrs)
        for contract in (self.receipt["raw_contract"], self.receipt["normalized_contract"]):
            contract["definitions"]["calculate"]["attributes"]["4294967295"] = list(reversed(copy.deepcopy(attrs)))
        self.check()

    def test_attribute_set_comparison_preserves_values_and_duplicate_count(self):
        row = {"kind": "enum", "id": 90, "value": 0}
        self.before["definitions"]["calculate"]["attributes"]["4294967295"] = [row, row]
        self.receipt["raw_contract"]["definitions"]["calculate"]["attributes"]["4294967295"] = [row]
        with self.assertRaisesRegex(ValueError, "ABI differs"):
            self.check()

    def test_unexplained_definition_removal_rejected(self):
        self.receipt["inlined_functions"] = []
        with self.assertRaisesRegex(ValueError, "unexpected definitions"):
            self.check()

    def test_raw_personality_not_discarded_in_receipt(self):
        self.before["definitions"]["calculate"]["personality"] = "personality_one"
        with self.assertRaisesRegex(ValueError, "personality"):
            self.check()

    def test_raw_ordered_call_metadata_preserved(self):
        self.before["calls"]["calculate"][0]["attributes"] = {"0": [{"id": 1}]}
        with self.assertRaisesRegex(ValueError, "ordered call"):
            self.check()

    def test_policy_sensitive_inline_function_projects_to_exact_callers(self):
        policy = {"core_roots": ["calculate"], "sensitive_functions": ["_RNv_pricing"], "public_presentation": {}}
        original = copy.deepcopy(policy)
        projected, evidence = m.project_scope_policy(policy, self.receipt)
        self.assertEqual(projected["sensitive_functions"], ["calculate"])
        self.assertEqual(evidence["inlined_policy_functions"][0]["source_function"], "_RNv_pricing")
        self.assertEqual(policy, original)

    def test_policy_core_inline_function_is_not_lost(self):
        projected, evidence = m.project_scope_policy({"core_roots": ["_RNv_pricing"]}, self.receipt)
        self.assertEqual(projected["core_roots"], ["calculate"])
        self.assertEqual(evidence["original_policy"]["core_roots"], ["_RNv_pricing"])

    def test_policy_entry_presence_retains_original_symbol_evidence(self):
        projected, evidence = m.project_scope_policy({"core_roots": ["calculate"], "entry_points": ["_RNv_pricing"]}, self.receipt)
        self.assertEqual(projected["entry_points"], ["calculate"])
        self.assertEqual(evidence["inlined_policy_functions"][0]["role"], "entry_points")

    def test_policy_inlined_presentation_boundary_is_not_silently_covered(self):
        with self.assertRaisesRegex(ValueError, "presentation boundary"):
            m.project_scope_policy({"core_roots": ["calculate"], "public_presentation": {"_RNv_pricing": "UI only"}}, self.receipt)

    def test_policy_missing_original_function_rejected(self):
        with self.assertRaisesRegex(ValueError, "absent from raw"):
            m.project_scope_policy({"core_roots": ["not_in_raw"]}, self.receipt)

    def test_transitive_inlining_projects_to_all_surviving_callers(self):
        calls = {"root_a": [{"callee": "outer"}], "root_b": [{"callee": "inner"}],
                 "outer": [{"callee": "inner"}], "inner": []}
        self.assertEqual(m._surviving_callers("inner", {"outer", "inner"}, calls), ["root_a", "root_b"])

    def test_canonical_json_key_reordering_preserves_all_caller_occurrences(self):
        before = parsed(("z_root", "calculate", "helper"))
        before["definitions"]["calculate"]["linkage"] = 0
        before["graph"] = {"z_root": ["helper"], "calculate": ["helper"], "helper": []}
        before["calls"] = {name: [{"callee": callee, "type": "i64 (i64)", "attributes": {},
                                  "caller": name, "instruction_index": 0} for callee in edges]
                           for name, edges in before["graph"].items()}
        after = parsed(("z_root", "calculate"))
        after["definitions"]["calculate"] = copy.deepcopy(before["definitions"]["calculate"])
        after["graph"] = {"z_root": [], "calculate": []}
        after["calls"] = {"z_root": [], "calculate": []}
        receipt = normalization_fixture(before, after)
        saved = m.json_bytes(m.canonical(receipt))
        self.assertNotEqual(list(saved["raw_contract"]["calls"]), list(receipt["raw_contract"]["calls"]))
        result = m.check_normalization(self.raw, self.normalized, before, after, saved, ["calculate"])
        self.assertEqual(result["inlined_into"]["helper"], ["calculate", "z_root"])

    def test_cyclic_inline_provenance_rejected(self):
        with self.assertRaisesRegex(ValueError, "cyclic"):
            m._surviving_callers("one", {"one", "two"}, {"one": [{"callee": "two"}], "two": [{"callee": "one"}]})

    def test_raw_personality_inventory_fails_v2_but_passes_v3_without_dropping_it(self):
        def layout(_):
            return b"e-p:64:64"
        def personality(_):
            return 2
        def inline_asm(_, size):
            size._obj.value = 0
        llvm = SimpleNamespace(dll=SimpleNamespace(LLVMGetDataLayoutStr=layout, LLVMGetPersonalityFn=personality),
            LLVMContextCreate=lambda: 100, LLVMContextDispose=lambda _: None, LLVMDisposeModule=lambda _: None,
            LLVMGetModuleInlineAsm=inline_asm, LLVMGetFirstGlobal=lambda _: None,
            LLVMGetFirstGlobalAlias=lambda _: None, LLVMGetFirstGlobalIFunc=lambda _: None,
            LLVMGetNamedMetadataNumOperands=lambda *_: 0, functions=lambda _: [1, 2],
            name=lambda value: {1: "calculate", 2: "personality_one"}[value],
            LLVMGlobalGetValueType=lambda value: value, LLVMCountParamTypes=lambda _: 1,
            LLVMPrintTypeToString=lambda value: "i64 (i64)" if value == 1 else "i32 (...)" , string=lambda value: value,
            LLVMGetFunctionCallConv=lambda _: 0, LLVMGetLinkage=lambda _: 0, LLVMGetVisibility=lambda _: 0,
            LLVMGetDLLStorageClass=lambda _: 0, LLVMIsDeclaration=lambda value: value == 2,
            LLVMGetComdat=lambda _: None, LLVMHasPersonalityFn=lambda value: value == 1,
            instructions=lambda _: [], LLVMGetTarget=lambda _: m.TARGET.encode(), close=lambda: None)
        mapper = SimpleNamespace(_api=lambda _: llvm, open_llvm=lambda **_: llvm,
                                 _parse=lambda *_: 200, _attrs=lambda *_: {})
        # Preserve the current inventory assertion without loading the private v2 engine.
        # The historical rejection replay remains recorded separately.
        result = m.inspect_ir(mapper, Path("C:/not-loaded.dll"), b"mock only",
                              workspace_root=ROOT, trusted_engine_pins={"mock": "a" * 64})
        self.assertEqual(result["definitions"]["calculate"]["personality"], "personality_one")
        self.assertIn("personality_one", result["declarations"])


class TypedScopeTests(unittest.TestCase):
    def setUp(self):
        self.module = parsed(("calculate",))
        name = "llvm.fshl.i64"
        typed = {"name": name, "base": "llvm.fshl", "intrinsic_id": 17, "type": "i64 (i64, i64, i64)"}
        self.module["declarations"] = self.module["intrinsics"] = {name: typed}
        self.module["intrinsic_calls"] = {"calculate": [{"callee": name, "intrinsic_id": 17, "type": typed["type"]}]}
        self.plan = {"status": "needs_review", "selected_functions": ["calculate"], "boundary_functions": {},
            "max_functions": 64, "data_risks": [], "graph": {"calls": {"calculate": [name]}},
            "unresolved": [{"kind": "external_call", "symbol": "calculate", "detail": name, "relevant": True}]}

    def test_only_exact_typed_intrinsic_issue_is_resolved(self):
        original = copy.deepcopy(self.plan)
        result = m.typed_scope_plan(self.plan, self.module)
        self.assertEqual(result["status"], "ready")
        self.assertEqual(len(result["typed_intrinsic_resolutions"]), 1)
        self.assertEqual(m.choose_scope(self.module, result, ["calculate"])["selected_functions"], ["calculate"])
        self.assertEqual(self.plan, original)

    def test_missing_parsed_intrinsic_call_witness_rejected(self):
        self.module["intrinsic_calls"]["calculate"] = []
        with self.assertRaisesRegex(ValueError, "exact parsed call"):
            m.typed_scope_plan(self.plan, self.module)

    def test_mismatched_intrinsic_id_rejected(self):
        self.module["intrinsic_calls"]["calculate"][0]["intrinsic_id"] = 18
        with self.assertRaisesRegex(ValueError, "exact parsed call"):
            m.typed_scope_plan(self.plan, self.module)

    def test_mismatched_intrinsic_signature_rejected(self):
        self.module["intrinsic_calls"]["calculate"][0]["type"] = "i128 (i128)"
        with self.assertRaisesRegex(ValueError, "exact parsed call"):
            m.typed_scope_plan(self.plan, self.module)

    def test_unknown_llvm_name_not_prefix_ignored(self):
        self.plan["unresolved"][0]["detail"] = "llvm.fake.i64"
        self.plan["graph"]["calls"]["calculate"] = ["llvm.fake.i64"]
        with self.assertRaisesRegex(ValueError, "typed call graph"):
            m.typed_scope_plan(self.plan, self.module)

    def test_other_relevant_issue_still_blocks(self):
        self.plan["unresolved"].append({"kind": "inline_assembly", "symbol": "calculate", "detail": "unresolved", "relevant": True})
        self.assertEqual(m.typed_scope_plan(self.plan, self.module)["status"], "needs_review")

    def test_data_risks_still_block(self):
        self.plan["data_risks"] = [{"global": "data"}]
        self.assertEqual(m.typed_scope_plan(self.plan, self.module)["status"], "needs_review")

    def test_defined_edge_missing_from_text_parser_rejected(self):
        self.module["graph"]["calculate"].append("helper")
        with self.assertRaisesRegex(ValueError, "typed call graph"):
            m.typed_scope_plan(self.plan, self.module)

    def test_intrinsics_never_become_selected_definition_nodes(self):
        result = m.typed_scope_plan(self.plan, self.module)
        chosen = m.choose_scope(self.module, result, ["calculate"])
        request = SimpleNamespace(RustIRRequest=mock.Mock(return_value=True))
        m.build_mapper_request(request, file(Path("C:/owned/normalized.ll")), self.module, chosen, object())
        self.assertEqual(request.RustIRRequest.call_args.args[4], {"calculate": ()})


class ReaderTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="cargo-generic-ir-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        (self.root / ".runs/defense-loop").mkdir(parents=True)
        self.reader = m.Reader(self.root)
        self.path = self.root / ".runs/input.ll"
        self.path.write_bytes(b"owned inert IR text")
        self.item = file(self.path, "owned inert IR text")

    def test_file_change_invalidates_consumption_and_recheck(self):
        self.reader.read(self.item)
        self.path.write_bytes(b"modified")
        with self.assertRaisesRegex(ValueError, "descriptor changed"):
            self.reader.recheck()

    def test_hardlinked_source_rejected_but_explicit_cargo_artifact_copy_allowed(self):
        os.link(self.path, self.root / ".runs/alias.ll")
        with self.assertRaisesRegex(ValueError, "hardlinked"):
            self.reader.read(self.item)
        self.assertEqual(self.reader.read(self.item, hardlinks=True), b"owned inert IR text")

    def test_received_and_sensitive_dump_paths_rejected_without_read(self):
        for suffix in ("rea-analysis-reports/input.ll", ".runs/env.setting", ".runs/attackerfolder/input.ll",
                       ".runs/LINKREPRO/input.ll", ".runs/shared/input.ll"):
            with self.subTest(suffix=suffix), mock.patch.object(Path, "read_bytes", side_effect=AssertionError("must not read")), \
                    self.assertRaisesRegex(ValueError, "received/environment"):
                self.reader.read(file(self.root / suffix))

    def test_stop_blocks_before_any_process_and_preserves_terminal_report(self):
        self.reader.stop.write_text("STOP")
        with mock.patch("subprocess.Popen", side_effect=AssertionError("no process")), self.assertRaisesRegex(ValueError, "STOP"):
            m.prepare_capture(self.path, self.item["sha256"], self.path, self.item["sha256"],
                workspace_root=self.root, output_dir=self.root / ".runs/new",
                trusted_engine_pins={}, source_environment={}, compiler_environment={})
        receipt = self.reader.write(self.root / ".runs/terminal.json", b'{"status":"stopped"}', terminal=True)
        self.assertEqual(receipt["sha256"], m.digest(b'{"status":"stopped"}'))
        self.assertTrue(self.reader.stop.exists())

    def test_fresh_output_cannot_overwrite_existing_input(self):
        with self.assertRaisesRegex(ValueError, "fresh output"):
            self.reader.write(self.path, b"changed")
        self.assertEqual(self.path.read_bytes(), b"owned inert IR text")

    def test_unowned_path_and_boolean_byte_count_rejected(self):
        with self.assertRaisesRegex(ValueError, "outside owned"):
            self.reader.read(file(self.root.parent / "other.ll"))
        with self.assertRaisesRegex(ValueError, "strict byte"):
            self.reader.read({**self.item, "bytes": True})

    def test_watched_case_variants_keep_one_original_spelling(self):
        self.reader.read(self.item)
        variant = {**self.item, "path": self.item["path"].upper()}
        self.reader.read(variant)
        self.assertEqual(len(self.reader.watched), 1)
        row = next(iter(self.reader.watched.values()))
        self.assertEqual(row["path"], self.item["path"])

    def test_watched_case_variant_cannot_change_pin_or_count(self):
        self.reader.read(self.item)
        for changes in ({"sha256": "b" * 64}, {"bytes": self.item["bytes"] + 1}):
            variant = {**self.item, "path": self.item["path"].upper(), **changes}
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "conflicting hash/count"):
                self.reader.remember_verified(variant, owned=True, hardlinks=False)

    def test_preloaded_production_is_rejected_before_any_import(self):
        with mock.patch.dict(sys.modules, {"antirea": SimpleNamespace(__file__="C:/other/antirea.py")}), \
                mock.patch.object(m.importlib.util, "spec_from_file_location",
                                  side_effect=AssertionError("must not load")):
            with self.assertRaisesRegex(ValueError, "preloaded production"):
                m.load_production(self.reader, {})

    def test_preloaded_same_path_production_is_still_rejected(self):
        # A same-path object without complete spec/origin is not an accepted preload.
        with mock.patch.dict(sys.modules, {"antirea": SimpleNamespace(__file__=str(self.root / "antirea/__init__.py"))}):
            with self.assertRaisesRegex(ValueError, "preloaded production"):
                m.load_production(self.reader, {})

    def test_changed_engine_pin_fails_before_package_import(self):
        package = self.root / "antirea"
        package.mkdir()
        entry = package / "__init__.py"
        entry.write_bytes(b"# owned inert package\n")
        pin = file(entry, "# different reviewed bytes\n")
        # Remove prior modules only from the temporary test view, not real state.
        module_view = {key: value for key, value in sys.modules.items()
                       if key != "antirea" and not key.startswith("antirea.")
                       and key not in ("antirea_generic_cargo_semantic", "antirea_generic_cargo_mapper")}
        with mock.patch.object(m.sys, "modules", module_view), \
                mock.patch.object(m.importlib.util, "spec_from_file_location",
                                  side_effect=AssertionError("must not load")):
            with self.assertRaisesRegex(ValueError, "descriptor changed"):
                m.load_production(self.reader, m.pin_index([pin]))


class MockPipelineTests(unittest.TestCase):
    """Full orchestration/JSON handoff with LLVM, imports and processes mocked.

    This tests ordering and receipt shape, not real LLVM/Cargo/cleanup evidence.
    """

    def test_successful_three_crate_pipeline_retains_checked_evidence_and_json_handoff(self):
        with tempfile.TemporaryDirectory(prefix="generic-ir-v2-") as temporary, ExitStack() as stack:
            root = Path(temporary).resolve()
            runs = root / ".runs"
            runs.mkdir()
            (runs / "defense-loop").mkdir()
            llvm = root / ".tools/llvm"
            (llvm / "bin").mkdir(parents=True)
            windows = root / "Windows"
            (windows / "System32").mkdir(parents=True)
            scratch = runs / "llvm-temp"
            scratch.mkdir()
            package = root / "antirea"
            package.mkdir()
            (package / "__init__.py").write_bytes(b"# inert package, never imported\n")
            capture, inner = fixture()
            def relocate(value):
                if isinstance(value, str):
                    return value.replace("C:\\owned\\workspace", str(root)).replace("C:/owned/workspace", root.as_posix())
                if isinstance(value, list):
                    return [relocate(item) for item in value]
                if isinstance(value, dict):
                    return {key: relocate(item) for key, item in value.items()}
                return value
            capture, inner = relocate(capture), relocate(inner)
            inspection = inner["inspection"]
            for index, item in enumerate(inspection["input_snapshot"]["files"]):
                path = Path(item["path"])
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(("source" + str(index)).encode())
            for mode in ("original", "derivative"):
                for index, unit in enumerate(capture["arms"][mode]["artifacts"]["units"]):
                    if unit["llvm_ir"]:
                        item = unit["llvm_ir"]
                        path = Path(item["path"])
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(("owned scalar IR" + str(index)).encode())
            config_path = root / ".tools/kagura-toolchain.json"
            config_path.write_bytes(m.canonical({"schema_version": 1, "target": m.TARGET, "llvm_root": str(llvm)}))
            for name in ("opt.exe", "llvm-link.exe", "LLVM-C.dll", "rustc.exe"):
                (llvm / "bin" / name).write_bytes(("inert " + name).encode())
            helper_paths = [root / m.SEMANTIC, root / m.MAPPER, root / m.NORMALIZER, root / m.QUALIFIER]
            for path in helper_paths:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"# inert reviewed helper, never imported\n")
            for name in (*m.PACKAGE_ROLES, "swift_frontend"):
                path = package / (name + ".py")
                if not path.exists():
                    path.write_bytes(b"# inert reviewed role, never imported\n")
            def actual(path):
                raw = path.read_bytes()
                return {"path": str(path), "sha256": m.digest(raw), "bytes": len(raw)}
            inspection["toolchain"]["selection"]["rustc"] = str(llvm / "bin/rustc.exe")
            inspection["toolchain"]["compiler_inputs"] = {str(llvm / "bin/rustc.exe"): actual(llvm / "bin/rustc.exe")["sha256"]}
            reseal(inspection)
            inner_path = runs / "metadata-plan.json"
            inner_path.write_bytes(m.canonical(inner))
            capture_plan = runs / "capture-plan.json"
            capture_plan.write_bytes(b"{}")
            capture["capture_plan"] = actual(capture_plan)
            capture_path = runs / "capture.json"
            capture_path.write_bytes(m.canonical(capture))
            pin_paths = [Path(m.__file__).resolve(), *package.glob("*.py"), config_path,
                         *(llvm / "bin" / name for name in ("opt.exe", "llvm-link.exe", "LLVM-C.dll"))]
            pins = {str(path): actual(path)["sha256"] for path in pin_paths}
            recipe = {unit["unit"]: {"original_argv": ["rustc", "original"],
                       "forwarded_argv": ["rustc", "--crate-name", unit["target_name"]], "cwd": str(root / "project")}
                      for unit in capture["arms"]["derivative"]["artifacts"]["units"]}
            authenticated = {"derivative": recipe, "original": {}}
            whole = parsed()
            # Cross-crate definitions must have external linkage. Independent
            # repeated local names are covered by QualificationTests below.
            for signature in whole["definitions"].values():
                signature["linkage"] = 0
            names = list(whole["definitions"])
            parts = []
            for name in names:
                part = parsed(())
                for field in ("definitions", "graph", "calls"):
                    part[field] = {name: copy.deepcopy(whole[field][name])}
                part["declarations"] = {callee: copy.deepcopy(whole["definitions"][callee])
                                        for callee in whole["graph"][name]}
                parts.append(part)
            def fake_inspect(_mapper, _library, raw, **options):
                self.assertEqual(options["workspace_root"], root)
                self.assertEqual(options["trusted_engine_pins"], pins)
                if raw == b"linked mock IR":
                    return copy.deepcopy(whole)
                return copy.deepcopy(parts[int(raw.decode()[-1])])
            def fake_normalize(request, **options):
                self.assertEqual(options["trusted_engine_pins"], pins)
                self.assertEqual(set(request.selected_functions), set(names))
                self.assertEqual(request.public_exports, ("calculate",))
                self.assertEqual(request.input_ir.name, "module.normalized.ll")
                return b"mapped mock IR", {"schema_version": 1, "exact_restore_roundtrip": True,
                    "calling_convention_rewritten": False, "vm_applied": False,
                    "intrinsic_contract_preserved": True, "intrinsic_backend_validated": False,
                    "input_sha256": request.input_sha256, "output_sha256": m.digest(b"mapped mock IR"),
                    "intrinsic_declarations": {},
                    "source_selected_functions": sorted(request.selected_functions),
                    "source_graph": copy.deepcopy(whole["graph"]),
                    "functions": {name: {"source_symbol": name, "protected_symbol": name}
                                  for name in request.selected_functions},
                    "protected_selected_functions": list(request.selected_functions),
                    "exported_functions": list(request.public_exports),
                    "provenance": {"frontend_flags": request.provenance.frontend_flags,
                        "evidence_files": [{"path": str(row.path), "sha256": row.sha256}
                                           for row in request.provenance.evidence_files]}}
            mapper = SimpleNamespace(
                PinnedFile=lambda path, sha256: SimpleNamespace(path=path, sha256=sha256),
                RustSourceProvenance=lambda comp, src, evidence, flags, **kw:
                    SimpleNamespace(compiler_inputs=comp, source_inputs=src, evidence_files=evidence,
                                    frontend_flags=flags, **kw),
                RustIRRequest=lambda path, sha256, selected, exports, graph, provenance:
                    SimpleNamespace(input_ir=path, input_sha256=sha256, selected_functions=selected,
                                    public_exports=exports, expected_calls=graph, provenance=provenance),
                normalize_protection_ir=fake_normalize)
            scope = SimpleNamespace(analyze_scope=lambda *a, **k: {"status": "ready",
                "selected_functions": names, "boundary_functions": {}, "max_functions": 64,
                "graph": {"calls": whole["graph"]}, "unresolved": [], "data_risks": []})
            events = []
            def fake_qualify(units, **options):
                self.assertEqual(events, [])
                events.append("qualify")
                raw = tuple(Path(unit["input"]["path"]).read_bytes() for unit in units)
                original = [copy.deepcopy(parts[int(value.decode()[-1])]) for value in raw]
                engine = {m.path_key(path): actual(Path(path)) for path in options["trusted_engine_pins"]}
                _, receipt = qualification_receipt(units, original, raw, engine)
                return raw, receipt
            qualifier = SimpleNamespace(qualify_modules=fake_qualify)
            def fake_scalar_normalize(raw, **options):
                self.assertEqual(events, ["qualify", "link"])
                self.assertEqual(raw, b"linked mock IR")
                self.assertEqual(options["trusted_engine_pins"], pins)
                self.assertEqual(options["public_exports"], ("calculate",))
                self.assertEqual(options["expected_raw_sha256"], m.digest(raw))
                events.append("normalize")
                receipt = normalization_fixture(before=whole)
                receipt["inputs_before"] = dict(pins)
                receipt["inputs_after"] = dict(pins)
                return b"normalized mock IR", receipt
            normalizer = SimpleNamespace(normalize_ir=fake_scalar_normalize)
            metadata = SimpleNamespace(verify_plan=mock.Mock(return_value={"metadata_succeeded": True}),
                                       _clean=lambda result: result["mock_cleanup"] is True)
            imports = []
            def fake_import(reader, engine):
                self.assertTrue(set(engine) <= set(reader.watched))
                imports.append("after_pinning")
                return {"rust_cargo": metadata, "scope": scope, "process": SimpleNamespace(run_logged=None),
                        "rust_cargo_semantic": semantic, "rust_ir": mapper, "rust_normalize": normalizer,
                        "rust_qualify": qualifier, "_source_imports": []}
            def fake_runner(argv, cwd, prefix, **options):
                self.assertEqual(Path(argv[0]).name, "llvm-link.exe")
                self.assertEqual([Path(item).name for item in argv[2:-2]],
                                 ["crate-000.qualified.ll", "crate-001.qualified.ll", "crate-002.qualified.ll"])
                events.append("link")
                self.assertEqual(set(options["env"]), {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP"})
                self.assertLessEqual(options["timeout"], 30)
                self.assertEqual(options["cancel_file"], runs / "defense-loop/STOP")
                destination = Path(argv[-1])
                destination.write_bytes(Path(argv[-3]).read_bytes() if Path(argv[0]).name == "opt.exe" else b"linked mock IR")
                result = {"argv": argv, "stdout": str(prefix) + ".stdout.log",
                          "stderr": str(prefix) + ".stderr.log", "mock_cleanup": True}
                Path(result["stdout"]).write_bytes(b"")
                Path(result["stderr"]).write_bytes(b"")
                Path(str(prefix) + ".process.json").write_bytes(m.canonical(result))
                return result
            stack.enter_context(mock.patch("subprocess.Popen", side_effect=AssertionError("no actual process")))
            stack.enter_context(mock.patch.object(m, "load_production", side_effect=fake_import))
            loaded = [{"module": "antirea", "path": str(package / "__init__.py"),
                       "sha256": pins[str(package / "__init__.py")]}]
            loaded += [{"module": "antirea." + name, "path": str(package / (name + ".py")),
                        "sha256": pins[str(package / (name + ".py"))]}
                       for name in (*m.PACKAGE_ROLES, "swift_frontend")]
            stack.enter_context(mock.patch.object(m, "check_loaded_modules", return_value=loaded))
            stack.enter_context(mock.patch.object(m, "authenticate", return_value=authenticated))
            stack.enter_context(mock.patch.object(m, "inspect_ir", side_effect=fake_inspect))
            stack.enter_context(mock.patch.object(m, "inspect_scalar_ir", return_value=copy.deepcopy(whole)))
            environment = {"SYSTEMROOT": str(windows), "WINDIR": str(windows),
                           "PATH": str(llvm / "bin") + ";" + str(windows / "System32"),
                           "TEMP": str(scratch), "TMP": str(scratch)}
            output = runs / "prepared"
            result = m.prepare_capture(capture_path, actual(capture_path)["sha256"], inner_path,
                actual(inner_path)["sha256"], workspace_root=root, output_dir=output,
                trusted_engine_pins=pins, source_environment={}, compiler_environment=environment,
                runner=fake_runner)
            self.assertEqual(result["status"], "cargo_ir_prepared_unlinked_unvalidated", result)
            self.assertEqual(imports, ["after_pinning"])
            self.assertEqual(len(result["commands"]), 1)
            self.assertEqual(events, ["qualify", "link", "normalize"])
            self.assertTrue(result["inputs_unchanged"])
            self.assertFalse(result["object_handoff"]["object_pipeline_executed"])
            self.assertFalse(result["target_executed"])
            self.assertEqual(len(result["reviewed_engine_inputs"]), len(pins))
            self.assertEqual(result["llvm_environment"]["sha256"], m.digest(m.canonical(environment)))
            self.assertEqual(m.canonical(m.json_bytes((output / "preparation.json").read_bytes())), m.canonical(result))
            mapping = m.json_bytes(Path(result["lineage"]["mapping"]["path"]).read_bytes())
            self.assertIsInstance(mapping["provenance"]["frontend_flags"], list)
            checked = m.pin_index(result["checked_inputs"])
            for role in ("qualification", "qualified_linked_ir", "canonical_linked_ir", "normalized_ir", "normalization",
                         "mapped_ir", "mapping", "source_context"):
                self.assertIn(m.path_key(result["lineage"][role]["path"]), checked)
            self.assertNotIn("raw_linked_ir", result["lineage"])
            self.assertEqual(result["source_ir_kind"], "qualified_raw_linked_baseline")
            self.assertEqual(result["object_handoff"]["source_ir"], result["lineage"]["qualified_linked_ir"])
            self.assertEqual(result["object_handoff"]["source_ir_kind"], result["source_ir_kind"])
            self.assertEqual(len(result["source_definition_lineage"]), 3)
            for row in result["lineage"]["crates"]:
                self.assertEqual(Path(row["raw_copy"]["path"]).read_bytes(), Path(row["captured_ir"]["path"]).read_bytes())
                self.assertNotEqual(row["raw_copy"]["path"], row["qualified_ir"]["path"])
            self.assertEqual(result["object_handoff"]["normalized_ir"], result["lineage"]["normalized_ir"])
            self.assertEqual(result["object_handoff"]["call_provenance"],
                             result["normalization_gate"]["call_provenance"])
            self.assertEqual(result["preparation_revision"], 5)
            # Saved JSON consumer uses the independent parent gates, not the
            # producer's in-memory objects. Only compiler/auth/parser seams are
            # mocked; the byte/owner/lineage/provenance checks execute normally.
            arguments = dict(capture_path=capture_path, capture_sha256=actual(capture_path)["sha256"],
                plan_path=inner_path, plan_sha256=actual(inner_path)["sha256"], workspace_root=root,
                trusted_engine_pins=pins, source_environment={}, compiler_environment=environment)
            report_path = output / "preparation.json"
            checked = m.verify_preparation_receipt(report_path, actual(report_path)["sha256"], **arguments)
            self.assertEqual(checked["status"], "preparation_receipt_rechecked_unlinked_unvalidated")
            self.assertEqual(checked["selected_functions"], result["object_handoff"]["selected_functions"])
            self.assertFalse(checked["independent_llvm_reexecution"])
            saved_report = report_path.read_bytes()
            for label in ("baseline", "owner", "normalized_hash", "source_evidence", "command_order"):
                changed = copy.deepcopy(result)
                if label == "baseline":
                    changed["object_handoff"]["source_ir"] = changed["lineage"]["normalized_ir"]
                elif label == "owner":
                    changed["lineage"]["crates"][0]["owner"]["unit"] = "foreign"
                elif label == "normalized_hash":
                    changed["lineage"]["normalized_ir"]["sha256"] = "0" * 64
                elif label == "source_evidence":
                    changed["source_definition_lineage"] = []
                else:
                    changed["commands"][0]["argv"][2:5] = list(reversed(changed["commands"][0]["argv"][2:5]))
                report_path.write_bytes(m.canonical(changed))
                with self.subTest(mutation=label), self.assertRaises(ValueError):
                    m.verify_preparation_receipt(report_path, actual(report_path)["sha256"], **arguments)
                report_path.write_bytes(saved_report)



class PackageImportTests(unittest.TestCase):
    """Source-only fixture imports; no LLVM or process is permitted."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="cargo-prepare-package-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.package = self.root / "antirea"
        self.package.mkdir()
        (self.root / ".runs/defense-loop").mkdir(parents=True)
        self.reader = m.Reader(self.root)
        self.sources = {"__init__": "SOURCE_ONLY = True\n"}
        self.sources.update({name: "ROLE = " + repr(name) + "\n" for name in m.PACKAGE_ROLES})
        for name, text in self.sources.items():
            (self.package / (name + ".py")).write_text(text, encoding="utf-8")
        self.pins = self.snapshot()
        # Only the owned test view is isolated. Production never clears caches.
        view = {name: module for name, module in sys.modules.items()
                if name != "antirea" and not name.startswith("antirea.")}
        self.modules_patch = mock.patch.object(m.sys, "modules", view)
        self.modules_patch.start()
        self.addCleanup(self.modules_patch.stop)
        self.no_process = mock.patch("subprocess.Popen", side_effect=AssertionError("no process"))
        self.no_process.start()
        self.addCleanup(self.no_process.stop)

    def snapshot(self):
        return m.pin_index([{"path": str(path), "sha256": m.digest(path.read_bytes())}
                            for path in self.package.rglob("*.py")])

    def add_source(self, name, text):
        path = self.package / (name + ".py")
        path.write_text(text, encoding="utf-8")
        self.pins = self.snapshot()
        return path

    def poison_cache(self, path):
        target = Path(importlib.util.cache_from_source(str(path)))
        target.parent.mkdir(exist_ok=True)
        header = (importlib.util.MAGIC_NUMBER + struct.pack("<III", 0, int(path.stat().st_mtime),
                                                          path.stat().st_size))
        code = compile("raise AssertionError('unreviewed bytecode cache executed')", str(path), "exec")
        target.write_bytes(header + marshal.dumps(code))

    def test_all_fixed_roles_import_from_reviewed_source(self):
        before_path, before_meta = list(sys.path), list(sys.meta_path)
        result = m.load_production(self.reader, self.pins)
        self.assertEqual(set(result), {*m.PACKAGE_ROLES, "_source_imports"})
        self.assertEqual({row["module"] for row in result["_source_imports"]},
                         {"antirea", *("antirea." + name for name in m.PACKAGE_ROLES)})
        self.assertTrue(all(row["loader"] == "verified_source_bytes_no_bytecode_cache"
                            for row in result["_source_imports"]))
        self.assertEqual(sys.path, before_path)
        self.assertEqual(sys.meta_path, before_meta)

    def test_complete_canonical_preload_is_reused_not_purged(self):
        first = m.load_production(self.reader, self.pins)
        second = m.load_production(self.reader, self.pins)
        self.assertEqual(second["_source_imports"], [])
        for role in m.PACKAGE_ROLES:
            self.assertIs(second[role], first[role])

    def test_forged_valid_timestamp_caches_are_never_read(self):
        for name in ("__init__", "rust_ir", "rust_cargo_semantic"):
            self.poison_cache(self.package / (name + ".py"))
        result = m.load_production(self.reader, self.pins)
        self.assertEqual(result["rust_ir"].ROLE, "rust_ir")
        self.assertTrue(sys.modules["antirea"].SOURCE_ONLY)

    def test_transitive_dependency_uses_same_source_snapshot(self):
        leaf = self.add_source("local_leaf", "VALUE = 27\n")
        self.add_source("rust_cargo", "from .local_leaf import VALUE\n")
        self.poison_cache(leaf)
        result = m.load_production(self.reader, self.pins)
        self.assertEqual(result["rust_cargo"].VALUE, 27)
        self.assertIn("antirea.local_leaf", {row["module"] for row in result["_source_imports"]})

    def test_missing_recursive_source_pin_blocks_before_import(self):
        nested = self.package / "sub"
        nested.mkdir()
        (nested / "__init__.py").write_bytes(b"OWNED = True\n")
        with self.assertRaisesRegex(ValueError, "complete production"):
            m.load_production(self.reader, self.pins)
        self.assertNotIn("antirea", sys.modules)

    def test_changed_source_pin_blocks_before_import(self):
        (self.package / "rust_ir.py").write_bytes(b"CHANGED = True\n")
        with self.assertRaisesRegex(ValueError, "descriptor changed"):
            m.load_production(self.reader, self.pins)
        self.assertNotIn("antirea", sys.modules)

    def test_unknown_namespace_dependency_fails_and_rolls_back(self):
        self.add_source("rust_cargo", "from . import unreviewed_plugin\n")
        old_path, old_meta = list(sys.path), list(sys.meta_path)
        with self.assertRaisesRegex(ValueError, "unknown/ambiguous"):
            m.load_production(self.reader, self.pins)
        self.assertFalse(any(name == "antirea" or name.startswith("antirea.") for name in sys.modules))
        self.assertEqual(sys.path, old_path)
        self.assertEqual(sys.meta_path, old_meta)

    def test_partial_preload_none_or_initializing_is_rejected(self):
        for mode in ("none", "no_spec", "initializing"):
            item = None
            if mode != "none":
                item = SimpleNamespace(__file__=str(self.package / "rust_ir.py"))
                if mode == "initializing":
                    item.__spec__ = SimpleNamespace(origin=item.__file__, _initializing=True)
            sys.modules["antirea.rust_ir"] = item
            try:
                with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, "partial preloaded"):
                    m.load_production(self.reader, self.pins)
                self.assertIs(sys.modules["antirea.rust_ir"], item)
            finally:
                sys.modules.pop("antirea.rust_ir", None)

    def test_foreign_preload_is_not_removed_by_failure(self):
        foreign = SimpleNamespace(__file__="C:/foreign/rust_ir.py",
                                  __spec__=SimpleNamespace(origin="C:/foreign/rust_ir.py"))
        sys.modules["antirea.rust_ir"] = foreign
        with self.assertRaisesRegex(ValueError, "preloaded production"):
            m.load_production(self.reader, self.pins)
        self.assertIs(sys.modules["antirea.rust_ir"], foreign)

    def test_successful_import_cannot_add_unpinned_package_source(self):
        text = ("from pathlib import Path\n"
                "Path(__file__).with_name('added.py').write_text('VALUE = 1\\n')\n")
        self.add_source("rust_cargo", text)
        with self.assertRaisesRegex(ValueError, "complete production"):
            m.load_production(self.reader, self.pins)
        self.assertFalse(any(name == "antirea" or name.startswith("antirea.") for name in sys.modules))

    def test_failed_import_preserves_preexisting_complete_module(self):
        first = m.load_production(self.reader, self.pins)
        retained = first["rust_ir"]
        # Construct a second owned request with one role absent from its cache,
        # while the reviewed source itself remains unchanged.
        removed = sys.modules.pop("antirea.rust_cargo")
        delattr(sys.modules["antirea"], "rust_cargo")
        with mock.patch.object(m.importlib, "import_module", side_effect=ValueError("owned import failed")):
            with self.assertRaisesRegex(ValueError, "owned import failed"):
                m.load_production(self.reader, self.pins)
        self.assertIs(sys.modules["antirea.rust_ir"], retained)
        self.assertNotIn("antirea.rust_cargo", sys.modules)
        self.assertIsNotNone(removed)

    def test_verified_parser_entry_receives_explicit_engine_authority(self):
        fake = SimpleNamespace(open_llvm=mock.Mock(side_effect=RuntimeError("parser sentinel")))
        pins = {"owned-pin": "a" * 64}
        for function, args in ((m.inspect_ir, (fake, Path("C:/owned/LLVM-C.dll"), b"IR")),
                               (m.inspect_scalar_ir, (fake, Path("C:/owned/LLVM-C.dll"), b"IR", ["entry"]))):
            with self.subTest(function=function.__name__), self.assertRaisesRegex(RuntimeError, "parser sentinel"):
                function(*args, workspace_root=self.root, trusted_engine_pins=pins)
            self.assertEqual(fake.open_llvm.call_args.kwargs,
                             {"workspace_root": self.root, "llvm_library": Path("C:/owned/LLVM-C.dll"),
                              "trusted_engine_pins": pins})



if __name__ == "__main__":
    unittest.main()
