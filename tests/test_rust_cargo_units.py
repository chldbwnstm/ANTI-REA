"""Cargo unit/receipt regression tests. No Cargo/compiler/target subprocess."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from antirea import rust_cargo_units as m


def args(root):
    return ["--crate-name", "rules", "--edition=2021", "src/lib.rs", "--crate-type", "lib",
            "--target", m.TARGET,
            "--emit=dep-info,metadata,link", "-C", "opt-level=2", "-C", "overflow-checks=on",
            "--cfg", 'feature="alternate"', "-C", "panic=abort", "-C", "embed-bitcode=yes",
            "-Ccodegen-units=16", "-C", "metadata=opaque_cargo_identity", "-Cextra-filename=-123abc",
            "--out-dir", str(root / "debug" / "deps"), "-L", "dependency=" + str(root / "debug" / "deps")]


class RecipeTests(unittest.TestCase):
    def test_original_forwarded_unchanged(self):
        original = args(Path("C:/owned/original/target"))
        self.assertEqual(m.derive_recipe(original, "original")["forwarded_argv"], original)
        self.assertEqual(m.derive_recipe(original, "original")["changes"], [])

    def test_derivative_changes_only_explicit_recipe(self):
        original = args(Path("C:/owned/derivative/target"))
        derived = m.derive_recipe(original, "derivative")
        output = derived["forwarded_argv"]
        self.assertIn("--emit=dep-info,metadata,link,llvm-ir", output)
        self.assertEqual(output[-3:], ["-Cno-prepopulate-passes", "-Cembed-bitcode=no", "-Ccodegen-units=1"])
        for unchanged in ("opt-level=2", "overflow-checks=on", "panic=abort", 'feature="alternate"', "metadata=opaque_cargo_identity"):
            self.assertIn(unchanged, output)
        self.assertNotIn("embed-bitcode=yes", output)
        self.assertNotIn("-Ccodegen-units=16", output)
        self.assertEqual(len(derived["changes"]), 6)

    def test_probes_are_not_rewritten(self):
        probes = [["-vV"], ["--crate-name", "___", "--print=file-names", "--crate-type", "bin", "-", "--print=cfg"]]
        for probe in probes:
            with self.subTest(probe=probe):
                self.assertEqual(m.derive_recipe(probe, "derivative"), {"kind": "probe", "forwarded_argv": probe, "changes": []})

    def test_response_unknown_or_ambiguous_probe_rejected(self):
        for value in (["@unowned.rsp"], ["--future-option"], ["--print=link-args", "file.rs"], ["-vV", "file.rs"]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                m.derive_recipe(value, "derivative")

    def test_buildscript_procmacro_test_units_rejected(self):
        for kind in ("bin", "proc-macro"):
            value = args(Path("C:/owned/target"))
            value[value.index("--crate-type") + 1] = kind
            with self.assertRaises(ValueError):
                m.derive_recipe(value, "original")
        with self.assertRaises(ValueError):
            m.derive_recipe(args(Path("C:/owned/target")) + ["--test"], "original")

    def test_repeated_crate_types_preserve_original_tokens(self):
        value = args(Path("C:/owned/target"))
        value[value.index("--crate-type") + 1] = "rlib"
        value += ["--crate-type", "cdylib"]
        self.assertEqual(m.derive_recipe(value, "original")["forwarded_argv"], value)
        transformed = m.derive_recipe(value, "derivative")["forwarded_argv"]
        self.assertEqual(transformed.count("--crate-type"), 2)
        self.assertIn("rlib", transformed)
        self.assertIn("cdylib", transformed)

    def test_duplicate_or_forbidden_repeated_crate_types_rejected(self):
        for extra in ("lib", "proc-macro", "bin", "test"):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                m.derive_recipe(args(Path("C:/owned/target")) + ["--crate-type", extra], "original")

    def test_missing_repeated_foreign_and_json_targets_rejected(self):
        original = args(Path("C:/owned/target"))
        at = original.index("--target")
        values = [original[:at] + original[at + 2:], original + ["--target", m.TARGET]]
        for target in ("aarch64-pc-windows-msvc", "x86_64-unknown-linux-gnu", "C:/outside/custom.json"):
            changed = list(original)
            changed[at + 1] = target
            values.append(changed)
        for value in values:
            for mode in ("original", "derivative"):
                with self.subTest(value=value, mode=mode), self.assertRaisesRegex(ValueError, "target"):
                    m.derive_recipe(value, mode)

    def test_print_probe_fixed_target_is_optional_but_not_foreign_or_repeated(self):
        for value in (["--print=cfg"], ["--print=cfg", "--target", m.TARGET]):
            self.assertEqual(m.derive_recipe(value, "derivative")["forwarded_argv"], value)
        for value in (["--print=cfg", "--target=C:/outside/custom.json"],
                      ["--print=cfg", "--target", m.TARGET, "--target", m.TARGET]):
            with self.assertRaisesRegex(ValueError, "target"):
                m.derive_recipe(value, "original")

    def test_explicit_emit_destinations_not_dropped(self):
        value = args(Path("C:/owned/target"))
        value[value.index("--emit=dep-info,metadata,link")] = "--emit=link,dep-info=outside.d"
        for mode in ("original", "derivative"):
            with self.assertRaises(ValueError):
                m.derive_recipe(value, mode)

    def test_arbitrary_link_arguments_backend_and_native_library_not_forwarded(self):
        for option in ("-Clink-arg=outside.exe", "-Ccodegen-backend=outside.dll", "-loutside"):
            with self.subTest(option=option), self.assertRaises(ValueError):
                m.derive_recipe(args(Path("C:/owned/target")) + [option], "original")

    def test_wrapper_vector_crosscheck_does_not_execute_or_verify_producer(self):
        vectors = [{"input": value, "sha256": hashlib.sha256(value.encode()).hexdigest()} for value in m.SHA_SAMPLES]
        self.assertFalse(m.verify_wrapper_selftest(vectors)["producer_verified"])
        vectors[-1]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            m.verify_wrapper_selftest(vectors)

    def test_inspector_ascii_digest_is_distinct_from_record_utf8_digest(self):
        env = {"Path": "C:/tool/한글"}
        self.assertNotEqual(m.environment_digest(env), m.inspector_environment_digest(env))
        expected = hashlib.sha256(json.dumps({"PATH": env["Path"]}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
        self.assertEqual(m.inspector_environment_digest(env), expected)

    def test_fixed_linker_spelling_is_preserved_by_both_recipes(self):
        original = args(Path("C:/owned/target")) + ["-C", "linker=C:/trusted/link.exe"]
        policy = {"linker": "C:/trusted/link.exe", "linker_sha256": "a" * 64}
        for mode in ("original", "derivative"):
            forwarded = m.derive_recipe(original, mode)["forwarded_argv"]
            m.validate_linker_args(m.parse_rustc_args(forwarded), policy)
            self.assertIn("linker=C:/trusted/link.exe", forwarded)
            at = forwarded.index("linker=C:/trusted/link.exe")
            self.assertEqual(forwarded[at - 1], "-C")

    def test_crate_linker_missing_foreign_repeated_or_empty_rejected(self):
        policy = {"linker": "C:/trusted/link.exe", "linker_sha256": "a" * 64}
        for suffix in ([], ["-Clinker=C:/foreign/link.exe"], ["-Clinker="],
                       ["-Clinker=C:/trusted/link.exe", "-C", "linker=C:/trusted/link.exe"]):
            with self.subTest(suffix=suffix), self.assertRaisesRegex(ValueError, "linker"):
                m.validate_linker_args(m.parse_rustc_args(args(Path("C:/owned/target")) + suffix), policy)

    def test_probe_linker_optional_but_never_foreign_or_repeated(self):
        policy = {"linker": "C:/trusted/link.exe", "linker_sha256": "a" * 64}
        for suffix, accepted in (([], True), (["-Clinker=C:/trusted/link.exe"], True),
                (["-Clinker=C:/foreign/link.exe"], False),
                (["-Clinker=C:/trusted/link.exe", "-Clinker=C:/trusted/link.exe"], False)):
            parsed = m.parse_rustc_args(["--print=cfg", *suffix])
            with self.subTest(suffix=suffix):
                if accepted:
                    m.validate_linker_args(parsed, policy)
                else:
                    with self.assertRaisesRegex(ValueError, "linker"):
                        m.validate_linker_args(parsed, policy)


class RecordTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cargo-unit-draft-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "source"
        (self.source / "src").mkdir(parents=True)
        (self.source / "src" / "lib.rs").write_text("pub fn owned() {}")
        self.tools = {}
        for name in ("backend", "wrapper", "linker"):
            path = self.root / (name + ".exe")
            path.write_bytes(b"inert mock tool")
            self.tools[name] = {"path": str(path), "sha256": m.file_hash(path)}

    def arm(self, mode):
        root = self.root / mode
        (root / "target" / "debug" / "deps").mkdir(parents=True, exist_ok=True)
        (root / "units").mkdir(exist_ok=True)
        policy = {"mode": mode, "record_root": str(root / "units"), "target_root": str(root / "target")}
        for kind, tool in self.tools.items():
            policy[kind], policy[kind + "_sha256"] = tool["path"], tool["sha256"]
        controls = {"RUSTC": policy["backend"], "RUSTC_WRAPPER": policy["wrapper"],
                    "CARGO_TARGET_DIR": policy["target_root"], "ANTIREA_RUST_UNIT_POLICY": str(root / "wrapper-policy.txt")}
        return {"policy": policy, "policy_sha256": "a" * 64, "environment_overrides": controls,
                "argv": [str(self.root / "cargo.exe"), "build", "--profile", "dev"],
                "recorded_sources": [str(self.source / "src" / "lib.rs")]}

    def record(self, arm):
        original = args(Path(arm["policy"]["target_root"]))
        original += ["-C", "linker=" + self.tools["linker"]["path"]]
        result = m.derive_recipe(original, arm["policy"]["mode"])
        env = dict(arm["environment_overrides"], CARGO_PKG_NAME="rules", PRIVATE_TOKEN="secret-never-written",
                   PATH="C:/tools/한글;C:/other/Ω", CARGO_MAKEFLAGS="-j --jobserver-auth=owned-test\tcontrol\nvalue")
        return {"schema_version": 1, "mode": arm["policy"]["mode"], "backend": self.tools["backend"], "wrapper": self.tools["wrapper"], "linker": self.tools["linker"],
                "policy_sha256": arm["policy_sha256"], "cwd": str(self.source), "kind": result["kind"],
                "original_argv": [self.tools["backend"]["path"], *original],
                "forwarded_argv": [self.tools["backend"]["path"], *result["forwarded_argv"]], "changes": result["changes"],
                "environment_sha256": m.environment_digest(env), "control_environment": arm["environment_overrides"],
                "environment_digest_format": "uppercase-names-sorted-utf8-json-v1",
                "environment_value_sha256": {k: hashlib.sha256(v.encode()).hexdigest() for k, v in env.items()},
                "diagnostic_environment": {k: env[k] for k in ("PATH", "CARGO_MAKEFLAGS") if k in env},
                "cargo_identity": {"CARGO_PKG_NAME": "rules", "CARGO_PKG_VERSION": "0.1.0", "CARGO_MANIFEST_DIR": str(self.source)},
                "consumed_inputs": {str(self.source / "src" / "lib.rs"): m.file_hash(self.source / "src" / "lib.rs")},
                "target_tree_before": m.check_target_tree(arm["policy"]["target_root"])}

    def test_matching_actual_cargo_decisions(self):
        original, derivative = self.arm("original"), self.arm("derivative")
        a, b = self.record(original), self.record(derivative)
        self.assertEqual(m.compare_cargo_decisions(a, b, original, derivative)["functional_equivalence"], "not_evaluated")
        self.assertNotIn("secret-never-written", json.dumps(a))
        self.assertEqual(set(a["diagnostic_environment"]), {"PATH", "CARGO_MAKEFLAGS"})

    def test_shared_diagnostic_validator_is_pure_and_returns_no_private_values(self):
        record = self.record(self.arm("original"))
        with mock.patch.object(m, "_absolute", side_effect=AssertionError("unexpected filesystem access")), \
                mock.patch.object(m, "check_target_tree", side_effect=AssertionError("unexpected target scan")):
            self.assertIsNone(m.validate_diagnostic_environment(record))
            for malformed in (None, {}, {"environment_value_sha256": {"PATH": False}},
                              {"environment_value_sha256": {"Path": "0" * 64}}):
                with self.subTest(malformed=malformed), self.assertRaisesRegex(ValueError, "diagnostic environment"):
                    m.validate_diagnostic_environment(malformed)

    def test_missing_or_malformed_diagnostic_environment_rejected(self):
        arm = self.arm("original")
        for value in (None, False, [], "not-a-map"):
            record = self.record(arm)
            record["diagnostic_environment"] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "diagnostic environment"):
                m.validate_start_record(record, arm)
        record = self.record(arm)
        del record["diagnostic_environment"]
        with self.assertRaisesRegex(ValueError, "diagnostic environment"):
            m.validate_start_record(record, arm)

    def test_missing_or_extra_diagnostic_keys_rejected(self):
        arm = self.arm("original")
        for key in ("PATH", "CARGO_MAKEFLAGS"):
            record = self.record(arm)
            del record["diagnostic_environment"][key]
            with self.subTest(missing=key), self.assertRaisesRegex(ValueError, "diagnostic environment"):
                m.validate_start_record(record, arm)
        for key in ("PRIVATE_TOKEN", "RUSTC", "Path", "UNRECORDED"):
            record = self.record(arm)
            record["diagnostic_environment"][key] = "must-not-be-accepted"
            with self.subTest(extra=key), self.assertRaisesRegex(ValueError, "diagnostic environment"):
                m.validate_start_record(record, arm)

    def test_tampered_or_nonstring_diagnostic_values_rejected_without_leaking_them(self):
        arm = self.arm("original")
        for key in ("PATH", "CARGO_MAKEFLAGS"):
            for value in ("changed-private-value", None, False, 0, []):
                record = self.record(arm)
                record["diagnostic_environment"][key] = value
                with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, "diagnostic environment") as caught:
                    m.validate_start_record(record, arm)
                self.assertNotIn("changed-private-value", str(caught.exception))

    def test_absent_diagnostic_key_is_distinct_from_present_empty_value(self):
        arm = self.arm("original")
        record = self.record(arm)
        record["diagnostic_environment"]["PATH"] = ""
        record["environment_value_sha256"]["PATH"] = hashlib.sha256(b"").hexdigest()
        del record["diagnostic_environment"]["CARGO_MAKEFLAGS"]
        del record["environment_value_sha256"]["CARGO_MAKEFLAGS"]
        m.validate_start_record(record, arm)
        record["diagnostic_environment"]["CARGO_MAKEFLAGS"] = ""
        with self.assertRaisesRegex(ValueError, "diagnostic environment"):
            m.validate_start_record(record, arm)
        del record["diagnostic_environment"]["CARGO_MAKEFLAGS"]
        del record["diagnostic_environment"]["PATH"]
        with self.assertRaisesRegex(ValueError, "diagnostic environment"):
            m.validate_start_record(record, arm)
        del record["environment_value_sha256"]["PATH"]
        m.validate_start_record(record, arm)

    def test_diagnostic_recording_does_not_allow_unexplained_environment_differences(self):
        original, derivative = self.arm("original"), self.arm("derivative")
        for key in ("PATH", "CARGO_MAKEFLAGS"):
            a, b = self.record(original), self.record(derivative)
            value = b["diagnostic_environment"][key] + "-different"
            b["diagnostic_environment"][key] = value
            b["environment_value_sha256"][key] = hashlib.sha256(value.encode("utf-8")).hexdigest()
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "environments differ"):
                m.compare_cargo_decisions(a, b, original, derivative)

    def observed_comparison(self, profile="release"):
        arms = [self.arm("original"), self.arm("derivative")]
        records = [self.record(arm) for arm in arms]
        folder = "debug" if profile == "dev" else profile
        common = ["C:/fixed/" + str(index) for index in range(77)]
        common[5], common[19] = "", "C:/Case/한글/Ω"
        for record, arm, endpoint in zip(records, arms, ("217229458", "285472132")):
            arm["argv"][-1] = profile
            own = str(Path(arm["policy"]["target_root"]) / folder / "deps")
            self.set_diagnostic(record, "PATH", ";".join([*common[:37], own, *common[37:]]))
            value = "__rust_jobserver_semaphore_" + endpoint
            self.set_diagnostic(record, "CARGO_MAKEFLAGS", "-j --jobserver-fds=" + value + " --jobserver-auth=" + value)
        return records, arms

    def set_diagnostic(self, record, key, value):
        record["diagnostic_environment"][key] = value
        record["environment_value_sha256"][key] = hashlib.sha256(value.encode("utf-8")).hexdigest()

    def test_observed_path_and_jobserver_differences_report_digest_rules_only(self):
        records, arms = self.observed_comparison()
        before = copy.deepcopy(records)
        result = m.compare_cargo_decisions(*records, *arms)
        self.assertEqual(records, before)
        self.assertEqual(result["functional_equivalence"], "not_evaluated")
        self.assertTrue(result["environment_equivalence"].startswith("not_claimed:"))
        self.assertEqual({row["rule"] for row in result["recognized_environment_rules"]},
                         {"exact_owned_host_profile_deps_v1", "exact_windows_rust_jobserver_semaphore_v1"})
        for row in result["recognized_environment_rules"]:
            self.assertEqual(set(row), {"variable", "rule", "original_value_sha256", "derivative_value_sha256", "normalized_sha256"})
            self.assertEqual(row["original_value_sha256"], records[0]["environment_value_sha256"][row["variable"]])
            self.assertEqual(row["derivative_value_sha256"], records[1]["environment_value_sha256"][row["variable"]])
            self.assertRegex(row["normalized_sha256"], r"^[0-9a-f]{64}$")
        serialized = json.dumps(result)
        for record in records:
            for raw in record["diagnostic_environment"].values():
                self.assertNotIn(raw, serialized)
        self.assertNotIn("217229458", serialized)
        self.assertNotIn("285472132", serialized)

    def test_path_profile_is_derived_from_explicit_dev_release_or_custom_profile(self):
        for profile in ("dev", "release", "custom-fast"):
            records, arms = self.observed_comparison(profile)
            with self.subTest(profile=profile):
                result = m.compare_cargo_decisions(*records, *arms)
                self.assertEqual(result["recognized_environment_rules"][0]["variable"], "PATH")

    def test_path_normalization_rejects_other_entry_spelling_order_or_suffix_changes(self):
        for change in ("case", "reorder", "remove_empty", "extra_entry", "dotdot", "trailing_separator", "foreign_suffix"):
            records, arms = self.observed_comparison()
            entries = records[1]["diagnostic_environment"]["PATH"].split(";")
            if change == "case":
                entries[19] = entries[19].lower()
            elif change == "reorder":
                entries[0], entries[1] = entries[1], entries[0]
            elif change == "remove_empty":
                del entries[5]
            elif change == "extra_entry":
                entries.append("C:/extra")
            elif change == "dotdot":
                entries[37] += "/../deps"
            elif change == "trailing_separator":
                entries[37] += "/"
            else:
                entries[37] += "-foreign"
            self.set_diagnostic(records[1], "PATH", ";".join(entries))
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "environments differ"):
                m.compare_cargo_decisions(*records, *arms)

    def test_path_normalization_requires_unique_own_entry_at_same_index(self):
        for change in ("duplicate", "move", "missing", "foreign_root", "target_triple"):
            records, arms = self.observed_comparison()
            entries = records[1]["diagnostic_environment"]["PATH"].split(";")
            if change == "duplicate":
                entries.append(entries[37])
            elif change == "move":
                entries[36], entries[37] = entries[37], entries[36]
            elif change == "missing":
                entries[37] = "C:/outside/release/deps"
            elif change == "foreign_root":
                entries[37] = str(self.root / "foreign" / "target" / "release" / "deps")
            else:
                entries[37] = str(Path(arms[1]["policy"]["target_root"]) / m.TARGET / "release" / "deps")
            self.set_diagnostic(records[1], "PATH", ";".join(entries))
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "environments differ"):
                m.compare_cargo_decisions(*records, *arms)

    def test_path_normalization_rejects_missing_repeated_unsafe_or_different_profiles(self):
        for suffix in ([], ["--profile"], ["--profile=release"], ["--profile", "release", "--profile", "release"],
                       ["--profile", "dev"], ["--profile", "../release"], ["--profile", "a..b"],
                       ["--profile", "a/b"], ["--profile", "a\\b"], ["--profile", "release "], ["--profile", ""]):
            records, arms = self.observed_comparison()
            arms[1]["argv"] = [str(self.root / "cargo.exe"), "build", *suffix]
            with self.subTest(suffix=suffix), self.assertRaisesRegex(ValueError, "environments differ"):
                m.compare_cargo_decisions(*records, *arms)

    def test_jobserver_normalization_requires_exact_grammar_and_matching_endpoints(self):
        value = "__rust_jobserver_semaphore_285472132"
        valid = "-j --jobserver-fds=" + value + " --jobserver-auth=" + value
        invalid = [" " + valid, valid + " ", valid + "\n", valid + " -k", valid.replace("-j ", "-j2 "),
                   valid.replace("--jobserver-fds=", "--other-fds="), "-j --jobserver-auth=" + value,
                   valid.replace("--jobserver-auth=" + value, "--jobserver-auth=__rust_jobserver_semaphore_7"),
                   valid.replace("__rust_jobserver_semaphore_", "foreign_semaphore_"),
                   valid.replace("285472132", "１２３")]
        for raw in invalid:
            records, arms = self.observed_comparison()
            self.set_diagnostic(records[1], "CARGO_MAKEFLAGS", raw)
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, "environments differ"):
                m.compare_cargo_decisions(*records, *arms)

    def test_recognized_process_controls_do_not_hide_other_environment_changes(self):
        records, arms = self.observed_comparison()
        records[1]["environment_value_sha256"]["PRIVATE_TOKEN"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "environments differ"):
            m.compare_cargo_decisions(*records, *arms)

    def test_recognized_rules_still_require_raw_value_hash_and_presence_binding(self):
        for change in ("raw_tamper", "missing_diagnostic", "missing_hash"):
            records, arms = self.observed_comparison()
            if change == "raw_tamper":
                records[1]["diagnostic_environment"]["PATH"] += ";C:/tamper"
            elif change == "missing_diagnostic":
                del records[1]["diagnostic_environment"]["PATH"]
            else:
                del records[1]["environment_value_sha256"]["PATH"]
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "diagnostic environment"):
                m.compare_cargo_decisions(*records, *arms)

    def test_identical_diagnostic_values_need_no_normalization_rule(self):
        arms = [self.arm("original"), self.arm("derivative")]
        records = [self.record(arm) for arm in arms]
        self.assertEqual(m.compare_cargo_decisions(*records, *arms)["recognized_environment_rules"], [])

    def test_changed_profile_is_not_hidden(self):
        original, derivative = self.arm("original"), self.arm("derivative")
        a, b = self.record(original), self.record(derivative)
        b["original_argv"][b["original_argv"].index("opt-level=2")] = "opt-level=3"
        changed = m.derive_recipe(b["original_argv"][1:], "derivative")
        b["forwarded_argv"] = [self.tools["backend"]["path"], *changed["forwarded_argv"]]
        b["changes"] = changed["changes"]
        with self.assertRaisesRegex(ValueError, "Cargo original/derivative"):
            m.compare_cargo_decisions(a, b, original, derivative)

    def test_cfg_literal_is_not_output_path_normalized(self):
        original, derivative = self.arm("original"), self.arm("derivative")
        records = [self.record(original), self.record(derivative)]
        for record, arm in zip(records, [original, derivative]):
            record["original_argv"] += ["--cfg", 'literal="' + arm["policy"]["target_root"] + '"']
            rewritten = m.derive_recipe(record["original_argv"][1:], arm["policy"]["mode"])
            record["forwarded_argv"] = [self.tools["backend"]["path"], *rewritten["forwarded_argv"]]
            record["changes"] = rewritten["changes"]
        with self.assertRaisesRegex(ValueError, "Cargo original/derivative"):
            m.compare_cargo_decisions(*records, original, derivative)

    def test_equivalent_option_spelling_is_not_claimed_exact_argv(self):
        original, derivative = self.arm("original"), self.arm("derivative")
        a, b = self.record(original), self.record(derivative)
        at = b["original_argv"].index("--edition=2021")
        b["original_argv"][at:at + 1] = ["--edition", "2021"]
        rewritten = m.derive_recipe(b["original_argv"][1:], "derivative")
        b["forwarded_argv"] = [self.tools["backend"]["path"], *rewritten["forwarded_argv"]]
        b["changes"] = rewritten["changes"]
        with self.assertRaisesRegex(ValueError, "Cargo original/derivative"):
            m.compare_cargo_decisions(a, b, original, derivative)

    def test_arbitrary_changed_environment_not_dropped(self):
        original, derivative = self.arm("original"), self.arm("derivative")
        a, b = self.record(original), self.record(derivative)
        b["environment_value_sha256"]["PRIVATE_TOKEN"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "environments differ"):
            m.compare_cargo_decisions(a, b, original, derivative)

    def test_changed_forwarded_semantics_rejected(self):
        arm = self.arm("derivative")
        record = self.record(arm)
        record["forwarded_argv"] += ["-Coverflow-checks=off"]
        with self.assertRaisesRegex(ValueError, "unsupported original semantics"):
            m.validate_start_record(record, arm)

    def test_schema_boolean_and_missing_environment_encoding_rejected(self):
        arm = self.arm("original")
        record = self.record(arm)
        record["schema_version"] = True
        with self.assertRaisesRegex(ValueError, "schema"):
            m.validate_start_record(record, arm)
        record["schema_version"] = 1
        del record["environment_digest_format"]
        with self.assertRaisesRegex(ValueError, "encoding"):
            m.validate_start_record(record, arm)

    def test_missing_observed_source_hash_rejected(self):
        arm = self.arm("original")
        record = self.record(arm)
        record["consumed_inputs"] = {}
        with self.assertRaisesRegex(ValueError, "source hash"):
            m.validate_start_record(record, arm)

    def test_missing_or_changed_linker_tool_descriptor_rejected(self):
        arm = self.arm("original")
        for replacement in (None, {"path": "C:/other/link.exe", "sha256": "a" * 64}):
            record = self.record(arm)
            record["linker"] = replacement
            with self.subTest(replacement=replacement), self.assertRaisesRegex(ValueError, "tool identity"):
                m.validate_start_record(record, arm)

    def test_record_cannot_change_fixed_linker_even_with_consistent_rewrite(self):
        arm = self.arm("derivative")
        record = self.record(arm)
        at = record["original_argv"].index("linker=" + self.tools["linker"]["path"])
        record["original_argv"][at] = "linker=C:/unapproved/link.exe"
        derived = m.derive_recipe(record["original_argv"][1:], "derivative")
        record["forwarded_argv"] = [arm["policy"]["backend"], *derived["forwarded_argv"]]
        record["changes"] = derived["changes"]
        with self.assertRaisesRegex(ValueError, "single pinned linker"):
            m.validate_start_record(record, arm)

    def test_incremental_write_outside_arm_rejected(self):
        arm = self.arm("original")
        record = self.record(arm)
        record["original_argv"] += ["-Cincremental=" + str(self.root / "outside")]
        record["forwarded_argv"] = list(record["original_argv"])
        with self.assertRaisesRegex(ValueError, "incremental output"):
            m.validate_start_record(record, arm)

    def test_duplicate_json_keys_are_not_silently_accepted(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            m._json(b'{"schema_version":1,"schema_version":1}')

    def test_missing_or_noop_records_not_scored(self):
        arm = self.arm("original")
        with self.assertRaisesRegex(ValueError, "no wrapper records"):
            m.inspect_unit_records(Path(arm["policy"]["record_root"]), arm)
        unit = Path(arm["policy"]["record_root"]) / "123-999"
        unit.mkdir()
        (unit / "start.json").write_text(json.dumps(self.record(arm)))
        with self.assertRaisesRegex(ValueError, "incomplete/crashed"):
            m.inspect_unit_records(unit.parent, arm)

    def test_complete_record_not_promoted_to_build_or_graph_success(self):
        arm = self.arm("original")
        unit = Path(arm["policy"]["record_root"]) / "123-999"
        unit.mkdir()
        start = unit / "start.json"
        start.write_text(json.dumps(self.record(arm)))
        finish = {"schema_version": 1, "compiler_pid": 456, "compiler_exit_code": 0, "cancelled": False,
                  "succeeded": True, "changed_inputs": [], "start_sha256": m.file_hash(start),
                  "target_tree_after": m.check_target_tree(arm["policy"]["target_root"])}
        (unit / "finish.json").write_text(json.dumps(finish))
        result = m.inspect_unit_records(unit.parent, arm)
        self.assertFalse(result["complete_crate_graph"])
        self.assertFalse(result["original_reference_linked"])
        self.assertFalse(result["protected_artifact_created"])
        finish["compiler_exit_code"] = False
        (unit / "finish.json").write_text(json.dumps(finish))
        with self.assertRaisesRegex(ValueError, "did not complete"):
            m.inspect_unit_records(unit.parent, arm)


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cargo-unit-plan-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "project"
        (self.source / "src").mkdir(parents=True)
        (self.source / "src" / "lib.rs").write_text("pub fn local() {}")
        self.wrapper = self.root / "trusted-wrapper.exe"
        self.wrapper.write_bytes(b"inert never executed")
        self.backend = self.root / "rustc.exe"
        self.backend.write_bytes(b"inert backend")
        self.windows = self.root / "windows"
        (self.windows / "System32").mkdir(parents=True)
        self.linker = self.root / "sdk/bin/link.exe"
        self.linker.parent.mkdir(parents=True)
        self.linker.write_bytes(b"inert linker never executed")
        self.library = self.root / "sdk/lib/owned.lib"
        self.library.parent.mkdir()
        self.library.write_bytes(b"inert SDK archive")
        self.context = self.root / ".runs/build-context"
        self.home = self.context / "user-profile"
        for directory in (self.home / "AppData/Roaming", self.home / "AppData/Local",
                          self.context / "cargo-home", self.context / "temp"):
            directory.mkdir(parents=True, exist_ok=True)
        self.env = {"SYSTEMROOT": str(self.windows), "WINDIR": str(self.windows),
            "PATH": ";".join(map(str, (self.backend.parent, self.linker.parent, self.windows / "System32"))),
            "LIB": str(self.library.parent), "RUSTC": str(self.backend), "CARGO_NET_OFFLINE": "true",
            "CARGO_TERM_COLOR": "never", "CARGO_TARGET_DIR": str(self.context / "target-unused"),
            "CARGO_HOME": str(self.context / "cargo-home"), "USERPROFILE": str(self.home), "HOME": str(self.home),
            "APPDATA": str(self.home / "AppData/Roaming"), "LOCALAPPDATA": str(self.home / "AppData/Local"),
            "TEMP": str(self.context / "temp"), "TMP": str(self.context / "temp"), m.LINKER_SELECTOR: str(self.linker)}
        policy = {"schema_version": 1, "policy": "windows_metadata_minimal_v1",
                  "child_template": {"CARGO_HOME": "<inspection>/cargo-home"}, "inherits_other_variables": False}
        policy["sha256"] = m._ascii_digest(policy)
        self.inspection = {
            "schema_version": 1, "status": "inspected_build_not_implemented", "backend": "rust_cargo_native",
            "workspace_root": str(self.root), "project_path": str(self.source / "project.json"),
            "input_snapshot": {"roots": [str(self.source)]},
            "environment": policy,
            "selection": {"manifest_path": "Cargo.toml", "package": "local", "profile": "release",
                          "features": ["extra"], "default_features": False},
            "toolchain": {"selection": {"cargo": str(self.root / "cargo.exe"), "rustc": str(self.backend), "sysroot": str(self.root), "target": m.TARGET},
                          "compiler_inputs": {str(self.backend): m.file_hash(self.backend)}},
            "resolution": {"closure": [{"package": {"targets": [{"kind": ["lib"], "src_path": str(self.source / "src" / "lib.rs")} ]}}]},
        }
        self.metadata_path = self.root / ".runs/metadata/plan.json"
        self.metadata_path.parent.mkdir()
        self.context_receipt = self.context / "context.json"
        self.context_receipt.write_text(json.dumps({"mock_only": True, "linker": str(self.linker)}))
        self.sdk_pins = {str(path): m.file_hash(path) for path in (self.linker, self.library)}
        self.seal_inspection()
        proof_dir = self.root / ".runs" / "host-probe"
        proof_dir.mkdir(parents=True)
        self.host_paths = {"stdout": proof_dir / "rustc.stdout.log", "stderr": proof_dir / "rustc.stderr.log", "process": proof_dir / "rustc.process.json"}
        self.host_paths["stdout"].write_text("rustc 0.0.0 (inert mock)\nhost: " + m.TARGET + "\n")
        self.host_paths["stderr"].write_text("")
        self.host_result = {"argv": [str(self.backend), "-vV"], "returncode": 0, "pid": 321, "timed_out": False, "cancelled": False,
                            "stdout": str(self.host_paths["stdout"]), "stderr": str(self.host_paths["stderr"]),
                            "cleanup": {"method": "windows_job", "status": "assigned_job_empty", "job_assigned": True,
                                        "active_after": 0, "parent_pid": 321, "parent_exit_confirmed": True, "job_handle_closed": True}}
        self.host_paths["process"].write_text(json.dumps(self.host_result))
        self.host = self.host_proof()

    @staticmethod
    def descriptor(path):
        return {"path": str(path), "sha256": m.file_hash(path), "bytes": path.stat().st_size}

    def seal_inspection(self):
        self.inspection.pop("fingerprint", None)
        self.inspection["fingerprint"] = m._ascii_digest(self.inspection)
        self.metadata_path.write_text(json.dumps({"inspection": self.inspection, "metadata_evidence": {"mock_only": True}}))
        self.evidence = [self.descriptor(self.metadata_path), self.descriptor(self.context_receipt)]
        self.receipt = m.create_build_environment_receipt(self.inspection, self.env,
            sdk_input_hashes=self.sdk_pins, evidence_files=self.evidence)

    def host_proof(self):
        return {"triple": m.TARGET, "rustc_sha256": m.file_hash(self.backend),
                **{key: {"path": str(path), "sha256": m.file_hash(path)} for key, path in self.host_paths.items()}}

    def plan(self):
        return m.plan_invocations(self.inspection, wrapper=m.Tool(str(self.wrapper), m.file_hash(self.wrapper)),
                                  output_root=self.root / ".runs" / "unit-job", environment=self.env,
                                  build_environment_receipt=self.receipt, backend_host=self.host)

    def test_only_fixed_recipes_no_directory_creation(self):
        result = self.plan()
        self.assertEqual(result["status"], "recipes_only_not_executed")
        self.assertFalse((self.root / ".runs" / "unit-job").exists())
        for mode, arm in result["arms"].items():
            self.assertFalse(arm["executed"])
            self.assertFalse(arm["shell"])
            self.assertEqual(arm["argv"][1:4], ["build", "--offline", "--locked"])
            self.assertIn("local/extra", arm["argv"])
            self.assertEqual(arm["argv"][arm["argv"].index("--jobs") + 1], "1")
            self.assertEqual(arm["policy"]["linker"], str(self.linker))
            self.assertEqual(arm["policy"]["linker_sha256"], m.file_hash(self.linker))
            self.assertEqual(arm["policy"]["mode"], mode)
            self.assertNotIn("not-written", json.dumps(arm))
        self.assertNotEqual(result["arms"]["original"]["root"], result["arms"]["derivative"]["root"])

    def test_changed_environment_or_tool_is_rejected(self):
        previous = self.env["CARGO_TARGET_DIR"]
        self.env["CARGO_TARGET_DIR"] = str(self.context / "changed-target")
        with self.assertRaisesRegex(ValueError, "environment changed"):
            self.plan()
        self.env["CARGO_TARGET_DIR"] = previous
        pinned = m.Tool(str(self.wrapper), m.file_hash(self.wrapper))
        self.wrapper.write_bytes(b"changed tool")
        with self.assertRaisesRegex(ValueError, "wrapper executable"):
            m.plan_invocations(self.inspection, wrapper=pinned, output_root=self.root / ".runs" / "job", environment=self.env,
                               build_environment_receipt=self.receipt, backend_host=self.host)

    def test_existing_output_or_received_input_is_rejected(self):
        (self.root / ".runs" / "unit-job").mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, "fresh private"):
            self.plan()
        self.inspection["input_snapshot"]["roots"] = [str(self.root / "rea-analysis-reports")]
        with self.assertRaisesRegex(ValueError, "received"):
            m.plan_invocations(self.inspection, wrapper=m.Tool(str(self.wrapper), m.file_hash(self.wrapper)),
                               output_root=self.root / ".runs" / "another", environment=self.env,
                               build_environment_receipt=self.receipt, backend_host=self.host)

    def test_inspected_foreign_toolchain_target_is_not_silently_overridden(self):
        self.inspection["toolchain"]["selection"]["target"] = "aarch64-pc-windows-msvc"
        with self.assertRaisesRegex(ValueError, "toolchain target"):
            self.plan()

    def test_missing_or_unbound_host_process_is_rejected(self):
        del self.host["process"]
        with self.assertRaisesRegex(ValueError, "host proof"):
            self.plan()
        self.host = self.host_proof()
        self.host_result["argv"] = [str(self.backend), "--version"]
        self.host_paths["process"].write_text(json.dumps(self.host_result))
        self.host = self.host_proof()
        with self.assertRaisesRegex(ValueError, "fixed command"):
            self.plan()

    def test_host_probe_cleanup_and_boolean_returncode_rejected(self):
        for change in ("returncode", "active_after", "job_handle_closed"):
            result = copy.deepcopy(self.host_result)
            if change == "returncode":
                result[change] = False
            elif change == "active_after":
                result["cleanup"][change] = False
            else:
                result["cleanup"][change] = False
            self.host_paths["process"].write_text(json.dumps(result))
            self.host = self.host_proof()
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "cleanup"):
                self.plan()

    def test_foreign_duplicate_or_changed_host_output_rejected(self):
        self.host_paths["stdout"].write_text("host: foreign\n")
        with self.assertRaisesRegex(ValueError, "path/hash"):
            self.plan()
        self.host = self.host_proof()
        with self.assertRaisesRegex(ValueError, "ambiguous or foreign"):
            self.plan()
        self.host_paths["stdout"].write_text(("host: " + m.TARGET + "\n") * 2)
        self.host = self.host_proof()
        with self.assertRaisesRegex(ValueError, "ambiguous or foreign"):
            self.plan()

    def test_metadata_policy_and_build_environment_have_distinct_hashes(self):
        result = self.plan()
        self.assertNotEqual(self.receipt["environment_sha256"], self.inspection["environment"]["sha256"])
        self.assertEqual(result["metadata_environment_policy_sha256"], self.inspection["environment"]["sha256"])
        self.assertEqual(result["build_environment_receipt"], self.receipt)
        self.assertFalse(self.receipt["sdk_selection_independently_verified"])

    def test_no_ambient_environment_inheritance_or_process_execution(self):
        with mock.patch.dict(os.environ, {"PRIVATE_TOKEN": "do-not-copy", "RUSTFLAGS": "unapproved"}), \
                mock.patch("subprocess.Popen", side_effect=AssertionError("no subprocess")), \
                mock.patch("subprocess.run", side_effect=AssertionError("no subprocess")):
            result = self.plan()
        self.assertNotIn("do-not-copy", json.dumps(result))
        self.assertNotIn("PRIVATE_TOKEN", self.receipt["environment_value_sha256"])

    def test_extra_missing_or_case_ambiguous_environment_controls_rejected(self):
        for key in ("PRIVATE_TOKEN", "RUSTFLAGS", "RUSTC_WRAPPER", "NODE_OPTIONS"):
            with self.subTest(extra=key), self.assertRaisesRegex(ValueError, "16 approved"):
                m.create_build_environment_receipt(self.inspection, {**self.env, key: "not-exposed"},
                    sdk_input_hashes=self.sdk_pins, evidence_files=self.evidence)
        for key in self.env:
            altered = dict(self.env)
            del altered[key]
            with self.subTest(missing=key), self.assertRaisesRegex(ValueError, "16 approved"):
                m.create_build_environment_receipt(self.inspection, altered,
                    sdk_input_hashes=self.sdk_pins, evidence_files=self.evidence)
        with self.assertRaisesRegex(ValueError, "case-ambiguous"):
            m.create_build_environment_receipt(self.inspection, {**self.env, "Path": self.env["PATH"]},
                sdk_input_hashes=self.sdk_pins, evidence_files=self.evidence)

    def test_linker_selector_path_and_sdk_pin_must_agree(self):
        altered = dict(self.sdk_pins)
        del altered[str(self.linker)]
        with self.assertRaisesRegex(ValueError, "exact linker"):
            m.create_build_environment_receipt(self.inspection, self.env,
                sdk_input_hashes=altered, evidence_files=self.evidence)
        env = dict(self.env, PATH=self.env["PATH"] + ";C:/foreign")
        with self.assertRaisesRegex(ValueError, "PATH"):
            m.create_build_environment_receipt(self.inspection, env,
                sdk_input_hashes=self.sdk_pins, evidence_files=self.evidence)

    def test_changed_sdk_file_or_evidence_rejected_before_recipe(self):
        previous = self.library.read_bytes()
        self.library.write_bytes(b"changed SDK")
        with self.assertRaisesRegex(ValueError, "SDK input pin"):
            self.plan()
        self.library.write_bytes(previous)
        self.context_receipt.write_text('{"changed":true}')
        with self.assertRaisesRegex(ValueError, "evidence"):
            self.plan()

    def test_selected_sdk_hardlinks_allow_content_pins_but_not_config_or_wrapper(self):
        os.link(self.linker, self.root / "installed-linker-alias.exe")
        os.link(self.library, self.root / "installed-library-alias.lib")
        result = self.plan()
        self.assertIn("OS aliases", result["build_environment_receipt"]["sdk_hardlink_policy"])
        config = self.root / "configuration.json"
        config.write_text("{}")
        os.link(config, self.root / "configuration-alias.json")
        with self.assertRaisesRegex(ValueError, "hardlinked"):
            m.create_build_environment_receipt(self.inspection, self.env,
                sdk_input_hashes={**self.sdk_pins, str(config): m.file_hash(config)}, evidence_files=self.evidence)
        os.link(self.wrapper, self.root / "wrapper-alias.exe")
        with self.assertRaisesRegex(ValueError, "hardlinked"):
            self.plan()

    def test_receipt_fields_missing_tampered_or_boolean_schema_rejected(self):
        original = copy.deepcopy(self.receipt)
        for key in ("metadata_environment_policy_sha256", "environment_sha256", "sdk_input_hashes", "metadata_plan"):
            self.receipt = copy.deepcopy(original)
            del self.receipt[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.plan()
        self.receipt = copy.deepcopy(original)
        self.receipt["schema_version"] = True
        with self.assertRaisesRegex(ValueError, "receipt was altered"):
            self.plan()

    def test_metadata_file_hash_and_inspection_fingerprint_rechecked(self):
        previous = self.metadata_path.read_bytes()
        self.metadata_path.write_bytes(previous + b" ")
        with self.assertRaisesRegex(ValueError, "evidence"):
            self.plan()
        self.metadata_path.write_bytes(previous)
        self.inspection["selection"]["profile"] = "dev"
        with self.assertRaisesRegex(ValueError, "inspection fingerprint"):
            self.plan()

    def test_missing_metadata_or_sdk_context_evidence_rejected(self):
        for evidence in ([self.descriptor(self.context_receipt)], [self.descriptor(self.metadata_path)]):
            with self.subTest(evidence=evidence), self.assertRaisesRegex(ValueError, "metadata plan plus SDK"):
                m.create_build_environment_receipt(self.inspection, self.env,
                    sdk_input_hashes=self.sdk_pins, evidence_files=evidence)

    def test_private_home_or_temp_must_not_overlap_project_or_received_inputs(self):
        for value in (str(self.source), str(self.root / ".runs/defense-loop/temp")):
            env = dict(self.env, TEMP=value, TMP=value)
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "private owned"):
                m.create_build_environment_receipt(self.inspection, env,
                    sdk_input_hashes=self.sdk_pins, evidence_files=self.evidence)

    def test_three_local_crates_are_not_reduced_to_two_fixture_units(self):
        for name in ("shared_rules", "independent_helper"):
            path = self.source / name / "lib.rs"
            path.parent.mkdir()
            path.write_text("pub fn ordinary_rust_helper() {}")
            self.inspection["resolution"]["closure"].append({"package": {
                "targets": [{"kind": ["lib"], "src_path": str(path)}]}})
        self.seal_inspection()
        result = self.plan()
        for arm in result["arms"].values():
            self.assertEqual(len(arm["recorded_sources"]), 3)
            self.assertEqual(arm["policy_text"].count("\nsource="), 3)
            self.assertEqual(arm["argv"].count("--jobs"), 1)


class TargetAliasTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cargo-target-alias-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.target = self.root / "target"
        self.target.mkdir()

    def test_only_fully_owned_aliases_are_allowed(self):
        first = self.target / "one.rlib"
        second = self.target / "two.rlib"
        first.write_bytes(b"owned inert artifact")
        os.link(first, second)
        result = m.check_target_tree(self.target)
        self.assertEqual(len(result["files"]), 2)
        self.assertEqual({row["links"] for row in result["files"]}, {2})
        self.assertEqual(len({row["identity"] for row in result["files"]}), 1)
        self.assertEqual(m.validate_target_tree_record(result, self.target), result)

    def test_outside_alias_is_rejected_without_touching_sentinel(self):
        sentinel = self.root / "sentinel"
        sentinel.write_bytes(b"must remain intact")
        os.link(sentinel, self.target / "planted.dll")
        with self.assertRaisesRegex(ValueError, "external aliases"):
            m.check_target_tree(self.target)
        self.assertEqual(sentinel.read_bytes(), b"must remain intact")

    def test_source_tool_policy_hardlinks_remain_rejected(self):
        source = self.root / "source.rs"
        source.write_text("pub fn never_run() {}")
        os.link(source, self.root / "alias.rs")
        with self.assertRaisesRegex(ValueError, "hardlinked"):
            m._absolute(source)

    def test_unstable_identity_scans_fail_closed(self):
        (self.target / "artifact.rlib").write_bytes(b"owned")
        with mock.patch.object(m, "_file_identity", side_effect=[("a:1", 1), ("a:2", 1)]):
            with self.assertRaisesRegex(ValueError, "changed while inspected"):
                m.check_target_tree(self.target)


if __name__ == "__main__":
    unittest.main()

