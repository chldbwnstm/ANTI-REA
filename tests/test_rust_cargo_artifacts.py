"""Pure/mock collector regressions; no compiler, Cargo, target or filesystem IO."""
import copy
import hashlib
import json
import ntpath
import unittest

from antirea import rust_cargo_artifacts as subject
from antirea import rust_cargo_units as cargo_units


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def fixture(mode="derivative", *, names=("rules", "component"),
            workspace=r"C:\owned\project", capture=r"C:\owned\capture",
            tool_root=r"C:\tools"):
    """Synthetic observations only: roots and actual unit count are variable."""
    root = capture + "\\" + mode + r"\target"
    out = root + r"\x86_64-pc-windows-msvc\debug\deps"
    backend, wrapper = tool_root + r"\rustc.exe", tool_root + r"\trusted-wrapper.exe"
    linker = tool_root + r"\lld-link.exe"
    policy = {"mode": mode, "target_root": root, "backend": backend, "backend_sha256": sha(b"rustc"),
              "wrapper": wrapper, "wrapper_sha256": sha(b"wrapper"), "sysroot": tool_root + r"\sysroot",
              "linker": linker, "linker_sha256": sha(b"linker")}
    controls = {"CARGO_TARGET_DIR": root, "ANTIREA_RUST_UNIT_POLICY": root + r"\policy.txt", "RUSTC": backend, "RUSTC_WRAPPER": wrapper}
    arm = {"policy": policy, "policy_sha256": sha(b"policy"), "environment_overrides": controls}
    snapshot, observed, packages, units, artifacts, deps = {}, {}, [], [], [], {}

    def add(path, contents, owned=False):
        observed[path] = {"sha256": sha(contents), "bytes": len(contents)}
        if owned:
            snapshot[path] = sha(contents)

    add(backend, b"rustc")
    add(wrapper, b"wrapper")
    add(linker, b"linker")
    previous = None
    for index, name in enumerate(names):
        directory = workspace + "\\" + name
        source = directory + r"\src\lib.rs"
        module = directory + r"\src\math.rs"
        manifest = directory + r"\Cargo.toml"
        add(source, b"owned root " + name.encode(), True)
        add(module, b"owned module " + name.encode(), True)
        add(manifest, b"owned manifest " + name.encode(), True)
        lib = out + "\\lib" + name + ".rlib"
        dep = out + "\\" + name + ".d"
        ir = out + "\\" + name + ".ll"
        add(lib, b"owned library " + name.encode())
        if mode == "derivative":
            add(ir, b"owned LLVM IR " + name.encode())
        targets = [dep, lib] + ([ir] if mode == "derivative" else [])
        raw = "\n\n".join(path + r": src/lib.rs src\math.rs" for path in targets)
        raw += "\n\nsrc/lib.rs:\nsrc\\math.rs:\n"
        deps[dep] = raw.encode()
        add(dep, deps[dep])
        argv = [backend, "--crate-name", name, "--crate-type", "rlib", "--edition=2021", "--target", subject.TARGET,
                "--emit=dep-info,link", "--out-dir", out, "--cfg", 'feature="math"',
                "-C", "linker=" + linker, "src/lib.rs"]
        consumed = {source: snapshot[source]}
        if previous:
            argv += ["--extern", previous[0] + "=" + previous[1]]
            consumed[previous[1]] = observed[previous[1]]["sha256"]
        derived = cargo_units.derive_recipe(argv[1:], mode)
        env_values = {key: sha(value.encode()) for key, value in controls.items()}
        identity = {"CARGO_MANIFEST_DIR": directory, "CARGO_MANIFEST_PATH": manifest, "CARGO_PKG_NAME": name, "CARGO_PKG_VERSION": "1.0.0"}
        start = {"schema_version": 1, "kind": "crate", "mode": mode, "policy_sha256": arm["policy_sha256"],
                 "backend": {"path": backend, "sha256": policy["backend_sha256"]},
                 "wrapper": {"path": wrapper, "sha256": policy["wrapper_sha256"]},
                 "linker": {"path": linker, "sha256": policy["linker_sha256"]},
                 "original_argv": argv, "forwarded_argv": [backend, *derived["forwarded_argv"]], "changes": derived["changes"],
                 "cwd": directory, "consumed_inputs": consumed, "cargo_identity": identity,
                 "environment_digest_format": "uppercase-names-sorted-utf8-json-v1", "environment_sha256": sha(b"private env"),
                 "environment_value_sha256": env_values, "control_environment": controls, "diagnostic_environment": {}}
        start_bytes = encoded(start)
        finish = {"schema_version": 1, "compiler_pid": 100 + index, "compiler_exit_code": 0, "succeeded": True,
                  "cancelled": False, "changed_inputs": [], "start_sha256": sha(start_bytes)}
        units.append({"unit": str(index), "start_bytes": start_bytes, "finish_bytes": encoded(finish)})
        target = {"name": name, "kind": ["lib"], "crate_types": ["rlib"], "src_path": source, "edition": "2021"}
        package = {"id": "path+file:///" + name + "#1.0.0", "name": name, "version": "1.0.0", "manifest_path": manifest, "targets": [target]}
        packages.append(package)
        artifacts.append({"reason": "compiler-artifact", "package_id": package["id"], "manifest_path": manifest,
                          "target": copy.deepcopy(target), "features": ["math"], "fresh": False,
                          "executable": None, "filenames": [lib], "profile": {"opt_level": "0"}})
        previous = (name, lib)
    return {"unit_records": units, "cargo_jsonl_bytes": b"\n".join(encoded(item) for item in [*artifacts, {"reason": "build-finished", "success": True}]),
            "arm": arm, "source_snapshot": snapshot, "compiler_snapshot": {}, "packages": packages,
            "observed_files": observed, "dep_info_contents": deps}


def mutate_start(data, index, mutate):
    unit = data["unit_records"][index]
    start, finish = json.loads(unit["start_bytes"]), json.loads(unit["finish_bytes"])
    mutate(start)
    unit["start_bytes"] = encoded(start)
    finish["start_sha256"] = sha(unit["start_bytes"])
    unit["finish_bytes"] = encoded(finish)


def mutate_message(data, index, mutate):
    lines = [json.loads(line) for line in data["cargo_jsonl_bytes"].splitlines()]
    mutate(lines[index])
    data["cargo_jsonl_bytes"] = b"\n".join(encoded(line) for line in lines)


def replace_dep(data, index, transform):
    path = list(data["dep_info_contents"])[index]
    raw = transform(data["dep_info_contents"][path])
    data["dep_info_contents"][path] = raw
    data["observed_files"][path] = {"sha256": sha(raw), "bytes": len(raw)}


def published_aggregates(data):
    """Model observed Cargo root rlib+cdylib publication, no filesystem IO."""
    component_lib = next(path for path in data["observed_files"] if path.endswith("libcomponent.rlib"))
    output_dir = ntpath.dirname(component_lib)
    published_dir = ntpath.dirname(output_dir)
    component_dll = output_dir + r"\component.dll"
    data["observed_files"][component_dll] = {"sha256": sha(b"component dll"), "bytes": len(b"component dll")}
    replace_dep(data, 1, lambda raw: raw + (component_dll + r": src/lib.rs src\math.rs" + "\n").encode())

    def add_type(start):
        start["original_argv"] += ["--crate-type", "cdylib"]
        derived = cargo_units.derive_recipe(start["original_argv"][1:], start["mode"])
        start["forwarded_argv"] = [start["original_argv"][0], *derived["forwarded_argv"]]
        start["changes"] = derived["changes"]

    mutate_start(data, 1, add_type)
    target = data["packages"][1]["targets"][0]
    target["kind"] = ["rlib", "cdylib"]
    target["crate_types"] = ["rlib", "cdylib"]
    published = []
    for original in (component_lib, component_dll):
        path = published_dir + "\\" + ntpath.basename(original)
        data["observed_files"][path] = copy.deepcopy(data["observed_files"][original])
        published.append(path)
    mutate_message(data, 1, lambda row: row.update(target=copy.deepcopy(target), filenames=published))
    dependencies = sorted(path for path in data["source_snapshot"] if path.endswith(".rs"))
    aggregates = []
    for output in published:
        path = ntpath.splitext(output)[0] + ".d"
        raw = (output + ": " + " ".join(dependencies) + "\n").encode()
        data["dep_info_contents"][path] = raw
        data["observed_files"][path] = {"sha256": sha(raw), "bytes": len(raw)}
        aggregates.append(path)
    return aggregates, dependencies


def set_dep(data, path, raw):
    data["dep_info_contents"][path] = raw
    data["observed_files"][path] = {"sha256": sha(raw), "bytes": len(raw)}


class DepInfoTests(unittest.TestCase):
    def test_windows_drive_paths_multiple_outputs_and_phony_rules(self):
        raw = (b"C:\\owned\\rules.d: rules/lib.rs rules\\rules.rs\r\n\r\n"
               b"C:\\owned\\lib_rules.rlib C:\\owned\\rules.ll: rules/lib.rs rules\\rules.rs\r\n\r\n"
               b"rules/lib.rs:\r\nrules\\rules.rs:\r\n")
        result = subject.parse_dep_info(raw)
        self.assertEqual(result["rules"][0]["targets"], [r"C:\owned\rules.d"])
        self.assertEqual(result["rules"][1]["dependencies"], ["rules/lib.rs", r"rules\rules.rs"])
        self.assertEqual(len(result["rules"][1]["targets"]), 2)
        self.assertEqual(result["rules"][2]["dependencies"], [])

    def test_spaces_hash_dollar_and_continuation(self):
        raw = b"C:\\my\\ name\\a.d: src/a\\ b.rs \\\n src/hash\\#name.rs src/dollar$$name.rs\n"
        rule = subject.parse_dep_info(raw)["rules"][0]
        self.assertEqual(rule["targets"], [r"C:\my name\a.d"])
        self.assertEqual(rule["dependencies"], ["src/a b.rs", "src/hash#name.rs", "src/dollar$name.rs"])

    def test_env_hash_only_present_empty_and_absent(self):
        raw = b"a.d: a.rs\n# env-dep:SECRET=do-not-persist\n# env-dep:EMPTY=\n# env-dep:ABSENT\n"
        result = subject.parse_dep_info(raw)
        self.assertEqual(result["env_dependencies"]["SECRET"]["value_sha256"], sha(b"do-not-persist"))
        self.assertEqual(result["env_dependencies"]["EMPTY"]["value_sha256"], sha(b""))
        self.assertFalse(result["env_dependencies"]["ABSENT"]["present"])
        self.assertNotIn("do-not-persist", encoded(result).decode())

    def test_env_supported_escape_grammar(self):
        result = subject.parse_dep_info(b"a.d: a.rs\n# env-dep:V=line\\nnext\\r\\\\tail\n")
        self.assertEqual(result["env_dependencies"]["V"]["value_sha256"], sha(b"line\nnext\r\\tail"))

    def test_reject_ambiguous_or_malformed_forms(self):
        for raw in (b"", b"no colon", b"a.d: a\x00.rs", b"a.d: $(SECRET)", b"a.d: a.rs #comment",
                    b"a.d: a.rs\r", b"a.d: a.rs\\", b"a.d: \\\\server\\share", b"a.d: a.rs\n# env-dep:V=\\q",
                    b"a.d: a.rs\n# env-dep:A=one\n# env-dep:a=two\n", b"\xff"):
            with self.subTest(raw=raw), self.assertRaises((ValueError, UnicodeError)):
                subject.parse_dep_info(raw)


class ArtifactTests(unittest.TestCase):
    def test_two_actual_crates_derivative_outputs_and_extern_edge(self):
        result = subject.collect_cargo_artifacts(**fixture())
        self.assertEqual(result["status"], "artifacts_bound_not_build_validated")
        self.assertEqual(result["actual_compiled_units"], 2)
        self.assertEqual(result["units"][1]["externs"][0]["producer_unit"], "0")
        self.assertTrue(all(unit["llvm_ir"]["sha256"] for unit in result["units"]))
        self.assertFalse(result["full_sysroot_native_linker_closure"])
        self.assertFalse(result["outer_job_cleanup_verified"])
        self.assertFalse(result["protected_artifact_created"])

    def test_no_aggregate_does_not_invent_cargo_declaration(self):
        self.assertEqual(subject.collect_cargo_artifacts(**fixture())["aggregate_dep_info"], [])

    def test_original_arm_does_not_invent_llvm_output(self):
        result = subject.collect_cargo_artifacts(**fixture("original"))
        self.assertTrue(all(unit["llvm_ir"] is None for unit in result["units"]))

    def test_inactive_metadata_package_is_not_required_to_compile(self):
        data = fixture()
        data["packages"].append({"id": "inactive", "name": "inactive", "targets": []})
        self.assertEqual(subject.collect_cargo_artifacts(**data)["actual_compiled_units"], 2)

    def test_reject_unpinned_module_or_include(self):
        for change in (lambda raw: raw.replace(b"src\\math.rs", b"src\\untracked.inc"),
                       lambda raw: raw.replace(b"src\\math.rs", b"C:\\outside\\secret.rs")):
            data = fixture()
            replace_dep(data, 0, change)
            with self.assertRaisesRegex(ValueError, "unpinned"):
                subject.collect_cargo_artifacts(**data)

    def test_snapshot_hash_mismatch_and_output_missing(self):
        for field in ("source", "output"):
            data = fixture()
            key = next(iter(data["source_snapshot"])) if field == "source" else next(path for path in data["observed_files"] if path.endswith(".ll"))
            if field == "source":
                data["observed_files"][key]["sha256"] = "0" * 64
            else:
                del data["observed_files"][key]
            with self.subTest(field=field), self.assertRaises(ValueError):
                subject.collect_cargo_artifacts(**data)

    def test_missing_derivative_ir_even_when_cargo_does_not_list_it(self):
        data = fixture()
        replace_dep(data, 0, lambda raw: b"\n".join(line for line in raw.splitlines() if b"rules.ll:" not in line))
        with self.assertRaisesRegex(ValueError, "LLVM IR"):
            subject.collect_cargo_artifacts(**data)

    def test_dep_info_raw_hash_must_match_observation(self):
        data = fixture()
        key = next(iter(data["dep_info_contents"]))
        data["dep_info_contents"][key] += b"\n"
        with self.assertRaisesRegex(ValueError, "bytes/hash"):
            subject.collect_cargo_artifacts(**data)

    def test_env_dependency_must_match_actual_recorded_hash(self):
        data = fixture()
        replace_dep(data, 0, lambda raw: raw + b"# env-dep:OWNED_SECRET=test-value\n")
        with self.assertRaisesRegex(ValueError, "env-dep"):
            subject.collect_cargo_artifacts(**data)
        mutate_start(data, 0, lambda start: start["environment_value_sha256"].update(OWNED_SECRET=sha(b"test-value")))
        result = subject.collect_cargo_artifacts(**data)
        self.assertNotIn("test-value", encoded(result).decode())

    def test_absent_env_dependency_rejects_even_empty_present_value(self):
        data = fixture()
        replace_dep(data, 0, lambda raw: raw + b"# env-dep:ABSENT\n")
        mutate_start(data, 0, lambda start: start["environment_value_sha256"].update(ABSENT=sha(b"")))
        with self.assertRaisesRegex(ValueError, "env-dep"):
            subject.collect_cargo_artifacts(**data)

    def test_unit_failures_or_tampered_start_are_not_promoted(self):
        variants = ({"compiler_exit_code": 1}, {"cancelled": True}, {"succeeded": False},
                    {"changed_inputs": ["x"]}, {"start_sha256": "0" * 64}, {"compiler_pid": True})
        for variant in variants:
            data = fixture()
            finish = json.loads(data["unit_records"][0]["finish_bytes"])
            finish.update(variant)
            data["unit_records"][0]["finish_bytes"] = encoded(finish)
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                subject.collect_cargo_artifacts(**data)

    def test_original_forwarded_recipe_and_target_are_bound(self):
        for mutate in (lambda start: start["forwarded_argv"].append("-Copt-level=3"),
                       lambda start: start.update(changes=[]),
                       lambda start: start["original_argv"].__setitem__(start["original_argv"].index(subject.TARGET), "aarch64-pc-windows-msvc")):
            data = fixture()
            mutate_start(data, 0, mutate)
            with self.assertRaises(ValueError):
                subject.collect_cargo_artifacts(**data)

    def test_missing_or_duplicate_artifact_not_coverage(self):
        for duplicate in (False, True):
            data = fixture()
            rows = data["cargo_jsonl_bytes"].splitlines()
            data["cargo_jsonl_bytes"] = b"\n".join(([rows[0], rows[0], *rows[1:]]) if duplicate else rows[1:])
            with self.assertRaises(ValueError):
                subject.collect_cargo_artifacts(**data)

    def test_fresh_false_and_build_finished_required(self):
        for change in ("fresh", "finish", "hook", "trailing"):
            data = fixture()
            if change == "fresh":
                mutate_message(data, 0, lambda row: row.update(fresh=True))
            elif change == "finish":
                data["cargo_jsonl_bytes"] = b"\n".join(data["cargo_jsonl_bytes"].splitlines()[:-1])
            elif change == "hook":
                data["cargo_jsonl_bytes"] = encoded({"reason": "build-script-executed"}) + b"\n" + data["cargo_jsonl_bytes"]
            else:
                data["cargo_jsonl_bytes"] += b"\n" + encoded({"reason": "compiler-artifact"})
            with self.subTest(change=change), self.assertRaises(ValueError):
                subject.collect_cargo_artifacts(**data)

    def test_package_source_features_and_target_identity_exact(self):
        changes = (lambda row: row.update(package_id="unknown"), lambda row: row.update(features=[]),
                   lambda row: row["target"].update(name="other"), lambda row: row["target"].update(edition="2018"),
                   lambda row: row["target"].update(src_path=r"C:\outside\lib.rs"))
        for change in changes:
            data = fixture()
            mutate_message(data, 0, change)
            with self.assertRaises(ValueError):
                subject.collect_cargo_artifacts(**data)

    def test_published_copy_bound_by_exact_basename_and_bytes_not_file_identity(self):
        data = fixture()
        path = next(path for path in data["observed_files"] if path.endswith("librules.rlib"))
        copy_path = ntpath.dirname(ntpath.dirname(path)) + r"\librules.rlib"
        data["observed_files"][copy_path] = copy.deepcopy(data["observed_files"][path])
        mutate_message(data, 0, lambda row: row.update(filenames=[copy_path]))
        result = subject.collect_cargo_artifacts(**data)
        self.assertEqual(result["units"][0]["outputs"][0]["declared_output"], subject._path(path))
        data["observed_files"][copy_path]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "content binding"):
            subject.collect_cargo_artifacts(**data)

    def test_external_artifact_and_unexplained_dep_info_rejected(self):
        data = fixture()
        mutate_message(data, 0, lambda row: row.update(filenames=[r"C:\outside\librules.rlib"]))
        with self.assertRaises(ValueError):
            subject.collect_cargo_artifacts(**data)
        data = fixture()
        extra = data["arm"]["policy"]["target_root"] + r"\unexplained.d"
        data["dep_info_contents"][extra] = b"a.d: a.rs\n"
        data["observed_files"][extra] = {"sha256": sha(b"a.d: a.rs\n"), "bytes": len(b"a.d: a.rs\n")}
        with self.assertRaisesRegex(ValueError, "unexplained dep-info"):
            subject.collect_cargo_artifacts(**data)

    def test_dep_info_disagreeing_rules_and_phony_extra_rejected(self):
        for suffix in (b"\nC:\\owned\\outside.d: src/lib.rs\n", b"\nsrc/untracked.rs:\n"):
            data = fixture()
            replace_dep(data, 0, lambda raw: raw + suffix)
            with self.assertRaises(ValueError):
                subject.collect_cargo_artifacts(**data)

    def test_unmatched_extern_producer_rejected(self):
        data = fixture()
        path = data["arm"]["policy"]["target_root"] + r"\unrecorded.rlib"
        data["observed_files"][path] = {"sha256": sha(b"unrecorded"), "bytes": len(b"unrecorded")}

        def mutation(start):
            old = next(value for value in start["original_argv"] if value.startswith("rules="))
            old_path = old.split("=", 1)[1]
            start["original_argv"][start["original_argv"].index(old)] = "rules=" + path
            derived = cargo_units.derive_recipe(start["original_argv"][1:], start["mode"])
            start["forwarded_argv"] = [start["original_argv"][0], *derived["forwarded_argv"]]
            start["changes"] = derived["changes"]
            del start["consumed_inputs"][old_path]
            start["consumed_inputs"][path] = sha(b"unrecorded")

        mutate_start(data, 1, mutation)
        with self.assertRaisesRegex(ValueError, "producer"):
            subject.collect_cargo_artifacts(**data)


class GenericCollectionTests(unittest.TestCase):
    def test_single_local_library_has_no_invented_extern(self):
        result = subject.collect_cargo_artifacts(**fixture(names=("standalone",)))
        self.assertEqual(result["actual_compiled_units"], 1)
        self.assertEqual(result["units"][0]["externs"], [])

    def test_three_crate_chain_is_bound_by_actual_producers(self):
        result = subject.collect_cargo_artifacts(**fixture(names=("bits", "rules", "service")))
        self.assertEqual(result["actual_compiled_units"], 3)
        units = {item["unit"]: item for item in result["units"]}
        self.assertEqual(units["1"]["externs"][0]["producer_unit"], "0")
        self.assertEqual(units["2"]["externs"][0]["producer_unit"], "1")
        closure = subject._transitive_dependencies(result["units"])
        self.assertEqual(closure["2"]["units"], ["0", "1", "2"])
        self.assertEqual(len(closure["2"]["dependencies"]), 6)

    def test_five_crates_under_relocated_drive_roots(self):
        data = fixture(names=("bits", "rules", "cost", "order", "api"),
                       workspace=r"D:\work\business", capture=r"E:\private\build",
                       tool_root=r"F:\sdk\rust")
        result = subject.collect_cargo_artifacts(**data)
        self.assertEqual(result["actual_compiled_units"], 5)
        self.assertTrue(all(item["source"].startswith("d:\\work\\business\\") for item in result["units"]))
        self.assertEqual(result["units"][4]["externs"][0]["producer_unit"], "3")

    def test_message_record_and_metadata_order_do_not_define_edges(self):
        data = fixture(names=("bits", "rules", "service"))
        expected = subject.collect_cargo_artifacts(**data)
        data["unit_records"].reverse()
        data["packages"].reverse()
        rows = data["cargo_jsonl_bytes"].splitlines()
        data["cargo_jsonl_bytes"] = b"\n".join([*reversed(rows[:-1]), rows[-1]])
        actual = subject.collect_cargo_artifacts(**data)
        self.assertEqual(sorted(actual["units"], key=lambda row: row["unit"]),
                         sorted(expected["units"], key=lambda row: row["unit"]))

    def test_duplicate_unit_id_rejected(self):
        data = fixture()
        data["unit_records"][1]["unit"] = data["unit_records"][0]["unit"]
        with self.assertRaisesRegex(ValueError, "duplicate unit"):
            subject.collect_cargo_artifacts(**data)

    def test_duplicate_metadata_package_identity_rejected(self):
        data = fixture()
        data["packages"].append(copy.deepcopy(data["packages"][0]))
        with self.assertRaisesRegex(ValueError, "exact inspected local graph"):
            subject.collect_cargo_artifacts(**data)

    def test_case_colliding_source_snapshot_rejected(self):
        data = fixture()
        path = next(iter(data["source_snapshot"]))
        data["source_snapshot"][path.upper()] = data["source_snapshot"][path]
        with self.assertRaisesRegex(ValueError, "ambiguous snapshot"):
            subject.collect_cargo_artifacts(**data)

    def test_case_colliding_post_build_inventory_rejected(self):
        data = fixture()
        path = next(iter(data["observed_files"]))
        data["observed_files"][path.upper()] = copy.deepcopy(data["observed_files"][path])
        with self.assertRaisesRegex(ValueError, "invalid observed file"):
            subject.collect_cargo_artifacts(**data)

    def test_case_colliding_raw_dep_info_rejected(self):
        data = fixture()
        path = next(iter(data["dep_info_contents"]))
        data["dep_info_contents"][path.upper()] = data["dep_info_contents"][path]
        with self.assertRaisesRegex(ValueError, "ambiguous/unowned"):
            subject.collect_cargo_artifacts(**data)

    def test_source_and_compiler_snapshot_overlap_rejected(self):
        data = fixture()
        path = next(iter(data["source_snapshot"]))
        data["compiler_snapshot"][path] = data["source_snapshot"][path]
        with self.assertRaisesRegex(ValueError, "overlaps"):
            subject.collect_cargo_artifacts(**data)

    def test_boolean_negative_or_noninteger_observed_sizes_rejected(self):
        for size in (True, -1, 1.5, "1"):
            data = fixture()
            data["observed_files"][next(iter(data["observed_files"]))]["bytes"] = size
            with self.subTest(size=size), self.assertRaisesRegex(ValueError, "invalid observed file"):
                subject.collect_cargo_artifacts(**data)

    def test_target_root_prefix_sibling_is_not_owned_output(self):
        data = fixture()
        path = data["arm"]["policy"]["target_root"] + r"-foreign\librules.rlib"
        data["observed_files"][path] = {"sha256": sha(b"foreign library"), "bytes": 15}
        mutate_message(data, 0, lambda row: row.update(filenames=[path]))
        with self.assertRaisesRegex(ValueError, "unowned"):
            subject.collect_cargo_artifacts(**data)

    def test_changed_pinned_compiler_file_is_rejected(self):
        data = fixture()
        path = r"C:\tools\sysroot\lib\compiler-input.rlib"
        data["compiler_snapshot"][path] = sha(b"before")
        data["observed_files"][path] = {"sha256": sha(b"after"), "bytes": 5}
        with self.assertRaisesRegex(ValueError, "input missing/changed"):
            subject.collect_cargo_artifacts(**data)

    def test_collection_does_not_mutate_supplied_observations(self):
        data = fixture(names=("bits", "rules", "service"))
        before = copy.deepcopy(data)
        subject.collect_cargo_artifacts(**data)
        self.assertEqual(data, before)

    def test_pinned_linker_descriptor_bytes_and_exact_recipe_required(self):
        for change in ("missing_record", "changed_bytes", "wrong_path", "missing_argument", "duplicate_argument"):
            data = fixture()
            linker = data["arm"]["policy"]["linker"]

            def mutate(start):
                if change == "missing_record":
                    del start["linker"]
                    return
                args = start["original_argv"]
                position = args.index("linker=" + linker)
                if change == "wrong_path":
                    args[position] = r"linker=C:\foreign\other-linker.exe"
                elif change == "missing_argument":
                    del args[position - 1:position + 1]
                elif change == "duplicate_argument":
                    args.extend(["-C", "linker=" + linker])
                derived = cargo_units.derive_recipe(args[1:], start["mode"])
                start["forwarded_argv"] = [args[0], *derived["forwarded_argv"]]
                start["changes"] = derived["changes"]

            with self.subTest(change=change), self.assertRaises(ValueError):
                if change == "changed_bytes":
                    data["observed_files"][linker]["sha256"] = sha(b"changed linker")
                else:
                    mutate_start(data, 0, mutate)
                subject.collect_cargo_artifacts(**data)


class AggregateTests(unittest.TestCase):
    def test_published_dll_and_rlib_aggregate_exact_transitive_union(self):
        for mode in ("original", "derivative"):
            data = fixture(mode)
            paths, dependencies = published_aggregates(data)
            result = subject.collect_cargo_artifacts(**data)
            aggregates = result["aggregate_dep_info"]
            self.assertEqual({item["path"] for item in aggregates}, {subject._path(path) for path in paths})
            self.assertEqual(len(aggregates), 2)
            for item in aggregates:
                self.assertEqual(item["classification"], "cargo_published_aggregate_dep_info")
                self.assertEqual(item["owner_unit"], "1")
                self.assertEqual(item["transitive_units"], ["0", "1"])
                self.assertEqual({row["path"] for row in item["declared_dependencies"]}, {subject._path(path) for path in dependencies})
                self.assertEqual(item["sha256"], data["observed_files"][paths[0] if item["path"] == subject._path(paths[0]) else paths[1]]["sha256"])

    def test_missing_transitive_source_rejected(self):
        data = fixture()
        paths, dependencies = published_aggregates(data)
        set_dep(data, paths[0], data["dep_info_contents"][paths[0]].replace((dependencies[0] + " ").encode(), b""))
        with self.assertRaisesRegex(ValueError, "transitive declared-source union"):
            subject.collect_cargo_artifacts(**data)

    def test_extra_foreign_and_unrelated_pinned_source_rejected(self):
        for pinned in (False, True):
            data = fixture()
            paths, _ = published_aggregates(data)
            path = r"C:\owned\project\unrelated.rs" if pinned else r"C:\outside\foreign.rs"
            if pinned:
                data["source_snapshot"][path] = sha(b"unrelated")
                data["observed_files"][path] = {"sha256": sha(b"unrelated"), "bytes": len(b"unrelated")}
            raw = data["dep_info_contents"][paths[0]].rstrip(b"\n") + b" " + path.encode() + b"\n"
            set_dep(data, paths[0], raw)
            with self.subTest(pinned=pinned), self.assertRaisesRegex(ValueError, "transitive declared-source union"):
                subject.collect_cargo_artifacts(**data)

    def test_duplicate_rhs_source_rejected_not_set_normalized(self):
        data = fixture()
        paths, dependencies = published_aggregates(data)
        set_dep(data, paths[0], data["dep_info_contents"][paths[0]].rstrip(b"\n") + b" " + dependencies[0].encode() + b"\n")
        with self.assertRaisesRegex(ValueError, "transitive declared-source union"):
            subject.collect_cargo_artifacts(**data)

    def test_exact_same_directory_suffix_mapping_required(self):
        data = fixture()
        paths, _ = published_aggregates(data)
        raw = data["dep_info_contents"].pop(paths[0])
        data["observed_files"].pop(paths[0])
        unexpected = ntpath.dirname(paths[0]) + r"\wrong-name.d"
        set_dep(data, unexpected, raw)
        with self.assertRaisesRegex(ValueError, "unexplained dep-info"):
            subject.collect_cargo_artifacts(**data)

    def test_target_must_be_exact_published_output(self):
        data = fixture()
        paths, _ = published_aggregates(data)
        raw = data["dep_info_contents"][paths[0]]
        target = ntpath.splitext(paths[0])[0] + ".rlib"
        set_dep(data, paths[0], raw.replace(target.encode(), br"C:\outside\library.rlib", 1))
        with self.assertRaisesRegex(ValueError, "exact published primary"):
            subject.collect_cargo_artifacts(**data)

    def test_env_phony_or_second_rule_rejected(self):
        for extra in (b"# env-dep:PATH=private-value\n", b"C:\\owned\\source.rs:\n", b"C:\\owned\\other.dll: C:\\owned\\source.rs\n"):
            data = fixture()
            paths, _ = published_aggregates(data)
            set_dep(data, paths[0], data["dep_info_contents"][paths[0]] + extra)
            with self.assertRaisesRegex(ValueError, "one rule"):
                subject.collect_cargo_artifacts(**data)

    def test_raw_aggregate_hash_and_inventory_omission_rejected(self):
        for omit in (False, True):
            data = fixture()
            paths, _ = published_aggregates(data)
            if omit:
                del data["dep_info_contents"][paths[0]]
            else:
                data["dep_info_contents"][paths[0]] += b"\n"
            with self.subTest(omit=omit), self.assertRaises(ValueError):
                subject.collect_cargo_artifacts(**data)

    def test_ambiguous_aggregate_output_owner_rejected(self):
        root = r"c:\target"
        dependency = {"path": r"c:\owned\source.rs", "sha256": "1" * 64, "classification": "owned_source"}
        outputs = [{"path": root + "\\same" + suffix, "sha256": "2" * 64, "bytes": 2, "declared_output": root + "\\same" + suffix} for suffix in (".dll", ".rlib")]
        unit = {"unit": "one", "externs": [], "declared_dependencies": [dependency], "dep_info": {"path": root + r"\unit.d"}, "outputs": outputs}
        raw = (outputs[0]["path"] + ": " + dependency["path"] + "\n").encode()
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            subject._aggregate_dep_info({root + r"\same.d": subject.parse_dep_info(raw)}, [unit], {})

    def test_cycle_rejected_even_without_aggregate_files(self):
        units = [{"unit": "one", "externs": [{"producer_unit": "two"}], "declared_dependencies": []},
                 {"unit": "two", "externs": [{"producer_unit": "one"}], "declared_dependencies": []}]
        with self.assertRaisesRegex(ValueError, "cycle"):
            subject._transitive_dependencies(units)

    def test_shared_dependency_dag_is_not_mistaken_for_cycle(self):
        dependency = {"path": r"c:\owned\common.rs", "sha256": "1" * 64, "classification": "owned_source"}
        units = [{"unit": "top", "externs": [{"producer_unit": "left"}, {"producer_unit": "right"}], "declared_dependencies": []},
                 {"unit": "left", "externs": [{"producer_unit": "base"}], "declared_dependencies": []},
                 {"unit": "right", "externs": [{"producer_unit": "base"}], "declared_dependencies": []},
                 {"unit": "base", "externs": [], "declared_dependencies": [dependency]}]
        closure = subject._transitive_dependencies(units)
        self.assertEqual(closure["top"]["units"], ["base", "left", "right", "top"])
        self.assertEqual(closure["top"]["dependencies"], [dependency])


class DiagnosticBindingTests(unittest.TestCase):
    def test_allowlisted_raw_value_must_hash_match_and_is_not_returned(self):
        data = fixture()

        def good(start):
            start["environment_value_sha256"]["PATH"] = sha(b"private-path-value")
            start["diagnostic_environment"] = {"PATH": "private-path-value"}

        mutate_start(data, 0, good)
        result = subject.collect_cargo_artifacts(**data)
        self.assertNotIn("private-path-value", encoded(result).decode())
        mutate_start(data, 0, lambda start: start["diagnostic_environment"].update(PATH="wrong"))
        with self.assertRaisesRegex(ValueError, "diagnostic"):
            subject.collect_cargo_artifacts(**data)

    def test_extra_or_missing_raw_diagnostic_rejected(self):
        for mutate in (lambda start: start["diagnostic_environment"].update(SECRET="not-allowlisted"),
                       lambda start: start.pop("diagnostic_environment"),
                       lambda start: start["environment_value_sha256"].update(CARGO_MAKEFLAGS=sha(b"jobserver"))):
            data = fixture()
            mutate_start(data, 0, mutate)
            with self.assertRaisesRegex(ValueError, "diagnostic"):
                subject.collect_cargo_artifacts(**data)


if __name__ == "__main__":
    unittest.main()


