"""PLAN-only integration tests; all metadata is inert.

No compiler, Cargo executable, target or subprocess may execute in this suite.
The actual reused inspector handles inventories and fake Cargo JSON/receipts.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from antirea import projects, rust_cargo
from antirea.defense_mcp import DefenseBridge, TOOLS


class CargoPlanIntegration(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='cargo-plan-integration-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / 'owned-component'
        self.rules = self.root / 'local-rules'
        for directory in (self.source / 'src', self.rules / 'src', self.root / '.tools', self.root / 'cargo-home'):
            directory.mkdir(parents=True)
        self.project = self.source / 'project.json'
        self.source_code = self.source / 'src/lib.rs'
        self.source_code.write_text('pub fn score(x:u64)->u64 { x.wrapping_add(1) }', encoding='utf-8')
        (self.rules / 'src/lib.rs').write_text('pub fn choose(x:u64)->u64 { x ^ 7 }', encoding='utf-8')
        (self.source / 'Cargo.toml').write_text(
            '[package]\nname="component"\nversion="0.1.0"\nedition="2021"\n'
            '[dependencies]\nrules={path="../local-rules"}\n'
            '[features]\nextra=[]\n[profile.release]\nopt-level=2\n', encoding='utf-8')
        (self.source / 'Cargo.lock').write_text(
            'version=4\n[[package]]\nname="component"\nversion="0.1.0"\ndependencies=["rules"]\n'
            '[[package]]\nname="rules"\nversion="0.1.0"\n', encoding='utf-8')
        (self.rules / 'Cargo.toml').write_text('[package]\nname="rules"\nversion="0.1.0"\nedition="2021"\n', encoding='utf-8')
        self.manifest = {'schema_version': 1, 'name': 'component', 'language': 'rust', 'functions': ['score'],
            'rust_cargo': {'manifest_path': 'Cargo.toml', 'package': 'component', 'target_kind': 'lib',
                'profile': 'release', 'features': [], 'default_features': True,
                'local_dependency_roots': ['../local-rules']}}
        self.save_manifest()
        self.sysroot = self.root / 'trusted-backend'
        (self.sysroot / 'bin').mkdir(parents=True)
        target_lib = self.sysroot / 'lib/rustlib' / rust_cargo.TARGET / 'lib'
        target_lib.mkdir(parents=True)
        for name in ('cargo.exe', 'rustc.exe', 'rustc_driver.dll'):
            (self.sysroot / 'bin' / name).write_bytes(('inert mock ' + name).encode())
        (target_lib / 'libcore.rlib').write_bytes(b'inert mock core library')
        self.configuration = {'schema_version': 1, 'cargo': str(self.sysroot / 'bin/cargo.exe'),
            'rustc': str(self.sysroot / 'bin/rustc.exe'), 'sysroot': str(self.sysroot), 'target': rust_cargo.TARGET}
        self.config_path = self.root / '.tools/rust-cargo-toolchain.json'
        self.save_config()
        self.metadata = {'version': 1, 'workspace_root': str(self.source), 'workspace_members': ['root'],
            'packages': [self.package('root', 'component', self.source), self.package('rules', 'rules', self.rules)],
            'resolve': {'nodes': [{'id': 'root', 'deps': [{'name': 'rules', 'pkg': 'rules',
                'dep_kinds': [{'kind': None, 'target': None}]}], 'features': []},
                {'id': 'rules', 'deps': [], 'features': []}]}}
        self.windows = self.root / 'fake-windows'
        (self.windows / 'System32').mkdir(parents=True)
        self.environment = {'CARGO_HOME': str(self.root / 'cargo-home'), 'USERPROFILE': str(self.root),
                            'SYSTEMROOT': str(self.windows), 'WINDIR': str(self.windows),
                            'PATH': 'inert mock path', 'PRIVATE_TOKEN': 'never-serialize-this-test-value',
                            'OPENAI_API_KEY': 'another-not-inherited-secret', 'PYTHONPATH': 'not-inherited'}
        self.calls = []
        self.callback = None
        self.service = projects.ProjectService(self.root)
        for mocker in (
            patch.dict(os.environ, self.environment, clear=True),
            patch('antirea.process.run_logged', side_effect=self.fake_metadata),
            patch('subprocess.Popen', side_effect=AssertionError('No actual process permitted')),
            patch('subprocess.run', side_effect=AssertionError('No actual process permitted')),
        ):
            mocker.start()
            self.addCleanup(mocker.stop)

    def save_manifest(self):
        self.project.write_text(json.dumps(self.manifest), encoding='utf-8')

    def save_config(self):
        self.config_path.write_text(json.dumps(self.configuration), encoding='utf-8')

    @staticmethod
    def package(identity, name, directory):
        return {'id': identity, 'name': name, 'version': '0.1.0', 'source': None, 'links': None,
            'manifest_path': str(directory / 'Cargo.toml'), 'edition': '2021',
            'targets': [{'kind': ['lib'], 'crate_types': ['lib'], 'name': name,
                'src_path': str(directory / 'src/lib.rs'), 'edition': '2021'}]}

    def fake_metadata(self, argv, cwd, prefix, **kwargs):
        self.assertEqual(argv[:2], [self.configuration['cargo'], 'metadata'])
        self.assertTrue(prefix.parent.parent.is_dir())
        self.assertTrue(prefix.parent.is_dir())
        self.assertEqual(prefix.parent.name, 'inspection')
        self.assertEqual(prefix.parent.parent.parent, self.service.output_root)
        self.assertFalse((prefix.parent.parent / 'build').exists())
        self.calls.append((argv, cwd, prefix, kwargs))
        prefix.with_suffix('.stdout.log').write_text(json.dumps(self.metadata), encoding='utf-8')
        prefix.with_suffix('.stderr.log').write_bytes(b'')
        pid = 100 + len(self.calls)
        process = {'argv': argv, 'returncode': 0, 'pid': pid, 'seconds': float(len(self.calls)),
            'cancelled': False, 'timed_out': False, 'stdout': str(prefix.with_suffix('.stdout.log')),
            'stderr': str(prefix.with_suffix('.stderr.log')), 'mock_only': True,
            'cleanup': {'method': 'windows_job', 'status': 'assigned_job_empty', 'job_assigned': True,
                'active_after': 0, 'parent_pid': pid, 'parent_exit_confirmed': True, 'job_handle_closed': True}}
        prefix.with_suffix('.process.json').write_text(json.dumps(process), encoding='utf-8')
        if self.callback:
            self.callback(prefix, process)
        return process

    def plan(self, **kwargs):
        return self.service.plan(self.project, **kwargs)

    def test_explicit_manifest_creates_job_before_metadata_and_stays_build_blocked(self):
        result = self.plan()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(result['backend'], 'rust_cargo_native')
        self.assertEqual(result['kind'], 'rust_cargo_inspection')
        self.assertEqual(result['inspection_status'], 'inspected_build_not_implemented')
        self.assertEqual(result['status'], 'blocked')
        self.assertIn('rust_cargo_build_not_implemented', result['blockers'])
        self.assertFalse(result['build_implemented'])
        self.assertFalse(result['executes_target_build'])
        self.assertFalse(result['executes_application'])
        self.assertFalse(result['publishes'])
        self.assertFalse(Path(result['output_dir']).exists())

    def test_receipt_descriptor_binds_raw_inspection_and_metadata_logs(self):
        result = self.plan()
        item = result['inspection_receipt']
        raw = Path(item['path']).read_bytes()
        self.assertEqual(item['bytes'], len(raw))
        self.assertEqual(item['sha256'], hashlib.sha256(raw).hexdigest())
        saved = json.loads(raw)
        self.assertEqual(saved['inspection'], result['inspection'])
        self.assertEqual(result['inspection_verification']['status'], 'unchanged')
        for descriptor in saved['metadata_evidence']['files'].values():
            self.assertEqual(hashlib.sha256(Path(descriptor['path']).read_bytes()).hexdigest(), descriptor['sha256'])

    def test_source_and_sibling_dependency_inventories_are_bound(self):
        result = self.plan()
        self.assertEqual(set(result['inputs']['roots']), {str(self.source), str(self.rules)})
        records = {row['path']: row for row in result['inputs']['files']}
        for path in (self.project, self.source_code, self.rules / 'src/lib.rs', self.source / 'Cargo.lock'):
            self.assertEqual(records[str(path)]['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_actual_tool_backend_and_sysroot_inventory_are_recorded(self):
        result = self.plan()
        tools = result['inspection']['toolchain']
        self.assertEqual(tools['selection']['rustc'], self.configuration['rustc'])
        expected = self.sysroot / 'bin/rustc_driver.dll'
        self.assertEqual(tools['compiler_inputs'][str(expected)], hashlib.sha256(expected.read_bytes()).hexdigest())
        self.assertEqual(result['toolchain']['configuration']['sha256'], hashlib.sha256(self.config_path.read_bytes()).hexdigest())

    def test_semantic_fingerprint_stable_across_fresh_receipts(self):
        first, second = self.plan(), self.plan()
        self.assertNotEqual(first['plan_id'], second['plan_id'])
        self.assertNotEqual(first['inspection_receipt']['sha256'], second['inspection_receipt']['sha256'])
        self.assertNotEqual(first['fingerprint'], second['fingerprint'])
        self.assertEqual(first['semantic_fingerprint'], second['semantic_fingerprint'])

    def test_semantic_fingerprint_changes_with_seed_source_or_tool(self):
        first = self.plan()
        self.assertNotEqual(first['semantic_fingerprint'], self.plan(seed=1730)['semantic_fingerprint'])
        self.source_code.write_text('pub fn score(x:u64)->u64 { x ^ 9 }', encoding='utf-8')
        changed = self.plan()
        self.assertNotEqual(first['semantic_fingerprint'], changed['semantic_fingerprint'])
        (self.sysroot / 'bin/rustc_driver.dll').write_bytes(b'changed inert tool')
        self.assertNotEqual(changed['semantic_fingerprint'], self.plan()['semantic_fingerprint'])

    def test_exact_outer_plan_fingerprint_includes_receipt(self):
        result = self.plan()
        saved = json.loads((self.service.output_root / result['plan_id'] / 'plan.json').read_bytes())
        self.assertEqual(result['fingerprint'], projects._digest(projects._encoded(saved)))
        saved['inspection_receipt']['sha256'] = '0' * 64
        self.assertNotEqual(result['fingerprint'], projects._digest(projects._encoded(saved)))

    def test_raw_environment_values_are_not_serialized(self):
        result = self.plan()
        self.assertNotIn(self.environment['PRIVATE_TOKEN'], json.dumps(result))
        self.assertIn('sha256', result['inspection']['environment'])

    def test_child_environment_is_exact_minimal_allowlist_not_parent_copy(self):
        result = self.plan()
        _, _, prefix, kwargs = self.calls[0]
        child = kwargs['env']
        expected = {'SYSTEMROOT', 'WINDIR', 'PATH', 'RUSTC', 'CARGO_NET_OFFLINE', 'CARGO_TERM_COLOR',
                    'CARGO_TARGET_DIR', 'CARGO_HOME', 'HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP'}
        self.assertEqual(set(child), expected)
        self.assertEqual(child['PATH'], str(self.sysroot / 'bin') + ';' + str(self.windows / 'System32'))
        self.assertEqual(child['RUSTC'], self.configuration['rustc'])
        self.assertEqual(child['CARGO_NET_OFFLINE'], 'true')
        for key in ('CARGO_HOME', 'HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP'):
            self.assertTrue(Path(child[key]).is_relative_to(prefix.parent))
            self.assertTrue(Path(child[key]).is_dir())
        for key in ('PRIVATE_TOKEN', 'OPENAI_API_KEY', 'PYTHONPATH'):
            self.assertNotIn(key, child)
            self.assertNotIn(self.environment[key], json.dumps(result))

    def test_actual_environment_receipt_distinct_from_stable_semantic_template(self):
        first, second = self.plan(), self.plan()
        one = json.loads(Path(first['inspection_receipt']['path']).read_bytes())
        two = json.loads(Path(second['inspection_receipt']['path']).read_bytes())
        self.assertEqual(first['semantic_fingerprint'], second['semantic_fingerprint'])
        self.assertEqual(one['inspection']['environment'], two['inspection']['environment'])
        self.assertNotEqual(one['metadata_evidence']['execution_environment'],
                            two['metadata_evidence']['execution_environment'])
        self.assertNotIn(first['plan_id'], json.dumps(first['inspection']['environment']))
        self.assertIn('<inspection>', json.dumps(first['inspection']['environment']))

    def test_irrelevant_secret_change_is_not_semantic_input_or_child_variable(self):
        first = self.plan()
        os.environ['PRIVATE_TOKEN'] = 'changed-secret-not-a-tool-input'
        second = self.plan()
        self.assertEqual(first['semantic_fingerprint'], second['semantic_fingerprint'])
        self.assertNotIn('PRIVATE_TOKEN', self.calls[-1][3]['env'])

    def test_cargo_and_rust_overrides_block_before_query_without_values(self):
        for name in ('RUSTFLAGS', 'RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER',
                     'RUSTUP_TOOLCHAIN', 'CARGO_BUILD_TARGET', 'CARGO_ENCODED_RUSTFLAGS',
                     'CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER', 'CARGO_REGISTRIES_CRATES_IO_TOKEN'):
            with self.subTest(name=name), patch.dict(os.environ, {name: 'override-secret-value'}):
                result = self.plan()
                self.assertEqual(result['inspection_status'], 'blocked')
                self.assertIn('unsupported_environment_selector:' + name, result['blockers'])
                self.assertNotIn('override-secret-value', json.dumps(result))
                self.assertEqual(self.calls, [])

    def test_global_cargo_config_is_not_silently_hidden_by_private_home(self):
        config = self.root / 'cargo-home/config.toml'
        config.write_text('[profile.release]\nopt-level=1\n# private-config-token\n', encoding='utf-8')
        result = self.plan()
        self.assertEqual(result['inspection_status'], 'blocked')
        self.assertIn('unsupported_cargo_configuration:' + str(config), result['blockers'])
        self.assertEqual(self.calls, [])
        self.assertNotIn('private-config-token', json.dumps(result))
        records = {item['path']: item for item in result['inspection']['configuration']['discovery']}
        self.assertEqual(records[str(config)]['sha256'], hashlib.sha256(config.read_bytes()).hexdigest())

    def test_default_userprofile_global_config_is_also_blocked(self):
        del os.environ['CARGO_HOME']
        config = self.root / '.cargo/config'
        config.parent.mkdir()
        config.write_text('[build]\njobs=2\n', encoding='utf-8')
        result = self.plan()
        self.assertEqual(self.calls, [])
        self.assertIn('unsupported_cargo_configuration:' + str(config), result['blockers'])

    def test_project_config_is_explicit_blocker_not_silently_ignored(self):
        config = self.source / '.cargo/config.toml'
        config.parent.mkdir()
        config.write_text('[net]\noffline=true\n', encoding='utf-8')
        result = self.plan()
        self.assertEqual(self.calls, [])
        self.assertIn('unsupported_cargo_configuration:' + str(config), result['blockers'])

    def test_changed_global_config_invalidates_saved_inspection(self):
        result = self.plan()
        receipt = Path(result['inspection_receipt']['path'])
        (self.root / 'cargo-home/config.toml').write_text('[net]\noffline=true\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'configuration/environment changed'):
            rust_cargo.verify_plan(json.loads(receipt.read_bytes()), plan_path=receipt,
                workspace_root=self.root, toolchain=result['toolchain']['selection'])
        self.assertEqual(len(self.calls), 1)

    def test_override_added_during_query_invalidates_outer_plan(self):
        self.callback = lambda *_: os.environ.__setitem__('RUSTFLAGS', 'changed-control')
        with self.assertRaisesRegex(ValueError, 'configuration/environment changed'):
            self.plan()
        inner = self.calls[0][2].parent / 'plan.json'
        self.assertEqual(json.loads(inner.read_bytes())['inspection']['status'], 'inputs_changed')
        self.assertFalse((inner.parent.parent / 'plan.json').exists())

    def test_environment_receipt_tamper_rejected_even_if_plan_rehashed(self):
        result = self.plan()
        receipt = Path(result['inspection_receipt']['path'])
        saved = json.loads(receipt.read_bytes())
        saved['metadata_evidence']['execution_environment']['sha256'] = '0' * 64
        receipt.write_text(json.dumps(saved), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'execution environment receipt mismatch'):
            rust_cargo.verify_plan(saved, plan_path=receipt, workspace_root=self.root,
                toolchain=result['toolchain']['selection'])

    def test_invalid_windows_host_never_queries(self):
        for change in ({'SYSTEMROOT': 'relative', 'WINDIR': 'relative'},
                       {'WINDIR': str(self.root)}):
            with self.subTest(change=change), patch.dict(os.environ, change):
                with self.assertRaises(ValueError):
                    self.plan()
        self.assertEqual(self.calls, [])

    def test_plain_mapping_duplicate_environment_case_never_queries(self):
        # Windows os.environ normalizes key case, so use the direct env seam.
        (self.root / '.runs').mkdir()
        with self.assertRaisesRegex(ValueError, 'ambiguous case-insensitive'):
            rust_cargo.inspect_project(self.project, workspace_root=self.root,
                toolchain={key: self.configuration[key] for key in ('cargo', 'rustc', 'sysroot', 'target')},
                output_dir=self.root / '.runs/duplicate-env', env={**self.environment, 'Path': 'second-spelling'})
        self.assertEqual(self.calls, [])

    def test_missing_windows_host_never_queries(self):
        del os.environ['SYSTEMROOT']
        del os.environ['WINDIR']
        with self.assertRaisesRegex(ValueError, 'SYSTEMROOT or WINDIR'):
            self.plan()
        self.assertEqual(self.calls, [])

    def test_missing_global_home_discovery_rejects_before_query(self):
        for name in ('CARGO_HOME', 'USERPROFILE', 'HOME'):
            os.environ.pop(name, None)
        with self.assertRaisesRegex(ValueError, 'required for global Cargo config discovery'):
            self.plan()
        self.assertEqual(self.calls, [])

    def test_global_home_discovery_uses_explicit_cargo_then_profile_then_home(self):
        cargo_home = self.root / 'cargo-home'
        profile = self.root / 'separate-profile'
        fallback = self.root / 'separate-home'
        for directory in (cargo_home, profile / '.cargo', fallback / '.cargo'):
            directory.mkdir(parents=True, exist_ok=True)
            (directory / 'config.toml').write_text('[net]\noffline=true\n', encoding='utf-8')
        for override, expected in ((str(cargo_home), cargo_home), ('', profile / '.cargo')):
            with self.subTest(cargo_home=override), patch.dict(os.environ,
                    {'CARGO_HOME': override, 'USERPROFILE': str(profile), 'HOME': str(fallback)}):
                result = self.plan()
                self.assertIn('unsupported_cargo_configuration:' + str(expected / 'config.toml'), result['blockers'])
        with patch.dict(os.environ, {'CARGO_HOME': '', 'USERPROFILE': '', 'HOME': str(fallback)}):
            result = self.plan()
            self.assertIn('unsupported_cargo_configuration:' + str(fallback / '.cargo/config.toml'), result['blockers'])
        self.assertEqual(self.calls, [])

    def test_build_rejects_before_inspection_or_builder_or_new_marker(self):
        result = self.plan()
        with patch('antirea.projects._inspect') as inspect, patch('antirea.projects._build') as build, \
                patch('antirea.rust_cargo.inspect_project') as metadata:
            with self.assertRaisesRegex(ValueError, 'rust_cargo_build_not_implemented'):
                self.service.build(result['plan_id'], result['fingerprint'])
        inspect.assert_not_called(); build.assert_not_called(); metadata.assert_not_called()
        job = self.service.output_root / result['plan_id']
        self.assertFalse((job / 'started.json').exists())
        self.assertFalse((job / 'build').exists())

    def test_build_remains_disabled_if_generic_blocker_list_is_removed(self):
        result = self.plan()
        path = self.service.output_root / result['plan_id'] / 'plan.json'
        value = json.loads(path.read_bytes())
        value['blockers'] = []
        path.write_text(json.dumps(value), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'rust_cargo_build_not_implemented'):
            self.service.build(result['plan_id'], projects._digest(projects._encoded(value)))
        self.assertEqual(len(self.calls), 1)

    def test_direct_dispatchers_do_not_fall_back_to_single_file_rust(self):
        with self.assertRaisesRegex(ValueError, 'fresh metadata job'):
            projects._inspect(self.project, workspace_root=self.root)
        with self.assertRaisesRegex(ValueError, 'rust_cargo_build_not_implemented'):
            projects._build(self.project, self.root / 'unused', workspace_root=self.root, seed=1)

    def test_non_cargo_route_is_unchanged(self):
        legacy = self.source / 'legacy.json'
        legacy.write_text('{"schema_version":1,"language":"rust","sources":["src/lib.rs"]}', encoding='utf-8')
        (self.root / '.tools/kagura-toolchain.json').write_text('{}', encoding='utf-8')
        with patch('antirea.projects._inspect', return_value={'language': 'rust', 'blockers': []}) as inspector, \
                patch('antirea.projects.shutil.which', return_value=None):
            result = self.service.plan(legacy)
        inspector.assert_called_once()
        self.assertEqual(result['kind'], 'native_source_build')
        self.assertEqual(result['status'], 'planned')
        self.assertEqual(self.calls, [])

    def test_stop_prevents_metadata_and_job_creation(self):
        stop = self.root / '.runs/defense-loop/STOP'
        stop.parent.mkdir(parents=True)
        stop.write_bytes(b'')
        with self.assertRaisesRegex(ValueError, 'STOP'):
            self.plan()
        self.assertEqual(self.calls, [])
        self.assertFalse(self.service.output_root.exists())

    def test_config_missing_or_relative_tool_never_queries_metadata(self):
        self.config_path.unlink()
        with self.assertRaises((OSError, ValueError)):
            self.plan()
        self.configuration['cargo'] = 'cargo.exe'
        self.save_config()
        with self.assertRaisesRegex(ValueError, 'absolute'):
            self.plan()
        self.assertEqual(self.calls, [])

    def test_unknown_config_fields_and_bool_schema_rejected(self):
        for key, value in (('command', 'arbitrary'), ('schema_version', True)):
            original = copy.deepcopy(self.configuration)
            self.configuration[key] = value
            self.save_config()
            with self.assertRaisesRegex(ValueError, 'schema'):
                self.plan()
            self.configuration = original
        self.assertEqual(self.calls, [])

    def test_manifest_cannot_supply_tools_or_wrong_language(self):
        for key, value in (('toolchain', self.configuration), ('language', 'cpp'), ('schema_version', True)):
            original = copy.deepcopy(self.manifest)
            self.manifest[key] = value
            self.save_manifest()
            with self.assertRaises(ValueError):
                self.plan()
            self.manifest = original
        self.assertEqual(self.calls, [])

    def test_service_output_root_cannot_be_a_dependency_input(self):
        target = self.root / '.runs/source-protection/old-job'
        target.mkdir(parents=True)
        self.manifest['rust_cargo']['local_dependency_roots'].append(str(Path('..') / '.runs/source-protection/old-job'))
        self.save_manifest()
        with self.assertRaisesRegex(ValueError, 'service output'):
            self.plan()
        self.assertEqual(self.calls, [])

    def test_build_script_is_blocked_before_metadata(self):
        (self.source / 'build.rs').write_text('fn main() {}', encoding='utf-8')
        result = self.plan()
        self.assertEqual(self.calls, [])
        self.assertEqual(result['inspection_status'], 'blocked')
        self.assertTrue(any('build_script_not_supported' in item for item in result['blockers']))

    def test_configuration_changed_during_metadata_rejects_outer_plan(self):
        self.callback = lambda *_: self.config_path.write_text(self.config_path.read_text() + ' ', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.plan()
        self.assertEqual(len(self.calls), 1)
        self.assertFalse((self.calls[0][2].parent.parent / 'plan.json').exists())

    def test_tampered_raw_process_is_rejected(self):
        self.callback = lambda prefix, _: prefix.with_suffix('.process.json').write_text('{}', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'process record'):
            self.plan()
        self.assertFalse((self.calls[0][2].parent.parent / 'plan.json').exists())

    def test_raw_process_bool_is_not_equal_to_integer_receipt(self):
        def tamper(prefix, process):
            saved = copy.deepcopy(process)
            saved['returncode'] = False
            prefix.with_suffix('.process.json').write_text(json.dumps(saved), encoding='utf-8')
        self.callback = tamper
        with self.assertRaisesRegex(ValueError, 'process record'):
            self.plan()

    def test_failed_metadata_is_never_inspection_success(self):
        def failed(prefix, process):
            process['returncode'] = 1
            prefix.with_suffix('.process.json').write_text(json.dumps(process), encoding='utf-8')
        self.callback = failed
        result = self.plan()
        self.assertEqual(result['inspection_status'], 'metadata_failed')
        self.assertEqual(result['status'], 'blocked')
        self.assertFalse(result['inspection_verification']['metadata_succeeded'])
        self.assertFalse(result['build_implemented'])

    def test_unverified_cleanup_is_never_inspection_success(self):
        def failed(prefix, process):
            process['cleanup']['active_after'] = False
            prefix.with_suffix('.process.json').write_text(json.dumps(process), encoding='utf-8')
        self.callback = failed
        result = self.plan()
        self.assertEqual(result['inspection_status'], 'metadata_failed')
        self.assertFalse(result['inspection_verification']['metadata_succeeded'])

    def test_source_mutation_during_metadata_preserves_failed_inner_evidence(self):
        self.callback = lambda *_: self.source_code.write_text('changed source during mock query', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.plan()
        inner = self.calls[0][2].parent / 'plan.json'
        self.assertEqual(json.loads(inner.read_bytes())['inspection']['status'], 'inputs_changed')
        self.assertFalse((inner.parent.parent / 'plan.json').exists())

    def test_scope_policy_outside_declared_roots_rejected_before_metadata(self):
        outside = self.root / 'shared-policy'
        outside.mkdir()
        policy = outside / 'policy.json'
        policy.write_text('{"policy":"outside inventoried roots"}', encoding='utf-8')
        self.manifest['scope_policy'] = '../shared-policy/policy.json'
        self.save_manifest()
        with self.assertRaisesRegex(ValueError, 'scope_policy must stay inside declared input roots'):
            self.plan()
        self.assertEqual(self.calls, [])
        self.assertFalse(self.service.output_root.exists())
        # The canonical inspector itself enforces this, not just service routing.
        with self.assertRaisesRegex(ValueError, 'scope_policy must stay inside declared input roots'):
            rust_cargo.inspect_project(self.project, workspace_root=self.root,
                toolchain={key: self.configuration[key] for key in ('cargo', 'rustc', 'sysroot', 'target')},
                output_dir=self.root / '.runs/uncreated-inspection', env=self.environment)
        self.assertEqual(self.calls, [])

    def test_scope_policy_inside_project_or_local_root_is_hashed_and_changes_meaning(self):
        for relative, policy in (('policy.json', self.source / 'policy.json'),
                                 ('../local-rules/policy.json', self.rules / 'policy.json')):
            with self.subTest(policy=relative):
                policy.write_text('{"policy":"first"}', encoding='utf-8')
                self.manifest['scope_policy'] = relative
                self.save_manifest()
                first = self.plan()
                expected = hashlib.sha256(policy.read_bytes()).hexdigest()
                records = {row['path']: row for row in first['inputs']['files']}
                self.assertEqual(records[str(policy)]['sha256'], expected)
                self.assertEqual(first['inspection']['input_snapshot']['sha256'], first['inputs']['sha256'])
                policy.write_text('{"policy":"second"}', encoding='utf-8')
                second = self.plan()
                self.assertNotEqual(first['semantic_fingerprint'], second['semantic_fingerprint'])
                self.assertNotEqual(first['inputs']['sha256'], second['inputs']['sha256'])

    def test_scope_policy_content_change_invalidates_saved_inspection(self):
        policy = self.source / 'policy.json'
        policy.write_text('{"policy":"before"}', encoding='utf-8')
        self.manifest['scope_policy'] = 'policy.json'
        self.save_manifest()
        result = self.plan()
        receipt = Path(result['inspection_receipt']['path'])
        saved = json.loads(receipt.read_bytes())
        policy.write_text('{"policy":"after"}', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'inventory changed'):
            rust_cargo.verify_plan(saved, plan_path=receipt, workspace_root=self.root,
                toolchain=result['toolchain']['selection'], env=self.environment)
        self.assertEqual(len(self.calls), 1)

    def test_scope_policy_mutation_during_query_is_not_a_valid_outer_plan(self):
        policy = self.rules / 'policy.json'
        policy.write_text('{"policy":"before"}', encoding='utf-8')
        self.manifest['scope_policy'] = '../local-rules/policy.json'
        self.save_manifest()
        self.callback = lambda *_: policy.write_text('{"policy":"after"}', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'inventory changed'):
            self.plan()
        self.assertEqual(len(self.calls), 1)
        inner = self.calls[0][2].parent / 'plan.json'
        captured = json.loads(inner.read_bytes())
        self.assertEqual(captured['inspection']['status'], 'inputs_changed')
        self.assertFalse((inner.parent.parent / 'plan.json').exists())

    def test_feature_flags_and_profile_remain_explicit(self):
        self.manifest['rust_cargo'].update(features=['extra'], default_features=False, profile='custom')
        self.metadata['resolve']['nodes'][0]['features'] = ['extra']
        self.save_manifest()
        result = self.plan()
        self.assertIn('component/extra', self.calls[0][0])
        self.assertIn('--no-default-features', self.calls[0][0])
        self.assertEqual(result['inspection']['selection']['profile'], 'custom')
        self.assertEqual(result['inspection']['resolution']['profile_resolution'], 'pending_actual_build_recipe')

    def test_mcp_exposes_inspection_without_build_support(self):
        bridge = DefenseBridge(object(), self.service)
        result = bridge.call('protection_source_plan', {'project_path': str(self.project)})
        self.assertEqual(result['inspection_status'], 'inspected_build_not_implemented')
        with self.assertRaisesRegex(ValueError, 'rust_cargo_build_not_implemented'):
            bridge.call('protection_source_build', {'plan_id': result['plan_id'], 'fingerprint': result['fingerprint']})
        description = next(row['description'] for row in TOOLS if row['name'] == 'protection_source_plan')
        self.assertIn('Cargo metadata', description)


if __name__ == '__main__':
    unittest.main(verbosity=2)
