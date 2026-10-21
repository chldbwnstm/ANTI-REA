"""Cargo PLAN pins for the promoted preparation modules; metadata is mocked.

The real ProjectService Cargo route and inspector execute against owned inert
fixtures. No compiler, Cargo executable, application or subprocess may run.
Only temporary stand-in engine bytes are changed; production files are read-only.
"""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from antirea import projects, rust_cargo


PREPARATION_MODULES = ('rust_cargo_prepare', 'rust_cargo_semantic', 'rust_cargo_objects')


class CargoPreparationPlanPinTests(unittest.TestCase):
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

        # The service reads these paths only. Intentionally non-Python text
        # makes accidental helper execution fail instead of passing unnoticed.
        self.engine_directory = self.root / 'inert-service-engine'
        self.engine_directory.mkdir()
        self.engine_files = {}
        for name in ('projects', 'process', '__init__', 'protectors', *PREPARATION_MODULES):
            path = self.engine_directory / (name + '.py')
            path.write_bytes(('INERT ENGINE INVENTORY FIXTURE: ' + name + '\n').encode())
            self.engine_files[name] = path
        service_location = patch.object(projects, '__file__', str(self.engine_files['projects']))
        service_location.start()
        self.addCleanup(service_location.stop)

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


    @staticmethod
    def expected_descriptor(path):
        raw = path.read_bytes()
        return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}

    def assert_pinned(self, result):
        records = {row['path']: row for row in result['engine_inputs']}
        for name in PREPARATION_MODULES:
            with self.subTest(module=name):
                path = self.engine_files[name]
                self.assertEqual(records[str(path)], self.expected_descriptor(path))

    def test_both_preparation_dependencies_have_exact_saved_cargo_plan_pins(self):
        result = self.plan()
        self.assert_pinned(result)
        saved = json.loads((self.service.output_root / result['plan_id'] / 'plan.json').read_bytes())
        self.assertEqual(saved['engine_inputs'], result['engine_inputs'])
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(result['backend'], 'rust_cargo_native')
        self.assertEqual(result['status'], 'blocked')
        self.assertFalse(result['build_implemented'])

    def test_unchanged_dependencies_keep_semantic_fingerprint_across_jobs(self):
        first, second = self.plan(), self.plan()
        self.assert_pinned(first)
        self.assert_pinned(second)
        self.assertNotEqual(first['plan_id'], second['plan_id'])
        self.assertNotEqual(first['fingerprint'], second['fingerprint'])
        self.assertEqual(first['semantic_fingerprint'], second['semantic_fingerprint'])
        self.assertEqual(first['engine_inputs'], second['engine_inputs'])
        self.assertEqual(len(self.calls), 2)

    def assert_new_plan_changes_meaning_for(self, name):
        first = self.plan()
        self.assert_pinned(first)
        saved_path = self.service.output_root / first['plan_id'] / 'plan.json'
        saved_before = saved_path.read_bytes()
        other_inputs_before = {key: path.read_bytes() for key, path in self.engine_files.items() if key != name}
        path = self.engine_files[name]
        path.write_bytes(path.read_bytes() + b'CHANGED STAND-IN ENGINE BYTES\n')
        second = self.plan()
        self.assert_pinned(second)
        self.assertNotEqual(first['semantic_fingerprint'], second['semantic_fingerprint'])
        # Input/metadata semantics did not change: the new engine pin caused this difference.
        self.assertEqual(first['inputs'], second['inputs'])
        self.assertEqual(first['inspection']['fingerprint'], second['inspection']['fingerprint'])
        before = {row['path']: row for row in first['engine_inputs']}
        after = {row['path']: row for row in second['engine_inputs']}
        changed = [key for key in before if before[key] != after[key]]
        self.assertEqual(changed, [str(path)])
        self.assertEqual(saved_path.read_bytes(), saved_before)
        self.assertEqual({key: self.engine_files[key].read_bytes() for key in other_inputs_before}, other_inputs_before)

    def test_prepare_module_drift_changes_cargo_semantic_fingerprint(self):
        self.assert_new_plan_changes_meaning_for('rust_cargo_prepare')

    def test_semantic_module_drift_changes_cargo_semantic_fingerprint(self):
        self.assert_new_plan_changes_meaning_for('rust_cargo_semantic')

    def assert_drift_during_query_rejected_for(self, name):
        path = self.engine_files[name]
        self.callback = lambda *_: path.write_bytes(path.read_bytes() + b'CHANGED DURING MOCK METADATA\n')
        with self.assertRaisesRegex(ValueError, 'Cargo planning source/configuration/engine changed'):
            self.plan()
        self.assertEqual(len(self.calls), 1)
        inspection_directory = self.calls[0][2].parent
        # Keep the successful inner evidence, but never publish a valid outer PLAN.
        self.assertTrue((inspection_directory / 'plan.json').is_file())
        self.assertFalse((inspection_directory.parent / 'plan.json').exists())
        self.assertFalse((inspection_directory.parent / 'started.json').exists())
        self.assertFalse((inspection_directory.parent / 'build').exists())

    def test_prepare_drift_during_metadata_rejects_outer_plan(self):
        self.assert_drift_during_query_rejected_for('rust_cargo_prepare')

    def test_semantic_drift_during_metadata_rejects_outer_plan(self):
        self.assert_drift_during_query_rejected_for('rust_cargo_semantic')

    def assert_missing_dependency_blocks_for(self, name):
        # This removes only this test's inert temporary stand-in, never package code.
        self.engine_files[name].unlink()
        with self.assertRaises((OSError, ValueError)):
            self.plan()
        self.assertEqual(self.calls, [])
        self.assertFalse(self.service.output_root.exists())

    def test_missing_prepare_dependency_blocks_before_query(self):
        self.assert_missing_dependency_blocks_for('rust_cargo_prepare')

    def test_missing_semantic_dependency_blocks_before_query(self):
        self.assert_missing_dependency_blocks_for('rust_cargo_semantic')

    def test_objects_module_drift_changes_cargo_semantic_fingerprint(self):
        self.assert_new_plan_changes_meaning_for('rust_cargo_objects')

    def test_objects_drift_during_metadata_rejects_outer_plan(self):
        self.assert_drift_during_query_rejected_for('rust_cargo_objects')

    def test_missing_objects_dependency_blocks_before_query(self):
        self.assert_missing_dependency_blocks_for('rust_cargo_objects')

    def test_cargo_build_remains_disabled_before_any_dispatch(self):
        result = self.plan()
        self.assert_pinned(result)
        before_calls = len(self.calls)
        with patch('antirea.projects._inspect') as inspect, patch('antirea.projects._build') as build, \
                patch('antirea.rust_cargo.inspect_project') as metadata:
            with self.assertRaisesRegex(ValueError, 'rust_cargo_build_not_implemented'):
                self.service.build(result['plan_id'], result['fingerprint'])
        inspect.assert_not_called()
        build.assert_not_called()
        metadata.assert_not_called()
        self.assertEqual(len(self.calls), before_calls)
        directory = self.service.output_root / result['plan_id']
        self.assertFalse((directory / 'started.json').exists())
        self.assertFalse((directory / 'build').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
