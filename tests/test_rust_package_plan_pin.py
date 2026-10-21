"""Rust package dependencies participate in the real stale-plan gate.

Only inert temporary engine files are mutated. Compiler execution is forbidden.
"""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from antirea import projects


MODULES = ('rust_ir', 'rust_normalize', 'rust_qualify', 'rust_cargo_link',
           'rust_cargo_prepare', 'rust_cargo_semantic', 'rust_cargo_objects')


class RustPackagePlanPinTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        source = self.root / 'owned'
        source.mkdir()
        self.project = source / 'project.json'
        self.project.write_text('{"schema_version":1}', encoding='utf-8')
        (source / 'core.c').write_text('int core(int x) { return x + 1; }', encoding='utf-8')
        tools = self.root / '.tools'
        tools.mkdir()
        (tools / 'kagura-toolchain.json').write_text('{"llvm_version":"22.1.0"}', encoding='utf-8')
        engine = self.root / 'inert-engine'
        engine.mkdir()
        self.engine_files = {}
        for name in ('projects', *MODULES):
            path = engine / (name + '.py')
            path.write_bytes(('INERT ENGINE INVENTORY FIXTURE: ' + name + '\n').encode())
            self.engine_files[name] = path
        self._patch('antirea.projects.__file__', str(self.engine_files['projects']))
        self._patch('antirea.projects._inspect', return_value={'language': 'c', 'blockers': []})
        self._patch('antirea.projects.shutil.which', return_value=None)
        self.no_process = self._patch('subprocess.Popen', side_effect=AssertionError('No subprocess'))
        self.service = projects.ProjectService(self.root)

    def _patch(self, target, *args, **kwargs):
        selected = patch(target, *args, **kwargs)
        value = selected.start()
        self.addCleanup(selected.stop)
        return value

    @staticmethod
    def successful_builder(source, output, **kwargs):
        output.mkdir(parents=True)
        result = {'status': 'artifact_created_unvalidated', 'artifacts': {}, 'coverage': {}}
        (output / 'report.json').write_text(json.dumps(result), encoding='utf-8')
        return result

    def test_all_package_modules_have_distinct_plan_pins(self):
        with patch('antirea.projects._build') as build:
            plan = self.service.plan(self.project)
        for name in MODULES:
            with self.subTest(module=name):
                row = plan['toolchain']['tools']['engine_' + name]
                path = self.engine_files[name]
                self.assertEqual(row['path'], str(path))
                self.assertEqual(row['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
                self.assertEqual(row['bytes'], path.stat().st_size)
        build.assert_not_called()
        self.no_process.assert_not_called()

    def test_each_module_drift_is_rejected_before_builder_or_output(self):
        for name in MODULES:
            with self.subTest(module=name):
                before = {key: path.read_bytes() for key, path in self.engine_files.items()}
                plan = self.service.plan(self.project)
                self.engine_files[name].write_bytes(before[name] + b'CHANGED\n')
                with patch('antirea.projects._build', side_effect=self.successful_builder) as build:
                    with self.assertRaisesRegex(ValueError, 'project or toolchain changed after planning'):
                        self.service.build(plan['plan_id'], plan['fingerprint'])
                    build.assert_not_called()
                output = Path(plan['output_dir'])
                self.assertFalse(output.exists())
                self.assertFalse((output.parent / 'started.json').exists())
                self.assertFalse((output.parent / 'result.json').exists())
                for key, raw in before.items():
                    if key != name:
                        self.assertEqual(self.engine_files[key].read_bytes(), raw)
                self.engine_files[name].write_bytes(before[name])
        self.no_process.assert_not_called()

    def test_unchanged_package_preserves_mock_build(self):
        plan = self.service.plan(self.project)
        before = {name: path.read_bytes() for name, path in self.engine_files.items()}
        with patch('antirea.projects._build', side_effect=self.successful_builder) as build:
            result = self.service.build(plan['plan_id'], plan['fingerprint'])
        self.assertEqual(result['status'], 'artifact_created_unvalidated')
        self.assertEqual(result['external_attack_evaluation'], 'not_evaluated')
        self.assertFalse(result['published'])
        build.assert_called_once()
        self.assertEqual({name: path.read_bytes() for name, path in self.engine_files.items()}, before)
        self.no_process.assert_not_called()


if __name__ == '__main__':
    unittest.main()
