"""Public plan/build/MCP wiring for owned mixed JS/TS; never run the application."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from antirea.defense_mcp import DefenseBridge
from antirea.projects import ProjectService
from antirea import javascript_frontend, javascript_mixed_module


class MixedSourceServiceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.app = self.root / 'owned_app'
        self.app.mkdir()
        self.source = self.app / 'ui.js'
        self.source.write_text(
            '"use strict";\n'
            'throw new Error("application startup must never run in plan/build");\n'
            'const display = require("./display.js");\n'
            'function helper(x) { return x * 37 + 19; }\n'
            'function core(x) { return helper(x) ^ 97153; }\n'
            'function ui(x) { return display.render(core(x)); }\n'
            'module.exports = {core, ui};\n', encoding='utf-8')
        (self.app / 'display.js').write_text(
            'module.exports = {render: value => "value:" + value};\n', encoding='utf-8')
        self.project = self.app / 'project.json'
        self.value = {'schema_version': 1, 'name': 'owned_mixed_js', 'language': 'javascript',
                      'sources': ['ui.js'], 'functions': ['core'], 'protection_mode': 'mixed_module'}
        self.project.write_text(json.dumps(self.value), encoding='utf-8')
        self.service = ProjectService(self.root)

    def plan_build(self):
        plan = self.service.plan(self.project, seed=71)
        result = self.service.build(plan['plan_id'], plan['fingerprint'])
        self.assertEqual(plan['status'], 'planned')
        self.assertEqual(result['status'], 'artifact_created_unvalidated', result)
        return plan, result

    def test_real_plan_build_preserves_module_without_application_execution(self):
        before = self.source.read_bytes()
        plan, result = self.plan_build()
        self.assertTrue(plan['executes_compilers'])
        self.assertFalse(plan['executes_application'])
        self.assertEqual(plan['inspection']['backend'], 'javascript_mixed_module_vm')
        self.assertFalse(plan['toolchain']['native_toolchain_required'])
        self.assertEqual(len(plan['inputs']), 3)
        for key in ('source_executed', 'execution_authorized', 'published'):
            self.assertIs(result[key], False)
        self.assertEqual(result['external_attack_evaluation'], 'not_evaluated')
        self.assertEqual(result['coverage']['helper_closure'], ['core', 'helper'])
        self.assertEqual(Path(result['baseline']).read_bytes(), before)
        protected = Path(result['protected']).read_text(encoding='utf-8')
        self.assertIn('require("./display.js")', protected)
        self.assertIn('application startup must never run', protected)
        self.assertNotIn('return x * 37 + 19', protected)
        self.assertEqual(self.source.read_bytes(), before)
        self.assertEqual(hashlib.sha256((Path(plan['output_dir']) / 'report.json').read_bytes()).hexdigest(),
                         result['build_report_sha256'])

    def test_pure_and_unknown_modes_do_not_silently_select_mixed(self):
        for mode in (None, 'pure', 'MIXED_MODULE', True, 1):
            value = dict(self.value)
            if mode is None:
                value.pop('protection_mode')
            else:
                value['protection_mode'] = mode
            self.project.write_text(json.dumps(value), encoding='utf-8')
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.service.plan(self.project)
        self.assertFalse(self.service.output_root.exists())

    def test_both_frontends_and_mixed_tools_are_pinned(self):
        plan = self.service.plan(self.project)
        tools = plan['toolchain']['tools']
        for name, module in (('javascript_frontend', javascript_frontend),
                             ('javascript_mixed_module', javascript_mixed_module)):
            record = tools['engine_' + name]
            self.assertEqual(Path(record['path']), Path(module.__file__).resolve())
            self.assertEqual(record['sha256'], hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest())
        files = plan['inspection']['toolchain']['files']
        self.assertIn('mixed_compiler', files)
        self.assertIn('mixed_runtime_template', files)
        self.assertNotIn('mixed_validator', files)
        original = self.service._toolchain
        def changed(inspection=None):
            value = original(inspection)
            value['tools']['engine_javascript_mixed_module']['sha256'] = '0' * 64
            return value
        with patch.object(self.service, '_toolchain', side_effect=changed), patch('antirea.projects._build') as build:
            with self.assertRaisesRegex(ValueError, 'changed after planning'):
                self.service.build(plan['plan_id'], plan['fingerprint'])
            build.assert_not_called()

    def test_surrounding_package_change_invalidates_plan(self):
        plan = self.service.plan(self.project)
        (self.app / 'display.js').write_text('throw Error("changed");\n', encoding='utf-8')
        with patch('antirea.projects._build') as build:
            with self.assertRaisesRegex(ValueError, 'changed after planning'):
                self.service.build(plan['plan_id'], plan['fingerprint'])
            build.assert_not_called()

    def test_scalar_validation_cannot_authorize_application_execution(self):
        plan, _ = self.plan_build()
        contract = self.app / 'samples.json'
        contract.write_text(json.dumps({'kind': 'javascript_scalar_samples', 'functions': []}), encoding='utf-8')
        with patch('antirea.javascript_validate.validate_build') as pure, \
                patch('antirea.native_validate.validate_build') as native, \
                patch('subprocess.Popen', side_effect=AssertionError('no application import')):
            with self.assertRaisesRegex(ValueError, 'mixed application contract requires'):
                self.service.validate(plan['plan_id'], contract)
            pure.assert_not_called()
            native.assert_not_called()
        self.assertFalse(any(Path(plan['output_dir']).parent.glob('validation-*')))

    def test_fingerprint_and_single_attempt_gates(self):
        plan = self.service.plan(self.project)
        with self.assertRaisesRegex(ValueError, 'fingerprint'):
            self.service.build(plan['plan_id'], '0' * 64)
        result = self.service.build(plan['plan_id'], plan['fingerprint'])
        self.assertEqual(result['status'], 'artifact_created_unvalidated')
        with self.assertRaisesRegex(ValueError, 'already attempted'):
            self.service.build(plan['plan_id'], plan['fingerprint'])

    def test_stop_prevents_mixed_build(self):
        plan = self.service.plan(self.project)
        stop = self.root / '.runs/defense-loop/STOP'
        stop.parent.mkdir(parents=True)
        stop.write_text('owned test STOP', encoding='utf-8')
        with patch('antirea.projects._build') as build, \
                patch('subprocess.Popen', side_effect=AssertionError('no parser or app')):
            self.assertEqual(self.service.build(plan['plan_id'], plan['fingerprint'])['status'], 'cancelled')
            build.assert_not_called()

    def test_existing_mcp_tools_reach_opt_in_builder(self):
        bridge = DefenseBridge(SimpleNamespace(root=self.root), self.service)
        plan = bridge.call('protection_source_plan', {'project_path': str(self.project), 'seed': 73})
        result = bridge.call('protection_source_build', {'plan_id': plan['plan_id'], 'fingerprint': plan['fingerprint']})
        self.assertEqual(result['status'], 'artifact_created_unvalidated')
        self.assertEqual(result['backend'], 'javascript_mixed_module_vm')
        self.assertFalse(result['source_executed'])

    def test_typescript_mixed_route_preserves_transpiled_runtime_constructs(self):
        source = self.app / 'ui.ts'
        source.write_text('throw new Error("never executed");\n'
                          'export enum Colour { Red, Blue }\n'
                          'export function core(x: number): number { return x * 37 + 19; }\n'
                          'export function label(x: number): string { return Colour[x] + core(x); }\n', encoding='utf-8')
        value = {**self.value, 'language': 'typescript', 'sources': ['ui.ts']}
        self.project.write_text(json.dumps(value), encoding='utf-8')
        plan, result = self.plan_build()
        self.assertEqual(plan['kind'], 'javascript_source_build')
        self.assertTrue(result['coverage']['transpiled_typescript'])
        protected = Path(result['protected']).read_text(encoding='utf-8')
        self.assertIn('exports.Colour', protected)
        self.assertIn('function label(', protected)
        self.assertNotIn('return x * 37 + 19', protected)


if __name__ == '__main__':
    unittest.main()
