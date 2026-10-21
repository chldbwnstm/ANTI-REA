"""Different-profile measurement control tests; dummy DLLs are never loaded."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import compare_vm_profiles as comparison


class ProfileInvariantTests(unittest.TestCase):
    def setUp(self):
        self.report = {"coverage": {"functions": {"a": {"virtualized": True}, "b": {"virtualized": True}},
                                   "exported_functions": ["public"], "requested_core_passes": ["fla", "sub", "co", "vm"],
                                   "runtime_evidence": {"fla_dispatcher": True, "substitution_instructions": 1,
                                                        "constant_obfuscation_instructions": 1},
                                   "hardening_evidence": {"verified_retained_components": ["checksum"]}}}
        self.manifest = {"parameters": {"codec": "old"}, "used_handlers": ["F_RR_ADD"], "format_version": 2,
                         "requested_hardening_layers": ["anti_tamper", "multi_vm_indirect_dispatch"],
                         "blobs": [{"global": "bc", "original_bytes": 20, "original_instructions": 9,
                                    "emitted_instructions": 6, "fused_groups": 1, "fusion_counts": {"F_RR_ADD": 1},
                                    "absorbed_dispatches": 3, "original_sha256": "original", "encoded_sha256": "encoded",
                                    "encoded_bytes": 22, "relocated_branch_targets": 0}]}
        self.new_report, self.new_manifest = copy.deepcopy(self.report), copy.deepcopy(self.manifest)
        self.new_report['coverage']['hardening_evidence']['verified_retained_components'].append(comparison.MULTI_COMPONENT)
        self.new_manifest.update(engine_mode='per_function_indirect', engines=[{}, {}], parameters={'codec': 'different'})
        self.new_manifest['blobs'][0]['encoded_sha256'] = 'different'

    def delta(self):
        return comparison._profile_delta((self.report, self.manifest), (self.new_report, self.new_manifest))

    def test_explicit_different_profile_not_an_identity_claim(self):
        self.assertFalse(self.delta()['same_protection_profile'])
        self.assertEqual(self.delta()['candidate_engine_count'], 2)

    def test_cannot_drop_scope_passes_or_retained_protection(self):
        changes = [lambda r: r['coverage']['functions'].pop('b'),
                   lambda r: r['coverage'].update(requested_core_passes=['vm']),
                   lambda r: r['coverage']['runtime_evidence'].update(fla_dispatcher=False),
                   lambda r: r['coverage']['hardening_evidence'].update(verified_retained_components=[comparison.MULTI_COMPONENT])]
        for change in changes:
            original = copy.deepcopy(self.new_report)
            change(self.new_report)
            with self.assertRaises(ValueError):
                self.delta()
            self.new_report = original

    def test_original_bytecode_or_fusion_change_is_rejected(self):
        for key, value in [('original_sha256', 'changed'), ('fused_groups', 0), ('absorbed_dispatches', 0), ('encoded_bytes', 999)]:
            before = self.new_manifest['blobs'][0][key]
            self.new_manifest['blobs'][0][key] = value
            with self.assertRaisesRegex(ValueError, 'bytecode or instruction fusion'):
                self.delta()
            self.new_manifest['blobs'][0][key] = before

    def test_wrong_profile_pair_is_rejected(self):
        self.new_manifest['engine_mode'] = 'shared_direct'
        with self.assertRaisesRegex(ValueError, 'shared-direct'):
            self.delta()

    def test_normalized_ir_excludes_only_build_location_not_algorithm_data(self):
        a, b = Path('C:/private/first'), Path('C:/private/second')
        def source(folder):
            escaped = str(folder).replace('\\', '\\\\')
            return f'; ModuleID = \'{folder}/module.raw.ll\'\n@data = constant i32 7\n!1 = !DIFile(filename: "core.c", directory: "{escaped}")\n'
        self.assertEqual(comparison._source_ir_identity(source(a), a), comparison._source_ir_identity(source(b), b))
        self.assertNotEqual(comparison._source_ir_identity(source(a), a), comparison._source_ir_identity(source(b).replace('i32 7', 'i32 8'), b))
        self.assertNotEqual(comparison._source_ir_identity(source(a), a), comparison._source_ir_identity(source(b).replace('core.c', 'other.c'), b))


class MeasurementBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / '.runs/result'
        self.request = {'workspace_root': str(self.root), 'pinned_inputs': {}, 'profile_comparison': {'same_protection_profile': False}}

    def compare(self):
        return comparison.compare_profiles('old', 'new', 'contract', self.output, workspace_root=self.root)

    def test_verified_cleanup_is_required_to_accept_worker_measurement(self):
        def worker(*args, **kwargs):
            comparison.perf._save(self.output / 'worker-reply.json', {'status': 'measured', 'timings': {}})
            return {'returncode': 0, 'cleanup': {'parent_exit_confirmed': True, 'status': 'unverified', 'job_handle_closed': True}}
        with patch.object(comparison, 'prepare_profiles', return_value=self.request), patch.object(comparison.perf, 'run_logged', side_effect=worker):
            result = self.compare()
        self.assertEqual(result['status'], 'failed')
        self.assertNotIn('timings', result)

    def test_stop_or_existing_output_never_launches_worker(self):
        with patch.object(comparison, 'prepare_profiles', return_value=self.request), patch.object(comparison.perf, 'run_logged', side_effect=AssertionError('must not run')):
            stop = self.root / '.runs/defense-loop/STOP'
            stop.parent.mkdir(parents=True)
            stop.touch()
            with self.assertRaisesRegex(ValueError, 'STOP'):
                self.compare()
            self.output.mkdir()
            with self.assertRaisesRegex(ValueError, 'fresh'):
                self.compare()

    def test_shared_output_is_rejected_before_worker(self):
        self.output = self.root / '.runs/attackerfolder/new'
        with patch.object(comparison, 'prepare_profiles', return_value=self.request), patch.object(comparison.perf, 'run_logged', side_effect=AssertionError('must not run')):
            with self.assertRaisesRegex(ValueError, 'shared'):
                self.compare()


if __name__ == '__main__':
    unittest.main()
