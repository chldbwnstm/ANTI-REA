"""Dispatch is a hint; language-specific integration owns authorization."""
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

from antirea.projects import ProjectService
from antirea.csharp_application import CSharpApplicationError
from antirea.languages import language_catalog


class SourceIntegrateDispatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.service = ProjectService(self.root)
        self.plan_id = "source-20261020T010203Z-0123456789ab"
        self.directory = self.service.output_root / self.plan_id
        self.directory.mkdir(parents=True)

    def result(self, value):
        (self.directory / "result.json").write_text(json.dumps(value), encoding="utf-8")

    def test_jvm_result_dispatches_exact_arguments(self):
        self.result({"backend": "jvm_bytecode_native", "status": "untrusted_hint"})
        fake = types.ModuleType("antirea.jvm_application")
        fake.integrate_source_application = Mock(return_value={"status": "mock_only"})
        with patch.dict(sys.modules, {"antirea.jvm_application": fake}):
            result = self.service.integrate(self.plan_id, "spec.json", "cases.json",
                                            timeout_seconds=87)
        self.assertEqual(result, {"status": "mock_only"})
        fake.integrate_source_application.assert_called_once_with(
            self.service, self.plan_id, "spec.json", "cases.json", timeout_seconds=87)

    def test_csharp_dispatch_preserved(self):
        self.result({"backend": "dotnet_il_native"})
        with patch("antirea.csharp_application.integrate_source_application") as target:
            self.service.integrate(self.plan_id, "spec.json", "cases.json")
        target.assert_called_once_with(self.service, self.plan_id, "spec.json",
                                       "cases.json", timeout_seconds=120)

    def test_unknown_backend_remains_fail_closed_in_existing_service(self):
        self.result({"backend": "unknown_backend", "status": "artifact_created_unvalidated"})
        with self.assertRaisesRegex(CSharpApplicationError, "supports only csharp"):
            self.service.integrate(self.plan_id, "spec.json", "cases.json")

    def test_go_swift_result_dispatches_exact_arguments_not_authorization(self):
        for backend in ("go_typed_native", "swift_llvm_native"):
            with self.subTest(backend=backend):
                self.result({"backend": backend, "status": "untrusted_hint"})
                fake = types.ModuleType("antirea.native_application")
                fake.integrate_source_application = Mock(return_value={"status": "mock_only"})
                with patch.dict(sys.modules, {"antirea.native_application": fake}):
                    result = self.service.integrate(self.plan_id, "spec.json", "cases.json", timeout_seconds=87)
                self.assertEqual(result, {"status": "mock_only"})
                fake.integrate_source_application.assert_called_once_with(
                    self.service, self.plan_id, "spec.json", "cases.json", timeout_seconds=87)

    def test_go_swift_catalog_declares_subset_and_explicit_execution(self):
        for language in ("go", "swift"):
            with self.subTest(language=language):
                entry = language_catalog(language)["languages"][0]
                route = entry["source_protection"]["application_integration"]
                self.assertEqual(route["status"], "experimental")
                self.assertEqual(route["cli"], "source-integrate")
                self.assertEqual(route["contract"], "native_application_samples")
                self.assertFalse(route["whole_application_verified"])
                self.assertFalse(route["package_manager_hooks_supported"])
                self.assertFalse(entry["tool_discovery"]["executed"])

    def test_bad_timeout_rejected_before_directory_lookup(self):
        with patch.object(self.service, "_directory") as directory:
            for timeout in (True, 0, 601, "120", 1.5):
                with self.subTest(timeout=timeout), self.assertRaises(CSharpApplicationError):
                    self.service.integrate("invalid", "spec.json", "cases.json",
                                           timeout_seconds=timeout)
            directory.assert_not_called()

    def test_nonobject_result_is_rejected_without_jvm_import(self):
        self.result([])
        with patch.dict(sys.modules, {"antirea.jvm_application": None}):
            with self.assertRaisesRegex(CSharpApplicationError, "no successful artifact"):
                self.service.integrate(self.plan_id, "spec.json", "cases.json")

    def test_jvm_catalog_identifies_experimental_app_route_without_whole_app_claim(self):
        for language in ("java", "kotlin"):
            with self.subTest(language=language):
                entry = language_catalog(language)["languages"][0]
                route = entry["source_protection"]["application_integration"]
                self.assertEqual(route["status"], "experimental")
                self.assertEqual(route["cli"], "source-integrate")
                self.assertEqual(route["contract"], "jvm_application_samples")
                self.assertFalse(route["whole_application_verified"])
                self.assertFalse(route["metadata_reflection_equivalence"])
                self.assertFalse(entry["tool_discovery"]["executed"])
