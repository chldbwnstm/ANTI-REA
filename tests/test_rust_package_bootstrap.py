"""Source-only bootstrap regressions for the Rust package.

Every package/configuration/DLL path below is a temporary owned fixture. The
DLL is inert bytes, the LLVM adapter is a Python stub, and subprocess/CDLL are
blocked. Actual IR parsing, compiler execution and target execution are absent.
Temporary engine pins are derived from these owned fixture copies only.
"""
from __future__ import annotations

import ctypes
import hashlib
import importlib.abc
import importlib.machinery
import importlib.util
import inspect
import json
import marshal
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


PROJECT = Path(__file__).resolve().parents[1]
CANDIDATES = PROJECT / "antirea"
TARGET = "x86_64-pc-windows-msvc"
SWIFT_STUB = '''from .helper import VALUE
INSTANCES = []
MISSING = None
class Callback:
    def __call__(self, *args):
        raise AssertionError("LLVM execution is forbidden in bootstrap tests")
class DLL:
    def __getattr__(self, name):
        if name == MISSING:
            raise AttributeError(name)
        return Callback()
class _LLVM:
    def __init__(self, library):
        self.library = library
        self.dll = DLL()
        self.close_count = 0
        INSTANCES.append(self)
    def close(self):
        self.close_count += 1
'''


def digest(data):
    return hashlib.sha256(data).hexdigest()


def source_bootstrap(name, path):
    """Test coordinator loads its reviewed entry bytes, never a .pyc fallback."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="antirea-package-bootstrap-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.package = self.root / "antirea"
        self.package.mkdir()
        (self.root / ".tools").mkdir()
        self.library = self.root / "llvm/bin/LLVM-C.dll"
        self.library.parent.mkdir(parents=True)
        self.library.write_bytes(b"INERT LIBRARY FIXTURE, NEVER LOADED")
        self.config = self.root / ".tools/kagura-toolchain.json"
        self.config.write_text(json.dumps({"schema_version": 1, "target": TARGET,
            "llvm_root": str(self.library.parent.parent)}), encoding="utf-8")
        self.files = {
            "__init__": self.package / "__init__.py",
            "helper": self.package / "helper.py",
            "protectors": self.package / "protectors.py",
            "swift_frontend": self.package / "swift_frontend.py",
            "rust_ir": self.package / "rust_ir.py",
            "rust_normalize": self.package / "rust_normalize.py",
        }
        self.files["__init__"].write_text('PACKAGE_MARKER = "reviewed source"\n', encoding="utf-8")
        self.files["helper"].write_text('VALUE = "reviewed helper"\n', encoding="utf-8")
        self.files["protectors"].write_text('INERT = True\n', encoding="utf-8")
        self.files["swift_frontend"].write_text(SWIFT_STUB, encoding="utf-8")
        for name in ("rust_ir", "rust_normalize"):
            self.files[name].write_bytes((CANDIDATES / (name + ".py")).read_bytes())

        self.previous_modules = {name: module for name, module in list(sys.modules.items())
                                 if self.is_test_module(name)}
        for name in self.previous_modules:
            sys.modules.pop(name)
        self.addCleanup(self.restore_modules)
        self.original_path, self.original_meta = list(sys.path), list(sys.meta_path)
        self.addCleanup(self.restore_import_configuration)
        self.no_process = self.start_patch("subprocess.Popen", side_effect=AssertionError("No subprocess"))
        self.no_dll = self.start_patch("ctypes.CDLL", side_effect=AssertionError("No native library"))
        self.mapper = source_bootstrap("_bootstrap_review_mapper", self.files["rust_ir"])
        self.normalizer = source_bootstrap("_bootstrap_review_normalizer", self.files["rust_normalize"])
        self.pins = {str(path): digest(path.read_bytes())
                     for path in (*self.files.values(), self.config, self.library)}

    @staticmethod
    def is_test_module(name):
        return name == "antirea" or name.startswith("antirea.") or name.startswith("_bootstrap_review_")

    def restore_modules(self):
        for name in list(sys.modules):
            if self.is_test_module(name):
                sys.modules.pop(name)
        sys.modules.update(self.previous_modules)

    def restore_import_configuration(self):
        sys.path[:] = self.original_path
        sys.meta_path[:] = self.original_meta

    def start_patch(self, name, **kwargs):
        selected = patch(name, **kwargs)
        value = selected.start()
        self.addCleanup(selected.stop)
        return value

    def tearDown(self):
        self.no_process.assert_not_called()
        self.no_dll.assert_not_called()

    def refresh(self, path):
        self.pins[str(path)] = digest(path.read_bytes())

    def load(self, name="antirea.swift_frontend", pins=None):
        return self.mapper.import_verified_module(name, workspace_root=self.root,
            trusted_engine_pins=self.pins if pins is None else pins)

    def reject(self, call):
        with self.assertRaises((ValueError, ImportError, TypeError)):
            call()

    def forge_cache(self, name):
        path = self.files[name]
        cache = Path(importlib.util.cache_from_source(str(path)))
        cache.parent.mkdir(exist_ok=True)
        info = path.stat()
        trap = compile('raise AssertionError("UNREVIEWED BYTECODE WAS EXECUTED")\n', str(path), "exec")
        raw = (importlib.util.MAGIC_NUMBER
               + struct.pack("<III", 0, int(info.st_mtime) & 0xffffffff, info.st_size & 0xffffffff)
               + marshal.dumps(trap))
        cache.write_bytes(raw)
        return cache, raw

    def assert_import_configuration_restored(self, path=None, meta=None):
        self.assertEqual(sys.path, self.original_path if path is None else path)
        expected = self.original_meta if meta is None else meta
        self.assertEqual(len(sys.meta_path), len(expected))
        self.assertTrue(all(a is b for a, b in zip(sys.meta_path, expected)))

    def test_public_apis_require_explicit_engine_snapshot(self):
        for function in (self.mapper.open_llvm, self.mapper.normalize_protection_ir,
                         self.mapper.import_verified_module, self.normalizer.open_llvm,
                         self.normalizer.normalize_ir):
            with self.subTest(function=function.__name__):
                parameter = inspect.signature(function).parameters["trusted_engine_pins"]
                self.assertIs(parameter.default, inspect.Parameter.empty)

    def test_complete_snapshot_loads_only_reviewed_package_sources(self):
        module, engine, origins, source_imports = self.load()
        self.assertEqual(module.VALUE, "reviewed helper")
        self.assertEqual(engine, self.pins)
        self.assertTrue(origins)
        self.assertTrue(source_imports)
        self.assertEqual(Path(module.__file__), self.files["swift_frontend"])
        self.assertEqual(sys.modules["antirea"].PACKAGE_MARKER, "reviewed source")
        self.assert_import_configuration_restored()

    def test_empty_snapshot_is_rejected_before_package_import(self):
        self.reject(lambda: self.load(pins={}))
        self.assertNotIn("antirea", sys.modules)

    def test_missing_each_required_source_pin_is_rejected(self):
        for path in self.files.values():
            pins = dict(self.pins)
            del pins[str(path)]
            with self.subTest(path=path.name):
                self.reject(lambda: self.load(pins=pins))
                self.assertNotIn("antirea", sys.modules)

    def test_missing_configuration_pin_is_rejected(self):
        pins = dict(self.pins)
        del pins[str(self.config)]
        self.reject(lambda: self.load(pins=pins))

    def test_changed_helper_source_is_rejected_before_import(self):
        self.files["helper"].write_text('raise AssertionError("changed helper executed")\n', encoding="utf-8")
        self.reject(self.load)
        self.assertNotIn("antirea", sys.modules)

    def test_changed_configuration_is_rejected_before_import(self):
        self.config.write_bytes(self.config.read_bytes() + b"\n")
        self.reject(self.load)
        self.assertNotIn("antirea", sys.modules)

    def test_changed_library_pin_is_rejected_without_native_load(self):
        self.library.write_bytes(b"CHANGED INERT LIBRARY")
        self.reject(self.load)

    def test_malformed_digest_types_are_rejected(self):
        for malformed in (False, None, "0" * 63, "A" * 64):
            with self.subTest(value=malformed):
                pins = {**self.pins, str(self.files["helper"]): malformed}
                self.reject(lambda: self.load(pins=pins))

    def test_duplicate_casefolded_pin_is_rejected(self):
        value = str(self.files["helper"])
        alternate = str(self.files["helper"].parent / "HELPER.py")
        self.assertNotEqual(value, alternate)
        self.reject(lambda: self.load(pins={**self.pins, alternate: self.pins[value]}))

    def test_direct_import_rejects_other_names_and_prefixes(self):
        for name in ("os", "antirea", "antirea.helper", "antirea.rust_normalize",
                     "antireax.rust_ir", "antirea.rust_ir.extra", "..rust_ir"):
            with self.subTest(name=name):
                self.reject(lambda: self.load(name))

    def test_missing_loaded_module_identity_is_rejected(self):
        sys.modules["antirea.rust_ir"] = types.ModuleType("antirea.rust_ir")
        self.reject(self.load)

    def test_none_cached_module_is_rejected(self):
        sys.modules["antirea.rust_ir"] = None
        self.reject(self.load)

    def test_foreign_loaded_module_origin_is_rejected(self):
        module = types.ModuleType("antirea.rust_ir")
        module.__file__ = str(self.root / "foreign.py")
        module.__spec__ = importlib.util.spec_from_file_location("antirea.rust_ir", module.__file__)
        sys.modules["antirea.rust_ir"] = module
        self.reject(self.load)

    def test_same_file_with_conflicting_spec_origin_is_rejected(self):
        module = types.ModuleType("antirea.rust_ir")
        module.__file__ = str(self.files["rust_ir"])
        module.__spec__ = importlib.util.spec_from_file_location("antirea.rust_ir", self.root / "foreign.py")
        sys.modules["antirea.rust_ir"] = module
        self.reject(self.load)

    def test_same_origin_initializing_module_is_rejected(self):
        module = types.ModuleType("antirea.rust_ir")
        module.__file__ = str(self.files["rust_ir"])
        module.__spec__ = importlib.util.spec_from_file_location("antirea.rust_ir", module.__file__)
        module.__spec__._initializing = True
        sys.modules["antirea.rust_ir"] = module
        self.reject(self.load)

    def test_foreign_loaded_package_search_path_is_rejected(self):
        module = types.ModuleType("antirea")
        module.__file__ = str(self.files["__init__"])
        module.__spec__ = importlib.util.spec_from_file_location("antirea", module.__file__)
        module.__path__ = [str(self.root / "foreign-package")]
        sys.modules["antirea"] = module
        self.reject(self.load)

    def test_valid_preloaded_sources_can_be_reused_without_reload(self):
        first, _, _, _ = self.load()
        second, _, origins, _ = self.load()
        self.assertIs(first, second)
        self.assertTrue(origins)
        self.assert_import_configuration_restored()

    def test_preloaded_source_drift_is_rejected(self):
        self.load()
        self.files["helper"].write_bytes(b'VALUE = "changed after import"\n')
        self.reject(self.load)

    def test_new_source_inventory_entry_is_rejected(self):
        engine = self.mapper.verify_engine_snapshot(self.root, self.pins)
        (self.package / "late.py").write_bytes(b"INERT = 1\n")
        self.reject(lambda: self.mapper._recheck_engine(engine, self.root))

    def test_deleted_source_inventory_entry_is_rejected(self):
        engine = self.mapper.verify_engine_snapshot(self.root, self.pins)
        self.files["helper"].unlink()
        self.reject(lambda: self.mapper._recheck_engine(engine, self.root))

    def test_valid_timestamp_cache_cannot_override_package_init(self):
        cache, raw = self.forge_cache("__init__")
        self.load()
        self.assertEqual(sys.modules["antirea"].PACKAGE_MARKER, "reviewed source")
        self.assertEqual(cache.read_bytes(), raw)

    def test_valid_timestamp_cache_cannot_override_mapper(self):
        cache, raw = self.forge_cache("rust_ir")
        mapper, _, _, _ = self.load("antirea.rust_ir")
        self.assertTrue(callable(mapper.normalize_protection_ir))
        self.assertEqual(cache.read_bytes(), raw)

    def test_valid_timestamp_cache_cannot_override_swift_helper(self):
        cache, raw = self.forge_cache("swift_frontend")
        module, _, _, _ = self.load()
        self.assertEqual(module.VALUE, "reviewed helper")
        self.assertEqual(cache.read_bytes(), raw)

    def test_valid_timestamp_cache_cannot_override_transitive_helper(self):
        cache, raw = self.forge_cache("helper")
        module, _, _, _ = self.load()
        self.assertEqual(module.VALUE, "reviewed helper")
        self.assertEqual(cache.read_bytes(), raw)

    def test_extension_candidate_is_not_selected_instead_of_pinned_source(self):
        extension = self.package / ("swift_frontend" + importlib.machinery.EXTENSION_SUFFIXES[0])
        extension.write_bytes(b"INERT EXTENSION FIXTURE, NEVER LOADED")
        module, _, _, _ = self.load()
        self.assertEqual(Path(module.__file__), self.files["swift_frontend"])

    def test_unknown_antirea_dependency_never_reaches_other_finder(self):
        self.files["swift_frontend"].write_text("import antirea.not_reviewed\n", encoding="utf-8")
        self.refresh(self.files["swift_frontend"])
        calls = []
        class TrapFinder(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if fullname == "antirea.not_reviewed":
                    calls.append(fullname)
                    raise AssertionError("Unknown package namespace fell through")
                return None
        trap = TrapFinder()
        sys.meta_path.insert(0, trap)
        before = list(sys.meta_path)
        self.reject(self.load)
        self.assertEqual(calls, [])
        self.assertNotIn("antirea.swift_frontend", sys.modules)
        self.assert_import_configuration_restored(meta=before)

    def test_import_exception_restores_paths_and_removes_partial_module(self):
        self.files["swift_frontend"].write_text('from .helper import VALUE\nraise RuntimeError("owned fixture failure")\n', encoding="utf-8")
        self.refresh(self.files["swift_frontend"])
        with self.assertRaisesRegex(RuntimeError, "owned fixture failure"):
            self.load()
        self.assertNotIn("antirea.swift_frontend", sys.modules)
        self.assertNotIn("antirea.helper", sys.modules)
        self.assertNotIn("antirea", sys.modules)
        self.assert_import_configuration_restored()

    def test_normalizer_bootstrap_ignores_forged_mapper_cache(self):
        cache, raw = self.forge_cache("rust_ir")
        mapper, engine, source_imports = self.normalizer._package_mapper(self.root, self.pins)
        self.assertTrue(callable(mapper.normalize_protection_ir))
        self.assertEqual(engine, self.pins)
        self.assertTrue(source_imports)
        self.assertEqual(cache.read_bytes(), raw)
        self.assert_import_configuration_restored()

    def test_normalizer_bootstrap_rejects_partial_engine_snapshot(self):
        pins = dict(self.pins)
        del pins[str(self.files["helper"])]
        self.reject(lambda: self.normalizer._package_mapper(self.root, pins))
        self.assertNotIn("antirea", sys.modules)

    def test_normalizer_bootstrap_rejects_initializing_mapper(self):
        module = types.ModuleType("antirea.rust_ir")
        module.__file__ = str(self.files["rust_ir"])
        module.__spec__ = importlib.util.spec_from_file_location("antirea.rust_ir", module.__file__)
        module.__spec__._initializing = True
        sys.modules["antirea.rust_ir"] = module
        self.reject(lambda: self.normalizer._package_mapper(self.root, self.pins))

    def test_mapper_open_llvm_returns_caller_owned_stub_and_engine_receipt(self):
        llvm = self.mapper.open_llvm(workspace_root=self.root, llvm_library=self.library,
                                     trusted_engine_pins=self.pins)
        self.assertEqual(llvm.trusted_engine_inputs, self.pins)
        self.assertEqual(llvm.close_count, 0)
        llvm.close()
        self.assertEqual(llvm.close_count, 1)

    def test_mapper_added_api_failure_closes_created_adapter(self):
        self.files["swift_frontend"].write_text(SWIFT_STUB + '\nMISSING = "LLVMLookupIntrinsicID"\n', encoding="utf-8")
        self.refresh(self.files["swift_frontend"])
        with self.assertRaises(AttributeError):
            self.mapper.open_llvm(workspace_root=self.root, llvm_library=self.library,
                                  trusted_engine_pins=self.pins)
        self.assertEqual(sys.modules["antirea.swift_frontend"].INSTANCES[0].close_count, 1)

    def test_normalizer_open_llvm_returns_caller_owned_stub_and_engine_receipt(self):
        llvm = self.normalizer.open_llvm(workspace_root=self.root, llvm_library=self.library,
                                         trusted_engine_pins=self.pins)
        self.assertEqual(llvm.trusted_engine_inputs, self.pins)
        self.assertEqual(llvm.close_count, 0)
        llvm.close()
        self.assertEqual(llvm.close_count, 1)

    def test_normalizer_added_api_failure_closes_created_adapter(self):
        self.files["swift_frontend"].write_text(SWIFT_STUB + '\nMISSING = "LLVMGetGC"\n', encoding="utf-8")
        self.refresh(self.files["swift_frontend"])
        with self.assertRaises(AttributeError):
            self.normalizer.open_llvm(workspace_root=self.root, llvm_library=self.library,
                                      trusted_engine_pins=self.pins)
        self.assertEqual(sys.modules["antirea.swift_frontend"].INSTANCES[0].close_count, 1)



QUALIFIER = PROJECT / "antirea/rust_qualify.py"


class QualifierBootstrapTests(unittest.TestCase):
    is_test_module = staticmethod(BootstrapTests.is_test_module)
    restore_modules = BootstrapTests.restore_modules
    restore_import_configuration = BootstrapTests.restore_import_configuration
    start_patch = BootstrapTests.start_patch
    tearDown = BootstrapTests.tearDown
    refresh = BootstrapTests.refresh
    load = BootstrapTests.load
    reject = BootstrapTests.reject
    forge_cache = BootstrapTests.forge_cache
    assert_import_configuration_restored = BootstrapTests.assert_import_configuration_restored

    def setUp(self):
        BootstrapTests.setUp(self)
        self.qualifier_path = self.package / "rust_qualify.py"
        self.qualifier_path.write_bytes(QUALIFIER.read_bytes())
        self.refresh(self.qualifier_path)
        self.qualifier = source_bootstrap("_bootstrap_review_qualifier", self.qualifier_path)

    def bootstrap(self, pins=None):
        return self.qualifier._bootstrap(self.root, self.library,
            self.pins[str(self.library)], self.pins[str(self.config)],
            self.pins if pins is None else pins)

    def test_qualifier_bootstrap_and_shared_llvm_stub_are_pin_bound(self):
        mapper, index = self.bootstrap()
        self.assertEqual(Path(mapper.__file__), self.files["rust_ir"])
        self.assertEqual(len(index), len(self.pins))
        for path, expected in self.pins.items():
            self.assertEqual(index[self.qualifier.path_identity(path)]["sha256"], expected)
        llvm = mapper.open_llvm(workspace_root=self.root, llvm_library=self.library,
                                trusted_engine_pins=self.pins)
        self.qualifier._extra(llvm)
        self.assertEqual(llvm.trusted_engine_inputs, self.pins)
        self.assertEqual(llvm.close_count, 0)
        llvm.close()
        self.assertEqual(llvm.close_count, 1)
        self.assert_import_configuration_restored()

    def test_qualifier_does_not_execute_valid_mapper_pyc_trap(self):
        cache, raw = self.forge_cache("rust_ir")
        mapper, _ = self.bootstrap()
        self.assertTrue(callable(mapper.normalize_protection_ir))
        self.assertEqual(cache.read_bytes(), raw)

    def test_qualifier_does_not_execute_valid_package_pyc_trap(self):
        cache, raw = self.forge_cache("__init__")
        self.bootstrap()
        self.assertEqual(sys.modules["antirea"].PACKAGE_MARKER, "reviewed source")
        self.assertEqual(cache.read_bytes(), raw)

    def test_qualifier_rejects_missing_own_helper_config_or_library_pin(self):
        for path in (self.qualifier_path, self.files["helper"], self.config, self.library):
            with self.subTest(path=path.name):
                pins = dict(self.pins)
                del pins[str(path)]
                self.reject(lambda: self.bootstrap(pins))
                self.assertNotIn("antirea", sys.modules)

    def test_qualifier_rejects_changed_helper_before_loading_package(self):
        self.files["helper"].write_bytes(b'raise AssertionError("changed source executed")\n')
        self.reject(self.bootstrap)
        self.assertNotIn("antirea", sys.modules)

    def test_qualifier_rejects_foreign_preloaded_mapper_origin(self):
        module = types.ModuleType("antirea.rust_ir")
        module.__file__ = str(self.root / "foreign.py")
        sys.modules["antirea.rust_ir"] = module
        self.reject(self.bootstrap)

    def test_qualifier_rejects_initializing_same_source_mapper(self):
        mapper, _, _, _ = self.load("antirea.rust_ir")
        mapper.__spec__._initializing = True
        self.reject(self.bootstrap)
        self.assert_import_configuration_restored()

    def test_qualifier_rejects_none_cached_mapper(self):
        sys.modules["antirea.rust_ir"] = None
        self.reject(self.bootstrap)


if __name__ == "__main__":
    unittest.main(verbosity=2)
