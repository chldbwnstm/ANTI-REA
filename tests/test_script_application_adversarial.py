"""Independent adversarial tests for the phase24 script-application integration.

Authored by the INDEPENDENT worker lane (``.runs/phase24-root/brief.md``). These
tests exercise the REAL public API of the landed modules with structural, tamper
and refusal cases:

* engine ``validate_spec(spec) -> dict`` and ``validate_contract(contract) -> list``
  (the shared validator API the coordinator pinned for independent audit),
* engine ``run_integration(...)`` refusal / no-execution behaviour,
* the shared lexical reserved/received-path guard the whole route relies on, and
* the adapters' ``prepare_application(...)`` keyword-only interface conformance.

Design rules honoured (per the brief's INDEPENDENT lane):

* The production validators are NOT mocked.  Each negative (tamper) case is
  paired with a positive acceptance oracle so the suite cannot be satisfied by a
  validator that simply rejects everything.  The checks assert real refusal
  semantics, never an incidental matching ``TypeError``.
* Author-only.  No process / compiler / target is executed here.  The engine
  refusal tests patch ``process.run_logged`` with a tripwire and assert it is
  never reached, proving malformed input is refused before any child process.
  The worker does not run this file; root executes it after source freeze.
* A module that has not landed yet skips cleanly (``ModuleNotFoundError`` for
  that exact module); any other import failure (syntax / missing dependency in a
  landed module) is surfaced, not hidden.  A landed module that is missing an
  agreed symbol fails loudly as a routed finding.

Contract bounds mirror ``antirea.native_application`` exactly, as the brief
requires ("Same bounds as native_application"): 1..64 cases, unique labels,
<=16 args/case, <=256 chars/arg, stdout <=4096 chars, label <=128 chars,
integer (non-bool) returncode with no range restriction, and the exact case /
expect key sets.
"""
import contextlib
import importlib
import inspect
import os
import unittest


ENGINE_NAME = "antirea.script_app_integration"
PY_ADAPTER_NAME = "antirea.script_python_application"
JS_ADAPTER_NAME = "antirea.script_javascript_application"
GUARD_NAME = "antirea.jvm_app_integration"

SPEC_KIND = "script_application_integration"
CONTRACT_KIND = "script_application_samples"
SUCCESS_STATUS = "script_application_samples_passed"

# Brief-pinned reserved/received path components (defense-loop STOP excepted only
# for the existence probe, never as a consumable input).
FORBIDDEN_COMPONENTS = ("rea-analysis-reports", "attackerfolder", "env.setting",
                        "LINKREPRO", "linkrepro", "defense-loop")

# Brief adapter signature: prepare_application(*, ...) -- all keyword-only.
EXPECTED_PREPARE_PARAMS = ("source_root", "input_files", "protected_source", "entrypoint",
                           "producer", "output_dir", "tools", "trusted_inputs",
                           "timeout_seconds", "stop_file")
# Brief engine signature: run_integration(*, ...) -- all keyword-only.
EXPECTED_RUN_PARAMS = ("language", "source_root", "input_files", "producer", "spec",
                       "contract", "output_dir", "tools", "trusted_inputs",
                       "timeout_seconds", "stop_file")


def _import_or_skip_reason(name):
    """Import ``name``; return (module, None) or (None, reason) if not landed yet.

    Only the target module's OWN absence (or that of an ancestor package) is a
    clean "not landed" skip.  A ``ModuleNotFoundError`` for a different name (a
    missing dependency inside a landed module) is re-raised so it surfaces, as
    are ``SyntaxError`` / ``ImportError`` for other reasons.
    """
    try:
        return importlib.import_module(name), None
    except ModuleNotFoundError as exc:
        missing = getattr(exc, "name", None)
        if missing and (name == missing or name.startswith(missing + ".")):
            return None, "module %r has not landed yet: %s" % (name, exc)
        raise


def _refuse_errors(module):
    """Refusal oracle: the module's own ``*Error`` classes plus ``ValueError``.

    The codebase convention is that every integrate/application error subclasses
    ``ValueError`` (fail closed), so ``ValueError`` alone is a strong oracle; the
    module's concrete classes are added for robustness if that ever differs.
    """
    errors = [ValueError]
    for value in vars(module).values():
        if (isinstance(value, type) and issubclass(value, Exception)
                and getattr(value, "__module__", None) == module.__name__
                and value.__name__.endswith("Error")):
            errors.append(value)
    out = []
    for err in errors:
        if err not in out:
            out.append(err)
    return tuple(out)


class _EngineBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine, reason = _import_or_skip_reason(ENGINE_NAME)
        if cls.engine is None:
            # The engine landed on 2026-10-20; its absence is now a qualification
            # failure, never a silent skip.
            raise AssertionError("required engine module absent at qualification: " + str(reason))
        cls.refuse = _refuse_errors(cls.engine)

    def _require(self, attr):
        fn = getattr(self.engine, attr, None)
        if fn is None:
            self.skipTest("%s.%s not present (see test_engine_exposes_agreed_api)" % (ENGINE_NAME, attr))
        return fn


class EngineApiPresenceTests(_EngineBase):
    def test_engine_exposes_agreed_api(self):
        # The coordinator pinned these exact names for independent audit; a
        # landed engine that lacks them is a routed interface finding.
        for attr in ("validate_spec", "validate_contract", "run_integration"):
            with self.subTest(symbol=attr):
                self.assertTrue(callable(getattr(self.engine, attr, None)),
                                "%s must expose %s()" % (ENGINE_NAME, attr))


class EngineSpecValidationTests(_EngineBase):
    """Tamper/refusal + acceptance oracle for ``validate_spec``."""

    def setUp(self):
        self.validate_spec = self._require("validate_spec")

    def _valid_python(self):
        return {"schema_version": 1, "kind": SPEC_KIND, "language": "python",
                "protected_source": "core.py", "entrypoint": "app.py",
                "application_files": ["core.py", "app.py", "data.json", "readme.txt"]}

    def _valid_javascript(self):
        return {"schema_version": 1, "kind": SPEC_KIND, "language": "javascript",
                "protected_source": "lib.js", "entrypoint": "cli.cjs",
                "application_files": ["lib.js", "cli.cjs", "config.json", "notes.txt"]}

    def _accepts(self, spec):
        try:
            self.validate_spec(spec)
            return True
        except Exception:
            return False

    # --- positive acceptance oracles ------------------------------------ #
    def test_accepts_valid_python_spec(self):
        result = self.validate_spec(self._valid_python())
        self.assertIsInstance(result, dict)

    def test_accepts_valid_javascript_spec(self):
        result = self.validate_spec(self._valid_javascript())
        self.assertIsInstance(result, dict)

    # --- structural tamper refusals ------------------------------------- #
    def test_rejects_non_object_spec(self):
        for bad in ([], "spec", 7, None, ("a",)):
            with self.subTest(spec=bad), self.assertRaises(self.refuse):
                self.validate_spec(bad)

    def test_rejects_extra_or_missing_keys(self):
        base = self._valid_python()
        extra = dict(base, surprise=True)
        with self.subTest(case="extra"), self.assertRaises(self.refuse):
            self.validate_spec(extra)
        for key in list(base):
            missing = {k: v for k, v in base.items() if k != key}
            with self.subTest(missing=key), self.assertRaises(self.refuse):
                self.validate_spec(missing)

    def test_rejects_bad_schema_version(self):
        for bad in (2, 0, "1", 1.0, True, None):
            spec = dict(self._valid_python(), schema_version=bad)
            with self.subTest(schema_version=bad), self.assertRaises(self.refuse):
                self.validate_spec(spec)

    def test_rejects_wrong_kind(self):
        for bad in ("native_application_integration", "script_application_samples", "", None):
            spec = dict(self._valid_python(), kind=bad)
            with self.subTest(kind=bad), self.assertRaises(self.refuse):
                self.validate_spec(spec)

    def test_rejects_unsupported_language(self):
        for bad in ("ruby", "go", "PYTHON", "", None, 1):
            spec = dict(self._valid_python(), language=bad)
            with self.subTest(language=bad), self.assertRaises(self.refuse):
                self.validate_spec(spec)

    def test_rejects_unclean_protected_source_or_entrypoint(self):
        unclean = ["/abs/core.py", "..\\core.py", "../core.py", "a/../b.py", "a/./b.py",
                   "c:/core.py", "back\\slash.py", "trail.py ", " lead.py", "", "a//b.py"]
        base = self._valid_python()
        for field in ("protected_source", "entrypoint"):
            for value in unclean:
                spec = dict(base)
                spec[field] = value
                spec["application_files"] = list(base["application_files"]) + [value]
                with self.subTest(field=field, value=value), self.assertRaises(self.refuse):
                    self.validate_spec(spec)

    def test_rejects_entrypoint_equal_to_protected_source(self):
        # A protected source integrated by itself defeats the "ordinary callers
        # actually integrated" requirement and must be refused.
        spec = dict(self._valid_python(), protected_source="core.py", entrypoint="core.py",
                    application_files=["core.py", "data.json"])
        with self.assertRaises(self.refuse):
            self.validate_spec(spec)

    def test_rejects_application_files_not_a_bounded_list(self):
        base = self._valid_python()
        for bad in (None, "core.py", {}, []):
            spec = dict(base, application_files=bad)
            with self.subTest(application_files=bad), self.assertRaises(self.refuse):
                self.validate_spec(spec)
        over = ["core.py", "app.py"] + ["f%d.py" % i for i in range(127)]  # 129 > 128
        spec = dict(base, application_files=over)
        with self.subTest(count=len(over)), self.assertRaises(self.refuse):
            self.validate_spec(spec)

    def test_rejects_files_missing_protected_source_or_entrypoint(self):
        base = self._valid_python()
        without_protected = dict(base, application_files=["app.py", "data.json"])
        with self.subTest(drop="protected_source"), self.assertRaises(self.refuse):
            self.validate_spec(without_protected)
        without_entry = dict(base, application_files=["core.py", "data.json"])
        with self.subTest(drop="entrypoint"), self.assertRaises(self.refuse):
            self.validate_spec(without_entry)

    def test_rejects_duplicate_and_casefold_collisions(self):
        base = self._valid_python()
        dup = dict(base, application_files=["core.py", "app.py", "app.py"])
        with self.subTest(kind="duplicate"), self.assertRaises(self.refuse):
            self.validate_spec(dup)
        casefold = dict(base, application_files=["core.py", "app.py", "App.py"])
        with self.subTest(kind="casefold"), self.assertRaises(self.refuse):
            self.validate_spec(casefold)

    def test_rejects_cross_language_extensions(self):
        py = dict(self._valid_python(),
                  application_files=["core.py", "app.py", "sneaky.js"])
        with self.subTest(language="python", ext=".js"), self.assertRaises(self.refuse):
            self.validate_spec(py)
        js = dict(self._valid_javascript(),
                  application_files=["lib.js", "cli.cjs", "sneaky.py"])
        with self.subTest(language="javascript", ext=".py"), self.assertRaises(self.refuse):
            self.validate_spec(js)
        esm = dict(self._valid_javascript(),
                   application_files=["lib.js", "cli.cjs", "mod.mjs"])
        with self.subTest(language="javascript", ext=".mjs"), self.assertRaises(self.refuse):
            self.validate_spec(esm)

    def test_rejects_reserved_received_component_in_files(self):
        base = self._valid_python()
        spec = dict(base, application_files=["core.py", "app.py", "rea-analysis-reports/leak.py"])
        with self.assertRaises(self.refuse):
            self.validate_spec(spec)

    # --- TypeScript: concrete now that the engine validator has landed --- #
    def _ts_baseline(self):
        return {"schema_version": 1, "kind": SPEC_KIND, "language": "typescript",
                "protected_source": "core.ts", "entrypoint": "app.ts",
                "application_files": ["core.ts", "app.ts", "data.json"]}

    def test_accepts_valid_typescript_spec(self):
        result = self.validate_spec(self._ts_baseline())
        self.assertIsInstance(result, dict)
        self.assertEqual(result["language"], "typescript")

    def test_typescript_rejects_declaration_jsx_and_output_collision(self):
        base = self._ts_baseline()
        for leak in ("types.d.ts", "widget.tsx"):
            spec = dict(base, application_files=list(base["application_files"]) + [leak])
            with self.subTest(leak=leak), self.assertRaises(self.refuse):
                self.validate_spec(spec)
        # core.ts transpiles to core.js; an explicitly listed core.js collides.
        collide = dict(base, application_files=list(base["application_files"]) + ["core.js"])
        with self.subTest(case="transpile-output-collision"), self.assertRaises(self.refuse):
            self.validate_spec(collide)


class EngineContractValidationTests(_EngineBase):
    """Tamper/refusal + acceptance oracle for ``validate_contract``."""

    def setUp(self):
        self.validate_contract = self._require("validate_contract")

    def _valid(self):
        return {"schema_version": 1, "kind": CONTRACT_KIND,
                "cases": [{"label": "ok", "args": ["7"], "expect": {"returncode": 0, "stdout": "42\n"}},
                          {"label": "usage", "args": [], "expect": {"returncode": 2, "stdout": ""}}]}

    def _case(self, **over):
        case = {"label": "ok", "args": ["7"], "expect": {"returncode": 0, "stdout": "42\n"}}
        case.update(over)
        return {"schema_version": 1, "kind": CONTRACT_KIND, "cases": [case]}

    # --- positive acceptance oracle ------------------------------------- #
    def test_accepts_valid_contract_and_returns_cases(self):
        result = self.validate_contract(self._valid())
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)
        self.assertEqual({c["label"] for c in result}, {"ok", "usage"})

    # --- structural tamper refusals ------------------------------------- #
    def test_rejects_non_object_contract(self):
        for bad in ([], "x", 1, None):
            with self.subTest(contract=bad), self.assertRaises(self.refuse):
                self.validate_contract(bad)

    def test_rejects_extra_or_missing_keys(self):
        base = self._valid()
        with self.subTest(case="extra"), self.assertRaises(self.refuse):
            self.validate_contract(dict(base, extra=1))
        for key in ("schema_version", "kind", "cases"):
            with self.subTest(missing=key), self.assertRaises(self.refuse):
                self.validate_contract({k: v for k, v in base.items() if k != key})

    def test_rejects_bad_schema_version_and_kind(self):
        for bad in (2, "1", 1.0, True, None):
            with self.subTest(schema_version=bad), self.assertRaises(self.refuse):
                self.validate_contract(dict(self._valid(), schema_version=bad))
        for bad in ("native_application_samples", "script_application_integration", "", None):
            with self.subTest(kind=bad), self.assertRaises(self.refuse):
                self.validate_contract(dict(self._valid(), kind=bad))

    def test_rejects_empty_and_oversized_case_lists(self):
        with self.subTest(case="empty"), self.assertRaises(self.refuse):
            self.validate_contract(dict(self._valid(), cases=[]))
        with self.subTest(case="not-list"), self.assertRaises(self.refuse):
            self.validate_contract(dict(self._valid(), cases={"label": "x"}))
        too_many = [{"label": "c%d" % i, "args": [], "expect": {"returncode": 0, "stdout": ""}}
                    for i in range(65)]
        with self.subTest(case="too-many"), self.assertRaises(self.refuse):
            self.validate_contract(dict(self._valid(), cases=too_many))

    def test_rejects_duplicate_labels(self):
        cases = [{"label": "dup", "args": [], "expect": {"returncode": 0, "stdout": ""}},
                 {"label": "dup", "args": [], "expect": {"returncode": 1, "stdout": ""}}]
        with self.assertRaises(self.refuse):
            self.validate_contract(dict(self._valid(), cases=cases))

    def test_rejects_bad_case_and_expect_shapes(self):
        with self.subTest(part="case-not-object"), self.assertRaises(self.refuse):
            self.validate_contract(dict(self._valid(), cases=["notacase"]))
        with self.subTest(part="case-extra-key"), self.assertRaises(self.refuse):
            self.validate_contract(self._case(shell=True))
        for forbidden in ("flags", "env", "cwd", "command"):
            with self.subTest(forbidden_field=forbidden), self.assertRaises(self.refuse):
                self.validate_contract(self._case(**{forbidden: "x"}))
        with self.subTest(part="expect-extra-key"), self.assertRaises(self.refuse):
            self.validate_contract(self._case(expect={"returncode": 0, "stdout": "", "stderr": ""}))
        for drop in ("returncode", "stdout"):
            partial = {k: v for k, v in {"returncode": 0, "stdout": ""}.items() if k != drop}
            with self.subTest(expect_missing=drop), self.assertRaises(self.refuse):
                self.validate_contract(self._case(expect=partial))

    def test_rejects_bad_labels(self):
        # Landed engine bounds: non-empty printable str <=128 chars.
        for bad in ("", 7, None, "x" * 129, "has\nnewline", "tab\tlabel"):
            with self.subTest(label=bad), self.assertRaises(self.refuse):
                self.validate_contract(self._case(label=bad))

    def test_rejects_contract_without_a_success_case(self):
        # The landed engine requires >=1 returncode==0 case for the missing-module
        # control; a contract of only non-zero cases must be refused.
        cases = [{"label": "fail", "args": [], "expect": {"returncode": 1, "stdout": ""}},
                 {"label": "usage", "args": [], "expect": {"returncode": 2, "stdout": ""}}]
        with self.assertRaises(self.refuse):
            self.validate_contract(dict(self._valid(), cases=cases))

    def test_rejects_bad_args(self):
        with self.subTest(args="not-list"), self.assertRaises(self.refuse):
            self.validate_contract(self._case(args="7"))
        with self.subTest(args="too-many"), self.assertRaises(self.refuse):
            self.validate_contract(self._case(args=["a"] * 17))
        with self.subTest(args="non-string"), self.assertRaises(self.refuse):
            self.validate_contract(self._case(args=[7]))
        with self.subTest(args="boolean"), self.assertRaises(self.refuse):
            self.validate_contract(self._case(args=[True]))
        with self.subTest(args="too-long"), self.assertRaises(self.refuse):
            self.validate_contract(self._case(args=["x" * 257]))
        with self.subTest(args="control-char"), self.assertRaises(self.refuse):
            self.validate_contract(self._case(args=["bad\x00arg"]))

    def test_rejects_bad_returncode(self):
        for bad in (True, "0", 1.0, None, [0]):
            with self.subTest(returncode=bad), self.assertRaises(self.refuse):
                self.validate_contract(self._case(expect={"returncode": bad, "stdout": ""}))

    def test_rejects_bad_stdout(self):
        with self.subTest(stdout="non-string"), self.assertRaises(self.refuse):
            self.validate_contract(self._case(expect={"returncode": 0, "stdout": 7}))
        with self.subTest(stdout="too-long"), self.assertRaises(self.refuse):
            self.validate_contract(self._case(expect={"returncode": 0, "stdout": "x" * 4097}))
        with self.subTest(stdout="control-char"), self.assertRaises(self.refuse):
            self.validate_contract(self._case(expect={"returncode": 0, "stdout": "a\x00b"}))


class EngineRunIntegrationSignatureTests(_EngineBase):
    """Structural conformance of ``run_integration`` to the pinned signature.

    Kept separate from the refusal tests so a signature deviation is reported as
    a loud finding rather than skipped away by a gate.
    """

    def setUp(self):
        self.run_integration = self._require("run_integration")

    def test_run_integration_signature(self):
        params = inspect.signature(self.run_integration).parameters
        for name in EXPECTED_RUN_PARAMS:
            with self.subTest(param=name):
                self.assertIn(name, params, "run_integration missing agreed parameter %r" % name)
                self.assertEqual(params[name].kind, inspect.Parameter.KEYWORD_ONLY,
                                 "run_integration.%s must be keyword-only" % name)


class EngineRunIntegrationRefusalTests(_EngineBase):
    """``run_integration`` must refuse malformed input before executing anything."""

    def setUp(self):
        self.run_integration = self._require("run_integration")
        params = inspect.signature(self.run_integration).parameters
        if not set(EXPECTED_RUN_PARAMS) <= set(params):
            self.skipTest("run_integration signature mismatch (see "
                          "EngineRunIntegrationSignatureTests.test_run_integration_signature)")
        base_keys = {"language", "source_root", "input_files", "producer", "spec", "contract",
                     "output_dir", "tools", "trusted_inputs", "timeout_seconds", "stop_file"}
        unsatisfiable = [name for name, p in params.items()
                         if p.default is inspect.Parameter.empty
                         and p.kind in (inspect.Parameter.POSITIONAL_ONLY,
                                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                                        inspect.Parameter.KEYWORD_ONLY)
                         and name not in base_keys]
        if unsatisfiable:
            self.skipTest("run_integration has extra required parameter(s) %r; routed to engine owner"
                          % unsatisfiable)
        self.params = params

    def _kwargs(self, **over):
        base = {"language": "python", "source_root": ".", "input_files": {},
                "producer": {}, "spec": {}, "contract": {}, "output_dir": ".",
                "tools": {}, "trusted_inputs": None, "timeout_seconds": 120,
                "stop_file": "."}
        base.update(over)
        return {k: v for k, v in base.items() if k in self.params}

    @contextlib.contextmanager
    def _run_logged_tripwire(self):
        import unittest.mock as mock
        calls = []

        def tripwire(*args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError("process.run_logged reached on a refused/malformed input")

        proc = getattr(self.engine, "process", None)
        if proc is not None and hasattr(proc, "run_logged"):
            target = mock.patch.object(proc, "run_logged", side_effect=tripwire)
        else:
            import antirea.process as ap
            target = mock.patch.object(ap, "run_logged", side_effect=tripwire)
        with target:
            yield calls

    def _assert_refused_without_execution(self, **kwargs):
        with self._run_logged_tripwire() as calls:
            try:
                result = self.run_integration(**kwargs)
            except Exception:
                pass  # refused by raising -- acceptable fail-closed behaviour
            else:
                # Or refused by returning a non-success report -- also acceptable,
                # provided nothing was executed.
                self.assertIsInstance(result, dict)
                self.assertNotEqual(result.get("status"), SUCCESS_STATUS)
            self.assertEqual(calls, [], "run_integration executed a child on refused input")

    def test_malformed_inputs_never_execute_a_child(self):
        self._assert_refused_without_execution(**self._kwargs())

    def test_bad_timeout_is_refused_without_execution(self):
        for bad in (True, 0, -1, 601, "120", 1.5, None):
            with self.subTest(timeout=bad):
                self._assert_refused_without_execution(**self._kwargs(timeout_seconds=bad))

    def test_reserved_source_root_is_refused_without_execution(self):
        # A received/reserved component anywhere in the inputs must be refused
        # (lexically) and must never reach execution.
        self._assert_refused_without_execution(
            **self._kwargs(input_files={"rea-analysis-reports/leak.py":
                                        "0" * 64}))


class SharedReservedGuardTests(unittest.TestCase):
    """The lexical reserved/received guard the engine and adapters consume."""

    @classmethod
    def setUpClass(cls):
        cls.guard, reason = _import_or_skip_reason(GUARD_NAME)
        if cls.guard is None:
            raise unittest.SkipTest(reason)
        cls.refuse = _refuse_errors(cls.guard)

    def _clean_base(self):
        # An absolute, reserved-free base so the positive control does not depend
        # on the process working directory.
        return os.path.join(os.path.abspath(os.sep), "antirea_clean_base", "pkg")

    def test_reserved_components_are_lexically_refused(self):
        guard = getattr(self.guard, "_reserved_guard", None)
        if guard is None:
            self.skipTest("%s._reserved_guard not present" % GUARD_NAME)
        base = self._clean_base()
        for token in FORBIDDEN_COMPONENTS:
            for path in (os.path.join(base, token),
                         os.path.join(base, token, "x.py"),
                         os.path.join(base, "deep", token, "y.json")):
                with self.subTest(path=path), self.assertRaises(self.refuse):
                    guard(path)

    def test_clean_component_is_allowed(self):
        guard = getattr(self.guard, "_reserved_guard", None)
        if guard is None:
            self.skipTest("%s._reserved_guard not present" % GUARD_NAME)
        # Positive control: a reserved-free path must NOT be refused, otherwise
        # the negatives above would pass trivially.
        guard(os.path.join(self._clean_base(), "app", "main.py"))


REQUIRED_MODULES = (
    "antirea.script_application",        # root service (landed)
    "antirea.script_app_integration",    # engine (landed)
    "antirea.script_python_application", # python adapter (landed)
    "antirea.script_javascript_application",  # JS/TS adapter (landed 2026-10-20 13:10)
)


class RequiredModulesGateTests(unittest.TestCase):
    """Qualification gate: every required production module must be importable.

    A missing required module is a qualification failure (per the phase24 brief),
    not a skip. Root runs this suite after all source owners freeze, when all of
    REQUIRED_MODULES must be present.
    """

    def test_all_required_production_modules_import(self):
        absent = []
        for name in REQUIRED_MODULES:
            module, reason = _import_or_skip_reason(name)
            if module is None:
                absent.append(name)
        self.assertEqual(absent, [], "required production module(s) missing at qualification: %r" % absent)


class AdapterInterfaceConformanceTests(unittest.TestCase):
    """Independent structural check that adapters honour the agreed signature."""

    def _check_adapter(self, module_name, *, required):
        module, reason = _import_or_skip_reason(module_name)
        if module is None:
            if required:
                # Landed adapter: absence is a qualification failure, not a skip.
                self.fail("required adapter module absent at qualification: " + str(reason))
            self.skipTest(reason)
        prepare = getattr(module, "prepare_application", None)
        self.assertTrue(callable(prepare),
                        "%s must expose prepare_application()" % module_name)
        params = inspect.signature(prepare).parameters
        for name in EXPECTED_PREPARE_PARAMS:
            with self.subTest(module=module_name, param=name):
                self.assertIn(name, params,
                              "%s.prepare_application missing agreed parameter %r" % (module_name, name))
                self.assertEqual(params[name].kind, inspect.Parameter.KEYWORD_ONLY,
                                 "%s.prepare_application.%s must be keyword-only" % (module_name, name))
        # No bare positional-or-keyword parameters: the brief pins a `*,` signature.
        positional = [p for p in params.values()
                      if p.kind in (inspect.Parameter.POSITIONAL_ONLY,
                                    inspect.Parameter.POSITIONAL_OR_KEYWORD)]
        self.assertEqual(positional, [],
                         "%s.prepare_application must be fully keyword-only" % module_name)

    def test_python_adapter_signature(self):
        self._check_adapter(PY_ADAPTER_NAME, required=True)   # landed 2026-10-20

    def test_javascript_adapter_signature(self):
        self._check_adapter(JS_ADAPTER_NAME, required=True)   # landed 2026-10-20 13:10


if __name__ == "__main__":
    unittest.main()
