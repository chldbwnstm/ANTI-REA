"""Real installed-parser and owned-source VM checks; never external input execution."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from antirea import javascript_frontend as jf
from antirea.javascript_validate import validate_build


class JavaScriptFrontendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.tools = jf.discover_toolchain()
        except ValueError as exc:
            raise unittest.SkipTest(str(exc))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root, self.index = Path(self.temp.name), 0

    def project(self, source, functions=None, language="javascript"):
        self.index += 1
        directory = self.root / ("source-" + str(self.index)); directory.mkdir()
        suffix = ".ts" if language == "typescript" else ".js"
        (directory / ("core" + suffix)).write_text(source, encoding="utf-8")
        path = directory / "project.json"
        path.write_text(json.dumps({"schema_version": 1, "name": "owned", "language": language,
                                   "sources": ["core" + suffix], "functions": functions or ["core"]}), encoding="utf-8")
        return path

    def run_owned(self, source, functions=None, language="javascript", kind="number", parameters=None):
        path = self.project(source, functions, language)
        output = self.root / ".runs" / str(self.index)
        build = jf.build_project(path, output, workspace_root=self.root, seed=42)
        self.assertEqual(build["status"], "artifact_created_unvalidated", build)
        params = parameters or [{"name": "x", "type": kind, "minimum": "-100" if kind == "bigint" else -100,
                                  "maximum": "100" if kind == "bigint" else 100},
                                 {"name": "y", "type": kind, "minimum": "-5" if kind == "bigint" else -5,
                                  "maximum": "5" if kind == "bigint" else 5}]
        contract = {"schema_version": 1, "kind": "javascript_scalar_samples",
                    "functions": [{"name": name, "parameters": params} for name in functions or ["core"]]}
        contract_path = path.parent / "contract.json"; contract_path.write_text(json.dumps(contract), encoding="utf-8")
        validation = validate_build(output / "report.json", contract_path, output / "validation",
                                    workspace_root=self.root, random_cases=64, timeout_seconds=20)
        self.assertEqual(validation["status"], "functional_samples_passed", validation)
        return build, validation

    def test_inspection_deterministic_and_no_target_execution_or_output(self):
        path = self.project("function core(x, y) { return x + y; }")
        first, second = jf.inspect_project(path), jf.inspect_project(path)
        self.assertEqual(first, second)
        self.assertFalse(first["source_executed"])
        self.assertFalse((self.root / ".runs").exists())
        self.assertEqual(first["function_signatures"]["core"]["parameters"], ["x", "y"])

    def test_build_report_exact_and_no_plaintext_body(self):
        source = "const PRIVATE_BIAS = 731; function helper(value) { return value * PRIVATE_BIAS + 193; } function core(x,y) { return helper(x) ^ y; }"
        build, _ = self.run_owned(source)
        artifact = Path(build["protected"]).read_text()
        self.assertNotIn("PRIVATE_BIAS", artifact)
        self.assertNotIn("return helper(x)", artifact)
        self.assertNotIn("Function(", artifact)
        self.assertNotIn("eval(", artifact)
        self.assertEqual(build["coverage"]["helper_closure"], ["core", "helper"])
        self.assertFalse(build["coverage"]["kagura_passes_applied"])
        self.assertEqual(build, json.loads((Path(build["output_dir"]) / "report.json").read_text()))

    def test_js_numbers_nan_infinity_negative_zero_and_comparisons(self):
        self.run_owned("function core(x,y) { return x === y ? -x : (x / y); }")
        self.run_owned("function core(x,y) { return (x <= y) !== (x >= y); }")

    def test_short_circuit_and_nullish_preserve_values(self):
        self.run_owned("function core(x,y) { let value; return (x && y) || (value ?? x); }")

    def test_lexical_shadowing_tdz_and_const_assignment_errors(self):
        self.run_owned("function core(x,y) { let value = x; if (y > 0) { let value = y; value += 3; } return value; }")
        self.run_owned("function core(x,y) { if (x > 0) { const value = y; value += 1; } else { return x; } return y; }")
        self.run_owned("function core(x,y) { if (x > 0) { return value; let value = y; } return x; }")

    def test_loops_updates_break_continue_and_do_while(self):
        self.run_owned("""function core(x,y) {
          let value = x | 0; let limit = (y | 0) & 7;
          for (let i = 0; i < limit; ++i) { if (i === 2) continue; if (i === 5) break; value += i; }
          while (limit > 0) { limit--; if (limit === 3) continue; value ^= limit; }
          do { value += 1; limit++; } while (limit < 2);
          return value;
        }""")

    def test_bigint_division_negative_shifts_and_unsigned_shift_errors(self):
        self.run_owned("function core(x,y) { return x / y + (x << y); }", kind="bigint")
        self.run_owned("function core(x,y) { return x > 0n ? (x >>> y) : x; }", kind="bigint")

    def test_real_typescript_annotations_are_lowered_not_just_erased(self):
        build, _ = self.run_owned("export function core(x: bigint,y: bigint): bigint { return (x * x) ^ y; }", language="typescript", kind="bigint")
        self.assertIn("return (x * x) ^ y", Path(build["baseline"]).read_text())
        self.assertNotIn("return (x * x) ^ y", Path(build["protected"]).read_text())

    def test_exported_runtime_builtin_names_and_enter_parameter_do_not_shadow_vm(self):
        functions = ["Object", "Math", "Number", "process", "enter"]
        source = "\n".join(f"export function {name}(x: number, y: number): number {{ return x + y; }}" for name in functions)
        self.run_owned(source, functions, "typescript")
        self.run_owned("function core(enter, y) { return enter + y; }", parameters=[
            {"name": "enter", "type": "number", "minimum": -10, "maximum": 10},
            {"name": "y", "type": "number", "minimum": -10, "maximum": 10}])

    def test_unsupported_syntax_and_module_effects_rejected_before_output(self):
        sources = ["require('node:fs'); function core(x) { return x; }",
                   "function core(x) { return require('node:fs'); }",
                   "function core(x) { var y = x; return y; }",
                   "function core(x) { return [x][0]; }",
                   "function core(x) { return () => x; }",
                   "function core(x) { return core(x - 1); }",
                   "function core(x = 1) { return x; }",
                   "function core(...x) { return 1; }",
                   "async function core(x) { return x; }",
                   "function core(x) { let y = x; let y = 2; return y; }",
                   "const z = 2 + 3; function core(x) { return x; }",
                   "function core(x) { return Math.random(); }",
                   "function core(x) { return x.constructor(); }"]
        for source in sources:
            with self.subTest(source=source):
                project = self.project(source)
                output = self.root / ".runs" / str(self.index)
                with self.assertRaises(ValueError): jf.build_project(project, output, workspace_root=self.root)
                self.assertFalse(output.exists())

    def test_typescript_enums_namespaces_and_assertions_rejected(self):
        for source in ("enum E { A }; function core(x: number) { return x; }",
                       "namespace N { export const x = 1; } function core(x: number) { return x; }",
                       "function core<T>(x: T) { return x; }",
                       "function core(x: number) { return x as number; }"):
            with self.subTest(source=source), self.assertRaises(ValueError):
                jf.inspect_project(self.project(source, language="typescript"))

    def test_node_preload_environment_is_removed(self):
        preload = self.root / "preload.cjs"; preload.write_text("throw new Error('ambient preload ran');", encoding="utf-8")
        with patch.dict(os.environ, {"NODE_OPTIONS": '--require "' + str(preload) + '"', "NODE_PATH": str(self.root)}):
            self.run_owned("function core(x,y) { return x + y; }")

    def test_tool_pin_change_and_path_escape_fail_preflight(self):
        toolchain = jf.discover_toolchain(); toolchain["files"]["compiler_helper"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "changed"):
            jf._parse("function core(x) { return x; }", "javascript", ["core"], toolchain)
        project = self.project("function core(x,y) { return x+y; }")
        data = json.loads(project.read_text()); data["sources"] = ["../outside.js"]; project.write_text(json.dumps(data))
        with self.assertRaises(ValueError): jf.inspect_project(project)

    def test_existing_output_and_stop_prevent_build(self):
        project = self.project("function core(x,y) { return x+y; }")
        output = self.root / ".runs" / "existing"; output.mkdir(parents=True)
        with self.assertRaises(ValueError): jf.build_project(project, output, workspace_root=self.root)
        stop = self.root / ".runs/defense-loop/STOP"; stop.parent.mkdir(); stop.touch()
        with self.assertRaisesRegex(ValueError, "STOP"):
            jf.build_project(project, self.root / ".runs/stopped", workspace_root=self.root)


if __name__ == "__main__":
    unittest.main()
