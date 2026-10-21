import json
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

from antirea.go_frontend import (Emitter, GoFrontendError, _compiler, _environment, _run, build_project,
    inspect_project, reference_source, resolve_closure, verify_build)
from antirea.process import run_logged


def value(name="v0", typ="int32"):
    return {"kind": "variable", "id": name, "type": typ}


def constant(number, typ="int32"):
    return {"kind": "constant", "type": typ, "value": str(number)}


def method(name="Compute", body=None):
    return {"name": name, "parameters": [{"id": "v0", "name": "x", "type": "int32"}],
        "return_type": "int32", "locals": [{"id": "v0", "name": "x", "type": "int32"}], "calls": [],
        "body": body or {"kind": "return", "value": value()}}


class LoweringTests(unittest.TestCase):
    def emitter(self):
        m = method()
        return Emitter(m, {"Compute": "my_export"}, {"Compute": m})

    def test_arbitrary_function_name_and_signed_abi(self):
        proto, code = self.emitter().emit()
        self.assertIn("int32_t my_export(int32_t p0)", proto)
        self.assertIn("uint64_t v0", code)
        self.assertIn("0xffffffff", code)

    def test_wrap_add_multiply_and_negation_use_unsigned_patterns(self):
        e = self.emitter()
        for op in ("+", "-", "*", "&^", "^"):
            result = e.binary(op, "a", "b", "int32", "int32")
            self.assertIn("0xffffffff", result)
        self.assertIn("UINT64_C(0) -", e.expr({"kind": "unary", "op": "-", "type": "int32", "value": value()}))

    def test_signed_order_uses_bias_unsigned_order_does_not(self):
        e = self.emitter()
        self.assertIn("2147483648", e.binary("<", "a", "b", "int32", "bool"))
        self.assertNotIn("2147483648", e.binary("<", "a", "b", "uint32", "bool"))

    def test_go_shift_counts_not_masked(self):
        e = self.emitter()
        code = e.binary(">>", "a", "b", "int32", "int32", value("b", "uint64"))
        self.assertIn(">= 32", code)
        self.assertIn("UINT64_C(0) -", code)
        self.assertNotIn("& 31", code)
        code = e.binary("<<", "a", "b", "uint64", "uint64", value("b", "uint32"))
        self.assertIn(">= 64", code)

    def test_dynamic_signed_shift_fails_instead_of_losing_panic(self):
        with self.assertRaisesRegex(GoFrontendError, "may panic"):
            self.emitter().binary("<<", "a", "b", "int32", "int32", value("b", "int32"))

    def test_negative_constant_shift_fails(self):
        with self.assertRaises(GoFrontendError):
            self.emitter().binary("<<", "a", "b", "int32", "int32", constant(-1))

    def test_signed_widen_sign_extends_unsigned_widen_does_not(self):
        e = self.emitter()
        signed = e.expr({"kind": "convert", "type": "uint64", "value": value()})
        unsigned = e.expr({"kind": "convert", "type": "int64", "value": value(typ="uint32")})
        self.assertIn("2147483648", signed)
        self.assertNotIn("2147483648", unsigned)

    def test_narrowing_truncates_without_signed_arithmetic(self):
        code = self.emitter().expr({"kind": "convert", "type": "int32", "value": value(typ="int64")})
        self.assertIn("0xffffffff", code)

    def test_loop_continue_runs_post(self):
        code = "\n".join(self.emitter().stmt({"kind": "for", "init": {"kind": "empty"}, "condition": None,
            "body": {"kind": "continue"}, "post": {"kind": "incdec", "id": "v0", "type": "int32", "op": "++"}}))
        self.assertLess(code.index("goto continue_1"), code.index("continue_1:;"))
        self.assertLess(code.index("continue_1:;"), code.index("v0 ="))

    def test_loop_has_constant_control_and_checks_condition_before_body(self):
        condition = {"kind": "binary", "type": "bool", "op": "!=", "left": value(), "right": constant(0)}
        code = "\n".join(self.emitter().stmt({"kind": "for", "init": {"kind": "empty"}, "condition": condition,
            "body": {"kind": "incdec", "id": "v0", "type": "int32", "op": "++"}, "post": {"kind": "empty"}}))
        self.assertIn("for (;;) {", code)
        self.assertNotIn("while (", code)
        self.assertEqual(code.count("if (!("), 1)
        self.assertLess(code.index("if (!("), code.index("v0 ="))
        self.assertNotIn("volatile", code)

    def test_division_unknown_operation_and_expression_fail(self):
        e = self.emitter()
        for op in ("/", "%", "unknown"):
            with self.assertRaises(GoFrontendError):
                e.binary(op, "a", "b", "int32", "int32")
        with self.assertRaises(GoFrontendError):
            e.expr({"kind": "pointer", "type": "int32"})

    def test_helper_closure_is_transitive_and_not_plaintext_delegate(self):
        a, b, c = method("A"), method("B"), method("C")
        a["calls"], b["calls"] = ["B"], ["C"]
        selected, symbols, roots = resolve_closure({"methods": [a,b,c]}, [{"name": "A", "export": "a"}])
        self.assertEqual(set(selected), {"A", "B", "C"})
        self.assertEqual(roots, {"A"})
        self.assertTrue(symbols["B"].startswith("go_owned_"))

    def test_missing_helper_and_recursion_fail_closed(self):
        a = method("A"); a["calls"] = ["Missing"]
        with self.assertRaises(GoFrontendError):
            resolve_closure({"methods": [a]}, [{"name": "A", "export": "a"}])
        a["calls"] = ["A"]
        with self.assertRaisesRegex(GoFrontendError, "Recursive"):
            resolve_closure({"methods": [a]}, [{"name": "A", "export": "a"}])

    def test_reference_exact_decimal_signed_unsigned_parsing(self):
        m = method(); m["parameters"] += [{"id": "v1", "name": "b", "type": "uint64"}]
        source = reference_source({"Compute": m}, [{"name": "Compute", "export": "my_export"}])
        self.assertIn("strconv.ParseInt(fields[0], 10, 32)", source)
        self.assertIn("strconv.ParseUint(fields[1], 10, 64)", source)
        self.assertIn("Compute(int32(p0), uint64(p1))", source)

    def test_zero_argument_reference_does_not_import_unused_strconv(self):
        m=method(); m["parameters"]=[]; m["locals"]=[]
        source=reference_source({"Compute":m},[{"name":"Compute","export":"my_export"}])
        self.assertNotIn('"strconv"',source)
        self.assertIn("Compute()",source)


class BoundaryTests(unittest.TestCase):
    def test_ambient_go_hooks_are_removed(self):
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"GOFLAGS": "-toolexec=evil", "GOCACHEPROG": "evil", "GOTOOLCHAIN": "evil", "GOPROXY": "evil"}):
            env = _environment({"go_root": td}, Path(td))
            self.assertNotIn("GOFLAGS", env)
            self.assertNotIn("GOCACHEPROG", env)
            self.assertEqual(env["GOTOOLCHAIN"], "local")
            self.assertEqual(env["GOPROXY"], "off")
            self.assertEqual(env["GOENV"], "off")
            self.assertEqual(env["CGO_ENABLED"], "0")
            self.assertEqual(env["GOTELEMETRY"], "off")

    def test_manifest_unknown_fields_paths_and_exports_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root/"core.go").write_text("package p\nfunc F(x int32) int32 {return x}\n")
            base = {"schema_version":1,"name":"project","language":"go","sources":["core.go"],"functions":[{"name":"F","export":"f"}]}
            for change in ({"hooks":[]}, {"sources":["../core.go"]}, {"functions":[{"name":"F","export":"antirea_bad"}]}, {"schema_version":True}):
                path=root/"project.json"; path.write_text(json.dumps({**base,**change}))
                with self.assertRaises(ValueError): inspect_project(path)

    def test_build_rejects_source_outside_workspace_before_tools(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); workspace=root/"workspace"; workspace.mkdir()
            with self.assertRaisesRegex(GoFrontendError, "within"):
                build_project(root/"project.json",workspace/".runs/build",workspace_root=workspace)

    def test_existing_output_and_invalid_verification_counts(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); out=root/".runs/existing"; out.mkdir(parents=True)
            with self.assertRaises(GoFrontendError): build_project(root/"project.json",out,workspace_root=root)
            for count in (0,65537,True):
                with self.assertRaises(GoFrontendError): verify_build(root/".runs/report.json",root/".runs/new",workspace_root=root,random_cases=count)


_ROOT = Path(__file__).resolve().parents[1]
_CLANG = _ROOT / ".tools/clang+llvm-22.1.0-x86_64-pc-windows-msvc/bin/clang.exe"
_OPT = _CLANG.with_name("opt.exe")
_KOPT = _ROOT / ".tools/kagura-build/bin/kagura-opt.exe"


@unittest.skipUnless(_CLANG.is_file() and _OPT.is_file() and _KOPT.is_file(), "pinned local LLVM/Kagura required")
class CompiledLoopSemanticsTests(unittest.TestCase):
    def run_compiler(self, argv, source):
        completed = subprocess.run(list(map(str, argv)), input=source, text=True, capture_output=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return completed.stdout

    def pipeline(self, source, extra_flags=()):
        raw = self.run_compiler([_CLANG, "-std=c11", "-O0", "-Xclang", "-disable-O0-optnone", "-fno-inline",
                                 *extra_flags, "-S", "-emit-llvm", "-x", "c", "-", "-o", "-"], source)
        canonical = self.run_compiler([_OPT, "-passes=mem2reg", "-S", "-", "-o", "-"], raw)
        optimized = self.run_compiler([_KOPT, "-O1", "-S", "-", "-o", "-"], canonical)
        return raw, optimized

    def test_pinned_optimization_preserves_possible_go_nontermination(self):
        # For odd uint32 x, repeated +=2 cannot reach zero. No target execution
        # is needed here: inspect the compiled loop, not a claimed timeout win.
        variable = value(typ="uint32")
        loop = {"kind": "for", "init": {"kind": "empty"}, "post": {"kind": "empty"},
                "condition": {"kind": "binary", "type": "bool", "op": "!=", "left": variable, "right": constant(0, "uint32")},
                "body": {"kind": "assign", "id": "v0", "type": "uint32", "op": "+=", "value": constant(2, "uint32")}}
        metadata = {"name": "SpinOdd", "parameters": [{"id": "v0", "name": "x", "type": "uint32"}],
                    "return_type": "uint32", "locals": [{"id": "v0", "name": "x", "type": "uint32"}], "calls": [],
                    "body": {"kind": "block", "body": [loop, {"kind": "return", "value": constant(42, "uint32")}]}}
        generated = Emitter(metadata, {"SpinOdd": "spin_odd"}, {"SpinOdd": metadata}).emit()[1]
        prelude = "typedef unsigned int uint32_t; typedef unsigned long long uint64_t;\n#define UINT64_C(x) x##ULL\n"
        source = prelude + generated
        raw, optimized = self.pipeline(source)
        self.assertNotIn("llvm.loop.mustprogress", raw)
        body = re.search(r"(?ms)^define[^\n]*@spin_odd[^\n]*\{\n(.*?)^\}", optimized).group(1)
        self.assertIn("br i1", body)
        self.assertIn("4294967294", body)
        self.assertIn("ret i32 42", body)
        # Characterize the regression under the same pinned pipeline: the old
        # emission drops the loop; a scoped compiler flag would also preserve it.
        old = re.sub(r"for \(;;\) \{\nif \(!\((.*)\)\) break;", r"while (\1) {", source)
        self.assertNotEqual(source, old)
        old_raw, old_optimized = self.pipeline(old)
        self.assertIn("llvm.loop.mustprogress", old_raw)
        old_body = re.search(r"(?ms)^define[^\n]*@spin_odd[^\n]*\{\n(.*?)^\}", old_optimized).group(1)
        self.assertNotIn("br ", old_body)
        flag_raw, flag_optimized = self.pipeline(old, ["-fno-finite-loops"])
        self.assertNotIn("llvm.loop.mustprogress", flag_raw)
        self.assertIn("br i1", re.search(r"(?ms)^define[^\n]*@spin_odd[^\n]*\{\n(.*?)^\}", flag_optimized).group(1))


@unittest.skipUnless(os.environ.get("ANTIREA_RUN_GO_LOOP_TESTS") == "1", "opt-in actual Go/native/protected bounded loop regression")
class ActualLoopSemanticsTests(unittest.TestCase):
    def test_original_and_native_loop_control(self):
        root = Path(__file__).resolve().parents[1]
        output = root / ".runs" / ("go-loop-semantics-" + uuid.uuid4().hex[:12])
        fixture = output / "fixture"
        fixture.mkdir(parents=True)
        source = """package owned
func SpinOdd(x uint32) uint32 { for x != 0 { x += 2 }; return 42 }
func Continue(x uint32) uint32 {
    total := uint32(0)
    for i := uint32(0); i < 4; i++ { if i == x { continue }; total += i }
    return total + 7*x
}
func Inactive(x uint32) uint32 {
    if false { for x != 0 { x += 2 } }
    for false { x++ }
    return x*7 + 3
}
"""
        (fixture / "loops.go").write_text(source, encoding="utf-8")
        selectors = [{"name": n, "export": e} for n, e in
                     (("SpinOdd", "spin_odd"), ("Continue", "continue_post"), ("Inactive", "inactive"))]
        project = fixture / "project.json"
        project.write_text(json.dumps({"schema_version": 1, "name": "loop-semantics", "language": "go",
            "sources": ["loops.go"], "functions": selectors}), encoding="utf-8")
        evidence = {"status": "failed", "kind": "owned_loop_semantics_regression", "commands": [], "observations": [],
            "limitations": ["Timeout is bounded nonreturn observation, not proof of infinite execution or a general functional pass.",
                            "Only the owned regression fixture is tested; no attack or performance evaluation."]}
        try:
            build = build_project(project, output / "build", workspace_root=root, seed=1739)
            evidence["build_report"] = str(output / "build/report.json")
            self.assertEqual(build["status"], "artifact_created_unvalidated", build.get("error"))
            evidence["artifacts"] = build["artifacts"]
            # Independent launcher adds only a flushed entry marker around the
            # original Go function body, making nonreturn observations explicit.
            probe = output / "go-probe"
            probe.mkdir()
            original = probe / "original.go"
            original.write_text(source.replace("package owned", "package main", 1), encoding="utf-8")
            main = probe / "main.go"
            main.write_text('package main\nimport ("fmt"; "os"; "strconv")\n'
                'func main() { n, e := strconv.ParseUint(os.Args[2],10,32); if e!=nil { panic(e) }; '
                'fmt.Println("CALL_ENTERED"); x:=uint32(n); switch os.Args[1] { '
                'case "spin_odd": fmt.Println(SpinOdd(x)); case "continue_post": fmt.Println(Continue(x)); '
                'case "inactive": fmt.Println(Inactive(x)); default: panic("unknown") } }\n', encoding="utf-8")
            compiler = build["project"]["compiler"]
            stop = root / ".runs/defense-loop/STOP"
            executable = probe / "original.exe"
            _run([compiler["go"], "build", "-trimpath", "-buildvcs=false", "-o", executable, original, main],
                 output, evidence, stop, compiler)
            sha = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
            evidence["original_probe"] = {"path": str(executable), "sha256": sha(executable),
                "source_sha256": sha(original), "launcher_sha256": sha(main)}
            native_probe = ('import ctypes,sys; f=getattr(ctypes.CDLL(sys.argv[1],winmode=0x1100),sys.argv[2]); '
                'f.argtypes=[ctypes.c_uint32]; f.restype=ctypes.c_uint32; '
                'print("CALL_ENTERED",flush=True); print(f(int(sys.argv[3])),flush=True)')
            cases = [("spin_odd", 0, 42), ("spin_odd", 4294967294, 42)]
            for x in (0, 1, 2, 3, 4, 4294967295):
                cases += [("continue_post", x, ((6-x if x < 4 else 6) + 7*x) & 0xffffffff),
                          ("inactive", x, (7*x+3) & 0xffffffff)]
            # The last case must not return during the observation window.
            cases.append(("spin_odd", 1, None))
            for arm in ("original_go", "baseline", "protected"):
                path = executable if arm == "original_go" else Path(build["artifacts"][arm]["path"])
                pinned = sha(path)
                if arm != "original_go":
                    self.assertEqual(pinned, build["artifacts"][arm]["sha256"])
                for export, x, expected in cases:
                    argv = [str(executable), export, str(x)] if arm == "original_go" else [
                        sys.executable, "-I", "-S", "-c", native_probe, str(path), export, str(x)]
                    result = run_logged(argv, output, output / "logs" / f"probe-{len(evidence['observations']):03d}",
                                        timeout=1 if expected is None else 10, cancel_file=stop)
                    evidence["commands"].append(result)
                    lines = Path(result["stdout"]).read_text(encoding="utf-8-sig").splitlines()
                    observation = {"arm": arm, "export": export, "input": x, "expected": expected,
                                   "stdout": lines, "process": result,
                                   "kind": "bounded_nonreturn" if expected is None else "finite_return"}
                    evidence["observations"].append(observation)
                    self.assertFalse(result["cancelled"])
                    self.assertEqual(result["cleanup"].get("status"), "assigned_job_empty")
                    self.assertTrue(result["cleanup"].get("parent_exit_confirmed"))
                    self.assertTrue(result["cleanup"].get("job_handle_closed"))
                    if expected is None:
                        self.assertTrue(result["timed_out"])
                        self.assertEqual(lines, ["CALL_ENTERED"])
                    else:
                        self.assertFalse(result["timed_out"])
                        self.assertEqual(result["returncode"], 0)
                        self.assertEqual(lines, ["CALL_ENTERED", str(expected)])
                self.assertEqual(sha(path), pinned)
            evidence["status"] = "regression_expectations_observed"
        finally:
            (output / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
            print("Go loop regression evidence: " + str(output / "evidence.json"), flush=True)


@unittest.skipUnless(os.environ.get("ANTIREA_RUN_GO_PARSER_TESTS") == "1", "opt-in installed Go parser/typechecker tests")
class ActualParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.output = cls.root / ".runs" / ("go-parser-tests-" + uuid.uuid4().hex[:12])
        cls.output.mkdir()
        cls.compiler, cls.report = _compiler(), {"commands": [], "target_executed": False, "cases": []}
        cls.stop = cls.root / ".runs/defense-loop/STOP"
        cls.helper = cls.output / "inspect.exe"
        _run([cls.compiler["go"], "build", "-trimpath", "-buildvcs=false", "-o", cls.helper, cls.compiler["helper"]],
             cls.output, cls.report, cls.stop, cls.compiler)

    @classmethod
    def tearDownClass(cls):
        with (cls.output / "report.json").open("x", encoding="utf-8") as stream:
            json.dump(cls.report, stream, indent=2)

    def parse(self, text, *, rejected=False):
        path = self.output / ("case-" + str(len(self.report["cases"])) + ".go")
        path.write_text(text, encoding="utf-8")
        entry = {"path": str(path), "expected": "rejected" if rejected else "accepted"}
        self.report["cases"].append(entry)
        try:
            parsed = json.loads(_run([self.helper, path], self.output, self.report, self.stop, self.compiler))
            entry["actual"] = "accepted"
        except GoFrontendError:
            entry["actual"] = "rejected"
            if rejected:
                return None
            raise
        if rejected:
            self.fail("Unsupported source was accepted by trusted parser")
        self.assertFalse(parsed["target_executed"])
        return parsed

    def test_arbitrary_function_names_helpers_and_comparisons(self):
        parsed = self.parse("package p\nfunc helper(x uint32) uint32 { return x*7 }\nfunc Different(x int32) int32 { if x < 0 && x != -1 { return int32(helper(uint32(x))) }; return x }\n")
        selected, symbols, _ = resolve_closure(parsed, [{"name":"Different","export":"another_export"}])
        for method in selected.values():
            Emitter(method, symbols, selected).emit()
        self.assertEqual(set(selected), {"helper","Different"})

    def test_zero_argument_constant_function_has_empty_lists(self):
        parsed=self.parse("package p\nfunc F() int32 { return -7 }\n")
        selected,symbols,_=resolve_closure(parsed,[{"name":"F","export":"f"}])
        self.assertEqual(selected["F"]["locals"],[])
        self.assertEqual(selected["F"]["parameters"],[])
        self.assertIn("f(void)",Emitter(selected["F"],symbols,selected).emit()[0])

    def test_typed_locals_shadowing_zero_initialization_and_loop_break(self):
        parsed = self.parse("package p\nfunc F(a int32) int32 { var z int32; for i:=int32(0); i<4; i++ { if i==2 { break }; a:=i+1; z+=a }; return z+a }\n")
        selected, symbols, _ = resolve_closure(parsed, [{"name":"F","export":"f"}])
        code = Emitter(selected["F"], symbols, selected).emit()[1]
        self.assertIn("goto break_1",code)
        self.assertGreaterEqual(len(selected["F"]["locals"]),4)

    def test_unsigned_shift_is_accepted_but_signed_runtime_count_rejected(self):
        parsed = self.parse("package p\nfunc F(a int64,b uint64) int64 { return a>>b }\n")
        selected,symbols,_=resolve_closure(parsed,[{"name":"F","export":"f"}])
        self.assertIn(">= 64",Emitter(selected["F"],symbols,selected).emit()[1])
        parsed=self.parse("package p\nfunc F(a int64,b int64) int64 { return a>>b }\n")
        selected,symbols,_=resolve_closure(parsed,[{"name":"F","export":"f"}])
        with self.assertRaisesRegex(GoFrontendError,"may panic"):
            Emitter(selected["F"],symbols,selected).emit()

    def test_import_state_initializers_and_directives_rejected(self):
        sources = [
            'package p\nimport "fmt"\nfunc F(a int32) int32 { fmt.Println(a); return a }',
            'package p\nvar state int32\nfunc F(a int32) int32 { return a+state }',
            'package p\nfunc init() {}\nfunc F(a int32) int32 { return a }',
            '//go:generate arbitrary\npackage p\nfunc F(a int32) int32 { return a }',
            'package p\n//go:noinline\nfunc F(a int32) int32 { return a }',
        ]
        for text in sources:
            with self.subTest(text=text): self.parse(text,rejected=True)

    def test_machine_int_division_and_objects_rejected(self):
        sources = [
            'package p\nfunc F(a int) int { return a+1 }',
            'package p\nfunc F(a int32,b int32) int32 { return a/b }',
            'package p\nfunc F(a int32,b int32) int32 { return a%b }',
            'package p\nfunc F(a *int32) int32 { return *a }',
            'package p\nfunc F(a int32) int32 { x:=[1]int32{a}; return x[0] }',
            'package p\nfunc F(a int32) int32 { panic(a) }',
        ]
        for text in sources:
            with self.subTest(text=text): self.parse(text,rejected=True)

    def test_multiple_assignments_returns_and_range_rejected(self):
        sources=[
            'package p\nfunc F(a int32,b int32) int32 { a,b=b,a; return a }',
            'package p\nfunc F(a int32) (int32,int32) { return a,a }',
            'package p\nfunc F(a int32) int32 { for range 3 { a++ }; return a }',
            'package p\nfunc F(a int32) int32 { defer F(a); return a }',
        ]
        for text in sources:
            with self.subTest(text=text): self.parse(text,rejected=True)

    def test_typechecker_rejects_invalid_return_overflow_and_missing_identifier(self):
        for text in ('package p\nfunc F(a int32) int32 { return int64(a) }',
                     'package p\nfunc F(a int32) int32 { return 2147483648 }',
                     'package p\nfunc F(a int32) int32 { return missing }'):
            with self.subTest(text=text): self.parse(text,rejected=True)


if __name__ == "__main__":
    unittest.main()
