"""Owned Go fixed-width integer source -> typed AST -> C -> native protection.

The trusted parser/typechecker runs during build; target code runs only during
explicit reference validation. This is a bounded frontend, not whole Go support.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

from . import native_build
from .dotnet_frontend import _write, _hash, _mask, reference_cases
from .process import run_logged


class GoFrontendError(ValueError):
    pass


TYPES = {"int32": (32, "int32_t", "i32", "Int32"), "uint32": (32, "uint32_t", "u32", "UInt32"),
         "int64": (64, "int64_t", "i64", "Int64"), "uint64": (64, "uint64_t", "u64", "UInt64")}
LIMITATIONS = [
    "Experimental fixed-width int32/uint32/int64/uint64 functions and acyclic owned helper closure, not whole Go.",
    "No imports, package variables/init, methods, generics, pointers, objects, strings, arrays, slices, maps, interfaces or concurrency.",
    "Runtime division/remainder and dynamically signed shift counts are rejected instead of changing Go panic semantics.",
    "No machine-sized int/uint, multiple assignment/results, switch/range, goto, defer or compiler/build directives.",
    "All supplied functions must fit the typed subset; only selected roots and their direct helper closure are emitted.",
    "Only the native DLL is a deployment candidate; source/C/IR/reference executables remain private evidence.",
    "No automatic Go call-site rewriting; C-ABI integration is separate from direct algorithm protection.",
    "Windows x64 only; sampled original-runtime equivalence is not a whole-language semantic proof or defense evaluation.",
]


def _tree_digest(home):
    """Compact pin of the distribution's source inputs, including embedded files."""
    digest = hashlib.sha256()
    files = []
    for relative in ("src", "pkg/include"):
        directory = home / relative
        if not directory.is_dir():
            raise GoFrontendError("Incomplete portable Go source/include tree")
        for directory_name, subdirs, names in os.walk(directory, followlinks=False):
            for name in subdirs:
                native_build._no_links(Path(directory_name) / name)
            files.extend(native_build._no_links(Path(directory_name) / name) for name in names)
    if len(files) > 20000 or sum(p.stat().st_size for p in files) > 512 * 1024 * 1024:
        raise GoFrontendError("Go source inventory exceeds 20,000 files / 512 MiB")
    for path in sorted(files):
        if not path.is_file():
            raise GoFrontendError("Nonregular Go compiler input")
        digest.update(path.relative_to(home).as_posix().encode() + b"\0" + bytes.fromhex(_hash(path)))
    return {"sha256": digest.hexdigest(), "files": len(files), "bytes": sum(p.stat().st_size for p in files)}


def _compiler():
    repo = Path(__file__).resolve().parents[1]
    config_path = native_build._no_links(repo / ".tools/go-toolchain.json")
    if not config_path.is_file():
        raise GoFrontendError("Portable Go is not configured; no downloads are performed")
    config = native_build._read_json(config_path)
    if type(config.get("schema_version")) is not int or config["schema_version"] != 1:
        raise GoFrontendError("Go toolchain schema_version must be 1")
    home = native_build._no_links(Path(config["go_root"]))
    go = native_build._no_links(Path(config["go"]))
    if not home.is_relative_to(repo / ".tools") or go != home / "bin/go.exe":
        raise GoFrontendError("Portable Go must be under repository/.tools with its own bin/go.exe")
    helper = repo / "tools/go_frontend/main.go"
    tools = sorted((home / "pkg/tool/windows_amd64").glob("*.exe"))
    if not tools or not (home / "pkg/tool/windows_amd64/compile.exe").is_file():
        raise GoFrontendError("Portable Go compiler tools missing")
    inputs = [config_path, go, home / "VERSION", home / "go.env", *tools, helper,
              Path(__file__).resolve(), Path(__file__).with_name("dotnet_frontend.py")]
    hashes = {str(native_build._no_links(p)): _hash(p) for p in inputs}
    return {"go": str(go), "go_root": str(home), "version": config.get("version"), "helper": str(helper),
            "input_hashes": hashes, "distribution": _tree_digest(home)}


def inspect_project(project_path: Path) -> dict:
    path = native_build._no_links(Path(project_path))
    if "rea-analysis-reports" in {p.casefold() for p in path.parts}:
        raise GoFrontendError("Incoming reports cannot be source projects")
    data = native_build._read_json(path)
    if set(data) != {"schema_version", "name", "language", "sources", "functions"}:
        raise GoFrontendError("Expected exactly schema_version, name, language, sources and functions")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1 or data["language"] != "go":
        raise GoFrontendError("Expected schema_version 1 and language go")
    if not isinstance(data["name"], str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", data["name"]):
        raise GoFrontendError("Invalid project name")
    if not isinstance(data["sources"], list) or not 1 <= len(data["sources"]) <= 32:
        raise GoFrontendError("sources must contain 1..32 explicit .go source paths")
    sources = [native_build._relative(path.parent, p) for p in data["sources"]]
    if len(set(sources)) != len(sources) or any(p.suffix != ".go" or p.name.endswith("_test.go") for p in sources):
        raise GoFrontendError("Only unique non-test .go source files accepted")
    selectors = data["functions"]
    if not isinstance(selectors, list) or not 1 <= len(selectors) <= 16:
        raise GoFrontendError("functions must contain 1..16 explicit selectors")
    names, exports = set(), set()
    for selector in selectors:
        if not isinstance(selector, dict) or set(selector) != {"name", "export"}:
            raise GoFrontendError("Each function selector needs name and export")
        if any(not isinstance(selector[k], str) or not native_build.SYMBOL.fullmatch(selector[k]) for k in selector):
            raise GoFrontendError("Function/export names must be ordinary ASCII identifiers")
        if selector["export"].startswith(("antirea_", "kagura_", "go_owned_")):
            raise GoFrontendError("Reserved export prefix")
        if selector["name"] in names or selector["export"] in exports:
            raise GoFrontendError("Duplicate function/export")
        names.add(selector["name"]); exports.add(selector["export"])
    compiler = _compiler()
    return {"schema_version": 1, "name": data["name"], "language": "go", "project_path": str(path),
            "project_root": str(path.parent), "sources": list(map(str, sources)), "source_files": list(map(str, sources)),
            "selectors": selectors, "functions": [m["export"] for m in selectors],
            "exported_functions": [m["export"] for m in selectors],
            "input_hashes": native_build._snapshot([path.parent], [path]), "compiler": compiler,
            "compiler_inputs": compiler["input_hashes"], "compiler_inventory_sha256": compiler["distribution"]["sha256"],
            "route_status": "available", "blockers": [], "experimental": True, "target": native_build.TARGET,
            "artifact": "shared_library", "target_executed": False, "typecheck_status": "deferred_to_build",
            "limitations": list(LIMITATIONS)}


def resolve_closure(metadata, selectors):
    methods = {m["name"]: m for m in metadata["methods"]}
    if len(methods) != len(metadata["methods"]):
        raise GoFrontendError("Duplicate typed function")
    symbols = {s["name"]: s["export"] for s in selectors}
    roots, active, selected = set(symbols), set(), {}
    def visit(name):
        if name in active:
            raise GoFrontendError("Recursive helper calls unsupported")
        if name in selected:
            return
        if name not in methods:
            raise GoFrontendError("Missing owned helper/root: " + name)
        active.add(name)
        for called in methods[name]["calls"]:
            visit(called)
        active.remove(name)
        symbols.setdefault(name, "go_owned_" + hashlib.sha256(name.encode()).hexdigest()[:16])
        selected[name] = methods[name]
    for name in list(symbols):
        visit(name)
    return selected, symbols, roots


class Emitter:
    def __init__(self, method, symbols, methods):
        self.method, self.symbols, self.methods = method, symbols, methods
        self.counter = 0

    @staticmethod
    def clipped(value, typ):
        if typ == "bool":
            return f"(!!({value}))"
        if typ not in TYPES:
            raise GoFrontendError("Unsupported expression type: " + typ)
        return f"(({value}) & {_mask(TYPES[typ][0])})"

    def binary(self, op, left, right, operand_type, result_type, right_node=None):
        if op in ("&&", "||") and operand_type == "bool":
            return f"(({left}) {op} ({right}))"
        if op in ("==", "!=", "<", ">", "<=", ">="):
            if operand_type in TYPES and operand_type.startswith("int") and op not in ("==", "!="):
                sign = f"UINT64_C({1 << (TYPES[operand_type][0]-1)})"
                left, right = f"(({left}) ^ {sign})", f"(({right}) ^ {sign})"
            return f"(({left}) {op} ({right}))"
        if operand_type not in TYPES:
            raise GoFrontendError("Non-integer arithmetic")
        width = TYPES[operand_type][0]
        if op in ("<<", ">>"):
            typ = right_node["type"] if right_node else ""
            constant = right_node and right_node["kind"] == "constant"
            if constant:
                value = int(right_node["value"])
                if not 0 <= value <= (1 << 64)-1:
                    raise GoFrontendError("Shift count outside supported unsigned 64-bit range")
            elif typ not in ("uint32", "uint64"):
                raise GoFrontendError("Dynamic signed shift count may panic; use checked unsigned count")
            if op == ">>" and operand_type.startswith("int"):
                sign = f"UINT64_C({1 << (width-1)})"
                # Unsigned bias formula: no C signed overflow/right-shift assumptions.
                shifted = f"(((({left}) ^ {sign}) >> ({right})) - ({sign} >> ({right})))"
                large = f"(UINT64_C(0) - (({left}) >> {width-1}))"
            else:
                shifted, large = f"(({left}) {op} ({right}))", "UINT64_C(0)"
            return self.clipped(f"(({right}) >= {width} ? ({large}) : ({shifted}))", operand_type)
        if op == "&^":
            value = f"(({left}) & ~({right}))"
        elif op in ("+", "-", "*", "&", "|", "^"):
            value = f"(({left}) {op} ({right}))"
        else:
            raise GoFrontendError("Unsupported binary operation: " + op)
        return self.clipped(value, result_type)

    def expr(self, node):
        kind, typ = node["kind"], node["type"]
        if kind == "constant":
            if typ == "bool":
                return "UINT64_C(1)" if node["value"] else "UINT64_C(0)"
            value = int(node["value"])
            if typ.startswith("untyped"):
                if not -(1 << 63) <= value <= (1 << 64)-1:
                    raise GoFrontendError("Untyped constant exceeds supported integer range")
                width = 64
            else:
                width = TYPES[typ][0]
            return f"UINT64_C({value & ((1 << width)-1)})"
        if kind == "variable":
            return node["id"]
        if kind == "unary":
            value = self.expr(node["value"])
            if node["op"] == "!":
                return f"(!({value}))"
            if node["op"] == "+":
                return value
            if node["op"] in ("-", "^"):
                return self.clipped(f"UINT64_C(0) - ({value})" if node["op"] == "-" else f"~({value})", typ)
            raise GoFrontendError("Unsupported unary operator")
        if kind == "binary":
            return self.binary(node["op"], self.expr(node["left"]), self.expr(node["right"]),
                               node["left"]["type"], typ, node["right"])
        if kind == "convert":
            value, source = self.expr(node["value"]), node["value"]["type"]
            if source not in TYPES or typ not in TYPES:
                raise GoFrontendError("Unsupported conversion types")
            sw, tw = TYPES[source][0], TYPES[typ][0]
            if tw > sw and source.startswith("int"):
                sign = f"UINT64_C({1 << (sw-1)})"
                value = f"((({value}) ^ {sign}) - {sign})"
            return self.clipped(value, typ)
        if kind == "call":
            target = self.methods[node["name"]]
            args = [f"({TYPES[p['type']][1]})({self.expr(a)})" for p, a in zip(target["parameters"], node["args"])]
            if len(args) != len(node["args"]) or len(args) != len(target["parameters"]):
                raise GoFrontendError("Owned call arity mismatch")
            return self.clipped(f"(uint64_t){self.symbols[node['name']]}({', '.join(args)})", typ)
        raise GoFrontendError("Unsupported typed expression: " + kind)

    def stmt(self, node, loop=None):
        kind = node["kind"]
        if kind == "empty":
            return []
        if kind == "block":
            return ["{"] + [line for child in node["body"] for line in self.stmt(child, loop)] + ["}"]
        if kind == "assign":
            value = self.expr(node["value"])
            if node["op"] not in ("=", ":="):
                value = self.binary(node["op"][:-1], node["id"], value, node["type"], node["type"], node["value"])
            return [f"{node['id']} = {self.clipped(value, node['type'])};"]
        if kind == "incdec":
            value = self.binary("+" if node["op"] == "++" else "-", node["id"], "UINT64_C(1)", node["type"], node["type"])
            return [f"{node['id']} = {value};"]
        if kind == "return":
            return [f"return ({TYPES[self.method['return_type']][1]})({self.expr(node['value'])});"]
        if kind == "expression":
            return [f"(void)({self.expr(node['value'])});"]
        if kind == "if":
            return ["{"] + self.stmt(node["init"], loop) + [f"if ({self.expr(node['condition'])}) {{"] + self.stmt(node["then"], loop) + ["} else {"] + self.stmt(node["else"], loop) + ["}", "}"]
        if kind == "for":
            self.counter += 1
            current = (f"continue_{self.counter}", f"break_{self.counter}")
            condition = self.expr(node["condition"]) if node["condition"] else "1"
            # Go does not promise that a loop eventually terminates. A C11
            # dynamic-condition loop can acquire llvm.loop.mustprogress and
            # disappear during optimization even when Go would loop forever.
            # A constant control expression with an explicit exit preserves
            # that behavior without adding volatile state or observable work.
            return ["{"] + self.stmt(node["init"], loop) + ["for (;;) {", f"if (!({condition})) break;"] + self.stmt(node["body"], current) + [current[0] + ":;"] + self.stmt(node["post"], current) + ["}", current[1] + ":;", "}"]
        if kind in ("break", "continue"):
            if loop is None:
                raise GoFrontendError("Loop control outside a loop")
            return ["goto " + loop[0 if kind == "continue" else 1] + ";"]
        raise GoFrontendError("Unsupported typed statement: " + kind)

    def emit(self):
        method = self.method
        parameters = ", ".join(f"{TYPES[p['type']][1]} p{i}" for i, p in enumerate(method["parameters"])) or "void"
        signature = f"__declspec(noinline) {TYPES[method['return_type']][1]} {self.symbols[method['name']]}({parameters})"
        lines = [signature + " {"]
        for local in method["locals"]:
            lines.append(f"uint64_t {local['id']} = UINT64_C(0);")
        for i, param in enumerate(method["parameters"]):
            lines.append(f"{param['id']} = {self.clipped(f'(uint64_t)p{i}', param['type'])};")
        lines += self.stmt(method["body"]) + ["}"]
        return signature + ";", "\n".join(lines)


def _environment(compiler, output):
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GO") and k.upper() != "CGO_ENABLED"}
    cache = output / "go-private"
    for name in ("cache", "path", "mod", "tmp"):
        (cache / name).mkdir(parents=True, exist_ok=True)
    env.update(GOROOT=compiler["go_root"], GOENV="off", GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off", GOTELEMETRY="off",
        GOWORK="off", GO111MODULE="off", CGO_ENABLED="0", GOOS="windows", GOARCH="amd64",
        GOCACHE=str(cache / "cache"), GOPATH=str(cache / "path"), GOMODCACHE=str(cache / "mod"), GOTMPDIR=str(cache / "tmp"))
    return env


def _run(argv, output, report, stop, compiler, *, stdin=None, timeout=180):
    result = run_logged(list(map(str, argv)), output, output / "logs" / f"{len(report['commands'])+1:03d}",
        env=_environment(compiler, output), timeout=timeout, stdin=stdin, cancel_file=stop)
    report["commands"].append(result)
    if result.get("returncode") != 0 or result.get("timed_out") or result.get("cancelled"):
        raise GoFrontendError("Owned process failed: " + result["stderr"])
    if os.name == "nt" and (result.get("cleanup", {}).get("status") != "assigned_job_empty" or not result["cleanup"].get("job_handle_closed")):
        raise GoFrontendError("Owned process cleanup unverified")
    return Path(result["stdout"]).read_text(encoding="utf-8-sig")


def reference_source(methods, selectors):
    imports = '"bufio"; "fmt"; "os"; "strings"'
    if any(methods[s["name"]]["parameters"] for s in selectors):
        imports += '; "strconv"'
    lines = ['package main', 'import (' + imports + ')',
             'func must(err error) { if err != nil { panic(err) } }',
             'func main() { if len(os.Args)!=2 { panic("method required") }; scanner:=bufio.NewScanner(os.Stdin); out:=bufio.NewWriter(os.Stdout); defer out.Flush(); for scanner.Scan() { fields:=strings.Fields(scanner.Text()); switch os.Args[1] {']
    for selector in selectors:
        method = methods[selector["name"]]
        lines += [f'case "{selector["export"]}":', f'if len(fields)!={len(method["parameters"])} {{ panic("argument count") }}']
        for i, param in enumerate(method["parameters"]):
            parse = "ParseInt" if param["type"].startswith("int") else "ParseUint"
            lines.append(f'p{i}, err{i} := strconv.{parse}(fields[{i}], 10, {TYPES[param["type"]][0]}); must(err{i})')
        args = ", ".join(f'{p["type"]}(p{i})' for i, p in enumerate(method["parameters"]))
        lines.append(f'fmt.Fprintln(out, {selector["name"]}({args}))')
    lines += ['default: panic("unknown method") }; }; must(scanner.Err()) }']
    return "\n".join(lines) + "\n"


def _changed(inspection):
    changed = [file for file, digest in {**inspection["input_hashes"], **inspection["compiler_inputs"]}.items()
               if not Path(file).is_file() or _hash(file) != digest]
    if _tree_digest(Path(inspection["compiler"]["go_root"])) != inspection["compiler"]["distribution"]:
        changed.append("Go distribution source/include inventory")
    return changed


def build_project(project_path: Path, output_dir: Path, *, workspace_root: Path, seed: int = 1729) -> dict:
    root, source, output = map(native_build._no_links, map(Path, (workspace_root, project_path, output_dir)))
    if not source.is_relative_to(root):
        raise GoFrontendError("Source must stay within the explicit workspace")
    if output.exists() or not output.is_relative_to(root / ".runs") or output.is_relative_to(source.parent):
        raise GoFrontendError("Output must be fresh under workspace/.runs and outside the source project")
    inspection = inspect_project(source)
    stop = root / ".runs/defense-loop/STOP"
    if stop.exists():
        raise GoFrontendError("Defense STOP exists")
    output.mkdir(parents=True)
    frontend = output / "frontend"
    generated, reference = frontend / "generated", frontend / "reference"
    for directory in (generated, reference):
        directory.mkdir(parents=True)
    compiler = inspection["compiler"]
    report = {"schema_version": 1, "status": "failed", "backend": "go_typed_native", "language": "go",
        "project": inspection, "source_hashes": inspection["input_hashes"], "compiler_inputs": inspection["compiler_inputs"],
        "target_executed": False, "commands": [], "published": False, "functional_evaluation": "not_performed",
        "external_attack_evaluation": "not_performed", "limitations": list(LIMITATIONS)}
    try:
        helper = frontend / "go-inspect.exe"
        _run([compiler["go"], "build", "-trimpath", "-buildvcs=false", "-o", helper, compiler["helper"]], output, report, stop, compiler)
        metadata = json.loads(_run([helper, *inspection["sources"]], output, report, stop, compiler))
        _write(frontend / "metadata.json", metadata)
        selected, symbols, roots = resolve_closure(metadata, inspection["selectors"])
        prototypes, bodies, methods = [], [], []
        for name, method in selected.items():
            proto, body = Emitter(method, symbols, selected).emit()
            prototypes.append(proto); bodies.append(body)
            methods.append({"name": name, "export": symbols[name], "is_root": name in roots,
                "parameters": [p["type"] for p in method["parameters"]], "return_type": method["return_type"],
                "owned_calls": method["calls"], "lowering": "go_types_fixed_width_unsigned_bit_patterns"})
        _write(generated / "core.c", "#include <stdint.h>\n/* Private generated typed Go lowering. */\n" + "\n".join(prototypes + bodies))
        _write(generated / "scope.json", {"schema_version": 1, "core_roots": inspection["functions"],
            "sensitive_functions": list(symbols.values()), "public_presentation": {}, "max_functions": 64})
        _write(generated / "project.json", {"schema_version": 1, "name": inspection["name"], "language": "c",
            "sources": ["core.c"], "functions": inspection["functions"], "scope_policy": "scope.json"})
        contract = {"schema_version": 1, "library_name": inspection["name"].replace("-", "_"), "calling_convention": "cdecl", "functions": []}
        for selector in inspection["selectors"]:
            method = selected[selector["name"]]
            contract["functions"].append({"name": selector["export"], "return_type": TYPES[method["return_type"]][2],
                "parameters": [{"name": f"a{i}", "type": TYPES[p["type"]][2]} for i, p in enumerate(method["parameters"])]})
        _write(frontend / "contract.json", contract)
        # Only package declaration is rewritten. The analyzer already rejected
        # imports, initializers, global variables, directives and package state.
        originals = []
        for index, file in enumerate(inspection["sources"]):
            text = Path(file).read_text(encoding="utf-8-sig")
            text, count = re.subn(r"(?m)^(\s*package\s+)" + re.escape(metadata["package"]) + r"\b", r"\g<1>main", text, count=1)
            if count != 1:
                raise GoFrontendError("Cannot locate a normal package declaration for reference compilation")
            copied = reference / f"owned{index}.go"
            _write(copied, text); originals.append(copied)
        runner = reference / "reference_main.go"
        _write(runner, reference_source(selected, inspection["selectors"]))
        executable = reference / "reference.exe"
        _run([compiler["go"], "build", "-trimpath", "-buildvcs=false", "-o", executable, *originals, runner], output, report, stop, compiler)
        report.update(methods=methods, contract=contract, contract_path=str(frontend / "contract.json"),
            reference_executable={"path": str(executable), "sha256": _hash(executable)},
            reference_source_transform="package clause only, to main; original function bodies unchanged",
            frontend_artifact_hashes={str(p.relative_to(frontend)): _hash(p) for p in frontend.rglob("*") if p.is_file()})
        native = native_build.build_project(generated / "project.json", output / "native", workspace_root=root, seed=seed)
        report.update(status=native["status"], native_report=str(output / "native/report.json"), native_report_sha256=_hash(output / "native/report.json"),
            artifacts=native.get("artifacts"), coverage={**(native.get("coverage") or {}), "exported_functions": inspection["functions"]},
            signature_ir={"path": str(output / "native/module.before.ll"), "sha256": native.get("artifact_hashes", {}).get("module.before.ll")})
        if native.get("error"):
            report["error"] = native["error"]
    except Exception as exc:
        report.update(status="cancelled" if stop.exists() else "failed", error=type(exc).__name__ + ": " + str(exc))
    report["changed_inputs"] = _changed(inspection)
    if report["changed_inputs"]:
        report.update(status="failed", error="Source/compiler inputs changed during build")
    _write(output / "report.json", report)
    return report


def verify_build(report_path: Path, output_dir: Path, *, workspace_root: Path,
                 random_cases: int = 8192, include_protected: bool = True, timeout_seconds: int = 120) -> dict:
    root, path, output = map(native_build._no_links, map(Path, (workspace_root, report_path, output_dir)))
    if not path.is_relative_to(root / ".runs") or not output.is_relative_to(root / ".runs") or output.exists():
        raise GoFrontendError("Use private build report and fresh verification directory under workspace/.runs")
    if type(random_cases) is not int or not 1 <= random_cases <= 65536:
        raise GoFrontendError("random_cases must be 1..65536; full default is 8192")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
        raise GoFrontendError("timeout_seconds must be 1..600")
    stop = root / ".runs/defense-loop/STOP"
    if stop.exists():
        raise GoFrontendError("Defense STOP exists")
    build = native_build._read_json(path)
    if build.get("status") != "artifact_created_unvalidated" or build.get("backend") != "go_typed_native":
        raise GoFrontendError("A successful Go source build is required")
    if _changed(build["project"]):
        raise GoFrontendError("Source/compiler/runtime inputs changed since build; build again")
    watched = {str(path): _hash(path)}
    arms = ["baseline", "protected"] if include_protected else ["baseline"]
    for artifact in [build["reference_executable"], *(build["artifacts"][arm] for arm in arms)]:
        file = native_build._no_links(Path(artifact["path"]))
        if not file.is_relative_to(path.parent) or _hash(file) != artifact["sha256"]:
            raise GoFrontendError("Reference/native artifact path or hash mismatch")
        watched[str(file)] = artifact["sha256"]
    output.mkdir(parents=True)
    report = {"schema_version": 1, "status": "failed", "build_report": str(path), "build_report_sha256": _hash(path),
        "target_executed": True, "arms": arms, "commands": [], "methods": [], "validator_sha256": _hash(Path(__file__)),
        "random_cases_requested": random_cases, "timeout_seconds_per_process": timeout_seconds,
        "limitations": ["Sampled original Go runtime equivalence, not full semantic proof.",
                        "Trusted owned code executes in child processes, not a security sandbox.", "No performance or attack evaluation."]}
    try:
        for index, method in enumerate(m for m in build["methods"] if m["is_root"]):
            export = method["export"]
            args, result = method["parameters"], method["return_type"]
            cases, counts = reference_cases([TYPES[t][3] for t in args], random_cases, 3729 + index)
            _write(output / (export + ".cases.json"), cases)
            stdout = _run([build["reference_executable"]["path"], export], output, report, stop, build["project"]["compiler"],
                stdin="".join(" ".join(map(str, row)) + "\n" for row in cases), timeout=timeout_seconds)
            expected = [int(line) for line in stdout.splitlines()]
            if len(expected) != len(cases):
                raise GoFrontendError("Original Go returned wrong result count")
            entry = {"export": export, "total": len(cases), **counts, "comparisons": {}}
            report["methods"].append(entry)
            for arm in arms:
                artifact = build["artifacts"][arm]
                request, reply = output / f"{export}-{arm}.request.json", output / f"{export}-{arm}.reply.json"
                _write(request, {"library": artifact["path"], "sha256": artifact["sha256"], "export": export,
                    "parameters": [TYPES[t][3] for t in args], "return_type": TYPES[result][3], "cases": cases, "reply": str(reply)})
                bootstrap = "import sys;sys.path.insert(0,sys.argv[1]);from antirea.dotnet_frontend import _reference_native_worker;_reference_native_worker(sys.argv[2])"
                _run([sys.executable, "-I", "-S", "-c", bootstrap, str(Path(__file__).resolve().parents[1]), request],
                    output, report, stop, build["project"]["compiler"], timeout=timeout_seconds)
                actual = json.loads(reply.read_text(encoding="utf-8"))["values"]
                if len(actual) != len(expected) or any(type(v) is not int for v in actual):
                    raise GoFrontendError("Malformed native result values")
                differences = [i for i, (a, b) in enumerate(zip(expected, actual)) if a != b]
                entry["comparisons"][arm] = {"status": "failed" if differences else "passed", "total": len(cases),
                    "matched": len(cases)-len(differences), "library_sha256": artifact["sha256"],
                    "mismatches": [{"case": cases[i], "go": expected[i], "native": actual[i]} for i in differences[:10]]}
        if report["methods"] and all(c["status"] == "passed" for m in report["methods"] for c in m["comparisons"].values()):
            report["status"] = "passed"
    except Exception as exc:
        status = "cancelled" if stop.exists() else "timed_out" if report["commands"] and report["commands"][-1].get("timed_out") else "failed"
        report.update(status=status, error=type(exc).__name__ + ": " + str(exc))
    report["changed_inputs"] = [file for file, digest in watched.items() if not Path(file).is_file() or _hash(file) != digest] + _changed(build["project"])
    if report["changed_inputs"]:
        report.update(status="failed", error="Verification inputs changed")
    report["artifact_hashes"] = {str(p.relative_to(output)): _hash(p) for p in output.rglob("*") if p.is_file()}
    _write(output / "report.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("inspect", "build", "verify"))
    parser.add_argument("--project", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    if args.action != "inspect" and args.output_dir is None:
        parser.error("--output-dir required")
    if args.action == "verify" and args.report is None or args.action != "verify" and args.project is None:
        parser.error("--report or --project required")
    try:
        result = inspect_project(args.project) if args.action == "inspect" else (build_project(args.project, args.output_dir, workspace_root=args.workspace)
            if args.action == "build" else verify_build(args.report, args.output_dir, workspace_root=args.workspace))
    except (ValueError, OSError) as exc:
        result = {"status": "rejected", "error": str(exc)}
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") in ("artifact_created_unvalidated", "passed") or result.get("route_status") == "available" else 2


if __name__ == "__main__":
    raise SystemExit(main())
