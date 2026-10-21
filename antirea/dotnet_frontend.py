"""C# source -> metadata-only IL inspection -> checked-subset C -> native VM.

This frontend lowers selected scalar integer algorithms, not arbitrary .NET.
No target assembly is loaded during inspect/lower/build. Reference evaluation is
an explicit separate operation. Exceptions, calls, objects and fields fail closed.
"""
from __future__ import annotations

import argparse
import base64
from collections import deque
import ctypes
import hashlib
import itertools
import json
import os
from pathlib import Path
import random
import re
import shutil
import struct
import sys

from . import native_build
from .process import run_logged


class DotnetFrontendError(ValueError):
    pass


TYPES = {"Int32": (32, "int32_t", "i32"), "UInt32": (32, "uint32_t", "u32"),
         "Int64": (64, "int64_t", "i64"), "UInt64": (64, "uint64_t", "u64")}
LOCAL_TYPES = {**TYPES, "Boolean": (32, "uint32_t", "u32")}
TYPE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:[.+][A-Za-z_][A-Za-z0-9_]*)*\Z")
LIMITATIONS = [
    "Selected public static int/uint/long/ulong methods only; not whole C#/.NET protection.",
    "No calls, fields, objects, arrays, generics, exception handlers, checked overflow, division or remainder.",
    "Unchecked integer wrap, masked shifts and integer control flow only; unsupported IL is rejected.",
    "The selected algorithm is lowered from compiler-emitted IL, not manually translated from a fixture.",
    "Original assembly and generated C/IR are private build evidence, never part of the protected DLL.",
    "Only the native protected DLL is a candidate distributable; no managed assembly rewriting or automatic call-site replacement.",
    "Functional samples are separate from build coverage, performance acceptance and attack resistance.",
]


def _hash(path):
    return native_build._hash(Path(path))


def _write(path, value):
    path = Path(path)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(value if isinstance(value, str) else json.dumps(value, indent=2) + "\n")


def _versions(directory):
    return sorted((p for p in directory.iterdir() if p.is_dir() and re.fullmatch(r"\d+\.\d+\.\d+", p.name)),
                  key=lambda p: tuple(map(int, p.name.split(".")))) if directory.is_dir() else []


def _compiler():
    dotnet = shutil.which("dotnet")
    if not dotnet:
        raise DotnetFrontendError("Installed dotnet SDK required; no downloads are performed")
    dotnet = native_build._no_links(Path(dotnet))
    root = dotnet.parent
    sdks = _versions(root / "sdk")
    if not sdks:
        raise DotnetFrontendError("No installed SDK found beside dotnet")
    sdk = sdks[-1]
    major = sdk.name.split(".")[0]
    refs = [p for p in _versions(root / "packs/Microsoft.NETCore.App.Ref") if p.name.split(".")[0] == major]
    runtimes = [p for p in _versions(root / "shared/Microsoft.NETCore.App") if p.name.split(".")[0] == major]
    if not refs or not runtimes:
        raise DotnetFrontendError("Matching installed reference pack and runtime required")
    ref = refs[-1] / "ref" / ("net" + major + ".0")
    csc = sdk / "Roslyn/bincore/csc.dll"
    helpers = Path(__file__).resolve().parents[1] / "tools/dotnet_frontend"
    inputs = [dotnet, *sorted(csc.parent.glob("*.dll")), *sorted(csc.parent.glob("*.json")),
              *sorted(ref.glob("*.dll")), *sorted(runtimes[-1].glob("*.dll")),
              helpers / "Inspect.cs", helpers / "Runner.cs", Path(__file__).resolve()]
    if not csc.is_file() or not ref.is_dir():
        raise DotnetFrontendError("Installed compiler/reference pack is incomplete")
    hashes = {str(native_build._no_links(p)): _hash(p) for p in inputs}
    return {"dotnet": str(dotnet), "csc": str(csc), "sdk_version": sdk.name,
            "reference_dir": str(ref), "runtime_version": runtimes[-1].name,
            "framework": "net" + major + ".0", "helpers": str(helpers), "input_hashes": hashes}


def inspect_project(project_path: Path) -> dict:
    path = native_build._no_links(Path(project_path))
    if "rea-analysis-reports" in {p.casefold() for p in path.parts}:
        raise DotnetFrontendError("Incoming reports cannot be source projects")
    data = native_build._read_json(path)
    allowed = {"schema_version", "name", "language", "sources", "methods"}
    if set(data) - allowed:
        raise DotnetFrontendError("Unknown C# project fields: " + ", ".join(sorted(set(data) - allowed)))
    if type(data.get("schema_version")) is not int or data["schema_version"] != 1 or data.get("language") != "csharp":
        raise DotnetFrontendError("Expected schema_version 1 and language csharp")
    if not isinstance(data.get("name"), str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", data["name"]):
        raise DotnetFrontendError("Invalid project name")
    if not isinstance(data.get("sources"), list) or not 1 <= len(data["sources"]) <= 32:
        raise DotnetFrontendError("sources must contain 1..32 C# files")
    sources = [native_build._relative(path.parent, item) for item in data["sources"]]
    if len(set(sources)) != len(sources) or any(p.suffix.lower() != ".cs" for p in sources):
        raise DotnetFrontendError("Only unique .cs source files are accepted; no project build hooks")
    methods = data.get("methods")
    if not isinstance(methods, list) or not 1 <= len(methods) <= 16:
        raise DotnetFrontendError("methods must contain 1..16 explicit selectors")
    seen, exports = set(), set()
    for method in methods:
        if not isinstance(method, dict) or set(method) != {"type", "name", "export"}:
            raise DotnetFrontendError("Each method needs exactly type, name and export")
        if not isinstance(method["type"], str) or not TYPE_NAME.fullmatch(method["type"]):
            raise DotnetFrontendError("Unsupported declaring type name")
        if any(not isinstance(method[key], str) or not native_build.SYMBOL.fullmatch(method[key]) for key in ("name", "export")):
            raise DotnetFrontendError("Method/export names must be ordinary identifiers")
        if method["export"].startswith(("kagura_", "antirea_")):
            raise DotnetFrontendError("Reserved export prefix")
        identity = (method["type"], method["name"])
        if identity in seen or method["export"] in exports:
            raise DotnetFrontendError("Duplicate selected method/export")
        seen.add(identity)
        exports.add(method["export"])
    compiler = _compiler()
    return {"schema_version": 1, "project_path": str(path), "project_root": str(path.parent),
            "name": data["name"], "language": "csharp", "sources": list(map(str, sources)),
            "source_files": list(map(str, sources)), "functions": [m["export"] for m in methods],
            "exports": [m["export"] for m in methods], "methods": methods,
            "input_hashes": native_build._snapshot([path.parent], [path]),
            "compiler_inputs": compiler["input_hashes"], "compiler": compiler,
            "route_status": "available", "blockers": [], "experimental": True,
            "target": native_build.TARGET, "artifact": "shared_library", "limitations": list(LIMITATIONS)}


def decode_il(encoded, opcodes):
    code = base64.b64decode(encoded, validate=True)
    if not code or len(code) > 65536:
        raise DotnetFrontendError("IL body must be 1..65536 bytes")
    instructions, pc = [], 0
    formats = {"ShortInlineI": ("b", 1), "InlineI": ("i", 4), "InlineI8": ("q", 8),
               "ShortInlineVar": ("B", 1), "InlineVar": ("H", 2),
               "ShortInlineBrTarget": ("b", 1), "InlineBrTarget": ("i", 4),
               "InlineMethod": ("I", 4), "InlineField": ("I", 4), "InlineType": ("I", 4),
               "InlineTok": ("I", 4), "InlineString": ("I", 4), "InlineSig": ("I", 4),
               "ShortInlineR": ("f", 4), "InlineR": ("d", 8)}
    try:
        while pc < len(code):
            offset, token = pc, code[pc]
            pc += 1
            if token == 0xfe:
                token = 0xfe00 | code[pc]
                pc += 1
            info = opcodes.get(str(token))
            if info is None:
                raise DotnetFrontendError("Unknown IL opcode")
            kind, operand = info["operand"], None
            if kind == "InlineSwitch":
                count = struct.unpack_from("<I", code, pc)[0]
                pc += 4
                if count > 4096:
                    raise DotnetFrontendError("Switch exceeds bounded IL support")
                jumps = struct.unpack_from("<" + "i" * count, code, pc)
                pc += 4 * count
                operand = [pc + value for value in jumps]
            elif kind in formats:
                fmt, size = formats[kind]
                operand = struct.unpack_from("<" + fmt, code, pc)[0]
                pc += size
                if kind.endswith("BrTarget"):
                    operand += pc
            elif kind != "InlineNone":
                raise DotnetFrontendError("Unsupported IL operand encoding " + kind)
            instructions.append({"offset": offset, "next": pc, "name": info["name"], "operand": operand})
            if len(instructions) > 4096:
                raise DotnetFrontendError("Method exceeds 4096 instructions")
    except (IndexError, struct.error) as exc:
        raise DotnetFrontendError("Truncated IL operand") from exc
    return instructions


def _index(inst, family):
    name = inst["name"]
    if name == family or name == family + ".s":
        return inst["operand"]
    if name.startswith(family + ".") and name[-1:] in "0123":
        return int(name[-1])
    return None


CONVERSIONS = {"conv.i1": 32, "conv.u1": 32, "conv.i2": 32, "conv.u2": 32,
               "conv.i4": 32, "conv.u4": 32, "conv.i8": 64, "conv.u8": 64}
BINOPS = {"add": "+", "sub": "-", "mul": "*", "and": "&", "or": "|", "xor": "^"}
COMPARES = {"ceq", "cgt", "cgt.un", "clt", "clt.un"}
BRANCHES = {"beq", "bne.un", "bge", "bge.un", "bgt", "bgt.un", "ble", "ble.un", "blt", "blt.un"}


def analyze_method(method, instructions):
    if not method["is_static"] or not method["is_public"] or method["generic_count"] or method["exception_regions"] or method["calling_convention"] != "Default":
        raise DotnetFrontendError("Only public static non-generic methods without EH are supported")
    if method["return_type"] not in TYPES or any(t not in TYPES for t in method["parameters"]):
        raise DotnetFrontendError("Method ABI must use int, uint, long or ulong")
    if len(method["parameters"]) > 8 or len(method["locals"]) > 64 or method["max_stack"] > 64:
        raise DotnetFrontendError("Method exceeds bounded scalar ABI/locals/stack support")
    if any(t not in LOCAL_TYPES for t in method["locals"]) or (method["locals"] and not method["init_locals"]):
        raise DotnetFrontendError("Only initialized scalar integer locals are supported")
    args = [TYPES[t][0] for t in method["parameters"]]
    locals_ = [LOCAL_TYPES[t][0] for t in method["locals"]]
    by_offset = {item["offset"]: item for item in instructions}
    states, pending = {instructions[0]["offset"]: ()}, deque([instructions[0]["offset"]])
    while pending:
        offset = pending.popleft()
        inst, state = by_offset[offset], list(states[offset])
        name, operand = inst["name"], inst["operand"]
        base = name[:-2] if name.endswith(".s") else name
        successors = [inst["next"]]

        def pop():
            if not state:
                raise DotnetFrontendError("IL evaluation stack underflow")
            return state.pop()

        if name == "nop":
            pass
        elif (index := _index(inst, "ldarg")) is not None:
            if not 0 <= index < len(args):
                raise DotnetFrontendError("Argument index outside signature")
            state.append(args[index])
        elif (index := _index(inst, "starg")) is not None:
            if not 0 <= index < len(args) or pop() != args[index]:
                raise DotnetFrontendError("Argument store type mismatch")
        elif (index := _index(inst, "ldloc")) is not None:
            if not 0 <= index < len(locals_):
                raise DotnetFrontendError("Local index outside signature")
            state.append(locals_[index])
        elif (index := _index(inst, "stloc")) is not None:
            if not 0 <= index < len(locals_) or pop() != locals_[index]:
                raise DotnetFrontendError("Local store type mismatch")
        elif name.startswith("ldc.i4"):
            state.append(32)
        elif name == "ldc.i8":
            state.append(64)
        elif name == "dup":
            width = pop()
            state.extend([width, width])
        elif name == "pop":
            pop()
        elif name in BINOPS:
            rhs, lhs = pop(), pop()
            if rhs != lhs:
                raise DotnetFrontendError("Mixed-width binary IL arithmetic")
            state.append(lhs)
        elif name in {"shl", "shr", "shr.un"}:
            count, value = pop(), pop()
            if count != 32:
                raise DotnetFrontendError("Shift count must be IL int32")
            state.append(value)
        elif name in {"neg", "not"}:
            state.append(pop())
        elif name in CONVERSIONS:
            pop()
            state.append(CONVERSIONS[name])
        elif name in COMPARES or base in BRANCHES:
            if pop() != pop():
                raise DotnetFrontendError("Mixed-width comparison")
            if name in COMPARES:
                state.append(32)
            else:
                successors.append(operand)
        elif base in {"brtrue", "brfalse"}:
            pop()
            successors.append(operand)
        elif base == "br":
            successors = [operand]
        elif name == "switch":
            if pop() != 32:
                raise DotnetFrontendError("Switch operand must be int32")
            successors.extend(operand)
        elif name == "ret":
            if pop() != TYPES[method["return_type"]][0] or state:
                raise DotnetFrontendError("Return stack differs from signature")
            successors = []
        else:
            raise DotnetFrontendError(f"Unsupported IL {name} at {offset}; no semantic fallback")
        if len(state) > method["max_stack"]:
            raise DotnetFrontendError("IL exceeds declared max stack")
        for target in successors:
            if target not in by_offset:
                raise DotnetFrontendError("Branch/fallthrough is not an IL instruction boundary")
            if target in states:
                if states[target] != tuple(state):
                    raise DotnetFrontendError("Inconsistent stack types at CFG merge")
            else:
                states[target] = tuple(state)
                pending.append(target)
    if len(states) != len(instructions):
        raise DotnetFrontendError("Unreachable IL is not included in this verified subset")
    return states


def _mask(width):
    return "UINT64_C(0xffffffff)" if width == 32 else "UINT64_C(0xffffffffffffffff)"


def _comparison(name, left, right, width):
    operators = {"ceq": "==", "beq": "==", "bne": "!=", "cgt": ">", "bgt": ">", "bge": ">=", "clt": "<", "blt": "<", "ble": "<="}
    op = operators[name.replace(".un", "")]
    if name not in {"ceq", "beq", "bne.un"} and not name.endswith(".un"):
        sign = f"UINT64_C({1 << (width - 1)})"
        left, right = f"({left} ^ {sign})", f"({right} ^ {sign})"
    return f"({left} {op} {right})"


def emit_method(method, export, instructions):
    states = analyze_method(method, instructions)
    params = ", ".join(TYPES[kind][1] + f" p{i}" for i, kind in enumerate(method["parameters"])) or "void"
    lines = [f"{TYPES[method['return_type']][1]} {export}({params}) {{"]
    for i, kind in enumerate(method["parameters"]):
        lines.append(f"  uint64_t a{i} = (uint64_t)({ 'uint32_t' if TYPES[kind][0] == 32 else 'uint64_t' })p{i};")
    for i in range(len(method["locals"])):
        lines.append(f"  uint64_t l{i} = 0;")
    for i in range(max(1, method["max_stack"])):
        lines.append(f"  uint64_t s{i} = 0;")
    for inst in instructions:
        name, operand, offset = inst["name"], inst["operand"], inst["offset"]
        base = name[:-2] if name.endswith(".s") else name
        state = states[offset]
        n = len(state)
        top, lhs, rhs = f"s{n-1}", f"s{n-2}", f"s{n-1}"
        width = state[-1] if state else 32
        body = []
        if name == "nop" or name == "pop":
            pass
        elif (index := _index(inst, "ldarg")) is not None:
            body.append(f"s{n} = a{index};")
        elif (index := _index(inst, "starg")) is not None:
            body.append(f"a{index} = {top};")
        elif (index := _index(inst, "ldloc")) is not None:
            body.append(f"s{n} = l{index};")
        elif (index := _index(inst, "stloc")) is not None:
            body.append(f"l{index} = {top};")
        elif name.startswith("ldc.i4") or name == "ldc.i8":
            value = operand if operand is not None else (-1 if name == "ldc.i4.m1" else int(name.rsplit(".", 1)[1]))
            bits = 64 if name == "ldc.i8" else 32
            body.append(f"s{n} = UINT64_C({value & ((1 << bits)-1)});")
        elif name == "dup":
            body.append(f"s{n} = {top};")
        elif name in BINOPS:
            body.append(f"{lhs} = ({lhs} {BINOPS[name]} {rhs}) & {_mask(width)};")
        elif name in {"neg", "not"}:
            expression = f"(UINT64_C(0) - {top})" if name == "neg" else f"~{top}"
            body.append(f"{top} = ({expression}) & {_mask(width)};")
        elif name in {"shl", "shr", "shr.un"}:
            bits = state[-2]
            count = f"({rhs} & {bits-1}u)"
            if name == "shr":
                # Bias into the unsigned order, shift, then undo the bias.
                # Defined at count=0, no signed-C shift or shift-by-width, and
                # avoids generating LLVM funnel-shift intrinsics unsupported by VM.
                sign = f"UINT64_C({1 << (bits-1)})"
                expression = f"((({lhs} ^ {sign}) >> {count}) - ({sign} >> {count}))"
            else:
                expression = f"({lhs} {'<<' if name == 'shl' else '>>'} {count})"
            body.append(f"{lhs} = {expression} & {_mask(bits)};")
        elif name in CONVERSIONS:
            if name in {"conv.i4", "conv.u4"}:
                expression = f"{top} & {_mask(32)}"
            elif name == "conv.i8" and width == 32:
                expression = f"(({top} ^ UINT64_C(0x80000000)) - UINT64_C(0x80000000))"
            elif name in {"conv.i8", "conv.u8"}:
                expression = top
            else:
                bits = 8 if name[-1] == "1" else 16
                value = f"({top} & {((1 << bits)-1)}u)"
                expression = f"(({value} ^ {1 << (bits-1)}u) - UINT64_C({1 << (bits-1)})) & {_mask(32)}" if ".i" in name else value
            body.append(f"{top} = {expression};")
        elif name in COMPARES:
            body.append(f"{lhs} = {_comparison(name, lhs, rhs, width)};")
        elif base in BRANCHES:
            body.append(f"if {_comparison(base, lhs, rhs, width)} goto IL_{operand};")
        elif base in {"brtrue", "brfalse"}:
            body.append(f"if ({top} {'!=' if base == 'brtrue' else '=='} 0) goto IL_{operand};")
        elif name == "switch":
            body.extend(f"if ({top} == {index}u) goto IL_{target};" for index, target in enumerate(operand))
        elif base == "br":
            body.append(f"goto IL_{operand};")
        elif name == "ret":
            body.append(f"return ({TYPES[method['return_type']][1]}){top};")
        else:
            raise DotnetFrontendError("Emission missing for supported opcode " + name)
        if name != "ret" and base != "br":
            body.append(f"goto IL_{inst['next']};")
        lines.append(f"IL_{offset}: ; /* {name} */")
        lines.extend("  " + line for line in body)
    lines.append("}\n")
    return "\n".join(lines), {"instruction_count": len(instructions), "typed_cfg_nodes": len(states),
                               "supported_opcodes": sorted({i["name"] for i in instructions})}


def lower_project(project_path: Path, output_dir: Path, *, workspace_root: Path) -> dict:
    root = native_build._no_links(Path(workspace_root))
    source = native_build._no_links(Path(project_path))
    if not source.is_relative_to(root):
        raise DotnetFrontendError("Source project must be inside the explicit workspace")
    inspection = inspect_project(source)
    output = native_build._no_links(Path(output_dir))
    if output.exists() or not output.is_relative_to(root / ".runs") or output.is_relative_to(Path(inspection["project_root"])):
        raise DotnetFrontendError("Output must be fresh under workspace/.runs and outside the source project")
    stop = root / ".runs/defense-loop/STOP"
    if stop.exists():
        raise DotnetFrontendError("Defense STOP exists")
    output.mkdir(parents=True)
    compiler = inspection["compiler"]
    report = {"schema_version": 1, "status": "failed", "backend": "dotnet_il_native", "project": inspection,
              "source_hashes": inspection["input_hashes"], "compiler_inputs": inspection["compiler_inputs"],
              "commands": [], "target_executed": False, "limitations": list(LIMITATIONS)}

    def run(argv, timeout=120):
        env = os.environ.copy()
        env.update(DOTNET_CLI_TELEMETRY_OPTOUT="1", DOTNET_SKIP_FIRST_TIME_EXPERIENCE="1")
        process = run_logged(list(map(str, argv)), output, output / "logs" / f"{len(report['commands'])+1:03d}",
                             timeout=timeout, cancel_file=stop, env=env)
        report["commands"].append(process)
        clean = process.get("cleanup", {})
        if process.get("returncode") != 0 or process.get("timed_out") or process.get("cancelled"):
            raise DotnetFrontendError("Compiler/metadata helper failed: " + process["stderr"])
        if os.name == "nt" and (clean.get("status") != "assigned_job_empty" or not clean.get("job_handle_closed")):
            raise DotnetFrontendError("Compiler/helper cleanup is not verified")
        return Path(process["stdout"]).read_text(encoding="utf-8-sig")

    try:
        refs = ["-r:" + str(p) for p in sorted(Path(compiler["reference_dir"]).glob("*.dll"))]
        flags = [compiler["dotnet"], "exec", compiler["csc"], "-nologo", "-noconfig", "-nostdlib+", "-optimize+", "-deterministic+", "-checked-", "-unsafe-", "-langversion:12", *refs]
        original = output / "original.dll"
        run([*flags, "-target:library", "-out:" + str(original), *inspection["sources"]])
        runtime_config = {"runtimeOptions": {"tfm": compiler["framework"], "framework": {
            "name": "Microsoft.NETCore.App", "version": compiler["runtime_version"]}}}
        for helper in ("Inspect", "Runner"):
            run([*flags, "-target:exe", "-out:" + str(output / (helper + ".dll")), str(Path(compiler["helpers"]) / (helper + ".cs"))])
            _write(output / (helper + ".runtimeconfig.json"), runtime_config)
        metadata = json.loads(run([compiler["dotnet"], "exec", output / "Inspect.dll", original]))
        _write(output / "metadata.json", metadata)
        if any(m["name"] == ".cctor" for m in metadata["methods"]):
            raise DotnetFrontendError("Static/module initializers are unsupported observable runtime behavior")
        generated = output / "generated"
        generated.mkdir()
        bodies, method_reports, functions = [], [], []
        for selector in inspection["methods"]:
            matches = [m for m in metadata["methods"] if (m["type"], m["name"]) == (selector["type"], selector["name"])]
            if len(matches) != 1 or not matches[0]["il"]:
                raise DotnetFrontendError("Method missing/overloaded/bodyless: " + selector["type"] + "." + selector["name"])
            method = matches[0]
            instructions = decode_il(method["il"], metadata["opcodes"])
            code, evidence = emit_method(method, selector["export"], instructions)
            bodies.append(code)
            method_reports.append({"selector": selector, "metadata": method, "lowering": evidence})
            functions.append({"name": selector["export"], "return_type": TYPES[method["return_type"]][2],
                              "parameters": [{"name": f"a{i}", "type": TYPES[kind][2]} for i, kind in enumerate(method["parameters"])]})
        _write(generated / "core.c", "#include <stdint.h>\n\n/* Generated from inspected CIL; private build evidence. */\n\n" + "\n".join(bodies))
        _write(generated / "project.json", {"schema_version": 1, "name": inspection["name"], "language": "c",
                                             "sources": ["core.c"], "functions": inspection["functions"]})
        contract = {"schema_version": 1, "library_name": inspection["name"].replace("-", "_"), "functions": functions}
        _write(output / "contract.json", contract)
        report.update(status="lowered_unvalidated", original_assembly=str(original), original_sha256=_hash(original),
                      methods=method_reports, native_project=str(generated / "project.json"),
                      contract_path=str(output / "contract.json"), contract=contract)
    except Exception as exc:
        report.update(status="cancelled" if stop.exists() else "failed", error=type(exc).__name__ + ": " + str(exc))
    changed = []
    for path, digest in {**inspection["input_hashes"], **inspection["compiler_inputs"]}.items():
        if not Path(path).is_file() or _hash(path) != digest:
            changed.append(path)
    report["changed_inputs"] = changed
    if changed:
        report.update(status="failed", error="Frontend inputs changed")
    report["artifact_hashes"] = {str(p.relative_to(output)): _hash(p) for p in output.rglob("*") if p.is_file()}
    _write(output / "report.json", report)
    return report


def build_project(project_path: Path, output_dir: Path, *, workspace_root: Path, seed: int = 1729) -> dict:
    output = native_build._no_links(Path(output_dir))
    root = native_build._no_links(Path(workspace_root))
    source = native_build._no_links(Path(project_path))
    if not source.is_relative_to(root):
        raise DotnetFrontendError("Source project must be inside the explicit workspace")
    if output.exists() or not output.is_relative_to(root / ".runs") or output.is_relative_to(source.parent):
        raise DotnetFrontendError("Build output must be fresh under workspace/.runs")
    output.mkdir(parents=True)
    report = {"schema_version": 1, "status": "failed", "backend": "dotnet_il_native", "language": "csharp",
              "published": False, "functional_evaluation": "not_performed", "external_attack_evaluation": "not_performed",
              "limitations": list(LIMITATIONS)}
    try:
        frontend = lower_project(project_path, output / "frontend", workspace_root=root)
        report.update(frontend_report=str(output / "frontend/report.json"), frontend=frontend,
                      project=frontend["project"], source_hashes=frontend["source_hashes"])
        if frontend["status"] != "lowered_unvalidated":
            raise DotnetFrontendError(frontend.get("error", "IL lowering did not complete"))
        native = native_build.build_project(Path(frontend["native_project"]), output / "native", workspace_root=root, seed=seed)
        report.update(status=native["status"], native_report=str(output / "native/report.json"),
                      native_report_sha256=_hash(output / "native/report.json"),
                      artifacts=native.get("artifacts"),
                      coverage={**(native.get("coverage") or {}), "exported_functions": frontend["project"]["functions"]},
                      exported_functions=frontend["project"]["functions"], contract_path=frontend["contract_path"],
                      signature_ir={"path": str(output / "native/module.before.ll"),
                                    "sha256": native["artifact_hashes"].get("module.before.ll")})
        if native.get("error"):
            report["error"] = native["error"]
    except Exception as exc:
        report.update(status="failed", error=type(exc).__name__ + ": " + str(exc))
    _write(output / "report.json", report)
    return report


def reference_cases(parameters, count=8192, seed=1729):
    """Deterministic unique random cases plus correlated scalar edge cases."""
    rng = random.Random(seed)
    if not parameters:
        return [[]], {"random_unique_cases": 0, "edge_cases": 1}

    def value(bits, kind):
        width = TYPES[kind][0]
        bits &= (1 << width) - 1
        return bits - (1 << width) if kind.startswith("Int") and bits >= 1 << (width - 1) else bits

    randoms = set()
    while len(randoms) < count:
        randoms.add(tuple(value(rng.getrandbits(TYPES[kind][0]), kind) for kind in parameters))
    edge_values = [[value(x, kind) for x in (0, 1, 2, 7, 8, 15, 16, 31, 32, 33, 63, 64, 65,
                    -1, -2, -(1 << (TYPES[kind][0]-1)), (1 << (TYPES[kind][0]-1))-1,
                    (1 << (TYPES[kind][0]-1))+1)] for kind in parameters]
    edges = set()
    if len(parameters) <= 2:
        edges.update(itertools.product(*edge_values))
    else:
        for index in range(len(edge_values[0])):
            edges.add(tuple(values[index] for values in edge_values))
        for column, values in enumerate(edge_values):
            for item in values:
                row = [0] * len(parameters)
                row[column] = item
                edges.add(tuple(row))
    extra = edges - randoms
    return [list(row) for row in sorted(randoms | edges)], {"random_unique_cases": len(randoms), "edge_cases": len(extra)}


def _reference_native_worker(request_path):
    """Bounded by the caller's owned child process; reply is never stdout."""
    request = json.loads(Path(request_path).read_text(encoding="utf-8"))
    library = Path(request["library"])
    if _hash(library) != request["sha256"]:
        raise DotnetFrontendError("Native reference library hash mismatch")
    ctypes_types = {"Int32": ctypes.c_int32, "UInt32": ctypes.c_uint32,
                    "Int64": ctypes.c_int64, "UInt64": ctypes.c_uint64}
    dll = ctypes.CDLL(str(library))
    function = getattr(dll, request["export"])
    function.argtypes = [ctypes_types[kind] for kind in request["parameters"]]
    function.restype = ctypes_types[request["return_type"]]
    values = [int(function(*row)) for row in request["cases"]]
    if _hash(library) != request["sha256"]:
        raise DotnetFrontendError("Native reference library changed during execution")
    _write(Path(request["reply"]), {"values": values})


def verify_build(report_path: Path, output_dir: Path, *, workspace_root: Path,
                 random_cases: int = 8192, include_protected: bool = False,
                 timeout_seconds: int = 120) -> dict:
    """Explicit trusted-source execution: original CLR vs compiled native samples.

    Inspection and build do not execute the target. This separate operation does,
    in bounded owned subprocesses. It is not a sandbox or a proof of semantics.
    """
    root = native_build._no_links(Path(workspace_root))
    path = native_build._no_links(Path(report_path))
    output = native_build._no_links(Path(output_dir))
    if not path.is_relative_to(root / ".runs") or not output.is_relative_to(root / ".runs") or output.exists():
        raise DotnetFrontendError("Reference evidence must use existing build and fresh output under workspace/.runs")
    if type(random_cases) is not int or not 1 <= random_cases <= 65536:
        raise DotnetFrontendError("random_cases must be 1..65536; full fixture verification uses at least 8192")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
        raise DotnetFrontendError("timeout_seconds must be 1..600")
    stop = root / ".runs/defense-loop/STOP"
    if stop.exists():
        raise DotnetFrontendError("Defense STOP exists")
    build = native_build._read_json(path)
    if build.get("status") != "artifact_created_unvalidated" or build.get("backend") != "dotnet_il_native":
        raise DotnetFrontendError("A successful C# native build is required")
    frontend = build["frontend"]
    directory = path.parent
    watched = {str(path): _hash(path)}

    def bound(file, digest):
        file = native_build._no_links(Path(file))
        if not file.is_relative_to(directory) or not file.is_file() or _hash(file) != digest:
            raise DotnetFrontendError("Build artifact path/hash mismatch: " + str(file))
        watched[str(file)] = digest
        return file

    original = bound(frontend["original_assembly"], frontend["original_sha256"])
    frontdir = Path(build["frontend_report"]).parent
    runner = bound(frontdir / "Runner.dll", frontend["artifact_hashes"]["Runner.dll"])
    bound(frontdir / "Runner.runtimeconfig.json", frontend["artifact_hashes"]["Runner.runtimeconfig.json"])
    arms = ["baseline", "protected"] if include_protected else ["baseline"]
    libraries = {arm: bound(build["artifacts"][arm]["path"], build["artifacts"][arm]["sha256"]) for arm in arms}
    dotnet = native_build._no_links(Path(frontend["project"]["compiler"]["dotnet"]))
    if _hash(dotnet) != frontend["compiler_inputs"].get(str(dotnet)):
        raise DotnetFrontendError("Original CLR host differs from build provenance")
    runtime_dir = dotnet.parent / "shared/Microsoft.NETCore.App" / frontend["project"]["compiler"]["runtime_version"]
    runtime_inputs = {str(p): _hash(native_build._no_links(p)) for p in sorted(runtime_dir.glob("*.dll"))}
    for file, digest in runtime_inputs.items():
        if file in frontend["compiler_inputs"] and frontend["compiler_inputs"][file] != digest:
            raise DotnetFrontendError("Original CLR runtime differs from build provenance")
    watched.update(runtime_inputs)
    watched[str(dotnet)] = _hash(dotnet)
    output.mkdir(parents=True)
    report = {"schema_version": 1, "status": "failed", "build_report": str(path),
              "build_report_sha256": watched[str(path)], "original_sha256": _hash(original),
              "target_executed": True, "arms": arms, "methods": [], "commands": [],
              "validator_sha256": _hash(Path(__file__)), "runtime_inputs": runtime_inputs,
              "limitations": ["Sampled CLR equivalence only; not an exhaustive semantic proof.",
                              "Owned trusted source is executed; process ownership is not a security sandbox.",
                              "No performance gate or external attack evaluation is performed."]}

    def run(argv, label, stdin=None):
        process = run_logged(list(map(str, argv)), output, output / "logs" / label, timeout=timeout_seconds,
                             stdin=stdin, cancel_file=stop)
        report["commands"].append(process)
        cleanup = process.get("cleanup", {})
        if process.get("returncode") != 0 or process.get("timed_out") or process.get("cancelled"):
            raise DotnetFrontendError("Reference process failed: " + process["stderr"])
        if os.name == "nt" and (cleanup.get("status") != "assigned_job_empty" or not cleanup.get("job_handle_closed")):
            raise DotnetFrontendError("Reference process cleanup unverified")
        return Path(process["stdout"]).read_text(encoding="utf-8-sig")

    try:
        for index, entry in enumerate(frontend["methods"]):
            method, export = entry["metadata"], entry["selector"]["export"]
            cases, counts = reference_cases(method["parameters"], random_cases, 1729 + index)
            _write(output / (export + ".cases.json"), cases)
            stdout = run([dotnet, "exec", runner, original, str(method["token"])], export + "-clr",
                         "".join(json.dumps(list(map(str, row))) + "\n" for row in cases))
            expected = [int(line) for line in stdout.splitlines()]
            if len(expected) != len(cases):
                raise DotnetFrontendError("Original CLR returned an unexpected result count")
            result = {"export": export, "total": len(cases), **counts, "original_clr_outputs_sha256":
                      hashlib.sha256(json.dumps(expected).encode()).hexdigest(), "comparisons": {}}
            report["methods"].append(result)
            for arm, library in libraries.items():
                reply = output / (export + "-" + arm + ".reply.json")
                request = output / (export + "-" + arm + ".request.json")
                _write(request, {"library": str(library), "sha256": _hash(library), "export": export,
                                 "parameters": method["parameters"], "return_type": method["return_type"],
                                 "cases": cases, "reply": str(reply)})
                bootstrap = "import sys;sys.path.insert(0,sys.argv[1]);from antirea.dotnet_frontend import _reference_native_worker;_reference_native_worker(sys.argv[2])"
                run([sys.executable, "-I", "-S", "-c", bootstrap, str(Path(__file__).resolve().parents[1]), str(request)], export + "-" + arm)
                actual = json.loads(reply.read_text(encoding="utf-8"))["values"]
                if len(actual) != len(expected) or any(type(x) is not int for x in actual):
                    raise DotnetFrontendError("Native worker returned malformed values")
                differences = [i for i, (left, right) in enumerate(zip(expected, actual)) if left != right]
                result["comparisons"][arm] = {"status": "failed" if differences else "passed",
                    "matched": len(cases) - len(differences), "total": len(cases),
                    "mismatches": [{"case": cases[i], "clr": expected[i], "native": actual[i]} for i in differences[:10]],
                    "library_sha256": _hash(library)}
        if all(check["status"] == "passed" for item in report["methods"] for check in item["comparisons"].values()):
            report["status"] = "passed"
    except Exception as exc:
        report.update(status="cancelled" if stop.exists() else "failed", error=type(exc).__name__ + ": " + str(exc))
    report["changed_artifacts"] = [file for file, digest in watched.items() if not Path(file).is_file() or _hash(file) != digest]
    if report["changed_artifacts"]:
        report.update(status="failed", error="Reference input artifacts changed")
    report["artifact_hashes"] = {str(p.relative_to(output)): _hash(p) for p in output.rglob("*") if p.is_file()}
    _write(output / "report.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("inspect", "lower", "build", "verify"))
    parser.add_argument("--project", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--include-protected", action="store_true")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    if args.action != "inspect" and args.output_dir is None:
        parser.error("--output-dir required")
    if args.action == "verify" and args.report is None:
        parser.error("--report required for explicit verification")
    if args.action != "verify" and args.project is None:
        parser.error("--project required")
    try:
        result = verify_build(args.report, args.output_dir, workspace_root=args.workspace, include_protected=args.include_protected) if args.action == "verify" else inspect_project(args.project) if args.action == "inspect" else (
            lower_project(args.project, args.output_dir, workspace_root=args.workspace) if args.action == "lower" else
            build_project(args.project, args.output_dir, workspace_root=args.workspace))
    except (ValueError, OSError) as exc:
        result = {"status": "rejected", "error": str(exc)}
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") in {"passed", "lowered_unvalidated", "artifact_created_unvalidated"} or result.get("route_status") == "available" else 2


if __name__ == "__main__":
    raise SystemExit(main())
