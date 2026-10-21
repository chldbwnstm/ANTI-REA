"""Experimental pure-Python integer source -> diversified custom stack VM.

Compilation parses source; it never imports or executes the input. The resulting
module interprets encoded instructions, not Python code objects/marshal/exec.
This is obfuscation, not a sandbox, authenticated integrity, or proven resistance.
"""
from __future__ import annotations

import argparse
import ast
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PureWindowsPath
import random
import re
import secrets
import stat
import time
import tokenize

from . import python_runtime_hardening as _prh


FORMAT_VERSION = 2
MAX_SOURCE_BYTES = 512 * 1024
MAX_AST_NODES = 20000
LIMITATIONS = [
    "Experimental single-module pure integer/bool Python subset; not arbitrary Python applications.",
    "Only exact int/bool inputs; no objects, imports, I/O, collections, floats, async, generators or closures.",
    "No defaults, decorators, variadic/keyword-only parameters or recursive helper cycles.",
    "Selected roots and transitive owned helpers are virtualized; other module functions are not exported.",
    "Python unbounded arithmetic and exception classes are preserved in the supported subset; traceback/text/introspection differ.",
    "No execution or resource limit is imposed by the generated module; use a bounded validation subprocess.",
    "Function-local keys, VM runtime and transient decoded instructions remain available to a local analyst; no secrecy guarantee.",
    "Only the current instruction is decoded; encoded metadata/offsets are visible. Each function has its own seed-flattened dispatcher engine, but the fetch/operand decoder and operator/builtin helpers are shared and not independently obfuscated.",
    "Import-time SHA-256 covers encoded data plus codec/offset metadata, not runtime/wrapper code; not attacker authentication.",
    "Kagura native LLVM passes are not applied to this Python VM backend.",
    "Build success is not functional equivalence, performance acceptance or external attack resistance.",
    "baseline.py and manifests are private defender evidence and must not be published with protected.py.",
]
_BINARY = {ast.Add: "add", ast.Sub: "sub", ast.Mult: "mul", ast.FloorDiv: "floordiv",
           ast.Mod: "mod", ast.LShift: "lshift", ast.RShift: "rshift", ast.BitAnd: "and_",
           ast.BitOr: "or_", ast.BitXor: "xor"}
_UNARY = {ast.UAdd: "pos", ast.USub: "neg", ast.Invert: "invert", ast.Not: "not_"}
_COMPARE = {ast.Eq: "eq", ast.NotEq: "ne", ast.Lt: "lt", ast.LtE: "le", ast.Gt: "gt", ast.GtE: "ge"}
_BUILTINS = {"abs": (1, 1), "int": (1, 1), "bool": (1, 1), "min": (2, 16), "max": (2, 16)}
_OPS = ("const", "load", "store", "pop", "dup", "binary", "unary", "compare",
        "jump", "false", "true", "call", "builtin", "return", "iter", "next")


class PythonFrontendError(ValueError):
    pass


def _fail(node, message):
    raise PythonFrontendError(f"line {getattr(node, 'lineno', '?')}: {message}")


def _name(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", value) and not value.startswith(("_ar_", "__"))


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class _Compiler:
    def __init__(self, node, functions, constants):
        self.node, self.functions, self.constants = node, functions, constants
        self.parameters = [arg.arg for arg in node.args.args]
        local_names = set(self.parameters)
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                if child.id == "__debug__":
                    _fail(child, "Assignment to __debug__ is invalid Python")
                local_names.add(child.id)
        self.locals = list(self.parameters) + sorted(local_names - set(self.parameters))
        self.slots = {name: i for i, name in enumerate(self.locals)}
        self.code, self.calls, self.loops = [], set(), []

    def emit(self, opcode, *args):
        self.code.append([opcode, *args])
        return len(self.code) - 1

    def patch(self, index, target, operand=1):
        self.code[index][operand] = target

    def temp(self):
        index = len(self.locals)
        self.locals.append(f"$temporary{index}")
        return index

    def load(self, name, node):
        if name in self.slots:
            self.emit("load", self.slots[name])
        elif name in self.constants:
            self.emit("const", self.constants[name])
        else:
            _fail(node, f"Unknown value {name!r}; only locals and literal module constants are supported")

    def expr(self, node):
        if isinstance(node, ast.Constant):
            if type(node.value) not in (int, bool, type(None)):
                _fail(node, "Only integer, bool and None expression literals are supported")
            if type(node.value) is int and node.value.bit_length() > 4096:
                _fail(node, "Integer literal exceeds 4096 bits")
            self.emit("const", node.value)
        elif isinstance(node, ast.Name):
            self.load(node.id, node)
        elif isinstance(node, ast.BinOp) and type(node.op) in _BINARY:
            self.expr(node.left)
            self.expr(node.right)
            self.emit("binary", _BINARY[type(node.op)])
        elif isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY:
            self.expr(node.operand)
            self.emit("unary", _UNARY[type(node.op)])
        elif isinstance(node, ast.BoolOp):
            self.expr(node.values[0])
            exits = []
            for value in node.values[1:]:
                self.emit("dup")
                exits.append(self.emit("false" if isinstance(node.op, ast.And) else "true", None))
                self.emit("pop")
                self.expr(value)
            for index in exits:
                self.patch(index, len(self.code))
        elif isinstance(node, ast.Compare):
            if any(type(op) not in _COMPARE for op in node.ops):
                _fail(node, "Only integer equality/order comparisons are supported")
            # Hidden locals evaluate each intermediate comparator exactly once.
            left, right = self.temp(), self.temp()
            self.expr(node.left)
            self.emit("store", left)
            exits = []
            for i, (op, value) in enumerate(zip(node.ops, node.comparators)):
                self.expr(value)
                self.emit("store", right)
                self.emit("load", left)
                self.emit("load", right)
                self.emit("compare", _COMPARE[type(op)])
                if i < len(node.ops) - 1:
                    self.emit("dup")
                    exits.append(self.emit("false", None))
                    self.emit("pop")
                    self.emit("load", right)
                    self.emit("store", left)
            for index in exits:
                self.patch(index, len(self.code))
        elif isinstance(node, ast.IfExp):
            self.expr(node.test)
            branch = self.emit("false", None)
            self.expr(node.body)
            end = self.emit("jump", None)
            self.patch(branch, len(self.code))
            self.expr(node.orelse)
            self.patch(end, len(self.code))
        elif isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.keywords:
                _fail(node, "Calls require an owned helper or supported builtin name with positional arguments")
            name = node.func.id
            if name in self.slots or name in self.constants:
                _fail(node, f"Call target {name!r} is shadowed by a local/constant")
            if name in self.functions:
                if len(node.args) != len(self.functions[name].args.args):
                    _fail(node, f"Helper {name!r} requires {len(self.functions[name].args.args)} arguments")
                self.calls.add(name)
                opcode = "call"
            elif name in _BUILTINS:
                minimum, maximum = _BUILTINS[name]
                if not minimum <= len(node.args) <= maximum:
                    _fail(node, f"Builtin {name!r} requires {minimum}..{maximum} arguments")
                opcode = "builtin"
            else:
                _fail(node, f"Unsupported call {name!r}")
            for argument in node.args:
                self.expr(argument)
            self.emit(opcode, name, len(node.args))
        else:
            _fail(node, f"Unsupported expression {type(node).__name__}")

    def block(self, body):
        for node in body:
            self.statement(node)

    def statement(self, node):
        if isinstance(node, ast.Return):
            self.expr(node.value or ast.Constant(None))
            self.emit("return")
        elif isinstance(node, ast.Assign):
            if any(not isinstance(target, ast.Name) for target in node.targets):
                _fail(node, "Assignment targets must be simple local names")
            self.expr(node.value)
            for i, target in enumerate(node.targets):
                if i < len(node.targets) - 1:
                    self.emit("dup")
                self.emit("store", self.slots[target.id])
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name) and type(node.op) in _BINARY:
            self.load(node.target.id, node)
            self.expr(node.value)
            self.emit("binary", _BINARY[type(node.op)])
            self.emit("store", self.slots[node.target.id])
        elif isinstance(node, ast.If):
            self.expr(node.test)
            branch = self.emit("false", None)
            self.block(node.body)
            end = self.emit("jump", None)
            self.patch(branch, len(self.code))
            self.block(node.orelse)
            self.patch(end, len(self.code))
        elif isinstance(node, (ast.While, ast.For)):
            if isinstance(node, ast.For):
                call = node.iter
                if (not isinstance(node.target, ast.Name) or not isinstance(call, ast.Call)
                        or not isinstance(call.func, ast.Name) or call.func.id != "range"
                        or call.keywords or not 1 <= len(call.args) <= 3
                        or "range" in self.slots or "range" in self.functions or "range" in self.constants):
                    _fail(node, "for requires a simple target and unshadowed range with 1..3 positional arguments")
                for arg in call.args:
                    self.expr(arg)
                iterator = self.temp()
                self.emit("iter", len(call.args), iterator)
                start = len(self.code)
                exit_index = self.emit("next", iterator, self.slots[node.target.id], None)
                exit_operand = 3
            else:
                start = len(self.code)
                self.expr(node.test)
                exit_index, exit_operand = self.emit("false", None), 1
            loop = {"continue": start, "breaks": []}
            self.loops.append(loop)
            self.block(node.body)
            self.loops.pop()
            self.emit("jump", start)
            self.patch(exit_index, len(self.code), exit_operand)
            # The loop is no longer active inside its else suite (Python rules).
            self.block(node.orelse)
            for index in loop["breaks"]:
                self.patch(index, len(self.code))
        elif isinstance(node, ast.Break):
            if not self.loops:
                _fail(node, "break outside a loop")
            self.loops[-1]["breaks"].append(self.emit("jump", None))
        elif isinstance(node, ast.Continue):
            if not self.loops:
                _fail(node, "continue outside a loop")
            self.emit("jump", self.loops[-1]["continue"])
        elif isinstance(node, ast.Pass):
            return
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            # Docstrings/comments have no computational effect; never copy them.
            return
        else:
            _fail(node, f"Unsupported statement {type(node).__name__}")

    def compile(self):
        self.block(self.node.body)
        self.emit("const", None)
        self.emit("return")
        return {"parameters": self.parameters, "locals": self.locals, "code": self.code,
                "calls": sorted(self.calls)}


def _analyze(source_text, selected_functions):
    if not isinstance(source_text, str) or len(source_text.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise PythonFrontendError("Source must be UTF-8 text at most 512 KiB")
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(source_text.encode("utf-8")).readline)
    except (SyntaxError, LookupError) as exc:
        raise PythonFrontendError("Invalid Python source encoding declaration") from exc
    if encoding not in {"utf-8", "utf-8-sig"}:
        raise PythonFrontendError("Only UTF-8 source encoding declarations are supported")
    if (not isinstance(selected_functions, list) or not 1 <= len(selected_functions) <= 64
            or any(not _name(name) for name in selected_functions)
            or len(set(selected_functions)) != len(selected_functions)):
        raise PythonFrontendError("Select 1..64 unique ordinary function names (reserved _ar_/dunder prefixes excluded)")
    try:
        tree = ast.parse(source_text)
    except (SyntaxError, ValueError, RecursionError) as exc:
        raise PythonFrontendError(f"Invalid Python syntax: {exc}") from exc
    if sum(1 for _ in ast.walk(tree)) > MAX_AST_NODES:
        raise PythonFrontendError("Source exceeds 20000 AST nodes")
    functions, constants = {}, {}
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            continue
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            try:
                value = ast.literal_eval(node.value)
            except (ValueError, TypeError, SyntaxError) as exc:
                _fail(node, "Module constants must be literal integers or bools")
            if type(value) not in (int, bool) or (type(value) is int and value.bit_length() > 4096):
                _fail(node, "Module constants must be int/bool (at most 4096 literal bits)")
            if not _name(name) or name in functions or name in constants:
                _fail(node, "Duplicate/reserved module name")
            constants[name] = value
        elif isinstance(node, ast.FunctionDef):
            if not _name(node.name) or node.name in functions or node.name in constants:
                _fail(node, "Duplicate/reserved function name")
            args = node.args
            if (node.decorator_list or args.posonlyargs or args.kwonlyargs or args.vararg or args.kwarg
                    or args.defaults or getattr(node, "type_params", [])):
                _fail(node, "Decorators/defaults/positional-only/keyword-only/variadic/type parameters are unsupported")
            names = [arg.arg for arg in args.args]
            if len(names) > 16 or len(names) != len(set(names)) or any(not _name(name) for name in names):
                _fail(node, "Use at most 16 unique ordinary parameter names")
            for annotation in [node.returns, *(arg.annotation for arg in args.args)]:
                if annotation is not None and not (isinstance(annotation, ast.Name) and annotation.id in {"int", "bool"}):
                    _fail(annotation, "Only unevaluated int/bool annotations are supported")
            functions[node.name] = node
        else:
            _fail(node, f"Module-level {type(node).__name__} is unsupported (no imports or execution)")
    if len(functions) > 128:
        raise PythonFrontendError("At most 128 functions are supported")
    if set(selected_functions) - functions.keys():
        raise PythonFrontendError("Selected function not found: " + ", ".join(sorted(set(selected_functions) - functions.keys())))
    # Annotations are copied only to the private baseline. Reject shadowed builtins
    # to avoid annotation NameError or misleading runtime annotation semantics.
    if {"int", "bool"} & (functions.keys() | constants.keys()):
        raise PythonFrontendError("Module names int/bool are reserved for supported annotations/builtins")
    compiled = {name: _Compiler(node, functions, constants).compile() for name, node in functions.items()}
    visited, active = set(), set()

    def visit(name):
        if name in active:
            raise PythonFrontendError("Recursive helper cycles are not supported")
        if name in visited:
            return
        active.add(name)
        for helper in compiled[name]["calls"]:
            visit(helper)
        active.remove(name)
        visited.add(name)

    # Validate unreachable helpers too; baseline import never hides executable code.
    for name in compiled:
        visit(name)
    closure = set()
    def include(name):
        if name not in closure:
            closure.add(name)
            for helper in compiled[name]["calls"]:
                include(helper)
    for name in selected_functions:
        include(name)
    names = sorted(closure)
    result = {"schema_version": 1, "backend": "python_vm", "route_status": "available",
              "blockers": [], "selected_functions": list(selected_functions),
              "exported_functions": list(selected_functions), "protected_functions": names,
              "functions": {name: {"parameters": compiled[name]["parameters"],
                                   "helpers": compiled[name]["calls"],
                                   "instruction_count": len(compiled[name]["code"])} for name in names},
              "source_sha256": hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
              "source_executed": False, "limitations": list(LIMITATIONS)}
    return result, {name: compiled[name] for name in names}


def inspect_python_source(source_text: str, selected_functions: list[str]) -> dict:
    """Parse/validate a bounded source module without creating files or executing it."""
    return _analyze(source_text, selected_functions)[0]


# This fixed runtime interprets data instructions. It never compiles/executes a
# Python AST/source/code object. Literal tokens are replaced during generation.
def _function_codec(seed, identifier):
    """Deterministic function-local data codec, not a secret-key construction."""
    material = (b"ANTI-REA-python-context-v2\0" + seed.to_bytes(32, "big")
                + identifier.to_bytes(4, "big"))
    rng = random.Random(int.from_bytes(hashlib.sha256(material).digest(), "big"))
    return {"key": rng.getrandbits(64),
            "tokens": rng.sample(range(256, 65536), len(_OPS)),
            "multiply": rng.getrandbits(32) | 1, "add": rng.getrandbits(32),
            "mix": rng.getrandbits(32) | 1, "rotate": rng.randrange(7),
            "operand_multiply": rng.getrandbits(32) | 1,
            "operand_add": rng.getrandbits(32)}


def _operand_context(codec, record_pc, opcode):
    return ((record_pc * codec["operand_multiply"]) ^ opcode ^ codec["key"]
            ^ (codec["key"] >> 32) ^ codec["operand_add"]) & 0xffffffff


def _operand_step(codec, state, plain):
    rotated = ((state << 5) | (state >> 27)) & 0xffffffff
    return (rotated * codec["operand_multiply"] + plain + codec["operand_add"]) & 0xffffffff


def _encode_fetch_byte(codec, position, plain):
    mixed = (position * codec["multiply"] + codec["add"]) & 0xffffffff
    mixed ^= mixed >> 13
    mixed = (mixed * codec["mix"]) & 0xffffffff
    mixed ^= mixed >> 17
    mask = (mixed ^ (codec["key"] >> (8 * (position & 7)))) & 255
    rotation = ((position + codec["rotate"]) % 7) + 1
    value = (plain + mask) & 255
    return (((value << rotation) | (value >> (8 - rotation))) & 255) ^ ((mixed >> 8) & 255)


def _encode_function(function, indexes, codec):
    """Emit individually addressable records; branch targets remain instruction IDs."""
    encoded, positions = bytearray(), [0]
    for instruction in function["code"]:
        operation, *operands = instruction
        if operation == "call":
            operands[0] = indexes[operands[0]]
        opcode = codec["tokens"][_OPS.index(operation)]
        record_pc = len(encoded)
        record = bytearray(opcode.to_bytes(2, "big"))
        state = _operand_context(codec, record_pc, opcode)
        # Only codec arithmetic is fixed-width. Operand JSON retains Python
        # arbitrary-size integers, bool and None; it is data, not executable code.
        for plain in _json(operands).encode("ascii"):
            mask = (state ^ (state >> 11) ^ (state >> 23)) & 255
            record.append(plain ^ mask)
            state = _operand_step(codec, state, plain)
        encoded.extend(_encode_fetch_byte(codec, record_pc + i, value)
                       for i, value in enumerate(record))
        positions.append(len(encoded))
    return bytes(encoded), positions


_RUNTIME = '''"""Generated experimental Python integer VM; no original selected function bodies.
Only the current instruction is decoded. Keys/runtime remain locally available.
The data checksum is not authenticated integrity or protection of runtime code.
"""
import hashlib as _ar_hashlib
import json as _ar_json
import operator as _ar_operator
import builtins as _ar_builtins

# This one initialization precedes every public wrapper, including a wrapper
# named bytes. Preserve the literal blob anchor used by integrity regression tests.
_ar_blob = bytes.fromhex(@BLOB@)
_ar_functions = @FUNCTIONS@
_ar_metadata = _ar_json.dumps(_ar_functions, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii")
if _ar_hashlib.sha256(_ar_metadata + _ar_blob).hexdigest() != @DIGEST@:
    raise _ar_builtins.RuntimeError("ANTI-REA VM program integrity check failed")
del _ar_metadata

def _ar_validate_metadata():
    def integer(value, lower, upper):
        return _ar_builtins.type(value) is _ar_builtins.int and lower <= value <= upper
    def reject():
        raise _ar_builtins.RuntimeError("Invalid VM metadata")
    if _ar_builtins.type(_ar_functions) is not _ar_builtins.list or not 1 <= _ar_builtins.len(_ar_functions) <= 128:
        reject()
    next_offset = 0
    for function in _ar_functions:
        if (_ar_builtins.type(function) is not _ar_builtins.dict
                or _ar_builtins.set(function) != {"slots", "offset", "bytes", "positions", "codec"}):
            reject()
        if not integer(function["slots"], 0, 1000000):
            reject()
        if (not integer(function["offset"], 0, _ar_builtins.len(_ar_blob))
                or function["offset"] != next_offset
                or not integer(function["bytes"], 4, _ar_builtins.len(_ar_blob) - next_offset)):
            reject()
        positions = function["positions"]
        if (_ar_builtins.type(positions) is not _ar_builtins.list or _ar_builtins.len(positions) < 2
                or positions[0] != 0 or positions[-1] != function["bytes"]):
            reject()
        previous = -4
        for position in positions:
            if not integer(position, 0, function["bytes"]) or position < previous + 4:
                reject()
            previous = position
        codec = function["codec"]
        if (_ar_builtins.type(codec) is not _ar_builtins.dict
                or _ar_builtins.set(codec) != {"key", "tokens", "multiply", "add", "mix", "rotate",
                                                "operand_multiply", "operand_add"}):
            reject()
        if not integer(codec["key"], 0, (1 << 64) - 1) or not integer(codec["rotate"], 0, 6):
            reject()
        for name in ("multiply", "add", "mix", "operand_multiply", "operand_add"):
            if not integer(codec[name], 0, 0xffffffff):
                reject()
        if not (codec["multiply"] & codec["mix"] & codec["operand_multiply"] & 1):
            reject()
        tokens = codec["tokens"]
        if (_ar_builtins.type(tokens) is not _ar_builtins.list or _ar_builtins.len(tokens) != 16
                or _ar_builtins.any(not integer(token, 256, 65535) for token in tokens)
                or _ar_builtins.len(_ar_builtins.set(tokens)) != 16):
            reject()
        next_offset += function["bytes"]
    if next_offset != _ar_builtins.len(_ar_blob):
        reject()

_ar_validate_metadata()
_ar_unset = _ar_builtins.object()
_ar_builtins_table = {name: _ar_builtins.getattr(_ar_builtins, name)
                      for name in ("abs", "int", "bool", "min", "max")}

def _ar_read_byte(function, position):
    codec = function["codec"]
    mixed = (position * codec["multiply"] + codec["add"]) & 0xffffffff
    mixed ^= mixed >> 13
    mixed = (mixed * codec["mix"]) & 0xffffffff
    mixed ^= mixed >> 17
    mask = (mixed ^ (codec["key"] >> (8 * (position & 7)))) & 255
    rotation = ((position + codec["rotate"]) % 7) + 1
    value = _ar_blob[function["offset"] + position] ^ ((mixed >> 8) & 255)
    value = ((value >> rotation) | (value << (8 - rotation))) & 255
    return (value - mask) & 255

def _ar_fetch(function, instruction_pc):
    positions = function["positions"]
    if (_ar_builtins.type(instruction_pc) is not _ar_builtins.int
            or not 0 <= instruction_pc < _ar_builtins.len(positions) - 1):
        raise _ar_builtins.RuntimeError("Invalid VM instruction address")
    start, end = positions[instruction_pc], positions[instruction_pc + 1]
    opcode = (_ar_read_byte(function, start) << 8) | _ar_read_byte(function, start + 1)
    codec = function["codec"]
    if opcode not in codec["tokens"]:
        raise _ar_builtins.RuntimeError("Invalid VM opcode")
    state = ((start * codec["operand_multiply"]) ^ opcode ^ codec["key"]
             ^ (codec["key"] >> 32) ^ codec["operand_add"]) & 0xffffffff
    operand_bytes = _ar_builtins.bytearray()
    for position in _ar_builtins.range(start + 2, end):
        mask = (state ^ (state >> 11) ^ (state >> 23)) & 255
        plain = _ar_read_byte(function, position) ^ mask
        operand_bytes.append(plain)
        state = (((((state << 5) | (state >> 27)) & 0xffffffff)
                  * codec["operand_multiply"]) + plain + codec["operand_add"]) & 0xffffffff
    operands = _ar_json.loads(operand_bytes)
    if _ar_builtins.type(operands) is not _ar_builtins.list:
        raise _ar_builtins.RuntimeError("Invalid VM operand record")
    # No decoded-function cache: this list describes only the current instruction.
    return [opcode, *operands]

# Each protected function has its own generated flattened dispatcher engine
# below; _ar_dispatch maps a VM id to that engine. This _ar_invoke is only a
# bounded id-to-engine forwarding seam for wrappers, helper calls and tests; it
# performs no opcode dispatch. Opcode interpretation lives inside each engine.
@ENGINES@
@DISPATCH@
def _ar_invoke(identifier, arguments):
    return _ar_dispatch[identifier](arguments)

def _ar_enter(identifier, arguments):
    if _ar_builtins.any(_ar_builtins.type(value) not in (_ar_builtins.int, _ar_builtins.bool) for value in arguments):
        raise _ar_builtins.TypeError("This VM accepts exact Python int/bool inputs only")
    return _ar_invoke(identifier, arguments)

@WRAPPERS@
'''


def _generate(source_text, selected_functions, seed):
    inspection, compiled = _analyze(source_text, selected_functions)
    if seed is None:
        seed = secrets.randbits(128)
    if type(seed) is not int or not 0 <= seed < 2 ** 256:
        raise PythonFrontendError("seed must be an integer in 0..2**256-1, or None")
    encoded, functions = bytearray(), []
    indexes = {name: i for i, name in enumerate(compiled)}
    function_evidence, codec_hashes, opcode_tables = {}, set(), set()
    engine_sources, engine_metadata, engine_signatures = [], [], set()
    for name, function in compiled.items():
        identifier = indexes[name]
        codec = _function_codec(seed, identifier)
        codec_sha256 = hashlib.sha256(_json(codec).encode("ascii")).hexdigest()
        # A collision is an explicit generation failure, never a silent shared codec.
        if codec_sha256 in codec_hashes or tuple(codec["tokens"]) in opcode_tables:
            raise PythonFrontendError("function-local codec collision")
        codec_hashes.add(codec_sha256)
        opcode_tables.add(tuple(codec["tokens"]))
        # Each function gets its own flattened dispatcher engine with seed-derived
        # states/mask/handler order. A full state collision is a hard failure, never
        # two engines sharing control-flow identity.
        plan = _prh.engine_plan(seed, identifier)
        signature = (plan["fetch"], plan["execute"], plan["return"], plan["mask"])
        if signature in engine_signatures:
            raise PythonFrontendError("engine state collision")
        engine_signatures.add(signature)
        symbol = "_ar_engine_%d" % identifier
        engine_sources.append(_prh.render_engine(identifier, plan))
        engine_metadata.append(_prh.engine_coverage(identifier, plan, symbol))
        blob, positions = _encode_function(function, indexes, codec)
        functions.append({"slots": len(function["locals"]), "offset": len(encoded),
                          "bytes": len(blob), "positions": positions, "codec": codec})
        encoded.extend(blob)
        function_evidence[name] = {**inspection["functions"][name], "virtualized": True,
                                   "vm_function_id": identifier, "encoded_bytes": len(blob),
                                   "encoded_sha256": hashlib.sha256(blob).hexdigest(),
                                   "codec_sha256": codec_sha256,
                                   "instruction_offsets_sha256": hashlib.sha256(
                                       _json(positions).encode("ascii")).hexdigest()}
    metadata = _json(functions).encode("ascii")
    digest = hashlib.sha256(metadata + encoded).hexdigest()
    wrappers = []
    for name in selected_functions:
        parameters = compiled[name]["parameters"]
        wrappers.append(f"def {name}({', '.join(parameters)}):\n    return _ar_enter({indexes[name]}, [{', '.join(parameters)}])\n")
    runtime = _RUNTIME
    substitutions = {"BLOB": repr(encoded.hex()), "FUNCTIONS": repr(functions),
                     "DIGEST": repr(digest), "ENGINES": "\n".join(engine_sources),
                     "DISPATCH": _prh.render_dispatch_table(len(functions)),
                     "WRAPPERS": "\n".join(wrappers)}
    for token, value in substitutions.items():
        runtime = runtime.replace("@" + token + "@", value)
    runtime_hardening = {"schema_version": 1, "profile": "per_function_flattened_dispatch_v1",
                         "stage": "generated_source", "engine_count": len(functions),
                         "dispatch_table_symbol": "_ar_dispatch", "engines": engine_metadata,
                         "shared_fetch_and_operator_helpers": True,
                         "kagura_passes_applied": False, "external_resistance": "not_evaluated"}
    coverage = {"schema_version": 1, "backend": "python_vm", "protection": "python-custom-vm",
                "selected_functions": list(selected_functions), "exported_functions": list(selected_functions),
                "validation_exports": list(selected_functions), "helper_closure": list(compiled),
                "functions": function_evidence,
                "format_version": FORMAT_VERSION, "opcode_bits": 16,
                "encoding": "function-local PC/key fetch codec with instruction-context plaintext operand feedback",
                "fetch_encoding": "position_key_affine_rotate_xor_v1",
                "operand_encoding": "record_pc_opcode_key_plaintext_feedback32_v1",
                "operand_value_semantics": "JSON int/bool/None; Python integers are not narrowed",
                "decode_scope": "current_instruction", "decoded_instruction_cache": False,
                "opcode_scope": "per_function", "codec_scope": "per_function",
                "codec_count": len(functions), "dispatcher": "per_function_flattened_indirect_dispatch",
                "runtime_hardening": runtime_hardening,
                "encoded_bytes": len(encoded), "encoded_sha256": hashlib.sha256(encoded).hexdigest(),
                "metadata_sha256": hashlib.sha256(metadata).hexdigest(),
                "integrity": {"status": "generated", "algorithm": "SHA-256(canonical_metadata || encoded_program)",
                              "checked_at": "module_import", "covers_runtime_code": False,
                              "covers_codec_and_offsets": True, "authenticated": False},
                "kagura_passes_applied": False, "requested_core_passes": [],
                "original_selected_bodies_in_protected_artifact": False,
                "scope_mode": "explicit_roots_and_transitive_helpers",
                "qualification": "Transformation evidence only; semantics/performance/attack resistance require separate evaluation."}
    return runtime, coverage, inspection, seed


def _no_links(path):
    path = Path(os.path.abspath(path))
    if any(part.casefold() in {"rea-analysis-reports", "attackerfolder"} for part in path.parts):
        raise PythonFrontendError("Incoming/shared handoff paths are not trusted source/output paths")
    for candidate in (path, *path.parents):
        if candidate.exists() or candidate.is_symlink():
            info = candidate.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise PythonFrontendError("Links/reparse points are unsupported")
            if candidate.is_file() and info.st_nlink > 1:
                raise PythonFrontendError("Hardlinked inputs/outputs are unsupported")
    return path


def _write(path, text):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(text)


def _materialize(source_text, output, generated):
    runtime, coverage, inspection, seed = generated
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema_version": 1, "status": "failed", "backend": "python_vm",
              "seed": seed, "inspection": inspection,
              "source_executed": False, "functional_evaluation": "not_performed",
              "performance_evaluation": "not_performed", "external_attack_evaluation": "not_performed",
              "limitations": list(LIMITATIONS)}
    try:
        _write(output / "baseline.py", source_text)
        _write(output / "protected.py", runtime)
        artifacts = {arm: {"path": str(output / (arm + ".py")), "sha256": _hash(output / (arm + ".py")),
                           "bytes": (output / (arm + ".py")).stat().st_size} for arm in ("baseline", "protected")}
        coverage["artifacts"] = artifacts
        _write(output / "coverage.json", _json(coverage) + "\n")
        report.update(status="artifact_created_unvalidated", artifacts=artifacts,
                      baseline=artifacts["baseline"]["path"], protected=artifacts["protected"]["path"],
                      coverage=coverage, coverage_path=str(output / "coverage.json"))
    except (OSError, ValueError) as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
    return report


def protect_python_source(source_text: str, selected_functions: list[str], output_dir: Path, *, seed=None) -> dict:
    """Write a fresh private baseline, VM module and report; never run source.

    Unsupported input is rejected before output creation. Low-level caller owns
    directory choice; service users should use the workspace-bounded project API.
    """
    generated = _generate(source_text, selected_functions, seed)
    output = _no_links(output_dir)
    if output.exists():
        raise PythonFrontendError("Output directory must be fresh")
    report = _materialize(source_text, output, generated)
    _write(output / "report.json", _json(report) + "\n")
    return report


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PythonFrontendError(f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def inspect_project(project_path: Path) -> dict:
    path = _no_links(project_path)
    if not path.is_file() or path.stat().st_size > 256 * 1024:
        raise PythonFrontendError("A trusted project JSON file <=256 KiB is required")
    try:
        project = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PythonFrontendError("Project must be UTF-8 JSON") from exc
    if not isinstance(project, dict) or set(project) - {"schema_version", "name", "language", "sources", "functions"}:
        raise PythonFrontendError("Unknown project fields or non-object project")
    if type(project.get("schema_version")) is not int or project["schema_version"] != 1 or project.get("language") != "python":
        raise PythonFrontendError("Project requires schema_version 1 and language python")
    if not isinstance(project.get("name"), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", project["name"]):
        raise PythonFrontendError("name must be a short ASCII identifier")
    values = project.get("sources")
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], str):
        raise PythonFrontendError("Python route requires one relative .py source file")
    value = values[0]
    win = PureWindowsPath(value)
    if not value or "\x00" in value or Path(value).is_absolute() or win.drive or ".." in win.parts or ":" in value:
        raise PythonFrontendError("Source must stay inside the project")
    source = _no_links(path.parent / value.replace("\\", "/"))
    if not source.is_relative_to(path.parent) or source.suffix.lower() != ".py" or not source.is_file():
        raise PythonFrontendError("A local .py source is required")
    if source.stat().st_size > MAX_SOURCE_BYTES:
        raise PythonFrontendError("Source exceeds 512 KiB")
    text = source.read_text(encoding="utf-8-sig")
    inspection = inspect_python_source(text, project.get("functions"))
    return {**inspection, "name": project["name"], "language": "python", "project_path": str(path),
            "project_root": str(path.parent), "sources": [str(source)], "source_files": [str(source)],
            "functions": list(project["functions"]), "function_signatures": inspection["functions"],
            "input_hashes": {str(path): _hash(path), str(source): _hash(source)},
            "scope_mode": "explicit_roots_and_transitive_helpers", "target": "python-int-bool",
            "artifact": "python_module", "experimental": True}


def build_project(project_path: Path, output_dir: Path, *, workspace_root: Path, seed=None) -> dict:
    """Create modules inside workspace/.runs; source/runtime execution is separate."""
    project = inspect_project(project_path)
    workspace, output = _no_links(workspace_root), _no_links(output_dir)
    if (not workspace.is_dir() or not Path(project["project_path"]).is_relative_to(workspace)
            or not output.is_relative_to(workspace / ".runs") or output == workspace / ".runs"
            or output.exists() or output.is_relative_to(Path(project["project_root"]))):
        raise PythonFrontendError("Use owned source and a fresh output descendant of workspace/.runs outside the source project")
    stop = workspace / ".runs" / "defense-loop" / "STOP"
    if stop.exists():
        raise PythonFrontendError("Defense STOP marker exists")
    # Pin the frontend and the engine generator before compiling; the drift loop
    # below re-hashes both afterwards so a mid-build tool change fails closed.
    tool_hashes = {str(Path(path).resolve()): _hash(path) for path in (__file__, _prh.__file__)}
    source_text = Path(project["sources"][0]).read_text(encoding="utf-8-sig")
    generated = _generate(source_text, project["functions"], seed)
    # Bind compiled text to the inspected source even if it changes between reads.
    if generated[2]["source_sha256"] != project["source_sha256"]:
        raise PythonFrontendError("Source changed after inspection")
    started, stamp = time.monotonic(), datetime.now(timezone.utc).isoformat()
    report = _materialize(source_text, output, generated)
    report.update(project=project, output_dir=str(output), started_utc=stamp, commands=[],
                  tool_hashes=tool_hashes)
    changed = []
    for name, digest in {**project["input_hashes"], **tool_hashes}.items():
        try:
            if not Path(name).is_file() or _hash(_no_links(name)) != digest:
                changed.append(name)
        except (OSError, PythonFrontendError):
            changed.append(name)
    report.update(changed_inputs=changed, seconds=round(time.monotonic() - started, 6),
                  finished_utc=datetime.now(timezone.utc).isoformat())
    if changed or stop.exists():
        report.update(status="cancelled" if stop.exists() else "failed", error="STOP requested or pinned source changed")
    report["artifact_hashes"] = {path.name: _hash(path) for path in output.iterdir() if path.is_file()}
    _write(output / "report.json", _json(report) + "\n")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["inspect", "build"])
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--seed", type=int)
    args = parser.parse_args(argv)
    try:
        if args.action == "build" and args.output_dir is None:
            raise PythonFrontendError("build requires --output-dir")
        result = inspect_project(args.project) if args.action == "inspect" else build_project(
            args.project, args.output_dir, workspace_root=args.workspace, seed=args.seed)
    except (PythonFrontendError, OSError) as exc:
        result = {"status": "rejected", "error": str(exc)}
    print(json.dumps(result, indent=2))
    return 0 if result.get("route_status") == "available" or result.get("status") == "artifact_created_unvalidated" else 2


if __name__ == "__main__":
    raise SystemExit(main())
