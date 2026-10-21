"""Experimental opt-in mixed Python module -> selected format-2 VM bodies.

Inspection/build parse user source only. Importing a resulting mixed module executes its ordinary
unprotected imports/statements; the existing pure-source validator must not be
used to authorize that execution.
"""
from __future__ import annotations

import ast
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path, PureWindowsPath
import re
import time
import tokenize

from . import python_frontend as pf


BACKEND = "python_mixed_module_vm"
MODE = "mixed_module"
PREFIX = "_arm_"
LIMITATIONS = [
    "Opt-in single owned module replacement; not arbitrary Python or package-wide protection.",
    "Only selected top-level pure int/bool roots and acyclic owned helpers are virtualized.",
    "Selected code cannot load module-global values, even apparent literal constants; pass them as arguments.",
    "Selected defaults, decorators, closures, async, generators, objects and dynamic calls remain unsupported.",
    "Selected helper/builtin rebinding is unsupported and raises an explicit runtime error on the reached call.",
    "Missing helper bindings retain NameError; unrelated code and its side effects remain unprotected.",
    "Unrelated imports and statements retain source order/text; generated runtime initialization adds imports and cost.",
    "Selected callable names, fixed signatures and int/bool annotations remain; docstrings, source lines and introspection differ.",
    "Module deployment must preserve original package/import context; no dependency installation, copying or resolution is performed.",
    "Protected-module import may execute arbitrary ordinary application code; no validation/execution is authorized by this build.",
    "Namespace/reflection tampering, monkeypatching runtime dependencies and custom builtins environments are outside the supported contract.",
    "Format-2 keys/runtime remain public and transient instructions inspectable; no secrecy or external resistance claim.",
    "Kagura native LLVM passes are not applied to this Python VM; no functional/performance acceptance is inferred.",
    "baseline.py, reports and extracted-scope evidence are defender-private and must not be delivered to attackers.",
]


class MixedModuleError(pf.PythonFrontendError):
    pass


def _fail(node, message):
    raise MixedModuleError(f"line {getattr(node, 'lineno', '?')}: {message}")


def _digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _parse(source_text, selected_functions):
    if not isinstance(source_text, str) or len(source_text.encode("utf-8")) > pf.MAX_SOURCE_BYTES:
        raise MixedModuleError("Source must be UTF-8 text at most 512 KiB")
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(source_text.encode("utf-8")).readline)
        if encoding not in {"utf-8", "utf-8-sig"}:
            raise MixedModuleError("Only UTF-8 source encoding declarations are supported")
        # Retain a UTF-8 BOM in the output prefix while excluding it from AST
        # parsing; no newline normalization is performed on the input bytes.
        tree = ast.parse(source_text.removeprefix("\ufeff"))
    except (SyntaxError, ValueError, RecursionError, LookupError) as exc:
        raise MixedModuleError(f"Invalid Python source: {exc}") from exc
    if sum(1 for _ in ast.walk(tree)) > pf.MAX_AST_NODES:
        raise MixedModuleError("Source exceeds 20000 AST nodes")
    if (not isinstance(selected_functions, list) or not 1 <= len(selected_functions) <= 64
            or any(not pf._name(name) for name in selected_functions)
            or len(set(selected_functions)) != len(selected_functions)):
        raise MixedModuleError("Select 1..64 unique ordinary function names")
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Name):
            names.append(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.append(node.name)
        elif isinstance(node, ast.arg):
            names.append(node.arg)
        elif isinstance(node, ast.alias):
            names.append(node.asname or node.name.split(".")[0])
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            names.extend(node.names)
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            names.append(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            names.append(node.rest)
        if any(name.startswith(PREFIX) for name in names):
            _fail(node, "The _arm_ generated-runtime identifier prefix is reserved")
        if isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names):
            _fail(node, "Star imports cannot establish a bounded selected-name binding contract")
    return tree


class _ModuleBindings(ast.NodeVisitor):
    """Collect syntactic module writes without mistaking ordinary locals for them."""
    def __init__(self):
        self.bindings = {}

    def bind(self, name, node):
        self.bindings.setdefault(name, []).append(node)

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.bind(node.id, node)

    def visit_AnnAssign(self, node):
        # A bare annotation does not assign its target name. Receiver/index
        # expressions on complex targets and annotation expressions still need
        # traversal: they can contain explicit writes to protected globals.
        if node.value is not None:
            self.visit(node.value)
            self.visit(node.target)
        elif not isinstance(node.target, ast.Name):
            self.visit(node.target)
        self.visit(node.annotation)

    def visit_FunctionDef(self, node):
        self.bind(node.name, node)
        # Defaults/decorators/annotations execute in the enclosing scope. A
        # selected function's unsupported forms are rejected by the pure parser.
        for value in [*node.decorator_list, *node.args.defaults,
                      *(value for value in node.args.kw_defaults if value is not None),
                      node.returns, *(arg.annotation for arg in
                                      [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]),
                      node.args.vararg.annotation if node.args.vararg else None,
                      node.args.kwarg.annotation if node.args.kwarg else None]:
            if value is not None:
                self.visit(value)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self.bind(node.name, node)
        for value in [*node.bases, *node.decorator_list, *(item.value for item in node.keywords)]:
            self.visit(value)

    def visit_Lambda(self, node):
        # A lambda body is not module execution; defaults are.
        for value in [*node.args.defaults, *(v for v in node.args.kw_defaults if v is not None)]:
            self.visit(value)

    def _visit_comprehension_target(self, node):
        # Iteration names belong to the comprehension, not its enclosing scope.
        # Attribute/subscript receivers and indexes still evaluate expressions,
        # so do not skip the entire assignment target.
        if isinstance(node, ast.Name):
            return
        if isinstance(node, (ast.Tuple, ast.List)):
            for value in node.elts:
                self._visit_comprehension_target(value)
        elif isinstance(node, ast.Starred):
            self._visit_comprehension_target(node.value)
        else:
            self.visit(node)

    def _visit_comprehension(self, node):
        # Named expressions in comprehensions bind in the nearest surrounding
        # non-comprehension scope. Visit their expressions while excluding only
        # iteration-name stores. Lambda bodies remain a distinct scope through
        # visit_Lambda; lambda defaults still belong to the enclosing scope.
        #
        # A generator's first iterable is evaluated eagerly; its remaining
        # iterable/filter/value expressions are deferred. Reject possible
        # protected-name writes in either phase, even for an unconsumed generator.
        # This is a static unsupported-rebinding gate, not an execution trace.
        for generator in node.generators:
            self.visit(generator.iter)
            self._visit_comprehension_target(generator.target)
            for condition in generator.ifs:
                self.visit(condition)
        if isinstance(node, ast.DictComp):
            self.visit(node.key)
            self.visit(node.value)
        else:
            self.visit(node.elt)

    visit_ListComp = _visit_comprehension
    visit_SetComp = _visit_comprehension
    visit_DictComp = _visit_comprehension
    visit_GeneratorExp = _visit_comprehension

    def visit_Import(self, node):
        for alias in node.names:
            self.bind(alias.asname or alias.name.split(".")[0], node)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            self.bind(alias.asname or alias.name, node)

    def visit_ExceptHandler(self, node):
        if node.name:
            self.bind(node.name, node)
        self.generic_visit(node)

    def visit_MatchAs(self, node):
        if node.name:
            self.bind(node.name, node)
        self.generic_visit(node)

    visit_MatchStar = visit_MatchAs

    def visit_MatchMapping(self, node):
        if node.rest:
            self.bind(node.rest, node)
        self.generic_visit(node)


def _declared_global_writes(tree, protected):
    """Reject explicit writes to protected globals from any lexical scope.

    Dynamic namespace/reflection writes are not statically proven absent. The
    reached-helper identity checks are a correctness guard, not tamper resistance.
    """
    scopes = [node for node in ast.walk(tree)
              if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    for scope in scopes:
        nodes = []
        def collect(node):
            nodes.append(node)
            if node is not scope and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                return
            for child in ast.iter_child_nodes(node):
                collect(child)
        collect(scope)
        declared = {name for node in nodes if isinstance(node, ast.Global) for name in node.names} & protected
        if not declared:
            continue
        bindings = _ModuleBindings()
        for statement in scope.body:
            bindings.visit(statement)
        for name in declared & bindings.bindings.keys():
            _fail(bindings.bindings[name][0], "Explicit rebinding/deletion of a protected global is unsupported")


def _analyze(source_text, selected_functions):
    tree = _parse(source_text, selected_functions)
    definitions = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            definitions.setdefault(node.name, []).append(node)
    missing = set(selected_functions) - definitions.keys()
    if missing:
        raise MixedModuleError("Selected top-level function not found: " + ", ".join(sorted(missing)))
    functions = {name: nodes[0] for name, nodes in definitions.items()}
    compiled, active = {}, set()
    def include(name):
        if name in active:
            raise MixedModuleError("Recursive helper cycles are not supported")
        if name in compiled:
            return
        if len(definitions[name]) != 1:
            _fail(functions[name], "Protected function must have exactly one top-level definition")
        active.add(name)
        try:
            result = pf._Compiler(functions[name], functions, {}).compile()
        except pf.PythonFrontendError as exc:
            raise MixedModuleError(str(exc) + "; mixed selected code cannot freeze module-global values") from exc
        for helper in result["calls"]:
            include(helper)
        active.remove(name)
        compiled[name] = result
    for name in selected_functions:
        include(name)
    closure = sorted(compiled)
    if len(closure) > 128:
        raise MixedModuleError("At most 128 protected functions are supported")
    bindings = _ModuleBindings()
    bindings.visit(tree)
    for name in closure:
        if bindings.bindings.get(name) != [functions[name]]:
            _fail(functions[name], "Protected function names cannot be rebound/imported/deleted in module statements")
    _declared_global_writes(tree, set(closure))
    # Extract syntax, not executable code objects. The established parser remains
    # authoritative for selected signatures, annotations and supported opcodes.
    extracted = "\n\n".join(ast.unparse(functions[name]) for name in closure) + "\n"
    try:
        pure = pf.inspect_python_source(extracted, list(selected_functions))
    except pf.PythonFrontendError as exc:
        raise MixedModuleError(str(exc)) from exc
    inspection = {**pure, "backend": BACKEND, "protection_mode": MODE,
                  "source_sha256": _digest(source_text), "extracted_scope_sha256": _digest(extracted),
                  "exported_functions": closure, "validation_exports": [],
                  "unprotected_top_level_functions": sorted({node.name for node in tree.body
                      if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))} - set(closure)),
                  "original_module_text_preserved_outside_replacements": True,
                  "source_executed": False, "deployment_context": "original_module_package_context_required",
                  "functional_evaluation": "not_performed", "limitations": list(LIMITATIONS)}
    return tree, functions, extracted, inspection


def inspect_python_source(source_text: str, selected_functions: list[str]) -> dict:
    return _analyze(source_text, selected_functions)[3]


_GUARDS = '''
_arm_namespace = _ar_builtins.globals()
_arm_registered = {}
_arm_missing = _ar_builtins.object()
_arm_expected_builtins = _ar_builtins_table.copy()
_arm_expected_builtins["range"] = _ar_builtins.range

def _arm_register(identifier, function):
    if identifier in _arm_registered:
        raise _ar_builtins.RuntimeError("ANTI-REA mixed duplicate wrapper registration")
    _arm_registered[identifier] = function

def _arm_call(identifier, arguments):
    name = _arm_names[identifier]
    value = _arm_namespace.get(name, _arm_missing)
    if value is _arm_missing:
        raise _ar_builtins.NameError("name '" + name + "' is not defined")
    expected = _arm_registered.get(identifier, _arm_missing)
    if expected is _arm_missing or value is not expected:
        raise _ar_builtins.RuntimeError("ANTI-REA mixed unsupported helper rebinding: " + name)
    return _ar_invoke(identifier, arguments)

def _arm_builtin(name, arguments):
    value = _arm_namespace.get(name, _arm_missing)
    if value is _arm_missing:
        value = _ar_builtins.getattr(_ar_builtins, name, _arm_missing)
    if value is not _arm_expected_builtins[name]:
        raise _ar_builtins.RuntimeError("ANTI-REA mixed unsupported builtin rebinding: " + name)
    return value(*arguments)
'''


class _RuntimeAdapter(ast.NodeTransformer):
    """Recognized runtime hooks only; fail closed if the upstream shape changes."""
    def __init__(self):
        self.replacements = {"blob": 0, "helper": 0, "builtin": 0, "range": 0}

    def visit_Call(self, node):
        self.generic_visit(node)
        if (isinstance(node.func, ast.Attribute) and node.func.attr == "fromhex"
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "bytes"):
            if len(node.args) != 1 or node.keywords or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
                raise MixedModuleError("Upstream format-2 runtime adapter shape changed")
            self.replacements["blob"] += 1
            node.func.value = ast.Attribute(value=ast.Name(id="_ar_builtins", ctx=ast.Load()),
                                            attr="bytes", ctx=ast.Load())
        if (isinstance(node.func, ast.Name) and node.func.id == "_ar_invoke"
                and len(node.args) == 2 and isinstance(node.args[0], ast.Subscript)
                and isinstance(node.args[0].value, ast.Name) and node.args[0].value.id == "instruction"):
            expected = ast.parse("_ar_invoke(instruction[1], arguments)", mode="eval").body
            if ast.dump(node) != ast.dump(expected):
                raise MixedModuleError("Upstream format-2 runtime adapter shape changed")
            self.replacements["helper"] += 1
            node.func.id = "_arm_call"
        if (isinstance(node.func, ast.Subscript) and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "_ar_builtins_table"):
            expected = ast.parse("_ar_builtins_table[instruction[1]](*arguments)", mode="eval").body
            if ast.dump(node) != ast.dump(expected):
                raise MixedModuleError("Upstream format-2 runtime adapter shape changed")
            self.replacements["builtin"] += 1
            node = ast.Call(func=ast.Name(id="_arm_builtin", ctx=ast.Load()),
                            args=[node.func.slice, ast.Name(id="arguments", ctx=ast.Load())], keywords=[])
        if (isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "_ar_builtins" and node.func.attr == "range"
                and len(node.args) == 1 and isinstance(node.args[0], ast.Starred)):
            expected = ast.parse("_ar_builtins.range(*arguments)", mode="eval").body
            if ast.dump(node) != ast.dump(expected):
                raise MixedModuleError("Upstream format-2 runtime adapter shape changed")
            self.replacements["range"] += 1
            node = ast.Call(func=ast.Name(id="_arm_builtin", ctx=ast.Load()),
                            args=[ast.Constant("range"), ast.Name(id="arguments", ctx=ast.Load())], keywords=[])
        return node


def _isolated_runtime(generated, closure):
    runtime_tree = ast.parse(generated)
    runtime_tree.body = [node for node in runtime_tree.body
                         if not (isinstance(node, ast.FunctionDef) and node.name in closure)]
    adapter = _RuntimeAdapter()
    runtime_tree = adapter.visit(runtime_tree)
    # Each protected function now has its own flattened dispatcher engine, so the
    # helper/builtin/range call sites occur once per engine. Expect exactly one
    # per engine (and a single shared blob literal); any other count fails closed,
    # keeping the reached-call rebinding guards bound to EVERY engine, not the first.
    engines = len(closure)
    if adapter.replacements != {"blob": 1, "helper": engines, "builtin": engines, "range": engines}:
        raise MixedModuleError("Upstream format-2 runtime adapter shape changed")
    runtime_tree.body.extend(ast.parse("_arm_names = " + repr(closure) + "\n" + _GUARDS).body)
    runtime_tree.body.append(ast.Return(value=ast.Tuple(
        elts=[ast.Name(id="_ar_enter", ctx=ast.Load()), ast.Name(id="_arm_register", ctx=ast.Load())], ctx=ast.Load())))
    factory = ast.FunctionDef(name="_arm_factory", args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[],
                             vararg=None, kwarg=None, kw_defaults=[], defaults=[]), body=runtime_tree.body,
                             decorator_list=[], returns=None, type_comment=None, type_params=[])
    tree = ast.Module(body=[factory], type_ignores=[])
    text = ast.unparse(ast.fix_missing_locations(tree))
    return text + "\n_arm_enter, _arm_register = _arm_factory()\ndel _arm_factory\n\n"


def _generate(source_text, selected_functions, seed):
    if pf.FORMAT_VERSION != 2:
        raise MixedModuleError("Mixed-module adapter requires upstream format 2")
    tree, functions, extracted, inspection = _analyze(source_text, selected_functions)
    closure = inspection["protected_functions"]
    generated, coverage, _, seed = pf._generate(extracted, list(selected_functions), seed)
    isolated = _isolated_runtime(generated, closure)
    data = source_text.encode("utf-8")
    lines = data.splitlines(keepends=True)
    starts, offset = [], 0
    for line in lines:
        starts.append(offset)
        offset += len(line)
    replacements = []
    for name in closure:
        node = functions[name]
        # Top-level definitions occupy complete lines. Removing through the last
        # body line also removes same-line source comments, not just AST tokens.
        start = starts[node.lineno - 1]
        if node.lineno == 1 and data.startswith(b"\xef\xbb\xbf"):
            start += 3
        end = starts[node.end_lineno - 1] + len(lines[node.end_lineno - 1])
        identifier = coverage["functions"][name]["vm_function_id"]
        signature = ast.unparse(node.args)
        returns = " -> " + ast.unparse(node.returns) if node.returns is not None else ""
        arguments = ", ".join(arg.arg for arg in node.args.args)
        wrapper = (f"def {name}({signature}){returns}:\n"
                   f"    return _arm_enter({identifier}, [{arguments}])\n"
                   f"_arm_register({identifier}, {name})\n")
        replacements.append((start, end, wrapper.encode("utf-8"), name))
    replacements.sort()
    parts, cursor, spans = [], 0, []
    for index, (start, end, wrapper, name) in enumerate(replacements):
        parts.append(data[cursor:start])
        if index == 0:
            parts.append(isolated.encode("utf-8"))
        parts.append(wrapper)
        spans.append({"function": name, "original_utf8_start": start, "original_utf8_end": end,
                      "original_body_sha256": hashlib.sha256(data[start:end]).hexdigest(),
                      "replacement_sha256": hashlib.sha256(wrapper).hexdigest()})
        cursor = end
    parts.append(data[cursor:])
    protected = b"".join(parts).decode("utf-8")
    # Parse generated source but do not compile/import/execute it. This catches
    # insertion/order syntax errors while retaining future imports at their place.
    ast.parse(protected.removeprefix("\ufeff"))
    coverage.update(backend=BACKEND, protection="python-mixed-module-custom-vm", protection_mode=MODE,
                    selected_functions=list(selected_functions), exported_functions=closure,
                    validation_exports=[], mixed_runtime_namespace="lexical_factory",
                    original_module_source_sha256=inspection["source_sha256"],
                    extracted_scope_sha256=inspection["extracted_scope_sha256"],
                    preserved_unprotected_functions=inspection["unprotected_top_level_functions"],
                    module_global_values="rejected_not_frozen", helper_binding="identity_checked_at_reached_call",
                    builtin_binding="identity_checked_at_reached_call", replacements=spans,
                    module_text_outside_replacements="byte_preserved_in_original_order",
                    execution_authorized=False,
                    qualification="Experimental opt-in transformation; per-artifact execution/functional/performance/attack qualification is required.")
    return protected, coverage, inspection, seed


def _materialize(source_text, output, generated):
    protected, coverage, inspection, seed = generated
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema_version": 1, "status": "failed", "backend": BACKEND,
              "seed": seed, "inspection": inspection, "source_executed": False,
              "functional_evaluation": "not_performed", "performance_evaluation": "not_performed",
              "external_attack_evaluation": "not_performed", "execution_authorized": False,
              "limitations": list(LIMITATIONS)}
    try:
        pf._write(output / "baseline.py", source_text)
        pf._write(output / "protected.py", protected)
        artifacts = {arm: {"path": str(output / (arm + ".py")), "sha256": pf._hash(output / (arm + ".py")),
                           "bytes": (output / (arm + ".py")).stat().st_size} for arm in ("baseline", "protected")}
        coverage["artifacts"] = artifacts
        pf._write(output / "coverage.json", pf._json(coverage) + "\n")
        report.update(status="artifact_created_unvalidated", artifacts=artifacts,
                      baseline=artifacts["baseline"]["path"], protected=artifacts["protected"]["path"],
                      coverage=coverage, coverage_path=str(output / "coverage.json"))
    except (OSError, ValueError) as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
    return report


def protect_python_source(source_text: str, selected_functions: list[str], output_dir: Path, *, seed=None) -> dict:
    generated = _generate(source_text, selected_functions, seed)
    output = pf._no_links(output_dir)
    if output.exists():
        raise MixedModuleError("Output directory must be fresh")
    report = _materialize(source_text, output, generated)
    pf._write(output / "report.json", pf._json(report) + "\n")
    return report


def _read_source(source):
    with source.open("rb") as stream:
        data = stream.read(pf.MAX_SOURCE_BYTES + 1)
    if len(data) > pf.MAX_SOURCE_BYTES:
        raise MixedModuleError("Source exceeds 512 KiB")
    try:
        # Keep CRLF and any UTF-8 BOM so preserved text is byte-exact, not a
        # universal-newline-normalized reconstruction of the source file.
        return data.decode("utf-8")
    except UnicodeError as exc:
        raise MixedModuleError("Source must be UTF-8") from exc


def inspect_project(project_path: Path) -> dict:
    path = pf._no_links(project_path)
    if not path.is_file() or path.stat().st_size > 256 * 1024:
        raise MixedModuleError("A trusted project JSON file <=256 KiB is required")
    try:
        project = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=pf._pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise MixedModuleError("Project must be UTF-8 JSON") from exc
    required = {"schema_version", "name", "language", "sources", "functions", "protection_mode"}
    if not isinstance(project, dict) or set(project) != required:
        raise MixedModuleError("Mixed project requires exact fields including explicit protection_mode")
    if (type(project["schema_version"]) is not int or project["schema_version"] != 1
            or project["language"] != "python" or project["protection_mode"] != MODE):
        raise MixedModuleError("Project requires schema_version 1, language python, protection_mode mixed_module")
    if not isinstance(project["name"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", project["name"]):
        raise MixedModuleError("name must be a short ASCII identifier")
    sources = project["sources"]
    if not isinstance(sources, list) or len(sources) != 1 or not isinstance(sources[0], str):
        raise MixedModuleError("Mixed route requires one relative .py source file")
    value, win = sources[0], PureWindowsPath(sources[0])
    if not value or "\x00" in value or Path(value).is_absolute() or win.drive or ".." in win.parts or ":" in value:
        raise MixedModuleError("Source must stay inside the project")
    source = pf._no_links(path.parent / value.replace("\\", "/"))
    if not source.is_relative_to(path.parent) or source.suffix.lower() != ".py" or not source.is_file():
        raise MixedModuleError("A local .py source is required")
    if source.stat().st_size > pf.MAX_SOURCE_BYTES:
        raise MixedModuleError("Source exceeds 512 KiB")
    inspection = inspect_python_source(_read_source(source), project["functions"])
    return {**inspection, "name": project["name"], "language": "python", "project_path": str(path),
            "project_root": str(path.parent), "sources": [str(source)], "source_files": [str(source)],
            "functions": list(project["functions"]), "function_signatures": inspection["functions"],
            "input_hashes": {str(path): pf._hash(path), str(source): pf._hash(source)},
            "scope_mode": "selected_body_replacement_with_transitive_helpers",
            "target": "python-int-bool-mixed-module", "artifact": "python_module", "experimental": True}


def build_project(project_path: Path, output_dir: Path, *, workspace_root: Path, seed=None) -> dict:
    project = inspect_project(project_path)
    workspace, output = pf._no_links(workspace_root), pf._no_links(output_dir)
    if (not workspace.is_dir() or not Path(project["project_path"]).is_relative_to(workspace)
            or not output.is_relative_to(workspace / ".runs") or output == workspace / ".runs"
            or output.exists() or output.is_relative_to(Path(project["project_root"]))):
        raise MixedModuleError("Use owned source and a fresh workspace/.runs output outside the source project")
    stop = workspace / ".runs" / "defense-loop" / "STOP"
    if stop.exists():
        raise MixedModuleError("Defense STOP marker exists")
    # Pin the mixed adapter, the pure frontend and the shared engine generator;
    # the drift loop below re-hashes all three so a mid-build tool change fails closed.
    engines = {str(Path(path).resolve()): pf._hash(path)
               for path in (__file__, pf.__file__, pf._prh.__file__)}
    source_text = _read_source(Path(project["sources"][0]))
    generated = _generate(source_text, project["functions"], seed)
    if generated[2]["source_sha256"] != project["source_sha256"]:
        raise MixedModuleError("Source changed after inspection")
    started, stamp = time.monotonic(), datetime.now(timezone.utc).isoformat()
    report = _materialize(source_text, output, generated)
    report.update(project=project, output_dir=str(output), started_utc=stamp, commands=[], tool_hashes=engines)
    changed = []
    for name, digest in {**project["input_hashes"], **engines}.items():
        try:
            if not Path(name).is_file() or pf._hash(pf._no_links(name)) != digest:
                changed.append(name)
        except (OSError, pf.PythonFrontendError):
            changed.append(name)
    report.update(changed_inputs=changed, seconds=round(time.monotonic() - started, 6),
                  finished_utc=datetime.now(timezone.utc).isoformat())
    if changed or stop.exists():
        report.update(status="cancelled" if stop.exists() else "failed", error="STOP requested or pinned source changed")
    report["artifact_hashes"] = {path.name: pf._hash(path) for path in output.iterdir() if path.is_file()}
    pf._write(output / "report.json", pf._json(report) + "\n")
    return report
