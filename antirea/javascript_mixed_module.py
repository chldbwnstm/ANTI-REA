"""Experimental opt-in mixed JavaScript/TypeScript module -> selected format-2 VM bodies.

Experimental opt-in application module builder. Inspection/build parse the owned module with the pinned installed
TypeScript parser and NEVER import or execute it. Importing a resulting mixed
module runs its ordinary unprotected imports/statements/UI; the existing scalar
JavaScript VM validator must not be used to authorize that general execution.

Design notes (JavaScript hoisting boundary):
  * The generated VM is injected as HOISTED function declarations (`_arm_factory`,
    `_arm_enter`) with lazy, memoized initialization, placed after any shebang and
    directive prologue. Because function declarations hoist, an ordinary module may
    call a selected function before its textual definition and still reach an
    initialized VM; no require/integrity work runs at module load, so require and
    startup order are preserved.
  * Selected functions and their reachable owned helpers become delegating
    function declarations at their original byte positions, preserving public
    names, signatures and definition order. The real bodies live only in the VM.
  * Module-global value loads (even apparent literal consts) are rejected, not
    frozen. This includes a module-top-level binding that shadows a runtime
    intrinsic (`undefined`/`NaN`/`Infinity`) or a captured builtin receiver/callee
    (`Math`/`Number`/`BigInt`/`Boolean`): the shadowing module value is rejected,
    never silently resolved to the global intrinsic/builtin. The module scope used
    for this includes `var`s hoisted out of nested blocks and block-level function
    declarations (outer bindings under sloppy-mode Annex B), not only immediate
    top-level statements. Separately, any module-top-level binding that shadows a
    free global the injected runtime itself relies on (require/JSON/Symbol/Array/
    Object/Error/ReferenceError/TypeError/Set/Math/Number/BigInt/Boolean/undefined)
    is rejected even when selected code never names it, since the hoisted runtime
    factory would otherwise resolve the module's shadow and break.
  * Static rebinding/redeclaration/shadowing of a protected name anywhere in the
    module is rejected, including for-of/for-in assignment targets and
    destructuring patterns. Dynamic binding contexts a static scan cannot verify
    (a `with` block or a direct `eval(...)` call anywhere in the module) are
    conservatively rejected rather than risk a silent rebinding. A reached
    internal helper whose live binding no longer equals its registered wrapper
    throws instead of running a frozen body.
  * This is not whole-application protection: unselected code stays in plaintext
    and unprotected. No eval/Function/original-source fallback is used.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re
import subprocess
import time

from . import javascript_frontend as jf
from . import javascript_runtime_hardening as _jrh


BACKEND = "javascript_mixed_module_vm"
MODE = "mixed_module"
MIXED_TOOLS = Path(__file__).resolve().parents[1] / "tools" / "javascript_frontend"
LIMITATIONS = [
    "Opt-in single owned module replacement; not arbitrary JavaScript/TypeScript or package-wide protection.",
    "Only selected top-level pure Number/BigInt/boolean roots and acyclic owned helpers are virtualized.",
    "Selected code cannot load module-global values, even apparent literal consts; pass them as arguments.",
    "Selected closures, globals/function-value loads, var, destructuring, defaults/rest/optional params, async, generators, classes and dynamic calls are rejected.",
    "Protected names cannot be rebound/redeclared/imported/deleted/shadowed anywhere in the module, including for-of/for-in assignment targets and destructuring patterns; such reuse is conservatively rejected at build.",
    "A module-top-level binding that shadows a runtime intrinsic (undefined/NaN/Infinity) or a captured builtin receiver/callee (Math/Number/BigInt/Boolean) read by selected code is rejected as a module-global load, never silently resolved to the global; the module/top-level scope used for this includes var declarations hoisted out of nested blocks and block-level function declarations (which create an outer binding under sloppy-mode Annex B), not only immediate top-level statements.",
    "Any module-top-level binding that shadows a free global the injected runtime itself depends on (require, Math, Number, BigInt, Boolean, JSON, Symbol, Array, Object, Error, ReferenceError, TypeError, Set, undefined) is rejected even when selected code never uses that name, because the hoisted runtime factory would otherwise resolve the module's shadow and break; the fixed format-2 runtime is never rewritten to dodge this.",
    "Dynamic binding contexts a static scan cannot verify -- a `with` block or a direct `eval(...)` call anywhere in the module -- are conservatively rejected; builtin receivers/values are captured once at first call and later runtime monkeypatching of globals remains out of contract.",
    "Assignments/updates to CommonJS require are conservatively rejected throughout the module, including nested scopes and harmless writes to a local shadow; the injected VM depends on the unchanged wrapper loader binding.",
    "A reached owned-helper call whose live module binding changed raises an explicit error rather than running the frozen VM body.",
    "TypeScript is transpiled whole-module via isolatedModules; runtime-affecting constructs (enums, namespaces with runtime members, decorators, parameter properties) are emitted as ordinary runtime JavaScript and preserved as unselected code -- not type-erased away, not reinterpreted, and NOT rejected. Only TypeScript that isolatedModules cannot transpile (parse/isolatedModules diagnostics, e.g. ambient const-enum access or certain import=/export= forms) is rejected. Selected/virtualized functions remain a scalar subset that cannot itself use these constructs, so such runtime TS never enters the VM.",
    "Unselected imports/statements/UI keep source order; JavaScript preserves them byte-for-byte modulo a stripped UTF-8 BOM, TypeScript modulo whole-module CommonJS transpilation.",
    "First call to any selected function lazily initializes the VM (node:crypto/node:buffer require, integrity and metadata checks); this adds first-call cost.",
    "Selected callable names, fixed signatures remain; original bodies, docstrings/comments inside them and introspection differ.",
    "Module deployment must preserve original package/import context; no dependency installation, copying or resolution is performed.",
    "Protected-module import may execute arbitrary ordinary application code; no validation/execution is authorized by this build.",
    "Namespace/reflection tampering, monkeypatching global builtins (Math/Number/BigInt) and custom runtime environments are outside the supported contract.",
    "Function-local format-2 codecs/opcodes/fetch decoding and the first-selected-call SHA-256 program check are obfuscation/integrity, not secrecy or authenticated tamper resistance.",
    "Kagura/native hardening passes are not applied; this is the separate JavaScript VM backend.",
    "baseline.cjs, source snapshots, reports and intermediate instructions are private defender evidence.",
    "Build success does not establish functional equivalence, performance acceptance or attack resistance.",
]


class MixedModuleError(jf.JavaScriptFrontendError):
    pass


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _digest_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def discover_toolchain():
    base = jf.discover_toolchain()
    files = dict(base["files"])
    extras = {"mixed_compiler": MIXED_TOOLS / "compile_mixed.cjs",
              "mixed_runtime_template": MIXED_TOOLS / "runtime.mixed.cjs.in",
              "mixed_frontend": Path(__file__).resolve()}
    for name, path in extras.items():
        resolved = jf._no_links(path)
        if not resolved.is_file():
            raise MixedModuleError(f"Required trusted mixed helper is missing: {name}")
        files[name] = {"path": str(resolved), "sha256": jf._hash(resolved)}
    return {**base, "backend": BACKEND, "files": files, "mixed_mode": MODE}


def _check_tools(toolchain):
    for item in toolchain["files"].values():
        path = jf._no_links(item["path"])
        if not path.is_file() or jf._hash(path) != item["sha256"]:
            raise MixedModuleError("Pinned parser/runtime/mixed tool changed")


def _parse(source, language, functions, toolchain):
    _check_tools(toolchain)
    files = toolchain["files"]
    command = [files["node"]["path"], "--no-addons", "--max-old-space-size=256",
               files["mixed_compiler"]["path"], files["typescript"]["path"]]
    request = {"source": source, "language": language, "functions": functions}
    try:
        process = subprocess.run(command, input=_encoded(request), capture_output=True, text=True,
                                 encoding="utf-8", errors="strict", cwd=MIXED_TOOLS,
                                 env=jf.clean_node_environment(), timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as exc:
        raise MixedModuleError(f"Trusted mixed parser did not complete: {type(exc).__name__}") from exc
    _check_tools(toolchain)
    if len(process.stdout.encode("utf-8")) > 16 * 1024 * 1024 or len(process.stderr) > 1024 * 1024:
        raise MixedModuleError("Mixed parser protocol exceeded output budget")
    try:
        response = json.loads(process.stdout, object_pairs_hook=jf._pairs)
    except (json.JSONDecodeError, ValueError) as exc:
        raise MixedModuleError("Trusted mixed parser returned invalid JSON") from exc
    if not isinstance(response, dict):
        raise MixedModuleError("Trusted mixed parser response must be an object")
    if process.returncode or response.get("status") != "ok":
        raise MixedModuleError(str(response.get("error", "Mixed parser failed"))[:2048])
    result = response["result"]
    if result.get("compiler_version") != toolchain["typescript_version"] or result.get("source_executed") is not False:
        raise MixedModuleError("Mixed parser metadata differs from pinned toolchain")
    loaded = result.get("loaded_files")
    allowed = {Path(files[name]["path"]).resolve() for name in ("mixed_compiler", "typescript")}
    if not isinstance(loaded, list) or {Path(value).resolve() for value in loaded} != allowed:
        raise MixedModuleError("Mixed parser loaded an unpinned non-builtin dependency")
    result["compiler_execution"] = {"argv": command, "returncode": process.returncode,
                                    "target_executed": False, "protocol": "bounded JSON over stdin/stdout"}
    return result


def _encode_program(parsed, seed, runtime_template):
    """Reuse the production format-2 codec primitives; emit the mixed factory."""
    if jf.FORMAT_VERSION != 2:
        raise MixedModuleError("Mixed-module adapter requires upstream format 2")
    closure = parsed["helper_closure"]
    indexes = {name: i for i, name in enumerate(closure)}
    encoded, functions_meta = bytearray(), []
    evidence, codec_hashes, opcode_tables = {}, set(), set()
    for name in closure:
        fn = parsed["functions"][name]
        identifier = indexes[name]
        codec = jf._function_codec(seed, identifier)
        codec_sha256 = hashlib.sha256(jf._encoded(codec).encode("ascii")).hexdigest()
        if codec_sha256 in codec_hashes or tuple(codec["tokens"]) in opcode_tables:
            raise MixedModuleError("function-local codec collision")
        codec_hashes.add(codec_sha256)
        opcode_tables.add(tuple(codec["tokens"]))
        blob, positions = jf._encode_function(fn, indexes, codec)
        functions_meta.append({"slots": list(fn["slots"]), "offset": len(encoded), "bytes": len(blob),
                               "positions": positions, "codec": codec})
        encoded.extend(blob)
        evidence[name] = {"parameters": fn["parameters"], "helpers": fn["helpers"],
                          "instruction_count": len(fn["code"]), "virtualized": True,
                          "vm_function_id": identifier, "encoded_bytes": len(blob),
                          "encoded_sha256": hashlib.sha256(blob).hexdigest(),
                          "codec_sha256": codec_sha256,
                          "instruction_offsets_sha256": hashlib.sha256(
                              jf._encoded(positions).encode("ascii")).hexdigest()}
    metadata = jf._encoded(functions_meta).encode("ascii")
    digest = hashlib.sha256(metadata + encoded).hexdigest()
    engines_block, hardening = _jrh.emit_engines(seed, len(functions_meta), "mixed")
    getters = "[" + ", ".join("() => " + name for name in closure) + "]"
    substitutions = {"ENGINES": engines_block,
                     "BLOB": json.dumps(encoded.hex()), "FUNCTIONS": metadata.decode("ascii"),
                     "DIGEST": json.dumps(digest), "NAMES": json.dumps(closure),
                     "GETTERS": getters}
    runtime = runtime_template
    for token, value in substitutions.items():
        runtime = runtime.replace("@" + token + "@", value)
    if "@" in re.sub(r"node:\w+", "", runtime):
        # Guard against an unsubstituted placeholder surviving into the artifact.
        leftover = re.findall(r"@[A-Za-z_]+@", runtime)
        if leftover:
            raise MixedModuleError("Unsubstituted mixed runtime placeholder: " + leftover[0])
    coverage = {"schema_version": 1, "backend": BACKEND, "protection": "javascript-mixed-module-custom-vm",
                "protection_mode": MODE, "selected_functions": list(parsed["exported_functions"]),
                "exported_functions": list(closure), "validation_exports": [],
                "helper_closure": list(closure), "functions": evidence, "opcode_bits": 16,
                "format_version": jf.FORMAT_VERSION,
                "encoding": "function-local PC/key fetch codec with instruction-context plaintext operand feedback",
                "fetch_encoding": "position_key_affine_rotate_xor_v1",
                "operand_encoding": "record_pc_opcode_key_plaintext_feedback32_v1",
                "operand_value_semantics": "binary64 hex Number tags, decimal BigInt tags, boolean/null/undefined tags",
                "decode_scope": "current_instruction", "decoded_instruction_cache": False,
                "opcode_scope": "per_function", "codec_scope": "per_function", "codec_count": len(functions_meta),
                "dispatcher": "per_function_flattened_indirect_dispatch", "runtime_hardening": hardening,
                "encoded_sha256": hashlib.sha256(encoded).hexdigest(), "encoded_bytes": len(encoded),
                "metadata_sha256": hashlib.sha256(metadata).hexdigest(),
                "integrity": {"algorithm": "SHA-256(canonical_metadata || encoded_program)",
                              "checked_at": "first_selected_call", "authenticated": False,
                              "covers_codec_and_offsets": True, "covers_runtime_code": False},
                "kagura_passes_applied": False, "requested_core_passes": [],
                "mixed_runtime_namespace": "hoisted_lazy_factory",
                "module_global_values": "rejected_not_frozen",
                "helper_binding": "identity_checked_at_reached_call",
                "builtin_binding": "captured_at_first_call_monkeypatching_out_of_contract",
                "original_selected_bodies_in_protected_artifact": False,
                "module_text_outside_replacements": "preserved_in_original_order",
                "execution_authorized": False,
                "qualification": "Experimental opt-in transformation; per-artifact execution/functional/performance/attack qualification is required."}
    return runtime, coverage, evidence


def _generate(source_text, language, functions, toolchain, seed):
    parsed = _parse(source_text, language, functions, toolchain)
    closure = parsed["helper_closure"]
    runtime_template = Path(toolchain["files"]["mixed_runtime_template"]["path"]).read_text(encoding="utf-8")
    runtime_block, coverage, evidence = _encode_program(parsed, seed, runtime_template)

    working = parsed["working_source"]
    base = working.encode("utf-8")
    if len(base) != parsed["working_source_bytes"]:
        raise MixedModuleError("Working-source byte length disagreement")
    indexes = {name: evidence[name]["vm_function_id"] for name in closure}
    spans = {span["name"]: span for span in parsed["spans"]}
    if set(spans) != set(closure):
        raise MixedModuleError("Span/closure disagreement")

    edits = [(parsed["prologue_end"], parsed["prologue_end"], ("\n" + runtime_block + "\n").encode("utf-8"))]
    replacements = []
    for name in closure:
        span = spans[name]
        params = span["parameters"]
        if any(not isinstance(p, str) for p in params):
            raise MixedModuleError("Selected/helper parameter names were not resolvable")
        paramlist = ", ".join(params)
        wrapper = (f"function {name}({paramlist}) {{ return _arm_enter({indexes[name]}, [{paramlist}]); }}")
        wrapper_bytes = wrapper.encode("utf-8")
        edits.append((span["byte_start"], span["byte_end"], wrapper_bytes))
        replacements.append({"function": name, "working_utf8_start": span["byte_start"],
                             "working_utf8_end": span["byte_end"],
                             "original_declaration_sha256": hashlib.sha256(base[span["byte_start"]:span["byte_end"]]).hexdigest(),
                             "replacement_sha256": hashlib.sha256(wrapper_bytes).hexdigest()})
    edits.sort(key=lambda item: (item[0], item[1]))
    out, cursor = bytearray(), 0
    for start, end, repl in edits:
        if start < cursor:
            raise MixedModuleError("Overlapping replacement spans")
        out += base[cursor:start]
        out += repl
        cursor = end
    out += base[cursor:]
    protected = parsed["shebang"] + bytes(out).decode("utf-8")
    baseline = parsed["shebang"] + working

    coverage = {**coverage, "replacements": replacements,
                "original_module_source_sha256": _digest_text(source_text),
                "working_source_sha256": _digest_text(working),
                "transpiled_typescript": bool(parsed["transpiled"]),
                "preserved_unprotected_functions": parsed["unprotected_top_level_functions"]}
    inspection = {"schema_version": 1, "backend": BACKEND, "protection_mode": MODE, "language": language,
                  "route_status": "available", "blockers": [], "experimental": True,
                  "source_sha256": _digest_text(source_text), "working_source_sha256": _digest_text(working),
                  "functions": {name: {"parameters": evidence[name]["parameters"],
                                       "helpers": evidence[name]["helpers"],
                                       "instruction_count": evidence[name]["instruction_count"]} for name in closure},
                  "exported_functions": list(closure), "protected_functions": list(closure),
                  "validation_exports": [], "transpiled_typescript": bool(parsed["transpiled"]),
                  "unprotected_top_level_functions": parsed["unprotected_top_level_functions"],
                  "original_module_text_preserved_outside_replacements": True,
                  "scope_mode": "selected_body_replacement_with_transitive_helpers",
                  "target": "node-commonjs-mixed-module", "artifact": "javascript_module",
                  "source_executed": False, "deployment_context": "original_module_package_context_required",
                  "functional_evaluation": "not_performed", "type_checking": parsed["type_checking"],
                  "limitations": list(LIMITATIONS)}
    return protected, baseline, coverage, inspection, parsed


def inspect_project(project_path):
    path = jf._no_links(project_path)
    if not path.is_file() or path.stat().st_size > 256 * 1024:
        raise MixedModuleError("A trusted project JSON <=256 KiB is required")
    try:
        project = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=jf._pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise MixedModuleError("Project must be UTF-8 JSON") from exc
    required = {"schema_version", "name", "language", "sources", "functions", "protection_mode"}
    if not isinstance(project, dict) or set(project) != required:
        raise MixedModuleError("Mixed project requires schema_version/name/language/sources/functions/protection_mode only")
    if (type(project["schema_version"]) is not int or project["schema_version"] != 1
            or project["language"] not in {"javascript", "typescript"} or project["protection_mode"] != MODE):
        raise MixedModuleError("Use schema_version 1, language javascript/typescript, protection_mode mixed_module")
    if not isinstance(project["name"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", project["name"]):
        raise MixedModuleError("Project name must be a short ASCII identifier")
    values = project["sources"]
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], str):
        raise MixedModuleError("Exactly one owned source module is required")
    value, win = values[0], PureWindowsPath(values[0])
    if not value or "\x00" in value or Path(value).is_absolute() or win.drive or ".." in win.parts or ":" in value:
        raise MixedModuleError("Source must be relative and stay inside the project")
    source = jf._no_links(path.parent / value.replace("\\", "/"))
    expected = ".ts" if project["language"] == "typescript" else ".js"
    if not source.is_relative_to(path.parent) or source.suffix != expected or not source.is_file() or source.stat().st_size > 524288:
        raise MixedModuleError("Source extension/size/location differs from declared language")
    functions = project["functions"]
    if (not isinstance(functions, list) or not 1 <= len(functions) <= 64
            or any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]{0,127}", name) for name in functions)
            or len(set(functions)) != len(functions)):
        raise MixedModuleError("Select 1..64 unique ordinary function names")
    source_bytes = source.read_bytes()
    source_text = source_bytes.decode("utf-8-sig")
    toolchain = discover_toolchain()
    _, _, coverage, inspection, _ = _generate(source_text, project["language"], functions, toolchain, 0)
    return {**inspection, "name": project["name"], "project_path": str(path), "project_root": str(path.parent),
            "sources": [str(source)], "source_files": [str(source)], "functions": list(functions),
            "function_signatures": inspection["functions"], "toolchain": toolchain,
            "tool_hashes": {v["path"]: v["sha256"] for v in toolchain["files"].values()},
            "compiler_inputs": {v["path"]: v["sha256"] for v in toolchain["files"].values()},
            "input_hashes": {str(path): jf._hash(path), str(source): jf._hash(source)},
            "source_sha256": hashlib.sha256(source_bytes).hexdigest()}


def _node_check(toolchain, path, env):
    """Syntax-check the generated module without executing it (node --check)."""
    command = [toolchain["files"]["node"]["path"], "--no-addons", "--check", str(path)]
    try:
        process = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                                 errors="replace", env=env, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"argv": command, "returncode": None, "error": type(exc).__name__, "executed_target": False}
    return {"argv": command, "returncode": process.returncode, "target_executed": False,
            "stderr": process.stderr[:2048], "protocol": "node --check syntax only"}


def build_project(project_path, output_dir, *, workspace_root, seed=None):
    project = inspect_project(project_path)
    root, output = jf._no_links(workspace_root), jf._no_links(output_dir)
    if (not root.is_dir() or not Path(project["project_path"]).is_relative_to(root)
            or not output.is_relative_to(root / ".runs") or output == root / ".runs" or output.exists()
            or output.is_relative_to(Path(project["project_root"]))):
        raise MixedModuleError("Owned source and fresh output under workspace/.runs outside source are required")
    stop = root / ".runs/defense-loop/STOP"
    if stop.exists():
        raise MixedModuleError("Defense STOP marker exists")
    if seed is None:
        import secrets
        seed = secrets.randbits(128)
    if type(seed) is not int or not 0 <= seed < 2 ** 256:
        raise MixedModuleError("seed must be an integer in 0..2**256-1")
    source = Path(project["sources"][0])
    source_bytes = source.read_bytes()
    if hashlib.sha256(source_bytes).hexdigest() != project["source_sha256"]:
        raise MixedModuleError("Source changed after inspection")
    toolchain = project["toolchain"]
    protected, baseline, coverage, inspection, parsed = _generate(
        source_bytes.decode("utf-8-sig"), project["language"], project["functions"], toolchain, seed)
    started = time.monotonic()
    report = {"schema_version": 1, "backend": BACKEND, "protection_mode": MODE, "status": "failed",
              "project": project, "started_utc": datetime.now(timezone.utc).isoformat(), "seed": seed,
              "output_dir": str(output), "toolchain": toolchain, "tool_hashes": project["tool_hashes"],
              "source_executed": False, "execution_authorized": False,
              "functional_evaluation": "not_performed", "performance_evaluation": "not_performed",
              "external_attack_evaluation": "not_performed", "limitations": list(LIMITATIONS),
              "commands": [parsed["compiler_execution"]]}
    output.mkdir(parents=True, exist_ok=False)
    try:
        jf._write(output / ("source" + source.suffix), source_bytes.decode("utf-8-sig"))
        jf._write(output / "baseline.cjs", baseline)
        jf._write(output / "protected.cjs", protected)
        check = _node_check(toolchain, output / "protected.cjs", jf.clean_node_environment())
        report["commands"].append(check)
        if check.get("returncode") != 0:
            raise MixedModuleError("Generated protected module failed node --check syntax validation")
        artifacts = {arm: {"path": str(output / (arm + ".cjs")), "sha256": jf._hash(output / (arm + ".cjs")),
                           "bytes": (output / (arm + ".cjs")).stat().st_size} for arm in ("baseline", "protected")}
        coverage["artifacts"] = artifacts
        jf._write(output / "coverage.json", _encoded(coverage) + "\n")
        report.update(status="artifact_created_unvalidated", artifacts=artifacts, coverage=coverage,
                      coverage_path=str(output / "coverage.json"), baseline=artifacts["baseline"]["path"],
                      protected=artifacts["protected"]["path"])
    except (OSError, ValueError) as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
    changed = []
    for name, digest in {**project["input_hashes"], **project["tool_hashes"]}.items():
        try:
            if jf._hash(jf._no_links(name)) != digest:
                changed.append(name)
        except (OSError, ValueError):
            changed.append(name)
    report.update(changed_inputs=changed, seconds=round(time.monotonic() - started, 6),
                  finished_utc=datetime.now(timezone.utc).isoformat())
    if changed or stop.exists():
        report.update(status="cancelled" if stop.exists() else "failed",
                      error="Pinned inputs/tools changed or STOP requested")
    report["artifact_hashes"] = {path.name: jf._hash(path) for path in output.iterdir() if path.is_file()}
    jf._write(output / "report.json", _encoded(report) + "\n")
    return report
