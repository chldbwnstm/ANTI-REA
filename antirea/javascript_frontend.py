"""Owned JavaScript/TypeScript scalar functions -> encoded custom JavaScript VM.

A hash-pinned installed TypeScript parser runs during inspection; target source
does not run. Type erasure alone is not protection: build lowers selected ASTs
and their helper closure to custom instructions interpreted by generated code.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import random
import re
import secrets
import shutil
import subprocess
import time

from .python_frontend import _no_links, _pairs
from . import javascript_runtime_hardening as _jrh


BACKEND = "javascript_vm"
TOOLS = Path(__file__).resolve().parents[1] / "tools" / "javascript_frontend"
OPS = ("const", "reset", "load", "init", "set", "update", "pop", "dup", "unary", "binary",
       "jump", "false", "true", "nonnull", "call", "builtin", "return")
if tuple(_jrh.JS_OPS) != OPS:
    raise ImportError("javascript_runtime_hardening opcode layout drifted from frontend OPS")
LIMITATIONS = [
    "Experimental single-module pure Number/BigInt/boolean subset, not whole JavaScript/TypeScript applications.",
    "Installed TypeScript AST parser executes during inspection; input target code never executes during inspect/build.",
    "TS primitive annotations are syntax-checked/erased, not full TypeScript semantic type checking.",
    "No imports, objects, arrays, closures, recursion, async, generators, classes, enums, namespaces or decorators.",
    "Only lexical let/const locals; var, destructuring, default/rest/optional parameters and property mutation are rejected.",
    "Public inputs are primitive Number/BigInt/boolean; dynamic object coercion and ambient global behavior are outside scope.",
    "Native JS operators preserve Number/BigInt behavior; resource limits/exception traces/messages are not equivalent guarantees.",
    "Function-local codecs/opcodes and instruction fetch decoding are obfuscation; keys/runtime remain locally available.",
    "Only the active instruction is decoded per interpreter frame; suspended helper callers can retain their call instruction.",
    "No whole decoded-program cache; JavaScript GC, heap snapshots and runtime hooks can still expose values.",
    "Import-time SHA-256 binds encoded instructions plus codec/offset/slot metadata, not runtime code; it is not authenticated tamper resistance.",
    "Kagura/native hardening passes are not applied; this is a separate JavaScript VM backend.",
    "baseline.cjs, source snapshots, reports and intermediate instructions are private defender evidence.",
    "Build success does not establish functional equivalence, performance acceptance or attack resistance.",
]


class JavaScriptFrontendError(ValueError):
    pass


def _hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def clean_node_environment():
    env = os.environ.copy()
    for key in list(env):
        if key.upper() in {"NODE_OPTIONS", "NODE_PATH"}:
            del env[key]
    return env


def discover_toolchain():
    """Locate existing tools only; no npm execution/download or package hooks."""
    node_value = shutil.which("node")
    candidates = []
    user = Path.home()
    candidates.extend([user / "AppData/Roaming/npm/node_modules/typescript/lib/typescript.js",
                       user / "AppData/Local/Programs/cursor/resources/app/extensions/node_modules/typescript/lib/typescript.js"])
    vscode = user / "AppData/Local/Programs/Microsoft VS Code"
    if vscode.is_dir():
        candidates.extend(sorted(vscode.glob("*/resources/app/extensions/node_modules/typescript/lib/typescript.js")))
        candidates.append(vscode / "resources/app/extensions/node_modules/typescript/lib/typescript.js")
    candidates.extend([Path("C:/Program Files/Microsoft VS Code/resources/app/extensions/node_modules/typescript/lib/typescript.js"),
                       Path("C:/Program Files/nodejs/node_modules/typescript/lib/typescript.js")])
    compiler = next((path for path in candidates if path.is_file()), None)
    if not node_value or compiler is None:
        raise JavaScriptFrontendError("Existing Node and TypeScript compiler library are required; no automatic installation")
    node, compiler = _no_links(node_value), _no_links(compiler)
    package = _no_links(compiler.parent.parent / "package.json")
    metadata = json.loads(package.read_text(encoding="utf-8"))
    if metadata.get("name") != "typescript" or not isinstance(metadata.get("version"), str):
        raise JavaScriptFrontendError("Invalid installed TypeScript package metadata")
    paths = {"node": node, "typescript": compiler, "typescript_package": package,
             "compiler_helper": TOOLS / "compile.cjs", "runtime_template": TOOLS / "runtime.cjs.in",
             "validator_helper": TOOLS / "validate.cjs", "validator": Path(__file__).with_name("javascript_validate.py"),
             "runtime_hardening": Path(__file__).with_name("javascript_runtime_hardening.py"),
             "validation_evidence": Path(__file__).with_name("script_validation_evidence.py"),
             "frontend": Path(__file__).resolve()}
    for name, path in list(paths.items()):
        paths[name] = _no_links(path)
        if not paths[name].is_file():
            raise JavaScriptFrontendError(f"Required trusted helper is missing: {name}")
    # typescript.js is the compiler's self-contained CommonJS bundle. Its only
    # runtime imports are Node builtins; no ambient npm resolution is requested.
    return {"status": "available", "typescript_version": metadata["version"],
            "files": {name: {"path": str(path), "sha256": _hash(path)} for name, path in paths.items()},
            "source_execution": False, "dependency_loading": "absolute TypeScript bundle and Node builtins only"}


def _check_tools(toolchain):
    for item in toolchain["files"].values():
        path = _no_links(item["path"])
        if not path.is_file() or _hash(path) != item["sha256"]:
            raise JavaScriptFrontendError("Pinned parser/runtime tool changed")


def _parse(source, language, functions, toolchain, *, build=False):
    _check_tools(toolchain)
    files = toolchain["files"]
    command = [files["node"]["path"], "--no-addons", "--max-old-space-size=256",
               files["compiler_helper"]["path"], files["typescript"]["path"]]
    request = {"source": source, "language": language, "functions": functions,
               "action": "build" if build else "inspect"}
    try:
        process = subprocess.run(command, input=_encoded(request), capture_output=True, text=True,
                                 encoding="utf-8", errors="strict", cwd=TOOLS,
                                 env=clean_node_environment(), timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as exc:
        raise JavaScriptFrontendError(f"Trusted parser did not complete: {type(exc).__name__}") from exc
    _check_tools(toolchain)
    if len(process.stdout.encode("utf-8")) > 16 * 1024 * 1024 or len(process.stderr) > 1024 * 1024:
        raise JavaScriptFrontendError("Parser protocol exceeded output budget")
    try:
        response = json.loads(process.stdout, object_pairs_hook=_pairs)
    except (json.JSONDecodeError, ValueError) as exc:
        raise JavaScriptFrontendError("Trusted parser returned invalid JSON") from exc
    if not isinstance(response, dict):
        raise JavaScriptFrontendError("Trusted parser response must be an object")
    if process.returncode or response.get("status") != "ok":
        raise JavaScriptFrontendError(str(response.get("error", "Parser failed"))[:2048])
    result = response["result"]
    if result.get("compiler_version") != toolchain["typescript_version"] or result.get("source_executed") is not False:
        raise JavaScriptFrontendError("Parser metadata differs from pinned toolchain")
    loaded = result.get("loaded_files")
    allowed = {Path(files[name]["path"]).resolve() for name in ("compiler_helper", "typescript")}
    if not isinstance(loaded, list) or {Path(value).resolve() for value in loaded} != allowed:
        raise JavaScriptFrontendError("Parser loaded an unpinned non-builtin dependency")
    result["compiler_execution"] = {"argv": command, "returncode": process.returncode,
                                    "target_executed": False, "protocol": "bounded JSON over stdin/stdout"}
    return result


def inspect_project(project_path):
    path = _no_links(project_path)
    if not path.is_file() or path.stat().st_size > 256 * 1024:
        raise JavaScriptFrontendError("A trusted project JSON <=256 KiB is required")
    project = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=_pairs)
    if not isinstance(project, dict) or set(project) != {"schema_version", "name", "language", "sources", "functions"}:
        raise JavaScriptFrontendError("Project requires schema_version/name/language/sources/functions only")
    if (type(project["schema_version"]) is not int or project["schema_version"] != 1
            or not isinstance(project["language"], str) or project["language"] not in {"javascript", "typescript"}):
        raise JavaScriptFrontendError("Use schema_version 1 and language javascript or typescript")
    if not isinstance(project["name"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", project["name"]):
        raise JavaScriptFrontendError("Project name must be a short ASCII identifier")
    values = project["sources"]
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], str):
        raise JavaScriptFrontendError("Exactly one owned source module is required")
    value = values[0]
    win = PureWindowsPath(value)
    if not value or "\x00" in value or Path(value).is_absolute() or win.drive or ".." in win.parts or ":" in value:
        raise JavaScriptFrontendError("Source must be relative and stay inside the project")
    source = _no_links(path.parent / value.replace("\\", "/"))
    expected = ".ts" if project["language"] == "typescript" else ".js"
    if not source.is_relative_to(path.parent) or source.suffix != expected or not source.is_file() or source.stat().st_size > 524288:
        raise JavaScriptFrontendError("Source extension/size/location differs from declared language")
    functions = project["functions"]
    if (not isinstance(functions, list) or not 1 <= len(functions) <= 64
            or any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]{0,127}", name) for name in functions)
            or len(set(functions)) != len(functions)):
        raise JavaScriptFrontendError("Select 1..64 unique ordinary function names")
    source_bytes = source.read_bytes()
    toolchain = discover_toolchain()
    parsed = _parse(source_bytes.decode("utf-8-sig"), project["language"], functions, toolchain)
    signatures = {name: {"parameters": fn["parameters"], "helpers": fn["helpers"], "instruction_count": len(fn["code"])}
                  for name, fn in parsed["functions"].items()}
    return {"schema_version": 1, "backend": BACKEND, "route_status": "available", "blockers": [],
            "name": project["name"], "language": project["language"], "project_path": str(path),
            "project_root": str(path.parent), "sources": [str(source)], "source_files": [str(source)],
            "functions": functions, "exported_functions": functions, "protected_functions": parsed["helper_closure"],
            "function_signatures": signatures, "input_hashes": {str(path): _hash(path), str(source): _hash(source)},
            "source_sha256": hashlib.sha256(source_bytes).hexdigest(), "source_executed": False,
            "toolchain": toolchain, "tool_hashes": {v["path"]: v["sha256"] for v in toolchain["files"].values()},
            "compiler_inputs": {v["path"]: v["sha256"] for v in toolchain["files"].values()},
            "scope_mode": "explicit_roots_and_transitive_helpers", "experimental": True,
            "target": "node-commonjs-scalar", "artifact": "javascript_module",
            "type_checking": parsed["type_checking"], "limitations": list(LIMITATIONS)}


def _write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(value)


FORMAT_VERSION = 2


def _function_codec(seed, identifier):
    """Function-local deterministic obfuscation, not a secret-key construction."""
    material = (b"ANTI-REA-javascript-context-v2\0" + seed.to_bytes(32, "big")
                + identifier.to_bytes(4, "big"))
    rng = random.Random(int.from_bytes(hashlib.sha256(material).digest(), "big"))
    key = rng.getrandbits(64)
    # Two uint32 words survive JSON and JavaScript Number exactly. Never encode
    # a 64-bit integer in a JSON number or narrow a target program value.
    return {"key": [key & 0xffffffff, key >> 32],
            "tokens": rng.sample(range(256, 65536), len(OPS)),
            "multiply": rng.getrandbits(32) | 1, "add": rng.getrandbits(32),
            "mix": rng.getrandbits(32) | 1, "rotate": rng.randrange(7),
            "operand_multiply": rng.getrandbits(32) | 1,
            "operand_add": rng.getrandbits(32)}


def _operand_context(codec, record_pc, opcode):
    return ((record_pc * codec["operand_multiply"]) ^ opcode ^ codec["key"][0]
            ^ codec["key"][1] ^ codec["operand_add"]) & 0xffffffff


def _operand_step(codec, state, plain):
    rotated = ((state << 5) | (state >> 27)) & 0xffffffff
    return (rotated * codec["operand_multiply"] + plain + codec["operand_add"]) & 0xffffffff


def _encode_fetch_byte(codec, position, plain):
    mixed = (position * codec["multiply"] + codec["add"]) & 0xffffffff
    mixed ^= mixed >> 13
    mixed = (mixed * codec["mix"]) & 0xffffffff
    mixed ^= mixed >> 17
    key_byte = (codec["key"][(position >> 2) & 1] >> (8 * (position & 3))) & 255
    mask = (mixed ^ key_byte) & 255
    rotation = ((position + codec["rotate"]) % 7) + 1
    value = (plain + mask) & 255
    return (((value << rotation) | (value >> (8 - rotation))) & 255) ^ ((mixed >> 8) & 255)


def _encode_function(function, indexes, codec):
    """Individual records; jump targets remain instruction IDs, never byte PCs."""
    encoded, positions = bytearray(), [0]
    for instruction in function["code"]:
        operation, *operands = instruction
        if operation == "call":
            operands[0] = indexes[operands[0]]
        opcode = codec["tokens"][OPS.index(operation)]
        record_pc = len(encoded)
        record = bytearray(opcode.to_bytes(2, "big"))
        state = _operand_context(codec, record_pc, opcode)
        # Number values remain binary64 hex tags; BigInt remains a decimal string.
        # Codec fixed-width arithmetic is never applied to target operand values.
        for plain in _encoded(operands).encode("ascii"):
            mask = (state ^ (state >> 11) ^ (state >> 23)) & 255
            record.append(plain ^ mask)
            state = _operand_step(codec, state, plain)
        encoded.extend(_encode_fetch_byte(codec, record_pc + i, value)
                       for i, value in enumerate(record))
        positions.append(len(encoded))
    return bytes(encoded), positions


def _generate(parsed, seed):
    if type(seed) is not int or not 0 <= seed < 2 ** 256:
        raise JavaScriptFrontendError("seed must be an integer in 0..2**256-1")
    indexes = {name: i for i, name in enumerate(parsed["helper_closure"])}
    encoded, functions = bytearray(), []
    evidence, codec_hashes, opcode_tables = {}, set(), set()
    for name in parsed["helper_closure"]:
        fn = parsed["functions"][name]
        identifier = indexes[name]
        codec = _function_codec(seed, identifier)
        codec_sha256 = hashlib.sha256(_encoded(codec).encode("ascii")).hexdigest()
        if codec_sha256 in codec_hashes or tuple(codec["tokens"]) in opcode_tables:
            raise JavaScriptFrontendError("function-local codec collision")
        codec_hashes.add(codec_sha256)
        opcode_tables.add(tuple(codec["tokens"]))
        blob, positions = _encode_function(fn, indexes, codec)
        functions.append({"slots": list(fn["slots"]), "offset": len(encoded), "bytes": len(blob),
                          "positions": positions, "codec": codec})
        encoded.extend(blob)
        evidence[name] = {"parameters": fn["parameters"], "helpers": fn["helpers"],
                          "instruction_count": len(fn["code"]), "virtualized": True,
                          "vm_function_id": identifier, "encoded_bytes": len(blob),
                          "encoded_sha256": hashlib.sha256(blob).hexdigest(),
                          "codec_sha256": codec_sha256,
                          "instruction_offsets_sha256": hashlib.sha256(
                              _encoded(positions).encode("ascii")).hexdigest()}
    metadata = _encoded(functions).encode("ascii")
    digest = hashlib.sha256(metadata + encoded).hexdigest()
    runtime = (TOOLS / "runtime.cjs.in").read_text(encoding="utf-8")
    engines_block, hardening = _jrh.emit_engines(seed, len(functions), "pure")
    wrappers = []
    for name in parsed["exported_functions"]:
        parameters = ", ".join(parsed["functions"][name]["parameters"])
        wrappers.append(f"exported[{json.dumps(name)}] = function {name}({parameters}) {{ return _ar_enter({indexes[name]}, [{parameters}]); }};")
    substitutions = {"ENGINES": engines_block,
                     "BLOB": json.dumps(encoded.hex()), "FUNCTIONS": metadata.decode("ascii"),
                     "DIGEST": json.dumps(digest), "WRAPPERS": "\n  ".join(wrappers)}
    for token, value in substitutions.items():
        runtime = runtime.replace("@" + token + "@", value)
    leftover = re.findall(r"@[A-Za-z_]+@", runtime)
    if leftover:
        raise JavaScriptFrontendError("Unsubstituted runtime placeholder: " + leftover[0])
    coverage = {"schema_version": 1, "backend": BACKEND, "protection": "javascript-custom-vm",
                "selected_functions": parsed["exported_functions"], "exported_functions": parsed["exported_functions"],
                "validation_exports": parsed["exported_functions"], "helper_closure": parsed["helper_closure"],
                "functions": evidence, "opcode_bits": 16, "format_version": FORMAT_VERSION,
                "encoding": "function-local PC/key fetch codec with instruction-context plaintext operand feedback",
                "fetch_encoding": "position_key_affine_rotate_xor_v1",
                "operand_encoding": "record_pc_opcode_key_plaintext_feedback32_v1",
                "operand_value_semantics": "binary64 hex Number tags, decimal BigInt tags, boolean/null/undefined tags",
                "decode_scope": "current_instruction", "decoded_instruction_cache": False,
                "opcode_scope": "per_function", "codec_scope": "per_function",
                "codec_count": len(functions), "dispatcher": "per_function_flattened_indirect_dispatch",
                "runtime_hardening": hardening,
                "encoded_sha256": hashlib.sha256(encoded).hexdigest(), "encoded_bytes": len(encoded),
                "metadata_sha256": hashlib.sha256(metadata).hexdigest(),
                "integrity": {"algorithm": "SHA-256(canonical_metadata || encoded_program)",
                              "checked_at": "module_import", "authenticated": False,
                              "covers_codec_and_offsets": True, "covers_runtime_code": False},
                "kagura_passes_applied": False, "requested_core_passes": [],
                "original_selected_bodies_in_protected_artifact": False,
                "qualification": "Generated transformation evidence; separate functional/performance/external evaluation required."}
    return runtime, coverage


def build_project(project_path, output_dir, *, workspace_root, seed=None):
    project = inspect_project(project_path)
    root, output = _no_links(workspace_root), _no_links(output_dir)
    if (not root.is_dir() or not Path(project["project_path"]).is_relative_to(root)
            or not output.is_relative_to(root / ".runs") or output == root / ".runs" or output.exists()
            or output.is_relative_to(Path(project["project_root"]))):
        raise JavaScriptFrontendError("Owned source and fresh output under workspace/.runs outside source are required")
    stop = root / ".runs/defense-loop/STOP"
    if stop.exists():
        raise JavaScriptFrontendError("Defense STOP marker exists")
    if seed is None:
        seed = secrets.randbits(128)
    if type(seed) is not int or not 0 <= seed < 2 ** 256:
        raise JavaScriptFrontendError("seed must be an integer in 0..2**256-1")
    source = Path(project["sources"][0])
    source_bytes = source.read_bytes()
    if hashlib.sha256(source_bytes).hexdigest() != project["source_sha256"]:
        raise JavaScriptFrontendError("Source changed after inspection")
    parsed = _parse(source_bytes.decode("utf-8-sig"), project["language"], project["functions"], project["toolchain"], build=True)
    runtime, coverage = _generate(parsed, seed)
    started = time.monotonic()
    report = {"schema_version": 1, "backend": BACKEND, "status": "failed", "project": project,
              "started_utc": datetime.now(timezone.utc).isoformat(), "seed": seed, "output_dir": str(output),
              "toolchain": project["toolchain"], "tool_hashes": project["tool_hashes"], "source_executed": False,
              "functional_evaluation": "not_performed", "performance_evaluation": "not_performed",
              "external_attack_evaluation": "not_performed", "limitations": list(LIMITATIONS),
              "commands": [parsed["compiler_execution"]]}
    output.mkdir(parents=True, exist_ok=False)
    try:
        _write(output / ("source" + source.suffix), source_bytes.decode("utf-8-sig"))
        _write(output / "baseline.cjs", parsed["baseline"])
        _write(output / "protected.cjs", runtime)
        artifacts = {arm: {"path": str(output / (arm + ".cjs")), "sha256": _hash(output / (arm + ".cjs")),
                           "bytes": (output / (arm + ".cjs")).stat().st_size} for arm in ("baseline", "protected")}
        coverage["artifacts"] = artifacts
        _write(output / "coverage.json", _encoded(coverage) + "\n")
        report.update(status="artifact_created_unvalidated", artifacts=artifacts, coverage=coverage,
                      coverage_path=str(output / "coverage.json"), baseline=artifacts["baseline"]["path"], protected=artifacts["protected"]["path"])
    except (OSError, ValueError) as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
    changed = []
    for name, digest in {**project["input_hashes"], **project["tool_hashes"]}.items():
        try:
            if _hash(_no_links(name)) != digest:
                changed.append(name)
        except (OSError, ValueError):
            changed.append(name)
    report.update(changed_inputs=changed, seconds=round(time.monotonic() - started, 6),
                  finished_utc=datetime.now(timezone.utc).isoformat())
    if changed or stop.exists():
        report.update(status="cancelled" if stop.exists() else "failed", error="Pinned inputs/tools changed or STOP requested")
    report["artifact_hashes"] = {path.name: _hash(path) for path in output.iterdir() if path.is_file()}
    _write(output / "report.json", _encoded(report) + "\n")
    return report
