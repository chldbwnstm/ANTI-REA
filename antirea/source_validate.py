"""Composite validation for source-to-native lowering frontends.

A native baseline/protected match cannot prove a source lowering is correct.
Explicit source validation therefore also runs the original owned language code.
No received artifacts are executed and process boundaries are not sandboxes.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from . import native_validate
from .bindings import validate_contract
from .protectors import _json, _no_links, _read


BACKENDS = {"dotnet_il_native", "jvm_bytecode_native", "go_typed_native", "swift_llvm_native"}


def verify_source_contract(report, contract):
    """Bind signed scalar semantics to source metadata, not merely LLVM widths.

    Caller-chosen parameter names and the binding's library name are irrelevant
    to an ABI signature. Export names, return types, arity and ordered argument
    types must all agree. No source, compiler or runtime is executed here.
    """
    normalized = validate_contract(contract)

    def signatures(functions):
        checked = validate_contract({"schema_version": 1, "library_name": "source_signature",
                                     "functions": functions})
        return {item["name"]: {"return_type": item["return_type"],
                               "parameter_types": [p["type"] for p in item["parameters"]]}
                for item in checked["functions"]}

    def method_list(value):
        if (not isinstance(value, list) or not 1 <= len(value) <= 128
                or any(not isinstance(item, dict) for item in value)):
            raise ValueError("source method metadata must be a nonempty bounded list")
        return value

    def function(export, result, arguments):
        return {"name": export, "return_type": result,
                "parameters": [{"name": f"a{i}", "type": kind} for i, kind in enumerate(arguments)]}

    backend = report.get("backend")
    if backend == "dotnet_il_native":
        frontend = report.get("frontend")
        if not isinstance(frontend, dict):
            raise ValueError("C# source metadata is missing")
        scalar = {"Int32": "i32", "UInt32": "u32", "Int64": "i64", "UInt64": "u64"}
        expected = []
        for method in method_list(frontend.get("methods")):
            selector, metadata = method.get("selector"), method.get("metadata")
            if not isinstance(selector, dict) or not isinstance(metadata, dict):
                raise ValueError("C# method selector/metadata is malformed")
            result, arguments = metadata.get("return_type"), metadata.get("parameters")
            if (not isinstance(result, str) or result not in scalar
                    or not isinstance(arguments, list) or len(arguments) > 8
                    or any(not isinstance(kind, str) or kind not in scalar for kind in arguments)):
                raise ValueError("C# source signature uses unsupported scalar types")
            expected.append(function(selector.get("export"), scalar[result], [scalar[kind] for kind in arguments]))
        source = signatures(expected)
    elif backend == "jvm_bytecode_native":
        from .jvm_frontend import descriptor
        scalar = {"I": "i32", "J": "i64"}

        def jvm_signature(method):
            arguments, result = descriptor(method.get("descriptor"))
            return function(method.get("export"), scalar[result], [scalar[kind] for kind in arguments])

        methods = method_list(report.get("methods"))
        if any(type(method.get("is_root")) is not bool for method in methods):
            raise ValueError("JVM method root markers must be explicit booleans")
        source = signatures([jvm_signature(method) for method in methods if method["is_root"]])
        project = report.get("project")
        if not isinstance(project, dict):
            raise ValueError("JVM source selectors are missing")
        declared = signatures([jvm_signature(method) for method in method_list(project.get("methods"))])
        if source != declared:
            raise ValueError("JVM parsed root signatures differ from project selectors")
    elif backend == "go_typed_native":
        scalar = {"int32": "i32", "uint32": "u32", "int64": "i64", "uint64": "u64"}
        methods = method_list(report.get("methods"))
        if any(type(method.get("is_root")) is not bool for method in methods):
            raise ValueError("Go method root markers must be explicit booleans")
        expected = []
        roots = []
        for method in methods:
            if not method["is_root"]:
                continue
            result, arguments = method.get("return_type"), method.get("parameters")
            if (not isinstance(result, str) or result not in scalar
                    or not isinstance(arguments, list) or len(arguments) > 8
                    or any(not isinstance(kind, str) or kind not in scalar for kind in arguments)):
                raise ValueError("Go source signature uses unsupported scalar types")
            expected.append(function(method.get("export"), scalar[result], [scalar[kind] for kind in arguments]))
            roots.append((method.get("name"), method.get("export")))
        source = signatures(expected)
        project = report.get("project")
        if not isinstance(project, dict):
            raise ValueError("Go source selectors are missing")
        selectors = method_list(project.get("selectors"))
        declared = [(item.get("name"), item.get("export")) for item in selectors]
        if (any(not isinstance(name, str) or not isinstance(export, str) for name, export in roots + declared)
                or len(set(declared)) != len(declared) or sorted(roots) != sorted(declared)):
            raise ValueError("Go parsed root names/exports differ from project selectors")
    elif backend == "swift_llvm_native":
        expected = []
        for method in method_list(report.get("source_functions")):
            arguments = method.get("parameters")
            if not isinstance(arguments, list) or len(arguments) > 8 or any(not isinstance(item, dict) for item in arguments):
                raise ValueError("Swift source parameter metadata is malformed")
            expected.append(function(method.get("name"), method.get("return_type"), [item.get("type") for item in arguments]))
        source = signatures(expected)
        project = report.get("project")
        if not isinstance(project, dict) or project.get("functions") != list(source):
            raise ValueError("Swift source exports differ from project selectors")
    else:
        raise ValueError("source signature backend is unsupported")
    requested = signatures(normalized["functions"])
    if source != requested:
        raise ValueError("contract export names and exact signed scalar signatures must match original source metadata")
    return {"status": "matched", "backend": backend, "functions": source,
            "signedness": "original_source_metadata", "parameter_names_compared": False}


def _reference(backend, report, output, **kwargs):
    if backend == "dotnet_il_native":
        from .dotnet_frontend import verify_build
    elif backend == "jvm_bytecode_native":
        from .jvm_frontend import verify_build
    elif backend == "go_typed_native":
        from .go_frontend import verify_build
    elif backend == "swift_llvm_native":
        from .swift_frontend import verify_build
    else:
        raise ValueError("source reference backend is unsupported")
    return verify_build(report, output, include_protected=True, **kwargs)


def _reference_passed(reference, exports):
    if not isinstance(reference, dict) or reference.get("status") != "passed":
        return False
    methods = reference.get("methods")
    if not isinstance(methods, list) or len(methods) != len(exports):
        return False
    names = []
    for method in methods:
        if not isinstance(method, dict) or not isinstance(method.get("export"), str):
            return False
        names.append(method["export"])
        total = method.get("total")
        if type(total) is not int or total < 1:
            return False
        comparisons = method.get("comparisons")
        if not isinstance(comparisons, dict) or set(comparisons) != {"baseline", "protected"}:
            return False
        for entry in comparisons.values():
            if (not isinstance(entry, dict) or entry.get("status") != "passed"
                    or type(entry.get("matched")) is not int or type(entry.get("total")) is not int
                    or entry["matched"] != total or entry["total"] != total):
                return False
    return len(set(names)) == len(names) and set(names) == exports


def validate_lowered_build(report_path, contract_path, output_dir, *, workspace_root,
                           random_cases=8192, timeout_seconds=120):
    root = Path(os.path.abspath(workspace_root))
    report_path = Path(os.path.abspath(report_path))
    output = Path(os.path.abspath(output_dir))
    for path in (root, report_path, output):
        _no_links(path)
    if not report_path.is_relative_to(root / ".runs") or not output.is_relative_to(root / ".runs"):
        raise ValueError("lowered-source validation requires owned private .runs paths")
    if any(part.casefold() in {"attackerfolder", "rea-analysis-reports", "defense-loop"}
           for path in (report_path, output) for part in path.relative_to(root).parts):
        raise ValueError("received/shared artifacts cannot be source references")
    if output.exists():
        raise ValueError("source validation output must be fresh")
    if type(random_cases) is not int or not 1 <= random_cases <= 8192:
        raise ValueError("random_cases must be an integer in 1..8192")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
        raise ValueError("timeout_seconds must be an integer in 1..600")
    raw = _read(report_path, 16 * 1024 * 1024)
    contract_raw = _read(Path(contract_path), 256 * 1024)
    report = _json(raw)
    if (not isinstance(report, dict) or report.get("backend") not in BACKENDS
            or report.get("status") != "artifact_created_unvalidated"):
        raise ValueError("successful owned source-to-native build required")
    stop = root / ".runs/defense-loop/STOP"
    if stop.exists():
        return {"status": "cancelled", "reason": "defense STOP exists"}
    source_signature = verify_source_contract(report, _json(contract_raw))
    # Native preflight checks the contract, VM coverage and ABI before execution.
    result = native_validate.validate_build(report_path, contract_path, output / "native",
                                            workspace_root=root, random_cases=random_cases,
                                            timeout_seconds=timeout_seconds)
    result = {**result, "source_reference_required": True,
              "source_signature_evidence": source_signature,
              "validation_backend": "original_runtime_and_native_comparison",
              "source_reference": {"status": "not_run"},
              "native_validation_report": str(output / "native/validation.json")}
    if result.get("status") == "functional_samples_passed":
        try:
            reference = _reference(report["backend"], report_path, output / "reference",
                                   workspace_root=root, random_cases=random_cases,
                                   timeout_seconds=timeout_seconds)
            result["source_reference"] = reference
            unchanged = (hashlib.sha256(_read(report_path, 16 * 1024 * 1024)).digest() == hashlib.sha256(raw).digest()
                         and hashlib.sha256(_read(Path(contract_path), 256 * 1024)).digest() == hashlib.sha256(contract_raw).digest())
            result["inputs_unchanged"] = result.get("inputs_unchanged", True) and unchanged
            exports = set(result["functions"])
            if not unchanged or not _reference_passed(reference, exports):
                status = reference.get("status") if isinstance(reference, dict) else None
                result["status"] = status if status in {"cancelled", "timed_out"} else "failed"
                result["error"] = "Original source reference comparison did not pass for every export and both native arms"
        except Exception as exc:
            result["status"] = "cancelled" if stop.exists() else "failed"
            result["error"] = type(exc).__name__ + ": " + str(exc)[:2048]
    if stop.exists():
        result["status"] = "cancelled"
    if output.exists():
        native_validate._save(output / "validation.json", result)
    return result
