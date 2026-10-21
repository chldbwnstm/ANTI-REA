"""Honest language-route inventory, not a claim of whole-language protection."""
from __future__ import annotations

import shutil


LANGUAGE_IDS = ("c", "cpp", "rust", "swift", "go", "csharp", "java", "kotlin",
                "python", "javascript", "typescript")

_ROUTES = {
    "c": ("llvm", "experimental", "clang"),
    "cpp": ("llvm", "experimental", "clang++"),
    "rust": ("llvm", "experimental", "rustc"),
    "swift": ("swift_llvm_native", "experimental", "swiftc"),
    "go": ("go_typed_native", "experimental", "go"),
    "csharp": ("dotnet_il_native", "experimental", "dotnet"),
    "java": ("jvm_bytecode_native", "experimental", "javac"),
    "kotlin": ("jvm_bytecode_native", "experimental", "kotlinc"),
    "python": ("python_vm", "experimental", "python"),
    "javascript": ("javascript_vm", "experimental", "node"),
    "typescript": ("javascript_vm", "experimental", "tsc"),
}


def language_catalog(language: str | None = None) -> dict:
    if language is not None and language not in LANGUAGE_IDS:
        raise ValueError("unknown language")
    selected = LANGUAGE_IDS if language is None else (language,)
    entries = []
    for key in selected:
        route, state, command = _ROUTES[key]
        entries.append({
            "id": key,
            "source_protection": {"route": route, "status": state,
                                  "whole_language_verified": False},
            "native_core_integration": {
                "status": "binding_generator",
                "scope": "Calls already-protected native code; does not protect host-language source.",
                "runtime_validation": "per_project_required",
            },
            "tool_discovery": {"command": command, "path": shutil.which(command),
                               "executed": False, "compatible": "not_verified"},
        })
        if key == "csharp":
            entries[-1]["source_protection"]["application_integration"] = {
                "status": "experimental",
                "tool": "protection_source_integrate",
                "cli": "source-integrate",
                "contract": "csharp_application_samples",
                "requires": "Successful reviewed source-build plus integration spec and app contract in the original planned source tree.",
                "scope": "Rewrite selected call-free public static integer leaves in owned C# source; preserve ordinary callers and compile a managed app with its protected native core.",
                "execution": "Explicit application startup and declared CLI cases; separate from nonexecuting source plan/build.",
                "deployment": "Local compiled managed DLL, runtime configuration and native core; installed compatible .NET runtime required.",
                "whole_application_verified": False,
            }
        if key in {"java", "kotlin"}:
            entries[-1]["source_protection"]["application_integration"] = {
                "status": "experimental",
                "qualification": "per_project_required",
                "tool": "protection_source_integrate",
                "cli": "source-integrate",
                "contract": "jvm_application_samples",
                "requires": "Reviewed source-build of a separated static integer core; application sources, integration spec and exact-output contract in the same planned tree.",
                "scope": "Compile ordinary callers against original core classes, then replace the core with same-name native-backed facades; preserve caller bytecode.",
                "execution": "Explicit application startup and declared CLI cases; separate from nonexecuting source plan/build.",
                "deployment": "Generated facade/runtime and unchanged caller classfiles, JNI adapter and protected native core; compatible installed JVM and pinned Kotlin runtime JAR when required.",
                "whole_application_verified": False,
                "metadata_reflection_equivalence": False,
            }
        if key in {"go", "swift"}:
            entries[-1]["source_protection"]["application_integration"] = {
                "status": "experimental",
                "qualification": "per_project_required",
                "tool": "protection_source_integrate",
                "cli": "source-integrate",
                "contract": "native_application_samples",
                "requires": "Reviewed source-build of separated fixed-width integer core files; explicit app sources and exact-output contract in the same planned tree.",
                "scope": "Compile unchanged ordinary app sources with generated same-name native-backed facades; exclude the original core implementations from the protected compile.",
                "execution": "Explicit original/protected app startup, declared cases and missing/unset-core controls.",
                "deployment": "Windows x64 app.exe and protected.dll; pinned Swift runtime DLLs when required.",
                "whole_application_verified": False,
                "package_manager_hooks_supported": False,
            }
        if key == "python":
            entries[-1]["source_protection"]["modes"] = [
                {
                    "id": "pure_module",
                    "route": "python_vm",
                    "status": "experimental",
                    "project_selection": "omit protection_mode",
                    "scope": "The entire source module must fit the supported pure integer/bool subset.",
                    "validation": "python_integer_samples",
                },
                {
                    "id": "mixed_module",
                    "route": "python_mixed_module_vm",
                    "status": "experimental",
                    "project_selection": "protection_mode=mixed_module",
                    "scope": "Replace selected pure integer/bool roots and owned helpers in one ordinary module; preserve unselected code.",
                    "validation": "python_mixed_module_application_samples",
                    "deployment": "explicit_source_integrate_application_bundle",
                },
            ]
        if key in {"javascript", "typescript"}:
            entries[-1]["source_protection"]["modes"] = [
                {"id": "pure_module", "route": "javascript_vm", "status": "experimental",
                 "project_selection": "omit protection_mode",
                 "scope": "The entire module must fit the supported scalar subset.",
                 "validation": "javascript_scalar_samples"},
                {"id": "mixed_module", "route": "javascript_mixed_module_vm",
                 "status": "experimental",
                 "project_selection": "protection_mode=mixed_module",
                 "scope": "Replace selected scalar roots and owned helpers in one CommonJS module; TS uses one independently transpiled entry, not an arbitrary TS graph.",
                 "validation": key + "_mixed_module_application_samples",
                 "deployment": "explicit_source_integrate_application_bundle"},
            ]
        if key in {"python", "javascript", "typescript"}:
            entries[-1]["source_protection"]["application_integration"] = {
                "status": "experimental",
                "cli": "source-integrate",
                "spec": "script_application_integration",
                "contract": "script_application_samples",
                "requires": "One reviewed source-build module plus an explicit application-file inventory and entrypoint in the unchanged planned source tree.",
                "scope": "Replace the selected module with its pinned protected artifact; preserve surrounding Python/JS files or independently transpile ordinary TS files to CommonJS.",
                "execution": "Explicit original/protected/copied-deployment app cases and a missing-module dependency control.",
                "deployment": "Local script/data bundle with an already-installed interpreter, no original protected-core source, package installation or automatic source overwrite.",
                "whole_application_verified": False,
                "package_manager_hooks_supported": False,
            }
            entries[-1]["source_protection"]["runtime_hardening"] = {
                "status": "experimental",
                "profile": "per_function_flattened_dispatch_v1",
                "scope": "Generated per-function engines, indirect table routing, encoded state transitions and seeded handler ordering in both pure and mixed-module modes.",
                "coverage_field": "runtime_hardening",
                "shared_helpers": "Instruction fetch/operand decoding and operator/builtin helpers remain shared.",
                "qualification": "per_artifact_required",
                "kagura_passes_applied": False,
                "external_attack_evaluation": "not_evaluated",
            }
    return {"schema_version": 1, "languages": entries,
            "native_builder_targets": ["x86_64-pc-windows-msvc"],
            "macos_validation": "not_performed",
            "external_attack_evaluation": "not_evaluated",
            "limitations": [
                "Experimental LLVM routes support selected functions, not arbitrary application semantics.",
                "C# lowers restricted static integer IL to native VM code. Explicit source-integrate rewrites supported selected source bodies and validates declared app cases; arbitrary existing assemblies, objects, project hooks and all-input equivalence remain unsupported.",
                "Python pure mode requires a pure integer/bool module; opt-in mixed mode protects only selected supported roots/helpers and retains unselected application code.",
                "Both Python modes use a separate Python stack VM, not native Kagura hardening. Mixed scalar validation compares declared entrypoints. Separate source-integrate creates an explicit owned-file application bundle and compares declared CLI outputs/exit codes; arbitrary dependencies, side effects, GUI behavior and performance acceptance are not established.",
                "Java/Kotlin lower a restricted static int/long JVM subset with owned helpers to native VM. Experimental source-integrate substitutes same-name facades for a separated core; ordinary caller bytecode is unchanged. Every project requires fresh functional qualification; arbitrary JARs, build hooks, reflection and Kotlin metadata equivalence remain unsupported.",
                "JavaScript/TypeScript protect a restricted Number/BigInt/bool subset in a separate JS VM, not native Kagura.",
                "Opt-in JavaScript/TypeScript mixed mode preserves unselected module code; TS is transpiled to CommonJS, not fully type-checked. Separate mixed scalar contracts authorize entrypoint sampling and the TS mixed scalar validator rejects additional TS siblings. Explicit source-integrate separately accepts a declared application inventory and independently transpiles ordinary TS files; neither route supports arbitrary project hooks or proves whole-app equivalence. Build alone does not authorize execution.",
                "Go lowers restricted fixed-width integer cores with owned acyclic helpers. Explicit source-integrate connects a separated package-main core to unchanged ordinary app sources; modules, cgo, hooks and whole-application protection remain unsupported.",
                "Swift normalizes closed scalar LLVM cores with explicit C exports and owned acyclic helpers. Explicit source-integrate connects separated cores using compiler-derived names/argument labels; SwiftPM, checked-overflow core operations and whole-application protection remain unsupported.",
                "PATH-only discovery below may miss pinned portable Go/Swift/Kotlin compilers and the installed TypeScript parser bundle; source-plan inspects those separately.",
                "Tool presence is not compiler/IR/ABI compatibility evidence.",
                "Bindings are a separate integration capability, not direct source protection.",
                "Per-artifact coverage, correctness, performance and protection evidence are required.",
            ]}
