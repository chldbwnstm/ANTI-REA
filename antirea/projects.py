"""Audited source-project plans and native-core bindings for the defense bridge.

Planning may run a trusted language parser, but never target application code.
Builds accept a fingerprinted plan and never execute the resulting application.
This is not an OS sandbox.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import sys
import uuid

from .languages import language_catalog
from .protectors import _absolute, _no_links, _read, _job_lock, _json


MAX_PROJECT_FILES = 1024
MAX_PROJECT_BYTES = 64 * 1024 * 1024
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_JSON_BYTES = 256 * 1024
JOB_ID = re.compile(r"source-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}\Z")


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("utf-8")


def _create_json(path, value):
    _no_links(path)
    with path.open("xb") as stream:
        stream.write(_encoded(value) + b"\n")


def _inspect(path, *, workspace_root=None):
    project = _json(_read(path, MAX_JSON_BYTES))
    if not isinstance(project, dict):
        raise ValueError("source project must be a JSON object")
    if "rust_cargo" in project:
        raise ValueError("Cargo inspection requires ProjectService's fresh metadata job")
    language = project.get("language")
    if language == "python":
        if project.get("protection_mode") == "mixed_module":
            from .python_mixed_module import inspect_project
        else:
            # Unknown modes still fail the original exact pure-project schema.
            from .python_frontend import inspect_project
        return inspect_project(path)
    if language == "csharp":
        from .dotnet_frontend import inspect_project
        return inspect_project(path)
    if language in {"java", "kotlin"}:
        from .jvm_frontend import inspect_project
        return inspect_project(path)
    if language in {"javascript", "typescript"}:
        if project.get("protection_mode") == "mixed_module":
            from .javascript_mixed_module import inspect_project
        else:
            from .javascript_frontend import inspect_project
        return inspect_project(path)
    if language == "go":
        from .go_frontend import inspect_project
        return inspect_project(path)
    if language == "swift":
        from .swift_frontend import inspect_project
        return inspect_project(path)
    from .native_build import inspect_project
    return inspect_project(path, workspace_root=workspace_root)


def _build(path, output, *, workspace_root, seed):
    project = _json(_read(path, MAX_JSON_BYTES))
    if not isinstance(project, dict):
        raise ValueError("source project must be a JSON object")
    if "rust_cargo" in project:
        raise ValueError("rust_cargo_build_not_implemented")
    language = project.get("language")
    if language == "python":
        if project.get("protection_mode") == "mixed_module":
            from .python_mixed_module import build_project
        else:
            from .python_frontend import build_project
        return build_project(path, output, workspace_root=workspace_root, seed=seed)
    if language == "csharp":
        from .dotnet_frontend import build_project
        return build_project(path, output, workspace_root=workspace_root, seed=seed)
    if language in {"java", "kotlin"}:
        from .jvm_frontend import build_project
        return build_project(path, output, workspace_root=workspace_root, seed=seed)
    if language in {"javascript", "typescript"}:
        if project.get("protection_mode") == "mixed_module":
            from .javascript_mixed_module import build_project
        else:
            from .javascript_frontend import build_project
        return build_project(path, output, workspace_root=workspace_root, seed=seed)
    if language == "go":
        from .go_frontend import build_project
        return build_project(path, output, workspace_root=workspace_root, seed=seed)
    if language == "swift":
        from .swift_frontend import build_project
        return build_project(path, output, workspace_root=workspace_root, seed=seed)
    from .native_build import build_project
    return build_project(path, output, workspace_root=workspace_root, seed=seed)


def _bindings(contract, output):
    from .bindings import generate_bindings
    return generate_bindings(contract, output)


class ProjectService:
    def __init__(self, workspace_root):
        self.root = _absolute(workspace_root)
        _no_links(self.root)
        if not self.root.is_dir():
            raise ValueError("workspace_root must exist")
        self.output_root = self.root / ".runs" / "source-protection"

    def _owned(self, value):
        path = Path(value)
        if not path.is_absolute():
            path = self.root / path
        path = _absolute(path)
        _no_links(path)
        try:
            relative = path.relative_to(self.root)
        except ValueError as exc:
            raise ValueError("source input must stay inside configured workspace") from exc
        parts = [part.casefold() for part in relative.parts]
        if ("rea-analysis-reports" in parts or "attackerfolder" in parts
                or parts[:2] == [".runs", "defense-loop"]
                or parts[:2] == [".runs", "source-protection"]):
            raise ValueError("received reports, shared handoffs and service output are not source inputs")
        return path

    def _snapshot(self, project, inspection=None):
        """Pin the whole bounded project directory, including local headers.

        System SDK headers and compiler dependency DLLs are not a hermetic build
        environment. This limitation is included in every plan.
        """
        base = self._owned(project.parent)
        if base == self.root:
            raise ValueError("put the source manifest in a dedicated project subdirectory")
        records = []
        total = 0
        entries = 0
        pending = [base]
        while pending:
            directory = pending.pop()
            for path in sorted(directory.iterdir()):
                entries += 1
                if entries > MAX_PROJECT_FILES:
                    raise ValueError("project tree exceeds entry limit")
                path = self._owned(path)
                if path.is_dir():
                    pending.append(path)
                    continue
                if not path.is_file():
                    raise ValueError("project contains a non-regular input")
                # Empty headers are legal; _read intentionally requires nonempty.
                if path.stat().st_size == 0:
                    data = b""
                else:
                    data = _read(path, MAX_INPUT_BYTES)
                total += len(data)
                records.append({"path": str(path), "sha256": _digest(data), "bytes": len(data)})
                if len(records) > MAX_PROJECT_FILES or total > MAX_PROJECT_BYTES:
                    raise ValueError("project snapshot exceeds bounded input budget")
        if inspection and inspection.get("backend") == "compile_database_native":
            known = {entry["path"] for entry in records}
            for value, expected in inspection["input_hashes"].items():
                path = self._owned(value)
                data = _read(path, MAX_INPUT_BYTES) if path.stat().st_size else b""
                if _digest(data) != expected:
                    raise ValueError("Inspected compilation database input changed while snapshotting")
                if str(path) not in known:
                    records.append({"path": str(path), "sha256": expected, "bytes": len(data)})
                    known.add(str(path))
                    total += len(data)
            if len(records) > MAX_PROJECT_FILES or total > MAX_PROJECT_BYTES:
                raise ValueError("Expanded compilation database inputs exceed snapshot budget")
        return sorted(records, key=lambda item: item["path"])

    def _toolchain(self, inspection=None):
        inspection = inspection or {}
        native_required = inspection.get("language") not in {"python", "javascript", "typescript"}
        path = self.root / ".tools" / "kagura-toolchain.json"
        if native_required and not path.exists():
            return {"path": str(path), "sha256": None, "status": "missing"}
        raw = _read(path, MAX_JSON_BYTES) if native_required else None
        data = _json(raw) if raw is not None else {}
        if not isinstance(data, dict):
            raise ValueError("toolchain manifest must be an object")
        tools = {}
        candidates = {key: data[key] for key in ("clang", "clangxx", "optimizer", "runtime", "developer_shell")
                      if isinstance(data.get(key), str)}
        if isinstance(data.get("llvm_root"), str):
            candidates["llvm_link"] = str(Path(data["llvm_root"]) / "bin" / "llvm-link.exe")
            candidates["scope_optimizer"] = str(Path(data["llvm_root"]) / "bin" / "opt.exe")
            candidates["llvm_c"] = str(Path(data["llvm_root"]) / "bin" / "LLVM-C.dll")
            candidates["lld_link"] = str(Path(data["llvm_root"]) / "bin" / "lld-link.exe")
        if isinstance(data.get("kagura_source"), str):
            candidates["runtime_source"] = str(Path(data["kagura_source"]) / "runtime" / "core" / "vm_interpreter.c")
            candidates["opcode_source"] = str(Path(data["kagura_source"]) / "include" / "kagura" / "VMOpcodes.def")
        rustc = shutil.which("rustc") if native_required else None
        if rustc:
            candidates["rustc_launcher"] = rustc
        candidates["python_executable"] = sys.executable
        for module in ("native_build", "diversify", "hardening", "process", "projects", "scope",
                       "bindings", "native_validate", "native_abi", "source_validate", "python_frontend", "python_validate",
                       "python_mixed_module", "python_mixed_validate", "python_runtime_hardening",
                       "script_validation_evidence",
                       "dotnet_frontend", "csharp_app_integration", "csharp_transform", "csharp_application",
                       "jvm_frontend", "jvm_facade", "jvm_app_integration", "jvm_application",
                       "go_application_facade", "swift_application_facade",
                       "native_app_integration", "native_application",
                       "script_application", "script_app_integration",
                       "script_python_application", "script_javascript_application",
                       "javascript_frontend", "javascript_validate", "javascript_runtime_hardening",
                       "javascript_mixed_module", "javascript_mixed_validate", "typescript_reference",
                       "go_frontend", "swift_frontend", "compile_database", "cpp_symbols", "native_objects",
                       "rust_ir", "rust_normalize", "rust_qualify", "rust_cargo_link",
                       "rust_cargo_prepare", "rust_cargo_semantic", "rust_cargo_objects"):
            engine = Path(__file__).with_name(module + ".py")
            if engine.is_file():
                candidates["engine_" + module] = str(engine)
        if inspection.get("backend") == "javascript_mixed_module_vm":
            candidates["javascript_mixed_runner"] = str(
                Path(__file__).resolve().parents[1] / "tools/javascript_frontend/mixed_run_arm.cjs")
            if inspection.get("language") == "typescript":
                candidates["typescript_reference_helper"] = str(
                    Path(__file__).resolve().parents[1] / "tools/typescript_frontend/mixed_reference.cjs")
        if inspection.get("language") in {"javascript", "typescript"}:
            candidates["script_typescript_reference_helper"] = str(
                Path(__file__).resolve().parents[1] / "tools/typescript_frontend/application_reference.cjs")
        compiler_inputs = inspection.get("compiler_inputs", {})
        if not isinstance(compiler_inputs, dict):
            raise ValueError("compiler_inputs must map absolute paths to inspected hashes")
        for value, expected_hash in compiler_inputs.items():
            if not isinstance(value, str) or not Path(value).is_absolute() or not isinstance(expected_hash, str):
                raise ValueError("invalid frontend compiler input")
            candidates["frontend_" + _digest(value.encode("utf-8"))[:16]] = value
        for name, value in candidates.items():
            executable = _absolute(value)
            # rustup's installed launchers are ordinary hard-linked files.
            # They are read-only hash inputs, unlike project files and outputs.
            # Keep rejecting symbolic/reparse redirects, and rehash before use.
            _no_links(executable.parent)
            if not executable.is_file():
                tools[name] = {"path": str(executable), "status": "missing"}
                continue
            before = executable.lstat()
            if not stat.S_ISREG(before.st_mode) or getattr(before, "st_file_attributes", 0) & 0x400:
                raise ValueError("compiler tool must be a regular non-reparse file")
            if before.st_size > 512 * 1024 * 1024:
                raise ValueError("compiler tool exceeds hash input bound")
            with executable.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            after = executable.stat()
            if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
                raise ValueError("compiler tool changed while hashing")
            tools[name] = {"path": str(executable), "sha256": digest, "bytes": before.st_size,
                           "hardlink_count": before.st_nlink}
            if value in compiler_inputs and digest != compiler_inputs[value]:
                raise ValueError("frontend compiler input changed during inspection")
        return {"path": str(path) if native_required else None,
                "sha256": _digest(raw) if raw is not None else None, "status": "present",
                "native_toolchain_required": native_required,
                "tools": tools,
                "declared_llvm_version": data.get("llvm_version"),
                "declared_target": data.get("target"),
                "declared_kagura_commit": data.get("kagura_commit")}

    def _new_job(self):
        _no_links(self.output_root)
        self.output_root.mkdir(parents=True, exist_ok=True)
        job_id = "source-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:12]
        directory = self.output_root / job_id
        directory.mkdir()
        return job_id, directory

    def _directory(self, plan_id):
        if not isinstance(plan_id, str) or not JOB_ID.fullmatch(plan_id):
            raise ValueError("invalid source plan id")
        directory = self.output_root / plan_id
        _no_links(directory)
        if not directory.is_dir():
            raise ValueError("source plan not found")
        return directory

    def languages(self, language=None):
        return language_catalog(language)

    def _cargo_toolchain(self):
        """Only this fixed local operator configuration selects Cargo tools."""
        path = self.root / ".tools" / "rust-cargo-toolchain.json"
        raw = _read(path, MAX_JSON_BYTES)
        value = _json(raw)
        fields = {"schema_version", "cargo", "rustc", "sysroot", "target"}
        if (not isinstance(value, dict) or set(value) != fields
                or type(value.get("schema_version")) is not int or value["schema_version"] != 1):
            raise ValueError("Invalid trusted rust-cargo-toolchain.json schema")
        tools = {key: value[key] for key in ("cargo", "rustc", "sysroot", "target")}
        for key in ("cargo", "rustc", "sysroot"):
            if not isinstance(tools[key], str) or not Path(tools[key]).is_absolute():
                raise ValueError("Cargo tool configuration requires absolute installed paths")
            tools[key] = str(_absolute(tools[key]))
        # The reused inspector additionally checks actual backend/bin identities
        # and the complete bounded bin + lib/rustlib inventory before execution.
        return {"configuration": {"path": str(path), "sha256": _digest(raw), "bytes": len(raw)},
                "selection": tools}

    def _plan_cargo(self, path, raw, *, seed):
        from . import rust_cargo

        project = _json(raw)
        if (not isinstance(project, dict) or project.get("language") != "rust"
                or type(project.get("schema_version")) is not int or project["schema_version"] != 1):
            raise ValueError("rust_cargo requires a schema 1 Rust manifest")
        if (self.root / ".runs" / "defense-loop" / "STOP").exists():
            raise ValueError("STOP is set; no Cargo metadata process started")
        config = self._cargo_toolchain()
        # Reuse the inspector's manifest parser. Add the service's own exclusion
        # of previous service outputs to every declared input root before query.
        _, _, _, roots = rust_cargo._read_project(path, self.root)
        for root in roots:
            self._owned(root)
        engine_paths = [Path(__file__), Path(rust_cargo.__file__),
                        Path(__file__).with_name("process.py"), Path(__file__).with_name("__init__.py"),
                        Path(__file__).with_name("protectors.py"),
                        Path(__file__).with_name("rust_cargo_prepare.py"),
                        Path(__file__).with_name("rust_cargo_semantic.py"),
                        Path(__file__).with_name("rust_cargo_objects.py"), Path(sys.executable)]
        engines = [rust_cargo._file(item) for item in engine_paths]
        job_id, directory = self._new_job()
        metadata_path = directory / "inspection" / "plan.json"
        captured = rust_cargo.inspect_project(path, workspace_root=self.root,
            toolchain=config["selection"], output_dir=metadata_path.parent)
        captured_bytes = _read(metadata_path, MAX_PROJECT_BYTES)
        if _encoded(_json(captured_bytes)) != _encoded(captured):
            raise ValueError("Cargo inspector return differs from saved receipt")
        verification = rust_cargo.verify_plan(captured, plan_path=metadata_path,
            workspace_root=self.root, toolchain=config["selection"])
        if (_digest(_read(path, MAX_JSON_BYTES)) != _digest(raw)
                or self._cargo_toolchain() != config
                or [rust_cargo._file(Path(item["path"])) for item in engines] != engines):
            raise ValueError("Cargo planning source/configuration/engine changed")
        semantic = captured["inspection"]
        receipt = {"path": str(metadata_path), "sha256": _digest(captured_bytes), "bytes": len(captured_bytes)}
        # Stable meaning is distinct from the exact job/receipt fingerprint.
        # The latter intentionally changes with the metadata PID/time/raw logs.
        meaning = {"schema_version": 1, "backend": "rust_cargo_native", "seed": seed,
                   "inspection_fingerprint": semantic["fingerprint"],
                   "tool_configuration": config, "engine_inputs": engines}
        blockers = sorted(set(semantic["blockers"] + ["rust_cargo_build_not_implemented"]))
        plan = {"schema_version": 1, "plan_id": job_id, "kind": "rust_cargo_inspection",
                "backend": "rust_cargo_native", "workspace_root": str(self.root),
                "project_path": str(path), "seed": seed, "inspection": semantic,
                "inspection_status": semantic["status"], "inspection_receipt": receipt,
                "inspection_verification": verification, "semantic_fingerprint": _digest(_encoded(meaning)),
                "inputs": semantic["input_snapshot"], "toolchain": config, "engine_inputs": engines,
                "blockers": blockers, "output_dir": str(directory / "build"),
                "build_implemented": False, "executes_target_build": False,
                "executes_application": False, "publishes": False,
                "planning_may_query_compiler_metadata": True,
                "limitations": list(semantic["limitations"]) + [
                    "PLAN integration only: Cargo build, protection, original reference and validation are not connected.",
                    "Metadata may query compiler information; no target source compilation is requested.",
                    "Stable semantic fingerprint excludes execution receipts; exact plan fingerprint binds their hashes.",
                    "This does not make Cargo metadata a rustc build-unit plan or establish consumed/link dependency closure.",
                ]}
        _create_json(directory / "plan.json", plan)
        return {**plan, "fingerprint": _digest(_encoded(plan)), "status": "blocked"}

    def plan(self, project_path, *, seed=1729):
        if type(seed) is not int or not 1 <= seed <= 0x7FFFFFFF:
            raise ValueError("seed must be an integer between 1 and 2147483647")
        path = self._owned(project_path)
        raw = _read(path, MAX_JSON_BYTES)
        project = _json(raw)
        if isinstance(project, dict) and "rust_cargo" in project:
            return self._plan_cargo(path, raw, seed=seed)
        inspection = _inspect(path, workspace_root=self.root)
        snapshot = self._snapshot(path, inspection)
        if _digest(_read(path, MAX_JSON_BYTES)) != _digest(raw):
            raise ValueError("project changed during inspection")
        toolchain = self._toolchain(inspection)
        blockers = list(inspection.get("blockers", []))
        if toolchain["status"] == "missing":
            blockers.append("native_toolchain_not_configured")
        job_id, directory = self._new_job()
        kind = {"python": "python_source_build", "javascript": "javascript_source_build",
                "typescript": "javascript_source_build"}.get(inspection.get("language"), "native_source_build")
        plan = {"schema_version": 1, "plan_id": job_id,
                "kind": kind,
                "workspace_root": str(self.root), "project_path": str(path),
                "seed": seed, "inspection": inspection, "inputs": snapshot,
                "toolchain": toolchain, "blockers": blockers,
                "output_dir": str(directory / "build"),
                "executes_compilers": inspection.get("language") != "python", "executes_application": False,
                "publishes": False,
                "limitations": [
                    "The compiler process is not sandboxed; only owned source projects are allowed.",
                    "System headers, compiler dependency DLLs, rustup-selected backend and environment are not hermetically pinned.",
                    "Generated artifact requires separate function, performance and protection checks.",
                    "Source protection coverage does not imply host-language source coverage through FFI.",
                ]}
        fingerprint = _digest(_encoded(plan))
        _create_json(directory / "plan.json", plan)
        return {**plan, "fingerprint": fingerprint, "status": "blocked" if blockers else "planned"}

    def build(self, plan_id, fingerprint):
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[a-f0-9]{64}", fingerprint):
            raise ValueError("fingerprint must be lowercase SHA-256")
        directory = self._directory(plan_id)
        with _job_lock(directory):
            plan = _json(_read(directory / "plan.json", MAX_PROJECT_BYTES))
            if _digest(_encoded(plan)) != fingerprint or plan.get("plan_id") != plan_id:
                raise ValueError("source plan fingerprint does not match")
            if plan.get("workspace_root") != str(self.root):
                raise ValueError("source plan workspace does not match")
            if plan.get("backend") == "rust_cargo_native" or plan.get("kind") == "rust_cargo_inspection":
                # Never re-run metadata, import a builder or create started.json
                # for a plan-only route, even if its general blocker list changes.
                raise ValueError("rust_cargo_build_not_implemented")
            if plan.get("blockers"):
                raise ValueError("source plan has unresolved blockers")
            if (directory / "started.json").exists():
                raise ValueError("source plan was already attempted; create a new plan")
            if (self.root / ".runs" / "defense-loop" / "STOP").exists():
                return {"status": "cancelled", "reason": "defense STOP exists", "plan_id": plan_id}
            source = self._owned(plan["project_path"])
            inspection = _inspect(source, workspace_root=self.root)
            if (self._snapshot(source, inspection) != plan["inputs"] or inspection != plan["inspection"]
                    or self._toolchain(inspection) != plan["toolchain"]):
                raise ValueError("project or toolchain changed after planning")
            output = directory / "build"
            if plan["output_dir"] != str(output) or output.exists():
                raise ValueError("unexpected or existing output directory")
            _create_json(directory / "started.json", {"plan_id": plan_id, "fingerprint": fingerprint})
            try:
                result = _build(source, output, workspace_root=self.root, seed=plan["seed"])
                if not isinstance(result, dict):
                    raise ValueError("source builder returned invalid record")
                if (self._snapshot(source, inspection) != plan["inputs"] or _inspect(source, workspace_root=self.root) != plan["inspection"]
                        or self._toolchain(inspection) != plan["toolchain"]):
                    result = {"status": "original_input_changed", "build_result": result}
                elif result.get("status") == "artifact_created_unvalidated":
                    report_bytes = _read(output / "report.json", MAX_PROJECT_BYTES)
                    if _json(report_bytes) != result:
                        raise ValueError("native builder report differs from returned build result")
                    result = {**result, "build_report_sha256": _digest(report_bytes)}
            except Exception as exc:
                result = {"status": "failed", "error": type(exc).__name__ + ": " + str(exc)[:2048]}
            result = {**result, "plan_id": plan_id, "fingerprint": fingerprint,
                      "external_attack_evaluation": "not_evaluated", "published": False}
            _create_json(directory / "result.json", result)
            return result

    def bindings(self, contract_path):
        path = self._owned(contract_path)
        raw = _read(path, MAX_JSON_BYTES)
        contract = _json(raw)
        from .bindings import validate_contract
        validate_contract(contract)
        job_id, directory = self._new_job()
        result = _bindings(contract, directory / "bindings")
        record = {"schema_version": 1, "status": "bindings_generated_unvalidated",
                  "job_id": job_id, "contract_path": str(path), "contract_sha256": _digest(raw),
                  "output_dir": str(directory / "bindings"), "generation": result,
                  "source_protection": False, "executed": False, "published": False}
        _create_json(directory / "bindings.json", record)
        return record

    def integrate(self, plan_id, integration_spec_path, contract_path, *, timeout_seconds=120):
        """Explicitly compile/execute an owned app around its reviewed source build.

        Separate from source plan/build: application startup is authorized only
        through this application-specific contract. C# and JVM integrations each
        revalidate the source result under their own job lock before execution.
        The dispatch read is only a routing hint, never artifact authorization.
        """
        from .csharp_application import integrate_source_application as csharp_integrate
        # Preserve the established no-filesystem timeout rejection contract.
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
            return csharp_integrate(self, plan_id, integration_spec_path, contract_path,
                                    timeout_seconds=timeout_seconds)
        directory = self._directory(plan_id)
        result = _json(_read(directory / "result.json", MAX_PROJECT_BYTES))
        if isinstance(result, dict) and result.get("backend") in (
                "python_vm", "python_mixed_module_vm", "javascript_vm", "javascript_mixed_module_vm"):
            from .script_application import integrate_source_application as script_integrate
            return script_integrate(self, plan_id, integration_spec_path, contract_path,
                                    timeout_seconds=timeout_seconds)
        if isinstance(result, dict) and result.get("backend") == "jvm_bytecode_native":
            from .jvm_application import integrate_source_application as jvm_integrate
            return jvm_integrate(self, plan_id, integration_spec_path, contract_path,
                                 timeout_seconds=timeout_seconds)
        if isinstance(result, dict) and result.get("backend") in ("go_typed_native", "swift_llvm_native"):
            from .native_application import integrate_source_application as native_integrate
            return native_integrate(self, plan_id, integration_spec_path, contract_path,
                                    timeout_seconds=timeout_seconds)
        return csharp_integrate(self, plan_id, integration_spec_path, contract_path,
                                timeout_seconds=timeout_seconds)

    def validate(self, plan_id, contract_path, *, random_cases=8192, timeout_seconds=120):
        """Explicit execution of the reviewed build, never an implicit build step."""
        directory = self._directory(plan_id)
        with _job_lock(directory):
            record_bytes = _read(directory / "result.json", MAX_PROJECT_BYTES)
            record = _json(record_bytes)
            if record.get("status") != "artifact_created_unvalidated":
                raise ValueError("source plan has no successful artifact to validate")
            report_path = directory / "build" / "report.json"
            report_bytes = _read(report_path, MAX_PROJECT_BYTES)
            report = _json(report_bytes)
            if (not record.get("build_report_sha256") or _digest(report_bytes) != record["build_report_sha256"]
                    or report.get("artifacts") != record.get("artifacts")
                    or report.get("coverage") != record.get("coverage")):
                raise ValueError("build report no longer matches the source plan result")
            contract = self._owned(contract_path)
            # Validation reports are append-only; repeated measurements get a new directory.
            validation_id = "validation-" + uuid.uuid4().hex[:12]
            if report.get("backend") == "javascript_mixed_module_vm":
                # Explicit application contract, never the pure scalar route.
                # Bind the saved plan and all service/runner tools for each arm.
                from .javascript_mixed_validate import validate_build
                plan_path = directory / "plan.json"
                plan_bytes = _read(plan_path, MAX_PROJECT_BYTES)
                plan = _json(plan_bytes)
                if (not isinstance(plan, dict)
                        or _digest(_encoded(plan)) != record.get("fingerprint")
                        or plan.get("plan_id") != plan_id or record.get("plan_id") != plan_id
                        or plan.get("workspace_root") != str(self.root)
                        or plan.get("kind") != "javascript_source_build"
                        or plan.get("inspection") != report.get("project")
                        or plan.get("project_path") != report.get("project", {}).get("project_path")
                        or not isinstance(plan.get("inputs"), list)):
                    raise ValueError("source plan does not bind this mixed build result")
                if self._toolchain(plan["inspection"]) != plan.get("toolchain"):
                    raise ValueError("mixed validation engine or toolchain changed after planning")
                trusted_inputs = [
                    {"path": str(plan_path), "sha256": _digest(plan_bytes)},
                    {"path": str(directory / "result.json"),
                     "sha256": _digest(record_bytes)},
                ]
                trusted_inputs.extend({"path": tool["path"], "sha256": tool["sha256"]}
                                      for tool in plan["toolchain"]["tools"].values()
                                      if "sha256" in tool)
                result = validate_build(report_path, contract, directory / validation_id,
                                        workspace_root=self.root, expected_snapshot=plan["inputs"],
                                        trusted_inputs=trusted_inputs,
                                        random_cases=random_cases, timeout_seconds=timeout_seconds)
                return {**result, "plan_id": plan_id, "validation_id": validation_id}
            if report.get("backend") == "python_mixed_module_vm":
                # Ordinary module imports can execute arbitrary application
                # startup. Require a separate application contract and bind
                # every staged sibling to the original, fingerprinted plan.
                from .python_mixed_validate import validate_build
                plan = _json(_read(directory / "plan.json", MAX_PROJECT_BYTES))
                if (not isinstance(plan, dict)
                        or _digest(_encoded(plan)) != record.get("fingerprint")
                        or plan.get("plan_id") != plan_id or record.get("plan_id") != plan_id
                        or plan.get("workspace_root") != str(self.root)
                        or plan.get("kind") != "python_source_build"
                        or plan.get("inspection") != report.get("project")
                        or plan.get("project_path") != report.get("project", {}).get("project_path")
                        or not isinstance(plan.get("inputs"), list)):
                    raise ValueError("source plan does not bind this mixed build result")
                if self._toolchain(plan["inspection"]) != plan.get("toolchain"):
                    raise ValueError("mixed validation engine or toolchain changed after planning")
                result = validate_build(report_path, contract, directory / validation_id,
                                        workspace_root=self.root, expected_snapshot=plan["inputs"],
                                        random_cases=random_cases, timeout_seconds=timeout_seconds)
                return {**result, "plan_id": plan_id, "validation_id": validation_id}
            if report.get("backend") == "python_vm":
                from .python_validate import validate_build
            elif report.get("backend") == "javascript_vm":
                from .javascript_validate import validate_build
            elif report.get("backend") in {"dotnet_il_native", "jvm_bytecode_native", "go_typed_native", "swift_llvm_native"}:
                from .source_validate import validate_lowered_build as validate_build
            else:
                from .native_validate import validate_build
            result = validate_build(report_path, contract,
                                    directory / validation_id, workspace_root=self.root,
                                    random_cases=random_cases, timeout_seconds=timeout_seconds)
            return {**result, "plan_id": plan_id, "validation_id": validation_id}
