"""Internal fixed native transformation/object stages, never a linker/plugin API.

The caller owns source preparation, scope/ABI proofs, public-boundary evidence,
link recipes and original-reference compilation. Objects alone are not a
validated or distributable application. This module has no public CLI.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from types import MappingProxyType


def _native():
    # Keep existing evidence implementations in one place during this focused
    # extraction; native_build imports this module only after defining helpers.
    from . import native_build
    return native_build


@dataclass(frozen=True)
class IRInput:
    path: Path
    sha256: str


@dataclass(frozen=True)
class ObjectRequest:
    source_ir: IRInput                 # baseline input; no retention/renaming
    protection_ir: IRInput             # explicitly prepared protection input
    selected_functions: tuple[str, ...]
    seed: int
    public_boundary_ir: IRInput | None = None


class ObjectPipeline:
    """Validated internal state machine with fixed tool roles and fixed recipes.

    No callback, command hook, linker options or arbitrary tool paths are
    accepted. The configuration comes from the caller's trusted workspace.
    The shared commands list is the caller's append-only build journal; it is
    deliberately shared so caller-owned links preserve historical ordering.
    """
    _GENERATED = ("baseline.ll", "module.prevm.ll", "module.after.ll", "core.diversified.ll",
        "runtime.generated.c", "diversification.json", "core.public-joined.ll",
        "runtime.before.ll", "runtime.after.ll", "runtime.obj", "baseline.codegen.ll",
        "baseline.obj", "protected.codegen.ll", "protected.obj")
    _ROLES = ("clang", "clangxx", "optimizer", "llvm_link")

    def __init__(self, request: ObjectRequest, *, workspace_root: Path, output_dir: Path,
                 command_records: list[dict], environment: dict[str, str], build_tool_hashes: dict[str, str]):
        nb = _native()
        if type(request) is not ObjectRequest:
            raise nb.NativeBuildError("Native object pipeline requires an explicit typed request")
        self.root, self.output = Path(workspace_root), Path(output_dir)
        for path in (self.root, self.output):
            nb._no_links(path)
            if (not path.is_absolute() or ".." in path.parts or not path.is_dir()
                    or path != path.resolve(strict=True)):
                raise nb.NativeBuildError("Object pipeline paths must be canonical existing directories")
        if (self.output == self.root / ".runs" or not self.output.is_relative_to(self.root / ".runs")
                or any(part.casefold() in {"rea-analysis-reports", "attackerfolder", "defense-loop"}
                       for part in self.output.relative_to(self.root).parts)):
            raise nb.NativeBuildError("Object pipeline requires a private owned build directory")
        if (type(request.seed) is not int or not 1 <= request.seed <= 2147483647
                or type(request.selected_functions) is not tuple or not 1 <= len(request.selected_functions) <= 64
                or any(not isinstance(name, str) or not nb.SYMBOL.fullmatch(name)
                       or name.startswith(("kagura_", "__kg_", "antirea_dispatch_"))
                       for name in request.selected_functions)
                or len(set(request.selected_functions)) != len(request.selected_functions)):
            raise nb.NativeBuildError("Native object selection/seed is invalid")
        if (not isinstance(command_records, list) or any(not isinstance(row, dict) for row in command_records)
                or not isinstance(environment, dict)
                or any(not isinstance(k, str) or not isinstance(v, str) for k, v in environment.items())
                or not isinstance(build_tool_hashes, dict)):
            raise nb.NativeBuildError("Native object execution context is malformed")
        self.commands, self.environment = command_records, dict(environment)
        self.request, self.phase = request, "new"
        self.stop = self.root / ".runs/defense-loop/STOP"
        configured, configured_pins = nb._toolchain(self.root)
        self.config = MappingProxyType(dict(configured))
        configured_pins = dict(configured_pins)
        for module in (nb, nb.diversify, nb.hardening):
            path = Path(module.__file__).resolve()
            configured_pins[str(path)] = nb._hash(path)
        configured_pins[str(Path(__file__).resolve())] = nb._hash(Path(__file__).resolve())
        for path, digest in configured_pins.items():
            if build_tool_hashes.get(path) != digest:
                raise nb.NativeBuildError("Object pipeline tool differs from the original build pins: " + path)
        self.tool_pins = dict(configured_pins)
        self.inputs = {}
        self.produced = {}
        for item, expected in ((request.source_ir, "module.before.ll"),
                               (request.protection_ir, None),
                               (request.public_boundary_ir, "module.public-boundaries.ll")):
            if item is None:
                if expected != "module.public-boundaries.ll":
                    raise nb.NativeBuildError("Source and protection IR inputs are required")
                continue
            if type(item) is not IRInput or not isinstance(item.path, Path):
                raise nb.NativeBuildError("Native object IR descriptor is malformed")
            path = nb._no_links(item.path)
            if (not path.is_absolute() or ".." in path.parts or path.parent != self.output
                    or path.suffix != ".ll" or not path.is_file()
                    or not 0 < path.stat().st_size <= 32 * 1024 * 1024
                    or path != path.resolve(strict=True)
                    or expected is not None and path.name != expected
                    or not isinstance(item.sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", item.sha256)
                    or nb._hash(path) != item.sha256):
                raise nb.NativeBuildError("Native object IR must be exact hashed current-build input")
            if str(path) in self.inputs and self.inputs[str(path)] != item.sha256:
                raise nb.NativeBuildError("Conflicting native object IR input hashes")
            self.inputs[str(path)] = item.sha256
        if request.public_boundary_ir is not None and request.public_boundary_ir.path in {
                request.source_ir.path, request.protection_ir.path}:
            raise nb.NativeBuildError("Public boundary IR must be a separate module")
        for name in self._GENERATED:
            self._fresh_output(self.output / name)
        self._unchanged()

    def _fresh_output(self, path):
        """Refuse any existing directory entry, including dangling links.

        `_no_links` rejects ordinary links along the path. Its exists()/is_symlink()
        discovery can miss some dangling reparse kinds, so lstat is the final
        existence check; a missing referent does not make an output name fresh.
        This is a checkpoint, not atomic filesystem isolation against races.
        """
        nb = _native()
        if path.parent != self.output or path.name not in self._GENERATED:
            raise nb.NativeBuildError("Native object recipe output must be fresh and owned")
        nb._no_links(path)
        try:
            path.lstat()
        except FileNotFoundError:
            return
        raise nb.NativeBuildError("Native object output must be fresh; existing entries/links are not permitted")

    def _require(self, phase):
        if self.phase != phase:
            raise _native().NativeBuildError("Native object stage order/retry is invalid")
        self._unchanged()

    def _unchanged(self):
        nb = _native()
        if self.stop.exists():
            raise nb.NativeBuildError("Build cancelled by defense STOP marker")
        for value, expected in {**self.inputs, **self.tool_pins}.items():
            path = nb._no_links(Path(value))
            if not path.is_file() or nb._hash(path) != expected:
                raise nb.NativeBuildError("Native object input/tool changed: " + value)
        for value, record in self.produced.items():
            path = nb._no_links(Path(value))
            if (not path.is_file() or path.stat().st_size != record["bytes"]
                    or nb._hash(path) != record["sha256"]):
                raise nb.NativeBuildError("Native object produced artifact changed: " + value)

    def _observe(self, path):
        """Pin a fresh stage output before exposing/consuming its bytes."""
        nb = _native()
        nb._no_links(path)
        if (path.parent != self.output or path.name not in self._GENERATED
                or str(path) in self.produced or not path.is_file() or path.stat().st_size == 0):
            raise nb.NativeBuildError("Native object stage output is missing, reused or not owned")
        self.produced[str(path)] = {"path": str(path), "sha256": nb._hash(path),
                                    "bytes": path.stat().st_size, "observed_stage": self.phase}

    def _run(self, role, *args):
        if role not in self._ROLES:
            raise _native().NativeBuildError("Unsupported native object tool role")
        nb = _native()
        values = list(map(str, args))
        if values.count("-o") != 1 or values.index("-o") + 1 >= len(values):
            raise nb.NativeBuildError("Native object recipe requires one fixed output")
        output = Path(values[values.index("-o") + 1])
        self._unchanged()
        self._fresh_output(output)
        result = nb._run_build_command(self.config[role], args, output=self.output, records=self.commands,
                                       stop=self.stop, environment=self.environment)
        self._unchanged()  # catch a process that changes an earlier consumed artifact
        self._observe(output)
        return result

    def prepare(self):
        """Run fixed transforms and runtime IR passes, but create no object yet."""
        self._require("new")
        self.phase = "preparing"  # a failed attempt cannot be retried in place
        nb, out = _native(), self.output
        selected = list(self.request.selected_functions)
        baseline_ir, pre_vm, after = (out / name for name in ("baseline.ll", "module.prevm.ll", "module.after.ll"))
        protected_flags = ["-O1", "-kagura-fla", "-kagura-sub", "-kagura-co",
                           "-kagura-allow=" + ",".join(selected), f"-kagura-seed={self.request.seed}"]
        self._run("optimizer", "-O1", "-S", self.request.source_ir.path, "-o", baseline_ir)
        self._run("optimizer", *protected_flags, "-S", self.request.protection_ir.path, "-o", pre_vm)
        self._run("optimizer", *protected_flags, "-kagura-vm", "-S", self.request.protection_ir.path, "-o", after)
        baseline_text, after_text = baseline_ir.read_text(encoding="utf-8"), after.read_text(encoding="utf-8")
        if "@kagura_vm_execute(" in baseline_text or "@kagura_vm_bc_" in baseline_text:
            raise nb.NativeBuildError("Baseline unexpectedly contains Kagura VM protection")
        self.original_vm = nb._vm_evidence(after_text, selected, "kagura_vm_execute")
        self.pre_text = pre_vm.read_text(encoding="utf-8")
        self._unchanged()
        for name in ("core.diversified.ll", "runtime.generated.c", "diversification.json"):
            self._fresh_output(out / name)
        self.diversification = nb.diversify.generate(after, Path(self.config["runtime_source"]),
            Path(self.config["opcode_source"]), out, self.request.seed)
        self._unchanged()
        for name in ("core.diversified.ll", "runtime.generated.c", "diversification.json"):
            self._observe(out / name)
        self.dispatchers = self.diversification.get("dispatcher_symbols", [self.diversification["dispatcher_symbol"]])
        if (not isinstance(self.dispatchers, list) or not self.dispatchers
                or len(set(self.dispatchers)) != len(self.dispatchers)
                or any(not re.fullmatch(r"antirea_dispatch_[0-9a-f]{16}", name) for name in self.dispatchers)):
            raise nb.NativeBuildError("Unexpected generated dispatcher name")
        protected_ir, runtime_c = out / "core.diversified.ll", out / "runtime.generated.c"
        self.actual_vm = nb._manifest_vm_evidence(protected_ir.read_text(encoding="utf-8"), selected, self.diversification)
        self.protected_with_boundaries = protected_ir
        if self.request.public_boundary_ir is not None:
            self.protected_with_boundaries = out / "core.public-joined.ll"
            self._run("llvm_link", "-S", protected_ir, self.request.public_boundary_ir.path,
                      "-o", self.protected_with_boundaries)
        runtime_before, runtime_after = out / "runtime.before.ll", out / "runtime.after.ll"
        self._run("clang", "-target", nb.TARGET, "-std=c11", "-O1", "-fno-inline", "-S", "-emit-llvm",
                  runtime_c, "-o", runtime_before)
        self._run("optimizer", "-O1", "-kagura-fla", "-kagura-sub", "-kagura-co",
                  "-kagura-allow=" + ",".join(self.dispatchers), f"-kagura-seed={self.request.seed}",
                  "-S", runtime_before, "-o", runtime_after)
        self.runtime_evidence = nb._runtime_evidence(runtime_after.read_text(encoding="utf-8"), self.dispatchers)
        self._unchanged()
        self.phase = "prepared"

    def compile_runtime(self):
        self._require("prepared")
        self.phase = "runtime_compiling"
        self._run("clang", "-target", _native().TARGET, "-O0", "-c", self.output / "runtime.after.ll",
                  "-o", self.output / "runtime.obj")
        self.phase = "runtime_ready"
        return self._artifact(self.output / "runtime.obj")

    def compile_arm(self, arm):
        """Caller may link baseline before requesting protected; no links here."""
        if arm not in {"baseline", "protected"}:
            raise _native().NativeBuildError("Unknown native object arm")
        self._require("runtime_ready" if arm == "baseline" else "baseline_ready")
        self.phase = arm + "_compiling"
        ir = self.output / "baseline.ll" if arm == "baseline" else self.protected_with_boundaries
        codegen, obj = self.output / (arm + ".codegen.ll"), self.output / (arm + ".obj")
        self._run("clangxx", "-target", _native().TARGET, "-O1", "-S", "-emit-llvm", ir, "-o", codegen)
        self._run("clangxx", "-target", _native().TARGET, "-O0", "-c", codegen, "-o", obj)
        self.phase = arm + "_ready"
        return {"object": self._artifact(obj), "codegen_ir": self._artifact(codegen)}

    def _artifact(self, path):
        self._unchanged()
        if str(path) not in self.produced:
            raise _native().NativeBuildError("Native object artifact was not observed at production")
        return {key: self.produced[str(path)][key] for key in ("path", "sha256", "bytes")}

    def finalize(self):
        """Recheck retained VM/hardening; caller still owes scope/link/reference gates."""
        self._require("protected_ready")
        self.phase = "finalizing"
        nb = _native()
        final_ir = self.output / "protected.codegen.ll"
        final_core = final_ir.read_text(encoding="utf-8")
        retained = nb.hardening.inspect_hardening_artifact(self.diversification,
            (self.output / "runtime.after.ll").read_text(encoding="utf-8"), final_core)
        final_vm = nb._manifest_vm_evidence(final_core, list(self.request.selected_functions), self.diversification)
        self._unchanged()
        self.phase = "finalized"
        return {"schema_version": 1, "status": "native_objects_created_unlinked",
                "source_ir": {"path": str(self.request.source_ir.path), "sha256": self.request.source_ir.sha256},
                "protection_ir": {"path": str(self.request.protection_ir.path), "sha256": self.request.protection_ir.sha256},
                "selected_functions": list(self.request.selected_functions),
                "objects": {arm: self._artifact(self.output / (arm + ".obj"))
                            for arm in ("baseline", "protected", "runtime")},
                "final_ir": self._artifact(final_ir), "original_vm": self.original_vm,
                "functions": self.actual_vm, "final_vm": final_vm,
                "runtime_evidence": self.runtime_evidence, "hardening_evidence": retained,
                "watched_outputs": {Path(path).name: dict(record) for path, record in self.produced.items()},
                "qualification": "Objects only: caller must verify source scope, final public transit, link provenance, original semantics and deployment artifacts."}
