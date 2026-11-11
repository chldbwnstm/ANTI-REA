"""Bridge between the multi-language native build pipeline and the Pure-Rust VM engine (antirea-rust-v20).

Supports direct native routes (`c`, `cpp`, `rust` in `output_dir`), Cargo library crates
(`compile-cargo` with automatic `antirea.ontology` hot-loop scope filtering), and lowered
native routes (`csharp`, `java`, `kotlin`, `go`, `swift` in `output_dir / "native"`).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_windows_os(os_name: str | None = None) -> bool:
    tag = (os_name or os.name).lower()
    return tag in {"nt", "win32", "windows"} or tag.startswith("win")


def rust_cli_binary_name(os_name: str | None = None) -> str:
    return "antirea-cli.exe" if _is_windows_os(os_name) else "antirea-cli"


def staticlib_filename(stem: str = "antirea_multilang_runtime", *, os_name: str | None = None) -> str:
    return f"{stem}.lib" if _is_windows_os(os_name) else f"lib{stem}.a"


def shared_library_filename(stem: str = "protected.rust", *, os_name: str | None = None) -> str:
    tag = (os_name or sys.platform).lower()
    if _is_windows_os(tag):
        return f"{stem}.dll"
    if "darwin" in tag or "macos" in tag:
        return f"lib{stem}.dylib"
    return f"lib{stem}.so"


def ensure_rust_cli(workspace_root: Path) -> Path:
    cli_path = workspace_root / "rust/target/release" / rust_cli_binary_name()
    if cli_path.is_file():
        return cli_path
    manifest = workspace_root / "rust/Cargo.toml"
    if not manifest.is_file():
        raise FileNotFoundError(f"Rust workspace manifest not found: {manifest}")
    proc = subprocess.run(
        ["cargo", "build", "--release", "--manifest-path", str(manifest)],
        cwd=str(workspace_root),
        capture_output=True,
        text=True,
        timeout=600,
    )
    if proc.returncode != 0 or not cli_path.is_file():
        raise RuntimeError(f"cargo build --release failed: {proc.stderr or proc.stdout}")
    return cli_path


def resolve_native_stage_dir(output_dir: Path) -> Path:
    output_dir = Path(output_dir).resolve()
    if (output_dir / "module.after.ll").is_file() or (output_dir / "core.after.ll").is_file():
        return output_dir
    nested = output_dir / "native"
    if (nested / "module.after.ll").is_file() or (nested / "core.after.ll").is_file():
        return nested
    raise FileNotFoundError(f"Could not find module.after.ll or core.after.ll in {output_dir} or {nested}")


def _infer_cargo_lib_stem(manifest_path: Path) -> str:
    section = ""
    pkg_name: str | None = None
    lib_name: str | None = None
    for raw in manifest_path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        m = re.match(r'^name\s*=\s*"([^"]+)"', line)
        if m:
            if section == "lib":
                lib_name = m.group(1)
            elif section == "package":
                pkg_name = m.group(1)
    chosen = lib_name or pkg_name
    if not chosen:
        raise ValueError(f"Could not infer crate name from {manifest_path}")
    return chosen.replace("-", "_")


def compile_cargo_crate_vm(
    manifest_path: Path,
    output_dir: Path,
    *,
    workspace_root: Path,
    selected_functions: list[str] | None = None,
    seed: int = 90820261031,
    target_triple: str | None = None,
    max_slowdown: float = 10.0,
) -> dict:
    """Compile selected (or Auto-Ontology-recommended) Cargo crate functions into a Pure-Rust V20 VM staticlib."""
    workspace_root = Path(workspace_root).resolve()
    manifest_path = Path(manifest_path).resolve()
    output_dir = Path(output_dir).resolve()
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Cargo manifest not found: {manifest_path}")
    output_dir.mkdir(parents=True, exist_ok=True)
    cli_exe = ensure_rust_cli(workspace_root)

    ontology_scope: dict | None = None
    effective_functions = list(selected_functions) if selected_functions is not None else []
    if selected_functions is None:
        from . import ontology

        lib_stem = _infer_cargo_lib_stem(manifest_path)
        probe_target = output_dir / "ontology-ir-probe"
        emit_cmd = [
            "cargo",
            "rustc",
            "--manifest-path",
            str(manifest_path),
            "--lib",
            "--release",
            "--target-dir",
            str(probe_target),
        ]
        if target_triple:
            emit_cmd.extend(["--target", target_triple])
        emit_cmd.extend(
            [
                "--",
                "--emit=llvm-ir",
                "-C",
                "codegen-units=1",
                "-C",
                "debuginfo=0",
                "-C",
                "panic=abort",
            ]
        )
        emit_proc = subprocess.run(
            emit_cmd,
            cwd=str(workspace_root),
            capture_output=True,
            text=True,
            timeout=600,
        )
        if emit_proc.returncode != 0:
            raise RuntimeError(f"cargo rustc --emit=llvm-ir failed: {emit_proc.stderr or emit_proc.stdout}")

        deps_dir = (
            probe_target / target_triple / "release/deps"
            if target_triple
            else probe_target / "release/deps"
        )
        ll_candidates = sorted(deps_dir.glob(f"{lib_stem}-*.ll")) or sorted(deps_dir.glob("*.ll"))
        if not ll_candidates:
            raise FileNotFoundError(f"No LLVM IR emitted under {deps_dir}")
        bundle = ontology.compile_defense_ontology(
            db_root=output_dir / "ontology-db",
            workspace_root=workspace_root,
            ir_modules=[ll_candidates[0]],
            benchmark_records=[],
            target_engine_version="V20.0",
        )
        rec = bundle.recommend_scope(max_slowdown=max_slowdown, only_vm_lowerable=True)
        effective_functions = list(rec["recommended_ir_functions"])
        if not effective_functions:
            raise ValueError(f"Auto Ontology found no VM-lowerable non-loop functions in {manifest_path}")
        ontology_scope = {
            "recommended_ir_functions": effective_functions,
            "excluded_hot_loop_ir_functions": list(rec["excluded_hot_loop_ir_functions"]),
            "symmetric_input_mix_warnings": list(rec["symmetric_input_mix_warnings"]),
        }

    cmd = [
        str(cli_exe),
        "compile-cargo",
        "--workspace",
        str(workspace_root),
        "--manifest-path",
        str(manifest_path),
        "--functions",
        ",".join(effective_functions),
        "--output-dir",
        str(output_dir),
        "--seed",
        str(seed),
    ]
    if target_triple:
        cmd.extend(["--target", target_triple])
    proc = subprocess.run(
        cmd,
        cwd=str(workspace_root),
        capture_output=True,
        text=True,
        timeout=600,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"antirea-cli compile-cargo failed: {proc.stderr or proc.stdout}")

    report_path = output_dir / "rust-cargo-report.json"
    result = json.loads(report_path.read_text(encoding="utf-8"))
    if ontology_scope is not None:
        result["ontology_scope"] = ontology_scope
        report_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def compile_and_link_rust_multilang(
    output_dir: Path,
    *,
    workspace_root: Path,
    seed: int = 90820261031,
    replace_protected_dll: bool = False,
    target_triple: str | None = None,
) -> dict:
    """Compile Pure-Rust runtime for a prepared `native_build` or lowered output directory and link shared library."""
    workspace_root = Path(workspace_root).resolve()
    output_dir = Path(output_dir).resolve()
    stage_dir = resolve_native_stage_dir(output_dir)

    after_ll = stage_dir / "module.after.ll"
    if not after_ll.is_file():
        after_ll = stage_dir / "core.after.ll"
    div_path = stage_dir / "diversification.json"
    protected_obj = stage_dir / "protected.obj"
    if not protected_obj.is_file():
        protected_obj = stage_dir / "core.obj"
    if not protected_obj.is_file():
        protected_obj = stage_dir / "protected.o"
    if not after_ll.is_file() or not div_path.is_file() or not protected_obj.is_file():
        raise FileNotFoundError(
            f"Expected module.after.ll, diversification.json, and protected.obj in {stage_dir}"
        )

    div = json.loads(div_path.read_text(encoding="utf-8"))
    dispatchers = div.get("dispatcher_symbols") or [div["dispatcher_symbol"]]
    cli_exe = ensure_rust_cli(workspace_root)

    cli_cmd = [
        str(cli_exe),
        "compile-multilang",
        "--workspace",
        str(workspace_root),
        "--input-ir",
        str(after_ll),
        "--dispatchers",
        ",".join(dispatchers),
        "--output-dir",
        str(stage_dir),
        "--seed",
        str(seed),
    ]
    if target_triple:
        cli_cmd.extend(["--target", target_triple])
    proc = subprocess.run(
        cli_cmd,
        cwd=str(workspace_root),
        capture_output=True,
        text=True,
        timeout=600,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"antirea-cli compile-multilang failed: {proc.stderr or proc.stdout}")

    report = json.loads((stage_dir / "rust-multilang-report.json").read_text(encoding="utf-8"))
    staticlib_path = Path(report["staticlib_path"])
    rust_dll = stage_dir / shared_library_filename("protected.rust")

    if _is_windows_os():
        clangxx = workspace_root / ".tools/clang+llvm-22.1.0-x86_64-pc-windows-msvc/bin/clang++.exe"
        exports_def = stage_dir / "exports.def"
        def_arg = f"'-Wl,/DEF:{exports_def}' " if exports_def.is_file() else ""
        dev_shell = (
            r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\Launch-VsDevShell.ps1"
        )
        link_cmd = (
            f"& '{dev_shell}' -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null; "
            f"& '{clangxx}' -shared -fuse-ld=lld '{protected_obj}' '{staticlib_path}' "
            f"-lntdll -luserenv -lws2_32 -ladvapi32 -lbcrypt -o '{rust_dll}' "
            f"{def_arg}'-Wl,/DEBUG:NONE' '-Wl,/INCREMENTAL:NO'"
        )
        link_proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", link_cmd],
            cwd=str(workspace_root),
            capture_output=True,
            text=True,
            timeout=120,
        )
    else:
        clangxx_bin = shutil.which("clang++") or "clang++"
        posix_cmd = [clangxx_bin, "-shared", str(protected_obj), str(staticlib_path), "-o", str(rust_dll)]
        if target_triple:
            posix_cmd.extend(["--target", target_triple])
        link_proc = subprocess.run(
            posix_cmd,
            cwd=str(workspace_root),
            capture_output=True,
            text=True,
            timeout=120,
        )

    if link_proc.returncode != 0 or not rust_dll.is_file():
        raise RuntimeError(f"Linking {rust_dll.name} failed: {link_proc.stderr or link_proc.stdout}")

    if stage_dir != output_dir:
        shutil.copy2(rust_dll, output_dir / rust_dll.name)

    result = {
        "status": "passed",
        "engine": report["engine"],
        "format_version": report["format_version"],
        "seed": seed,
        "seed_commitment_sha256": report.get("seed_commitment_sha256", ""),
        "stage_dir": str(stage_dir),
        "blob_count": report["blob_count"],
        "dispatcher_symbols": dispatchers,
        "staticlib_path": str(staticlib_path),
        "staticlib_sha256": report["staticlib_sha256"],
        "protected_rust_dll": str(rust_dll),
        "protected_rust_dll_sha256": _sha256(rust_dll),
        "protected_rust_dll_bytes": rust_dll.stat().st_size,
    }
    if replace_protected_dll:
        base_shared = shared_library_filename("protected")
        for d in {stage_dir, output_dir}:
            target_dll = d / base_shared
            if target_dll.is_file():
                target_dll.write_bytes(rust_dll.read_bytes())
        result["replaced_protected_dll"] = True
    (stage_dir / "rust-multilang-report.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8"
    )
    if stage_dir != output_dir:
        (output_dir / "rust-multilang-report.json").write_text(
            json.dumps(result, indent=2), encoding="utf-8"
        )
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--cargo-manifest", type=Path, default=None)
    parser.add_argument("--functions", type=str, default=None)
    parser.add_argument("--target", type=str, default=None)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--seed", type=int, default=90820261031)
    parser.add_argument("--replace-protected-dll", action="store_true")
    args = parser.parse_args(argv)
    if args.cargo_manifest is not None:
        funcs = (
            [f.strip() for f in args.functions.split(",") if f.strip()]
            if args.functions
            else None
        )
        res = compile_cargo_crate_vm(
            args.cargo_manifest,
            args.output_dir,
            workspace_root=args.workspace,
            selected_functions=funcs,
            seed=args.seed,
            target_triple=args.target,
        )
    else:
        res = compile_and_link_rust_multilang(
            args.output_dir,
            workspace_root=args.workspace,
            seed=args.seed,
            replace_protected_dll=args.replace_protected_dll,
            target_triple=args.target,
        )
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
