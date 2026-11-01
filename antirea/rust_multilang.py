"""Bridge between the multi-language native build pipeline and the Pure-Rust VM engine (antirea-rust-v8).

Supports both direct native routes (`c`, `cpp`, `rust` in `output_dir`) and lowered native routes
(`csharp`, `java`, `kotlin`, `go`, `swift` in `output_dir / "native"`). Compiles `module.after.ll`
(or `core.after.ll`) through `antirea-cli.exe compile-multilang` into `antirea_multilang_runtime.lib`
and links `protected.obj` into a Pure-Rust-backed shared library (`protected.rust.dll`).
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_rust_cli(workspace_root: Path) -> Path:
    cli_path = workspace_root / "rust/target/release/antirea-cli.exe"
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


def compile_and_link_rust_multilang(
    output_dir: Path,
    *,
    workspace_root: Path,
    seed: int = 90820261031,
    replace_protected_dll: bool = False,
) -> dict:
    """Compile Pure-Rust runtime for a prepared `native_build` or lowered output directory and link `protected.rust.dll`."""
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
    if not after_ll.is_file() or not div_path.is_file() or not protected_obj.is_file():
        raise FileNotFoundError(
            f"Expected module.after.ll, diversification.json, and protected.obj in {stage_dir}"
        )

    div = json.loads(div_path.read_text(encoding="utf-8"))
    dispatchers = div.get("dispatcher_symbols") or [div["dispatcher_symbol"]]
    cli_exe = ensure_rust_cli(workspace_root)

    proc = subprocess.run(
        [
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
        ],
        cwd=str(workspace_root),
        capture_output=True,
        text=True,
        timeout=600,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"antirea-cli compile-multilang failed: {proc.stderr or proc.stdout}")

    report = json.loads((stage_dir / "rust-multilang-report.json").read_text(encoding="utf-8"))
    staticlib_path = Path(report["staticlib_path"])
    clangxx = workspace_root / ".tools/clang+llvm-22.1.0-x86_64-pc-windows-msvc/bin/clang++.exe"
    rust_dll = stage_dir / "protected.rust.dll"
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
    if link_proc.returncode != 0 or not rust_dll.is_file():
        raise RuntimeError(f"Linking protected.rust.dll failed: {link_proc.stderr or link_proc.stdout}")

    if stage_dir != output_dir:
        shutil.copy2(rust_dll, output_dir / "protected.rust.dll")

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
        for d in {stage_dir, output_dir}:
            target_dll = d / "protected.dll"
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
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--seed", type=int, default=90820261031)
    parser.add_argument("--replace-protected-dll", action="store_true")
    args = parser.parse_args(argv)
    res = compile_and_link_rust_multilang(
        args.output_dir,
        workspace_root=args.workspace,
        seed=args.seed,
        replace_protected_dll=args.replace_protected_dll,
    )
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
