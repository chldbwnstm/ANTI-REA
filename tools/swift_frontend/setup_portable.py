"""Assemble already authenticated/extracted Swift payloads locally, no installer.

Run only after the parent's official-bundle and payload checks. Nothing is
downloaded, installed system-wide, registered or added to the user's PATH.
Existing destinations are never overwritten. All retained files get hash pins.
"""
from pathlib import Path
import hashlib
import json
import shutil
import sys


ROOT = Path(__file__).resolve().parents[2]
EXTRACTED = ROOT / ".tools/swift-6.4.0-pinned/extracted"
BUILD = EXTRACTED / "bld.noasserts.msi/LocalApp/Programs/Swift/Toolchains/6.4.0+NoAsserts/usr"
CLI = EXTRACTED / "cli.noasserts.msi/LocalApp/Programs/Swift/Toolchains/6.4.0+NoAsserts/usr/bin"
SDK = EXTRACTED / "windows.msi/LocalApp/Programs/Swift/Platforms/6.4.0/Windows.platform/Developer/SDKs/Windows.sdk"
RUNTIME = EXTRACTED / "rtl.amd64.msi"
DESTINATION = ROOT / ".tools/swift-6.4.0-portable"
CONFIG = ROOT / ".tools/swift-toolchain.json"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def copy(source, destination):
    if source.is_symlink() or not source.is_file() or destination.exists():
        raise ValueError("Source must be regular and destination fresh: " + str(source))
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    if digest(source) != digest(destination):
        raise ValueError("Portable copy hash mismatch")


def main():
    if sys.argv[1:] == ["--complete-private-assemblies"]:
        existing = json.loads(CONFIG.read_text(encoding="utf-8"))
        if any(not Path(value).is_file() or digest(Path(value)) != expected for value, expected in existing["input_hashes"].items()):
            raise ValueError("Existing portable files changed; refusing configuration refresh")
        backup = CONFIG.with_name("swift-toolchain.before-private-assemblies.json")
        if backup.exists():
            raise ValueError("Private-assembly repair was already attempted")
        for directory in sorted((BUILD / "bin").iterdir()):
            if directory.is_dir():
                for source in sorted(directory.rglob("*")):
                    if source.is_file():
                        copy(source, DESTINATION / "usr/bin" / source.relative_to(BUILD / "bin"))
        copy(BUILD.parent / "ToolchainInfo.plist", DESTINATION / "ToolchainInfo.plist")
        existing["input_hashes"] = {str(source): digest(source) for source in sorted(DESTINATION.rglob("*")) if source.is_file()}
        shutil.copyfile(CONFIG, backup)
        CONFIG.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"status": "private_assemblies_added", "files": len(existing["input_hashes"]), "backup": str(backup)}))
        return
    if sys.argv[1:]:
        raise ValueError("Unsupported setup option")
    if DESTINATION.exists() or CONFIG.exists():
        raise ValueError("Portable compiler/config already exists; refusing overwrite")
    executables = {"swiftc.exe", "swift-frontend.exe", "swift-autolink-extract.exe", "swift-demangle.exe",
                   "swift-plugin-server.exe", "clang.exe", "clang++.exe", "lld-link.exe"}
    for name in executables:
        copy(BUILD / "bin" / name, DESTINATION / "usr/bin" / name)
    for source in sorted((BUILD / "bin").glob("*.dll")):
        copy(source, DESTINATION / "usr/bin" / source.name)
    for directory in sorted((BUILD / "bin").iterdir()):
        if directory.is_dir():
            for source in sorted(directory.rglob("*")):
                if source.is_file():
                    copy(source, DESTINATION / "usr/bin" / source.relative_to(BUILD / "bin"))
    copy(BUILD.parent / "ToolchainInfo.plist", DESTINATION / "ToolchainInfo.plist")
    copy(CLI / "_InternalSwiftScan.dll", DESTINATION / "usr/bin/_InternalSwiftScan.dll")
    for directory in ("lib", "include"):
        for source in sorted((BUILD / directory).rglob("*")):
            if source.is_file():
                copy(source, DESTINATION / "usr" / directory / source.relative_to(BUILD / directory))
    for source in sorted(SDK.rglob("*")):
        if source.is_file():
            copy(source, DESTINATION / "sdk" / source.relative_to(SDK))
    for source in sorted(RUNTIME.glob("*.dll")):
        copy(source, DESTINATION / "runtime" / source.name)
    files = {str(source): digest(source) for source in sorted(DESTINATION.rglob("*")) if source.is_file()}
    data = {"schema_version": 1, "version": "6.4",
            "swiftc": str(DESTINATION / "usr/bin/swiftc.exe"), "sdk": str(DESTINATION / "sdk"),
            "runtime_dirs": [str(DESTINATION / "runtime")], "input_hashes": files,
            "provenance": "Official Apple-signed bundle and signed-manifest SHA512 verified by parent before extraction; local copy only.",
            "system_installation": False, "persistent_path_changed": False,
            "limitations": ["Only selected driver executables plus compiler DLLs/resources and complete SDK/runtime are retained.",
                            "System Visual Studio/Windows SDK and system DLLs are outside this portable inventory."]}
    encoded = json.dumps(data, indent=2) + "\n"
    if len(encoded.encode()) > 1024 * 1024:
        raise ValueError("Portable configuration exceeds frontend's 1 MiB bound")
    with CONFIG.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(encoded)
    print(json.dumps({"status": "portable_files_assembled", "files": len(files),
                      "config": str(CONFIG), "config_bytes": len(encoded.encode()),
                      "target_executed": False, "system_installation": False}))


if __name__ == "__main__":
    main()
