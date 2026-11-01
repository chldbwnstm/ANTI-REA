# Version Tracking & Release Policy (`docs/versioning.md`)

This document defines how versions are tracked, synchronized, and released across the **ANTI-REA** repository.

---

## 1. Versioning Scheme

ANTI-REA tracks two distinct version identifiers:

1. **Repository & Package Version (`SemVer`: `MAJOR.MINOR.PATCH`)**
   - Stored canonically in [`VERSION`](../VERSION) at the repository root (currently `1.0.0`).
   - Follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html):
     - **`MAJOR` (`X.0.0`)**: Incompatible changes to the CLI (`antirea-cli compile-multilang`), MCP tool schemas (`antirea.defense_mcp`), or public protection report contract.
     - **`MINOR` (`1.X.0`)**: Backwards-compatible new defense passes, new language frontends, new MCP tools, or new protection engine format versions.
     - **`PATCH` (`1.0.X`)**: Backwards-compatible bug fixes, documentation updates, performance tuning, or internal refactoring.

2. **Protection Engine Format Version (`antirea-rust-v<N>`, `format_version: <N>`)**
   - Stored in [`rust/crates/antirea-passes/src/lib.rs`](../rust/crates/antirea-passes/src/lib.rs) (`protection_report.json` fields `"engine"` and `"format_version"`).
   - Tracks the structural schema and cryptographic generation of the emitted VM/CFF protection pass (currently `engine = "antirea-rust-v12"`, `format_version = 12`).
   - Increment `format_version` whenever the VM bytecode encoding, `VmCtx` polymorphic synthesis rules, or `protection_report.json` structural fields change.

---

## 2. Synchronized Version Files (Single Source of Truth)

Whenever the repository version is bumped, **all** of the following files must be updated together in the same commit:

| File | Location / Field | Purpose |
| :--- | :--- | :--- |
| [`VERSION`](../VERSION) | Single-line plain text (`1.0.0`) | Canonical single source of truth |
| [`pyproject.toml`](../pyproject.toml) | `[project] version = "1.0.0"` | Python package metadata |
| [`antirea/__init__.py`](../antirea/__init__.py) | `__version__ = "1.0.0"` | Python runtime version export |
| [`antirea/defense_mcp.py`](../antirea/defense_mcp.py) | `serverInfo.version` (imports `__version__`) | MCP JSON-RPC `initialize` handshake version |
| [`rust/Cargo.toml`](../rust/Cargo.toml) | `[workspace.package] version = "1.0.0"` | Rust workspace crates (`antirea-cli`, `antirea-driver`, `antirea-ir`, `antirea-passes`, `antirea-vm`, etc.) |
| [`rust/crates/antirea-passes/src/lib.rs`](../rust/crates/antirea-passes/src/lib.rs) | Generated runtime `Cargo.toml` `version = "1.0.0"` | Ephemeral protected binary crate manifest |
| [`CHANGELOG.md`](../CHANGELOG.md) | `## [X.Y.Z] - YYYY-MM-DD` | Human-readable release notes and history |
| [`README.md`](../README.md) & [`docs/readme/README_*.md`](readme/) | `Version-vX.Y.Z` shield badge | Public version badge across all 22 language READMEs |

---

## 3. Automated Version Sync Verification

Before committing any version bump or release, run the version synchronization test suite:

```powershell
# 1. Verify all version files, badges, and CHANGELOG entries match VERSION
python -m unittest discover -s tests -p "test_version_sync.py" -v

# 2. Verify MCP server reports the exact package version
python -m unittest discover -s tests -p "test_defense_mcp.py" -v

# 3. Verify Rust workspace builds and passes all unit tests
cargo test --manifest-path rust/Cargo.toml
```

[`tests/test_version_sync.py`](../tests/test_version_sync.py) automatically checks that:
- `VERSION` contains a valid `MAJOR.MINOR.PATCH` semantic version string.
- `pyproject.toml`, `antirea.__version__`, `antirea.defense_mcp` (`initialize` response), `rust/Cargo.toml`, and `rust/crates/antirea-passes/src/lib.rs` all equal `VERSION`.
- `CHANGELOG.md` contains a release heading `## [<VERSION>] - YYYY-MM-DD`.
- `README.md` and all 21 `docs/readme/README_*.md` files display the matching `Version-v<VERSION>` badge.

---

## 4. Release & Git Tag Procedure

1. Update [`VERSION`](../VERSION) and all synchronized files listed in Section 2.
2. Add a dated entry `## [X.Y.Z] - YYYY-MM-DD` in [`CHANGELOG.md`](../CHANGELOG.md) summarizing `Added`, `Changed`, `Fixed`, and `Removed` items.
3. Run the verification commands in Section 3 and confirm zero failures.
4. Commit the version bump:
   ```powershell
   git commit -m "Release vX.Y.Z: <concise summary>"
   ```
5. Create an annotated Git tag matching `vX.Y.Z`:
   ```powershell
   git tag -a vX.Y.Z -m "ANTI-REA vX.Y.Z"
   ```
6. Push to remote only when explicitly requested by the user:
   ```powershell
   git push origin main --tags
   ```
