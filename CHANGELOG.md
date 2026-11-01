# Changelog

All notable changes to **ANTI-REA** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See [`docs/versioning.md`](docs/versioning.md) for the full version-tracking policy and release synchronization checklist.

---

## [1.0.0] - 2026-11-01

### Highlights
First stable major release (`v1.0.0`) of the **ANTI-REA Pure-Rust Native Protection & Virtualization Engine** (`antirea-rust-v12`, `format_version: 12`) and MCP server (`antirea.defense_mcp`).

### Added
- **Pure-Rust `compile-multilang` Pipeline (`antirea-cli`, `antirea-driver`, `antirea-ir`, `antirea-passes`):**
  - Unified multi-language frontend supporting **C, C++, Rust, Go, Python, C#, Java, JavaScript, and TypeScript** down to LLVM IR and protected native PE/ELF/Mach-O binaries (`--profile dev | balanced | max`, `--domain-tag`, `--seed`).
  - Built-in **Pure-Rust LLVM IR Function-to-VM Bytecode Lowerer** (`rust/crates/antirea-ir/src/llvm_lower.rs`) and built-in 55-opcode instruction table (`default_opcode_table()`), eliminating any external bytecode compiler dependency.
- **Kerckhoffs-Compliant Open-Source White-Box Defense (`antirea-rust-v12`):**
  - **One-way CSPRNG (`ChaCha20Rng` / BLAKE3-class sponge):** Replaced all invertible PRNGs (`SplitMix64`) across `antirea-passes`, `antirea-ir`, and `antirea-vm` so exposed binary constants cannot be inverted to recover `--seed` or sibling keys.
  - **Polymorphic `VmCtx` Struct Layout Synthesis:** Per-build seeded shuffling of all 10 `VmCtx` fields and 6 internal register-bank slots with randomized dummy padding slots.
  - **Polymorphic Superoperator Synthesis & Non-Linear Bytecode Encoding:** Per-build seeded permutation of `ENC_MODE` (0..3), 3-way fused superoperators (`SUPER_LOAD_ADD_STORE`, `SUPER_CMP_SELECT`, `SUPER_XOR_ROT_ADD`), and 8-bit Galois-field S-box table lookups (`SBOX_TABLE` / `INV_SBOX_TABLE`) embedded into MBA arithmetic.
  - **Path-Coupled White-Box State Binding:** Continuous absorption of runtime input words and executed opcodes into `transcript_acc`, dynamically binding block-transition keys (`transition_mask`), VM handler index decoding (`handler_idx_mask`), and return value sealing (`return_seal`).
  - **Cross-Block Key-Schedule Chaining & Decoy State-Corruption Traps:** Continuous state ratification across basic blocks (`ratchet_acc`) where tampering or skipping checks silently corrupts downstream computation without explicit panic strings.
- **Agent-First MCP Server (`antirea.defense_mcp`):**
  - 6 structured JSON-RPC tools over stdio (`compile_protected_binary`, `verify_protection_gate`, `benchmark_binary`, `inspect_protection_report`, `generate_manifest`, `list_supported_frontends`) plus built-in agent setup prompts (`setup_and_protect`, `verify_release`).
- **22-Language Documentation Suite & Version Tracking Infrastructure:**
  - Synchronized `README.md` and 21 localized guides in `docs/readme/README_*.md` with agent-automated prerequisite installation and verification workflows.
  - Added `VERSION`, `CHANGELOG.md`, `docs/versioning.md`, and `tests/test_version_sync.py` to enforce single-source-of-truth version synchronization across Python, Rust, MCP metadata, and documentation.

### Changed
- Unified repository version across `VERSION`, `pyproject.toml`, `antirea/__init__.py`, `antirea/defense_mcp.py`, `rust/Cargo.toml`, and generated runtime manifests to `1.0.0`.
- Updated `rust/Cargo.toml` workspace license declaration to `MIT` to match the repository license and `pyproject.toml`.

### Removed
- Removed legacy external `.tools/kagura` binary dependency and legacy pre-`compile-multilang` CLI documentation references.

---

## [0.4.0] - 2026-10-25

### Added
- Multi-language frontend translation (`antirea-frontend`) and `compile-multilang` orchestration in the Rust workspace (`antirea-rust-v9` through `antirea-rust-v11`).
- Stripped symbol tables, suppressed panic strings, and added encrypted constant pools with decoy handlers.

---

## [0.2.0] - 2026-10-19

### Added
- MCP server (`antirea.defense_mcp`) and defender-only operational workflow (`antirea.defense_loop`).
- Verification gate checking binary structural stripping, baseline I/O parity, and performance budgets.

---

## [0.1.0] - 2026-10-15

### Added
- Initial ANTI-REA defense orchestration prototype and benchmark harness.
