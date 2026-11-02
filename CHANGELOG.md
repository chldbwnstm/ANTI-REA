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
  - **Literature-Review 5-Pass Hardening (`V13-M1`..`V13-M5`):**
    - `V13-M1` (RFC 8439 §2.1 & §2.3): Standard 20-round `ChaCha20Csprng` (`chacha20_quarter_round`, `chacha20_block`), domain-separated substreams (`derive_stream`), OS-entropy default seed generation (`os_entropy_seed`), and zero-seed-leakage public symbol tags (`b"antirea-v13-public-symbol-tag"`).
    - `V13-M2` (Loki USENIX '22 / VMHunt CCS '18): `F_CHAIN_<M1>_<ALU1>__<M2>_<ALU2>` 8-instruction 2-ALU data-dependent chain superoperators eliminating intermediate `VmCtx` slot writes.
    - `V13-M3` (SiMBA CCS '22 / GAMBA CCS '23 / QSynth BAR '20): Per-build 256-entry bijective `ANTIREA_SBOX` / `ANTIREA_INV_SBOX` tables and 6-variant compile-time polymorphic MBA lowering combining S-Box round-trips with odd-modulus multiplicative ring homomorphisms `(ring_m, ring_inv)` over $\mathbb{Z}_{2^{64}}$.
    - `V13-M4` (Path-Oriented Protections CCS '13): `VmCtx::svp_branch` input-anchored active equivalent path splitting (Symbolic Value Partitioning).
    - `V13-M5` (Barak et al. JACM '12 / LLM Benchmarks '25): Automated PE binary seed-leakage scanner (`scan_pe_for_seed_leakage`), SHA-256 seed commitment reporting (`seed_commitment_sha256`), and `p50`/`p95`/`max` tail-latency telemetry verified across all 11 supported languages (`0/11` recoveries, `34,903/34,903` I/O pairs verified).
  - **On-Demand Ephemeral Dynamic Defense & RSI Evolution (`V14-M1`..`V14-M4` & `V14.2`):**
    - `V14-M1` (Pushan '26 / XuanJia '26): Encrypted-at-rest `.rdata` S-Box vault (`VM_SBOX_ENC`) with runtime prologue-coupled ephemeral stack decryption and immediate volatile zero-wipe (`core::ptr::write_volatile(..., 0)`), eliminating plaintext S-Boxes from `.rdata` and post-prologue RAM/stack dumps without `RWX` / `VirtualProtect`.
    - `V14-M2` (Tigress-Static '26 / Syntia USENIX '17): Eliminated shared `helper_a` / `helper_b` leaf functions via `#[inline(always)]` 4-way polymorphically mutated leaf variants (`0` internal `call`s across all 16 cluster handlers).
    - `V14-M3` (Loki USENIX '22 / DCA '16): 96-word 3-share mixed-modulus ($\text{GF}(2) \times \mathbb{Z}_{2^{64}}$) header splitting `(s0 ^ s1.rotate_left(r1)).wrapping_sub(s2.rotate_right(r2))` + input-coupled context diffusion (`414 / 416` `VmCtx` qwords diffused).
    - `V14.2` (RSI Iteration 2): Branchless continuous prologue vault ratchet (`0` `0x1ff` compare landmarks), 4-way non-isomorphic cluster entry/exit token algebra, and whole-program cross-channel fusion (`0/5` recoveries, `4/5` `complete_no_recovery`, `5/5 USABLE` across 5 external attacker PCs).
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
