# Changelog

All notable changes to **ANTI-REA** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See [`docs/versioning.md`](docs/versioning.md) for the full version-tracking policy and release synchronization checklist.

---

## [1.1.0] - 2026-11-14

### Highlights
Completes **Phase 4 (`Dynamic Protection Hardening, Semantic Auto Ontology & Pure-Rust Engine V20 Completion`)** across 9 consecutive Multi-PC external attacker fleet rounds (`0 / 45` standalone recoveries, `45 / 45 USABLE`, `233,910 / 233,910` bit-exact cross-verified I/O pairs), activates **Phase 5 (`Real-World Project Dogfooding & Continuous Elimination of Inefficiencies and Bugs Across Diverse Projects`)**, upgrades the Pure-Rust VM compiler to **`antirea-rust-v20` (`format_version: 20`)**, and completes all 8 auxiliary C/LLVM IR hardening layers in `antirea/hardening.py`.

### Added
- **Pure-Rust Engine `V20.0` (`antirea-rust-v20`, `format_version: 20`):**
  - `V20-M1` (`F15` Verified `CLOSED`): Replaced all 7 `_mm_srli_si128(..., 8)` upper-lane extractions with `black_box`-guarded `_mm_unpackhi_epi64` and guarded `fast_entropy` shift arms (`0` `pshufd ..., 0xee` instructions across compiled x86-64 PEs), while routing all 3 rotation fallback guards (`feistel_round_params`, `reg_bias`, `stk_params`) through ChaCha20-derived `HDR_PAIR_ROTS`.
  - `V20-M2` (`F16` Closure — Cross-Platform & Direct Cargo Crate Route): Added bit-identical non-`x86_64` `portable_simd128` 128-bit lane polyfill (`aarch64`/portable Rust), cross-OS `.lib`/`lib*.a` staticlib resolution and PE/ELF/Mach-O seed/constant hygiene scanning (`scan_binary_for_*`), `--target <triple>` support, and direct Cargo library crate virtualization (`antirea-cli compile-cargo` and `antirea.rust_multilang.compile_cargo_crate_vm` with automatic zero-config `antirea.ontology` hot-loop scope filtering).
  - `V20-M3` (`F17` Closure — Live `.rdata` Vault Ciphertext Ratchet): Added W^X-compliant `sample_vault_ciphertext_digest()` sampling `ANTIREA_SBOX`, `ANTIREA_INV_SBOX`, `ANTIREA_CLUSTER_LUT`, and `ANTIREA_RDATA_POOL` via `read_volatile` to unmask `vault_init_masked` inside `VmCtx::init_in_place` and ratchet live `.rdata` ciphertexts during execution.
- **Complete 8-Layer C & LLVM IR Hardening Suite (`antirea/hardening.py`):**
  - Replaced `random.Random` and linear multi-VM seed stepping with one-way SHA-256 counter-mode CSPRNG derivation (**Kerckhoffs's Principle**).
  - Implemented `anti_dump` (`ephemeral_scrub_and_pool_guard`: `antirea_scrub_ephemeral_bytes` volatile zeroizer with compiler barrier + `antirea_verify_guard_pool_integrity` read-only anchor check) and `iat_api_hiding` (`internal_dispatch_table_resolver`: registered `antirea_symbol_entry_t` dispatch-by-hash resolver `antirea_resolve_symbol_by_hash`).
  - Added LLVM IR string literal XOR encryption (`encrypt_llvm_ir_cstrings`) and mixed Boolean-arithmetic `add`/`xor` instruction lowering (`rewrite_llvm_ir_mba`) verified in `inspect_hardening_artifact`.
- **Auto Ontology `V20.0` Lineage (`antirea/ontology.py`):**
  - Indexed `F15`–`F17` (`V19.2`) $\rightarrow$ `V20-M1`–`V20-M3` (`V20.0`, `verified_fleet_rounds = 1` following the 9th 5-PC 60-minute external Multi-PC fleet evaluation with `0 / 5` standalone recoveries) while maintaining `28 / 28` (`100.0%`) `auto-ontology-eval` A/B accuracy.

### Changed
- Closed **Phase 4 (`[COMPLETED]`)** with verified `Engine V20.0` (`0 / 45` standalone recoveries) and transitioned **Phase 5 (`[ACTIVE]`)** to **Real-World Project Dogfooding & Continuous Elimination of Inefficiencies and Bugs Across Diverse Projects** across `docs/assets/defense-roadmap.svg`, `docs/assets/defense-roadmap-ko.svg`, `README.md`, `docs/validation-status.md`, and all 21 localized `docs/readme/README_*.md` guides.
- Synchronized package and manifest versions to `1.1.0` across `VERSION`, `pyproject.toml`, `antirea/__init__.py`, `antirea/defense_mcp.py`, `rust/Cargo.toml`, and generated runtime `Cargo.toml` templates (`format_version: 20`).

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
    - `V15.0`–`V19.0` (`antirea-rust-v19`, `format_version: 19`): Feistel `.rdata` pool coupling & 3-share mixed-modulus header splitting (`V15`), ChaCha20 polymorphic input-packing & non-printable ASCII constant sanitization + variable non-16 cluster count (`V16`), per-build `HDR_PAIR_ROTS` rotation table + vault-encrypted `ANTIREA_CLUSTER_LUT` router + variable `VmCtx.arena` + `.pdata` medium-tier callable bridges (`V17`), stack-proximity volatile caller-frame argument scrubbing + keyed/decoy `compile-multilang` ABI + $\text{GF}(2^9)/\text{GF}(2^8)$ Galois LFSR prologue stepping + adaptive run-length cluster locality (`V18`), and position-coupled nonlinear per-index `VmCtx.route_lut[0..255]` masking (`V19-M1`) + per-build ChaCha20 SSE2 `pshufd` bijections & `fast_entropy` shift pairs (`V19-M2`) + dynamic $\text{GF}(2)$-homomorphic full-64-bit `VmCtx.hdr_route` blinding (`V19-M3`) (`V19`).
- **NVIDIA Auto Ontology Semantic Layer & Upstream Sync (`antirea.ontology`, `antirea.ontology_mcp`, `antirea.ontology_eval`, `antirea.auto_ontology_sync`):**
  - Integrated `NVIDIA/auto-ontology` and `NVIDIA/auto-ontology-eval` with automatic upstream fast-forward & breaking-change rollback (`auto_ontology_sync`), zero-config LLVM IR boundary/hot-loop scope optimization (`32.4x`–`4,345.7x` speedup across `xxHash`, `LZ4`, `BLAKE3`, `Lua 5.4`, `SQLite 3.46.1`), read-only authorizer-enforced JSON-RPC MCP tools (`ontology_mcp`), temporal `Attack Foothold` $\rightarrow$ `Defense Mitigation` RSI lineage, and a 28-task deterministic `auto-ontology-eval` benchmark (`100.0%` treatment accuracy vs `39.3%` schema-only baseline).
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
